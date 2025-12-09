use hickory_proto::rr::{Name, RData, Record, RecordType};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Cache entry for mDNS query results
#[derive(Clone, Debug)]
struct CacheEntry {
    records: Vec<Record>,
    timestamp: std::time::Instant,
}

/// mDNS resolver that bridges DNS queries to mDNS
pub struct MdnsResolver {
    daemon: ServiceDaemon,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    cache_ttl: Duration,
}

impl MdnsResolver {
    /// Create a new mDNS resolver
    pub fn new(cache_ttl: Duration) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let daemon = ServiceDaemon::new()?;
        
        Ok(Self {
            daemon,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
        })
    }

    /// Query mDNS for a given name and record type
    pub async fn query(
        &self,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let query_name = name.to_utf8();
        
        debug!("Querying mDNS for {} (type: {:?})", query_name, record_type);

        // Check cache first
        if let Some(cached) = self.get_cached(&query_name) {
            debug!("Returning cached results for {}", query_name);
            return Ok(cached);
        }

        // Perform mDNS query based on record type
        let records = match record_type {
            RecordType::A => self.query_a(name).await?,
            RecordType::AAAA => self.query_aaaa(name).await?,
            RecordType::PTR => self.query_ptr(name).await?,
            RecordType::SRV => self.query_srv(name).await?,
            RecordType::TXT => self.query_txt(name).await?,
            _ => {
                warn!("Unsupported record type: {:?}", record_type);
                Vec::new()
            }
        };

        // Cache the results
        if !records.is_empty() {
            self.cache_records(&query_name, records.clone());
        }

        Ok(records)
    }

    /// Query for A records (IPv4)
    async fn query_a(&self, name: &Name) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let hostname = name.to_utf8();
        
        // Check if this is a .local query
        if !hostname.ends_with(".local.") && !hostname.ends_with(".local") {
            return Ok(Vec::new());
        }

        // Try to resolve as a service instance or hostname
        let records = self.resolve_hostname_to_ipv4(&hostname).await?;
        
        Ok(records)
    }

    /// Query for AAAA records (IPv6)
    async fn query_aaaa(&self, name: &Name) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let hostname = name.to_utf8();
        
        if !hostname.ends_with(".local.") && !hostname.ends_with(".local") {
            return Ok(Vec::new());
        }

        let records = self.resolve_hostname_to_ipv6(&hostname).await?;
        
        Ok(records)
    }

    /// Query for PTR records (service enumeration)
    async fn query_ptr(&self, name: &Name) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let service_type = name.to_utf8();
        
        debug!("Browsing for service type: {}", service_type);
        
        let receiver = self.daemon.browse(&service_type)?;
        let mut records = Vec::new();
        
        // Wait for service discovery events with timeout
        let timeout_duration = Duration::from_secs(2);
        let start = std::time::Instant::now();
        
        loop {
            if start.elapsed() > timeout_duration {
                break;
            }
            
            match timeout(Duration::from_millis(500), receiver.recv_async()).await {
                Ok(Ok(event)) => {
                    match event {
                        ServiceEvent::ServiceResolved(info) => {
                            info!("Discovered service: {}", info.get_fullname());
                            
                            // Create PTR record
                            let ptr_name = Name::from_utf8(&service_type)?;
                            let target_name = Name::from_utf8(info.get_fullname())?;
                            
                            let record = Record::from_rdata(
                                ptr_name,
                                120, // TTL
                                RData::PTR(hickory_proto::rr::rdata::PTR(target_name)),
                            );
                            
                            records.push(record);
                        }
                        ServiceEvent::SearchStarted(ty) => {
                            debug!("Search started for: {}", ty);
                        }
                        ServiceEvent::SearchStopped(ty) => {
                            debug!("Search stopped for: {}", ty);
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(Err(e)) => {
                    error!("Error receiving mDNS event: {}", e);
                    break;
                }
                Err(_) => {
                    // Timeout, continue waiting
                    continue;
                }
            }
        }
        
        Ok(records)
    }

    /// Query for SRV records (service location)
    async fn query_srv(&self, name: &Name) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let service_name = name.to_utf8();
        
        debug!("Resolving SRV for: {}", service_name);
        
        // Extract service type from full name
        // Format: instance._service._tcp.local.
        // We need to get _service._tcp.local. from instance._service._tcp.local.
        let parts: Vec<&str> = service_name.split('.').collect();
        if parts.len() < 4 {
            return Ok(Vec::new());
        }
        
        // Skip instance name (first part) and reconstruct service type
        let service_type = parts[1..].join(".");
        
        let receiver = self.daemon.browse(&service_type)?;
        let mut records = Vec::new();
        
        let timeout_duration = Duration::from_secs(2);
        let start = std::time::Instant::now();
        
        // Loop through events until we find our service or timeout
        loop {
            if start.elapsed() > timeout_duration {
                break;
            }
            
            match timeout(Duration::from_millis(500), receiver.recv_async()).await {
                Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                    if info.get_fullname() == service_name {
                        let srv_name = Name::from_utf8(&service_name)?;
                        let target = Name::from_utf8(info.get_hostname())?;
                        
                        let record = Record::from_rdata(
                            srv_name,
                            120,
                            RData::SRV(hickory_proto::rr::rdata::SRV::new(
                                0,                    // priority
                                0,                    // weight
                                info.get_port(),      // port
                                target,               // target hostname
                            )),
                        );
                        
                        records.push(record);
                        break;
                    }
                }
                Ok(Ok(ServiceEvent::SearchStopped(_))) => break,
                Ok(Err(_)) => break,
                Err(_) => continue, // Timeout, try again
                _ => {}
            }
        }
        
        Ok(records)
    }

    /// Query for TXT records
    async fn query_txt(&self, name: &Name) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let service_name = name.to_utf8();
        
        debug!("Resolving TXT for: {}", service_name);
        
        // Extract service type from full name
        // Format: instance._service._tcp.local.
        let parts: Vec<&str> = service_name.split('.').collect();
        if parts.len() < 4 {
            return Ok(Vec::new());
        }
        
        // Skip instance name (first part) and reconstruct service type
        let service_type = parts[1..].join(".");
        
        let receiver = self.daemon.browse(&service_type)?;
        let mut records = Vec::new();
        
        let timeout_duration = Duration::from_secs(2);
        let start = std::time::Instant::now();
        
        // Loop through events until we find our service or timeout
        loop {
            if start.elapsed() > timeout_duration {
                break;
            }
            
            match timeout(Duration::from_millis(500), receiver.recv_async()).await {
                Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                    if info.get_fullname() == service_name {
                        let txt_name = Name::from_utf8(&service_name)?;
                        
                        let txt_records: Vec<String> = info
                            .get_properties()
                            .iter()
                            .map(|prop| format!("{}={}", prop.key(), prop.val_str()))
                            .collect();
                        
                        if !txt_records.is_empty() {
                            let record = Record::from_rdata(
                                txt_name,
                                120,
                                RData::TXT(hickory_proto::rr::rdata::TXT::new(txt_records)),
                            );
                            
                            records.push(record);
                        }
                        break;
                    }
                }
                Ok(Ok(ServiceEvent::SearchStopped(_))) => break,
                Ok(Err(_)) => break,
                Err(_) => continue, // Timeout, try again
                _ => {}
            }
        }
        
        Ok(records)
    }

    /// Resolve hostname to IPv4 addresses
    async fn resolve_hostname_to_ipv4(
        &self,
        hostname: &str,
    ) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        // Try browsing for common service types to find the host
        let service_types = vec!["_http._tcp.local.", "_ssh._tcp.local.", "_device-info._tcp.local."];
        
        for service_type in service_types {
            if let Ok(receiver) = self.daemon.browse(service_type) {
                let timeout_duration = Duration::from_secs(1);
                let start = std::time::Instant::now();
                
                loop {
                    if start.elapsed() > timeout_duration {
                        break;
                    }
                    
                    match timeout(Duration::from_millis(200), receiver.recv_async()).await {
                        Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                            let info_hostname = info.get_hostname();
                            if info_hostname == hostname || info_hostname.trim_end_matches('.') == hostname.trim_end_matches('.') {
                                let mut records = Vec::new();
                                
                                for addr in info.get_addresses() {
                                    match addr {
                                        mdns_sd::ScopedIp::V4(ipv4) => {
                                            let name = Name::from_utf8(hostname)?;
                                            let record = Record::from_rdata(
                                                name,
                                                120,
                                                RData::A(hickory_proto::rr::rdata::A::from(*ipv4.addr())),
                                            );
                                            records.push(record);
                                        }
                                        _ => {}
                                    }
                                }
                                
                                if !records.is_empty() {
                                    return Ok(records);
                                }
                            }
                        }
                        _ => continue,
                    }
                }
            }
        }
        
        Ok(Vec::new())
    }

    /// Resolve hostname to IPv6 addresses
    async fn resolve_hostname_to_ipv6(
        &self,
        hostname: &str,
    ) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let service_types = vec!["_http._tcp.local.", "_ssh._tcp.local.", "_device-info._tcp.local."];
        
        for service_type in service_types {
            if let Ok(receiver) = self.daemon.browse(service_type) {
                let timeout_duration = Duration::from_secs(1);
                let start = std::time::Instant::now();
                
                loop {
                    if start.elapsed() > timeout_duration {
                        break;
                    }
                    
                    match timeout(Duration::from_millis(200), receiver.recv_async()).await {
                        Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                            let info_hostname = info.get_hostname();
                            if info_hostname == hostname || info_hostname.trim_end_matches('.') == hostname.trim_end_matches('.') {
                                let mut records = Vec::new();
                                
                                for addr in info.get_addresses() {
                                    match addr {
                                        mdns_sd::ScopedIp::V6(ipv6) => {
                                            let name = Name::from_utf8(hostname)?;
                                            let record = Record::from_rdata(
                                                name,
                                                120,
                                                RData::AAAA(hickory_proto::rr::rdata::AAAA::from(*ipv6.addr())),
                                            );
                                            records.push(record);
                                        }
                                        _ => {}
                                    }
                                }
                                
                                if !records.is_empty() {
                                    return Ok(records);
                                }
                            }
                        }
                        _ => continue,
                    }
                }
            }
        }
        
        Ok(Vec::new())
    }

    /// Get cached records if still valid
    fn get_cached(&self, name: &str) -> Option<Vec<Record>> {
        let cache = self.cache.read().unwrap();
        
        if let Some(entry) = cache.get(name) {
            if entry.timestamp.elapsed() < self.cache_ttl {
                return Some(entry.records.clone());
            }
        }
        
        None
    }

    /// Cache query results
    fn cache_records(&self, name: &str, records: Vec<Record>) {
        let mut cache = self.cache.write().unwrap();
        
        cache.insert(
            name.to_string(),
            CacheEntry {
                records,
                timestamp: std::time::Instant::now(),
            },
        );
        
        // Clean up old entries
        cache.retain(|_, entry| entry.timestamp.elapsed() < self.cache_ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RData;
    use std::net::Ipv4Addr;

    fn create_test_record(name: &str, ttl: u32) -> Record {
        let name = Name::from_utf8(name).unwrap();
        Record::from_rdata(
            name,
            ttl,
            RData::A(hickory_proto::rr::rdata::A::from(Ipv4Addr::new(192, 168, 1, 1))),
        )
    }

    #[test]
    fn test_cache_entry_creation() {
        let records = vec![create_test_record("test.local", 120)];
        let entry = CacheEntry {
            records: records.clone(),
            timestamp: std::time::Instant::now(),
        };

        assert_eq!(entry.records.len(), 1);
        assert!(entry.timestamp.elapsed().as_millis() < 100);
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = MdnsResolver::new(Duration::from_secs(120));
        assert!(resolver.is_ok());
        
        let resolver = resolver.unwrap();
        assert_eq!(resolver.cache_ttl, Duration::from_secs(120));
    }

    #[test]
    fn test_resolver_with_custom_ttl() {
        let resolver = MdnsResolver::new(Duration::from_secs(300)).unwrap();
        assert_eq!(resolver.cache_ttl, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_cache_miss_on_empty_cache() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        let cached = resolver.get_cached("test.local");
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_hit_after_insert() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        let records = vec![create_test_record("test.local", 120)];
        
        resolver.cache_records("test.local", records.clone());
        
        let cached = resolver.get_cached("test.local");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let resolver = MdnsResolver::new(Duration::from_millis(100)).unwrap();
        let records = vec![create_test_record("test.local", 120)];
        
        resolver.cache_records("test.local", records);
        
        // Should be cached immediately
        assert!(resolver.get_cached("test.local").is_some());
        
        // Wait for cache to expire
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should be expired now
        assert!(resolver.get_cached("test.local").is_none());
    }

    #[tokio::test]
    async fn test_cache_multiple_entries() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        
        resolver.cache_records("host1.local", vec![create_test_record("host1.local", 120)]);
        resolver.cache_records("host2.local", vec![create_test_record("host2.local", 120)]);
        resolver.cache_records("host3.local", vec![create_test_record("host3.local", 120)]);
        
        assert!(resolver.get_cached("host1.local").is_some());
        assert!(resolver.get_cached("host2.local").is_some());
        assert!(resolver.get_cached("host3.local").is_some());
        assert!(resolver.get_cached("host4.local").is_none());
    }

    #[tokio::test]
    async fn test_cache_overwrites_existing() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        
        let records1 = vec![create_test_record("test.local", 120)];
        let records2 = vec![
            create_test_record("test.local", 120),
            create_test_record("test.local", 120),
        ];
        
        resolver.cache_records("test.local", records1);
        assert_eq!(resolver.get_cached("test.local").unwrap().len(), 1);
        
        resolver.cache_records("test.local", records2);
        assert_eq!(resolver.get_cached("test.local").unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_cache_cleanup_on_insert() {
        let resolver = MdnsResolver::new(Duration::from_millis(100)).unwrap();
        
        // Add some entries
        resolver.cache_records("host1.local", vec![create_test_record("host1.local", 120)]);
        resolver.cache_records("host2.local", vec![create_test_record("host2.local", 120)]);
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Add a new entry, which should trigger cleanup
        resolver.cache_records("host3.local", vec![create_test_record("host3.local", 120)]);
        
        // Old entries should be gone
        assert!(resolver.get_cached("host1.local").is_none());
        assert!(resolver.get_cached("host2.local").is_none());
        // New entry should exist
        assert!(resolver.get_cached("host3.local").is_some());
    }

    #[test]
    fn test_query_name_parsing() {
        // Test that Name parsing works correctly
        assert!(Name::from_utf8("test.local").is_ok());
        assert!(Name::from_utf8("test.local.").is_ok());
        assert!(Name::from_utf8("_http._tcp.local").is_ok());
        assert!(Name::from_utf8("MyService._http._tcp.local").is_ok());
    }

    #[tokio::test]
    async fn test_unsupported_record_type_returns_empty() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        let name = Name::from_utf8("test.local").unwrap();
        
        // Test unsupported record types
        let result = resolver.query(&name, RecordType::CNAME).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        
        let result = resolver.query(&name, RecordType::MX).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_non_local_domain_returns_empty() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        
        // Non-.local domains should return empty
        let name = Name::from_utf8("example.com").unwrap();
        let result = resolver.query(&name, RecordType::A).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_cache_entry_clone() {
        let records = vec![create_test_record("test.local", 120)];
        let entry = CacheEntry {
            records: records.clone(),
            timestamp: std::time::Instant::now(),
        };

        let cloned = entry.clone();
        assert_eq!(cloned.records.len(), entry.records.len());
    }

    #[test]
    fn test_cache_entry_debug() {
        let records = vec![create_test_record("test.local", 120)];
        let entry = CacheEntry {
            records,
            timestamp: std::time::Instant::now(),
        };

        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("CacheEntry"));
    }

    #[tokio::test]
    async fn test_query_with_cache() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        let name = Name::from_utf8("test.local").unwrap();
        
        // First query (will return empty as no actual mDNS service)
        let result1 = resolver.query(&name, RecordType::A).await;
        assert!(result1.is_ok());
        
        // If we got results, they should be cached
        if !result1.as_ref().unwrap().is_empty() {
            let result2 = resolver.query(&name, RecordType::A).await;
            assert!(result2.is_ok());
        }
    }

    #[tokio::test]
    async fn test_query_different_record_types() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        
        // Test A record query (won't find anything but should return Ok with empty vec)
        let name_a = Name::from_utf8("test.local").unwrap();
        let result = resolver.query(&name_a, RecordType::A).await;
        assert!(result.is_ok());
        
        // Test AAAA record query
        let name_aaaa = Name::from_utf8("test.local").unwrap();
        let result = resolver.query(&name_aaaa, RecordType::AAAA).await;
        assert!(result.is_ok());
        
        // Note: PTR/SRV/TXT queries involve actual network operations with browse()
        // which may fail if the daemon can't be created or network is unavailable.
        // These are better tested in integration tests.
    }

    #[tokio::test]
    async fn test_cache_key_case_sensitivity() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        let records = vec![create_test_record("test.local", 120)];
        
        resolver.cache_records("test.local", records.clone());
        
        // Same key should hit cache
        assert!(resolver.get_cached("test.local").is_some());
        
        // Different case should miss (cache is case-sensitive)
        assert!(resolver.get_cached("TEST.LOCAL").is_none());
        assert!(resolver.get_cached("Test.Local").is_none());
    }

    #[tokio::test]
    async fn test_empty_cache_returns_none() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        
        assert!(resolver.get_cached("nonexistent.local").is_none());
        assert!(resolver.get_cached("").is_none());
        assert!(resolver.get_cached("any.domain.local").is_none());
    }

    #[tokio::test]
    async fn test_cache_ttl_zero() {
        let resolver = MdnsResolver::new(Duration::from_secs(0)).unwrap();
        let records = vec![create_test_record("test.local", 120)];
        
        resolver.cache_records("test.local", records);
        
        // With 0 TTL, cache should effectively be disabled
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(resolver.get_cached("test.local").is_none());
    }

    #[tokio::test]
    async fn test_cache_with_empty_records() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        
        // Cache empty vector
        resolver.cache_records("test.local", vec![]);
        
        // Should return empty vector, not None
        let cached = resolver.get_cached("test.local");
        assert!(cached.is_some());
        assert!(cached.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_multiple_records_for_same_name() {
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        
        let records = vec![
            create_test_record("test.local", 120),
            create_test_record("test.local", 120),
            create_test_record("test.local", 120),
        ];
        
        resolver.cache_records("test.local", records);
        
        let cached = resolver.get_cached("test.local");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 3);
    }

    #[test]
    fn test_record_creation_with_different_ttls() {
        let record1 = create_test_record("test.local", 60);
        let record2 = create_test_record("test.local", 120);
        let record3 = create_test_record("test.local", 300);
        
        // All should be valid records (note: Name adds trailing dot)
        assert!(record1.name().to_utf8().starts_with("test.local"));
        assert!(record2.name().to_utf8().starts_with("test.local"));
        assert!(record3.name().to_utf8().starts_with("test.local"));
    }

    #[test]
    fn test_name_parsing_variations() {
        // Test various valid name formats
        assert!(Name::from_utf8("a.local").is_ok());
        assert!(Name::from_utf8("a.b.local").is_ok());
        assert!(Name::from_utf8("a-b.local").is_ok());
        assert!(Name::from_utf8("a1.local").is_ok());
        assert!(Name::from_utf8("1a.local").is_ok());
        
        // Service discovery names
        assert!(Name::from_utf8("_http._tcp.local").is_ok());
        assert!(Name::from_utf8("MyService._http._tcp.local").is_ok());
    }

    #[tokio::test]
    async fn test_resolver_with_very_long_ttl() {
        let resolver = MdnsResolver::new(Duration::from_secs(86400)).unwrap(); // 24 hours
        let records = vec![create_test_record("test.local", 120)];
        
        resolver.cache_records("test.local", records);
        
        // Should still be cached immediately
        assert!(resolver.get_cached("test.local").is_some());
    }

    #[tokio::test]
    async fn test_concurrent_cache_access() {
        use std::sync::Arc;
        
        let resolver = Arc::new(MdnsResolver::new(Duration::from_secs(120)).unwrap());
        let records = vec![create_test_record("test.local", 120)];
        
        resolver.cache_records("test.local", records);
        
        // Spawn multiple tasks accessing cache concurrently
        let mut handles = vec![];
        for _ in 0..10 {
            let resolver_clone = resolver.clone();
            let handle = tokio::spawn(async move {
                resolver_clone.get_cached("test.local")
            });
            handles.push(handle);
        }
        
        // All should succeed
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }
    }

    #[test]
    fn test_resolver_creation_different_ttls() {
        assert!(MdnsResolver::new(Duration::from_secs(1)).is_ok());
        assert!(MdnsResolver::new(Duration::from_secs(60)).is_ok());
        assert!(MdnsResolver::new(Duration::from_secs(300)).is_ok());
        assert!(MdnsResolver::new(Duration::from_secs(3600)).is_ok());
        assert!(MdnsResolver::new(Duration::from_millis(500)).is_ok());
    }
}
