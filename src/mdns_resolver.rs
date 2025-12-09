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
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let daemon = ServiceDaemon::new()?;
        
        Ok(Self {
            daemon,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(120),
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
        // Format: instance._service._tcp.local
        let parts: Vec<&str> = service_name.split('.').collect();
        if parts.len() < 3 {
            return Ok(Vec::new());
        }
        
        let service_type = format!("{}.{}.local.", parts[parts.len() - 3], parts[parts.len() - 2]);
        
        let receiver = self.daemon.browse(&service_type)?;
        let mut records = Vec::new();
        
        let timeout_duration = Duration::from_secs(2);
        
        match timeout(timeout_duration, receiver.recv_async()).await {
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
                }
            }
            _ => {}
        }
        
        Ok(records)
    }

    /// Query for TXT records
    async fn query_txt(&self, name: &Name) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let service_name = name.to_utf8();
        
        debug!("Resolving TXT for: {}", service_name);
        
        let parts: Vec<&str> = service_name.split('.').collect();
        if parts.len() < 3 {
            return Ok(Vec::new());
        }
        
        let service_type = format!("{}.{}.local.", parts[parts.len() - 3], parts[parts.len() - 2]);
        
        let receiver = self.daemon.browse(&service_type)?;
        let mut records = Vec::new();
        
        let timeout_duration = Duration::from_secs(2);
        
        match timeout(timeout_duration, receiver.recv_async()).await {
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
                }
            }
            _ => {}
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
