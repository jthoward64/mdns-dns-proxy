use hickory_proto::rr::{Name, RData, Record};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info};
use crate::config::Config;

/// Query for A records (IPv4)
pub async fn query_a(
    daemon: &ServiceDaemon,
    name: &Name,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let hostname = name.to_utf8();
    
    // Check if this is a .local query
    if !hostname.ends_with(".local.") && !hostname.ends_with(".local") {
        return Ok(Vec::new());
    }

    // Try to resolve as a service instance or hostname
    resolve_hostname_to_ipv4(daemon, &hostname, config).await
}

/// Query for AAAA records (IPv6)
pub async fn query_aaaa(
    daemon: &ServiceDaemon,
    name: &Name,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let hostname = name.to_utf8();
    
    if !hostname.ends_with(".local.") && !hostname.ends_with(".local") {
        return Ok(Vec::new());
    }

    resolve_hostname_to_ipv6(daemon, &hostname, config).await
}

/// Query for PTR records (service enumeration)
pub async fn query_ptr(
    daemon: &ServiceDaemon,
    name: &Name,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let service_type = name.to_utf8();
    
    debug!("Browsing for service type: {}", service_type);
    
    let receiver = daemon.browse(&service_type)?;
    let mut records = Vec::new();
    
    // Wait for service discovery events with timeout
    let timeout_duration = config.service_query_timeout();
    let poll_interval = config.service_poll_interval();
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout_duration {
            break;
        }
        
        match timeout(poll_interval, receiver.recv_async()).await {
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
pub async fn query_srv(
    daemon: &ServiceDaemon,
    name: &Name,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
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
    
    let receiver = daemon.browse(&service_type)?;
    let mut records = Vec::new();
    
    let timeout_duration = config.service_query_timeout();
    let poll_interval = config.service_poll_interval();
    let start = std::time::Instant::now();
    
    // Loop through events until we find our service or timeout
    loop {
        if start.elapsed() > timeout_duration {
            break;
        }
        
        match timeout(poll_interval, receiver.recv_async()).await {
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
pub async fn query_txt(
    daemon: &ServiceDaemon,
    name: &Name,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
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
    
    let receiver = daemon.browse(&service_type)?;
    let mut records = Vec::new();
    
    let timeout_duration = config.service_query_timeout();
    let poll_interval = config.service_poll_interval();
    let start = std::time::Instant::now();
    
    // Loop through events until we find our service or timeout
    loop {
        if start.elapsed() > timeout_duration {
            break;
        }
        
        match timeout(poll_interval, receiver.recv_async()).await {
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

/// Discover all advertised service types on the network
async fn discover_service_types(daemon: &ServiceDaemon, config: &Config) -> Vec<String> {
    let mut service_types = Vec::new();
    
    // Browse for the meta-query service to discover all service types
    if let Ok(receiver) = daemon.browse("_services._dns-sd._udp.local.") {
        let timeout_duration = config.service_discovery_timeout();
        let poll_interval = Duration::from_millis(50); // Fast polling for meta-query
        let start = std::time::Instant::now();
        
        loop {
            if start.elapsed() > timeout_duration {
                break;
            }
            
            match timeout(poll_interval, receiver.recv_async()).await {
                Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                    // The fullname is the service type
                    let service_type = info.get_fullname().to_string();
                    if !service_types.contains(&service_type) {
                        debug!("Discovered service type: {}", service_type);
                        service_types.push(service_type);
                    }
                }
                Ok(Ok(ServiceEvent::SearchStopped(_))) => break,
                Ok(Err(_)) => break,
                Err(_) => continue,
                _ => {}
            }
        }
    }
    
    // If no services discovered via meta-query, fall back to comprehensive common types
    if service_types.is_empty() {
        debug!("No service types discovered via meta-query, using fallback list");
        service_types = vec![
            "_http._tcp.local.".to_string(),
            "_https._tcp.local.".to_string(),
            "_ssh._tcp.local.".to_string(),
            "_sftp-ssh._tcp.local.".to_string(),
            "_smb._tcp.local.".to_string(),
            "_afpovertcp._tcp.local.".to_string(),
            "_workstation._tcp.local.".to_string(),
            "_device-info._tcp.local.".to_string(),
            "_companion-link._tcp.local.".to_string(),
            "_airplay._tcp.local.".to_string(),
            "_raop._tcp.local.".to_string(),
            "_homekit._tcp.local.".to_string(),
        ];
    }
    
    service_types
}

/// Resolve hostname to IPv4 addresses
async fn resolve_hostname_to_ipv4(
    daemon: &ServiceDaemon,
    hostname: &str,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    // Dynamically discover service types
    let service_types = discover_service_types(daemon, config).await;
    
    for service_type in &service_types {
        if let Ok(receiver) = daemon.browse(service_type.as_str()) {
            let timeout_duration = config.hostname_resolution_timeout();
            let poll_interval = Duration::from_millis(200);
            let start = std::time::Instant::now();
            
            loop {
                if start.elapsed() > timeout_duration {
                    break;
                }
                
                match timeout(poll_interval, receiver.recv_async()).await {
                    Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                        let info_hostname = info.get_hostname();
                        if info_hostname == hostname || info_hostname.trim_end_matches('.') == hostname.trim_end_matches('.') {
                            let mut records = Vec::new();
                            
                            for addr in info.get_addresses() {
                                match addr {
                                    mdns_sd::ScopedIp::V4(ipv4) => {
                                        let ipv4_addr = ipv4.addr();
                                        let name = Name::from_utf8(hostname)?;
                                        let record = Record::from_rdata(
                                            name,
                                            120,
                                            RData::A(hickory_proto::rr::rdata::A::from(*ipv4_addr)),
                                        );
                                        records.push(record);
                                        
                                        debug!("Found IPv4 address for {}: {}", hostname, ipv4_addr);
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

/// Query for SOA (Start of Authority) records per RFC 8766 Section 6.1
pub async fn query_soa(
    _daemon: &ServiceDaemon,
    name: &Name,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    use hickory_proto::rr::rdata::SOA;
    
    // Per RFC 8766 Section 6.1:
    // - MNAME: host name of the Discovery Proxy device
    // - RNAME: mailbox of the person responsible
    // - SERIAL: MUST be zero
    // - REFRESH: 7200, RETRY: 3600, EXPIRE: 86400 (recommended)
    // - MINIMUM: 10 (negative caching TTL per Section 5.5.1)
    
    let mname = Name::from_utf8("discovery-proxy.local.")?;
    let rname = Name::from_utf8("hostmaster.local.")?;
    
    let soa = SOA::new(
        mname,
        rname,
        0,      // SERIAL: must be zero per RFC 8766
        7200,   // REFRESH
        3600,   // RETRY
        86400,  // EXPIRE
        10,     // MINIMUM: 10 seconds per RFC 8766 Section 5.5.1
    );
    
    let record = Record::from_rdata(
        name.clone(),
        10, // TTL capped at 10 seconds
        hickory_proto::rr::RData::SOA(soa),
    );
    
    Ok(vec![record])
}

/// Query for NS (Name Server) records per RFC 8766 Section 6.2
pub async fn query_ns(
    _daemon: &ServiceDaemon,
    name: &Name,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    use hickory_proto::rr::rdata::NS;
    
    // Per RFC 8766 Section 6.2:
    // Each Discovery Proxy returns its own NS record plus records of other proxies on the link
    // For now, just return this proxy's NS record
    
    let ns_name = Name::from_utf8("discovery-proxy.local.")?;
    let ns = NS(ns_name);
    
    let record = Record::from_rdata(
        name.clone(),
        10, // TTL capped at 10 seconds
        hickory_proto::rr::RData::NS(ns),
    );
    
    Ok(vec![record])
}

/// Resolve hostname to IPv6 addresses
async fn resolve_hostname_to_ipv6(
    daemon: &ServiceDaemon,
    hostname: &str,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    // Dynamically discover service types
    let service_types = discover_service_types(daemon, config).await;
    
    for service_type in &service_types {
        if let Ok(receiver) = daemon.browse(service_type.as_str()) {
            let timeout_duration = config.hostname_resolution_timeout();
            let poll_interval = Duration::from_millis(200);
            let start = std::time::Instant::now();
            
            loop {
                if start.elapsed() > timeout_duration {
                    break;
                }
                
                match timeout(poll_interval, receiver.recv_async()).await {
                    Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                        let info_hostname = info.get_hostname();
                        debug!("Checking hostname: {} against {}", info_hostname, hostname);
                        debug!("Service has {} addresses", info.get_addresses().len());
                        
                        if info_hostname == hostname || info_hostname.trim_end_matches('.') == hostname.trim_end_matches('.') {
                            let mut records = Vec::new();
                            
                            for addr in info.get_addresses() {
                                debug!("  Address: {:?}", addr);
                                match addr {
                                    mdns_sd::ScopedIp::V6(ipv6) => {
                                        let ipv6_addr = ipv6.addr();
                                        // Include all IPv6 addresses: link-local, ULA, and global
                                        // Link-local (fe80::/10), ULA (fc00::/7), and global are all valid
                                        let name = Name::from_utf8(hostname)?;
                                        let record = Record::from_rdata(
                                            name,
                                            120,
                                            RData::AAAA(hickory_proto::rr::rdata::AAAA::from(*ipv6_addr)),
                                        );
                                        records.push(record);
                                        
                                        debug!("Found IPv6 address for {}: {}", hostname, ipv6_addr);
                                    }
                                    _ => {}
                                }
                            }
                            
                            if !records.is_empty() {
                                return Ok(records);
                            } else {
                                debug!("No IPv6 addresses found for {} (service has IPv4 only or no addresses)", hostname);
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
