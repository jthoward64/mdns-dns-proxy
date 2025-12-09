use hickory_proto::rr::{Name, RData, Record};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Query for A records (IPv4)
pub async fn query_a(
    daemon: &ServiceDaemon,
    name: &Name,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let hostname = name.to_utf8();
    
    // Check if this is a .local query
    if !hostname.ends_with(".local.") && !hostname.ends_with(".local") {
        return Ok(Vec::new());
    }

    // Try to resolve as a service instance or hostname
    resolve_hostname_to_ipv4(daemon, &hostname).await
}

/// Query for AAAA records (IPv6)
pub async fn query_aaaa(
    daemon: &ServiceDaemon,
    name: &Name,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let hostname = name.to_utf8();
    
    if !hostname.ends_with(".local.") && !hostname.ends_with(".local") {
        return Ok(Vec::new());
    }

    resolve_hostname_to_ipv6(daemon, &hostname).await
}

/// Query for PTR records (service enumeration)
pub async fn query_ptr(
    daemon: &ServiceDaemon,
    name: &Name,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let service_type = name.to_utf8();
    
    debug!("Browsing for service type: {}", service_type);
    
    let receiver = daemon.browse(&service_type)?;
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
pub async fn query_srv(
    daemon: &ServiceDaemon,
    name: &Name,
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
pub async fn query_txt(
    daemon: &ServiceDaemon,
    name: &Name,
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
    daemon: &ServiceDaemon,
    hostname: &str,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    // Try browsing for common service types to find the host
    let service_types = vec!["_http._tcp.local.", "_ssh._tcp.local.", "_device-info._tcp.local."];
    
    for service_type in service_types {
        if let Ok(receiver) = daemon.browse(service_type) {
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

/// Resolve hostname to IPv6 addresses
async fn resolve_hostname_to_ipv6(
    daemon: &ServiceDaemon,
    hostname: &str,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let service_types = vec!["_http._tcp.local.", "_ssh._tcp.local.", "_device-info._tcp.local."];
    
    for service_type in service_types {
        if let Ok(receiver) = daemon.browse(service_type) {
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
                            
                            let mut records_string = String::new();
                            for addr in info.get_addresses() {
                                records_string.push_str(&format!("{:?} ", addr));
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


                            assert!(!records.is_empty(), "Expected at least one IPv6 record for {}, found none. Records: {}", hostname, records_string);
                            
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
