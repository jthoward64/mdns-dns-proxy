use crate::config::Config;
use hickory_proto::rr::{domain::Label, Name, RData, Record};
use mdns_sd::{HostnameResolutionEvent, ServiceDaemon, ServiceEvent};
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Query for A records (IPv4)
pub async fn query_a_aaaa(
    daemon: &ServiceDaemon,
    name: &Name,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let hostname = name.to_utf8().to_lowercase();
    let hostname_unescaped = unescape_instance_label(&hostname);

    // Check if this is a .local query
    if hostname.strip_suffix(".").unwrap_or(&hostname).split(".").last().unwrap_or("") != "local" {
        return Ok(Vec::new());
    }

    // Try to resolve as a service instance or hostname
    resolve_hostname(daemon, &hostname_unescaped, config).await
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
                        let target_name = name_from_labels_str(info.get_fullname())?;

                        let record = Record::from_rdata(
                            ptr_name,
                            120, // TTL
                            RData::PTR(hickory_proto::rr::rdata::PTR(target_name)),
                        );

                        records.push(record);

                        info!("Added PTR record for {}", info.get_fullname());
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

    debug!("Browsing for service type: {}", service_type);

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
                // Compare case-insensitively and normalize escaped/unescaped instance labels
                let unescaped_query = unescape_instance_label(&service_name).to_lowercase();
                let escaped_query = escape_instance_label(&unescaped_query);

                let info_fullname = info.get_fullname();
                let info_fullname_lc = info_fullname.to_lowercase();
                let escaped_info_fullname = escape_instance_label(&info_fullname_lc);

                debug!("Comparing queried service name '{}' (escaped: '{}') with resolved service name '{}' (escaped: '{}')",
                    unescaped_query, escaped_query, info_fullname_lc, escaped_info_fullname);

                if info_fullname_lc == unescaped_query || escaped_info_fullname == escaped_query {
                    let srv_name = name.clone();
                    let target = Name::from_utf8(info.get_hostname())?;

                    let record = Record::from_rdata(
                        srv_name,
                        120,
                        RData::SRV(hickory_proto::rr::rdata::SRV::new(
                            0,               // priority
                            0,               // weight
                            info.get_port(), // port
                            target,          // target hostname
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
                // Compare case-insensitively and normalize escaped/unescaped instance labels
                let unescaped_query = unescape_instance_label(&service_name).to_lowercase();
                let escaped_query = escape_instance_label(&unescaped_query);

                let info_fullname = info.get_fullname();
                let info_fullname_lc = info_fullname.to_lowercase();
                let escaped_info_fullname = escape_instance_label(&info_fullname_lc);

                if info_fullname_lc == unescaped_query || escaped_info_fullname == escaped_query {
                    let txt_name = name.clone();

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
async fn resolve_hostname(
    daemon: &ServiceDaemon,
    hostname: &str,
    config: &Config,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let mut records = Vec::new();

    if let Ok(receiver) = daemon.resolve_hostname(
        hostname,
        Some(config.hostname_resolution_timeout().as_millis() as u64),
    ) {
        let now = std::time::Instant::now();
        let deadline = now + config.hostname_resolution_timeout();

        loop {
            // Wait for the smaller of poll_interval or the remaining time
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                break;
            }

            match receiver.recv_async().await {
                Ok(HostnameResolutionEvent::SearchStarted(_)) => {
                    debug!("Hostname resolution started for {}", hostname);
                }
                Ok(HostnameResolutionEvent::SearchStopped(_)) => {
                    debug!("Hostname resolution stopped for {}", hostname);
                }
                Ok(HostnameResolutionEvent::AddressesFound(_, addresses)) => {
                    for addr in addresses {
                        match addr {
                            mdns_sd::ScopedIp::V4(ipv4) => {
                                let ipv4_addr = ipv4.addr();
                                let name = name_from_labels_str(hostname)?;
                                let record = Record::from_rdata(
                                    name,
                                    120,
                                    RData::A(hickory_proto::rr::rdata::A::from(*ipv4_addr)),
                                );
                                records.push(record);

                                debug!("Found IPv4 address for {}: {}", hostname, ipv4_addr);
                            }
                            mdns_sd::ScopedIp::V6(ipv6) => {
                                let ipv6_addr = ipv6.addr();
                                let name = name_from_labels_str(hostname)?;
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
                }
                Ok(HostnameResolutionEvent::AddressesRemoved(_, addresses)) => {
                    for addr in addresses {
                        // Remove matching records from the results
                        records.retain(|record| match &addr {
                            mdns_sd::ScopedIp::V4(ipv4) => {
                                if let RData::A(a) = record.data() {
                                    a.0 != *ipv4.addr()
                                } else {
                                    true
                                }
                            }
                            mdns_sd::ScopedIp::V6(ipv6) => {
                                if let RData::AAAA(aaaa) = record.data() {
                                    aaaa.0 != *ipv6.addr()
                                } else {
                                    true
                                }
                            }
                            _ => true,
                        });
                        debug!("Removed address from results for {}: {:?} after {}", hostname, addr, config.hostname_resolution_timeout().as_secs_f32());
                    }
                }
                Ok(HostnameResolutionEvent::SearchTimeout(_)) => {
                    debug!("Hostname resolution timed out for {}", hostname);
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    error!("Error during hostname resolution for {}: {}", hostname, e);
                }
            }
        }
    }

    // Deduplicate records
    records.sort_by(|a, b| a.data().cmp(b.data()));
    records.dedup_by(|a, b| a.data() == b.data());
    Ok(records)
}

/// Escape the instance label (first label) of an mDNS fullname so Hickory accepts it as DNS.
/// Spaces are turned into "\032" per DNS escaping rules; other labels are left untouched.
fn escape_instance_label(fullname: &str) -> String {
    let mut parts: Vec<String> = fullname.split('.').map(str::to_string).collect();
    if let Some(first) = parts.first_mut() {
        *first = first.replace(' ', "\\032");
    }
    parts.join(".")
}

/// Inverse of escape_instance_label for comparison: "\032" back to space in the first label.
fn unescape_instance_label(fullname: &str) -> String {
    let mut parts: Vec<String> = fullname.split('.').map(str::to_string).collect();
    if let Some(first) = parts.first_mut() {
        *first = first.replace("\\032", " ");
    }
    parts.join(".")
}

/// Build a DNS Name from raw labels, permitting spaces by constructing Labels from bytes.
fn name_from_labels_str(fullname: &str) -> Result<Name, Box<dyn std::error::Error + Send + Sync>> {
    let labels: Vec<Label> = fullname
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| Label::from_raw_bytes(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Name::from_labels(labels)?)
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
        mname, rname, 0,     // SERIAL: must be zero per RFC 8766
        7200,  // REFRESH
        3600,  // RETRY
        86400, // EXPIRE
        10,    // MINIMUM: 10 seconds per RFC 8766 Section 5.5.1
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
