//! Administrative DNS Records per RFC 8766 Section 6
//!
//! This module handles administrative DNS queries that should be answered
//! directly by the Discovery Proxy without forwarding to Multicast DNS.

use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::rr::rdata::{SOA, NS};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

/// Maximum TTL for administrative records per RFC 8766 Section 5.5.1
const MAX_ADMIN_TTL: u32 = 10;

/// Configuration for suppressing unusable records per RFC 8766 Section 5.5.2
#[derive(Debug, Clone)]
pub struct RecordSuppressionConfig {
    /// Enable suppression of unusable records (default: true per RFC 8766)
    pub enabled: bool,
    /// Client IP address for determining if link-local addresses should be suppressed
    pub client_ip: Option<IpAddr>,
}

impl Default for RecordSuppressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            client_ip: None,
        }
    }
}

/// Check if a query is for domain enumeration per RFC 8766 Section 5.2.1
/// These are PTR queries for:
/// - b._dns-sd._udp.<domain> (browse domains)
/// - db._dns-sd._udp.<domain> (default browse domain)
/// - lb._dns-sd._udp.<domain> (legacy browse domain)
pub fn is_domain_enumeration_query(name: &Name, record_type: RecordType) -> bool {
    if record_type != RecordType::PTR {
        return false;
    }
    
    let name_str = name.to_utf8().to_lowercase();
    
    // Check for domain enumeration patterns
    name_str.starts_with("b._dns-sd._udp.") ||
    name_str.starts_with("db._dns-sd._udp.") ||
    name_str.starts_with("lb._dns-sd._udp.")
}

/// Check if a query is an administrative SRV query per RFC 8766 Section 6.4
/// These queries should be answered immediately without forwarding to mDNS
pub fn is_admin_srv_query(name: &Name, record_type: RecordType) -> bool {
    if record_type != RecordType::SRV {
        return false;
    }
    
    let name_str = name.to_utf8().to_lowercase();
    
    // LLQ-related SRV queries
    name_str.starts_with("_dns-llq._udp.") ||
    name_str.starts_with("_dns-llq._tcp.") ||
    name_str.starts_with("_dns-llq-tls._tcp.") ||
    // DNS Push SRV query
    name_str.starts_with("_dns-push-tls._tcp.") ||
    // DNS Update SRV queries (always negative)
    name_str.starts_with("_dns-update._udp.") ||
    name_str.starts_with("_dns-update._tcp.") ||
    name_str.starts_with("_dns-update-tls._tcp.")
}

/// Check if an administrative delegation query (SOA/NS/DS below zone apex)
/// These should return immediate negative answers per RFC 8766 Section 6.3
pub fn is_delegation_query_below_apex(name: &Name, record_type: RecordType, zone_apex: &Name) -> bool {
    match record_type {
        RecordType::SOA | RecordType::NS | RecordType::DS => {
            // If the query name has more labels than the zone apex, it's below apex
            // zone_apex.zone_of(name) returns true if zone_apex is a zone containing name
            name.num_labels() > zone_apex.num_labels() && zone_apex.zone_of(name)
        }
        _ => false,
    }
}

/// Check if a query is for the zone apex
pub fn is_zone_apex_query(name: &Name, zone_apex: &Name) -> bool {
    name == zone_apex
}

/// Generate SOA record for zone apex per RFC 8766 Section 6.1
pub fn generate_soa_record(name: &Name) -> Record {
    // Per RFC 8766 Section 6.1:
    // - MNAME: host name of the Discovery Proxy device
    // - RNAME: mailbox of the person responsible
    // - SERIAL: MUST be zero
    // - REFRESH: 7200, RETRY: 3600, EXPIRE: 86400 (recommended)
    // - MINIMUM: 10 (negative caching TTL per Section 5.5.1)
    
    let mname = Name::from_utf8("discovery-proxy.local.").unwrap();
    let rname = Name::from_utf8("hostmaster.local.").unwrap();
    
    let soa = SOA::new(
        mname,
        rname,
        0,      // SERIAL: must be zero per RFC 8766
        7200,   // REFRESH
        3600,   // RETRY
        86400,  // EXPIRE
        10,     // MINIMUM: 10 seconds per RFC 8766 Section 5.5.1
    );
    
    Record::from_rdata(
        name.clone(),
        MAX_ADMIN_TTL,
        RData::SOA(soa),
    )
}

/// Generate NS record for zone apex per RFC 8766 Section 6.2
pub fn generate_ns_record(name: &Name) -> Record {
    // Per RFC 8766 Section 6.2:
    // Each Discovery Proxy returns its own NS record
    // NS target host MUST NOT fall within delegated zone (except zone apex)
    
    let ns_name = Name::from_utf8("discovery-proxy.local.").unwrap();
    let ns = NS(ns_name);
    
    Record::from_rdata(
        name.clone(),
        MAX_ADMIN_TTL,
        RData::NS(ns),
    )
}

/// Generate domain enumeration PTR records per RFC 8766 Section 5.2.1 and 6.5
pub fn generate_domain_enumeration_records(name: &Name, zone_apex: &Name) -> Vec<Record> {
    // Return PTR record pointing to the configured zone
    // This tells clients which domains are available for service discovery
    
    let ptr_rdata = RData::PTR(hickory_proto::rr::rdata::PTR(zone_apex.clone()));
    
    vec![Record::from_rdata(
        name.clone(),
        MAX_ADMIN_TTL,
        ptr_rdata,
    )]
}

/// Generate negative response for unsupported administrative SRV queries
/// Per RFC 8766 Section 6.4, DNS Update SRV queries should return negative answers
pub fn is_negative_admin_srv_query(name: &Name) -> bool {
    let name_str = name.to_utf8().to_lowercase();
    
    // DNS Update queries always return negative
    name_str.starts_with("_dns-update._udp.") ||
    name_str.starts_with("_dns-update._tcp.") ||
    name_str.starts_with("_dns-update-tls._tcp.") ||
    // LLQ and DNS Push not currently supported, so return negative
    name_str.starts_with("_dns-llq._udp.") ||
    name_str.starts_with("_dns-llq._tcp.") ||
    name_str.starts_with("_dns-llq-tls._tcp.") ||
    name_str.starts_with("_dns-push-tls._tcp.")
}

/// Check if an IPv4 address is link-local (169.254/16)
/// Per RFC 8766 Section 5.5.2
pub fn is_ipv4_link_local(addr: &Ipv4Addr) -> bool {
    addr.octets()[0] == 169 && addr.octets()[1] == 254
}

/// Check if an IPv6 address is a Unique Local Address (fc00::/7)
/// Per RFC 8766 Section 5.5.2
pub fn is_ipv6_ula(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    (octets[0] & 0xfe) == 0xfc
}

/// Check if an IPv6 address is link-local (fe80::/10)
pub fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// Check if client is on the same local link as the address
/// This is a simplified check - in production, you'd check actual network interfaces
fn is_same_link(client_ip: &IpAddr, target_addr: &IpAddr) -> bool {
    match (client_ip, target_addr) {
        // If client is on loopback, they're local
        (IpAddr::V4(c), _) if c.is_loopback() => true,
        (IpAddr::V6(c), _) if c.is_loopback() => true,
        // Same address family private ranges suggest same network
        (IpAddr::V4(c), IpAddr::V4(t)) => {
            // Check if both are in the same /24 for private ranges
            if c.is_private() && t.is_private() {
                c.octets()[0..3] == t.octets()[0..3]
            } else {
                false
            }
        }
        (IpAddr::V6(c), IpAddr::V6(t)) => {
            // Check if both are link-local on same interface (simplified)
            is_ipv6_link_local(c) && is_ipv6_link_local(t)
        }
        _ => false,
    }
}

/// Suppress unusable address records per RFC 8766 Section 5.5.2
/// Returns true if the record should be suppressed (not returned to client)
pub fn should_suppress_address_record(record: &Record, config: &RecordSuppressionConfig) -> bool {
    if !config.enabled {
        return false;
    }
    
    let client_ip = match &config.client_ip {
        Some(ip) => ip,
        None => return false, // Can't suppress without knowing client
    };
    
    match record.data() {
        RData::A(a) => {
            let addr = a.0;
            // Suppress IPv4 link-local for non-local clients
            if is_ipv4_link_local(&addr) {
                let same_link = is_same_link(client_ip, &IpAddr::V4(addr));
                if !same_link {
                    debug!("Suppressing IPv4 link-local address {} for non-local client", addr);
                    return true;
                }
            }
            false
        }
        RData::AAAA(aaaa) => {
            let addr = aaaa.0;
            // Suppress IPv6 link-local for non-local clients
            if is_ipv6_link_local(&addr) {
                let same_link = is_same_link(client_ip, &IpAddr::V6(addr));
                if !same_link {
                    debug!("Suppressing IPv6 link-local address {} for non-local client", addr);
                    return true;
                }
            }
            // Suppress ULA for non-local clients  
            if is_ipv6_ula(&addr) {
                let same_link = is_same_link(client_ip, &IpAddr::V6(addr));
                if !same_link {
                    debug!("Suppressing IPv6 ULA address {} for non-local client", addr);
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Suppress SRV records that reference link-local target hosts
/// Per RFC 8766 Section 5.5.2.5
pub fn should_suppress_srv_record(record: &Record, address_records: &[Record], config: &RecordSuppressionConfig) -> bool {
    if !config.enabled {
        return false;
    }
    
    if let RData::SRV(srv) = record.data() {
        let target_name = srv.target();
        
        // Check if any address record for this target should be suppressed
        for addr_record in address_records {
            if addr_record.name() == target_name {
                if should_suppress_address_record(addr_record, config) {
                    debug!("Suppressing SRV record referencing link-local target {}", target_name);
                    return true;
                }
            }
        }
    }
    
    false
}

/// Filter records to remove unusable ones per RFC 8766 Section 5.5.2
pub fn filter_suppressed_records(records: Vec<Record>, config: &RecordSuppressionConfig) -> Vec<Record> {
    if !config.enabled {
        return records;
    }
    
    // First pass: identify all address records for SRV target checking
    let address_records: Vec<_> = records.iter()
        .filter(|r| matches!(r.data(), RData::A(_) | RData::AAAA(_)))
        .cloned()
        .collect();
    
    // Second pass: filter records
    records.into_iter()
        .filter(|record| {
            // Check address records
            if matches!(record.data(), RData::A(_) | RData::AAAA(_)) {
                return !should_suppress_address_record(record, config);
            }
            
            // Check SRV records
            if matches!(record.data(), RData::SRV(_)) {
                return !should_suppress_srv_record(record, &address_records, config);
            }
            
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_domain_enumeration_query() {
        // Valid domain enumeration queries
        let name = Name::from_utf8("b._dns-sd._udp.local.").unwrap();
        assert!(is_domain_enumeration_query(&name, RecordType::PTR));
        
        let name = Name::from_utf8("db._dns-sd._udp.local.").unwrap();
        assert!(is_domain_enumeration_query(&name, RecordType::PTR));
        
        let name = Name::from_utf8("lb._dns-sd._udp.local.").unwrap();
        assert!(is_domain_enumeration_query(&name, RecordType::PTR));
        
        // Not domain enumeration (wrong type)
        let name = Name::from_utf8("b._dns-sd._udp.local.").unwrap();
        assert!(!is_domain_enumeration_query(&name, RecordType::A));
        
        // Not domain enumeration (wrong name)
        let name = Name::from_utf8("_http._tcp.local.").unwrap();
        assert!(!is_domain_enumeration_query(&name, RecordType::PTR));
    }

    #[test]
    fn test_is_admin_srv_query() {
        // LLQ queries
        let name = Name::from_utf8("_dns-llq._udp.local.").unwrap();
        assert!(is_admin_srv_query(&name, RecordType::SRV));
        
        let name = Name::from_utf8("_dns-llq._tcp.local.").unwrap();
        assert!(is_admin_srv_query(&name, RecordType::SRV));
        
        let name = Name::from_utf8("_dns-llq-tls._tcp.local.").unwrap();
        assert!(is_admin_srv_query(&name, RecordType::SRV));
        
        // DNS Push query
        let name = Name::from_utf8("_dns-push-tls._tcp.local.").unwrap();
        assert!(is_admin_srv_query(&name, RecordType::SRV));
        
        // DNS Update queries
        let name = Name::from_utf8("_dns-update._udp.local.").unwrap();
        assert!(is_admin_srv_query(&name, RecordType::SRV));
        
        let name = Name::from_utf8("_dns-update._tcp.local.").unwrap();
        assert!(is_admin_srv_query(&name, RecordType::SRV));
        
        let name = Name::from_utf8("_dns-update-tls._tcp.local.").unwrap();
        assert!(is_admin_srv_query(&name, RecordType::SRV));
        
        // Not admin SRV (wrong type)
        let name = Name::from_utf8("_dns-llq._udp.local.").unwrap();
        assert!(!is_admin_srv_query(&name, RecordType::PTR));
        
        // Not admin SRV (regular service)
        let name = Name::from_utf8("_http._tcp.local.").unwrap();
        assert!(!is_admin_srv_query(&name, RecordType::SRV));
    }

    #[test]
    fn test_is_delegation_query_below_apex() {
        let apex = Name::from_utf8("local.").unwrap();
        
        // Below apex - should return true
        let name = Name::from_utf8("test.local.").unwrap();
        assert!(is_delegation_query_below_apex(&name, RecordType::SOA, &apex));
        assert!(is_delegation_query_below_apex(&name, RecordType::NS, &apex));
        assert!(is_delegation_query_below_apex(&name, RecordType::DS, &apex));
        
        // At apex - should return false
        let name = Name::from_utf8("local.").unwrap();
        assert!(!is_delegation_query_below_apex(&name, RecordType::SOA, &apex));
        
        // Wrong type - should return false
        let name = Name::from_utf8("test.local.").unwrap();
        assert!(!is_delegation_query_below_apex(&name, RecordType::A, &apex));
    }

    #[test]
    fn test_is_negative_admin_srv_query() {
        // DNS Update always negative
        let name = Name::from_utf8("_dns-update._udp.local.").unwrap();
        assert!(is_negative_admin_srv_query(&name));
        
        let name = Name::from_utf8("_dns-update._tcp.local.").unwrap();
        assert!(is_negative_admin_srv_query(&name));
        
        // LLQ (not supported currently)
        let name = Name::from_utf8("_dns-llq._udp.local.").unwrap();
        assert!(is_negative_admin_srv_query(&name));
        
        // Regular service - not negative
        let name = Name::from_utf8("_http._tcp.local.").unwrap();
        assert!(!is_negative_admin_srv_query(&name));
    }

    #[test]
    fn test_generate_soa_record() {
        let name = Name::from_utf8("local.").unwrap();
        let record = generate_soa_record(&name);
        
        assert_eq!(record.name(), &name);
        assert_eq!(record.ttl(), MAX_ADMIN_TTL);
        
        if let RData::SOA(soa) = record.data() {
            assert_eq!(soa.serial(), 0);
            assert_eq!(soa.refresh(), 7200);
            assert_eq!(soa.retry(), 3600);
            assert_eq!(soa.expire(), 86400);
            assert_eq!(soa.minimum(), 10);
        } else {
            panic!("Expected SOA record");
        }
    }

    #[test]
    fn test_generate_ns_record() {
        let name = Name::from_utf8("local.").unwrap();
        let record = generate_ns_record(&name);
        
        assert_eq!(record.name(), &name);
        assert_eq!(record.ttl(), MAX_ADMIN_TTL);
        assert!(matches!(record.data(), RData::NS(_)));
    }

    #[test]
    fn test_is_ipv4_link_local() {
        assert!(is_ipv4_link_local(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_ipv4_link_local(&Ipv4Addr::new(169, 254, 255, 255)));
        assert!(!is_ipv4_link_local(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_ipv4_link_local(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_is_ipv6_ula() {
        assert!(is_ipv6_ula(&"fc00::1".parse().unwrap()));
        assert!(is_ipv6_ula(&"fd12:3456:789a::1".parse().unwrap()));
        assert!(!is_ipv6_ula(&"2001:db8::1".parse().unwrap()));
        assert!(!is_ipv6_ula(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_is_ipv6_link_local() {
        assert!(is_ipv6_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_ipv6_link_local(&"fe80::1234:5678:abcd:ef01".parse().unwrap()));
        assert!(!is_ipv6_link_local(&"2001:db8::1".parse().unwrap()));
        assert!(!is_ipv6_link_local(&"fc00::1".parse().unwrap()));
    }

    #[test]
    fn test_should_suppress_address_record_disabled() {
        let config = RecordSuppressionConfig {
            enabled: false,
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        };
        
        let name = Name::from_utf8("test.local.").unwrap();
        let record = Record::from_rdata(
            name,
            10,
            RData::A(hickory_proto::rr::rdata::A::from(Ipv4Addr::new(169, 254, 1, 1))),
        );
        
        // Should not suppress when disabled
        assert!(!should_suppress_address_record(&record, &config));
    }

    #[test]
    fn test_should_suppress_ipv4_link_local() {
        let config = RecordSuppressionConfig {
            enabled: true,
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), // Remote client
        };
        
        let name = Name::from_utf8("test.local.").unwrap();
        let record = Record::from_rdata(
            name.clone(),
            10,
            RData::A(hickory_proto::rr::rdata::A::from(Ipv4Addr::new(169, 254, 1, 1))),
        );
        
        // Should suppress link-local for remote client
        assert!(should_suppress_address_record(&record, &config));
        
        // Should not suppress regular private address
        let record = Record::from_rdata(
            name,
            10,
            RData::A(hickory_proto::rr::rdata::A::from(Ipv4Addr::new(192, 168, 1, 1))),
        );
        assert!(!should_suppress_address_record(&record, &config));
    }

    #[test]
    fn test_generate_domain_enumeration_records() {
        let name = Name::from_utf8("b._dns-sd._udp.local.").unwrap();
        let apex = Name::from_utf8("local.").unwrap();
        
        let records = generate_domain_enumeration_records(&name, &apex);
        
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name(), &name);
        
        if let RData::PTR(ptr) = records[0].data() {
            assert_eq!(ptr.0, apex);
        } else {
            panic!("Expected PTR record");
        }
    }
}
