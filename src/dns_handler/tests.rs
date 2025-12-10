use super::*;
use crate::dns_handler::utils::build_response_from_records;
use crate::mdns_resolver::MdnsResolver;
use hickory_proto::op::ResponseCode;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_should_handle_local_domain_with_trailing_dot() {
    assert!(should_handle_domain("hostname.local."));
    assert!(should_handle_domain("subdomain.hostname.local."));
    assert!(should_handle_domain("my-device.local."));
}

#[test]
fn test_should_handle_local_domain_without_trailing_dot() {
    assert!(should_handle_domain("hostname.local"));
    assert!(should_handle_domain("subdomain.hostname.local"));
}

#[test]
fn test_should_handle_service_discovery_tcp() {
    assert!(should_handle_domain("_http._tcp.local"));
    assert!(should_handle_domain("_http._tcp.local."));
    assert!(should_handle_domain("MyService._http._tcp.local"));
    assert!(should_handle_domain("MyService._http._tcp.local."));
    assert!(should_handle_domain("_ssh._tcp.local"));
}

#[test]
fn test_should_handle_service_discovery_udp() {
    assert!(should_handle_domain("_dns._udp.local"));
    assert!(should_handle_domain("_dns._udp.local."));
    assert!(should_handle_domain("MyService._dns._udp.local"));
}

#[test]
fn test_should_not_handle_regular_domains() {
    assert!(!should_handle_domain("example.com"));
    assert!(!should_handle_domain("www.google.com"));
    assert!(!should_handle_domain("subdomain.example.org"));
    assert!(!should_handle_domain("192.168.1.1"));
}

#[test]
fn test_should_not_handle_similar_but_different_domains() {
    assert!(!should_handle_domain("localhost"));
    assert!(!should_handle_domain("localnet"));
    assert!(!should_handle_domain("mylocal.com"));
    assert!(!should_handle_domain("tcp.local.com"));
}

#[test]
fn test_should_handle_case_sensitivity() {
    // Domain names are case-insensitive, but our function is case-sensitive
    // This tests current behavior
    assert!(should_handle_domain("hostname.local"));
    assert!(should_handle_domain("hostname.LOCAL")); // Still contains .local
    assert!(should_handle_domain("HOSTNAME.local"));
}

#[test]
fn test_should_handle_empty_and_edge_cases() {
    assert!(!should_handle_domain(""));
    assert!(!should_handle_domain("."));
    assert!(!should_handle_domain(".."));
    assert!(should_handle_domain(".local")); // Technically matches
    assert!(should_handle_domain(".local."));
}

#[test]
fn test_should_handle_complex_service_names() {
    assert!(should_handle_domain("My Service (2)._http._tcp.local"));
    assert!(should_handle_domain("Office-Printer._ipp._tcp.local"));
    assert!(should_handle_domain("_device-info._tcp.local"));
}

#[test]
fn test_should_handle_various_tlds() {
    // Should handle .local TLD
    assert!(should_handle_domain("test.local"));
    assert!(should_handle_domain("test.local."));
    
    // Should not handle other TLDs
    assert!(!should_handle_domain("test.com"));
    assert!(!should_handle_domain("test.org"));
    assert!(!should_handle_domain("test.net"));
}

#[test]
fn test_should_handle_subdomain_levels() {
    assert!(should_handle_domain("a.local"));
    assert!(should_handle_domain("a.b.local"));
    assert!(should_handle_domain("a.b.c.local"));
    assert!(should_handle_domain("a.b.c.d.local"));
}

#[test]
fn test_should_handle_service_instance_patterns() {
    // Standard service instance format: instance._service._proto.domain
    assert!(should_handle_domain("MyPrinter._ipp._tcp.local"));
    assert!(should_handle_domain("Living Room TV._googlecast._tcp.local"));
    assert!(should_handle_domain("Office-PC._smb._tcp.local"));
}

#[test]
fn test_should_handle_mixed_case_protocols() {
    assert!(should_handle_domain("service._TCP.local"));
    assert!(should_handle_domain("service._Tcp.local"));
    assert!(should_handle_domain("service._UDP.local"));
    assert!(should_handle_domain("service._Udp.local"));
}

#[test]
fn test_dns_handler_creation() {
    let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
    let handler = MdnsDnsHandler::new(Arc::new(resolver));
    
    // Test that handler correctly identifies domains
    let name = hickory_proto::rr::Name::from_utf8("test.local").unwrap();
    assert!(handler.should_handle(&name));
    
    let name = hickory_proto::rr::Name::from_utf8("test.com").unwrap();
    assert!(!handler.should_handle(&name));
}

#[test]
fn test_should_handle_special_characters() {
    assert!(should_handle_domain("test-device.local"));
    assert!(should_handle_domain("test_device.local"));
    assert!(should_handle_domain("test123.local"));
    assert!(should_handle_domain("123test.local"));
}

#[test]
fn test_should_handle_unicode() {
    // DNS allows unicode in domain names
    assert!(should_handle_domain("münchen.local"));
    assert!(should_handle_domain("日本.local"));
    assert!(should_handle_domain("test-ñ.local"));
}

#[test]
fn test_should_handle_max_length() {
    // DNS labels can be up to 63 characters
    let long_label = "a".repeat(63);
    assert!(should_handle_domain(&format!("{}.local", long_label)));
    
    // With service discovery
    assert!(should_handle_domain(&format!("{}._http._tcp.local", long_label)));
}

#[test]
fn test_build_response_from_records_success_with_records() {
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let name = Name::from_str("test.local.").unwrap();
    let rdata = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 168, 1, 1)));
    let record = Record::from_rdata(name, 300, rdata);
    
    let records = vec![record];
    let result = Ok(records.clone());

    let (response_code, records_opt) = build_response_from_records(result);
    
    assert_eq!(response_code, ResponseCode::NoError);
    assert!(records_opt.is_some());
    assert_eq!(records_opt.unwrap().len(), 1);
}

#[test]
fn test_build_response_from_records_success_empty() {
    let records: Vec<hickory_proto::rr::Record> = vec![];
    let result = Ok(records);

    let (response_code, records_opt) = build_response_from_records(result);
    
    // Per RFC 8766 Section 5.6, empty responses should return NoError not NXDOMAIN
    assert_eq!(response_code, ResponseCode::NoError);
    assert!(records_opt.is_none());
}

#[test]
fn test_build_response_from_records_error() {
    use std::io;

    let error: Box<dyn std::error::Error + Send + Sync> = 
        Box::new(io::Error::new(io::ErrorKind::Other, "test error"));
    let result: Result<Vec<hickory_proto::rr::Record>, _> = Err(error);

    let (response_code, records_opt) = build_response_from_records(result);
    
    assert_eq!(response_code, ResponseCode::ServFail);
    assert!(records_opt.is_none());
}

#[test]
fn test_build_response_from_records_multiple_records() {
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let name = Name::from_str("test.local.").unwrap();
    let rdata1 = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 168, 1, 1)));
    let record1 = Record::from_rdata(name.clone(), 300, rdata1);
    
    let rdata2 = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 168, 1, 2)));
    let record2 = Record::from_rdata(name, 300, rdata2);
    
    let records = vec![record1, record2];
    let result = Ok(records);

    let (response_code, records_opt) = build_response_from_records(result);
    
    assert_eq!(response_code, ResponseCode::NoError);
    assert!(records_opt.is_some());
    assert_eq!(records_opt.unwrap().len(), 2);
}
