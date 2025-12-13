use super::*;
use crate::dns_handler::utils::build_response_from_records;
use crate::mdns_resolver::MdnsResolver;
use hickory_proto::op::ResponseCode;
use std::sync::Arc;

#[test]
fn test_should_handle_domain_with_trailing_dot() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("hostname.{}", dom), dom));
    assert!(should_handle_domain(&format!("subdomain.hostname.{}", dom), dom));
    assert!(should_handle_domain(&format!("my-device.{}", dom), dom));
}

#[test]
fn test_should_handle_domain_without_trailing_dot() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("hostname.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("subdomain.hostname.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_service_discovery_tcp() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("_http._tcp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("_http._tcp.{}", dom), dom));
    assert!(should_handle_domain(&format!("MyService._http._tcp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("MyService._http._tcp.{}", dom), dom));
    assert!(should_handle_domain(&format!("_ssh._tcp.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_service_discovery_udp() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("_dns._udp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("_dns._udp.{}", dom), dom));
    assert!(should_handle_domain(&format!("MyService._dns._udp.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_not_handle_regular_domains() {
    let dom = "mdns.home.arpa.";
    assert!(!should_handle_domain("example.com", dom));
    assert!(!should_handle_domain("www.google.com", dom));
    assert!(!should_handle_domain("subdomain.example.org", dom));
    assert!(!should_handle_domain("192.168.1.1", dom));
}

#[test]
fn test_should_not_handle_similar_but_different_domains() {
    let dom = "mdns.home.arpa.";
    assert!(!should_handle_domain("localhost", dom));
    assert!(!should_handle_domain("localnet", dom));
    assert!(!should_handle_domain("mylocal.com", dom));
    assert!(!should_handle_domain("tcp.local.com", dom));
}

#[test]
fn test_should_handle_case_sensitivity() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("hostname.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("hostname.{}", dom.to_uppercase()), dom));
    assert!(should_handle_domain(&format!("HOSTNAME.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_empty_and_edge_cases() {
    let dom = "mdns.home.arpa.";
    assert!(!should_handle_domain("", dom));
    assert!(!should_handle_domain(".", dom));
    assert!(!should_handle_domain("..", dom));
    assert!(should_handle_domain(dom.trim_start_matches('.'), dom));
    assert!(should_handle_domain(dom, dom));
}

#[test]
fn test_should_handle_complex_service_names() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("My Service (2)._http._tcp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("Office-Printer._ipp._tcp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("_device-info._tcp.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_various_tlds() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("test.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("test.{}", dom), dom));
    assert!(!should_handle_domain("test.com", dom));
    assert!(!should_handle_domain("test.org", dom));
    assert!(!should_handle_domain("test.net", dom));
}

#[test]
fn test_should_handle_subdomain_levels() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("a.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("a.b.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("a.b.c.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("a.b.c.d.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_service_instance_patterns() {
    // Standard service instance format: instance._service._proto.domain
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("MyPrinter._ipp._tcp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("Living Room TV._googlecast._tcp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("Office-PC._smb._tcp.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_mixed_case_protocols() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("service._TCP.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("service._Tcp.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("service._UDP.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("service._Udp.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_dns_handler_creation() {
    let config = crate::config::Config::default();
    let resolver = MdnsResolver::new(Arc::new(config)).unwrap();
    let discovery_domain = "mdns.home.arpa.".to_string();
    let handler = MdnsDnsHandler::new(Arc::new(resolver), discovery_domain.clone());
    
    // Test that handler correctly identifies domains
    let name = hickory_proto::rr::Name::from_utf8(&format!("test.{}", discovery_domain)).unwrap();
    assert!(handler.should_handle(&name));
    
    let name = hickory_proto::rr::Name::from_utf8("test.com").unwrap();
    assert!(!handler.should_handle(&name));
}

#[test]
fn test_should_handle_special_characters() {
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("test-device.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("test_device.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("test123.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("123test.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_unicode() {
    // DNS allows unicode in domain names
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("münchen.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("日本.{}", dom.trim_end_matches('.')), dom));
    assert!(should_handle_domain(&format!("test-ñ.{}", dom.trim_end_matches('.')), dom));
}

#[test]
fn test_should_handle_max_length() {
    // DNS labels can be up to 63 characters
    let long_label = "a".repeat(63);
    let dom = "mdns.home.arpa.";
    assert!(should_handle_domain(&format!("{}.{}", long_label, dom.trim_end_matches('.')), dom));
    
    // With service discovery
    assert!(should_handle_domain(&format!("{}._http._tcp.{}", long_label, dom.trim_end_matches('.')), dom));
}

#[test]
fn test_build_response_from_records_success_with_records() {
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let name = Name::from_str("test.mdns.home.arpa.").unwrap();
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

    let name = Name::from_str("test.mdns.home.arpa.").unwrap();
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
