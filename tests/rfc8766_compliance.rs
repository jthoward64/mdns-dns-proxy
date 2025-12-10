use std::time::Duration;

use hickory_proto::rr::{Name, Record, RecordType, RData};
use mdns_dns_proxy::MdnsResolver;
use mdns_sd::ServiceDaemon;
use serial_test::serial;
use std::sync::Arc;

/// Test that TTLs are capped at 10 seconds per RFC 8766 Section 5.5.1
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_ttl_capping_at_10_seconds() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let resolver = MdnsResolver::with_daemon(daemon, Duration::from_secs(120))
        .expect("failed to create resolver");
    
    // Query for any record type - the TTL should be capped
    let query_name = Name::from_utf8("_services._dns-sd._udp.local.").expect("invalid hostname");
    let records = resolver.query(&query_name, RecordType::PTR).await
        .expect("query failed");
    
    // Verify all TTLs are <= 10 seconds per RFC 8766
    for record in &records {
        assert!(
            record.ttl() <= 10,
            "TTL {} exceeds maximum of 10 seconds per RFC 8766 Section 5.5.1",
            record.ttl()
        );
    }
}

/// Test SOA record generation per RFC 8766 Section 6.1
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_soa_record_compliance() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let resolver = MdnsResolver::with_daemon(daemon, Duration::from_secs(5))
        .expect("failed to create resolver");
    
    let query_name = Name::from_utf8("local.").expect("invalid hostname");
    let records = resolver.query(&query_name, RecordType::SOA).await
        .expect("query failed");
    
    assert!(!records.is_empty(), "SOA query should return a record");
    
    let soa_record = &records[0];
    
    // Verify TTL is capped at 10 seconds
    assert_eq!(soa_record.ttl(), 10, "SOA TTL should be 10 seconds");
    
    // Verify it's an SOA record
    if let RData::SOA(soa) = soa_record.data() {
        // Per RFC 8766 Section 6.1:
        // - SERIAL must be zero
        assert_eq!(soa.serial(), 0, "SOA SERIAL must be zero per RFC 8766");
        
        // - REFRESH should be 7200
        assert_eq!(soa.refresh(), 7200, "SOA REFRESH should be 7200");
        
        // - RETRY should be 3600
        assert_eq!(soa.retry(), 3600, "SOA RETRY should be 3600");
        
        // - EXPIRE should be 86400
        assert_eq!(soa.expire(), 86400, "SOA EXPIRE should be 86400");
        
        // - MINIMUM (negative caching TTL) should be 10
        assert_eq!(soa.minimum(), 10, "SOA MINIMUM should be 10 per RFC 8766 Section 5.5.1");
    } else {
        panic!("Expected SOA record, got {:?}", soa_record.data());
    }
}

/// Test NS record generation per RFC 8766 Section 6.2
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_ns_record_compliance() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let resolver = MdnsResolver::with_daemon(daemon, Duration::from_secs(5))
        .expect("failed to create resolver");
    
    let query_name = Name::from_utf8("local.").expect("invalid hostname");
    let records = resolver.query(&query_name, RecordType::NS).await
        .expect("query failed");
    
    assert!(!records.is_empty(), "NS query should return at least one record");
    
    let ns_record = &records[0];
    
    // Verify TTL is capped at 10 seconds
    assert_eq!(ns_record.ttl(), 10, "NS TTL should be 10 seconds");
    
    // Verify it's an NS record
    assert!(
        matches!(ns_record.data(), RData::NS(_)),
        "Expected NS record, got {:?}",
        ns_record.data()
    );
}

/// Test that empty responses return NoError not NXDOMAIN per RFC 8766 Section 5.6
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_noerror_for_empty_responses() {
    use mdns_dns_proxy::dns_handler::utils::build_response_from_records;
    use hickory_proto::op::ResponseCode;
    
    // Test empty result returns NoError
    let empty_result = Ok(Vec::new());
    let (code, records) = build_response_from_records(empty_result);
    
    assert_eq!(
        code,
        ResponseCode::NoError,
        "Empty responses should return NoError per RFC 8766 Section 5.6, not NXDOMAIN"
    );
    assert!(records.is_none(), "Empty result should have no records");
}

/// Test that non-empty responses return NoError with records
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_noerror_for_successful_responses() {
    use mdns_dns_proxy::dns_handler::utils::build_response_from_records;
    use hickory_proto::op::ResponseCode;
    
    // Create a dummy record
    let name = Name::from_utf8("test.local.").expect("invalid name");
    let record = Record::from_rdata(
        name,
        10,
        RData::A(hickory_proto::rr::rdata::A::from(std::net::Ipv4Addr::new(192, 168, 1, 1))),
    );
    
    let result = Ok(vec![record]);
    let (code, records) = build_response_from_records(result);
    
    assert_eq!(code, ResponseCode::NoError, "Successful responses should return NoError");
    assert!(records.is_some(), "Successful result should have records");
    assert_eq!(records.unwrap().len(), 1, "Should have one record");
}

/// Test that errors return ServFail
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_servfail_for_errors() {
    use mdns_dns_proxy::dns_handler::utils::build_response_from_records;
    use hickory_proto::op::ResponseCode;
    
    let error_result: Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> = 
        Err("test error".into());
    let (code, records) = build_response_from_records(error_result);
    
    assert_eq!(code, ResponseCode::ServFail, "Errors should return ServFail");
    assert!(records.is_none(), "Error result should have no records");
}

/// Test TTL capping works for all record types
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_ttl_capping_all_record_types() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let resolver = MdnsResolver::with_daemon(daemon, Duration::from_secs(5))
        .expect("failed to create resolver");
    
    let test_cases = vec![
        (Name::from_utf8("local.").unwrap(), RecordType::SOA),
        (Name::from_utf8("local.").unwrap(), RecordType::NS),
        (Name::from_utf8("_services._dns-sd._udp.local.").unwrap(), RecordType::PTR),
    ];
    
    for (name, rtype) in test_cases {
        let records = resolver.query(&name, rtype).await.expect("query failed");
        
        for record in &records {
            assert!(
                record.ttl() <= 10,
                "TTL {} for {:?} record exceeds 10 seconds",
                record.ttl(),
                rtype
            );
        }
    }
}

/// Test that SOA records have correct structure
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_soa_record_structure() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let resolver = MdnsResolver::with_daemon(daemon, Duration::from_secs(5))
        .expect("failed to create resolver");
    
    let query_name = Name::from_utf8("test.local.").expect("invalid hostname");
    let records = resolver.query(&query_name, RecordType::SOA).await
        .expect("query failed");
    
    assert_eq!(records.len(), 1, "Should return exactly one SOA record");
    
    let soa_record = &records[0];
    
    // Verify owner name matches query
    assert_eq!(soa_record.name(), &query_name, "SOA owner name should match query");
    
    // Verify record type
    assert_eq!(soa_record.record_type(), RecordType::SOA, "Record type should be SOA");
}

/// Test that NS records have correct structure  
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_ns_record_structure() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let resolver = MdnsResolver::with_daemon(daemon, Duration::from_secs(5))
        .expect("failed to create resolver");
    
    let query_name = Name::from_utf8("test.local.").expect("invalid hostname");
    let records = resolver.query(&query_name, RecordType::NS).await
        .expect("query failed");
    
    assert_eq!(records.len(), 1, "Should return exactly one NS record");
    
    let ns_record = &records[0];
    
    // Verify owner name matches query
    assert_eq!(ns_record.name(), &query_name, "NS owner name should match query");
    
    // Verify record type
    assert_eq!(ns_record.record_type(), RecordType::NS, "Record type should be NS");
    
    // Verify NS target is valid
    if let RData::NS(ns) = ns_record.data() {
        assert!(!ns.0.is_empty(), "NS target should not be empty");
        assert!(ns.0.to_utf8().ends_with(".local."), "NS target should end with .local.");
    } else {
        panic!("Expected NS record");
    }
}

// ============================================================================
// RFC 8766 Section 5.2.1 - Domain Enumeration via Unicast Queries
// ============================================================================

/// Test domain enumeration query detection (REQ-5.2.1.1-5.2.1.3)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_domain_enumeration_query_detection() {
    use mdns_dns_proxy::dns_handler::admin_records::is_domain_enumeration_query;
    
    // Browse domains query (b._dns-sd._udp)
    let name = Name::from_utf8("b._dns-sd._udp.local.").expect("invalid name");
    assert!(
        is_domain_enumeration_query(&name, RecordType::PTR),
        "b._dns-sd._udp.local. should be recognized as domain enumeration query"
    );
    
    // Default browse domain query (db._dns-sd._udp)
    let name = Name::from_utf8("db._dns-sd._udp.local.").expect("invalid name");
    assert!(
        is_domain_enumeration_query(&name, RecordType::PTR),
        "db._dns-sd._udp.local. should be recognized as domain enumeration query"
    );
    
    // Legacy browse domain query (lb._dns-sd._udp)
    let name = Name::from_utf8("lb._dns-sd._udp.local.").expect("invalid name");
    assert!(
        is_domain_enumeration_query(&name, RecordType::PTR),
        "lb._dns-sd._udp.local. should be recognized as domain enumeration query"
    );
    
    // Regular service query should not be domain enumeration
    let name = Name::from_utf8("_http._tcp.local.").expect("invalid name");
    assert!(
        !is_domain_enumeration_query(&name, RecordType::PTR),
        "_http._tcp.local. should NOT be recognized as domain enumeration query"
    );
}

// ============================================================================
// RFC 8766 Section 6.3 - DNS Delegation Records
// ============================================================================

/// Test delegation query detection below zone apex (REQ-6.3.2-6.3.4)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_delegation_query_below_apex() {
    use mdns_dns_proxy::dns_handler::admin_records::is_delegation_query_below_apex;
    
    let apex = Name::from_utf8("local.").expect("invalid name");
    
    // SOA query below apex should return true (REQ-6.3.2)
    let name = Name::from_utf8("test.local.").expect("invalid name");
    assert!(
        is_delegation_query_below_apex(&name, RecordType::SOA, &apex),
        "SOA query below zone apex should be detected"
    );
    
    // NS query below apex should return true (REQ-6.3.3)
    assert!(
        is_delegation_query_below_apex(&name, RecordType::NS, &apex),
        "NS query below zone apex should be detected"
    );
    
    // DS query below apex should return true (REQ-6.3.4)
    assert!(
        is_delegation_query_below_apex(&name, RecordType::DS, &apex),
        "DS query below zone apex should be detected"
    );
    
    // Query at apex should return false
    let name = Name::from_utf8("local.").expect("invalid name");
    assert!(
        !is_delegation_query_below_apex(&name, RecordType::SOA, &apex),
        "SOA query at zone apex should NOT be detected as below apex"
    );
    
    // A query should return false regardless of position
    let name = Name::from_utf8("test.local.").expect("invalid name");
    assert!(
        !is_delegation_query_below_apex(&name, RecordType::A, &apex),
        "A query should NOT be detected as delegation query"
    );
}

// ============================================================================
// RFC 8766 Section 6.4 - DNS SRV Records
// ============================================================================

/// Test administrative SRV query detection (REQ-6.4.1-6.4.8)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_admin_srv_query_detection() {
    use mdns_dns_proxy::dns_handler::admin_records::{is_admin_srv_query, is_negative_admin_srv_query};
    
    // LLQ SRV queries (REQ-6.4.2-6.4.4)
    let name = Name::from_utf8("_dns-llq._udp.local.").expect("invalid name");
    assert!(
        is_admin_srv_query(&name, RecordType::SRV),
        "_dns-llq._udp should be recognized as admin SRV query"
    );
    
    let name = Name::from_utf8("_dns-llq._tcp.local.").expect("invalid name");
    assert!(
        is_admin_srv_query(&name, RecordType::SRV),
        "_dns-llq._tcp should be recognized as admin SRV query"
    );
    
    let name = Name::from_utf8("_dns-llq-tls._tcp.local.").expect("invalid name");
    assert!(
        is_admin_srv_query(&name, RecordType::SRV),
        "_dns-llq-tls._tcp should be recognized as admin SRV query"
    );
    
    // DNS Push SRV query (REQ-6.4.5)
    let name = Name::from_utf8("_dns-push-tls._tcp.local.").expect("invalid name");
    assert!(
        is_admin_srv_query(&name, RecordType::SRV),
        "_dns-push-tls._tcp should be recognized as admin SRV query"
    );
    
    // DNS Update SRV queries - should be negative (REQ-6.4.6-6.4.8)
    let name = Name::from_utf8("_dns-update._udp.local.").expect("invalid name");
    assert!(
        is_admin_srv_query(&name, RecordType::SRV),
        "_dns-update._udp should be recognized as admin SRV query"
    );
    assert!(
        is_negative_admin_srv_query(&name),
        "_dns-update._udp should return negative response"
    );
    
    let name = Name::from_utf8("_dns-update._tcp.local.").expect("invalid name");
    assert!(
        is_negative_admin_srv_query(&name),
        "_dns-update._tcp should return negative response"
    );
    
    let name = Name::from_utf8("_dns-update-tls._tcp.local.").expect("invalid name");
    assert!(
        is_negative_admin_srv_query(&name),
        "_dns-update-tls._tcp should return negative response"
    );
    
    // Regular service SRV query should NOT be admin
    let name = Name::from_utf8("_http._tcp.local.").expect("invalid name");
    assert!(
        !is_admin_srv_query(&name, RecordType::SRV),
        "_http._tcp should NOT be recognized as admin SRV query"
    );
}

// ============================================================================
// RFC 8766 Section 5.5.2 - Suppressing Unusable Records
// ============================================================================

/// Test IPv4 link-local detection (REQ-5.5.2.2)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_ipv4_link_local_detection() {
    use mdns_dns_proxy::dns_handler::admin_records::is_ipv4_link_local;
    use std::net::Ipv4Addr;
    
    // Link-local addresses (169.254/16)
    assert!(is_ipv4_link_local(&Ipv4Addr::new(169, 254, 0, 1)));
    assert!(is_ipv4_link_local(&Ipv4Addr::new(169, 254, 255, 255)));
    assert!(is_ipv4_link_local(&Ipv4Addr::new(169, 254, 100, 50)));
    
    // Non-link-local addresses
    assert!(!is_ipv4_link_local(&Ipv4Addr::new(192, 168, 1, 1)));
    assert!(!is_ipv4_link_local(&Ipv4Addr::new(10, 0, 0, 1)));
    assert!(!is_ipv4_link_local(&Ipv4Addr::new(172, 16, 0, 1)));
    assert!(!is_ipv4_link_local(&Ipv4Addr::new(8, 8, 8, 8)));
}

/// Test IPv6 ULA detection (REQ-5.5.2.4)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_ipv6_ula_detection() {
    use mdns_dns_proxy::dns_handler::admin_records::is_ipv6_ula;
    
    // ULA addresses (fc00::/7 = fc00:: to fdff::)
    assert!(is_ipv6_ula(&"fc00::1".parse().unwrap()));
    assert!(is_ipv6_ula(&"fd00::1".parse().unwrap()));
    assert!(is_ipv6_ula(&"fd12:3456:789a::1".parse().unwrap()));
    
    // Non-ULA addresses
    assert!(!is_ipv6_ula(&"2001:db8::1".parse().unwrap()));
    assert!(!is_ipv6_ula(&"fe80::1".parse().unwrap()));
    assert!(!is_ipv6_ula(&"::1".parse().unwrap()));
}

/// Test IPv6 link-local detection
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_ipv6_link_local_detection() {
    use mdns_dns_proxy::dns_handler::admin_records::is_ipv6_link_local;
    
    // Link-local addresses (fe80::/10)
    assert!(is_ipv6_link_local(&"fe80::1".parse().unwrap()));
    assert!(is_ipv6_link_local(&"fe80::1234:5678:abcd:ef01".parse().unwrap()));
    
    // Non-link-local addresses
    assert!(!is_ipv6_link_local(&"2001:db8::1".parse().unwrap()));
    assert!(!is_ipv6_link_local(&"fc00::1".parse().unwrap()));
    assert!(!is_ipv6_link_local(&"::1".parse().unwrap()));
}

/// Test record suppression configuration (REQ-5.5.2.1)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_record_suppression_config() {
    use mdns_dns_proxy::dns_handler::admin_records::{RecordSuppressionConfig, should_suppress_address_record};
    use hickory_proto::rr::rdata::A;
    use std::net::{IpAddr, Ipv4Addr};
    
    let name = Name::from_utf8("test.local.").expect("invalid name");
    let link_local_record = Record::from_rdata(
        name.clone(),
        10,
        RData::A(A::from(Ipv4Addr::new(169, 254, 1, 1))),
    );
    
    // With suppression disabled, link-local should NOT be suppressed
    let config = RecordSuppressionConfig {
        enabled: false,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    };
    assert!(
        !should_suppress_address_record(&link_local_record, &config),
        "Link-local should NOT be suppressed when suppression is disabled"
    );
    
    // With suppression enabled and remote client, link-local SHOULD be suppressed
    let config = RecordSuppressionConfig {
        enabled: true,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    };
    assert!(
        should_suppress_address_record(&link_local_record, &config),
        "Link-local SHOULD be suppressed for remote client"
    );
    
    // Regular private IP should NOT be suppressed
    let private_record = Record::from_rdata(
        name,
        10,
        RData::A(A::from(Ipv4Addr::new(192, 168, 1, 1))),
    );
    assert!(
        !should_suppress_address_record(&private_record, &config),
        "Private IP should NOT be suppressed"
    );
}

// ============================================================================
// RFC 8766 Section 6.5 - Domain Enumeration Records
// ============================================================================

/// Test domain enumeration record generation (REQ-6.5.1)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_domain_enumeration_record_generation() {
    use mdns_dns_proxy::dns_handler::admin_records::generate_domain_enumeration_records;
    
    let query_name = Name::from_utf8("b._dns-sd._udp.local.").expect("invalid name");
    let apex = Name::from_utf8("local.").expect("invalid name");
    
    let records = generate_domain_enumeration_records(&query_name, &apex);
    
    assert_eq!(records.len(), 1, "Should return one PTR record");
    
    let ptr_record = &records[0];
    assert_eq!(ptr_record.name(), &query_name);
    
    if let RData::PTR(ptr) = ptr_record.data() {
        assert_eq!(ptr.0, apex, "PTR should point to the zone apex");
    } else {
        panic!("Expected PTR record");
    }
}
