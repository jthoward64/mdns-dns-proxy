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
