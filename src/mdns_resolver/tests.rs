use super::*;
use cache::{Cache, CacheEntry};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::Ipv4Addr;
use std::time::Duration;

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
}

#[test]
fn test_resolver_with_custom_ttl() {
    let resolver = MdnsResolver::new(Duration::from_secs(300)).unwrap();
    assert_eq!(resolver.cache.ttl(), Duration::from_secs(300));
}

#[tokio::test]
async fn test_cache_miss_on_empty_cache() {
    let cache = Cache::new(Duration::from_secs(120));
    let cached = cache.get("test.local");
    assert!(cached.is_none());
}

#[tokio::test]
async fn test_cache_hit_after_insert() {
    let cache = Cache::new(Duration::from_secs(120));
    let records = vec![create_test_record("test.local", 120)];
    
    cache.insert("test.local", records.clone());
    
    let cached = cache.get("test.local");
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().len(), 1);
}

#[tokio::test]
async fn test_cache_expiration() {
    let cache = Cache::new(Duration::from_millis(100));
    let records = vec![create_test_record("test.local", 120)];
    
    cache.insert("test.local", records);
    
    // Should be cached immediately
    assert!(cache.get("test.local").is_some());
    
    // Wait for cache to expire
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    // Should be expired now
    assert!(cache.get("test.local").is_none());
}

#[tokio::test]
async fn test_cache_multiple_entries() {
    let cache = Cache::new(Duration::from_secs(120));
    
    cache.insert("host1.local", vec![create_test_record("host1.local", 120)]);
    cache.insert("host2.local", vec![create_test_record("host2.local", 120)]);
    cache.insert("host3.local", vec![create_test_record("host3.local", 120)]);
    
    assert!(cache.get("host1.local").is_some());
    assert!(cache.get("host2.local").is_some());
    assert!(cache.get("host3.local").is_some());
    assert!(cache.get("host4.local").is_none());
}

#[tokio::test]
async fn test_cache_overwrites_existing() {
    let cache = Cache::new(Duration::from_secs(120));
    
    let records1 = vec![create_test_record("test.local", 120)];
    let records2 = vec![
        create_test_record("test.local", 120),
        create_test_record("test.local", 120),
    ];
    
    cache.insert("test.local", records1);
    assert_eq!(cache.get("test.local").unwrap().len(), 1);
    
    cache.insert("test.local", records2);
    assert_eq!(cache.get("test.local").unwrap().len(), 2);
}

#[tokio::test]
async fn test_cache_cleanup_on_insert() {
    let cache = Cache::new(Duration::from_millis(100));
    
    // Add some entries
    cache.insert("host1.local", vec![create_test_record("host1.local", 120)]);
    cache.insert("host2.local", vec![create_test_record("host2.local", 120)]);
    
    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    // Add a new entry, which should trigger cleanup
    cache.insert("host3.local", vec![create_test_record("host3.local", 120)]);
    
    // Old entries should be gone
    assert!(cache.get("host1.local").is_none());
    assert!(cache.get("host2.local").is_none());
    // New entry should exist
    assert!(cache.get("host3.local").is_some());
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
}

#[tokio::test]
async fn test_cache_key_case_sensitivity() {
    let cache = Cache::new(Duration::from_secs(120));
    let records = vec![create_test_record("test.local", 120)];
    
    cache.insert("test.local", records.clone());
    
    // Same key should hit cache
    assert!(cache.get("test.local").is_some());
    
    // Different case should miss (cache is case-sensitive)
    assert!(cache.get("TEST.LOCAL").is_none());
    assert!(cache.get("Test.Local").is_none());
}

#[tokio::test]
async fn test_empty_cache_returns_none() {
    let cache = Cache::new(Duration::from_secs(120));
    
    assert!(cache.get("nonexistent.local").is_none());
    assert!(cache.get("").is_none());
    assert!(cache.get("any.domain.local").is_none());
}

#[tokio::test]
async fn test_cache_ttl_zero() {
    let cache = Cache::new(Duration::from_secs(0));
    let records = vec![create_test_record("test.local", 120)];
    
    cache.insert("test.local", records);
    
    // With 0 TTL, cache should effectively be disabled
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(cache.get("test.local").is_none());
}

#[tokio::test]
async fn test_cache_with_empty_records() {
    let cache = Cache::new(Duration::from_secs(120));
    
    // Cache empty vector
    cache.insert("test.local", vec![]);
    
    // Should return empty vector, not None
    let cached = cache.get("test.local");
    assert!(cached.is_some());
    assert!(cached.unwrap().is_empty());
}

#[tokio::test]
async fn test_multiple_records_for_same_name() {
    let cache = Cache::new(Duration::from_secs(120));
    
    let records = vec![
        create_test_record("test.local", 120),
        create_test_record("test.local", 120),
        create_test_record("test.local", 120),
    ];
    
    cache.insert("test.local", records);
    
    let cached = cache.get("test.local");
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
    let name = Name::from_utf8("test.local").unwrap();
    
    // Should still work with very long TTL
    let result = resolver.query(&name, RecordType::A).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_concurrent_cache_access() {
    use std::sync::Arc;
    
    let cache = Arc::new(Cache::new(Duration::from_secs(120)));
    let records = vec![create_test_record("test.local", 120)];
    
    cache.insert("test.local", records);
    
    // Spawn multiple tasks accessing cache concurrently
    let mut handles = vec![];
    for _ in 0..10 {
        let cache_clone = cache.clone();
        let handle = tokio::spawn(async move {
            cache_clone.get("test.local")
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
