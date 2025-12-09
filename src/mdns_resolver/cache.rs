use hickory_proto::rr::{Record, RecordType};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Cache entry for mDNS query results
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub records: Vec<Record>,
    pub timestamp: std::time::Instant,
}

/// Cache for mDNS query results
pub struct Cache {
    data: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Duration,
}

impl Cache {
    /// Create a new cache with the given TTL
    pub fn new(ttl: Duration) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Get cached records if still valid
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<Vec<Record>> {
        let cache = self.data.read().unwrap();
        let cache_key = Self::make_key(name, record_type);
        
        if let Some(entry) = cache.get(&cache_key) {
            if entry.timestamp.elapsed() < self.ttl {
                return Some(entry.records.clone());
            }
        }
        
        None
    }

    /// Cache query results
    pub fn insert(&self, name: &str, record_type: RecordType, records: Vec<Record>) {
        let mut cache = self.data.write().unwrap();
        let cache_key = Self::make_key(name, record_type);
        
        cache.insert(
            cache_key,
            CacheEntry {
                records,
                timestamp: std::time::Instant::now(),
            },
        );
        
        // Clean up old entries
        cache.retain(|_, entry| entry.timestamp.elapsed() < self.ttl);
    }

    /// Get the TTL for this cache
    #[allow(dead_code)]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Create a cache key from name and record type
    fn make_key(name: &str, record_type: RecordType) -> String {
        format!("{}:{:?}", name, record_type)
    }
}
