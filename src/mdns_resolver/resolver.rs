use hickory_proto::rr::{Name, Record, RecordType};
use mdns_sd::ServiceDaemon;
use std::time::Duration;
use tracing::{debug, warn};

use super::cache::Cache;
use super::query;

/// mDNS resolver that bridges DNS queries to mDNS
pub struct MdnsResolver {
    daemon: ServiceDaemon,
    pub(crate) cache: Cache,
}

impl MdnsResolver {
    /// Create a new mDNS resolver
    pub fn new(cache_ttl: Duration) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let daemon = ServiceDaemon::new()?;
        
        Ok(Self {
            daemon,
            cache: Cache::new(cache_ttl),
        })
    }

    /// Query mDNS for a given name and record type
    pub async fn query(
        &self,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
        let query_name = name.to_utf8();
        
        debug!("Querying mDNS for {} (type: {:?})", query_name, record_type);

        // Check cache first
        if let Some(cached) = self.cache.get(&query_name, record_type) {
            debug!("Returning cached results for {} (type: {:?})", query_name, record_type);
            return Ok(cached);
        }

        // Perform mDNS query based on record type
        let records = match record_type {
            RecordType::A => query::query_a(&self.daemon, name).await?,
            RecordType::AAAA => query::query_aaaa(&self.daemon, name).await?,
            RecordType::PTR => query::query_ptr(&self.daemon, name).await?,
            RecordType::SRV => query::query_srv(&self.daemon, name).await?,
            RecordType::TXT => query::query_txt(&self.daemon, name).await?,
            _ => {
                warn!("Unsupported record type: {:?}", record_type);
                Vec::new()
            }
        };

        // Cache the results
        if !records.is_empty() {
            self.cache.insert(&query_name, record_type, records.clone());
        }

        Ok(records)
    }
}
