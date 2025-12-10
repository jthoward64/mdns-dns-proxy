use hickory_proto::rr::{Name, Record, RecordType};
use mdns_sd::{IfKind, ServiceDaemon};
use std::sync::Arc;
use tracing::{debug, warn};
use crate::config::Config;

/// Maximum TTL for unicast DNS responses per RFC 8766 Section 5.5.1
/// TTLs are capped at 10 seconds to ensure timely updates for remote clients
const MAX_UNICAST_TTL: u32 = 10;

use super::cache::Cache;
use super::query;

/// mDNS resolver that bridges DNS queries to mDNS
pub struct MdnsResolver {
    daemon: Arc<ServiceDaemon>,
    pub(crate) cache: Cache,
    config: Arc<Config>,
}

impl MdnsResolver {
    /// Create a new mDNS resolver
    pub fn new(config: Arc<Config>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let daemon = Arc::new(ServiceDaemon::new()?);
        daemon.enable_interface(IfKind::All)?;
        daemon.accept_unsolicited(true)?;
        
        Ok(Self {
            daemon,
            cache: Cache::new(config.cache_ttl()),
            config,
        })
    }

    /// Create a new mDNS resolver with an existing ServiceDaemon
    /// This is useful for testing when you want to share a daemon between advertiser and resolver
    pub fn with_daemon(
        daemon: Arc<ServiceDaemon>,
        config: Arc<Config>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        daemon.enable_interface(IfKind::All)?;
        daemon.accept_unsolicited(true)?;
        
        Ok(Self {
            daemon,
            cache: Cache::new(config.cache_ttl()),
            config,
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
        let mut records = match record_type {
            RecordType::A => query::query_a(&self.daemon, name, &self.config).await?,
            RecordType::AAAA => query::query_aaaa(&self.daemon, name, &self.config).await?,
            RecordType::PTR => query::query_ptr(&self.daemon, name, &self.config).await?,
            RecordType::SRV => query::query_srv(&self.daemon, name, &self.config).await?,
            RecordType::TXT => query::query_txt(&self.daemon, name, &self.config).await?,
            RecordType::SOA => query::query_soa(&self.daemon, name).await?,
            RecordType::NS => query::query_ns(&self.daemon, name).await?,
            _ => {
                warn!("Unsupported record type: {:?}", record_type);
                Vec::new()
            }
        };

        // Cap TTLs at 10 seconds per RFC 8766 Section 5.5.1
        // This ensures remote clients receive timely updates
        for record in &mut records {
            if record.ttl() > MAX_UNICAST_TTL {
                record.set_ttl(MAX_UNICAST_TTL);
            }
        }

        // Cache the results
        if !records.is_empty() {
            self.cache.insert(&query_name, record_type, records.clone());
        }

        Ok(records)
    }
}
