use hickory_proto::rr::{Name, Record, RecordType, RData};
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
        // daemon.accept_unsolicited(true)?;
        
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
        // daemon.accept_unsolicited(true)?;
        
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

        let mdns_name = map_query_to_local(name, self.config.discovery_domain())?;
        let mdns_query = mdns_name.to_utf8();
        
        debug!("Querying mDNS for {} (mapped to {} for mDNS, type: {:?})", query_name, mdns_query, record_type);

        // Check cache first
        if let Some(cached) = self.cache.get(&query_name, record_type) {
            debug!("Returning cached results for {} (type: {:?})", query_name, record_type);
            return Ok(cached);
        }

        // Perform mDNS query based on record type
        let mdns_records = match record_type {
            RecordType::A | RecordType::AAAA => query::query_a_aaaa(&self.daemon, &mdns_name, &self.config).await?,
            RecordType::PTR => query::query_ptr(&self.daemon, &mdns_name, &self.config).await?,
            RecordType::SRV => query::query_srv(&self.daemon, &mdns_name, &self.config).await?,
            RecordType::TXT => query::query_txt(&self.daemon, &mdns_name, &self.config).await?,
            RecordType::SOA => query::query_soa(&self.daemon, &mdns_name).await?,
            RecordType::NS => query::query_ns(&self.daemon, &mdns_name).await?,
            _ => {
                warn!("Unsupported record type: {:?}", record_type);
                Vec::new()
            }
        };

        // Rewrite returned records from .local to the configured discovery domain
        let mut records = rewrite_records_to_discovery_domain(mdns_records, self.config.discovery_domain())?;

        // Cap TTLs at 10 seconds per RFC 8766 Section 5.5.1
        // This ensures remote clients receive timely updates
        for record in &mut records {
            if record.ttl() > MAX_UNICAST_TTL {
                record.set_ttl(MAX_UNICAST_TTL);
            }
        }

        if record_type == RecordType::A || record_type == RecordType::AAAA {
            // Need to segment the returned record set into A and AAAA records
            let (a_records, aaaa_records): (Vec<Record>, Vec<Record>) = records
                .into_iter()
                .partition(|record| record.record_type() == RecordType::A);
            
            if !a_records.is_empty() {
                self.cache.insert(&query_name, RecordType::A, a_records.clone());
            }
            if !aaaa_records.is_empty() {
                self.cache.insert(&query_name, RecordType::AAAA, aaaa_records.clone());
            }
            
            Ok(match record_type {
                RecordType::A => a_records,
                RecordType::AAAA => aaaa_records,
                _ => unreachable!(),
            })
        } else {
            if !records.is_empty() {
                self.cache.insert(&query_name, record_type, records.clone());
            }

            Ok(records)
        }
    }
}

fn map_query_to_local(name: &Name, discovery_domain: &str) -> Result<Name, Box<dyn std::error::Error + Send + Sync>> {
    let mut mapped = name.to_utf8().to_lowercase();
    let disc = discovery_domain.to_lowercase();
    let disc_no_dot = disc.trim_end_matches('.');

    let mapped_to_local = if mapped.ends_with(&disc) {
        let prefix = mapped[..mapped.len() - disc.len()]
            .trim_end_matches('.')
            .to_string();
        Some(prefix)
    } else if mapped.ends_with(disc_no_dot) {
        let prefix = mapped[..mapped.len() - disc_no_dot.len()]
            .trim_end_matches('.')
            .to_string();
        Some(prefix)
    } else {
        None
    };

    if let Some(prefix) = mapped_to_local {
        mapped = format!("{}.local.", prefix);
    }

    Ok(Name::from_utf8(&mapped)?)
}

fn rewrite_name_to_discovery(name: &Name, discovery_domain: &str) -> Result<Name, Box<dyn std::error::Error + Send + Sync>> {
    let mut n = name.to_utf8();
    let disc = discovery_domain.to_lowercase();
    let local = "local.";
    let lower = n.to_lowercase();
    if lower.ends_with(local) {
        n.truncate(n.len() - local.len());
        n.push_str(&disc);
        return Ok(Name::from_utf8(&n)?);
    }
    Ok(name.clone())
}

fn rewrite_records_to_discovery_domain(records: Vec<Record>, discovery_domain: &str) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records.into_iter() {
        let mut new_record = record.clone();
        let new_name = rewrite_name_to_discovery(record.name(), discovery_domain)?;
        new_record.set_name(new_name);

        let maybe_new_data = match record.data() {
            RData::PTR(ptr) => {
                let target = rewrite_name_to_discovery(&ptr.0, discovery_domain)?;
                Some(RData::PTR(hickory_proto::rr::rdata::PTR(target)))
            }
            RData::SRV(srv) => {
                let target = rewrite_name_to_discovery(srv.target(), discovery_domain)?;
                Some(RData::SRV(hickory_proto::rr::rdata::SRV::new(
                    srv.priority(),
                    srv.weight(),
                    srv.port(),
                    target,
                )))
            }
            RData::NS(ns) => {
                let target = rewrite_name_to_discovery(&ns.0, discovery_domain)?;
                Some(RData::NS(hickory_proto::rr::rdata::NS(target)))
            }
            RData::SOA(soa) => {
                let mname = rewrite_name_to_discovery(soa.mname(), discovery_domain)?;
                let rname = rewrite_name_to_discovery(soa.rname(), discovery_domain)?;
                Some(RData::SOA(hickory_proto::rr::rdata::SOA::new(
                    mname,
                    rname,
                    soa.serial(),
                    soa.refresh(),
                    soa.retry(),
                    soa.expire(),
                    soa.minimum(),
                )))
            }
            _ => None,
        };

        if let Some(rdata) = maybe_new_data {
            let ttl = new_record.ttl();
            let name_clone = new_record.name().clone();
            new_record = Record::from_rdata(name_clone, ttl, rdata);
        }

        out.push(new_record);
    }

    Ok(out)
}
