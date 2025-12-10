use crate::mdns_resolver::MdnsResolver;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::sync::Arc;
use tracing::{debug, error, info};

use super::utils::{build_response_from_records, parse_dns_request, should_handle_domain};
use super::admin_records::{
    is_admin_srv_query, is_delegation_query_below_apex, 
    is_domain_enumeration_query, is_negative_admin_srv_query,
    is_zone_apex_query, generate_soa_record, generate_ns_record,
    generate_domain_enumeration_records, filter_suppressed_records,
    RecordSuppressionConfig,
};

/// DNS request handler that forwards queries to mDNS
pub struct MdnsDnsHandler {
    resolver: Arc<MdnsResolver>,
    /// Zone apex for the Discovery Proxy (default: local.)
    zone_apex: Name,
    /// Configuration for suppressing unusable records
    suppression_config: RecordSuppressionConfig,
}

impl MdnsDnsHandler {
    /// Create a new DNS handler with mDNS resolver
    pub fn new(resolver: Arc<MdnsResolver>) -> Self {
        Self { 
            resolver,
            zone_apex: Name::from_utf8("local.").unwrap(),
            suppression_config: RecordSuppressionConfig::default(),
        }
    }

    /// Create a new DNS handler with custom zone apex
    pub fn with_zone_apex(resolver: Arc<MdnsResolver>, zone_apex: Name) -> Self {
        Self {
            resolver,
            zone_apex,
            suppression_config: RecordSuppressionConfig::default(),
        }
    }

    /// Check if the query should be handled by this proxy
    pub fn should_handle(&self, name: &Name) -> bool {
        should_handle_domain(&name.to_utf8())
    }

    /// Handle administrative queries that don't need mDNS forwarding
    /// Returns Some(records) if this is an administrative query, None otherwise
    fn handle_admin_query(&self, name: &Name, record_type: RecordType) -> Option<Vec<hickory_proto::rr::Record>> {
        // REQ-6.5.1/6.5.2: Domain enumeration queries (PTR for b/db/lb._dns-sd._udp)
        if is_domain_enumeration_query(name, record_type) {
            info!("Handling domain enumeration query for {}", name);
            return Some(generate_domain_enumeration_records(name, &self.zone_apex));
        }

        // REQ-6.4.1-6.4.8: Administrative SRV queries
        if is_admin_srv_query(name, record_type) {
            info!("Handling administrative SRV query for {}", name);
            if is_negative_admin_srv_query(name) {
                // Return empty for unsupported services (DNS Update, LLQ, DNS Push)
                return Some(Vec::new());
            }
            // If we supported LLQ/DNS Push, we'd return positive records here
            return Some(Vec::new());
        }

        // REQ-6.3.1: Zone apex SOA query
        if record_type == RecordType::SOA && is_zone_apex_query(name, &self.zone_apex) {
            info!("Handling zone apex SOA query");
            return Some(vec![generate_soa_record(name)]);
        }

        // REQ-6.3.2: SOA query below zone apex - immediate negative answer
        if is_delegation_query_below_apex(name, RecordType::SOA, &self.zone_apex) {
            debug!("SOA query below zone apex, returning empty");
            return Some(Vec::new());
        }

        // REQ-6.2.1: Zone apex NS query
        if record_type == RecordType::NS && is_zone_apex_query(name, &self.zone_apex) {
            info!("Handling zone apex NS query");
            return Some(vec![generate_ns_record(name)]);
        }

        // REQ-6.3.3: NS query below zone apex - immediate negative answer
        if is_delegation_query_below_apex(name, RecordType::NS, &self.zone_apex) {
            debug!("NS query below zone apex, returning empty");
            return Some(Vec::new());
        }

        // REQ-6.3.4: DS query below zone apex - immediate negative answer
        if is_delegation_query_below_apex(name, RecordType::DS, &self.zone_apex) {
            debug!("DS query below zone apex, returning empty");
            return Some(Vec::new());
        }

        None
    }
}

#[async_trait::async_trait]
impl RequestHandler for MdnsDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // Parse request and build initial response components
        let (mut header, builder) = match parse_dns_request(request) {
            Some((h, b)) => (h, b),
            None => {
                let mut header = Header::new();
                header.set_response_code(ResponseCode::FormErr);
                return ResponseInfo::from(header);
            }
        };

        // Check if request was malformed (FormErr code set by parse_dns_request)
        if header.response_code() == ResponseCode::FormErr {
            let response = builder.build_no_records(header);
            return response_handle.send_response(response).await.unwrap_or_else(|e| {
                error!("Error sending response: {}", e);
                ResponseInfo::from(header)
            });
        }

        // Get request info for querying
        let request_message = request.request_info().unwrap();

        // Check if we should handle this query
        if !self.should_handle(request_message.query.name()) {
            debug!("Query not for .local domain, returning NXDOMAIN");
            header.set_response_code(ResponseCode::NXDomain);
            let response = builder.build_no_records(header);
            return response_handle.send_response(response).await.unwrap_or_else(|e| {
                error!("Error sending response: {}", e);
                ResponseInfo::from(header)
            });
        }

        let query_name = request_message.query.name();
        let query_type = request_message.query.query_type();

        // RFC 8766 Section 6: Check for administrative queries that don't need mDNS
        if let Some(admin_records) = self.handle_admin_query(query_name, query_type) {
            header.set_response_code(ResponseCode::NoError);
            
            if admin_records.is_empty() {
                let response = builder.build_no_records(header);
                return response_handle.send_response(response).await.unwrap_or_else(|e| {
                    error!("Error sending response: {}", e);
                    ResponseInfo::from(header)
                });
            } else {
                let response = builder.build(
                    header,
                    admin_records.iter(),
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
                return response_handle.send_response(response).await.unwrap_or_else(|e| {
                    error!("Error sending response: {}", e);
                    ResponseInfo::from(header)
                });
            }
        }

        // Query mDNS for the records
        let records = self
            .resolver
            .query(query_name, query_type)
            .await;

        // Build response from mDNS records
        let (response_code, records_opt) = build_response_from_records(records);
        header.set_response_code(response_code);
        
        if let Some(records) = records_opt {
            // Apply RFC 8766 Section 5.5.2: Suppress unusable records
            let filtered_records = filter_suppressed_records(records, &self.suppression_config);
            
            if filtered_records.is_empty() {
                let response = builder.build_no_records(header);
                response_handle.send_response(response).await.unwrap_or_else(|e| {
                    error!("Error sending response: {}", e);
                    ResponseInfo::from(header)
                })
            } else {
                let response = builder.build(
                    header,
                    filtered_records.iter(),
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
                response_handle.send_response(response).await.unwrap_or_else(|e| {
                    error!("Error sending response: {}", e);
                    ResponseInfo::from(header)
                })
            }
        } else {
            let response = builder.build_no_records(header);
            response_handle.send_response(response).await.unwrap_or_else(|e| {
                error!("Error sending response: {}", e);
                ResponseInfo::from(header)
            })
        }
    }
}
