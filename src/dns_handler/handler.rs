use crate::mdns_resolver::MdnsResolver;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::Name;
use std::sync::Arc;
use tracing::{debug, error};

use super::utils::{build_response_from_records, parse_dns_request, should_handle_domain};

/// DNS request handler that forwards queries to mDNS
pub struct MdnsDnsHandler {
    resolver: Arc<MdnsResolver>,
}

impl MdnsDnsHandler {
    /// Create a new DNS handler with mDNS resolver
    pub fn new(resolver: Arc<MdnsResolver>) -> Self {
        Self { resolver }
    }

    /// Check if the query should be handled by this proxy
    pub fn should_handle(&self, name: &Name) -> bool {
        should_handle_domain(&name.to_utf8())
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

        // Query mDNS for the records
        let records = self
            .resolver
            .query(
                request_message.query.name(),
                request_message.query.query_type(),
            )
            .await;

        // Build response from mDNS records
        let (response_code, records_opt) = build_response_from_records(records);
        header.set_response_code(response_code);
        
        if let Some(records) = records_opt {
            let response = builder.build(
                header,
                records.iter(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            );
            response_handle.send_response(response).await.unwrap_or_else(|e| {
                error!("Error sending response: {}", e);
                ResponseInfo::from(header)
            })
        } else {
            let response = builder.build_no_records(header);
            response_handle.send_response(response).await.unwrap_or_else(|e| {
                error!("Error sending response: {}", e);
                ResponseInfo::from(header)
            })
        }
    }
}
