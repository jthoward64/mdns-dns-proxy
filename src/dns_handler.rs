use crate::mdns_resolver::MdnsResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::Name;
use std::sync::Arc;
use tracing::{debug, error, info};

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
    fn should_handle(&self, name: &Name) -> bool {
        let name_str = name.to_utf8();
        
        // Handle .local domain queries (RFC 8766)
        if name_str.ends_with(".local.") || name_str.ends_with(".local") {
            return true;
        }
        
        // Handle common mDNS service discovery queries
        if name_str.contains("._tcp.") || name_str.contains("._udp.") {
            return true;
        }
        
        false
    }
}

#[async_trait::async_trait]
impl RequestHandler for MdnsDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_message = match request.request_info() {
            Ok(info) => info,
            Err(e) => {
                error!("Error getting request info: {}", e);
                let mut header = Header::new();
                header.set_response_code(ResponseCode::FormErr);
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.build_no_records(header);
                return response_handle.send_response(response).await.unwrap_or_else(|e| {
                    error!("Error sending response: {}", e);
                    ResponseInfo::from(header)
                });
            }
        };
        
        info!(
            "Received DNS query: {} {:?}",
            request_message.query.name(),
            request_message.query.query_type()
        );

        // Build response
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        
        let builder = MessageResponseBuilder::from_message_request(request);

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
        match self
            .resolver
            .query(
                request_message.query.name(),
                request_message.query.query_type(),
            )
            .await
        {
            Ok(records) => {
                if records.is_empty() {
                    debug!("No records found for query");
                    header.set_response_code(ResponseCode::NXDomain);
                    let response = builder.build_no_records(header);
                    response_handle.send_response(response).await.unwrap_or_else(|e| {
                        error!("Error sending response: {}", e);
                        ResponseInfo::from(header)
                    })
                } else {
                    info!("Returning {} record(s)", records.len());
                    header.set_response_code(ResponseCode::NoError);
                    
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
                }
            }
            Err(e) => {
                error!("Error querying mDNS: {}", e);
                header.set_response_code(ResponseCode::ServFail);
                let response = builder.build_no_records(header);
                response_handle.send_response(response).await.unwrap_or_else(|e| {
                    error!("Error sending response: {}", e);
                    ResponseInfo::from(header)
                })
            }
        }
    }
}
