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
    pub fn should_handle(&self, name: &Name) -> bool {
        should_handle_domain(&name.to_utf8())
    }
}

/// Check if a domain name should be handled by the mDNS proxy
pub fn should_handle_domain(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    
    // Handle .local domain queries (RFC 8766)
    if name_lower.ends_with(".local.") || name_lower.ends_with(".local") {
        return true;
    }
    
    // Handle common mDNS service discovery queries
    if name_lower.contains("._tcp.") || name_lower.contains("._udp.") {
        return true;
    }
    
    false
}

/// Parse DNS request and create initial response components
/// Returns a tuple of (header, builder) or None if request is malformed
fn parse_dns_request(request: &Request) -> Option<(Header, MessageResponseBuilder<'_>)> {
    let request_message = match request.request_info() {
        Ok(info) => info,
        Err(e) => {
            error!("Error getting request info: {}", e);
            let mut header = Header::new();
            header.set_response_code(ResponseCode::FormErr);
            let builder = MessageResponseBuilder::from_message_request(request);
            return Some((header, builder));
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

    Some((header, builder))
}

/// Build a DNS response based on mDNS query results
/// Returns the appropriate response code and records (if any)
fn build_response_from_records(
    records: Result<Vec<hickory_proto::rr::Record>, Box<dyn std::error::Error + Send + Sync>>,
) -> (ResponseCode, Option<Vec<hickory_proto::rr::Record>>) {
    match records {
        Ok(records) => {
            if records.is_empty() {
                debug!("No records found for query");
                (ResponseCode::NXDomain, None)
            } else {
                info!("Returning {} record(s)", records.len());
                (ResponseCode::NoError, Some(records))
            }
        }
        Err(e) => {
            error!("Error querying mDNS: {}", e);
            (ResponseCode::ServFail, None)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_handle_local_domain_with_trailing_dot() {
        assert!(should_handle_domain("hostname.local."));
        assert!(should_handle_domain("subdomain.hostname.local."));
        assert!(should_handle_domain("my-device.local."));
    }

    #[test]
    fn test_should_handle_local_domain_without_trailing_dot() {
        assert!(should_handle_domain("hostname.local"));
        assert!(should_handle_domain("subdomain.hostname.local"));
    }

    #[test]
    fn test_should_handle_service_discovery_tcp() {
        assert!(should_handle_domain("_http._tcp.local"));
        assert!(should_handle_domain("_http._tcp.local."));
        assert!(should_handle_domain("MyService._http._tcp.local"));
        assert!(should_handle_domain("MyService._http._tcp.local."));
        assert!(should_handle_domain("_ssh._tcp.local"));
    }

    #[test]
    fn test_should_handle_service_discovery_udp() {
        assert!(should_handle_domain("_dns._udp.local"));
        assert!(should_handle_domain("_dns._udp.local."));
        assert!(should_handle_domain("MyService._dns._udp.local"));
    }

    #[test]
    fn test_should_not_handle_regular_domains() {
        assert!(!should_handle_domain("example.com"));
        assert!(!should_handle_domain("www.google.com"));
        assert!(!should_handle_domain("subdomain.example.org"));
        assert!(!should_handle_domain("192.168.1.1"));
    }

    #[test]
    fn test_should_not_handle_similar_but_different_domains() {
        assert!(!should_handle_domain("localhost"));
        assert!(!should_handle_domain("localnet"));
        assert!(!should_handle_domain("mylocal.com"));
        assert!(!should_handle_domain("tcp.local.com"));
    }

    #[test]
    fn test_should_handle_case_sensitivity() {
        // Domain names are case-insensitive, but our function is case-sensitive
        // This tests current behavior
        assert!(should_handle_domain("hostname.local"));
        assert!(should_handle_domain("hostname.LOCAL")); // Still contains .local
        assert!(should_handle_domain("HOSTNAME.local"));
    }

    #[test]
    fn test_should_handle_empty_and_edge_cases() {
        assert!(!should_handle_domain(""));
        assert!(!should_handle_domain("."));
        assert!(!should_handle_domain(".."));
        assert!(should_handle_domain(".local")); // Technically matches
        assert!(should_handle_domain(".local."));
    }

    #[test]
    fn test_should_handle_complex_service_names() {
        assert!(should_handle_domain("My Service (2)._http._tcp.local"));
        assert!(should_handle_domain("Office-Printer._ipp._tcp.local"));
        assert!(should_handle_domain("_device-info._tcp.local"));
    }

    #[test]
    fn test_should_handle_various_tlds() {
        // Should handle .local TLD
        assert!(should_handle_domain("test.local"));
        assert!(should_handle_domain("test.local."));
        
        // Should not handle other TLDs
        assert!(!should_handle_domain("test.com"));
        assert!(!should_handle_domain("test.org"));
        assert!(!should_handle_domain("test.net"));
    }

    #[test]
    fn test_should_handle_subdomain_levels() {
        assert!(should_handle_domain("a.local"));
        assert!(should_handle_domain("a.b.local"));
        assert!(should_handle_domain("a.b.c.local"));
        assert!(should_handle_domain("a.b.c.d.local"));
    }

    #[test]
    fn test_should_handle_service_instance_patterns() {
        // Standard service instance format: instance._service._proto.domain
        assert!(should_handle_domain("MyPrinter._ipp._tcp.local"));
        assert!(should_handle_domain("Living Room TV._googlecast._tcp.local"));
        assert!(should_handle_domain("Office-PC._smb._tcp.local"));
    }

    #[test]
    fn test_should_handle_mixed_case_protocols() {
        assert!(should_handle_domain("service._TCP.local"));
        assert!(should_handle_domain("service._Tcp.local"));
        assert!(should_handle_domain("service._UDP.local"));
        assert!(should_handle_domain("service._Udp.local"));
    }

    #[test]
    fn test_dns_handler_creation() {
        use std::time::Duration;
        use crate::mdns_resolver::MdnsResolver;
        use std::sync::Arc;
        
        let resolver = MdnsResolver::new(Duration::from_secs(120)).unwrap();
        let handler = MdnsDnsHandler::new(Arc::new(resolver));
        
        // Test that handler correctly identifies domains
        let name = hickory_proto::rr::Name::from_utf8("test.local").unwrap();
        assert!(handler.should_handle(&name));
        
        let name = hickory_proto::rr::Name::from_utf8("test.com").unwrap();
        assert!(!handler.should_handle(&name));
    }

    #[test]
    fn test_should_handle_special_characters() {
        assert!(should_handle_domain("test-device.local"));
        assert!(should_handle_domain("test_device.local"));
        assert!(should_handle_domain("test123.local"));
        assert!(should_handle_domain("123test.local"));
    }

    #[test]
    fn test_should_handle_unicode() {
        // DNS allows unicode in domain names
        assert!(should_handle_domain("münchen.local"));
        assert!(should_handle_domain("日本.local"));
        assert!(should_handle_domain("test-ñ.local"));
    }

    #[test]
    fn test_should_handle_max_length() {
        // DNS labels can be up to 63 characters
        let long_label = "a".repeat(63);
        assert!(should_handle_domain(&format!("{}.local", long_label)));
        
        // With service discovery
        assert!(should_handle_domain(&format!("{}._http._tcp.local", long_label)));
    }

    #[test]
    fn test_build_response_from_records_success_with_records() {
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let name = Name::from_str("test.local.").unwrap();
        let rdata = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 168, 1, 1)));
        let record = Record::from_rdata(name, 300, rdata);
        
        let records = vec![record];
        let result = Ok(records.clone());

        let (response_code, records_opt) = build_response_from_records(result);
        
        assert_eq!(response_code, ResponseCode::NoError);
        assert!(records_opt.is_some());
        assert_eq!(records_opt.unwrap().len(), 1);
    }

    #[test]
    fn test_build_response_from_records_success_empty() {
        let records: Vec<hickory_proto::rr::Record> = vec![];
        let result = Ok(records);

        let (response_code, records_opt) = build_response_from_records(result);
        
        assert_eq!(response_code, ResponseCode::NXDomain);
        assert!(records_opt.is_none());
    }

    #[test]
    fn test_build_response_from_records_error() {
        use std::io;

        let error: Box<dyn std::error::Error + Send + Sync> = 
            Box::new(io::Error::new(io::ErrorKind::Other, "test error"));
        let result: Result<Vec<hickory_proto::rr::Record>, _> = Err(error);

        let (response_code, records_opt) = build_response_from_records(result);
        
        assert_eq!(response_code, ResponseCode::ServFail);
        assert!(records_opt.is_none());
    }

    // Note: parse_dns_request is difficult to test in isolation as it requires
    // a valid Request object which depends on internal hickory types.
    // This function is covered by integration tests in the request handler.

    #[test]
    fn test_build_response_from_records_multiple_records() {
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let name = Name::from_str("test.local.").unwrap();
        let rdata1 = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 168, 1, 1)));
        let record1 = Record::from_rdata(name.clone(), 300, rdata1);
        
        let rdata2 = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 168, 1, 2)));
        let record2 = Record::from_rdata(name, 300, rdata2);
        
        let records = vec![record1, record2];
        let result = Ok(records);

        let (response_code, records_opt) = build_response_from_records(result);
        
        assert_eq!(response_code, ResponseCode::NoError);
        assert!(records_opt.is_some());
        assert_eq!(records_opt.unwrap().len(), 2);
    }
}
