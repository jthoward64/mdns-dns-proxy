use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::Request;
use hickory_proto::op::{Header, ResponseCode};
use tracing::{debug, error, info};

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
pub fn parse_dns_request(request: &Request) -> Option<(Header, MessageResponseBuilder<'_>)> {
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
/// Per RFC 8766 Section 5.6, returns NoError (not NXDOMAIN) when no records found
/// because the Discovery Proxy cannot know all names that may exist on the local link
pub fn build_response_from_records(
    records: Result<Vec<hickory_proto::rr::Record>, Box<dyn std::error::Error + Send + Sync>>,
) -> (ResponseCode, Option<Vec<hickory_proto::rr::Record>>) {
    match records {
        Ok(records) => {
            if records.is_empty() {
                debug!("No records found for query, returning NoError per RFC 8766");
                (ResponseCode::NoError, None) // RFC 8766: "no error no answer" not NXDOMAIN
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
