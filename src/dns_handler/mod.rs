mod handler;
pub mod utils; // Make public for testing
pub mod admin_records; // RFC 8766 Section 6 administrative records

pub use handler::MdnsDnsHandler;
pub use utils::should_handle_domain;

#[cfg(test)]
mod tests;
