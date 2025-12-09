pub mod config;
pub mod dns_handler;
pub mod mdns_resolver;

// Re-export commonly used types
pub use config::{Args, Config};
pub use dns_handler::MdnsDnsHandler;
pub use mdns_resolver::MdnsResolver;
