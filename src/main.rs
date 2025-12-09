mod config;
mod dns_handler;
mod mdns_resolver;

use crate::config::{Args, Config};
use crate::dns_handler::MdnsDnsHandler;
use crate::mdns_resolver::MdnsResolver;
use clap::Parser;
use hickory_server::ServerFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // Parse command-line arguments
    let args = Args::parse();
    
    // Load configuration
    let config = match Config::load(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };
    
    // Initialize tracing/logging with configured level
    tracing_subscriber::fmt()
        .with_max_level(config.parse_log_level())
        .init();

    info!("Starting mDNS-DNS Discovery Proxy (RFC 8766)");
    info!("Configuration: bind={}:{}, cache_ttl={}s, cache_enabled={}", 
          config.server.bind_address, 
          config.server.port, 
          config.cache.ttl_seconds,
          config.cache.enabled);

    // Create mDNS resolver with configured cache TTL
    let resolver = match MdnsResolver::new(config.cache_ttl()) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!("Failed to create mDNS resolver: {}", e);
            return;
        }
    };
    info!("mDNS resolver initialized");

    // Create DNS handler
    let handler = MdnsDnsHandler::new(resolver);

    // Configure server address from config
    let listen_addr = SocketAddr::new(config.server.bind_address, config.server.port);
    
    info!("Binding DNS server to {}", listen_addr);

    // Create UDP socket for DNS
    let udp_socket = match UdpSocket::bind(&listen_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP socket: {}", e);
            return;
        }
    };
    info!("UDP socket bound to {}", listen_addr);

    // Create TCP listener for DNS
    let tcp_listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind TCP listener: {}", e);
            return;
        }
    };
    info!("TCP listener bound to {}", listen_addr);

    // Create server future
    let mut server = ServerFuture::new(handler);

    // Register UDP socket
    server.register_socket(udp_socket);
    info!("Registered UDP socket");

    // Register TCP listener with configured timeout
    server.register_listener(
        tcp_listener, 
        std::time::Duration::from_secs(config.server.tcp_timeout)
    );
    info!("Registered TCP listener");

    info!("mDNS-DNS proxy server is running!");
    info!("Query .local domains via this DNS server at {}", listen_addr);
    info!("Example: dig @{} -p {} hostname.local", 
          config.server.bind_address, 
          config.server.port);

    // Run the server
    match server.block_until_done().await {
        Ok(_) => {
            info!("DNS server shutdown gracefully");
        }
        Err(e) => {
            error!("DNS server error: {}", e);
        }
    }
}
