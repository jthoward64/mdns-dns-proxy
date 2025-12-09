mod dns_handler;
mod mdns_resolver;

use crate::dns_handler::MdnsDnsHandler;
use crate::mdns_resolver::MdnsResolver;
use hickory_server::ServerFuture;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting mDNS-DNS Discovery Proxy (RFC 8766)");

    // Create mDNS resolver
    let resolver = match MdnsResolver::new() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!("Failed to create mDNS resolver: {}", e);
            return;
        }
    };
    info!("mDNS resolver initialized");

    // Create DNS handler
    let handler = MdnsDnsHandler::new(resolver);

    // Configure server address
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5333);
    
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

    // Register TCP listener
    server.register_listener(tcp_listener, std::time::Duration::from_secs(30));
    info!("Registered TCP listener");

    info!("mDNS-DNS proxy server is running!");
    info!("Query .local domains via this DNS server at {}", listen_addr);
    info!("Example: dig @127.0.0.1 -p 5353 hostname.local");

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
