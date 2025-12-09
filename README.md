# mDNS-DNS Discovery Proxy

An RFC 8766 compliant DNS-SD Discovery Proxy implementation in Rust that bridges mDNS (Multicast DNS) queries from the local network to standard DNS queries.

## Overview

This project implements a DNS server that resolves `.local` domain names and mDNS service discovery queries using the mDNS-SD protocol. It allows devices that only support standard DNS to discover and access mDNS services on the local network.

## Features

- **RFC 8766 Compliance**: Implements Discovery Proxy for Multicast DNS-Based Service Discovery
- **Full DNS Record Support**:
  - A records (IPv4 addresses)
  - AAAA records (IPv6 addresses)
  - PTR records (service enumeration)
  - SRV records (service location)
  - TXT records (service metadata)
- **Query Caching**: Results are cached for 120 seconds to improve performance
- **UDP and TCP Support**: Handles both UDP and TCP DNS queries
- **Async Runtime**: Built on Tokio for high performance

## Architecture

### Components

1. **MdnsResolver** (`src/mdns_resolver.rs`):
   - Interfaces with the local mDNS network using `mdns-sd`
   - Implements query logic for different record types
   - Manages caching of mDNS query results
   - Handles service discovery and resolution

2. **MdnsDnsHandler** (`src/dns_handler.rs`):
   - Implements hickory-server's `RequestHandler` trait
   - Processes incoming DNS queries
   - Routes `.local` domain queries to the mDNS resolver
   - Formats responses according to DNS protocol

3. **Main Server** (`src/main.rs`):
   - Sets up the DNS server on port 5353
   - Configures UDP and TCP listeners
   - Initializes logging and error handling

## Installation

### Prerequisites

- Rust 1.91.1 or higher
- Cargo

### Build

```bash
cargo build --release
```

## Usage

### Running the Server

```bash
cargo run
```

The server will bind to `127.0.0.1:5353` by default.

### Querying the Server

Use `dig` or any DNS client to query .local domains:

```bash
# Query for an A record
dig @127.0.0.1 -p 5353 hostname.local

# Query for service discovery (PTR record)
dig @127.0.0.1 -p 5353 _http._tcp.local PTR

# Query for service details (SRV record)
dig @127.0.0.1 -p 5353 myservice._http._tcp.local SRV

# Query for service metadata (TXT record)
dig @127.0.0.1 -p 5353 myservice._http._tcp.local TXT
```

### Integration with System DNS

To make `.local` domains resolvable system-wide, configure your system resolver to forward queries to this proxy:

#### Linux (systemd-resolved)

Edit `/etc/systemd/resolved.conf`:
```ini
[Resolve]
DNS=127.0.0.1:5353
Domains=~local
```

Then restart systemd-resolved:
```bash
sudo systemctl restart systemd-resolved
```

#### macOS

Add a resolver configuration:
```bash
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/local
echo "port 5353" | sudo tee -a /etc/resolver/local
```

## Configuration

The server can be configured in three ways (in order of precedence):

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration file** (TOML format)
4. **Default values** (lowest priority)

### Configuration File

Create a TOML configuration file (see `config.example.toml` for a complete example):

```toml
[server]
bind_address = "127.0.0.1"
port = 5353
tcp_timeout = 30

[cache]
ttl_seconds = 120
enabled = true

[logging]
level = "info"

[mdns]
query_timeout_ms = 1000
discovery_timeout_ms = 2000
service_types = [
    "_http._tcp.local.",
    "_ssh._tcp.local.",
    "_device-info._tcp.local."
]
```

Load the configuration file:
```bash
mdns-dns-proxy --config /path/to/config.toml
# Or via environment variable
export MDNS_DNS_PROXY_CONFIG=/path/to/config.toml
mdns-dns-proxy
```

### Command-Line Arguments

```bash
# Show all available options
mdns-dns-proxy --help

# Common usage examples
mdns-dns-proxy --port 5354 --log-level debug
mdns-dns-proxy --bind-address 0.0.0.0 --cache-ttl 300
mdns-dns-proxy --no-cache --query-timeout 2000
```

### Environment Variables

All configuration options can be set via environment variables:

```bash
export MDNS_DNS_PROXY_BIND_ADDRESS=0.0.0.0
export MDNS_DNS_PROXY_PORT=5354
export MDNS_DNS_PROXY_CACHE_TTL=300
export MDNS_DNS_PROXY_LOG_LEVEL=debug
export MDNS_DNS_PROXY_QUERY_TIMEOUT=2000
export MDNS_DNS_PROXY_NO_CACHE=true

mdns-dns-proxy
```

### Configuration Options

| Option | CLI Flag | Environment Variable | Config File | Default | Description |
|--------|----------|---------------------|-------------|---------|-------------|
| Config file | `--config` | `MDNS_DNS_PROXY_CONFIG` | N/A | None | Path to TOML config file |
| Bind address | `--bind-address` | `MDNS_DNS_PROXY_BIND_ADDRESS` | `server.bind_address` | 127.0.0.1 | IP address to bind to |
| Port | `--port` | `MDNS_DNS_PROXY_PORT` | `server.port` | 5353 | Port to bind to |
| TCP timeout | N/A | N/A | `server.tcp_timeout` | 30 | TCP connection timeout (seconds) |
| Cache TTL | `--cache-ttl` | `MDNS_DNS_PROXY_CACHE_TTL` | `cache.ttl_seconds` | 120 | Cache TTL in seconds |
| Disable cache | `--no-cache` | `MDNS_DNS_PROXY_NO_CACHE` | `cache.enabled` | true | Enable/disable caching |
| Log level | `--log-level` | `MDNS_DNS_PROXY_LOG_LEVEL` | `logging.level` | info | Log level (trace/debug/info/warn/error) |
| Query timeout | `--query-timeout` | `MDNS_DNS_PROXY_QUERY_TIMEOUT` | `mdns.query_timeout_ms` | 1000 | mDNS query timeout (ms) |
| Discovery timeout | N/A | N/A | `mdns.discovery_timeout_ms` | 2000 | Service discovery timeout (ms) |
| Service types | N/A | N/A | `mdns.service_types` | [see config] | Service types to query |

## Technical Details

### RFC 8766 Implementation

This proxy implements the core requirements of RFC 8766:

- Translates DNS queries for `.local` domains to mDNS queries
- Maintains compatibility with standard DNS clients
- Provides service discovery capabilities via DNS-SD
- Handles multicast responses and converts them to unicast DNS responses

### mDNS Query Process

1. DNS client sends query to proxy
2. Proxy checks if domain ends with `.local`
3. Proxy broadcasts mDNS query on local network
4. mDNS responders reply with their information
5. Proxy aggregates responses and caches them
6. Proxy formats responses as standard DNS records
7. DNS client receives standard DNS response

### Supported Service Types

The resolver automatically queries common service types when resolving hostnames:
- `_http._tcp.local.` - HTTP services
- `_ssh._tcp.local.` - SSH services
- `_device-info._tcp.local.` - Device information services

## Development

### Building from Source

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run development version
cargo run -- --help
```

### Running Tests

The project includes comprehensive unit tests:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test config::tests
cargo test dns_handler::tests
cargo test mdns_resolver::tests
```

See [TESTING_UNIT.md](TESTING_UNIT.md) for detailed testing documentation.

### Project Structure

```
src/
├── lib.rs           # Library interface
├── main.rs          # Binary entry point
├── config.rs        # Configuration management (18 tests)
├── dns_handler.rs   # DNS request handling (10 tests)
└── mdns_resolver.rs # mDNS resolution logic (13 tests)
```

## Dependencies

- **hickory-server**: DNS server implementation
- **hickory-proto**: DNS protocol types and utilities
- **mdns-sd**: mDNS service discovery client
- **tokio**: Async runtime
- **tracing**: Structured logging
- **async-trait**: Async trait support
- **clap**: Command-line argument parsing
- **serde**: Serialization/deserialization
- **toml**: TOML configuration parsing

## Performance Considerations

- Queries are cached for 120 seconds by default
- mDNS queries have a 1-2 second timeout
- The server uses async I/O for efficient connection handling
- Cache automatically cleans up expired entries

## Troubleshooting

### No responses for .local queries

- Ensure mDNS services are running on your network
- Check that firewall allows mDNS traffic (UDP port 5353)
- Verify the proxy has network access

### High latency

- mDNS discovery takes 1-2 seconds for first query
- Subsequent queries use cached results (faster)
- Consider increasing cache TTL for less dynamic networks

### Permission errors on port 5353

- Use a different port (e.g., 5354) or run with appropriate permissions
- On Linux: `sudo setcap CAP_NET_BIND_SERVICE=+eip target/release/mdns-dns-proxy`

## License

This project is released under the MIT License.

## References

- [RFC 8766 - Discovery Proxy for Multicast DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc8766.html)
- [RFC 6763 - DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763.html)
- [RFC 6762 - Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762.html)
