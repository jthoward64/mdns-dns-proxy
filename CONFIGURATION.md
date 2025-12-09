# Configuration Guide

This guide explains all configuration options for the mDNS-DNS Discovery Proxy.

## Configuration Priority

Configuration is applied in the following order (highest priority first):

1. **Command-line arguments** - Flags passed when starting the program
2. **Environment variables** - System environment variables
3. **Configuration file** - TOML file specified by `--config` or `MDNS_DNS_PROXY_CONFIG`
4. **Default values** - Built-in defaults

This means CLI arguments override environment variables, which override the config file, which overrides defaults.

## Quick Start Examples

### Using CLI Arguments

```bash
# Basic usage with custom port
mdns-dns-proxy --port 5354

# Listen on all interfaces with debug logging
mdns-dns-proxy --bind-address 0.0.0.0 --log-level debug

# Disable caching and increase query timeout
mdns-dns-proxy --no-cache --query-timeout 2000

# Combine multiple options
mdns-dns-proxy -p 5354 -b 0.0.0.0 -l debug --cache-ttl 300
```

### Using Environment Variables

```bash
# Set environment variables
export MDNS_DNS_PROXY_PORT=5354
export MDNS_DNS_PROXY_BIND_ADDRESS=0.0.0.0
export MDNS_DNS_PROXY_LOG_LEVEL=debug

# Run with environment variables
mdns-dns-proxy

# Or inline for a single run
MDNS_DNS_PROXY_PORT=5354 mdns-dns-proxy
```

### Using a Configuration File

```bash
# Create a config file
cat > my-config.toml << EOF
[server]
bind_address = "0.0.0.0"
port = 5354

[logging]
level = "debug"

[cache]
ttl_seconds = 300
EOF

# Run with config file
mdns-dns-proxy --config my-config.toml

# Or use environment variable
export MDNS_DNS_PROXY_CONFIG=my-config.toml
mdns-dns-proxy
```

### Combining Configuration Methods

```bash
# Load from file, but override port via CLI
mdns-dns-proxy --config my-config.toml --port 5355

# Use environment for config file location, CLI for other options
export MDNS_DNS_PROXY_CONFIG=/etc/mdns-proxy/config.toml
mdns-dns-proxy --log-level trace
```

## Configuration Options Reference

### Server Configuration

#### Bind Address
- **Description**: IP address to bind the DNS server to
- **CLI Flag**: `--bind-address`, `-b`
- **Environment**: `MDNS_DNS_PROXY_BIND_ADDRESS`
- **Config File**: `server.bind_address`
- **Default**: `127.0.0.1` (localhost only)
- **Examples**:
  - `127.0.0.1` - Listen only on localhost
  - `0.0.0.0` - Listen on all IPv4 interfaces
  - `::` - Listen on all IPv6 interfaces
  - `192.168.1.10` - Listen on specific interface

#### Port
- **Description**: Port to bind the DNS server to
- **CLI Flag**: `--port`, `-p`
- **Environment**: `MDNS_DNS_PROXY_PORT`
- **Config File**: `server.port`
- **Default**: `5353`
- **Note**: Ports below 1024 require root/admin privileges
- **Examples**:
  - `5353` - Standard mDNS port (requires privileges)
  - `5354` - Alternative port
  - `53533` - High port number

#### TCP Timeout
- **Description**: TCP connection timeout in seconds
- **Config File**: `server.tcp_timeout`
- **Default**: `30`
- **Range**: 1-3600 seconds

### Cache Configuration

#### Cache TTL
- **Description**: How long to cache mDNS query results (in seconds)
- **CLI Flag**: `--cache-ttl`
- **Environment**: `MDNS_DNS_PROXY_CACHE_TTL`
- **Config File**: `cache.ttl_seconds`
- **Default**: `120` (2 minutes)
- **Examples**:
  - `60` - 1 minute (faster updates, more mDNS traffic)
  - `300` - 5 minutes (less traffic, slower updates)
  - `600` - 10 minutes (static networks)

#### Cache Enabled
- **Description**: Enable or disable result caching
- **CLI Flag**: `--no-cache` (to disable)
- **Environment**: `MDNS_DNS_PROXY_NO_CACHE=true` (to disable)
- **Config File**: `cache.enabled`
- **Default**: `true` (enabled)
- **Note**: Disabling cache increases network traffic but ensures fresh results

### Logging Configuration

#### Log Level
- **Description**: Verbosity of logging output
- **CLI Flag**: `--log-level`, `-l`
- **Environment**: `MDNS_DNS_PROXY_LOG_LEVEL`
- **Config File**: `logging.level`
- **Default**: `info`
- **Options**:
  - `error` - Only errors
  - `warn` - Errors and warnings
  - `info` - Normal operation (recommended)
  - `debug` - Detailed debugging information
  - `trace` - Very detailed, includes packet-level details

### mDNS Configuration

These options are only available in the configuration file.

#### Query Timeout
- **Description**: Timeout for individual mDNS queries in milliseconds
- **CLI Flag**: `--query-timeout`
- **Environment**: `MDNS_DNS_PROXY_QUERY_TIMEOUT`
- **Config File**: `mdns.query_timeout_ms`
- **Default**: `1000` (1 second)
- **Range**: 100-10000 milliseconds

#### Discovery Timeout
- **Description**: Timeout for service discovery operations in milliseconds
- **Config File**: `mdns.discovery_timeout_ms`
- **Default**: `2000` (2 seconds)
- **Range**: 500-10000 milliseconds

#### Service Types
- **Description**: List of service types to query when resolving hostnames
- **Config File**: `mdns.service_types`
- **Default**: 
  ```toml
  service_types = [
      "_http._tcp.local.",
      "_ssh._tcp.local.",
      "_device-info._tcp.local."
  ]
  ```
- **Common Service Types**:
  - `_http._tcp.local.` - HTTP services
  - `_https._tcp.local.` - HTTPS services
  - `_ssh._tcp.local.` - SSH servers
  - `_smb._tcp.local.` - Samba/Windows file sharing
  - `_afpovertcp._tcp.local.` - Apple Filing Protocol
  - `_device-info._tcp.local.` - Device information
  - `_workstation._tcp.local.` - Workstations
  - `_printer._tcp.local.` - Printers
  - `_ipp._tcp.local.` - Internet Printing Protocol

## Complete Configuration File Example

```toml
# Server Configuration
[server]
# Listen on all interfaces (0.0.0.0 for IPv4, :: for IPv6)
bind_address = "0.0.0.0"

# Use alternative port (standard 5353 requires root)
port = 5354

# TCP connection timeout
tcp_timeout = 30

# Cache Configuration
[cache]
# Cache results for 5 minutes
ttl_seconds = 300

# Enable caching (set to false to disable)
enabled = true

# Logging Configuration
[logging]
# Set log level (trace, debug, info, warn, error)
level = "info"

# mDNS Configuration
[mdns]
# Query timeout in milliseconds
query_timeout_ms = 1500

# Service discovery timeout in milliseconds
discovery_timeout_ms = 2500

# Service types to query for hostname resolution
service_types = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_device-info._tcp.local.",
    "_workstation._tcp.local.",
]
```

## Environment Variables

All configuration options can be set via environment variables. They use the prefix `MDNS_DNS_PROXY_`:

```bash
# Server configuration
export MDNS_DNS_PROXY_CONFIG=/path/to/config.toml
export MDNS_DNS_PROXY_BIND_ADDRESS=0.0.0.0
export MDNS_DNS_PROXY_PORT=5354

# Cache configuration
export MDNS_DNS_PROXY_CACHE_TTL=300
export MDNS_DNS_PROXY_NO_CACHE=true  # Set to disable cache

# Logging
export MDNS_DNS_PROXY_LOG_LEVEL=debug

# mDNS
export MDNS_DNS_PROXY_QUERY_TIMEOUT=1500
```

## Running as a System Service

### systemd (Linux)

Create `/etc/systemd/system/mdns-dns-proxy.service`:

```ini
[Unit]
Description=mDNS-DNS Discovery Proxy
After=network.target

[Service]
Type=simple
User=mdns-proxy
Group=mdns-proxy
ExecStart=/usr/local/bin/mdns-dns-proxy --config /etc/mdns-proxy/config.toml
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/mdns-proxy

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mdns-dns-proxy
sudo systemctl start mdns-dns-proxy
sudo systemctl status mdns-dns-proxy
```

### Docker

Create a `Dockerfile`:
```dockerfile
FROM rust:1.91 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/mdns-dns-proxy /usr/local/bin/
EXPOSE 5353/udp 5353/tcp
CMD ["mdns-dns-proxy"]
```

Run with Docker:
```bash
docker build -t mdns-dns-proxy .
docker run -d \
  --name mdns-proxy \
  --network host \
  -e MDNS_DNS_PROXY_PORT=5354 \
  -e MDNS_DNS_PROXY_LOG_LEVEL=info \
  mdns-dns-proxy
```

## Troubleshooting

### "Address already in use" Error

Port 5353 is likely in use. Solutions:
- Use a different port: `--port 5354`
- Stop other services using the port
- On Linux: `sudo lsof -i :5353` to find the process

### "Permission denied" on Port 5353

Ports below 1024 require elevated privileges:
- Use a higher port number (recommended)
- Run with sudo (not recommended)
- Use capabilities on Linux: `sudo setcap CAP_NET_BIND_SERVICE=+eip /path/to/mdns-dns-proxy`

### Configuration Not Loading

Check that:
- Config file path is correct
- Config file has valid TOML syntax
- Environment variables are properly exported
- CLI arguments are spelled correctly

### Cache Not Working

- Verify `cache.enabled = true` in config
- Check that queries are identical (case-sensitive)
- Monitor with `--log-level debug` to see cache hits

## Performance Tuning

### High-Traffic Networks

```toml
[cache]
ttl_seconds = 300  # Longer cache

[mdns]
query_timeout_ms = 500  # Faster timeout
```

### Reliable Results (Slow Network)

```toml
[cache]
ttl_seconds = 60  # Shorter cache for fresh data

[mdns]
query_timeout_ms = 2000  # Longer timeout
discovery_timeout_ms = 5000
```

### Production Deployment

```toml
[server]
bind_address = "0.0.0.0"
port = 5353
tcp_timeout = 30

[cache]
ttl_seconds = 180
enabled = true

[logging]
level = "warn"  # Less verbose in production
```
