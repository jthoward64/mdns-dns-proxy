# mdns-dns-proxy Documentation

A DNS server that proxies .local domain queries to mDNS (Multicast DNS).

## Overview

mdns-dns-proxy allows standard DNS clients to resolve hostnames advertised via mDNS/Bonjour without requiring mDNS support in the client application.

It is meant to be used a forwarder by another dns server as mdns-dns-proxy is incable of resolving names outside of mDNS.

This project was mostly 'vibe coded', but has fairly robust testing and all code has been reviewed by me.

## Quick Start

```bash
# Run with defaults (localhost:5335)
mdns-dns-proxy

# List options
mdns-dns-proxy --help

# Bind to all interfaces
mdns-dns-proxy --bind-address 0.0.0.0

# Use a configuration file
mdns-dns-proxy --config config.toml

# Get example configuration
mdns-dns-proxy --print-example-config > config.toml
```

## Configuration

Configuration can be provided via:
1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration file (TOML format)
4. Built-in defaults (lowest priority)

### Key Options

- `--bind-address` / `MDNS_DNS_PROXY_BIND_ADDRESS` - IP address to bind to (default: 127.0.0.1)
- `--port` / `MDNS_DNS_PROXY_PORT` - Port to bind to (default: 5335)
- `--cache-ttl` / `MDNS_DNS_PROXY_CACHE_TTL` - Cache TTL in seconds (default: 120)
- `--log-level` / `MDNS_DNS_PROXY_LOG_LEVEL` - Log level: trace, debug, info, warn, error (default: info)

Run `mdns-dns-proxy --help` for complete options.

## Man Pages

- `mdns-dns-proxy(1)` - Command-line interface and options
- `mdns-dns-proxy.toml(5)` - Configuration file format

To view man pages:
```bash
man doc/mdns-dns-proxy.1
man doc/mdns-dns-proxy.toml.5
```

## Standards

- RFC 6762 - Multicast DNS
- RFC 8766 - Discovery Proxy for Multicast DNS-Based Service Discovery

## Support

- Issues: https://github.com/jthoward64/mdns-dns-proxy/issues
- Repository: https://github.com/jthoward64/mdns-dns-proxy
