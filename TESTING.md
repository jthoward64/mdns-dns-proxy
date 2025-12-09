# Testing the mDNS-DNS Discovery Proxy

## Prerequisites

Ensure you have some mDNS services running on your local network. Many devices and services advertise themselves via mDNS:
- macOS computers (Bonjour)
- Linux machines with Avahi
- Printers
- Smart home devices
- Development servers

## Starting the Server

```bash
# Run in development mode with detailed logs
RUST_LOG=debug cargo run

# Or run the release build
cargo build --release
./target/release/mdns-dns-proxy
```

Expected output:
```
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: Starting mDNS-DNS Discovery Proxy (RFC 8766)
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: mDNS resolver initialized
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: Binding DNS server to 127.0.0.1:5353
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: UDP socket bound to 127.0.0.1:5353
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: TCP listener bound to 127.0.0.1:5353
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: Registered UDP socket
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: Registered TCP listener
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: mDNS-DNS proxy server is running!
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: Query .local domains via this DNS server at 127.0.0.1:5353
2025-12-08T00:00:00.000000Z  INFO mdns_dns_proxy: Example: dig @127.0.0.1 -p 5353 hostname.local
```

## Test Cases

### 1. Discover HTTP Services

```bash
# Browse for all HTTP services on the network
dig @127.0.0.1 -p 5353 _http._tcp.local PTR

# Expected output:
# ;; ANSWER SECTION:
# _http._tcp.local.       120     IN      PTR     MyServer._http._tcp.local.
```

### 2. Resolve a Specific Service

```bash
# Get SRV record for a specific service
dig @127.0.0.1 -p 5353 MyServer._http._tcp.local SRV

# Expected output:
# ;; ANSWER SECTION:
# MyServer._http._tcp.local. 120 IN SRV 0 0 8080 myserver.local.
```

### 3. Get Service Metadata

```bash
# Query TXT records for service information
dig @127.0.0.1 -p 5353 MyServer._http._tcp.local TXT

# Expected output:
# ;; ANSWER SECTION:
# MyServer._http._tcp.local. 120 IN TXT "version=1.0" "path=/api"
```

### 4. Resolve Hostname to IP

```bash
# Query A record for IPv4 address
dig @127.0.0.1 -p 5353 myserver.local A

# Expected output:
# ;; ANSWER SECTION:
# myserver.local.         120     IN      A       192.168.1.100

# Query AAAA record for IPv6 address
dig @127.0.0.1 -p 5353 myserver.local AAAA

# Expected output:
# ;; ANSWER SECTION:
# myserver.local.         120     IN      AAAA    fe80::1234:5678:90ab:cdef
```

### 5. Test with nslookup

```bash
# Query using nslookup
nslookup -port=5353 myserver.local 127.0.0.1
```

### 6. Test with curl (if hostname resolves)

After configuring system DNS to use the proxy:

```bash
# If myservice._http._tcp.local resolves to myserver.local:8080
curl http://myserver.local:8080/
```

## Common Service Types to Test

```bash
# SSH services
dig @127.0.0.1 -p 5353 _ssh._tcp.local PTR

# Printers
dig @127.0.0.1 -p 5353 _ipp._tcp.local PTR

# AirPlay devices
dig @127.0.0.1 -p 5353 _airplay._tcp.local PTR

# HomeKit devices
dig @127.0.0.1 -p 5353 _hap._tcp.local PTR

# Chromecast devices
dig @127.0.0.1 -p 5353 _googlecast._tcp.local PTR
```

## Debugging

### Enable Debug Logging

```bash
RUST_LOG=debug cargo run
```

This will show:
- Each incoming DNS query
- mDNS query operations
- Cache hits/misses
- Service discovery events
- Response details

### Check if mDNS Services are Available

Use an mDNS browser tool to verify services exist:

```bash
# On Linux with avahi
avahi-browse -a

# On macOS
dns-sd -B _http._tcp local
```

### Monitor Network Traffic

```bash
# Capture mDNS traffic
sudo tcpdump -i any port 5353

# Or use Wireshark with filter: mdns
```

## Performance Testing

### Test Query Latency

```bash
# First query (uncached) - expect 1-2 seconds
time dig @127.0.0.1 -p 5353 myserver.local +short

# Second query (cached) - expect < 100ms
time dig @127.0.0.1 -p 5353 myserver.local +short
```

### Test Concurrent Queries

```bash
# Send 100 concurrent queries
for i in {1..100}; do
  dig @127.0.0.1 -p 5353 myserver.local +short &
done
wait
```

## Troubleshooting

### "No answer" or NXDOMAIN

- Verify mDNS services are running: `avahi-browse -a` or `dns-sd -B _http._tcp`
- Check firewall allows mDNS multicast (224.0.0.251:5353)
- Ensure the proxy has network interface access

### Connection Refused

- Check the server is running
- Verify port 5353 is not already in use: `lsof -i :5353`
- Try a different port if needed

### Slow Responses

- First query always takes 1-2 seconds (mDNS discovery)
- Increase cache TTL in code for better performance
- Check network latency

## Integration Testing

Create a simple test service using Python:

```python
# test_service.py
from zeroconf import ServiceInfo, Zeroconf
import socket

zeroconf = Zeroconf()
info = ServiceInfo(
    "_http._tcp.local.",
    "TestService._http._tcp.local.",
    addresses=[socket.inet_aton("127.0.0.1")],
    port=8080,
    properties={"path": "/test"},
)
zeroconf.register_service(info)
print("Test service registered")
input("Press Enter to exit...")
zeroconf.unregister_service(info)
zeroconf.close()
```

Then query it:
```bash
python3 test_service.py &
dig @127.0.0.1 -p 5353 TestService._http._tcp.local SRV
```
