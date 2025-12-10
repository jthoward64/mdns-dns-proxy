# RFC 8766 Requirements Checklist

## Section 5.1 - Delegated Subdomain for DNS-based Service Discovery Records

- [ ] **REQ-5.1.1**: Support delegation of Unicast DNS domain names to Discovery Proxy
- [ ] **REQ-5.1.2**: Translate queries from delegated subdomain to .local
- [ ] **REQ-5.1.3**: Replace .local in responses with delegated zone name
- [ ] **REQ-5.1.4**: Support VLAN configuration for multiple logical links
- [ ] **REQ-5.1.5**: Use existing Multicast DNS caching mechanism

## Section 5.2 - Domain Enumeration

### 5.2.1 - Domain Enumeration via Unicast Queries
- [ ] **REQ-5.2.1.1**: Support PTR queries for "b._dns-sd._udp.<domain>" (browse domains)
- [ ] **REQ-5.2.1.2**: Support PTR queries for "db._dns-sd._udp.<domain>" (default browse)
- [ ] **REQ-5.2.1.3**: Support PTR queries for "lb._dns-sd._udp.<domain>" (legacy browse)
- [ ] **REQ-5.2.1.4**: Handle up to 243-466 domains in response (based on name compression)

### 5.2.2 - Domain Enumeration via Multicast Queries
- [ ] **REQ-5.2.2.1**: Generate Multicast DNS responses for "b._dns-sd._udp.local." PTR queries
- [ ] **REQ-5.2.2.2**: Generate Multicast DNS responses for "db._dns-sd._udp.local." PTR queries
- [ ] **REQ-5.2.2.3**: Generate Multicast DNS responses for "lb._dns-sd._udp.local." PTR queries

## Section 5.3 - Delegated Subdomain for LDH Host Names

- [ ] **REQ-5.3.1**: Support separate subdomain for LDH (letter-digit-hyphen) host names
- [ ] **REQ-5.3.2**: Use rich-text domain for service names (SRV records)
- [ ] **REQ-5.3.3**: Use LDH domain for address records (A/AAAA)
- [ ] **REQ-5.3.4**: Support Punycode-encoded names in LDH domain

## Section 5.4 - Delegated Subdomain for Reverse Mapping

- [ ] **REQ-5.4.1**: Support delegation of IPv4 reverse mapping (in-addr.arpa)
- [ ] **REQ-5.4.2**: Support delegation of IPv6 reverse mapping (ip6.arpa)
- [ ] **REQ-5.4.3**: Translate reverse mapping queries to Multicast DNS
- [ ] **REQ-5.4.4**: Rewrite .local responses with configured LDH domain

## Section 5.5 - Data Translation

- [x] **REQ-5.5.1**: Replace .local with delegated subdomain in owner names
- [x] **REQ-5.5.2**: Translate .local in RDATA based on delegation type
- [x] **REQ-5.5.3**: Use LDH subdomain for host names in RDATA
- [x] **REQ-5.5.4**: Use rich-text subdomain for service names in RDATA

### 5.5.1 - DNS TTL Limiting
- [x] **REQ-5.5.1.1**: Cap TTLs at 10 seconds for traditional Unicast DNS queries
- [x] **REQ-5.5.1.2**: Cap negative caching TTL (SOA MINIMUM) at 10 seconds
- [ ] **REQ-5.5.1.3**: Return unmodified TTLs for LLQ/Push Notification queries

### 5.5.2 - Suppressing Unusable Records
- [ ] **REQ-5.5.2.1**: Offer configurable option to suppress unusable records (enabled by default)
- [ ] **REQ-5.5.2.2**: Suppress IPv4 link-local (169.254/16) for non-local clients
- [ ] **REQ-5.5.2.3**: Suppress IPv4 link-local across private address realms
- [ ] **REQ-5.5.2.4**: Suppress IPv6 Unique Local Addresses for non-local clients
- [ ] **REQ-5.5.2.5**: Suppress SRV records referencing link-local target hosts

### 5.5.3 - NSEC and NSEC3 Queries
- [ ] **REQ-5.5.3.1**: Issue qtype "ANY" Multicast DNS query for NSEC/NSEC3 queries
- [ ] **REQ-5.5.3.2**: Generate NSEC/NSEC3 with Type Bit Map for queried name only
- [ ] **REQ-5.5.3.3**: Do NOT forward Multicast DNS NSEC records unmodified
- [ ] **REQ-5.5.3.4**: Ensure NSEC bit is SET in Unicast DNS NSEC records

### 5.5.4 - No Text-Encoding Translation
- [x] **REQ-5.5.4.1**: Do NOT translate between Punycode and UTF-8
- [x] **REQ-5.5.4.2**: Pass through all bytes as-is without text encoding translation

### 5.5.5 - Application-Specific Data Translation
- [ ] **REQ-5.5.5.1**: MAY perform application-specific data translation for efficiency
- [ ] **REQ-5.5.5.2**: Translate embedded .local names in TXT records (e.g., adminurl)
- [ ] **REQ-5.5.5.3**: This is OPTIONAL and for efficiency only

## Section 5.6 - Answer Aggregation

- [x] **REQ-5.6.1**: Return "no error no answer" (NoError) not NXDOMAIN for empty results
- [ ] **REQ-5.6.2**: For standard DNS query with no cache: wait 6 seconds, issue mDNS queries
- [ ] **REQ-5.6.3**: For standard DNS query with cache: return immediately, no new mDNS queries
- [ ] **REQ-5.6.4**: For LLQ with no cache: return empty, issue mDNS query, send updates
- [ ] **REQ-5.6.5**: For LLQ with cache: return cached, issue mDNS query, send updates
- [ ] **REQ-5.6.6**: For DNS Push: return cached if any, issue mDNS query, send updates
- [ ] **REQ-5.6.7**: Support LLQ (Long-Lived Queries) RFC 8764
- [ ] **REQ-5.6.8**: Support DNS Push Notifications RFC 8765

## Section 6 - Administrative DNS Records

### 6.1 - DNS SOA Record
- [x] **REQ-6.1.1**: MNAME SHOULD contain host name of Discovery Proxy device
- [x] **REQ-6.1.2**: RNAME SHOULD contain mailbox of responsible person
- [x] **REQ-6.1.3**: SERIAL MUST be zero
- [x] **REQ-6.1.4**: REFRESH SHOULD be 7200
- [x] **REQ-6.1.5**: RETRY SHOULD be 3600
- [x] **REQ-6.1.6**: EXPIRE SHOULD be 86400
- [x] **REQ-6.1.7**: MINIMUM SHOULD be 10 (negative caching TTL)

### 6.2 - DNS NS Records
- [x] **REQ-6.2.1**: Return own NS record for zone apex
- [ ] **REQ-6.2.2**: Return NS records of fellow Discovery Proxies on same link
- [x] **REQ-6.2.3**: NS target host MUST NOT fall within delegated zone (except zone apex)

### 6.3 - DNS Delegation Records
- [ ] **REQ-6.3.1**: Return SOA record for zone apex queries
- [ ] **REQ-6.3.2**: Return immediate negative answer for SOA queries below zone apex
- [ ] **REQ-6.3.3**: Return immediate negative answer for NS queries below zone apex
- [ ] **REQ-6.3.4**: Return immediate negative answer for DS queries below zone apex

### 6.4 - DNS SRV Records
- [ ] **REQ-6.4.1**: Return immediate answers for administrative SRV queries (not pass to mDNS)
- [ ] **REQ-6.4.2**: Positively respond to "_dns-llq._udp.<zone>" if LLQ supported
- [ ] **REQ-6.4.3**: Positively respond to "_dns-llq._tcp.<zone>" if LLQ supported
- [ ] **REQ-6.4.4**: Positively respond to "_dns-llq-tls._tcp.<zone>" if LLQ supported
- [ ] **REQ-6.4.5**: Positively respond to "_dns-push-tls._tcp.<zone>" if DNS Push supported
- [ ] **REQ-6.4.6**: Return negative answer for "_dns-update._udp.<zone>"
- [ ] **REQ-6.4.7**: Return negative answer for "_dns-update._tcp.<zone>"
- [ ] **REQ-6.4.8**: Return negative answer for "_dns-update-tls._tcp.<zone>"

### 6.5 - Domain Enumeration Records
- [ ] **REQ-6.5.1**: Generate immediate answers for address-based Domain Enumeration queries
- [ ] **REQ-6.5.2**: Do NOT pass Domain Enumeration queries to Multicast DNS

## Section 7 - DNSSEC Considerations

### 7.1 - Online Signing Only
- [ ] **REQ-7.1.1**: Discovery Proxy needs signing keys for DNSSEC
- [ ] **REQ-7.1.2**: Offline signing not applicable

### 7.2 - NSEC and NSEC3 Records
- [ ] **REQ-7.2.1**: Synthesize NSEC record for queried name only (no zone walking)
- [ ] **REQ-7.2.2**: NSEC3 not necessary since single-name NSEC prevents zone walking
- [ ] **REQ-7.2.3**: For DNS Push subscriptions, NSEC not returned for negative answers

## Section 8 - IPv6 Considerations
- [x] **REQ-8.1**: Support IPv6 addresses in queries and responses
- [x] **REQ-8.2**: Support AAAA record queries
- [x] **REQ-8.3**: Support IPv6 reverse mapping (ip6.arpa)

## Section 9 - Security Considerations

### 9.1 - Authenticity
- [ ] **REQ-9.1.1**: Support DNSSEC for authenticity (optional)
- [ ] **REQ-9.1.2**: Note: Multicast DNS has no authenticity guarantees

### 9.2 - Privacy
- [ ] **REQ-9.2.1**: Be aware Discovery Proxy exposes local device information
- [ ] **REQ-9.2.2**: Consider privacy implications of exposing .local data

### 9.3 - Denial of Service
- [ ] **REQ-9.3.1**: Consider DoS attack mitigations
- [ ] **REQ-9.3.2**: Rate limiting on queries (implementation-specific)

## Implementation Status Summary

- **Implemented**: 20 requirements
- **Not Implemented**: 56 requirements  
- **Total**: 76 requirements

## Priority for Implementation

### Critical (Core Functionality)
1. REQ-5.6.2-5.6.6: Proper answer aggregation timing
2. REQ-6.3.1-6.3.4: Delegation record handling
3. REQ-6.4.1-6.4.8: Administrative SRV records
4. REQ-5.5.2.1-5.5.2.5: Suppress unusable records

### Important (Enhanced Functionality)
5. REQ-5.2.1.1-5.2.1.3: Domain enumeration
6. REQ-6.2.2: Multi-proxy NS records
7. REQ-5.5.3.1-5.5.3.4: NSEC/NSEC3 support
8. REQ-5.6.7-5.6.8: LLQ and DNS Push support

### Optional (Nice to Have)
9. REQ-5.3.1-5.3.4: Separate LDH domain support
10. REQ-5.4.1-5.4.4: Reverse mapping delegation
11. REQ-7.1.1-7.2.3: DNSSEC support
12. REQ-9.1.1-9.3.2: Security enhancements
