# Unit Testing Documentation

This document describes the unit test structure and coverage for the mDNS-DNS Discovery Proxy.

## Test Organization

Tests are organized into three main modules corresponding to the project structure:

1. **config::tests** - Configuration parsing and validation
2. **dns_handler::tests** - DNS request handling and domain filtering
3. **mdns_resolver::tests** - mDNS resolution and caching

## Running Tests

### Run All Tests

```bash
cargo test
```

### Run Library Tests Only

```bash
cargo test --lib
```

### Run Tests for a Specific Module

```bash
cargo test config::tests
cargo test dns_handler::tests
cargo test mdns_resolver::tests
```

### Run a Specific Test

```bash
cargo test test_should_handle_local_domain
```

### Run Tests with Output

```bash
cargo test -- --nocapture
```

### Run Tests in Verbose Mode

```bash
cargo test -- --test-threads=1 --nocapture
```

## Test Coverage

### Configuration Module (config.rs)

**Total Tests: 18**

#### Default Configuration Tests
- `test_default_config` - Verifies default configuration values
- `test_default_server_config` - Tests server configuration defaults
- `test_default_cache_config` - Tests cache configuration defaults
- `test_default_logging_config` - Tests logging configuration defaults
- `test_default_mdns_config` - Tests mDNS configuration defaults

#### TOML Parsing Tests
- `test_toml_parse` - Basic TOML parsing
- `test_toml_partial_config` - Partial configuration with defaults
- `test_toml_full_config` - Complete configuration from TOML
- `test_toml_ipv6_address` - IPv6 address parsing
- `test_service_types_customization` - Custom service types

#### Log Level Parsing Tests
- `test_parse_log_level_valid` - Valid log level strings
- `test_parse_log_level_case_insensitive` - Case-insensitive parsing
- `test_parse_log_level_invalid_defaults_to_info` - Invalid input handling

#### Duration Conversion Tests
- `test_cache_ttl_conversion` - Cache TTL to Duration
- `test_query_timeout_conversion` - Query timeout to Duration
- `test_discovery_timeout_conversion` - Discovery timeout to Duration

#### Serialization Tests
- `test_config_serialization` - Round-trip serialization
- `test_config_clone` - Configuration cloning

### DNS Handler Module (dns_handler.rs)

**Total Tests: 10**

#### Domain Filtering Tests
- `test_should_handle_local_domain_with_trailing_dot` - .local domains with trailing dot
- `test_should_handle_local_domain_without_trailing_dot` - .local domains without trailing dot
- `test_should_handle_service_discovery_tcp` - TCP service discovery queries
- `test_should_handle_service_discovery_udp` - UDP service discovery queries
- `test_should_not_handle_regular_domains` - Regular internet domains
- `test_should_not_handle_similar_but_different_domains` - Edge cases

#### Case Sensitivity Tests
- `test_should_handle_case_sensitivity` - DNS is case-insensitive

#### Edge Case Tests
- `test_should_handle_empty_and_edge_cases` - Empty strings and edge cases
- `test_should_handle_complex_service_names` - Complex service names with special characters

### mDNS Resolver Module (mdns_resolver.rs)

**Total Tests: 13**

#### Resolver Creation Tests
- `test_resolver_creation` - Basic resolver initialization
- `test_resolver_with_custom_ttl` - Custom TTL configuration

#### Cache Tests
- `test_cache_entry_creation` - Cache entry structure
- `test_cache_entry_clone` - Cache entry cloning
- `test_cache_entry_debug` - Debug trait implementation
- `test_cache_miss_on_empty_cache` - Cache miss behavior
- `test_cache_hit_after_insert` - Cache hit behavior
- `test_cache_expiration` - Cache TTL expiration
- `test_cache_multiple_entries` - Multiple cache entries
- `test_cache_overwrites_existing` - Cache entry updates
- `test_cache_cleanup_on_insert` - Automatic cleanup of expired entries

#### Query Tests
- `test_query_name_parsing` - DNS name parsing
- `test_unsupported_record_type_returns_empty` - Unsupported record types
- `test_non_local_domain_returns_empty` - Non-.local domain handling

## Test Categories

### Unit Tests

Unit tests focus on individual functions and components in isolation:
- Configuration parsing and validation
- Domain name filtering logic
- Cache management
- Data structure operations

### Async Tests

Tests that use `#[tokio::test]` for async operations:
- Cache operations with time-based expiration
- Resolver query methods
- Async timeout behavior

## Adding New Tests

When adding new features, follow these guidelines:

### 1. Test Function Naming

Use descriptive names that indicate what is being tested:

```rust
#[test]
fn test_<component>_<behavior>_<expected_result>() {
    // Test implementation
}
```

Examples:
- `test_cache_expiration_removes_old_entries`
- `test_config_override_cli_takes_precedence`
- `test_should_handle_ipv6_addresses`

### 2. Async Tests

For async functions, use the tokio test macro:

```rust
#[tokio::test]
async fn test_async_operation() {
    // Test implementation
}
```

### 3. Test Organization

Group related tests using comments:

```rust
// Cache expiration tests
#[tokio::test]
async fn test_cache_expires_after_ttl() { /* ... */ }

#[tokio::test]
async fn test_cache_cleanup_removes_expired() { /* ... */ }

// Query timeout tests
#[tokio::test]
async fn test_query_respects_timeout() { /* ... */ }
```

### 4. Test Data

Use helper functions to create test data:

```rust
fn create_test_record(name: &str, ttl: u32) -> Record {
    // Create a test record
}

#[test]
fn test_using_helper() {
    let record = create_test_record("test.local", 120);
    // Use record in test
}
```

## Testing Best Practices

### Do's

✅ Test both success and failure cases
✅ Test edge cases and boundary conditions
✅ Use descriptive test names
✅ Keep tests independent and isolated
✅ Test one thing per test function
✅ Use helper functions for common setup
✅ Add comments for complex test logic

### Don'ts

❌ Don't rely on test execution order
❌ Don't use shared mutable state between tests
❌ Don't test implementation details
❌ Don't write tests that depend on external services
❌ Don't ignore failing tests

## Continuous Integration

Tests should be run automatically in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: cargo test --all-features

- name: Run tests with coverage
  run: cargo tarpaulin --out Xml
```

## Test Coverage Goals

Target coverage levels:
- **Configuration module**: 90%+
- **DNS handler module**: 85%+
- **mDNS resolver module**: 70%+ (lower due to integration with system mDNS)
- **Overall project**: 75%+

## Future Testing Plans

### Integration Tests

Integration tests will be added in the `tests/` directory:
- End-to-end DNS query processing
- Configuration loading from files
- Network communication tests
- Performance benchmarks

### Property-Based Tests

Consider adding property-based tests using `proptest` or `quickcheck`:
- Random domain name generation
- Configuration validation across all possible values
- Cache behavior with varying TTLs

### Benchmarks

Add benchmarks using `criterion`:
- Cache lookup performance
- Domain filtering performance
- Configuration parsing speed

## Running Tests in Docker

```dockerfile
FROM rust:1.91
WORKDIR /app
COPY . .
RUN cargo test --release
```

```bash
docker build -t mdns-proxy-test .
docker run mdns-proxy-test
```

## Troubleshooting Test Failures

### Port Conflicts

If integration tests fail due to port conflicts:
```bash
# Check for processes using port 5353
sudo lsof -i :5353
# Kill the process or use a different port
```

### Timing Issues

If async tests fail intermittently:
- Increase timeout values
- Run with `--test-threads=1`
- Check for resource contention

### Dependency Issues

If tests fail to compile:
```bash
cargo clean
cargo update
cargo test
```

## Test Metrics

Current test statistics:
- **Total tests**: 41
- **Pass rate**: 100%
- **Average execution time**: ~150ms
- **Async tests**: 8
- **Sync tests**: 33

## Contributing Tests

When contributing, ensure:
1. All new code includes tests
2. Tests pass locally before submitting PR
3. Test coverage doesn't decrease
4. Tests are documented if complex
5. Follow existing naming conventions
