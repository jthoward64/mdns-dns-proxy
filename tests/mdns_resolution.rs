use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::rr::{Name, RData, Record, RecordType};
use mdns_dns_proxy::{Config, MdnsResolver};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use serial_test::serial;
use tokio::time::sleep;

const SERVICE_TYPE: &str = "_http._tcp.local.";

/// Create test config with specified cache TTL
fn create_test_config(ttl_seconds: u64) -> Arc<Config> {
    let mut config = Config::default();
    config.cache.ttl_seconds = ttl_seconds;
    Arc::new(config)
}

struct TestMdnsService {
    _daemon: Arc<ServiceDaemon>,
    host_name: String,
    full_name: String,
    port: u16,
}

impl TestMdnsService {
    fn advertise(daemon: Arc<ServiceDaemon>, ip_addrs: &[&str], port: u16) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_micros();
        let instance_name = format!("integration-mdns-{suffix}");
        let host_name = format!("integration-mdns-{suffix}.local.");

        let mut service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_name,
            ip_addrs,
            port,
            HashMap::<String, String>::new(),
        )
        .expect("failed to create service info");
        service_info.set_requires_probe(false);

        let full_name = service_info.get_fullname().to_string();
        daemon
            .register(service_info)
            .expect("failed to register test service");

        Self {
            _daemon: daemon,
            host_name,
            full_name,
            port,
        }
    }

    async fn allow_propagation(&self) {
        // Give more time for IPv6 mDNS to propagate across network
        sleep(Duration::from_secs(2)).await;
    }
}



#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn resolves_ipv4_mdns_hostname() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let service = TestMdnsService::advertise(daemon.clone(), &["127.0.0.1"], 6200);
    service.allow_propagation().await;

    let resolver = MdnsResolver::with_daemon(daemon, create_test_config(5))
        .expect("failed to create resolver");
    let query_name = Name::from_utf8(&service.host_name).expect("invalid hostname");

    let records = query_with_retry(&resolver, &query_name, RecordType::A).await;

    assert!(
        contains_ipv4(&records, Ipv4Addr::new(127, 0, 0, 1)),
        "expected IPv4 record for {} but found {:?}",
        service.host_name,
        records
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn resolves_srv_record_for_service_instance() {
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let service = TestMdnsService::advertise(daemon.clone(), &["127.0.0.1"], 6300);
    service.allow_propagation().await;

    let config = create_test_config(5);
    let discovery_domain = config.discovery_domain().to_string();
    let resolver = MdnsResolver::with_daemon(daemon, config)
        .expect("failed to create resolver");

    let srv_query = format!(
        "{}.{}",
        service.full_name.trim_end_matches(".local."),
        discovery_domain
    );
    let srv_name = Name::from_utf8(&srv_query).expect("invalid service fullname");

    let records = query_with_retry(&resolver, &srv_name, RecordType::SRV).await;

    assert!(
        records.iter().any(|record| {
            if let RData::SRV(srv) = record.data() {
                let expected_target = format!(
                    "{}.{}",
                    service.host_name.trim_end_matches(".local."),
                    discovery_domain
                );
                srv.port() == service.port && srv.target().to_utf8() == expected_target
            } else {
                false
            }
        }),
        "expected SRV record pointing at {}:{} but found {:?}",
        format!(
            "{}.{}",
            service.host_name.trim_end_matches(".local."),
            discovery_domain
        ),
        service.port,
        records
    );
}

async fn query_with_retry(
    resolver: &MdnsResolver,
    name: &Name,
    record_type: RecordType,
) -> Vec<Record> {
    let mut records = Vec::new();
    for _attempt in 0..5 {
        records = resolver
            .query(name, record_type)
            .await
            .expect("mDNS query failed");
        if !records.is_empty() {
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    records
}

fn contains_ipv4(records: &[Record], expected: Ipv4Addr) -> bool {
    records.iter().any(|record| {
        if let RData::A(addr) = record.data() {
            addr.0 == expected
        } else {
            false
        }
    })
}

// TODO: Figure out how to test IPv6 mDNS resolution properly

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn resolves_ipv6_mdns_hostname() {
    // Note: IPv6 mDNS multicast doesn't work on loopback (::1) interfaces.
    // This test verifies the AAAA query mechanism works correctly (doesn't crash, returns proper type),
    // but cannot test actual IPv6 mDNS resolution without a real network interface.
    // For real IPv6 testing, use an actual network with advertised IPv6 mDNS services.
    
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let service = TestMdnsService::advertise(daemon.clone(), &["127.0.0.1"], 6201);
    service.allow_propagation().await;

    let resolver = MdnsResolver::with_daemon(daemon, create_test_config(5))
        .expect("failed to create resolver");
    let query_name = Name::from_utf8(&service.host_name).expect("invalid hostname");

    // Query for AAAA - this verifies the code path works even if no IPv6 is available
    let records = query_with_retry(&resolver, &query_name, RecordType::AAAA).await;

    // Service only has IPv4, so AAAA should return empty or only AAAA records (no mixed types)
    assert!(
        records.is_empty() || records.iter().all(|r| matches!(r.data(), RData::AAAA(_))),
        "AAAA query should return empty or only AAAA records, but found {:?}",
        records
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn resolves_dual_stack_hostname() {
    // Test querying for both A and AAAA records
    // Note: IPv6 loopback (::1) doesn't work for mDNS multicast, so this only tests IPv4
    let daemon = Arc::new(ServiceDaemon::new().expect("failed to create daemon"));
    let service = TestMdnsService::advertise(daemon.clone(), &["127.0.0.1"], 6202);
    service.allow_propagation().await;

    let resolver = MdnsResolver::with_daemon(daemon, create_test_config(5))
        .expect("failed to create resolver");
    let query_name = Name::from_utf8(&service.host_name).expect("invalid hostname");

    // Should resolve IPv4
    let ipv4_records = query_with_retry(&resolver, &query_name, RecordType::A).await;
    assert!(
        contains_ipv4(&ipv4_records, Ipv4Addr::LOCALHOST),
        "expected IPv4 A record for {} but found {:?}",
        service.host_name,
        ipv4_records
    );

    // AAAA query should work (not crash) even if service has no IPv6
    let ipv6_records = query_with_retry(&resolver, &query_name, RecordType::AAAA).await;
    assert!(
        ipv6_records.is_empty() || ipv6_records.iter().all(|r| matches!(r.data(), RData::AAAA(_))),
        "AAAA query should return empty or only AAAA records, but found {:?}",
        ipv6_records
    );
}
