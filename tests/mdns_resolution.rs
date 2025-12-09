use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::rr::{Name, RData, Record, RecordType};
use mdns_dns_proxy::MdnsResolver;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use serial_test::serial;
use tokio::time::sleep;

const SERVICE_TYPE: &str = "_http._tcp.local.";

struct TestMdnsService {
    daemon: ServiceDaemon,
    host_name: String,
    full_name: String,
    port: u16,
}

impl TestMdnsService {
    fn advertise(ip_addrs: &[&str], port: u16) -> Self {
        let daemon = ServiceDaemon::new().expect("failed to start mDNS advertiser");
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
            daemon,
            host_name,
            full_name,
            port,
        }
    }

    async fn allow_propagation(&self) {
        sleep(Duration::from_millis(700)).await;
    }
}

impl Drop for TestMdnsService {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.full_name);
        let _ = self.daemon.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn resolves_ipv4_mdns_hostname() {
    let service = TestMdnsService::advertise(&["127.0.0.1"], 6200);
    service.allow_propagation().await;

    let resolver = MdnsResolver::new(Duration::from_secs(5)).expect("failed to create resolver");
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
    let service = TestMdnsService::advertise(&["127.0.0.1"], 6300);
    service.allow_propagation().await;

    let resolver = MdnsResolver::new(Duration::from_secs(5)).expect("failed to create resolver");
    let srv_name = Name::from_utf8(&service.full_name).expect("invalid service fullname");

    let records = query_with_retry(&resolver, &srv_name, RecordType::SRV).await;

    assert!(
        records.iter().any(|record| {
            if let RData::SRV(srv) = record.data() {
                srv.port() == service.port && srv.target().to_utf8() == service.host_name
            } else {
                false
            }
        }),
        "expected SRV record pointing at {}:{} but found {:?}",
        service.host_name,
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
