//! RFC 9174 §4.1: Connection retry with backoff (production path)
//!
//! Tests drive BundleAgent with outbound bundles and poll at advancing times,
//! verifying that connection requests are emitted at exact times per RFC 9174 §4.1
//! reconnection obligations (minimum delay, exponential backoff, pacing).

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::policy::ForwardingFailedPolicy;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;

/// Helper to create a bundle for a destination
fn create_bundle_to(dest_node: u64) -> Bundle {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, dest_node, 0).unwrap();

    BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"test".to_vec())
        .build()
        .unwrap()
}

/// Helper to create BundleAgent with standard config
fn create_agent() -> BundleAgent {
    // Set up static routes so forwarding works
    let mut routes = std::collections::HashMap::new();
    routes.insert(EndpointId::ipn(0, 2, 0).unwrap(), NodeId::ipn(0, 2));
    routes.insert(EndpointId::ipn(0, 3, 0).unwrap(), NodeId::ipn(0, 3));

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: ForwardingFailedPolicy::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    BundleAgent::new(config, storage)
}

/// RFC9174-4-1-003: "MUST NOT overwhelm its target with repeated connection attempts"
#[test]
fn test_rfc9174_4_1_003_no_overwhelm_target() {
    let mut agent = create_agent();

    let bundle = create_bundle_to(2);
    agent.send(bundle).unwrap();

    agent.poll(SimInstant::from_nanos(0));
    assert_eq!(agent.connection_requests().len(), 1);

    agent.record_connection_failure(&NodeId::ipn(0, 2));

    agent.poll(SimInstant::from_nanos(1_000_000));
    assert_eq!(agent.connection_requests().len(), 1, "Blocked before delay");

    agent.poll(SimInstant::from_nanos(1_000_000_000));
    assert_eq!(agent.connection_requests().len(), 2, "Allowed after delay");
}

/// RFC9174-4-1-007: "MUST NOT retry the connection setup earlier than some delay time"
#[test]
fn test_rfc9174_4_1_007_minimum_delay_enforced() {
    let mut agent = create_agent();

    let bundle = create_bundle_to(2);
    agent.send(bundle).unwrap();

    agent.poll(SimInstant::from_nanos(1_000_000_000));
    assert_eq!(agent.connection_requests().len(), 1);

    agent.record_connection_failure(&NodeId::ipn(0, 2));

    agent.poll(SimInstant::from_nanos(1_999_000_000));
    assert_eq!(
        agent.connection_requests().len(),
        1,
        "Blocked before min_delay"
    );

    agent.poll(SimInstant::from_nanos(2_000_000_000));
    assert_eq!(agent.connection_requests().len(), 2, "Allowed at min_delay");
}

/// RFC9174-4-1-008: "SHOULD use a (binary) exponential backoff mechanism"
#[test]
fn test_rfc9174_4_1_008_exponential_backoff() {
    let mut agent = create_agent();

    let bundle = create_bundle_to(2);
    agent.send(bundle).unwrap();

    agent.poll(SimInstant::from_nanos(0));
    agent.record_connection_failure(&NodeId::ipn(0, 2));

    agent.poll(SimInstant::from_nanos(1_000_000_000));
    agent.record_connection_failure(&NodeId::ipn(0, 2));

    agent.poll(SimInstant::from_nanos(3_000_000_000));
    agent.record_connection_failure(&NodeId::ipn(0, 2));

    agent.poll(SimInstant::from_nanos(7_000_000_000));
    agent.record_connection_failure(&NodeId::ipn(0, 2));

    agent.poll(SimInstant::from_nanos(15_000_000_000));

    let requests = agent.connection_requests();
    assert_eq!(requests.len(), 5);

    // Verify exponential spacing: 1000, 2000, 4000, 8000
    assert_eq!(
        requests[1].time.as_nanos() - requests[0].time.as_nanos(),
        1_000_000_000
    );
    assert_eq!(
        requests[2].time.as_nanos() - requests[1].time.as_nanos(),
        2_000_000_000
    );
    assert_eq!(
        requests[3].time.as_nanos() - requests[2].time.as_nanos(),
        4_000_000_000
    );
    assert_eq!(
        requests[4].time.as_nanos() - requests[3].time.as_nanos(),
        8_000_000_000
    );
}
