//! RFC 9758 §5.5: Administrative domain boundary configuration tests
//!
//! RFC9758-011, RFC9758-030: Implementations MUST be sufficiently configurable
//! to prevent Private Use bundles from crossing administrative domains while
//! allowing them within a domain.

use interplanetary_sdk::bp::{BundleBuilder, CreationTimestamp};
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::{Bytes, DtnTimeMs, EndpointId, NodeId};

/// RFC9758-011, RFC9758-030: Domain boundary configuration test
///
/// Tests BOTH behaviors:
/// 1. Private Use bundles are BLOCKED when crossing domain boundaries
/// 2. Private Use bundles are ALLOWED within the same domain
#[test]
fn test_rfc9758_011_030_domain_boundary_enforcement() {
    use interplanetary_sdk::types::SimInstant;
    use std::collections::HashMap;

    // Setup: Node 100 in domain 1
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_node = NodeId::ipn(0, 100);
    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();

    // Configure neighbor domains and routes
    let neighbor_same_domain = NodeId::ipn(0, 200); // Also in domain 1
    let neighbor_different_domain = NodeId::ipn(0, 300); // In domain 2

    let mut routes = HashMap::new();
    routes.insert(
        EndpointId::ipn(0, 200, 0).unwrap(),
        neighbor_same_domain.clone(),
    );
    routes.insert(
        EndpointId::ipn(0, 300, 0).unwrap(),
        neighbor_different_domain.clone(),
    );

    let config = BpaConfig {
        local_node: local_node.clone(),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: true,
        administrative_domain: Some(1), // This node is in domain 1
        static_routes: Some(routes),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config.clone(), storage);

    agent
        .set_neighbor_domain(neighbor_same_domain.clone(), 1)
        .unwrap(); // Same domain
    agent
        .set_neighbor_domain(neighbor_different_domain.clone(), 2)
        .unwrap(); // Different domain

    // Create bundle with Private Use source (node 100000 is in range 1-16777215)
    let private_use_src = EndpointId::ipn(0, 100000, 0).unwrap();
    assert!(
        private_use_src.is_private_use_ipn(),
        "Verify test uses Private Use EID"
    );

    // TEST 1: Forward to neighbor in SAME domain - should SUCCEED
    let bundle_same_domain = BundleBuilder::new()
        .source(private_use_src.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0xAA])
        .build()
        .unwrap();

    // Production path: receive bundle, poll triggers automatic forward (within domain)
    let _bundle_id1 = agent.receive_from_cla(bundle_same_domain).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify bundle is in CLA queue (allowed within domain)
    assert_eq!(
        agent.cla_tx_queue().len(),
        1,
        "RFC9758-011/030: Private Use MUST be allowed within same domain"
    );

    // Clear queue for next test
    agent.clear_cla_tx_queue();

    // TEST 2: Forward to neighbor in DIFFERENT domain - should FAIL
    let bundle_different_domain = BundleBuilder::new()
        .source(private_use_src)
        .destination(EndpointId::ipn(0, 300, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 0))
        .lifetime(3600)
        .payload(vec![0xBB])
        .build()
        .unwrap();

    // Production path: receive bundle, poll triggers forward attempt (crosses domain)
    let _bundle_id2 = agent.receive_from_cla(bundle_different_domain).unwrap();
    agent.poll(SimInstant::from_nanos(200_000_000));

    // Verify bundle is deleted (blocked when crossing domains)
    let final_count = agent.storage().enumerate().len();
    assert_eq!(
        final_count, 1,
        "RFC9758-011/030: Private Use MUST be blocked when crossing domain boundaries (bundle deleted)"
    );

    // Verify NOT in CLA queue
    assert!(
        agent.cla_tx_queue().is_empty(),
        "CLA queue must be empty - no cross-domain forwarding of Private Use"
    );
}

/// RFC9758-030: Test that implementations are configurable (can disable enforcement)
#[test]
fn test_rfc9758_030_configurable_enforcement() {
    use interplanetary_sdk::types::SimInstant;
    use std::collections::HashMap;

    // Setup with enforcement DISABLED
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_node = NodeId::ipn(0, 100);

    // Configure neighbor in different domain
    let neighbor = NodeId::ipn(0, 200);

    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 200, 0).unwrap(), neighbor.clone());

    let config = BpaConfig {
        local_node,
        local_eid: EndpointId::ipn(0, 100, 0).unwrap(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false, // DISABLED for single-domain deployment
        administrative_domain: Some(1),
        static_routes: Some(routes),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config, storage);
    agent.set_neighbor_domain(neighbor.clone(), 2).unwrap(); // Different domain

    // Create Private Use bundle
    let private_use_src = EndpointId::ipn(0, 100000, 0).unwrap();
    let bundle = BundleBuilder::new()
        .source(private_use_src)
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0xCC])
        .build()
        .unwrap();

    // Production path: receive bundle, poll triggers forward (enforcement disabled)
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify bundle is forwarded (enforcement disabled allows crossing domains)
    assert_eq!(
        agent.cla_tx_queue().len(),
        1,
        "RFC9758-030: Implementation MUST be configurable to allow Private Use when enforcement disabled"
    );
}
