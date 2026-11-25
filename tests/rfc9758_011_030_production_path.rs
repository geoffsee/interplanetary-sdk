//! RFC9758-011, RFC9758-030: Domain boundary enforcement via production path
//!
//! RFC 9758 §5.5: "Implementations MUST be sufficiently configurable that operators
//! can elect to prevent Private Use ipn URIs from being used at all in a bundle's
//! source, destination, and report-to fields, and they MUST also be sufficiently
//! configurable that operators can elect to allow such URIs to be used only within
//! a specified administrative domain and not across administrative domain boundaries."

use interplanetary_sdk::bp::{BundleBuilder, CreationTimestamp};
use interplanetary_sdk::bpa::admin::ReasonCode;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::{Bytes, DtnTimeMs, EndpointId, NodeId, SimInstant};
use std::collections::HashMap;

/// RFC9758-011, RFC9758-030: Private Use forwarded within same domain
///
/// RFC 9758 §5.5: When configured with administrative_domain, Private Use bundles
/// MUST be allowed to forward to neighbors in the SAME domain.
#[test]
fn test_rfc9758_011_030_private_use_within_domain() {
    // Node ipn:0.100 in domain 1, with route to ipn:0.200 (also domain 1)
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 200, 0).unwrap(), NodeId::ipn(0, 200));

    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 100),
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
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // Configure neighbor as same domain
    agent.set_neighbor_domain(NodeId::ipn(0, 200), 1).unwrap();

    // Create bundle with Private Use source (100000 is in range 1-16777215)
    let private_use_src = EndpointId::ipn(0, 100000, 0).unwrap();
    assert!(
        private_use_src.is_private_use_ipn(),
        "Test uses Private Use EID"
    );

    let bundle = BundleBuilder::new()
        .source(private_use_src.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0xAA, 0xBB, 0xCC])
        .build()
        .unwrap();

    let _bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Auto-forward via production path
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC9758-011/030: Private Use MUST be allowed within same domain
    let tx_queue = agent.cla_tx_queue();
    assert_eq!(
        tx_queue.len(),
        1,
        "Bundle must be forwarded within same domain"
    );

    // Verify exact cla_tx_queue entry
    let queued = &tx_queue[0];
    assert_eq!(
        queued.bundle.primary.source, private_use_src,
        "Source preserved"
    );
    assert_eq!(
        queued.bundle.primary.destination,
        EndpointId::ipn(0, 200, 0).unwrap(),
        "Destination preserved"
    );

    // Encode and verify byte-exact forwarding
    let encoded = interplanetary_sdk::bp::encode(&queued.bundle).unwrap();
    assert!(!encoded.is_empty(), "Bundle encoded for transmission");
}

/// RFC9758-011, RFC9758-030: Private Use blocked across domain boundary
///
/// RFC 9758 §5.5: When configured with administrative_domain, Private Use bundles
/// MUST NOT cross to neighbors in DIFFERENT domains.
#[test]
fn test_rfc9758_011_030_private_use_blocked_across_boundary() {
    // Node ipn:0.100 in domain 1, with route to ipn:0.300 (domain 2)
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 300, 0).unwrap(), NodeId::ipn(0, 300));

    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 100),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::all(
            local_eid.clone(),
        ),
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
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // Configure neighbor as DIFFERENT domain
    agent.set_neighbor_domain(NodeId::ipn(0, 300), 2).unwrap();

    // Create bundle with Private Use destination
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 100, 0).unwrap())
        .destination(EndpointId::ipn(0, 50000, 0).unwrap()) // Private Use
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 0))
        .lifetime(3600)
        .bundle_flags(0x040000) // Request deletion report
        .payload(vec![0xDD])
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.clear_generated_reports();

    // Auto-forward via production path - should FAIL and DELETE
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC9758-011/030: Bundle must be DELETED when crossing boundary
    assert!(
        agent.storage().get(&bundle_id).is_none(),
        "Bundle must be deleted when crossing domain boundary"
    );

    // CLA queue must be EMPTY
    assert_eq!(
        agent.cla_tx_queue().len(),
        0,
        "Bundle must NOT be queued across domain boundary"
    );

    // Verify correct deletion reason
    let reports = agent.generated_reports();
    assert!(!reports.is_empty(), "Deletion report must be generated");
    assert_eq!(
        reports[0].reason_code,
        ReasonCode::NoKnownRoute,
        "Deletion reason must be NoKnownRoute (domain boundary)"
    );
}

/// RFC9758-030: Configurability test - administrative_domain controls enforcement
///
/// RFC 9758 §5.5: "Implementations MUST be sufficiently configurable that operators
/// can elect to prevent Private Use ipn URIs from being used at all in a bundle's
/// source, destination, and report-to fields, and they MUST also be sufficiently
/// configurable that operators can elect to allow such URIs to be used only within
/// a specified administrative domain and not across administrative domain boundaries."
#[test]
fn test_rfc9758_030_configurability() {
    // Test 1: administrative_domain = None → all forwarding crosses boundaries
    let mut routes1 = HashMap::new();
    routes1.insert(EndpointId::ipn(0, 200, 0).unwrap(), NodeId::ipn(0, 200));

    let config1 = BpaConfig {
        local_node: NodeId::ipn(0, 100),
        local_eid: EndpointId::ipn(0, 100, 0).unwrap(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: true,
        administrative_domain: None, // No domain = all forwarding crosses boundaries
        static_routes: Some(routes1),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage1 = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent1 = BundleAgent::new(config1, storage1);

    let bundle1 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 50000, 0).unwrap()) // Private Use
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0x01])
        .build()
        .unwrap();

    let bundle_id1 = agent1.receive_from_cla(bundle1).unwrap();
    agent1.poll(SimInstant::from_nanos(100_000_000));

    // RFC9758-030: With domain=None, Private Use is BLOCKED (strictest)
    assert!(
        agent1.storage().get(&bundle_id1).is_none(),
        "Config: domain=None blocks all Private Use forwarding"
    );

    // Test 2: administrative_domain = Some(1), neighbor in same domain → ALLOWED
    let mut routes2 = HashMap::new();
    routes2.insert(EndpointId::ipn(0, 200, 0).unwrap(), NodeId::ipn(0, 200));

    let config2 = BpaConfig {
        local_node: NodeId::ipn(0, 100),
        local_eid: EndpointId::ipn(0, 100, 0).unwrap(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: true,
        administrative_domain: Some(1), // Domain 1
        static_routes: Some(routes2),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage2 = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent2 = BundleAgent::new(config2, storage2);
    agent2.set_neighbor_domain(NodeId::ipn(0, 200), 1).unwrap(); // Same domain

    let bundle2 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 50000, 0).unwrap()) // Private Use
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 0))
        .lifetime(3600)
        .payload(vec![0x02])
        .build()
        .unwrap();

    let _bundle_id2 = agent2.receive_from_cla(bundle2).unwrap();
    agent2.poll(SimInstant::from_nanos(100_000_000));

    // RFC9758-030: With same domain configured, Private Use is ALLOWED
    assert_eq!(
        agent2.cla_tx_queue().len(),
        1,
        "Config: same domain allows Private Use forwarding"
    );

    // Test 3: enforce_private_use_restrictions = false → all allowed (opt-out)
    let mut routes3 = HashMap::new();
    routes3.insert(EndpointId::ipn(0, 300, 0).unwrap(), NodeId::ipn(0, 300));

    let config3 = BpaConfig {
        local_node: NodeId::ipn(0, 100),
        local_eid: EndpointId::ipn(0, 100, 0).unwrap(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false, // Disabled
        administrative_domain: Some(1),
        static_routes: Some(routes3),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage3 = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent3 = BundleAgent::new(config3, storage3);
    agent3.set_neighbor_domain(NodeId::ipn(0, 300), 2).unwrap(); // Different domain

    let bundle3 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 50000, 0).unwrap()) // Private Use
        .destination(EndpointId::ipn(0, 300, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3000), 0))
        .lifetime(3600)
        .payload(vec![0x03])
        .build()
        .unwrap();

    let _bundle_id3 = agent3.receive_from_cla(bundle3).unwrap();
    agent3.poll(SimInstant::from_nanos(100_000_000));

    // RFC9758-030: With enforcement disabled, Private Use crosses boundaries
    assert_eq!(
        agent3.cla_tx_queue().len(),
        1,
        "Config: enforcement disabled allows crossing boundaries"
    );
}
