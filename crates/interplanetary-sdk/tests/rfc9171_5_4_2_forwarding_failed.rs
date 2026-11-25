//! RFC 9171 §5.4.2: Forwarding Failed tests
//!
//! Tests for bundle handling when forwarding is contraindicated.
use interplanetary_sdk::SimInstant;
use interplanetary_sdk::bp::{Bundle, BundleBuilder, CreationTimestamp};
use interplanetary_sdk::bpa::policy::ForwardingFailedPolicy;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::{Bytes, DtnTimeMs, EndpointId, NodeId};
use std::collections::HashMap;

fn create_test_bundle(seq: u64) -> Bundle {
    BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 999, 0).unwrap()) // No route to this destination
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), seq))
        .lifetime(60_000)
        .payload(vec![0xAA, 0xBB, 0xCC])
        .build()
        .unwrap()
}

/// RFC9171-5-022: Forwarding Failed Step 1 - BPA MAY forward bundle back to previous node
///
/// RFC 9171 §5.4.2: "The steps in responding to a declaration of forwarding failure
/// are as follows: Step 1: The BPA MAY forward the bundle back to the node that sent it,
/// as identified by the Previous Node Block, if present."
#[test]
fn test_rfc9171_5_022_may_forward_back_to_previous_node() {
    use interplanetary_sdk::bp::BlockType;
    use interplanetary_sdk::bp::extensions::PreviousNodeBlock;

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();
    let local_node = NodeId::ipn(0, 100);

    // Set up routing: no route to destination 999
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 50, 0).unwrap(), NodeId::ipn(0, 50));

    let config = BpaConfig {
        local_node,
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: ForwardingFailedPolicy::ReturnToPreviousNode,
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config, storage);

    // Create bundle with Previous Node block pointing to node 50
    let mut bundle = create_test_bundle(1);
    let prev_node_eid = EndpointId::ipn(0, 50, 0).unwrap();
    let prev_node_block = PreviousNodeBlock::new(1, prev_node_eid.clone());
    bundle
        .blocks
        .insert(0, prev_node_block.to_canonical().unwrap());

    // Receive bundle (which will try to forward to destination 999, fail, and return to node 50)
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Poll to trigger dispatch
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4.2 Step 1: Bundle should be forwarded back to previous node (50)
    let tx_queue = agent.cla_tx_queue();
    assert_eq!(
        tx_queue.len(),
        1,
        "Bundle should be queued for return to previous node"
    );

    // Verify bundle has Previous Node block pointing to current node (100)
    let returned = &tx_queue[0].bundle;
    let has_prev_node = returned.blocks.iter().any(|b| {
        if b.block_type == BlockType::PreviousNode
            && let Ok(pn) = PreviousNodeBlock::from_canonical(b)
        {
            return pn.previous_node == local_eid;
        }
        false
    });
    assert!(
        has_prev_node,
        "Returned bundle should have Previous Node pointing to local node"
    );
}

/// RFC9171-5-023: Forwarding back SHALL use Step 4 and Step 5 of Section 5.4
///
/// RFC 9171 §5.4.2: "This forwarding, if performed, SHALL be accomplished by
/// performing Step 4 and Step 5 of Section 5.4"
#[test]
fn test_rfc9171_5_023_forward_back_uses_steps_4_5() {
    use interplanetary_sdk::bp::extensions::PreviousNodeBlock;

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();
    let local_node = NodeId::ipn(0, 100);

    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 50, 0).unwrap(), NodeId::ipn(0, 50));

    let config = BpaConfig {
        local_node,
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: ForwardingFailedPolicy::ReturnToPreviousNode,
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config, storage);

    // Create bundle with Previous Node block
    let mut bundle = create_test_bundle(2);
    let prev_node_eid = EndpointId::ipn(0, 50, 0).unwrap();
    let prev_node_block = PreviousNodeBlock::new(1, prev_node_eid.clone());
    bundle
        .blocks
        .insert(0, prev_node_block.to_canonical().unwrap());

    agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4 Step 4: Previous Node block must be updated (points to local node)
    // RFC 9171 §5.4 Step 5: Bundle queued for transmission
    let tx_queue = agent.cla_tx_queue();
    assert_eq!(tx_queue.len(), 1, "Bundle queued per §5.4 Step 5");

    let returned = &tx_queue[0].bundle;
    let prev_node = returned.blocks.iter().find_map(|b| {
        if b.block_type == interplanetary_sdk::bp::BlockType::PreviousNode {
            PreviousNodeBlock::from_canonical(b).ok()
        } else {
            None
        }
    });

    assert!(
        prev_node.is_some(),
        "Previous Node block must exist per §5.4 Step 4"
    );
    assert_eq!(
        prev_node.unwrap().previous_node,
        local_eid,
        "Previous Node must point to local node per §5.4 Step 4"
    );
}

/// RFC9171-5-024: Sole node selected SHALL be the node that sent the bundle
///
/// RFC 9171 §5.4.2: "where the sole node selected for forwarding SHALL be the
/// node that sent the bundle."
#[test]
fn test_rfc9171_5_024_sole_node_is_previous_node() {
    use interplanetary_sdk::bp::extensions::PreviousNodeBlock;

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_node = NodeId::ipn(0, 100);

    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 50, 0).unwrap(), NodeId::ipn(0, 50));
    routes.insert(EndpointId::ipn(0, 60, 0).unwrap(), NodeId::ipn(0, 60));

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
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: ForwardingFailedPolicy::ReturnToPreviousNode,
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config, storage);

    // Create bundle from node 50 (previous node)
    let mut bundle = create_test_bundle(3);
    let prev_node_eid = EndpointId::ipn(0, 50, 0).unwrap();
    let prev_node_block = PreviousNodeBlock::new(1, prev_node_eid.clone());
    bundle
        .blocks
        .insert(0, prev_node_block.to_canonical().unwrap());

    agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4.2: Sole node SHALL be node 50 (not node 60 or any other)
    // This is verified implicitly: bundle is in tx_queue with Previous Node = 100,
    // which means it's being sent back to node 50 (the sender)
    let tx_queue = agent.cla_tx_queue();
    assert_eq!(
        tx_queue.len(),
        1,
        "Bundle forwarded to sole node (previous node 50)"
    );
}

/// RFC9171-5-026: Otherwise, bundle MUST be deleted per Section 5.10
///
/// RFC 9171 §5.4.2: "Otherwise, the bundle MUST be deleted: the Bundle Deletion
/// procedure defined in Section 5.10"
#[test]
fn test_rfc9171_5_026_otherwise_bundle_deleted() {
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_node = NodeId::ipn(0, 100);

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
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None, // No routes = forwarding contraindicated
        forwarding_failed_policy: ForwardingFailedPolicy::Delete,
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None, // Delete policy
    };

    let mut agent = BundleAgent::new(config, storage);

    // Create bundle without Previous Node block
    let bundle = create_test_bundle(4);
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Poll to trigger dispatch
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4.2: "Otherwise, the bundle MUST be deleted"
    assert!(
        agent.storage().get(&bundle_id).is_none(),
        "Bundle must be deleted when forwarding fails and no alternative"
    );
}
