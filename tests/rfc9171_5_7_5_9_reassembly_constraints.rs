//! RFC 9171 §5.7 & §5.9 Reassembly Constraint Tests
//!
//! Tests for reassembly pending constraints and fragment handling

use interplanetary_sdk::SimInstant;
use interplanetary_sdk::bp::{BundleBuilder, fragment_bundle};
use interplanetary_sdk::bpa::policy::StatusReportPolicy;
use interplanetary_sdk::bpa::retention::RetentionConstraint;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

fn create_test_agent() -> BundleAgent {
    let config = BpaConfig {
        local_node: NodeId::dtn("node1"),
        local_eid: EndpointId::dtn("node1").unwrap(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: Default::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    BundleAgent::new(config, storage)
}

/// RFC9171-5-044: Local Bundle Delivery Step 1 - Fragment reassembly invocation
///
/// RFC 9171 §5.7: "Step 1: If the received bundle is a fragment, the ADU Reassembly
/// procedure described in Section 5.9 MUST be followed."
///
/// Tests:
/// 1. In-order fragment arrival produces exact reassembled ADU
/// 2. Out-of-order fragment arrival produces exact reassembled ADU  
/// 3. Duplicate fragments handled correctly with exact reassembled ADU
/// 4. No delivery occurs until all fragments received
#[test]
fn test_rfc9171_5_044_fragment_invokes_reassembly() {
    // Test 1: In-order arrival
    {
        let mut agent = create_test_agent();
        let original_payload = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::dtn("node1").unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(original_payload.clone())
            .build()
            .unwrap();

        let fragments = fragment_bundle(&bundle, Bytes(2)).unwrap();
        assert!(fragments.len() >= 2, "Should produce multiple fragments");

        // RFC 9171 §5.7 Step 1: No delivery until reassembly complete
        let frag1_id = agent.receive_from_cla(fragments[0].clone()).unwrap();
        agent.poll(SimInstant::from_nanos(50_000_000));
        assert_eq!(
            agent.delivered_adus().len(),
            0,
            "No delivery until reassembly complete"
        );

        // Receive remaining fragments in order
        let mut frag_ids = vec![frag1_id];
        for frag in &fragments[1..] {
            let id = agent.receive_from_cla(frag.clone()).unwrap();
            frag_ids.push(id);
        }

        agent.poll(SimInstant::from_nanos(100_000_000));

        // RFC 9171 §5.7: Reassembly MUST produce complete ADU exactly once
        let delivered = agent.delivered_adus();
        assert_eq!(delivered.len(), 1, "Exactly one complete ADU delivered");
        assert_eq!(
            &delivered[0].blocks[0].data, &original_payload,
            "Delivered payload must match original exactly per RFC 9171 §5.9"
        );
    }

    // Test 2: Out-of-order arrival
    {
        let mut agent = create_test_agent();
        let original_payload = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 2, 0).unwrap())
            .destination(EndpointId::dtn("node1").unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 2))
            .lifetime(60_000)
            .payload(original_payload.clone())
            .build()
            .unwrap();

        let fragments = fragment_bundle(&bundle, Bytes(2)).unwrap();
        assert!(fragments.len() >= 3, "Should produce multiple fragments");

        // Receive fragments out of order: last, first, middle
        agent
            .receive_from_cla(fragments.last().unwrap().clone())
            .unwrap();
        agent.poll(SimInstant::from_nanos(10_000_000));
        assert_eq!(
            agent.delivered_adus().len(),
            0,
            "No delivery with incomplete fragments"
        );

        agent.receive_from_cla(fragments[0].clone()).unwrap();
        agent.poll(SimInstant::from_nanos(20_000_000));
        assert_eq!(agent.delivered_adus().len(), 0, "Still incomplete");

        // Receive remaining middle fragments
        for frag in &fragments[1..fragments.len() - 1] {
            agent.receive_from_cla(frag.clone()).unwrap();
        }

        agent.poll(SimInstant::from_nanos(100_000_000));

        // RFC 9171 §5.9: Out-of-order arrival MUST produce exact ADU once
        let delivered = agent.delivered_adus();
        assert_eq!(delivered.len(), 1, "Exactly one complete ADU delivered");
        assert_eq!(
            &delivered[0].blocks[0].data, &original_payload,
            "Out-of-order reassembly must produce exact original payload"
        );
    }

    // Test 3: Duplicate fragment arrival
    {
        let mut agent = create_test_agent();
        let original_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 3, 0).unwrap())
            .destination(EndpointId::dtn("node1").unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 3))
            .lifetime(60_000)
            .payload(original_payload.clone())
            .build()
            .unwrap();

        let fragments = fragment_bundle(&bundle, Bytes(1)).unwrap();
        assert!(fragments.len() >= 2, "Should produce multiple fragments");

        // Receive all fragments including a duplicate of the first
        for frag in &fragments {
            agent.receive_from_cla(frag.clone()).unwrap();
        }
        // Send duplicate of first fragment
        agent.receive_from_cla(fragments[0].clone()).unwrap();

        agent.poll(SimInstant::from_nanos(100_000_000));

        // RFC 9171 §5.9: Duplicate fragments MUST NOT cause multiple deliveries
        let delivered = agent.delivered_adus();
        assert_eq!(
            delivered.len(),
            1,
            "Exactly one ADU delivered despite duplicate fragment"
        );
        assert_eq!(
            &delivered[0].blocks[0].data, &original_payload,
            "Duplicate fragments must not corrupt reassembled payload"
        );
    }
}

/// RFC9171-5-045: Reassembly pending constraint when incomplete
///
/// RFC 9171 §5.7 Step 1: "the retention constraint 'Reassembly pending' MUST be
/// added to the bundle, and all remaining steps of this procedure MUST be skipped."
#[test]
fn test_rfc9171_5_045_reassembly_pending_constraint() {
    let mut agent = create_test_agent();

    let original_payload = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 2, 0).unwrap())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 2))
        .lifetime(60_000)
        .payload(original_payload)
        .build()
        .unwrap();

    let fragments = fragment_bundle(&bundle, Bytes(3)).unwrap();
    assert!(fragments.len() >= 2);

    // Receive only first fragment
    let frag_id = agent.receive_from_cla(fragments[0].clone()).unwrap();

    // RFC 9171 §5.45: "the retention constraint 'Reassembly pending' MUST be added"
    let metadata = agent.get_metadata(&frag_id).unwrap();
    assert!(
        metadata.has_constraint(RetentionConstraint::ReassemblyPending),
        "Incomplete fragment MUST have ReassemblyPending constraint per RFC 9171 §5.45"
    );

    // RFC 9171 §5.45: "all remaining steps of this procedure MUST be skipped"
    // Fragment should NOT be delivered (delivery is a later step)
    agent.poll(SimInstant::from_nanos(100_000_000));

    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Incomplete fragment must not be delivered - remaining steps skipped per RFC 9171 §5.45"
    );

    // No status reports should be generated for incomplete fragment
    assert_eq!(
        agent.generated_reports().len(),
        0,
        "No status reports for incomplete fragments - remaining steps skipped"
    );
}

/// RFC9171-5-061: Remove reassembly pending from all fragments when complete
///
/// RFC 9171 §5.9: "The 'Reassembly pending' retention constraint MUST be removed
/// from every other fragment with the same source node ID and creation timestamp"
///
/// Tests:
/// 1. Fragments have ReassemblyPending while incomplete
/// 2. Exactly one complete ADU delivered after all fragments received
/// 3. Stored fragments are released/deleted after reassembly completes
#[test]
fn test_rfc9171_5_061_remove_reassembly_pending_all_fragments() {
    let mut agent = create_test_agent();

    let original_payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 3, 0).unwrap())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 3))
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    let fragments = fragment_bundle(&bundle, Bytes(2)).unwrap();
    assert!(fragments.len() >= 3, "Need multiple fragments");

    // RFC 9171 §5.9: Fragments have ReassemblyPending while incomplete
    let frag1_id = agent.receive_from_cla(fragments[0].clone()).unwrap();
    let frag2_id = agent.receive_from_cla(fragments[1].clone()).unwrap();

    assert!(
        agent
            .get_metadata(&frag1_id)
            .unwrap()
            .has_constraint(RetentionConstraint::ReassemblyPending),
        "First fragment must have ReassemblyPending per RFC 9171 §5.9"
    );
    assert!(
        agent
            .get_metadata(&frag2_id)
            .unwrap()
            .has_constraint(RetentionConstraint::ReassemblyPending),
        "Second fragment must have ReassemblyPending per RFC 9171 §5.9"
    );

    // No delivery while incomplete
    agent.poll(SimInstant::from_nanos(50_000_000));
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "No delivery while fragments incomplete"
    );

    // Receive final fragment (completes reassembly)
    let mut all_frag_ids = vec![frag1_id, frag2_id];
    for frag in &fragments[2..] {
        let id = agent.receive_from_cla(frag.clone()).unwrap();
        all_frag_ids.push(id);
    }

    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.9: Exactly one complete ADU delivered with exact payload
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "Exactly one reassembled bundle delivered per RFC 9171 §5.9"
    );
    assert_eq!(
        &delivered[0].blocks[0].data, &original_payload,
        "Reassembled payload must exactly match original per RFC 9171 §5.9"
    );

    // RFC 9171 §5.9: Fragments must be released after reassembly completes
    // The ReassemblyManager deletes fragments after successful reassembly
    for frag_id in &all_frag_ids {
        assert!(
            agent.storage().get(frag_id).is_none(),
            "Fragment must be released after reassembly completes per RFC 9171 §5.9"
        );
    }
}
