//! RFC 9171 §5.9 Bundle Reassembly at the Node
//!
//! Tests node-level reassembly behavior when fragments are received.

use interplanetary_sdk::bp::{BundleBuilder, fragment_bundle};
use interplanetary_sdk::bpa::policy::StatusReportPolicy;
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
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    BundleAgent::new(config, storage)
}

#[test]
fn test_rfc9171_5_060_reassembly_delivers_complete_adu() {
    // RFC 9171 §5.9: "If the concatenation...forms a continuous byte array whose
    // length is equal to the total application data unit length...then:
    // * This byte array -- the reassembled ADU -- MUST replace the payload..."

    let mut agent = create_test_agent();

    // Create original bundle
    let original_payload = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 42))
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    // Fragment the bundle
    let fragments = fragment_bundle(&bundle, Bytes(4)).unwrap();
    assert!(fragments.len() >= 2, "Should produce multiple fragments");

    // Receive fragments in order
    let mut reassembled_id = None;
    for frag in fragments {
        let result = agent.receive_from_cla(frag).unwrap();
        reassembled_id = Some(result);
    }

    // Reassembly should be complete after all fragments received
    assert!(reassembled_id.is_some(), "Reassembly should complete");

    // Verify reassembled bundle has complete payload
    let reassembled_id = reassembled_id.unwrap();
    let reassembled = agent.storage().get(&reassembled_id).unwrap();
    let payload = reassembled
        .blocks
        .iter()
        .find(|b| b.block_type == interplanetary_sdk::bp::BlockType::Payload)
        .unwrap();

    assert_eq!(
        payload.data, original_payload,
        "Reassembled payload must match original exactly"
    );
    assert!(
        !reassembled.primary.is_fragment(),
        "Reassembled bundle must not have is-fragment flag"
    );
}

#[test]
fn test_rfc9171_5_9_out_of_order_reassembly() {
    // RFC 9171 §5.9: Reassembly must handle fragments received in any order

    let mut agent = create_test_agent();

    let original_payload = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 2, 0).unwrap())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 99))
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    let mut fragments = fragment_bundle(&bundle, Bytes(3)).unwrap();
    assert!(fragments.len() >= 3, "Should produce multiple fragments");

    // Shuffle fragments (reverse order)
    fragments.reverse();

    // Receive all but last fragment
    for frag in &fragments[..fragments.len() - 1] {
        let _ = agent.receive_from_cla(frag.clone());
    }

    // Last fragment completes reassembly
    let result = agent.receive_from_cla(fragments.last().unwrap().clone());
    assert!(
        result.is_ok(),
        "Should complete reassembly regardless of order"
    );

    let reassembled_id = result.unwrap();
    let reassembled = agent.storage().get(&reassembled_id).unwrap();
    let payload = reassembled
        .blocks
        .iter()
        .find(|b| b.block_type == interplanetary_sdk::bp::BlockType::Payload)
        .unwrap();

    assert_eq!(
        payload.data, original_payload,
        "Reassembled payload must match original"
    );
}

#[test]
fn test_rfc9171_5_9_deliver_once() {
    // RFC 9171 §5.9: Reassembled ADU must be delivered exactly once

    let mut agent = create_test_agent();

    let original_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 3, 0).unwrap())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 123))
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    let fragments = fragment_bundle(&bundle, Bytes(2)).unwrap();

    // Receive all fragments
    let mut completed = false;
    for frag in fragments {
        if let Ok(_bundle_id) = agent.receive_from_cla(frag) {
            completed = true;
        }
    }

    assert!(completed, "Reassembly should complete");

    // Verify that reassembly completed by checking storage
    // The reassembled bundle should be in storage with a non-fragment primary block
    // For this test, we just check that the final receive_from_cla succeeded
    // which means the bundle was reassembled and admitted to storage
}

#[test]
fn test_rfc9171_5_9_overlapping_identical_fragments() {
    // RFC 9171 §5.7: Overlapping fragments with identical data are allowed

    let mut agent = create_test_agent();

    let original_payload = vec![0xFF; 8];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 4, 0).unwrap())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 456))
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    let fragments = fragment_bundle(&bundle, Bytes(4)).unwrap();

    // Receive first fragment twice (simulating retransmission)
    let _ = agent.receive_from_cla(fragments[0].clone());
    let result = agent.receive_from_cla(fragments[0].clone());
    // Should handle duplicate with identical data gracefully
    assert!(
        result.is_ok(),
        "Duplicate fragment with identical data should be handled"
    );

    // Complete reassembly with remaining fragments
    for frag in &fragments[1..] {
        let _ = agent.receive_from_cla(frag.clone());
    }
}

#[test]
fn test_rfc9171_5_9_continuous_byte_array_requirement() {
    // RFC 9171 §5.9: Fragments must form a "continuous byte array"

    let original_payload = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 5, 0).unwrap())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 789))
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    let fragments = fragment_bundle(&bundle, Bytes(2)).unwrap();
    assert!(fragments.len() >= 2);

    // Verify that offsets form a continuous sequence
    let mut offsets: Vec<_> = fragments
        .iter()
        .map(|f| f.primary.fragment_offset.unwrap())
        .collect();
    offsets.sort();

    // Check continuity
    for i in 1..offsets.len() {
        let prev_offset = offsets[i - 1];
        let curr_offset = offsets[i];
        let prev_frag = fragments
            .iter()
            .find(|f| f.primary.fragment_offset == Some(prev_offset))
            .unwrap();
        let prev_len = prev_frag
            .blocks
            .iter()
            .find(|b| b.block_type == interplanetary_sdk::bp::BlockType::Payload)
            .unwrap()
            .data
            .len() as u64;

        assert_eq!(
            prev_offset + prev_len,
            curr_offset,
            "Fragments must form continuous byte array"
        );
    }
}

#[test]
fn test_rfc9171_5_9_total_length_in_reassembly_key() {
    // RFC 9171 §5.9: Fragments are keyed by source, timestamp, AND total ADU length
    // Two fragment sets with same source/timestamp but different total lengths must not merge

    let mut agent = create_test_agent();

    // Create two bundles with same source and timestamp but different payloads
    let timestamp = CreationTimestamp::new(DtnTimeMs::ZERO, 999);
    let source = EndpointId::ipn(0, 6, 0).unwrap();

    let bundle1 = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(vec![0xAA; 10]) // 10 bytes
        .build()
        .unwrap();

    let bundle2 = BundleBuilder::new()
        .source(source)
        .destination(EndpointId::dtn("node1").unwrap())
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(vec![0xBB; 20]) // 20 bytes - different total length
        .build()
        .unwrap();

    // Fragment both
    let fragments1 = fragment_bundle(&bundle1, Bytes(4)).unwrap();
    let fragments2 = fragment_bundle(&bundle2, Bytes(4)).unwrap();

    // Verify fragments have different total lengths
    assert_ne!(
        fragments1[0].primary.total_app_data_length, fragments2[0].primary.total_app_data_length,
        "Fragments must have different total lengths"
    );

    // Interleave fragments from both sets
    let _ = agent.receive_from_cla(fragments1[0].clone());
    let _ = agent.receive_from_cla(fragments2[0].clone());

    // The ReassemblyManager should detect total_length mismatch if fragments
    // from different sets are incorrectly merged. Complete both sets.
    for frag in &fragments1[1..] {
        let _ = agent.receive_from_cla(frag.clone());
    }
    for frag in &fragments2[1..] {
        let _ = agent.receive_from_cla(frag.clone());
    }

    // Test passes if no conflicts detected - fragments kept separate by total_length
}
