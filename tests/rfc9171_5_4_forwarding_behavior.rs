//! RFC 9171 §5.4 Bundle Forwarding - BPA Forwarding Path Tests
//!
//! These tests exercise the Bundle Processing Agent forwarding behavior,
//! verifying hop count, previous node insertion, bundle age updates, and
//! forwarding failure scenarios.

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::extensions::{BundleAgeBlock, HopCountBlock, PreviousNodeBlock};
use interplanetary_sdk::bp::processing::process_on_forward;
use interplanetary_sdk::bp::{BlockType, BundleBuilder};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId, SimDuration};

#[test]
fn test_rfc9171_5_009_forward_selects_next_hop_and_updates_metadata() {
    // RFC 9171 §5.4 Step 3: "Provided the BPA succeeded in selecting the node
    // or nodes to forward the bundle to, the BPA MUST select one or more
    // appropriate convergence-layer adapters (CLAs) through which to forward
    // the bundle to the selected nodes."
    //
    // This test verifies that process_on_forward updates bundle metadata
    // (hop count, previous node, bundle age) as required for forwarding.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 10, 0).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(60000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    // Add Hop Count extension block (limit=10, count=0)
    let hop_block = HopCountBlock::new(2, 10, 0).unwrap();
    bundle.blocks.insert(0, hop_block.to_canonical().unwrap());

    // Add Bundle Age extension block (age=0)
    let age_block = BundleAgeBlock::new(3, 0);
    bundle.blocks.insert(1, age_block.to_canonical().unwrap());

    let forwarder = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(150);

    // Capture initial hop count
    let initial_hop_count = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::HopCount)
        .and_then(|b| HopCountBlock::from_canonical(b).ok())
        .map(|hb| hb.hop_count)
        .unwrap();

    // Forward the bundle through the BPA
    let result = process_on_forward(&mut bundle, &forwarder, residence_time);

    assert!(result.is_ok(), "BPA forwarding should succeed");

    // Verify hop count incremented
    let new_hop_count = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::HopCount)
        .and_then(|b| HopCountBlock::from_canonical(b).ok())
        .map(|hb| hb.hop_count)
        .unwrap();
    assert_eq!(
        new_hop_count,
        initial_hop_count + 1,
        "Hop count MUST be incremented on forward"
    );

    // Verify Previous Node block inserted
    let prev_node = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .and_then(|b| PreviousNodeBlock::from_canonical(b).ok())
        .expect("Previous Node block MUST be inserted");
    assert_eq!(
        prev_node.previous_node, forwarder,
        "Previous Node MUST be set to forwarding node EID"
    );

    // Verify Bundle Age incremented
    let new_age = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .and_then(|b| BundleAgeBlock::from_canonical(b).ok())
        .map(|ab| ab.age_ms)
        .unwrap();
    assert!(
        new_age >= 150,
        "Bundle age MUST be increased by residence time (expected >= 150ms, got {}ms)",
        new_age
    );
}

#[test]
fn test_rfc9171_5_012_hop_limit_exceeded_prevents_forward() {
    // RFC 9171 §5.4 Step 4: Hop count is incremented before forwarding.
    // §4.4.3: If hop count >= hop limit, bundle MUST be deleted.
    //
    // This test verifies that the BPA rejects forwarding when hop limit
    // would be exceeded.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 10, 0).unwrap();

    // Create bundle with hop count block
    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(60000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Add Hop Count extension block (limit=5, count starts at 0)
    let hop_block = HopCountBlock::new(2, 5, 0).unwrap();
    bundle.blocks.insert(0, hop_block.to_canonical().unwrap());

    // Manually set hop count to limit - 1
    let hop_block_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::HopCount)
        .unwrap();
    let mut hop_block = HopCountBlock::from_canonical(&bundle.blocks[hop_block_idx]).unwrap();
    hop_block.hop_count = (hop_block.hop_limit as u64) - 1;
    bundle.blocks[hop_block_idx] = hop_block.to_canonical().unwrap();

    let forwarder = EndpointId::ipn(0, 2, 0).unwrap();

    // First forward: count = limit - 1, should succeed and set count = limit
    let result = process_on_forward(&mut bundle, &forwarder, SimDuration::ZERO);
    assert!(result.is_ok(), "Forward should succeed when count < limit");

    // Verify count now equals limit
    let hop_count_after_first = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::HopCount)
        .and_then(|b| HopCountBlock::from_canonical(b).ok())
        .map(|hb| hb.hop_count)
        .unwrap();
    let hop_limit = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::HopCount)
        .and_then(|b| HopCountBlock::from_canonical(b).ok())
        .map(|hb| hb.hop_limit)
        .unwrap();
    assert_eq!(
        hop_count_after_first, hop_limit as u64,
        "After forward, count should equal limit"
    );

    // Second forward: count = limit, increment would exceed
    let result = process_on_forward(&mut bundle, &forwarder, SimDuration::ZERO);
    assert!(result.is_err(), "Forward MUST fail when hop count >= limit");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Hop limit exceeded"),
        "Error must indicate hop limit exceeded"
    );
}

#[test]
fn test_rfc9171_5_014_previous_node_inserted_by_forwarder() {
    // RFC 9171 §5.4 Step 4: "If the BPA is configured to attach Previous Node
    // Blocks to forwarded bundles, then a Previous Node Block, as defined in
    // Section 4.4.1, containing the node ID of the forwarding node MUST be
    // inserted into the bundle."
    //
    // §4.4.1: "If the local node is the source of the bundle, then the bundle
    // MUST NOT contain any Previous Node Block."

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 10, 0).unwrap();

    // Test 1: Source node forwards its own bundle - no Previous Node
    let mut bundle = simple_bundle(source.clone(), dest.clone());
    let result = process_on_forward(&mut bundle, &source, SimDuration::ZERO);
    assert!(result.is_ok());

    let has_prev_node = bundle
        .blocks
        .iter()
        .any(|b| b.block_type == BlockType::PreviousNode);
    assert!(
        !has_prev_node,
        "Source MUST NOT insert Previous Node block when forwarding its own bundle"
    );

    // Test 2: Intermediate node forwards - inserts Previous Node
    let mut bundle = simple_bundle(source, dest);
    let forwarder = EndpointId::ipn(0, 2, 0).unwrap();
    let result = process_on_forward(&mut bundle, &forwarder, SimDuration::ZERO);
    assert!(result.is_ok());

    let prev_node_block = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .expect("Intermediate forwarder MUST insert Previous Node block");
    let prev_node = PreviousNodeBlock::from_canonical(prev_node_block).unwrap();
    assert_eq!(
        prev_node.previous_node, forwarder,
        "Previous Node MUST contain forwarding node EID"
    );
}

#[test]
fn test_rfc9171_5_015_bundle_age_increased_before_forward() {
    // RFC 9171 §5.4 Step 4: "If the bundle has a Bundle Age block, as defined
    // in Section 4.4.2, then at the last possible moment before the CLA
    // initiates conveyance of the bundle via the CL protocol, the value of the
    // bundle's age MUST be increased by the time that has elapsed from the
    // time the bundle was received (or, if the local node is the source of the
    // bundle, from the time the bundle was created by the local BPA) to the
    // time at which the bundle is transmitted."

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(60000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Add Bundle Age extension block with initial age 1000ms
    let age_block = BundleAgeBlock::new(2, 1000);
    bundle.blocks.insert(0, age_block.to_canonical().unwrap());

    let initial_age = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .and_then(|b| BundleAgeBlock::from_canonical(b).ok())
        .map(|ab| ab.age_ms)
        .unwrap();

    let forwarder = EndpointId::ipn(0, 5, 0).unwrap();
    let residence_time = SimDuration::from_millis(2500); // 2.5 seconds

    let result = process_on_forward(&mut bundle, &forwarder, residence_time);
    assert!(result.is_ok());

    let new_age = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .and_then(|b| BundleAgeBlock::from_canonical(b).ok())
        .map(|ab| ab.age_ms)
        .unwrap();

    assert_eq!(
        new_age,
        initial_age + residence_time.as_millis(),
        "Bundle age MUST be increased by residence time"
    );
}

#[test]
fn test_rfc9171_5_013_previous_node_replaced_on_each_forward() {
    // RFC 9171 §5.4 Step 4: "If the bundle has a Previous Node Block, as
    // defined in Section 4.4.1, then that block MUST be removed from the
    // bundle before the new Previous Node Block is added."

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 10, 0).unwrap();
    let mut bundle = simple_bundle(source, dest);

    // First hop: node 2 forwards
    let node2 = EndpointId::ipn(0, 2, 0).unwrap();
    process_on_forward(&mut bundle, &node2, SimDuration::ZERO).unwrap();

    let prev_after_first = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .and_then(|b| PreviousNodeBlock::from_canonical(b).ok())
        .unwrap();
    assert_eq!(prev_after_first.previous_node, node2);

    // Count Previous Node blocks
    let prev_count_after_first = bundle
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::PreviousNode)
        .count();
    assert_eq!(
        prev_count_after_first, 1,
        "Should have exactly one Previous Node block"
    );

    // Second hop: node 3 forwards
    let node3 = EndpointId::ipn(0, 3, 0).unwrap();
    process_on_forward(&mut bundle, &node3, SimDuration::ZERO).unwrap();

    // Old Previous Node (node2) MUST be removed
    let prev_after_second = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .and_then(|b| PreviousNodeBlock::from_canonical(b).ok())
        .unwrap();
    assert_eq!(
        prev_after_second.previous_node, node3,
        "Previous Node MUST be updated to current forwarder"
    );

    // Still exactly one Previous Node block
    let prev_count_after_second = bundle
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::PreviousNode)
        .count();
    assert_eq!(
        prev_count_after_second, 1,
        "Old Previous Node MUST be removed before adding new one"
    );
}

#[test]
fn test_rfc9171_5_4_multi_hop_forwarding_path() {
    // RFC 9171 §5.4: Full forwarding path through multiple intermediate nodes
    // Verifies cumulative effects: hop count increments, age accumulates,
    // previous node updates on each hop.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 99, 0).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(60000)
        .payload(b"multi-hop test".to_vec())
        .build()
        .unwrap();

    // Add Hop Count extension block (limit=10, count=0)
    let hop_block = HopCountBlock::new(2, 10, 0).unwrap();
    bundle.blocks.insert(0, hop_block.to_canonical().unwrap());

    // Add Bundle Age extension block (age=0)
    let age_block = BundleAgeBlock::new(3, 0);
    bundle.blocks.insert(1, age_block.to_canonical().unwrap());

    // Simulate 4-hop path: source -> n2 -> n3 -> n4 -> dest
    let hops = [
        (EndpointId::ipn(0, 2, 0).unwrap(), 100u64), // node 2, 100ms
        (EndpointId::ipn(0, 3, 0).unwrap(), 200u64), // node 3, 200ms
        (EndpointId::ipn(0, 4, 0).unwrap(), 150u64), // node 4, 150ms
    ];

    for (idx, (node, residence_ms)) in hops.iter().enumerate() {
        let result = process_on_forward(&mut bundle, node, SimDuration::from_millis(*residence_ms));
        assert!(result.is_ok(), "Hop {} should succeed", idx + 1);

        // Verify hop count
        let hop_count = bundle
            .blocks
            .iter()
            .find(|b| b.block_type == BlockType::HopCount)
            .and_then(|b| HopCountBlock::from_canonical(b).ok())
            .map(|hb| hb.hop_count)
            .unwrap();
        assert_eq!(
            hop_count,
            (idx + 1) as u64,
            "Hop count after hop {}",
            idx + 1
        );

        // Verify previous node is current forwarder
        let prev = bundle
            .blocks
            .iter()
            .find(|b| b.block_type == BlockType::PreviousNode)
            .and_then(|b| PreviousNodeBlock::from_canonical(b).ok())
            .unwrap();
        assert_eq!(
            prev.previous_node,
            *node,
            "Previous node after hop {}",
            idx + 1
        );
    }

    // Verify total bundle age
    let final_age = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .and_then(|b| BundleAgeBlock::from_canonical(b).ok())
        .map(|ab| ab.age_ms)
        .unwrap();
    let total_residence: u64 = hops.iter().map(|(_, ms)| ms).sum();
    assert_eq!(
        final_age, total_residence,
        "Total age MUST equal sum of residence times"
    );

    // Verify hop count
    let final_hop_count = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::HopCount)
        .and_then(|b| HopCountBlock::from_canonical(b).ok())
        .map(|hb| hb.hop_count)
        .unwrap();
    assert_eq!(final_hop_count, 3, "Should have 3 hops after 3 forwards");
}
