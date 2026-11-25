//! RFC 9171 §4.4.1 Previous Node Extension Block Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::BlockType;
use interplanetary_sdk::bp::extensions::PreviousNodeBlock;
use interplanetary_sdk::bp::processing::process_on_forward;
use interplanetary_sdk::types::{EndpointId, SimDuration};

#[test]
fn test_rfc9171_4_4_1_previous_node_inserted_on_forward() {
    // RFC 9171 §4.4.1: "If the local node is the source of the bundle,
    // then the bundle MUST NOT contain any Previous Node Block. Otherwise,
    // the bundle SHOULD contain one (1) occurrence of this type of block"
    //
    // RFC 9171 §5.4: "A Previous Node block for this bundle... a new
    // Previous Node block containing the node ID of the forwarding node
    // MUST be inserted"

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 3, 0).unwrap();
    let mut bundle = simple_bundle(source.clone(), dest);

    // No Previous Node block initially
    assert!(
        !bundle
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::PreviousNode),
        "Bundle should not initially have Previous Node block"
    );

    // Forward at node 2
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(result.is_ok(), "Forward should succeed");

    // Previous Node block should now exist
    let prev_node_block = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .expect("Previous Node block MUST be inserted on forward");

    // Decode and verify it contains the forwarding node
    let decoded = PreviousNodeBlock::from_canonical(prev_node_block).unwrap();
    assert_eq!(
        decoded.previous_node, forwarding_node,
        "Previous Node block MUST contain forwarding node EID"
    );
}

#[test]
fn test_rfc9171_4_4_1_previous_node_replaced_on_forward() {
    // RFC 9171 §5.4: "If a Previous Node block already exists in the bundle,
    // then that block MUST be removed from the bundle and a new Previous Node
    // block containing the node ID of the forwarding node MUST be inserted"

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 4, 0).unwrap();
    let mut bundle = simple_bundle(source.clone(), dest);

    // Add initial Previous Node block (from node 2)
    let initial_prev_node = EndpointId::ipn(0, 2, 0).unwrap();
    let prev_block = PreviousNodeBlock::new(2, initial_prev_node.clone());
    bundle.blocks.push(prev_block.to_canonical().unwrap());

    // Forward at node 3
    let forwarding_node = EndpointId::ipn(0, 3, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(result.is_ok(), "Forward should succeed");

    // Should have exactly one Previous Node block
    let prev_node_blocks: Vec<_> = bundle
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::PreviousNode)
        .collect();

    assert_eq!(
        prev_node_blocks.len(),
        1,
        "Should have exactly one Previous Node block after forward"
    );

    // It should contain the new forwarding node, not the old one
    let decoded = PreviousNodeBlock::from_canonical(prev_node_blocks[0]).unwrap();
    assert_eq!(
        decoded.previous_node, forwarding_node,
        "Previous Node block MUST be replaced with new forwarding node"
    );
    assert_ne!(
        decoded.previous_node, initial_prev_node,
        "Old Previous Node EID must be replaced"
    );
}

#[test]
fn test_rfc9171_4_4_1_no_previous_node_when_source_is_forwarder() {
    // RFC 9171 §4.4.1: "If the local node is the source of the bundle,
    // then the bundle MUST NOT contain any Previous Node Block"

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut bundle = simple_bundle(source.clone(), dest);

    // Forward at source node (node 1)
    // When forwarding node == source, no Previous Node should be added
    let forwarding_node = source.clone();
    let residence_time = SimDuration::from_millis(100);

    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(result.is_ok(), "Forward should succeed");

    // Bundle MUST NOT contain Previous Node block when source == forwarder
    assert!(
        !bundle
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::PreviousNode),
        "Bundle MUST NOT contain Previous Node block when forwarded by source"
    );
}

#[test]
fn test_rfc9171_4_4_1_previous_node_across_multiple_hops() {
    // Verify Previous Node is updated at each hop (not accumulated)

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 5, 0).unwrap();
    let mut bundle = simple_bundle(source.clone(), dest);

    // First hop: node 2
    let node2 = EndpointId::ipn(0, 2, 0).unwrap();
    let _ = process_on_forward(&mut bundle, &node2, SimDuration::from_millis(50));

    let prev_after_1 = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .map(|b| PreviousNodeBlock::from_canonical(b).unwrap().previous_node)
        .expect("Previous Node should exist");
    assert_eq!(prev_after_1, node2, "Previous Node should be node 2");

    // Second hop: node 3
    let node3 = EndpointId::ipn(0, 3, 0).unwrap();
    let _ = process_on_forward(&mut bundle, &node3, SimDuration::from_millis(50));

    let prev_after_2 = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .map(|b| PreviousNodeBlock::from_canonical(b).unwrap().previous_node)
        .expect("Previous Node should exist");
    assert_eq!(
        prev_after_2, node3,
        "Previous Node should be updated to node 3"
    );

    // Should still have exactly one Previous Node block
    let count = bundle
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::PreviousNode)
        .count();
    assert_eq!(
        count, 1,
        "Should always have exactly one Previous Node block"
    );
}
