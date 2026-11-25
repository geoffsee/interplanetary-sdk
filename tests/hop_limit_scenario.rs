//! 3-node scenario test for hop limit exceeded deletion per RFC 9171 §4.4.3

use interplanetary_sdk::{
    bp::{BundleBuilder, CrcType, HopCountBlock, process_on_forward},
    types::{CreationTimestamp, DtnTimeMs, EndpointId, SimDuration},
};

#[test]
fn test_hop_limit_deletion_3_node_scenario() {
    // Scenario: Node 1 -> Node 2 -> Node 3
    // Bundle has hop_limit = 1
    // Bundle should be deleted at Node 2 when trying to forward to Node 3

    let node1_eid = EndpointId::ipn(0, 1, 0).unwrap();
    let node2_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let node3_eid = EndpointId::ipn(0, 3, 0).unwrap();

    // Create bundle at Node 1 with hop limit = 1
    let mut bundle = BundleBuilder::new()
        .source(node1_eid.clone())
        .destination(node3_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .crc_type(CrcType::Crc16)
        .build()
        .unwrap();

    // Add hop count block with limit 1
    let hop_block = HopCountBlock::new(2, 1, 0).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    // Node 1 forwards to Node 2 (first hop)
    let residence_at_node1 = SimDuration::from_millis(100);
    let result = process_on_forward(&mut bundle, &node1_eid, residence_at_node1);
    assert!(result.is_ok(), "First forward should succeed");

    // Check hop count was incremented to 1
    let hop_block = HopCountBlock::from_canonical(
        bundle
            .blocks
            .iter()
            .find(|b| b.block_type == interplanetary_sdk::bp::BlockType::HopCount)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(hop_block.hop_count, 1);
    assert_eq!(hop_block.hop_limit, 1);
    assert!(!hop_block.is_exceeded(), "Count = limit, not yet exceeded");

    // Node 2 attempts to forward to Node 3 (second hop)
    let residence_at_node2 = SimDuration::from_millis(150);
    let result = process_on_forward(&mut bundle, &node2_eid, residence_at_node2);

    // Should fail with hop limit exceeded
    assert!(
        result.is_err(),
        "Second forward should fail: hop limit exceeded"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Hop limit exceeded"),
        "Error should mention hop limit: {}",
        error_msg
    );

    // Verify the hop count would be 2 > limit of 1
    // (The increment happens before the check, so the error is caught)
}

#[test]
fn test_hop_limit_allows_exactly_limit_hops() {
    // Test that hop_limit=2 allows exactly 2 hops (3 nodes)
    let node1_eid = EndpointId::ipn(0, 1, 0).unwrap();
    let node2_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let node3_eid = EndpointId::ipn(0, 3, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(node1_eid.clone())
        .destination(node3_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test".to_vec())
        .crc_type(CrcType::Crc16)
        .build()
        .unwrap();

    // Hop limit = 2 (allows 2 hops)
    let hop_block = HopCountBlock::new(2, 2, 0).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    // First hop: Node 1 -> Node 2
    assert!(process_on_forward(&mut bundle, &node1_eid, SimDuration::ZERO).is_ok());

    // Second hop: Node 2 -> Node 3
    assert!(process_on_forward(&mut bundle, &node2_eid, SimDuration::ZERO).is_ok());

    // Third hop would fail
    let result = process_on_forward(&mut bundle, &node3_eid, SimDuration::ZERO);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Hop limit exceeded")
    );
}

#[test]
fn test_deletion_reason_code() {
    use interplanetary_sdk::bp::DeletionReason;

    // Verify hop limit exceeded reason code is 9 per RFC 9171 §6.1.1 Table 1
    assert_eq!(DeletionReason::HopLimitExceeded.to_u8(), 9);
}
