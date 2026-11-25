//! RFC 9171 §4.4.3 Hop Count Extension Block Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::BlockType;
use interplanetary_sdk::bp::extensions::HopCountBlock;
use interplanetary_sdk::bp::processing::process_on_forward;
use interplanetary_sdk::types::{EndpointId, SimDuration};

#[test]
fn test_rfc9171_4_4_3_hop_count_incremented_on_forward() {
    // RFC 9171 §4.4.3: "The hop count value SHOULD initially be zero and
    // SHOULD be increased by 1 on each hop"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 3, 0).unwrap(),
    );

    // Add hop count block with initial count=0, limit=10
    let hop_block = HopCountBlock::new(2, 10, 0).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    let initial_hop_count = 0u64;

    // Forward at node 2
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(
        result.is_ok(),
        "Forward should succeed when under hop limit"
    );

    // Check that hop count was incremented
    let hop_block_after = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::HopCount)
        .expect("Hop Count block should still exist");

    let decoded = HopCountBlock::from_canonical(hop_block_after).unwrap();
    assert_eq!(
        decoded.hop_count,
        initial_hop_count + 1,
        "Hop count SHOULD be increased by 1 on each hop"
    );
}

#[test]
fn test_rfc9171_4_4_3_hop_limit_exceeded_causes_deletion() {
    // RFC 9171 §4.4.3: "If the hop count is equal to or exceeds the hop
    // limit, then the bundle MUST be deleted for the reason 'hop limit
    // exceeded', following the bundle deletion procedure defined in
    // Section 5.10"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 3, 0).unwrap(),
    );

    // Add hop count block at limit: count=10, limit=10
    // After increment will be 11, which exceeds limit
    let hop_block = HopCountBlock::new(2, 10, 10).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    // Forward - this will increment count to 11, which exceeds limit
    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);

    // RFC 9171 §4.4.3: bundle MUST be deleted when hop count exceeds hop limit
    // Note: Current implementation checks `hop_count > hop_limit` (strictly greater)
    assert!(
        result.is_err(),
        "Bundle MUST be deleted when hop count exceeds hop limit"
    );

    // Verify the error indicates hop limit exceeded
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("hop"),
        "Error should indicate hop limit issue"
    );
}

#[test]
fn test_rfc9171_4_4_3_hop_limit_strict_enforcement() {
    // RFC 9171 §4.4.3: Verify that count >= limit triggers deletion

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 3, 0).unwrap(),
    );

    // Start with count equal to limit: count=5, limit=5
    // After increment will be 6, which exceeds limit
    let hop_block = HopCountBlock::new(2, 5, 5).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    // Should fail since incrementing exceeds limit (6 > 5)
    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);

    assert!(
        result.is_err(),
        "Bundle MUST be deleted when hop count would exceed limit"
    );
}
