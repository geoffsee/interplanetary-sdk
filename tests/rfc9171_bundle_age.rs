//! RFC 9171 §4.4.2 Bundle Age Extension Block Tests

mod common;

use common::{bundle_with_zero_time, simple_bundle};
use interplanetary_sdk::bp::BlockType;
use interplanetary_sdk::bp::extensions::BundleAgeBlock;
use interplanetary_sdk::bp::processing::{process_on_forward, validate_at_generation};
use interplanetary_sdk::types::{EndpointId, SimDuration};

#[test]
fn test_rfc9171_4_4_2_bundle_age_required_when_creation_time_zero() {
    // RFC 9171 §4.4.2: "If the bundle's creation time is zero, then the
    // bundle MUST contain exactly one (1) occurrence of this type of block
    // [Bundle Age]"

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle with creation time = 0
    let bundle = bundle_with_zero_time(source, dest);

    assert_eq!(
        bundle.primary.creation_timestamp.time.as_millis(),
        0,
        "Creation time should be zero"
    );

    // Validation should fail because Bundle Age is missing
    let result = validate_at_generation(&bundle);
    assert!(
        result.is_err(),
        "Bundle MUST contain Bundle Age block when creation time is zero"
    );
}

#[test]
fn test_rfc9171_4_4_2_bundle_age_incremented_on_forward() {
    // RFC 9171 §4.4.2 + §5.4: "If the node's BPA implementation supports
    // the Bundle Age extension block, then the bundle age value MUST be
    // increased by the difference between the current time and the time
    // at which the bundle was received (i.e., the bundle's residence time
    // at this node)"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 3, 0).unwrap(),
    );

    // Add Bundle Age block with initial value 1000ms
    let initial_age_ms = 1000u64;
    let age_block = BundleAgeBlock::new(2, initial_age_ms);
    bundle.blocks.push(age_block.to_canonical().unwrap());

    // Forward with residence time 500ms
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(500);

    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(result.is_ok(), "Forward should succeed");

    // Check that Bundle Age was incremented by residence time
    let age_block_after = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .expect("Bundle Age block should still exist");

    let decoded = BundleAgeBlock::from_canonical(age_block_after).unwrap();
    assert_eq!(
        decoded.age_ms,
        initial_age_ms + residence_time.as_millis(),
        "Bundle Age MUST be increased by residence time (1000 + 500 = 1500)"
    );
}

#[test]
fn test_rfc9171_4_4_2_bundle_age_multiple_hops() {
    // Verify Bundle Age accumulates across multiple hops

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 4, 0).unwrap(),
    );

    // Start with age = 0
    let age_block = BundleAgeBlock::new(2, 0);
    bundle.blocks.push(age_block.to_canonical().unwrap());

    // First hop: residence time 100ms
    let node2 = EndpointId::ipn(0, 2, 0).unwrap();
    let _ = process_on_forward(&mut bundle, &node2, SimDuration::from_millis(100));

    // Check age after first hop
    let age_after_1 = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .map(|b| BundleAgeBlock::from_canonical(b).unwrap().age_ms)
        .unwrap();
    assert_eq!(age_after_1, 100, "Age should be 100ms after first hop");

    // Second hop: residence time 200ms
    let node3 = EndpointId::ipn(0, 3, 0).unwrap();
    let _ = process_on_forward(&mut bundle, &node3, SimDuration::from_millis(200));

    // Check age after second hop
    let age_after_2 = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .map(|b| BundleAgeBlock::from_canonical(b).unwrap().age_ms)
        .unwrap();
    assert_eq!(
        age_after_2, 300,
        "Age MUST accumulate across hops (100 + 200 = 300)"
    );
}

#[test]
fn test_rfc9171_4_4_2_bundle_age_encoding() {
    // RFC 9171 §4.4.2: "The block-type-specific data in a Bundle Age Block
    // SHALL be the bundle's age, represented as a CBOR unsigned integer"

    let age_block = BundleAgeBlock::new(2, 12345);
    let canonical = age_block.to_canonical().unwrap();

    assert_eq!(canonical.block_type, BlockType::BundleAge);
    assert!(
        !canonical.data.is_empty(),
        "Block data must contain age value"
    );

    // Decode and verify
    let decoded = BundleAgeBlock::from_canonical(&canonical).unwrap();
    assert_eq!(decoded.age_ms, 12345, "Decoded age must match original");
}
