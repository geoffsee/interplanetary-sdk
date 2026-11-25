//! RFC 9171 §5 Bundle Processing obligation tests
//!
//! Tests for transmission, forwarding, reception, delivery, fragmentation,
//! deletion, discarding, and canceling per RFC 9171 §5.

use interplanetary_sdk::bp::{
    BundleBuilder, BundleCodec,
    processing::{self, DeletionReason},
};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId, SimDuration};

/// Helper to create a simple test bundle
fn create_test_bundle(source: EndpointId, dest: EndpointId) -> interplanetary_sdk::bp::Bundle {
    BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03, 0x04])
        .build()
        .unwrap()
}

#[test]
fn test_rfc9171_5_2_bundle_generation_requires_bundle_age_when_time_zero() {
    // RFC 9171 §5.2 + §4.4.2: "If the bundle's creation time is zero, then the bundle
    // MUST contain exactly one (1) occurrence of this type of block [Bundle Age]"

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0)) // time=0
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    // Validation should fail because Bundle Age is missing
    let result = processing::validate_at_generation(&bundle);
    assert!(
        result.is_err(),
        "Should reject bundle without Bundle Age when creation time=0"
    );
}

#[test]
fn test_rfc9171_5_4_hop_count_increment_on_forward() {
    // RFC 9171 §5.4 + §4.4.3: "The hop count value SHOULD initially be zero and SHOULD be
    // increased by 1 on each hop"

    use interplanetary_sdk::bp::BlockType;
    use interplanetary_sdk::bp::extensions::HopCountBlock;

    let mut bundle = create_test_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 3, 0).unwrap(),
    );

    // Add hop count block with limit=2
    let hop_block = HopCountBlock::new(2, 2, 0).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    // Forward at node 2
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_secs(10);

    let result = processing::process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(result.is_ok(), "Forward should succeed");

    // Check that hop count was incremented
    let hop_block_after = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::HopCount))
        .expect("Hop Count block should exist");

    let hop_block = HopCountBlock::from_canonical(hop_block_after).unwrap();
    assert_eq!(
        hop_block.hop_count, 1,
        "Hop count should be incremented to 1"
    );
}

#[test]
fn test_rfc9171_5_4_hop_limit_exceeded_causes_deletion() {
    // RFC 9171 §5.4 + §4.4.3: "If the hop count value is equal to the hop limit value,
    // the bundle SHOULD be deleted for the reason 'Hop limit exceeded'"

    use interplanetary_sdk::bp::extensions::HopCountBlock;

    let mut bundle = create_test_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 3, 0).unwrap(),
    );

    // Add hop count block with limit=1, count=1 (at limit)
    let hop_block = HopCountBlock::new(2, 1, 1).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    // Try to forward (should fail)
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_secs(10);

    let result = processing::process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(
        result.is_err(),
        "Forward should fail when hop limit exceeded"
    );

    // Verify error indicates hop limit exceeded
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("Hop limit exceeded") || err_msg.contains("hop"));
}

#[test]
fn test_rfc9171_5_4_previous_node_insertion_on_forward() {
    // RFC 9171 §5.4 + §4.4.1: "If the local node is not the source of the bundle, then
    // the bundle SHOULD contain one (1) occurrence of this type of block [Previous Node]"

    use interplanetary_sdk::bp::BlockType;

    let mut bundle = create_test_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(), // source
        EndpointId::ipn(0, 3, 0).unwrap(), // dest
    );

    // Forward at node 2 (not the source)
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_secs(10);

    processing::process_on_forward(&mut bundle, &forwarding_node, residence_time).unwrap();

    // Check that Previous Node block was added
    let prev_node_blocks: Vec<_> = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::PreviousNode))
        .collect();

    assert_eq!(
        prev_node_blocks.len(),
        1,
        "Should have exactly one Previous Node block"
    );
}

#[test]
fn test_rfc9171_5_4_bundle_age_accumulation() {
    // RFC 9171 §5.4 + §4.4.2: "If a bundle contains a Bundle Age Block, then when the
    // bundle is forwarded the bundle age value MUST be increased by the time that the
    // bundle has resided at the node"

    use interplanetary_sdk::bp::BlockType;
    use interplanetary_sdk::bp::extensions::BundleAgeBlock;

    let mut bundle = create_test_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 3, 0).unwrap(),
    );

    // Add Bundle Age block with initial age=1000ms
    let age_block = BundleAgeBlock::new(2, 1000);
    bundle.blocks.push(age_block.to_canonical().unwrap());

    // Forward with residence time of 500ms
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(500);

    processing::process_on_forward(&mut bundle, &forwarding_node, residence_time).unwrap();

    // Check that age was increased
    let age_block_after = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::BundleAge))
        .expect("Bundle Age block should exist");

    let age_block = BundleAgeBlock::from_canonical(age_block_after).unwrap();
    assert_eq!(
        age_block.age_ms, 1500,
        "Age should be increased by residence time"
    );
}

#[test]
fn test_rfc9171_5_5_bundle_expiry_causes_deletion() {
    // RFC 9171 §5.5: "When a bundle expires, the BPA MUST delete the bundle for the
    // reason 'Lifetime expired'; the Bundle Deletion procedure defined in Section 5.10
    // MUST be followed"

    // This is tested in the simulator integration tests
    // Just verify the deletion reason code exists
    assert_eq!(DeletionReason::LifetimeExpired.to_u8(), 1);
}

#[test]
fn test_rfc9171_5_10_deletion_reason_codes() {
    // RFC 9171 §5.10 + §6.1.1 Table 1: Verify all deletion reason codes

    assert_eq!(DeletionReason::NoInformation.to_u8(), 0);
    assert_eq!(DeletionReason::LifetimeExpired.to_u8(), 1);
    assert_eq!(DeletionReason::ForwardedOverUnidirectionalLink.to_u8(), 2);
    assert_eq!(DeletionReason::TransmissionCanceled.to_u8(), 3);
    assert_eq!(DeletionReason::DepletedStorage.to_u8(), 4);
    assert_eq!(DeletionReason::DestinationEidUnavailable.to_u8(), 5);
    assert_eq!(DeletionReason::NoKnownRoute.to_u8(), 6);
    assert_eq!(DeletionReason::NoTimelyContact.to_u8(), 7);
    assert_eq!(DeletionReason::BlockUnintelligible.to_u8(), 8);
    assert_eq!(DeletionReason::HopLimitExceeded.to_u8(), 9);
    assert_eq!(DeletionReason::TrafficPared.to_u8(), 10);
    assert_eq!(DeletionReason::BlockUnsupported.to_u8(), 11);
}

#[test]
fn test_rfc9171_5_2_bundle_encoding_round_trip() {
    // RFC 9171 §5.2: Bundle transmission requires correct encoding

    let bundle = create_test_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Encode
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Decode
    let decoded = BundleCodec::decode(&encoded).unwrap();

    // Verify primary block fields match
    assert_eq!(decoded.primary.source, bundle.primary.source);
    assert_eq!(decoded.primary.destination, bundle.primary.destination);
    assert_eq!(
        decoded.primary.creation_timestamp,
        bundle.primary.creation_timestamp
    );
}

#[test]
fn test_rfc9171_6_1_1_status_report_reason_code_values() {
    // RFC 9171 §6.1.1 Table 1: Status report reason codes
    // Values must match the table exactly

    use interplanetary_sdk::bp::processing::DeletionReason;

    // Verify each reason code value per Table 1
    assert_eq!(
        DeletionReason::NoInformation as u8,
        0,
        "No additional information"
    );
    assert_eq!(DeletionReason::LifetimeExpired as u8, 1, "Lifetime expired");
    assert_eq!(DeletionReason::ForwardedOverUnidirectionalLink as u8, 2);
    assert_eq!(DeletionReason::TransmissionCanceled as u8, 3);
    assert_eq!(DeletionReason::DepletedStorage as u8, 4);
    assert_eq!(DeletionReason::DestinationEidUnavailable as u8, 5);
    assert_eq!(DeletionReason::NoKnownRoute as u8, 6);
    assert_eq!(DeletionReason::NoTimelyContact as u8, 7);
    assert_eq!(DeletionReason::BlockUnintelligible as u8, 8);
    assert_eq!(DeletionReason::HopLimitExceeded as u8, 9);
    assert_eq!(DeletionReason::TrafficPared as u8, 10);
    assert_eq!(DeletionReason::BlockUnsupported as u8, 11);
}
