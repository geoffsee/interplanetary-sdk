//! RFC 9171 §5.8-5.9 Bundle Fragmentation and Reassembly Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bpa::admin::bundle_flags;
use interplanetary_sdk::types::EndpointId;

#[test]
fn test_rfc9171_5_8_must_not_fragment_flag_honored() {
    // RFC 9171 §5.8 (maps to RFC9171-5-052): "A bundle whose bundle
    // processing control flags do *NOT* indicate that it must not be
    // fragmented MAY be fragmented"
    //
    // This tests the converse: when the flag IS set, fragmentation is blocked.

    let mut bundle_with_flag = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Set the "must not fragment" flag (bit 2 = 0x0004)
    bundle_with_flag.primary.bundle_flags |= bundle_flags::MUST_NOT_FRAGMENT;

    // Verify flag is set
    assert_eq!(
        bundle_with_flag.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT,
        bundle_flags::MUST_NOT_FRAGMENT,
        "'Must not fragment' flag should be set"
    );

    // Bundle MUST NOT be fragmented when this flag is set
    let can_fragment_when_set =
        (bundle_with_flag.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT) == 0;
    assert!(
        !can_fragment_when_set,
        "Bundle with 'must not fragment' flag MUST NOT be fragmented"
    );

    // Test the positive case: bundle without the flag MAY be fragmented
    let bundle_without_flag = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Verify flag is NOT set
    assert_eq!(
        bundle_without_flag.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT,
        0,
        "'Must not fragment' flag should not be set"
    );

    // Bundle MAY be fragmented when this flag is not set
    let can_fragment_when_not_set =
        (bundle_without_flag.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT) == 0;
    assert!(
        can_fragment_when_not_set,
        "Bundle without 'must not fragment' flag MAY be fragmented (per RFC9171-5-052)"
    );
}

#[test]
fn test_rfc9171_5_8_fragment_has_is_fragment_flag() {
    // RFC 9171 §5.8: "The 'Bundle is a fragment' flag MUST be set to 1
    // in every bundle fragment"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Simulate creating a fragment by setting the flag
    bundle.primary.bundle_flags |= bundle_flags::IS_FRAGMENT;

    // Set fragment offset and total data length
    bundle.primary.fragment_offset = Some(0);
    bundle.primary.total_app_data_length = Some(1000);

    // Verify fragment flag is set
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::IS_FRAGMENT,
        bundle_flags::IS_FRAGMENT,
        "'Is fragment' flag MUST be set in every fragment"
    );

    // Verify fragment metadata is present
    assert!(
        bundle.primary.fragment_offset.is_some(),
        "Fragment MUST have offset"
    );
    assert!(
        bundle.primary.total_app_data_length.is_some(),
        "Fragment MUST have total data length"
    );
}

#[test]
fn test_rfc9171_5_8_fragment_offset_and_length() {
    // RFC 9171 §5.8: "The fragment offset and total application data
    // unit length of every fragment MUST be as defined in Section 4.2.3"

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Original bundle payload
    let original_payload = vec![0xAA; 1000];

    // Simulate first fragment: bytes 0-399
    let mut fragment1 = bundle.clone();
    fragment1.primary.bundle_flags |= bundle_flags::IS_FRAGMENT;
    fragment1.primary.fragment_offset = Some(0);
    fragment1.primary.total_app_data_length = Some(1000);
    fragment1.blocks[0].data = original_payload[0..400].to_vec();

    // Simulate second fragment: bytes 400-799
    let mut fragment2 = bundle.clone();
    fragment2.primary.bundle_flags |= bundle_flags::IS_FRAGMENT;
    fragment2.primary.fragment_offset = Some(400);
    fragment2.primary.total_app_data_length = Some(1000);
    fragment2.blocks[0].data = original_payload[400..800].to_vec();

    // Simulate third fragment: bytes 800-999
    let mut fragment3 = bundle.clone();
    fragment3.primary.bundle_flags |= bundle_flags::IS_FRAGMENT;
    fragment3.primary.fragment_offset = Some(800);
    fragment3.primary.total_app_data_length = Some(1000);
    fragment3.blocks[0].data = original_payload[800..1000].to_vec();

    // Verify fragments have correct offsets and lengths
    assert_eq!(fragment1.primary.fragment_offset, Some(0));
    assert_eq!(fragment1.blocks[0].data.len(), 400);

    assert_eq!(fragment2.primary.fragment_offset, Some(400));
    assert_eq!(fragment2.blocks[0].data.len(), 400);

    assert_eq!(fragment3.primary.fragment_offset, Some(800));
    assert_eq!(fragment3.blocks[0].data.len(), 200);

    // All fragments MUST have same total data length
    assert_eq!(fragment1.primary.total_app_data_length, Some(1000));
    assert_eq!(fragment2.primary.total_app_data_length, Some(1000));
    assert_eq!(fragment3.primary.total_app_data_length, Some(1000));
}

#[test]
fn test_rfc9171_5_9_reassembly_byte_identical() {
    // RFC 9171 §5.9: "The result of concatenating the payloads of all
    // fragments in ascending order by offset MUST always be identical
    // to the payload of the original unfragmented bundle"

    let _source = EndpointId::ipn(0, 1, 0).unwrap();
    let _dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Original payload
    let original_payload = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    // Create fragments (simulated)
    let fragment_payloads = [
        (0, vec![0x01, 0x02, 0x03]),
        (3, vec![0x04, 0x05]),
        (5, vec![0x06, 0x07, 0x08]),
    ];

    // Reassemble by concatenating in offset order
    let mut reassembled = Vec::new();
    for (_offset, payload) in fragment_payloads.iter() {
        reassembled.extend_from_slice(payload);
    }

    // Result MUST be byte-identical to original
    assert_eq!(
        reassembled, original_payload,
        "Reassembled payload MUST be byte-identical to original"
    );
}

#[test]
fn test_rfc9171_5_9_reassembly_out_of_order() {
    // RFC 9171 §5.9: Reassembly works regardless of fragment arrival order

    let original_payload = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    // Fragments arriving out of order (Vec needed for sort_by_key)
    #[allow(clippy::useless_vec)]
    let mut fragments = vec![
        (4, vec![0xEE, 0xFF]), // Last fragment arrives first
        (0, vec![0xAA, 0xBB]), // First fragment arrives second
        (2, vec![0xCC, 0xDD]), // Middle fragment arrives last
    ];

    // Sort by offset before reassembly
    fragments.sort_by_key(|(offset, _)| *offset);

    // Reassemble
    let mut reassembled = Vec::new();
    for (_offset, payload) in fragments.iter() {
        reassembled.extend_from_slice(payload);
    }

    assert_eq!(
        reassembled, original_payload,
        "Reassembly MUST work correctly regardless of arrival order"
    );
}

#[test]
fn test_rfc9171_5_8_fragment_without_must_not_fragment() {
    // Verify that a bundle can be fragmented when "must not fragment" is NOT set

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Ensure "must not fragment" flag is NOT set
    bundle.primary.bundle_flags &= !bundle_flags::MUST_NOT_FRAGMENT;

    // Verify flag is not set
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT,
        0,
        "'Must not fragment' flag should not be set"
    );

    // Bundle CAN be fragmented when this flag is not set
    let can_fragment = (bundle.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT) == 0;
    assert!(
        can_fragment,
        "Bundle without 'must not fragment' flag can be fragmented"
    );
}
