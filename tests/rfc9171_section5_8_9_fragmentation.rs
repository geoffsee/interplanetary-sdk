//! RFC 9171 §5.8-5.9 Bundle Fragmentation and Reassembly tests
//!
//! Tests fragmentation constraints and properties:
//! - Must-not-fragment flag (bundle flag bit 2)
//! - Fragment offset and total ADU length fields
//! - Fragment structure validation

use interplanetary_sdk::bp::blocks::{BlockFlags, BlockType, CanonicalBlock};
use interplanetary_sdk::bp::crc::CrcType;
use interplanetary_sdk::bp::{Bundle, BundleBuilder};
use interplanetary_sdk::bpa::admin::bundle_flags;
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// Test RFC 9171 §5.8: Must-not-fragment flag (bit 2)
#[test]
fn test_rfc9171_5_8_must_not_fragment_flag() {
    // RFC 9171 §4.2.3 Table 2: "Bit 2 (0x000004): Bundle must not be fragmented."
    // RFC 9171 §5.8: "A bundle whose bundle processing control flags do *NOT*
    // indicate that it must not be fragmented MAY be fragmented"

    let bundle_with_flag = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .bundle_flags(bundle_flags::MUST_NOT_FRAGMENT)
        .payload(vec![0u8; 1000])
        .build()
        .unwrap();

    // RFC 9171 §4.2.3: Verify bit 2 (0x000004) is set
    assert_eq!(
        bundle_with_flag.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT,
        bundle_flags::MUST_NOT_FRAGMENT,
        "MUST_NOT_FRAGMENT flag (bit 2) should be set to 0x000004"
    );

    assert_eq!(
        bundle_flags::MUST_NOT_FRAGMENT,
        0x000004,
        "MUST_NOT_FRAGMENT constant must match RFC 9171 §4.2.3 Table 2"
    );
}

/// Test RFC 9171 §5.8: Bundle without must-not-fragment flag may be fragmented
#[test]
fn test_rfc9171_5_8_fragmentable_bundle() {
    // RFC 9171 §5.8: A bundle without the must-not-fragment flag MAY be fragmented

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0u8; 1000])
        .build()
        .unwrap();

    // Verify must-not-fragment flag is NOT set
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::MUST_NOT_FRAGMENT,
        0,
        "Bundle without MUST_NOT_FRAGMENT flag may be fragmented"
    );
}

/// Test RFC 9171 §5.8: Fragment offset and total ADU length fields
#[test]
fn test_rfc9171_5_8_fragment_fields() {
    // RFC 9171 §5.8: "The primary block of each fragment MUST differ from that
    // of the original bundle in that the values of the fragment offset and total
    // application data unit length fields MUST be present"

    // Create a fragment manually
    let mut fragment = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0xAB; 300])
        .build()
        .unwrap();

    // Set fragment fields as required by §5.8
    fragment.primary.fragment_offset = Some(0);
    fragment.primary.total_app_data_length = Some(1000);

    // Verify fields are present
    assert!(
        fragment.primary.fragment_offset.is_some(),
        "Fragment MUST have fragment_offset field present per RFC 9171 §5.8"
    );
    assert!(
        fragment.primary.total_app_data_length.is_some(),
        "Fragment MUST have total_app_data_length field present per RFC 9171 §5.8"
    );

    assert_eq!(fragment.primary.fragment_offset, Some(0));
    assert_eq!(fragment.primary.total_app_data_length, Some(1000));
}

/// Test RFC 9171 §5.8: Multiple fragments with correct offsets
#[test]
fn test_rfc9171_5_8_fragment_offset_sequence() {
    // RFC 9171 §5.8: Fragments must have correct offset values

    let fragments = [
        create_fragment(0, 1000, &[0xAA; 300]),
        create_fragment(300, 1000, &[0xBB; 300]),
        create_fragment(600, 1000, &[0xCC; 400]),
    ];

    // Verify each fragment has correct offset and total length
    for (i, fragment) in fragments.iter().enumerate() {
        assert!(fragment.primary.fragment_offset.is_some());
        assert_eq!(fragment.primary.total_app_data_length, Some(1000));

        let expected_offset = i * 300;
        assert_eq!(
            fragment.primary.fragment_offset,
            Some(expected_offset as u64),
            "Fragment {} should have offset {}",
            i,
            expected_offset
        );
    }
}

/// Test RFC 9171 §4.2.4: Replicate-in-every-fragment block flag (bit 0)
#[test]
fn test_rfc9171_4_2_4_replicate_in_fragments_flag() {
    // RFC 9171 §4.2.4 Table 3: "Bit 0 (0x01): Block must be replicated in every fragment"

    let ext_block = CanonicalBlock {
        block_type: BlockType::Unknown(99),
        block_number: 10,
        block_flags: BlockFlags::REPLICATE_IN_FRAGMENTS,
        crc_type: CrcType::None,
        data: vec![0xDE, 0xAD],
    };

    // Verify bit 0 is set
    assert_eq!(
        ext_block.block_flags & BlockFlags::REPLICATE_IN_FRAGMENTS,
        BlockFlags::REPLICATE_IN_FRAGMENTS,
        "REPLICATE_IN_FRAGMENTS flag (bit 0) should be set"
    );

    assert_eq!(
        BlockFlags::REPLICATE_IN_FRAGMENTS,
        0x01,
        "REPLICATE_IN_FRAGMENTS must be bit 0 (0x01) per RFC 9171 §4.2.4"
    );
}

/// Test RFC 9171 §5.8: Fragment with replicate-in-fragments extension block
#[test]
fn test_rfc9171_5_8_extension_block_with_replicate_flag() {
    // RFC 9171 §5.8: Extension blocks with replicate-in-every-fragment flag
    // must be replicated in all fragments

    let mut fragment = create_fragment(0, 1000, &vec![0u8; 300]);

    // Add extension block that should be replicated
    let ext_block = CanonicalBlock {
        block_type: BlockType::Unknown(99),
        block_number: 10,
        block_flags: BlockFlags::REPLICATE_IN_FRAGMENTS,
        crc_type: CrcType::None,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    fragment.blocks.push(ext_block);

    // Verify the extension block is present and has the correct flag
    let has_replicate_block = fragment.blocks.iter().any(|b| {
        matches!(b.block_type, BlockType::Unknown(99))
            && (b.block_flags & BlockFlags::REPLICATE_IN_FRAGMENTS) != 0
    });

    assert!(
        has_replicate_block,
        "Fragment should contain extension block with REPLICATE_IN_FRAGMENTS flag"
    );
}

/// Test RFC 9171 §5.9: Fragment structure for reassembly
#[test]
fn test_rfc9171_5_9_fragment_structure_for_reassembly() {
    // RFC 9171 §5.9: Fragments must have structure that enables reassembly

    let fragment1 = create_fragment(0, 500, &[0xAA; 200]);
    let fragment2 = create_fragment(200, 500, &[0xBB; 200]);
    let fragment3 = create_fragment(400, 500, &[0xCC; 100]);

    // Verify fragments have same source and creation timestamp (same bundle ID)
    assert_eq!(fragment1.primary.source, fragment2.primary.source);
    assert_eq!(fragment1.primary.source, fragment3.primary.source);
    assert_eq!(
        fragment1.primary.creation_timestamp,
        fragment2.primary.creation_timestamp
    );

    // Verify fragments cover entire ADU
    let total_length = fragment1.primary.total_app_data_length.unwrap();
    assert_eq!(total_length, 500);

    let fragment_spans = [
        (
            fragment1.primary.fragment_offset.unwrap(),
            fragment1.blocks[0].data.len() as u64,
        ),
        (
            fragment2.primary.fragment_offset.unwrap(),
            fragment2.blocks[0].data.len() as u64,
        ),
        (
            fragment3.primary.fragment_offset.unwrap(),
            fragment3.blocks[0].data.len() as u64,
        ),
    ];

    // Verify contiguous coverage
    assert_eq!(fragment_spans[0].0, 0); // First starts at 0
    assert_eq!(fragment_spans[0].0 + fragment_spans[0].1, 200); // First ends at 200
    assert_eq!(fragment_spans[1].0, 200); // Second starts at 200
    assert_eq!(fragment_spans[1].0 + fragment_spans[1].1, 400); // Second ends at 400
    assert_eq!(fragment_spans[2].0, 400); // Third starts at 400
    assert_eq!(fragment_spans[2].0 + fragment_spans[2].1, 500); // Third ends at 500 (total)
}

/// Test RFC 9171 §5.9: Fragment IDs include offset for uniqueness
#[test]
fn test_rfc9171_5_9_bundle_id_consistency() {
    // RFC 9171 §5.9: Fragments of the same bundle have unique IDs (include offset)
    // but share the same source EID, creation timestamp, and total length

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);

    let fragment1 = create_fragment_with_id(&source, &timestamp, 0, 1000, &vec![0u8; 300]);
    let fragment2 = create_fragment_with_id(&source, &timestamp, 300, 1000, &vec![0u8; 300]);

    // Fragments have different IDs (different offsets)
    assert_ne!(
        fragment1.id(),
        fragment2.id(),
        "Fragments must have unique IDs including offset"
    );

    // But same source and timestamp (reassembly key)
    assert_eq!(fragment1.primary.source, fragment2.primary.source);
    assert_eq!(
        fragment1.primary.creation_timestamp,
        fragment2.primary.creation_timestamp
    );
    assert_eq!(
        fragment1.primary.total_app_data_length,
        fragment2.primary.total_app_data_length
    );
}

/// Helper: Create a fragment bundle
fn create_fragment(offset: u64, total_length: u64, data: &[u8]) -> Bundle {
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(data.to_vec())
        .build()
        .unwrap();

    bundle.primary.fragment_offset = Some(offset);
    bundle.primary.total_app_data_length = Some(total_length);

    bundle
}

/// Helper: Create fragment with specific source and timestamp
fn create_fragment_with_id(
    source: &EndpointId,
    timestamp: &CreationTimestamp,
    offset: u64,
    total_length: u64,
    data: &[u8],
) -> Bundle {
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(*timestamp)
        .lifetime(60_000)
        .payload(data.to_vec())
        .build()
        .unwrap();

    bundle.primary.fragment_offset = Some(offset);
    bundle.primary.total_app_data_length = Some(total_length);

    bundle
}
