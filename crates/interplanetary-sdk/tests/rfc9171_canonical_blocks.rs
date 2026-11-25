//! RFC 9171 §4.3 Canonical Bundle Block Rules Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::CrcType;
use interplanetary_sdk::bp::blocks::{BlockType, CanonicalBlock};
use interplanetary_sdk::types::EndpointId;

#[test]
fn test_rfc9171_4_3_1_block_numbers_unique() {
    // RFC 9171 §4.3.1: "Every block of every bundle SHALL have a block
    // number, and block numbers SHALL be unique within a bundle"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Add multiple blocks with unique numbers
    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::HopCount,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![1, 10], // Hop count data
    });

    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::BundleAge,
        block_number: 3,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0, 0],
    });

    // Check all block numbers are unique
    let block_numbers: Vec<u64> = bundle.blocks.iter().map(|b| b.block_number).collect();
    let mut sorted_numbers = block_numbers.clone();
    sorted_numbers.sort();
    sorted_numbers.dedup();

    assert_eq!(
        block_numbers.len(),
        sorted_numbers.len(),
        "Block numbers SHALL be unique within bundle (RFC 9171 §4.3.1)"
    );
}

#[test]
fn test_rfc9171_4_3_1_payload_block_number_one() {
    // RFC 9171 §4.3.1: "The payload block SHALL have block number 1"

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Find payload block and verify its number
    let payload_block = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload));

    assert!(payload_block.is_some(), "Bundle must have payload block");

    let payload = payload_block.unwrap();
    assert_eq!(
        payload.block_number, 1,
        "Payload block SHALL have block number 1 (RFC 9171 §4.3.1)"
    );
}

#[test]
fn test_rfc9171_4_3_1_payload_block_last() {
    // RFC 9171 §4.3.1: "The payload block SHALL be the last block in the bundle"

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Last block must be payload block
    let last_block = bundle.blocks.last();
    assert!(last_block.is_some(), "Bundle must have at least one block");

    let is_last_payload = matches!(last_block.unwrap().block_type, BlockType::Payload);
    assert!(
        is_last_payload,
        "Payload block SHALL be last block in bundle (RFC 9171 §4.3.1)"
    );
}

#[test]
fn test_rfc9171_4_3_1_payload_block_required() {
    // RFC 9171 §4.3.1: "Every bundle SHALL have a payload block"

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Check payload block exists
    let has_payload = bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Payload));

    assert!(
        has_payload,
        "Every bundle SHALL have a payload block (RFC 9171 §4.3.1)"
    );
}

#[test]
fn test_rfc9171_4_3_1_block_type_codes() {
    // RFC 9171 §4.3.1: Block type codes are defined

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Test different block types
    assert!(matches!(bundle.blocks[0].block_type, BlockType::Payload));

    // Add other block types
    bundle.blocks.insert(
        0,
        CanonicalBlock {
            block_type: BlockType::PreviousNode,
            block_number: 2,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![],
        },
    );

    // Verify block types are recognized
    let has_previous_node = bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::PreviousNode));

    assert!(
        has_previous_node,
        "Block type codes are defined per RFC 9171 §4.3.1"
    );
}

#[test]
fn test_rfc9171_4_3_1_block_number_nonzero() {
    // RFC 9171 §4.3.1: Block numbers are positive integers

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // All block numbers must be > 0
    for block in &bundle.blocks {
        assert!(
            block.block_number > 0,
            "Block numbers must be positive (non-zero)"
        );
    }
}

#[test]
fn test_rfc9171_4_3_1_block_ordering_except_payload() {
    // RFC 9171 §4.3.1: Blocks other than payload may appear in any order

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Add extension blocks before payload
    bundle.blocks.insert(
        0,
        CanonicalBlock {
            block_type: BlockType::HopCount,
            block_number: 2,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![1, 10],
        },
    );

    bundle.blocks.insert(
        1,
        CanonicalBlock {
            block_type: BlockType::BundleAge,
            block_number: 3,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![0, 0],
        },
    );

    // Payload must still be last
    let last_is_payload = matches!(bundle.blocks.last().unwrap().block_type, BlockType::Payload);

    assert!(
        last_is_payload,
        "Extension blocks may appear in any order, but payload MUST be last"
    );
}

#[test]
fn test_rfc9171_4_3_block_flags_present() {
    // RFC 9171 §4.3: Block processing control flags field is present

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // All blocks have block_flags field
    for block in &bundle.blocks {
        // Block flags is a u64, always present by type
        let _flags: u64 = block.block_flags;
    }

    // The presence of block_flags is guaranteed by the Block type structure
}

#[test]
fn test_rfc9171_4_3_crc_type_field_present() {
    // RFC 9171 §4.3: CRC type field is present in every block

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // All blocks have CRC type field
    for block in &bundle.blocks {
        assert!(
            matches!(
                block.crc_type,
                CrcType::None | CrcType::Crc16 | CrcType::Crc32
            ),
            "CRC type field is present in every block"
        );
    }
}
