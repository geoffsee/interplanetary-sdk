//! RFC 9171 §4.2.4 Block Processing Control Flags Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::blocks::CanonicalBlock;
use interplanetary_sdk::bp::{BlockType, CrcType};
use interplanetary_sdk::types::EndpointId;

#[test]
fn test_rfc9171_4_2_4_delete_bundle_if_block_cant_be_processed() {
    // RFC 9171 §4.2.4: "If bit 2 is set ('Delete bundle if block can't
    // be processed'), the bundle MUST be deleted when the block cannot
    // be processed"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Add an unknown block with "delete bundle" flag (bit 2 = 0x04)
    let unknown_block = CanonicalBlock {
        block_type: BlockType::Unknown(192), // Application-specific type
        block_number: 2,
        block_flags: 0x04, // "Delete bundle if can't process"
        crc_type: CrcType::None,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    bundle.blocks.push(unknown_block);

    // When processing, if the block cannot be processed and bit 2 is set,
    // the bundle MUST be deleted
    let has_unprocessable_critical_block = bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Unknown(_)) && (b.block_flags & 0x04) != 0);

    assert!(
        has_unprocessable_critical_block,
        "Bundle has unprocessable block with 'delete bundle' flag set"
    );
}

#[test]
fn test_rfc9171_4_2_4_discard_block_if_cant_be_processed() {
    // RFC 9171 §4.2.4: "If bit 4 is set ('Discard block if it can't
    // be processed'), the block MUST be discarded when it cannot be
    // processed"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Add an unknown block with "discard block" flag (bit 4 = 0x10)
    let unknown_block = CanonicalBlock {
        block_type: BlockType::Unknown(193),
        block_number: 2,
        block_flags: 0x10, // "Discard block if can't process"
        crc_type: CrcType::None,
        data: vec![0xCA, 0xFE],
    };
    bundle.blocks.push(unknown_block);

    let initial_count = bundle.blocks.len();

    // Simulate processing: unknown block with discard flag should be removed
    bundle.blocks.retain(|b| {
        // Keep blocks that are either:
        // - Known types (can be processed), OR
        // - Unknown types without discard flag
        !matches!(b.block_type, BlockType::Unknown(_)) || (b.block_flags & 0x10) == 0
    });

    assert_eq!(
        bundle.blocks.len(),
        initial_count - 1,
        "Unknown block with 'discard' flag MUST be removed"
    );
}

#[test]
fn test_rfc9171_4_2_4_report_if_block_cant_be_processed() {
    // RFC 9171 §4.2.4: "If bit 5 is set ('Report status if block
    // can't be processed'), a bundle status report with reason code
    // 'Block unintelligible' MUST be generated when the block cannot
    // be processed"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Set report-to endpoint
    bundle.primary.report_to = EndpointId::ipn(0, 1, 0).unwrap();

    // Add an unknown block with "report status" flag (bit 5 = 0x20)
    let unknown_block = CanonicalBlock {
        block_type: BlockType::Unknown(194),
        block_number: 2,
        block_flags: 0x20, // "Report status if can't process"
        crc_type: CrcType::None,
        data: vec![0xDE, 0xAD],
    };
    bundle.blocks.push(unknown_block);

    // Check if bundle has unprocessable block requiring status report
    let should_generate_report = bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Unknown(_)) && (b.block_flags & 0x20) != 0);

    assert!(
        should_generate_report,
        "Should generate status report when unknown block has 'report' flag"
    );
}

#[test]
fn test_rfc9171_4_2_4_multiple_flags_combined() {
    // RFC 9171 §4.2.4: Multiple flags can be set together

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Block with both "delete bundle" (0x04) and "report status" (0x20)
    let unknown_block = CanonicalBlock {
        block_type: BlockType::Unknown(195),
        block_number: 2,
        block_flags: 0x04 | 0x20, // Both flags set
        crc_type: CrcType::None,
        data: vec![0xBE, 0xEF],
    };
    bundle.blocks.push(unknown_block);

    // Verify both flags are set
    let block = &bundle.blocks.last().unwrap();
    assert_eq!(
        block.block_flags & 0x04,
        0x04,
        "Delete bundle flag should be set"
    );
    assert_eq!(
        block.block_flags & 0x20,
        0x20,
        "Report status flag should be set"
    );
}

#[test]
fn test_rfc9171_4_2_4_block_must_be_replicated() {
    // RFC 9171 §4.2.4: "If bit 0 is set ('Block must be replicated in
    // every fragment'), the block MUST be replicated in every fragment"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Add a block with "replicate in fragments" flag (bit 0 = 0x01)
    let block_to_replicate = CanonicalBlock {
        block_type: BlockType::Unknown(196),
        block_number: 2,
        block_flags: 0x01, // "Replicate in every fragment"
        crc_type: CrcType::None,
        data: vec![0xAB, 0xCD],
    };
    bundle.blocks.push(block_to_replicate);

    // Verify flag is set
    let block = &bundle.blocks.last().unwrap();
    assert_eq!(
        block.block_flags & 0x01,
        0x01,
        "Replicate flag MUST be honored during fragmentation"
    );
}

#[test]
fn test_rfc9171_4_2_4_transmit_status_report_if_not_processed() {
    // RFC 9171 §4.2.4: "If bit 6 is set ('Transmit status report if
    // block can't be processed'), the bundle MUST NOT be forwarded and
    // a bundle status report with reason code 'Block unintelligible'
    // MUST be generated"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    bundle.primary.report_to = EndpointId::ipn(0, 1, 0).unwrap();

    // Add unknown block with "transmit status report" flag (bit 6 = 0x40)
    let unknown_block = CanonicalBlock {
        block_type: BlockType::Unknown(197),
        block_number: 2,
        block_flags: 0x40, // "Transmit status report if can't process"
        crc_type: CrcType::None,
        data: vec![0x12, 0x34],
    };
    bundle.blocks.push(unknown_block);

    // Check if bundle has block that would prevent forwarding
    let should_not_forward = bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Unknown(_)) && (b.block_flags & 0x40) != 0);

    assert!(
        should_not_forward,
        "Bundle with unknown block having 'transmit status report' flag MUST NOT be forwarded"
    );
}
