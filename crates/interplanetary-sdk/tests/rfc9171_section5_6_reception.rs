//! RFC 9171 §5.6 Bundle Reception integration tests
//!
//! Tests the complete bundle reception procedure including:
//! - Block processing control flags (bits 1, 2, 4)
//! - Status report generation on reception
//! - Handling of unsupported blocks

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::bp::blocks::{BlockFlags, BlockType, CanonicalBlock};
use interplanetary_sdk::bp::crc::CrcType;
use interplanetary_sdk::bp::processing::{DeletionReason, ReceptionResult, process_on_reception};
use interplanetary_sdk::bpa::admin::{bundle_flags, is_admin_record, requests_reception_report};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// Test RFC 9171 §5.6: Bundle with unsupported critical block must be deleted
#[test]
fn test_rfc9171_5_6_delete_on_critical_unsupported_block() {
    // RFC 9171 §5.6: "If the 'Delete bundle if block can't be processed' flag (bit 2)
    // is 1 in the block's block processing control flags, then the BPA MUST delete
    // the bundle for the reason 'Block unsupported'"

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    // Add unsupported block with DELETE_BUNDLE_ON_FAILURE flag (bit 2 = 0x04)
    let unsupported_block = CanonicalBlock {
        block_type: BlockType::Unknown(999),
        block_number: 10,
        block_flags: BlockFlags::DELETE_BUNDLE_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0x01, 0x02, 0x03],
    };
    bundle.blocks.push(unsupported_block);

    let result = process_on_reception(&mut bundle).unwrap();

    assert_eq!(
        result,
        ReceptionResult::DeleteBundle(DeletionReason::BlockUnsupported),
        "Bundle with critical unsupported block must be deleted"
    );
}

/// Test RFC 9171 §5.6: Report if block can't be processed (bit 1)
#[test]
fn test_rfc9171_5_6_report_on_unsupported_block() {
    // RFC 9171 §5.6: "If the 'Report if block can't be processed' flag (bit 1)
    // is 1 in the block's block processing control flags, then a bundle status
    // report with reason code 'Block unsupported' SHOULD be generated"

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    // Add unsupported block with REPORT_ON_FAILURE flag (bit 1 = 0x02)
    let unsupported_block = CanonicalBlock {
        block_type: BlockType::Unknown(888),
        block_number: 11,
        block_flags: BlockFlags::REPORT_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0xAA, 0xBB],
    };
    bundle.blocks.push(unsupported_block);

    let result = process_on_reception(&mut bundle).unwrap();

    assert_eq!(
        result,
        ReceptionResult::ReportFailure(DeletionReason::BlockUnsupported),
        "Should request status report for unsupported reportable block"
    );
}

/// Test RFC 9171 §5.6: Discard block if it can't be processed (bit 4)
#[test]
fn test_rfc9171_5_6_discard_unsupported_block() {
    // RFC 9171 §5.6: "If the 'Discard block if it can't be processed' flag (bit 4)
    // is 1 in the block's block processing control flags, then the BPA MUST remove
    // this block from the bundle"

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let initial_block_count = bundle.blocks.len();

    // Add unsupported block with DISCARD_BLOCK_ON_FAILURE flag (bit 4 = 0x10)
    let unsupported_block = CanonicalBlock {
        block_type: BlockType::Unknown(777),
        block_number: 12,
        block_flags: BlockFlags::DISCARD_BLOCK_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0xFF],
    };
    bundle.blocks.push(unsupported_block);

    let result = process_on_reception(&mut bundle).unwrap();

    assert_eq!(
        result,
        ReceptionResult::Accepted,
        "Bundle should be accepted after discarding block"
    );

    assert_eq!(
        bundle.blocks.len(),
        initial_block_count,
        "Unsupported block with discard flag should be removed"
    );

    assert!(
        !bundle
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Unknown(777))),
        "Block 777 should have been discarded"
    );
}

/// Test RFC 9171 §5.6: Reception status report requested (bit 14)
#[test]
fn test_rfc9171_5_6_reception_status_report_requested() {
    // RFC 9171 §4.2.3 Table 2: "Bit 14 (0x004000): Request reporting of bundle reception"
    // RFC 9171 §5.6 Step 2: "If the 'request reporting of bundle reception' flag is set
    // in the bundle's bundle processing control flags, then a bundle reception status
    // report SHOULD be generated"

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .bundle_flags(bundle_flags::REQUEST_REPORT_RECEPTION)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    assert!(
        requests_reception_report(&bundle),
        "Bundle should request reception report (bit 14)"
    );

    assert!(
        !is_admin_record(&bundle),
        "Payload bundle should not be an admin record"
    );
}

/// Test RFC 9171 §5.6: No status reports for administrative records
#[test]
fn test_rfc9171_5_6_no_reports_for_admin_records() {
    // RFC 9171 §6.1: "A bundle node MUST NOT generate a status report in response
    // to the receipt, forwarding, delivery, or deletion of an administrative record."
    // Administrative records have bit 1 (IS_ADMIN_RECORD = 0x000002) set.
    //
    // Also, per RFC 9171 §4.2.3: "If the bundle processing control flags indicate
    // that the bundle's ADU is an administrative record, then all status report
    // request flag values MUST be zero."

    let admin_bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .bundle_flags(bundle_flags::IS_ADMIN_RECORD) // Admin records MUST have zero status report flags
        .payload(b"status report data".to_vec())
        .build()
        .unwrap();

    assert!(
        is_admin_record(&admin_bundle),
        "Bundle should be marked as admin record (bit 1)"
    );

    assert!(
        !requests_reception_report(&admin_bundle),
        "Admin record must NOT have reception report flag set (RFC 9171 §4.2.3)"
    );

    // The BPA must NOT generate status reports for admin records
    // This check is enforced by is_admin_record() before calling the status report generator
}

/// Test RFC 9171 §5.6: Multiple unsupported blocks with mixed flags
#[test]
fn test_rfc9171_5_6_multiple_unsupported_blocks() {
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let initial_block_count = bundle.blocks.len();

    // Add first unsupported block with discard flag
    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::Unknown(100),
        block_number: 10,
        block_flags: BlockFlags::DISCARD_BLOCK_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0x01],
    });

    // Add second unsupported block with discard flag
    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::Unknown(200),
        block_number: 11,
        block_flags: BlockFlags::DISCARD_BLOCK_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0x02],
    });

    let result = process_on_reception(&mut bundle).unwrap();

    assert_eq!(result, ReceptionResult::Accepted);

    // Both unsupported blocks should be discarded
    assert_eq!(bundle.blocks.len(), initial_block_count);
    assert!(
        !bundle
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Unknown(100)))
    );
    assert!(
        !bundle
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Unknown(200)))
    );
}

/// Test RFC 9171 §5.6: Flag priority (delete takes precedence over report)
#[test]
fn test_rfc9171_5_6_flag_priority() {
    // When multiple flags are set, deletion should take priority
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    // Add unsupported block with BOTH delete and report flags
    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::Unknown(555),
        block_number: 10,
        block_flags: BlockFlags::DELETE_BUNDLE_ON_FAILURE | BlockFlags::REPORT_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0xDE, 0xAD],
    });

    let result = process_on_reception(&mut bundle).unwrap();

    // Delete should take precedence
    assert_eq!(
        result,
        ReceptionResult::DeleteBundle(DeletionReason::BlockUnsupported)
    );
}
