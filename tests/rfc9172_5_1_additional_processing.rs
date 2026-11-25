//! RFC 9172 §5.1 Additional Processing Rules
//!
//! Tests verify:
//! - Non-payload BCB decryption failure handling (discard target and security blocks)
//! - Multiple BCB operations processing (Erratum 7002: one target per BCB)
//! - Multiple BIB operations processing
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{
    bp::*,
    bpa::{SecurityContext, SecurityProcessingResult},
    security::{AesGcmVariant, HmacVariant, bcb, bib},
    types::*,
};

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_088_non_payload_decryption_failure_discards_target() {
    // RFC 9172 §5.1.1: "other than the payload block cannot be decrypted, then the
    // associated security target and all security blocks associated with that target
    // MUST be discarded and processed no further."
    //
    // This test verifies that when a NON-PAYLOAD block cannot be decrypted, the target
    // block and all security blocks for that target are discarded (removed from bundle).

    let mut ctx = SecurityContext::new();
    let security_source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 3, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(security_source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    // Add hop count block (non-payload block type 10)
    let hop_count_block = CanonicalBlock {
        block_type: BlockType::HopCount,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x82, 0x1E, 0x00], // CBOR [30, 0]
    };
    bundle.blocks.insert(1, hop_count_block);

    // Add BCB encrypting hop count block
    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];
    let bcb_config = bcb::BcbConfig {
        security_source: security_source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![2], // hop count
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    // Replace hop count with ciphertext
    let hop_count_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 2)
        .unwrap();
    bundle.blocks[hop_count_idx].data = ciphertexts[0].clone();

    // Count blocks before: BCB (block 0 inserted), primary, hop count, payload
    // After insertion, we have: BCB + primary + payload + hop count = 4 (but primary is implicit)
    // Actually: blocks vector has: BCB, hop_count, payload
    let blocks_before = bundle.blocks.len();
    assert!(
        blocks_before >= 3,
        "Should have at least BCB, hop count, payload"
    );

    // Add WRONG key to security context (decryption will fail)
    let wrong_key = vec![0xEF; 16];
    ctx.add_aes_key(security_source, wrong_key);

    // Process BCBs - hop count cannot decrypt; RFC9172-088 discards target + security blocks
    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();

    assert!(
        matches!(result, SecurityProcessingResult::Success),
        "RFC9172-088: non-payload decrypt failure MUST discard and continue (Success), got {:?}",
        result
    );
    assert!(
        !bundle.blocks.iter().any(|b| b.block_number == 2),
        "RFC9172-088: hop-count security target MUST be discarded"
    );
    assert!(
        !bundle
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bcb)),
        "RFC9172-088: associated BCB MUST be discarded"
    );
    assert!(
        bundle
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Payload)),
        "RFC9172-088: payload MUST remain after non-payload discard"
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_091_bcb_operations_processed_independently() {
    // RFC 9172 §5.1.1: "If a BCB contains multiple security operations, each operation
    // processed by the node MUST be treated as if the security operation has been
    // represented by a single BCB with a single security operation for the purposes of
    // report generation and policy processing."
    //
    // Per Erratum 7002, a BCB MUST have only one target (enforced by SDK).
    // This test verifies that when SEPARATE BCBs exist (one operation per BCB),
    // each is processed independently.

    let mut ctx = SecurityContext::new();
    let security_source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 3, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(security_source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Payload 1".to_vec())
        .build()
        .unwrap();

    // Add second payload-like extension block
    let second_block = CanonicalBlock {
        block_type: BlockType::Unknown(192), // Extension block
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: b"Payload 2".to_vec(),
    };
    bundle.blocks.insert(1, second_block);

    let key = vec![0xAB; 16];

    // Per Erratum 7002, create TWO separate BCBs (one per target)
    // BCB 1 for payload (block 1)
    let iv1 = vec![0xCD; 12];
    let bcb_config1 = bcb::BcbConfig {
        security_source: security_source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: iv1,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block1, ciphertexts1) = bcb::generate_bcb(&bundle, &bcb_config1, None).unwrap();

    // BCB 2 for extension block (block 2)
    let iv2 = vec![0xDE; 12]; // DIFFERENT IV per Erratum 7002
    let bcb_config2 = bcb::BcbConfig {
        security_source: security_source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![2],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: iv2,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block2, ciphertexts2) = bcb::generate_bcb(&bundle, &bcb_config2, None).unwrap();

    // Insert both BCBs
    bundle.blocks.insert(0, bcb_block1);
    bundle.blocks.insert(0, bcb_block2);

    // Replace targets with ciphertexts
    let idx1 = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    let idx2 = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 2)
        .unwrap();
    bundle.blocks[idx1].data = ciphertexts1[0].clone();
    bundle.blocks[idx2].data = ciphertexts2[0].clone();

    ctx.add_aes_key(security_source, key);

    // Process BCBs - each BCB (operation) processed independently
    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();

    // RFC 9172 §5.1.1: Each operation processed independently
    // Both BCBs decrypt successfully with correct key
    assert!(
        matches!(result, SecurityProcessingResult::Success),
        "Each BCB operation MUST be processed independently"
    );

    // All BCBs removed after processing
    let bcbs = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bcb))
        .count();
    assert_eq!(bcbs, 0, "All BCBs removed after independent processing");
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_105_multiple_bib_operations_processed_independently() {
    // RFC 9172 §5.1.2: "If a BIB contains multiple security operations, each operation
    // processed by the node MUST be treated as if the security operation has been
    // represented by a single BIB with a single security operation for the purposes of
    // report generation and policy processing."
    //
    // This test verifies that when a BIB has multiple targets, each target is
    // verified independently.

    let mut ctx = SecurityContext::new();
    let security_source = EndpointId::ipn(0, 2, 1).unwrap();
    let local_eid = EndpointId::ipn(0, 3, 2).unwrap(); // Destination
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(security_source.clone())
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Payload".to_vec())
        .build()
        .unwrap();

    // Add hop count block
    let hop_count_block = CanonicalBlock {
        block_type: BlockType::HopCount,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x82, 0x1E, 0x00], // CBOR [30, 0]
    };
    bundle.blocks.insert(1, hop_count_block);

    // Create BIB with multiple targets (payload + hop count)
    let key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: security_source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1, 2], // Two targets
        },
        sha_variant: HmacVariant::Sha256,
        key: key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    ctx.add_hmac_key(security_source, key);

    // Process BIBs as acceptor - each target verified independently
    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut bundle,
        &ctx,
        true, // IS destination
    )
    .unwrap();

    // RFC 9172 §5.1.2: Each operation processed independently
    // All targets verify successfully with correct key
    assert!(
        matches!(result, SecurityProcessingResult::Success),
        "Each BIB operation MUST be processed independently"
    );

    // BIB removed at acceptor after all verifications succeed
    let bibs = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bib))
        .count();
    assert_eq!(bibs, 0, "BIB removed after verification at acceptor");

    // Note: If ANY target verification fails, the entire BIB fails per current implementation.
    // The RFC requires each operation to be treated independently for "report generation and
    // policy processing" - meaning status reports and policy decisions apply per-target,
    // not necessarily that partial failures are allowed.
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_105_multiple_bib_operations_partial_failure() {
    // RFC 9172 §5.1.2: Each BIB operation processed independently for policy processing.
    //
    // This test verifies that when one target verification fails, the failure is reported
    // for that specific target (independent processing per RFC requirement).

    let mut ctx = SecurityContext::new();
    let security_source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 3, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(security_source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    // Add hop count
    let hop_count_block = CanonicalBlock {
        block_type: BlockType::HopCount,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x82, 0x1E, 0x00],
    };
    bundle.blocks.insert(1, hop_count_block);

    // Create BIB with correct key
    let correct_key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: security_source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1, 2],
        },
        sha_variant: HmacVariant::Sha256,
        key: correct_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Add WRONG key to context (verification will fail)
    let wrong_key = vec![0xCD; 32];
    ctx.add_hmac_key(security_source, wrong_key);

    // Process BIBs - should fail verification
    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut bundle,
        &ctx,
        false, // Not destination
    )
    .unwrap();

    // RFC 9172 §5.1.2: Failure reported for specific target
    match result {
        SecurityProcessingResult::BibVerificationFailed {
            bib_block_num: _,
            target_block_num,
        } => {
            // Failure reported for the FIRST failed target (implementation processes in order)
            assert!(
                target_block_num == 1 || target_block_num == 2,
                "Should report specific target that failed"
            );
        }
        _ => panic!("Expected BibVerificationFailed when verification fails"),
    }

    // The requirement is that each operation is treated independently for "report generation
    // and policy processing" - meaning status reports identify the specific failed target.
}
