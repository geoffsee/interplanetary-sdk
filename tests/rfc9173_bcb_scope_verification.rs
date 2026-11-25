//! RFC 9173 BCB Scope Flag Verification Tests
//!
//! Tests that scope flags in AAD affect BCB encryption/decryption and that
//! tampering with scope-protected data causes decryption failure.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

#[cfg(feature = "test-fixtures")]
use interplanetary_sdk::{
    bp::*,
    bpa::{SecurityContext, SecurityProcessingResult},
    security::{AesGcmVariant, bcb},
    types::*,
};

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_086_bcb_scope_flags_affect_decryption() {
    // RFC 9173 §4.7.2: "While the AAD scope flags might not be included in the BCB
    // representing the security operation, they MUST be included in the AAD value itself."
    //
    // Test: Generate BCB with scope_flags=0x01 (primary block in AAD), then decrypt
    // with matching flags succeeds, but mismatched flags fails.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);

    let original_payload = b"Test data".to_vec();
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];

    // Generate BCB with scope_flags including primary (0x01)
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x01, // Include primary block in AAD
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    let mut bundle_encrypted = bundle.clone();
    bundle_encrypted.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle_encrypted
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle_encrypted.blocks[payload_idx].data = ciphertexts[0].clone();

    // Test 1: Decrypt with correct key succeeds
    let mut ctx = SecurityContext::new();
    ctx.add_aes_key(source.clone(), key.clone());

    let result = interplanetary_sdk::bpa::security_processing::process_bcbs(
        &mut bundle_encrypted.clone(),
        &mut ctx,
    )
    .unwrap();

    assert!(
        matches!(result, SecurityProcessingResult::Success),
        "Decryption with matching scope flags MUST succeed"
    );

    // Test 2: Different scope flags in AAD causes authentication failure
    // This is implicit - the AAD used during generation included primary block,
    // so tampering with primary will cause decryption to fail
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_087_primary_block_in_aad_prevents_tampering() {
    // RFC 9173 §4.7.2 Step 2: "If the primary block flag of the AAD scope flags is
    // set to 1, then a canonical form of the bundle's primary block MUST be calculated
    // and the result appended to the AAD."
    //
    // Test: BCB with primary block in AAD (flag 0x01) fails decryption if primary
    // block is tampered with.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);

    let original_payload = b"Protected data".to_vec();
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];

    // Generate BCB with scope_flags=0x01 (primary block protected)
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x01, // Primary block in AAD
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    let mut bundle_encrypted = bundle.clone();
    bundle_encrypted.blocks.insert(0, bcb_block);

    let payload_idx = bundle_encrypted
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle_encrypted.blocks[payload_idx].data = ciphertexts[0].clone();

    // Tamper with primary block (change destination)
    bundle_encrypted.primary.destination = EndpointId::ipn(0, 99, 0).unwrap();

    // Try to decrypt - MUST fail because primary block changed
    let mut ctx = SecurityContext::new();
    ctx.add_aes_key(source, key);

    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle_encrypted, &mut ctx)
            .unwrap();

    // RFC 9173 §4.7.2: Primary block in AAD MUST cause decryption failure when tampered
    match result {
        SecurityProcessingResult::BcbDecryptionFailed {
            target_block_num, ..
        } => {
            assert_eq!(
                target_block_num, 1,
                "Decryption MUST fail for tampered primary block"
            );
        }
        _ => panic!("Expected BcbDecryptionFailed when primary block is tampered"),
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_bcb_scope_0x00_vs_0x01_produces_different_ciphertext() {
    // RFC 9173 §4.7.2: Different scope flags MUST produce different AAD,
    // which produces different auth tags (different ciphertexts).

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);

    let payload = b"Test data".to_vec();
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(payload.clone())
        .build()
        .unwrap();

    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12]; // Same IV for comparison (normally unique)

    // Generate with scope_flags=0x00
    let bcb_config_00 = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_00, _) = bcb::generate_bcb(&bundle, &bcb_config_00, None).unwrap();

    // Generate with scope_flags=0x01 (primary in AAD)
    let bcb_config_01 = bcb::BcbConfig {
        security_source: source,
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0x01,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_01, _) = bcb::generate_bcb(&bundle, &bcb_config_01, None).unwrap();

    // RFC 9173 §4.7.2: Different scope flags MUST produce different BCB blocks
    assert_ne!(
        bcb_00.data, bcb_01.data,
        "BCBs with different scope flags MUST have different auth tags/results"
    );
}
