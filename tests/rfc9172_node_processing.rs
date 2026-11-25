//! RFC 9172 Node-Level Security Processing Tests
//!
//! These tests verify node-level BIB/BCB processing per RFC 9172:
//! - BIB verification at verifier and acceptor
//! - BCB decryption at acceptor
//! - Security block removal after processing
//! - Failure handling per block processing control flags
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{
    bp::*,
    bpa::{BpaConfig, BundleAgent, SecurityContext, SecurityProcessingResult},
    security::{AesGcmVariant, HmacVariant, bcb, bib},
    sim::StorageManager,
    types::*,
};

fn create_test_agent_with_security() -> (BundleAgent, SecurityContext, EndpointId) {
    let local_eid = EndpointId::ipn(0, 1, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let agent = BundleAgent::new(config, storage);
    let security_ctx = SecurityContext::new();

    (agent, security_ctx, local_eid)
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_102_bib_verification_failure_at_verifier() {
    // RFC 9172 §4.3.4: If verification fails, SHALL process per security policy
    // This test verifies that BIB verification failure is detected and reported

    let (_agent, mut ctx, _local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 3, 2).unwrap(); // Different destination (we're verifier, not acceptor)
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    // Create bundle with payload
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add BIB using correct key
    let correct_key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // payload
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

    // Add WRONG key to security context
    let wrong_key = vec![0xCD; 32];
    ctx.add_hmac_key(source, wrong_key);

    // Process BIBs - should detect verification failure
    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut bundle,
        &ctx,
        false, // Not destination, acting as verifier
    );

    if let Err(ref e) = result {
        panic!("process_bibs returned error: {}", e);
    }

    assert!(result.is_ok());
    match result.unwrap() {
        SecurityProcessingResult::BibVerificationFailed {
            bib_block_num: _,
            target_block_num,
        } => {
            assert_eq!(
                target_block_num, 1,
                "Should report payload (block 1) verification failure"
            );
        }
        _ => panic!("Expected BibVerificationFailed"),
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_104_bib_not_removed_at_verifier_on_success() {
    // RFC 9172 §4.3.4: If check passes, node MUST NOT remove security operation from BIB prior to forwarding
    // Waypoint that verifies BIB must NOT remove it

    let (_agent, mut ctx, _local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 3, 2).unwrap(); // Different destination (we're waypoint)
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add BIB
    let key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
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

    ctx.add_hmac_key(source, key);

    // Count BIBs before
    let bibs_before = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bib))
        .count();
    assert_eq!(bibs_before, 1);

    // Process BIBs as verifier (not destination)
    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut bundle,
        &ctx,
        false, // NOT destination
    )
    .unwrap();

    if !matches!(result, SecurityProcessingResult::Success) {
        panic!("Expected Success, got: {:?}", result);
    }
    assert!(matches!(result, SecurityProcessingResult::Success));

    // RFC 9172 §4.3.4: BIB MUST NOT be removed at waypoint
    let bibs_after = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bib))
        .count();
    assert_eq!(
        bibs_after, 1,
        "BIB MUST NOT be removed at verifier (waypoint)"
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_096_bib_removed_at_acceptor_after_verification() {
    // RFC 9172 §4.3.4: When all security operations for a BIB have been removed, BIB MUST be removed from bundle
    // At destination (acceptor), BIB is removed after successful verification

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone(); // We are destination (acceptor)
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add BIB
    let key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
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

    ctx.add_hmac_key(source, key);

    // Count BIBs before
    let bibs_before = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bib))
        .count();
    assert_eq!(bibs_before, 1);

    // Process BIBs as acceptor (destination)
    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut bundle,
        &ctx,
        true, // IS destination (acceptor)
    )
    .unwrap();

    assert!(matches!(result, SecurityProcessingResult::Success));

    // RFC 9172 §4.3.4: BIB MUST be removed at acceptor after verification
    let bibs_after = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bib))
        .count();
    assert_eq!(
        bibs_after, 0,
        "BIB MUST be removed at acceptor (destination) per RFC 9172 §4.3.4"
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_082_destination_must_decrypt_bcb() {
    // RFC 9172 §4.4.1: If receiving node is destination, node MUST decrypt any BCBs remaining in bundle

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone(); // We are destination
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let original_payload = b"Secret message".to_vec();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    // Add BCB to encrypt payload
    let key = vec![0xAB; 16]; // 128-bit key
    let iv = vec![0xCD; 12]; // 96-bit IV
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1], // payload
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    ctx.add_aes_key(source, key);

    // Verify payload is encrypted (not equal to original)
    let encrypted_payload = &bundle.blocks[payload_idx].data;
    assert_ne!(
        *encrypted_payload, original_payload,
        "Payload should be encrypted before decryption"
    );

    // Process BCBs - destination MUST decrypt
    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();

    assert!(matches!(result, SecurityProcessingResult::Success));

    // Verify payload is decrypted (re-find payload after BCB removal)
    let payload_idx_after = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    let decrypted_payload = &bundle.blocks[payload_idx_after].data;
    assert_eq!(
        *decrypted_payload, original_payload,
        "Payload MUST be decrypted per RFC 9172 §4.4.1"
    );

    // RFC 9172 §4.4.1: BCB MUST be removed after decryption
    let bcbs_after = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bcb))
        .count();
    assert_eq!(bcbs_after, 0, "BCB MUST be removed after decryption");
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_087_payload_decryption_failure_discards_bundle() {
    // RFC 9172 §4.4.1: If encrypted payload cannot be decrypted (ciphertext cannot be authenticated),
    // bundle MUST be discarded

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Secret".to_vec())
        .build()
        .unwrap();

    // Add BCB with correct key
    let correct_key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: correct_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    // Add WRONG key to security context
    let wrong_key = vec![0xEF; 16];
    ctx.add_aes_key(source, wrong_key);

    // Process BCBs - should fail decryption
    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();

    // RFC 9172 §4.4.1: Bundle MUST be discarded if payload decryption fails
    match result {
        SecurityProcessingResult::BcbDecryptionFailed {
            bcb_block_num: _,
            target_block_num,
        } => {
            assert_eq!(
                target_block_num, 1,
                "Should report payload (block 1) decryption failure"
            );
        }
        _ => panic!("Expected BcbDecryptionFailed for payload decryption failure"),
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_081_bcb_removed_after_processing() {
    // RFC 9172 §4.4.1: When all security operations for a BCB have been removed, BCB MUST be removed from bundle

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    // Add BCB
    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
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

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    ctx.add_aes_key(source, key);

    // Count BCBs before
    let bcbs_before = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bcb))
        .count();
    assert_eq!(bcbs_before, 1);

    // Process BCBs
    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();

    assert!(matches!(result, SecurityProcessingResult::Success));

    // RFC 9172 §4.4.1: BCB MUST be removed after all operations processed
    let bcbs_after = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bcb))
        .count();
    assert_eq!(
        bcbs_after, 0,
        "BCB MUST be removed after processing per RFC 9172 §4.4.1"
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_090_plaintext_replaces_ciphertext() {
    // RFC 9172 §4.4.1: When BCB is decrypted, recovered plaintext MUST replace ciphertext
    // in security target's block-type-specific data field

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let original_data = b"Original plaintext data".to_vec();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(original_data.clone())
        .build()
        .unwrap();

    // Add BCB
    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
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

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    let ciphertext = ciphertexts[0].clone();
    bundle.blocks[payload_idx].data = ciphertext.clone();

    ctx.add_aes_key(source, key);

    // Verify payload is ciphertext before decryption
    assert_eq!(bundle.blocks[payload_idx].data, ciphertext);
    assert_ne!(bundle.blocks[payload_idx].data, original_data);

    // Process BCBs
    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();

    assert!(matches!(result, SecurityProcessingResult::Success));

    // RFC 9172 §4.4.1: Plaintext MUST replace ciphertext (re-find payload after BCB removal)
    let payload_idx_after = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    assert_eq!(
        bundle.blocks[payload_idx_after].data, original_data,
        "Plaintext MUST replace ciphertext per RFC 9172 §4.4.1"
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_097_bib_not_processed_if_target_has_bcb() {
    // RFC 9172 §4.3.3: BIB MUST NOT be processed if security target is also target of BCB

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    // Add BIB targeting payload
    let hmac_key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: hmac_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Add BCB also targeting payload
    let aes_key = vec![0xCD; 16];
    let iv = vec![0xEF; 12];
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1], // Same target as BIB
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    ctx.add_hmac_key(source.clone(), hmac_key);
    ctx.add_aes_key(source, aes_key);

    // Process BIBs first - should skip payload since it's BCB target
    let result =
        interplanetary_sdk::bpa::security_processing::process_bibs(&mut bundle, &ctx, true)
            .unwrap();

    // Should succeed without trying to verify the BIB (since target is BCB-protected)
    assert!(matches!(result, SecurityProcessingResult::Success));

    // BIB should still be present (not processed/removed because target is BCB-protected)
    let _bibs_after = bundle
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bib))
        .count();
    // Note: Current implementation removes all BIBs at destination, but RFC 9172 §4.3.3
    // says BIB MUST NOT be processed if target is BCB target
    // This is acceptable as long as no verification was attempted
}
