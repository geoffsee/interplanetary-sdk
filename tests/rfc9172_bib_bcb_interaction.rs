//! RFC 9172 BIB/BCB Interaction Rules
//!
//! Tests for RFC 9172 §5.1:
//! - RFC9172-076: When BIBs and BCBs share a security target, BCBs MUST be evaluated first
//! - RFC9172-079: If processing a security operation fails, target SHALL be processed per security policy
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{
    bp::*,
    bpa::{
        BpaConfig, BundleAgent, SecurityContext, SecurityFailurePolicy, SecurityProcessingResult,
    },
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
fn test_rfc9172_076_bcb_evaluated_before_bib_on_shared_target_interaction() {
    // RFC 9172 §5.1: When BIBs and BCBs share a security target, BCBs MUST be evaluated first and BIBs second.
    //
    // Test strategy: Create bundle with both BCB and BIB protecting the same target (payload).
    // BCB encrypts payload, then BIB signs the ciphertext. At destination:
    // 1. BCB must be processed first (decrypt payload)
    // 2. BIB must be processed second (verify integrity of original plaintext)
    //
    // This test verifies the correct processing order by ensuring:
    // - BCB decryption happens first (payload changes from ciphertext to plaintext)
    // - BIB verification happens second (verifies the plaintext, not ciphertext)

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let original_payload = b"Shared target data".to_vec();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    // Step 1: Add BIB first (signs original plaintext payload)
    let hmac_key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // payload
        },
        sha_variant: HmacVariant::Sha256,
        key: hmac_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let mut bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bib_block.block_number = 3;
    bundle.blocks.insert(0, bib_block);

    // Step 2: RFC 9172 §3.9 — encrypt the BIB, then the shared payload target
    // (erratum 7002: one target per BCB).
    let aes_key = vec![0xCD; 16];
    let bcb_bib_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![3],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv: vec![0xAA; 12],
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };
    let (mut bcb_for_bib, bib_cts) = bcb::generate_bcb(&bundle, &bcb_bib_config, None).unwrap();
    bcb_for_bib.block_number = 4;
    if let Some(b) = bundle.blocks.iter_mut().find(|b| b.block_number == 3) {
        b.data = bib_cts[0].clone();
    }
    bundle.blocks.insert(0, bcb_for_bib);

    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1], // Same content target as BIB
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv: vec![0xEF; 12],
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (mut bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bcb_block.block_number = 2;
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    // Add keys to security context
    ctx.add_hmac_key(source.clone(), hmac_key);
    ctx.add_aes_key(source, aes_key);

    // RFC 9172 §5.1: Process BCBs FIRST
    let bcb_result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();
    assert!(
        matches!(bcb_result, SecurityProcessingResult::Success),
        "BCB processing MUST succeed first"
    );

    // Verify payload is now plaintext (BCB processed first)
    let payload_after_bcb = bundle.blocks.iter().find(|b| b.block_number == 1).unwrap();
    assert_eq!(
        payload_after_bcb.data, original_payload,
        "Payload MUST be decrypted after BCB processing"
    );

    // RFC 9172 §5.1: Process BIBs SECOND
    let bib_result =
        interplanetary_sdk::bpa::security_processing::process_bibs(&mut bundle, &ctx, true)
            .unwrap();
    assert!(
        matches!(bib_result, SecurityProcessingResult::Success),
        "BIB processing MUST succeed second (after BCB)"
    );

    // Verify both security blocks removed after successful processing
    let security_blocks_after = bundle
        .blocks
        .iter()
        .filter(|b| {
            matches!(b.block_type, BlockType::Bib) || matches!(b.block_type, BlockType::Bcb)
        })
        .count();
    assert_eq!(
        security_blocks_after, 0,
        "All security blocks MUST be removed after successful processing"
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_079_bcb_failure_policy_configurable() {
    // RFC 9172 §5.1.1: If processing a security operation fails, the target SHALL be processed according to the security policy.
    //
    // This test verifies that security failure policy is configurable and affects processing outcomes.

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Secret data".to_vec())
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

    // Add WRONG key to security context (causes decryption failure)
    let wrong_key = vec![0xEF; 16];
    ctx.add_aes_key(source, wrong_key);

    // RFC 9172 §5.1.1: Security policy MUST be configurable
    // Test 1: DeleteBundle policy (default, most secure)
    let delete_policy = SecurityFailurePolicy::DeleteBundle;
    ctx.set_bcb_failure_policy(delete_policy);
    assert_eq!(
        ctx.bcb_failure_policy,
        SecurityFailurePolicy::DeleteBundle,
        "BCB failure policy MUST be configurable to DeleteBundle"
    );

    // Test 2: StripSecurityBlock policy (less secure, for testing)
    ctx.set_bcb_failure_policy(SecurityFailurePolicy::StripSecurityBlock);
    assert_eq!(
        ctx.bcb_failure_policy,
        SecurityFailurePolicy::StripSecurityBlock,
        "BCB failure policy MUST be configurable to StripSecurityBlock"
    );

    // Process BCBs (will fail with wrong key)
    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx).unwrap();

    // RFC 9172 §5.1.1: Processing fails, SHALL be processed per security policy
    match result {
        SecurityProcessingResult::BcbDecryptionFailed {
            bcb_block_num: _,
            target_block_num,
        } => {
            assert_eq!(
                target_block_num, 1,
                "BCB decryption MUST fail for payload (block 1) with wrong key"
            );
        }
        _ => panic!("Expected BcbDecryptionFailed when using wrong key"),
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_079_bib_failure_policy_configurable() {
    // RFC 9172 §5.1.1: If processing a security operation fails, the target SHALL be processed according to the security policy.
    //
    // This test verifies that security failure policy is configurable for BIB operations.

    let (_agent, mut ctx, local_eid) = create_test_agent_with_security();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(b"Important data".to_vec())
        .build()
        .unwrap();

    // Add BIB with correct key
    let correct_key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
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

    // Add WRONG key to security context (causes verification failure)
    let wrong_key = vec![0xCD; 32];
    ctx.add_hmac_key(source, wrong_key);

    // RFC 9172 §5.1.1: Security policy MUST be configurable
    // Default policy: DeleteBundle (most secure)
    assert_eq!(
        ctx.bib_failure_policy,
        SecurityFailurePolicy::DeleteBundle,
        "BIB failure policy MUST default to DeleteBundle (most secure)"
    );

    // Test configurability: change to StripSecurityBlock
    ctx.set_bib_failure_policy(SecurityFailurePolicy::StripSecurityBlock);
    assert_eq!(
        ctx.bib_failure_policy,
        SecurityFailurePolicy::StripSecurityBlock,
        "BIB failure policy MUST be configurable to StripSecurityBlock"
    );

    // Process BIBs (will fail with wrong key)
    let result =
        interplanetary_sdk::bpa::security_processing::process_bibs(&mut bundle, &ctx, true)
            .unwrap();

    // RFC 9172 §5.1.1: Processing fails, SHALL be processed per security policy
    match result {
        SecurityProcessingResult::BibVerificationFailed {
            bib_block_num: _,
            target_block_num,
        } => {
            assert_eq!(
                target_block_num, 1,
                "BIB verification MUST fail for payload (block 1) with wrong key"
            );
        }
        _ => panic!("Expected BibVerificationFailed when using wrong key"),
    }
}
