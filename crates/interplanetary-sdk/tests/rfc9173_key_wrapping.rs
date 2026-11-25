//! RFC 9173 §4.3.3: AES Key Wrap for BCB
//!
//! Tests key wrapping and unwrapping per RFC 3394 and RFC 9173 Appendix A.2.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::bpa::security_processing::{
    SecurityContext, SecurityFailurePolicy, SecurityProcessingResult,
};
use interplanetary_sdk::security::{AesGcmVariant, bcb, keywrap};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

#[test]
fn test_rfc9173_4_3_3_wrapped_key_in_bcb_generation() {
    // RFC 9173 §4.3.3: "This optional parameter contains the output of the AES key wrap
    // function as defined in [RFC3394]."
    //
    // Verify that when a KEK is provided during BCB generation, the CEK is wrapped
    // and included in the security parameters.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Test payload for key wrapping".to_vec())
        .build()
        .unwrap();

    // RFC 9173 Appendix A.2 test vector values
    let cek = hex::decode("71776572747975696f70617364666768").unwrap(); // 16 bytes
    let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap(); // 16 bytes
    let iv = hex::decode("5477656c7665313231323132").unwrap(); // 12 bytes

    // Wrap the CEK with the KEK
    let wrapped_key = keywrap::wrap_key(&kek, &cek).unwrap();

    // Expected wrapped key from RFC 9173 Appendix A.2
    let expected_wrapped = hex::decode("69c411276fecddc4780df42c8a2af89296fabf34d7fae700").unwrap();
    assert_eq!(
        wrapped_key, expected_wrapped,
        "Wrapped key should match RFC 9173 Appendix A.2 exactly"
    );

    // Generate BCB with wrapped key
    let config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1], // Target payload
        },
        aes_variant: AesGcmVariant::Aes128,
        key: cek.clone(),
        iv: iv.clone(),
        wrapped_key: Some(wrapped_key.clone()),
        scope_flags: 0x00,
        key_id: Some(b"test-key-id".to_vec()),
        skip_source_validation: true,
    };

    let mut nonce_registry = interplanetary_sdk::security::NonceRegistry::new();
    let (bcb_block, _replacements) = bcb::generate_bcb(&bundle, &config, Some(&mut nonce_registry))
        .expect("BCB generation should succeed");

    // Verify the BCB includes the wrapped key in parameters
    // Parse the block data to check for wrapped key parameter (ID 3)
    let block_data = &bcb_block.data;
    let mut cursor = std::io::Cursor::new(block_data);

    // Skip targets
    let _: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
    // Skip context ID
    let _: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
    // Skip flags
    let _: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
    // Skip security source
    let _: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();

    // Parse parameters
    let params_val: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
    let params_arr = match params_val {
        ciborium::Value::Array(a) => a,
        _ => panic!("Parameters should be array"),
    };

    // Find wrapped key parameter (ID 3)
    let mut found_wrapped_key = false;
    for param in params_arr {
        if let ciborium::Value::Array(pair) = param
            && pair.len() == 2
            && let ciborium::Value::Integer(id) = &pair[0]
            && TryInto::<u64>::try_into(*id).unwrap() == 3
            && let ciborium::Value::Bytes(key_bytes) = &pair[1]
        {
            assert_eq!(
                key_bytes, &wrapped_key,
                "Wrapped key in BCB should match generated wrapped key"
            );
            found_wrapped_key = true;
        }
    }

    assert!(
        found_wrapped_key,
        "BCB parameters should include wrapped key (parameter ID 3)"
    );
}

#[test]
fn test_rfc9173_5_3_bcb_decrypt_with_wrapped_key() {
    // RFC 9173 §5.3: "The decryption key MUST be derived using the wrapped key security
    // context parameter if such a parameter is included in the security context parameters
    // of the BCB."
    //
    // Create a bundle with BCB that has a wrapped key, then decrypt it at a node with the KEK.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let plaintext_payload = b"Secret payload with key wrapping";

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(plaintext_payload.to_vec())
        .build()
        .unwrap();

    // Use RFC 9173 test vector values
    let cek = hex::decode("71776572747975696f70617364666768").unwrap();
    let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
    let iv = hex::decode("5477656c7665313231323132").unwrap();

    let wrapped_key = keywrap::wrap_key(&kek, &cek).unwrap();

    // Generate BCB with wrapped key
    let config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: cek.clone(),
        iv: iv.clone(),
        wrapped_key: Some(wrapped_key),
        scope_flags: 0x00,
        key_id: Some(b"test-key-id".to_vec()),
        skip_source_validation: true,
    };

    let mut nonce_registry = interplanetary_sdk::security::NonceRegistry::new();
    let (bcb_block, mut replacements) =
        bcb::generate_bcb(&bundle, &config, Some(&mut nonce_registry)).unwrap();

    // Build secured bundle
    let mut secured_bundle = bundle.clone();

    // Replace payload with ciphertext
    let payload_replacement = replacements.remove(0);
    secured_bundle.blocks[0].data = payload_replacement;

    // Add BCB block
    let mut bcb_with_number = bcb_block;
    bcb_with_number.block_number = 2; // Assign block number
    secured_bundle.blocks.push(bcb_with_number);

    // Now decrypt at destination using KEK (not CEK directly)
    let mut ctx = SecurityContext::new();
    ctx.add_kek(source.clone(), kek); // Provide KEK, not CEK
    ctx.bcb_failure_policy = SecurityFailurePolicy::DeleteBundle;

    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut secured_bundle, &mut ctx)
            .unwrap();

    match result {
        SecurityProcessingResult::Success => {
            // Verify payload was decrypted correctly
            assert_eq!(
                secured_bundle.blocks[0].data, plaintext_payload,
                "Payload should be decrypted correctly using unwrapped key"
            );
        }
        _ => panic!(
            "BCB decryption should succeed with correct KEK: {:?}",
            result
        ),
    }
}

#[test]
fn test_rfc9172_bcb_decryption_failure_with_wrong_kek() {
    // RFC 9172 §4.4.1: "If the BCB cannot be decrypted, the security policy
    // at the security acceptor determines the processing of the bundle."
    //
    // Verify that providing the wrong KEK causes decryption to fail.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Secret payload".to_vec())
        .build()
        .unwrap();

    let cek = hex::decode("71776572747975696f70617364666768").unwrap();
    let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
    let iv = hex::decode("5477656c7665313231323132").unwrap();

    let wrapped_key = keywrap::wrap_key(&kek, &cek).unwrap();

    // Generate BCB
    let config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: cek,
        iv,
        wrapped_key: Some(wrapped_key),
        scope_flags: 0x00,
        key_id: Some(b"test-key-id".to_vec()),
        skip_source_validation: true,
    };

    let mut nonce_registry = interplanetary_sdk::security::NonceRegistry::new();
    let (bcb_block, mut replacements) =
        bcb::generate_bcb(&bundle, &config, Some(&mut nonce_registry)).unwrap();

    // Build secured bundle
    let mut secured_bundle = bundle.clone();
    secured_bundle.blocks[0].data = replacements.remove(0);

    let mut bcb_with_number = bcb_block;
    bcb_with_number.block_number = 2;
    secured_bundle.blocks.push(bcb_with_number);

    // Try to decrypt with WRONG KEK
    let wrong_kek = hex::decode("ffffffffffffffffffffffffffffffff").unwrap();

    let mut ctx = SecurityContext::new();
    ctx.add_kek(source.clone(), wrong_kek);
    ctx.bcb_failure_policy = SecurityFailurePolicy::DeleteBundle;

    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut secured_bundle, &mut ctx)
            .unwrap();

    match result {
        SecurityProcessingResult::BcbDecryptionFailed { .. } => {
            // Expected: decryption should fail with wrong KEK
        }
        SecurityProcessingResult::Success => {
            panic!("BCB decryption should FAIL with wrong KEK per RFC 9172 §4.4.1");
        }
        _ => panic!("Unexpected result: {:?}", result),
    }
}

#[test]
fn test_rfc9173_5_3_bcb_decrypt_without_wrapped_key() {
    // RFC 9173 §5.3: "Otherwise, this key MUST be derived in accordance with local
    // security policy at the decrypting node or in accordance with established key
    // agreement."
    //
    // Verify that when no wrapped key is present, the node uses the direct key from policy.

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let plaintext_payload = b"Payload without key wrapping";

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(plaintext_payload.to_vec())
        .build()
        .unwrap();

    let cek = hex::decode("71776572747975696f70617364666768").unwrap();
    let iv = hex::decode("5477656c7665313231323132").unwrap();

    // Generate BCB WITHOUT wrapped key
    let config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: cek.clone(),
        iv,
        wrapped_key: None, // No wrapped key
        scope_flags: 0x00,
        key_id: Some(b"test-key-id".to_vec()),
        skip_source_validation: true,
    };

    let mut nonce_registry = interplanetary_sdk::security::NonceRegistry::new();
    let (bcb_block, mut replacements) =
        bcb::generate_bcb(&bundle, &config, Some(&mut nonce_registry)).unwrap();

    // Build secured bundle
    let mut secured_bundle = bundle.clone();
    secured_bundle.blocks[0].data = replacements.remove(0);

    let mut bcb_with_number = bcb_block;
    bcb_with_number.block_number = 2;
    secured_bundle.blocks.push(bcb_with_number);

    // Decrypt using direct AES key (no KEK needed)
    let mut ctx = SecurityContext::new();
    ctx.add_aes_key(source.clone(), cek);
    ctx.bcb_failure_policy = SecurityFailurePolicy::DeleteBundle;

    let result =
        interplanetary_sdk::bpa::security_processing::process_bcbs(&mut secured_bundle, &mut ctx)
            .unwrap();

    match result {
        SecurityProcessingResult::Success => {
            assert_eq!(
                secured_bundle.blocks[0].data, plaintext_payload,
                "Payload should be decrypted using direct key from policy"
            );
        }
        _ => panic!(
            "BCB decryption should succeed with direct AES key: {:?}",
            result
        ),
    }
}
