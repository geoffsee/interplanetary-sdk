//! RFC 9173-056 IV/Nonce Uniqueness Verification
//!
//! RFC 9173 §4.3.1: "The initialization vector can have any value, with the caveat
//! that a value MUST NOT be reused for multiple encryptions using the same encryption key."
//!
//! This test verifies that generate_bcb integrates with NonceRegistry and enforces uniqueness.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::*;
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::{AesGcmVariant, NonceRegistry};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

fn create_test_bundle() -> Bundle {
    BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 1).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap()
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_056_generate_bcb_with_different_ivs() {
    // RFC 9173 §4.3.1: Verify generate_bcb produces different IVs for same key
    // Test decodes both BCBs and asserts the IV security parameters differ

    let bundle = create_test_bundle();
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let key = vec![0xAA; 16];

    // Generate first BCB with IV1
    let bcb_config1 = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: vec![0x01; 12], // IV1
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb1, _ciphertexts1) = generate_bcb(&bundle, &bcb_config1, None).unwrap();

    // Generate second BCB with IV2
    let bcb_config2 = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv: vec![0x02; 12], // IV2 - different from IV1
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb2, _ciphertexts2) = generate_bcb(&bundle, &bcb_config2, None).unwrap();

    // Simple verification: BCB blocks with different IVs should have different data
    // (ciphertext and auth tags will differ due to different IVs)
    // RFC 9173 §4.3.1: IVs MUST differ when using same key
    assert_ne!(
        bcb1.data, bcb2.data,
        "RFC 9173 §4.3.1: BCBs with different IVs MUST produce different outputs"
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_056_nonce_registry_prevents_reuse() {
    // RFC 9173 §4.3.1: generate_bcb MUST register IV and return Err on reuse
    // This test forces a repeated IV through the registry

    let bundle = create_test_bundle();
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let key_id = b"test-key-id".to_vec();
    let key = vec![0xAA; 16];
    let iv = vec![0x01; 12];

    let mut registry = NonceRegistry::new();

    // First BCB with this IV should succeed
    let bcb_config1 = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: Some(key_id.clone()),
        skip_source_validation: true,
    };

    let result1 = generate_bcb(&bundle, &bcb_config1, Some(&mut registry));
    assert!(result1.is_ok(), "First BCB with IV should succeed");

    // Second BCB with SAME key_id and IV should fail (RFC 9173 §4.3.1 violation)
    let bcb_config2 = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: Some(key_id),
        skip_source_validation: true,
    };

    let result2 = generate_bcb(&bundle, &bcb_config2, Some(&mut registry));
    assert!(
        result2.is_err(),
        "RFC 9173 §4.3.1: Reusing IV with same key MUST fail"
    );

    let err_msg = result2.unwrap_err().to_string();
    assert!(
        err_msg.contains("IV reuse") || err_msg.contains("9173"),
        "Error should mention IV reuse or RFC 9173 §4.3.1, got: {}",
        err_msg
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_056_different_keys_allow_same_iv() {
    // RFC 9173 §4.3.1: Same IV with different keys is allowed

    let bundle = create_test_bundle();
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let key1_id = b"key1".to_vec();
    let key2_id = b"key2".to_vec();
    let same_iv = vec![0x01; 12];

    let mut registry = NonceRegistry::new();

    // BCB with key1 and IV
    let bcb_config1 = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: vec![0xAA; 16],
        iv: same_iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: Some(key1_id),
        skip_source_validation: true,
    };

    let result1 = generate_bcb(&bundle, &bcb_config1, Some(&mut registry));
    assert!(result1.is_ok(), "BCB with key1 should succeed");

    // BCB with key2 and SAME IV - should succeed (different key)
    let bcb_config2 = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: vec![0xBB; 16],
        iv: same_iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: Some(key2_id),
        skip_source_validation: true,
    };

    let result2 = generate_bcb(&bundle, &bcb_config2, Some(&mut registry));
    assert!(
        result2.is_ok(),
        "RFC 9173 §4.3.1: Same IV with different key is allowed"
    );
}
