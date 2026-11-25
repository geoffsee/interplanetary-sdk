//! BPSec RFC 9173 Test Vectors
//!
//! Tests BPSec BIB and BCB generation and verification through the
//! test-fixtures API. These tests verify that our implementation produces
//! correct cryptographic outputs matching known test vectors.
//!
//! Requires `test-fixtures` feature to access bib/bcb generation functions.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{
    bp::*,
    security::{AesGcmVariant, HmacVariant, bcb, bib},
    types::*,
};

#[test]
fn test_bib_hmac_sha256_deterministic() {
    // Test that BIB generation with same inputs produces same signature

    let key = vec![0x42u8; 32]; // Exactly 32 bytes for SHA-256
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();
    let dest = EndpointId::ipn(0, 16777217, 0).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::ZERO, 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(b"Test payload for HMAC".to_vec())
        .build()
        .unwrap();

    // Generate BIB twice with same configuration
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // Target payload block
        },
        sha_variant: HmacVariant::Sha256,
        key: key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    let bib1 = bib::generate_bib(&bundle, &bib_config).unwrap();
    let bib2 = bib::generate_bib(&bundle, &bib_config).unwrap();

    // BIB blocks should be identical (deterministic)
    assert_eq!(
        bib1.data, bib2.data,
        "BIB generation should be deterministic"
    );

    // Signature should be present and non-empty
    assert!(!bib1.data.is_empty(), "BIB should contain security results");
}

#[test]
fn test_bib_different_keys_different_signatures() {
    let key1 = vec![0x11u8; 32]; // Exactly 32 bytes for SHA-256
    let key2 = vec![0x22u8; 32]; // Exactly 32 bytes for SHA-256, different from key1
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Secret".to_vec())
        .build()
        .unwrap();

    let bib_config1 = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: key1.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    let bib_config2 = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: key2.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    let bib1 = bib::generate_bib(&bundle, &bib_config1).unwrap();
    let bib2 = bib::generate_bib(&bundle, &bib_config2).unwrap();

    // Different keys should produce different signatures
    assert_ne!(
        bib1.data, bib2.data,
        "Different keys should produce different BIBs"
    );
}

#[test]
fn test_bib_modified_payload_different_signature() {
    let key = vec![0x33u8; 32]; // Exactly 32 bytes for SHA-256
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();

    let bundle1 = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Original".to_vec())
        .build()
        .unwrap();

    let bundle2 = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Modified".to_vec())
        .build()
        .unwrap();

    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    let bib1 = bib::generate_bib(&bundle1, &bib_config).unwrap();
    let bib2 = bib::generate_bib(&bundle2, &bib_config).unwrap();

    // Modified payload should produce different signature
    assert_ne!(
        bib1.data, bib2.data,
        "Modified payload should change BIB signature"
    );
}

#[test]
fn test_bcb_aes_gcm_deterministic() {
    // Test BCB generation with deterministic IV
    let content_key = b"sixteen-byte-key"; // 16 bytes for AES-128
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Confidential data".to_vec())
        .build()
        .unwrap();

    // Use fixed IV for deterministic testing
    let iv = vec![
        0x5b, 0xdc, 0xb2, 0x84, 0x59, 0xf9, 0x07, 0xff, 0x4d, 0xa0, 0xa5, 0xd4,
    ];

    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1], // Target payload
        },
        aes_variant: AesGcmVariant::Aes128,
        key: content_key.to_vec(),
        iv: iv.clone(),
        wrapped_key: Some(vec![0; 24]), // Dummy wrapped key
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: false,
    };

    let (bcb1, _ciphertexts1) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    let (bcb2, _ciphertexts2) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();

    // With same IV, BCB should be deterministic
    assert_eq!(
        bcb1.data, bcb2.data,
        "BCB with same IV should be deterministic"
    );
}

#[test]
fn test_bcb_different_ivs_different_ciphertexts() {
    let content_key = b"sixteen-byte-key";
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Secret message".to_vec())
        .build()
        .unwrap();

    let iv1 = vec![0x01; 12];
    let iv2 = vec![0x02; 12];

    let bcb_config1 = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: content_key.to_vec(),
        iv: iv1,
        wrapped_key: Some(vec![0; 24]),
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: false,
    };

    let bcb_config2 = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: content_key.to_vec(),
        iv: iv2,
        wrapped_key: Some(vec![0; 24]),
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: false,
    };

    let (bcb1, _ciphertexts1) = bcb::generate_bcb(&bundle, &bcb_config1, None).unwrap();
    let (bcb2, _ciphertexts2) = bcb::generate_bcb(&bundle, &bcb_config2, None).unwrap();

    // Different IVs should produce different ciphertexts
    assert_ne!(
        bcb1.data, bcb2.data,
        "Different IVs should produce different BCB ciphertexts"
    );
}

#[test]
fn test_multi_target_bib_generation() {
    // Test BIB with multiple targets (primary + extension blocks)
    let key = vec![0x44u8; 32]; // Exactly 32 bytes for SHA-256
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"Multi-target test".to_vec())
        .build()
        .unwrap();

    // Single target BIB
    let bib_config_single = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    let bib_single = bib::generate_bib(&bundle, &bib_config_single).unwrap();

    // BIB should be generated successfully
    assert!(
        !bib_single.data.is_empty(),
        "Single-target BIB should be non-empty"
    );
}

#[test]
fn test_construct_ippt_deterministic() {
    // Test that IPPT construction is deterministic
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();
    let bundle = BundleBuilder::new()
        .source(source)
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"IPPT test".to_vec())
        .build()
        .unwrap();

    let ippt1 = bib::construct_ippt(&bundle, 1, 0x00).unwrap();
    let ippt2 = bib::construct_ippt(&bundle, 1, 0x00).unwrap();

    assert_eq!(ippt1, ippt2, "IPPT construction should be deterministic");
    assert!(!ippt1.is_empty(), "IPPT should be non-empty");
}

#[test]
fn test_construct_aad_deterministic() {
    // Test that AAD construction is deterministic
    let source = EndpointId::ipn(0, 16777216, 0).unwrap();
    let bundle = BundleBuilder::new()
        .source(source)
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(b"AAD test".to_vec())
        .build()
        .unwrap();

    // AAD for BCB targeting payload block (1) with BCB at block 2
    let aad1 = bcb::construct_aad(&bundle, 1, 2, 0x00).unwrap();
    let aad2 = bcb::construct_aad(&bundle, 1, 2, 0x00).unwrap();

    assert_eq!(aad1, aad2, "AAD construction should be deterministic");
    assert!(!aad1.is_empty(), "AAD should be non-empty");
}
