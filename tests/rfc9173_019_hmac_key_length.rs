//! RFC 9173 §3.5: HMAC key length validation
//!
//! "HMAC keys used with this context MUST be symmetric and MUST have a
//! key length equal to the output of the HMAC."
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::security::HmacVariant;
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

#[test]
fn test_rfc9173_019_hmac_sha256_wrong_key_length_generation() {
    // RFC 9173 §3.5: HMAC-SHA-256 requires 32-byte key (output length)
    // Test with wrong key lengths: reject at generation

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Test with 16-byte key (wrong for SHA-256)
    let wrong_key_16 = vec![0x42; 16];
    let config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: wrong_key_16,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let result = generate_bib(&bundle, &config);
    assert!(
        result.is_err(),
        "RFC 9173 §3.5: Must reject 16-byte key for HMAC-SHA-256"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("3.5") || err_msg.contains("key") || err_msg.contains("32"),
        "Error message should reference RFC 9173 §3.5 or key length requirement: {}",
        err_msg
    );

    // Test with 64-byte key (wrong for SHA-256)
    let wrong_key_64 = vec![0x42; 64];
    let config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: wrong_key_64,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let result = generate_bib(&bundle, &config);
    assert!(
        result.is_err(),
        "RFC 9173 §3.5: Must reject 64-byte key for HMAC-SHA-256"
    );
}

#[test]
fn test_rfc9173_019_hmac_sha384_wrong_key_length_generation() {
    // RFC 9173 §3.5: HMAC-SHA-384 requires 48-byte key (output length)

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Test with 32-byte key (wrong for SHA-384)
    let wrong_key = vec![0x42; 32];
    let config = BibConfig {
        security_source: source,
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha384,
        key: wrong_key,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let result = generate_bib(&bundle, &config);
    assert!(
        result.is_err(),
        "RFC 9173 §3.5: Must reject 32-byte key for HMAC-SHA-384"
    );
}

#[test]
fn test_rfc9173_019_hmac_sha512_wrong_key_length_generation() {
    // RFC 9173 §3.5: HMAC-SHA-512 requires 64-byte key (output length)

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Test with 32-byte key (wrong for SHA-512)
    let wrong_key = vec![0x42; 32];
    let config = BibConfig {
        security_source: source,
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha512,
        key: wrong_key,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let result = generate_bib(&bundle, &config);
    assert!(
        result.is_err(),
        "RFC 9173 §3.5: Must reject 32-byte key for HMAC-SHA-512"
    );
}

#[test]
fn test_rfc9173_019_hmac_sha256_correct_key_lengths_accepted() {
    // RFC 9173 §3.5: Verify that correct key lengths ARE accepted

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // SHA-256 with 32-byte key
    let key_256 = vec![0x42; 32];
    let config_256 = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: key_256,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };
    assert!(
        generate_bib(&bundle, &config_256).is_ok(),
        "RFC 9173 §3.5: Must accept 32-byte key for HMAC-SHA-256"
    );

    // SHA-384 with 48-byte key
    let key_384 = vec![0x42; 48];
    let config_384 = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha384,
        key: key_384,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };
    assert!(
        generate_bib(&bundle, &config_384).is_ok(),
        "RFC 9173 §3.5: Must accept 48-byte key for HMAC-SHA-384"
    );

    // SHA-512 with 64-byte key
    let key_512 = vec![0x42; 64];
    let config_512 = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha512,
        key: key_512,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };
    assert!(
        generate_bib(&bundle, &config_512).is_ok(),
        "RFC 9173 §3.5: Must accept 64-byte key for HMAC-SHA-512"
    );
}
