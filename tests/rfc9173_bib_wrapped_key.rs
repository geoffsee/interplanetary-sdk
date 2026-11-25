#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

//! RFC 9173 BIB wrapped-key tests
//!
//! RFC9173-036: HMAC key MAY be wrapped using AES-KW (RFC 3394)
//! RFC9173-043: HMAC key MUST be unwrapped if wrapped_key parameter present

use interplanetary_sdk::bp::{BundleBuilder, CreationTimestamp};
use interplanetary_sdk::bpa::security_processing::{
    SecurityContext, SecurityFailurePolicy, SecurityProcessingResult,
};
use interplanetary_sdk::security::{HmacVariant, bib, keywrap};
use interplanetary_sdk::types::{DtnTimeMs, EndpointId};

/// RFC9173-036 & 043: BIB with wrapped key - successful verification
#[test]
fn test_rfc9173_036_043_bib_wrapped_key_verification() {
    // RFC 9173 §3.3.2 (036): "The HMAC key MAY be included as a security context parameter,
    // in which case it MUST be wrapped using the AES key wrap function as defined in [RFC3394]"
    //
    // RFC 9173 §3.8.2 (043): "The HMAC key MUST be derived using the wrapped key security
    // context parameter if such a parameter is included"
    //
    // Verify that a BIB with wrapped key can be generated and verified using KEK.

    // RFC 9173 Appendix A.2 style KEK and content key
    let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap(); // "abcdefghijklmnop" (16 bytes for AES-128)
    // RFC 9173 §3.5: SHA-256 requires 32-byte HMAC key
    let content_key =
        hex::decode("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();

    // Wrap the HMAC key with the KEK per RFC 3394 (via AES-KW)
    let wrapped_key = keywrap::wrap_key(&kek, &content_key).expect("Key wrap");

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);

    let payload_data = b"Test payload for wrapped-key BIB";
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(payload_data.to_vec())
        .build()
        .unwrap();

    // Generate BIB with wrapped key
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // Target payload block
        },
        sha_variant: HmacVariant::Sha256,
        key: content_key.clone(), // This is the unwrapped key used for signing
        wrapped_key: Some(wrapped_key.clone()),
        scope_flags: 0x00,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).expect("Generate BIB");

    // Add BIB to bundle
    let mut secured_bundle = bundle;
    let mut bib_with_number = bib_block;
    bib_with_number.block_number = 2; // Assign block number
    secured_bundle.blocks.push(bib_with_number);

    // Now verify at destination using KEK (not content key directly)
    let mut ctx = SecurityContext::new();
    ctx.add_kek(source.clone(), kek); // Provide KEK, SDK will unwrap to get HMAC key
    ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut secured_bundle,
        &ctx,
        false,
    )
    .expect("BIB processing should not error");

    match result {
        SecurityProcessingResult::Success => {
            println!("✓ RFC9173-036/043: BIB with wrapped key verified successfully using KEK");
        }
        _ => panic!(
            "BIB verification should succeed with correct KEK and wrapped key: {:?}",
            result
        ),
    }
}

/// RFC9173-036 & 043: BIB with tampered wrapped key - verification fails
#[test]
fn test_rfc9173_036_043_bib_tampered_wrapped_key_fails() {
    // RFC 9173 §3.8.2 (043): If wrapped key unwrapping fails or signature verification
    // fails, the BIB check fails per RFC 9172 security policy.

    let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
    // RFC 9173 §3.5: SHA-256 requires 32-byte HMAC key
    let content_key =
        hex::decode("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();

    let wrapped_key = keywrap::wrap_key(&kek, &content_key).expect("Key wrap");

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);

    let payload_data = b"Test payload for tampered wrapped-key BIB";
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(payload_data.to_vec())
        .build()
        .unwrap();

    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: content_key.clone(),
        wrapped_key: Some(wrapped_key.clone()),
        scope_flags: 0x00,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).expect("Generate BIB");

    let mut secured_bundle = bundle;
    let mut bib_with_number = bib_block;
    bib_with_number.block_number = 2;

    // Tamper with the BIB data before inserting
    // The wrapped key is embedded in the parameters section of the BIB data
    // We'll flip some bits to corrupt it
    if bib_with_number.data.len() > 80 {
        bib_with_number.data[80] ^= 0xFF;
        if bib_with_number.data.len() > 90 {
            bib_with_number.data[90] ^= 0xFF;
        }
    }

    secured_bundle.blocks.push(bib_with_number);

    // Try to verify with correct KEK but tampered wrapped key
    let mut ctx = SecurityContext::new();
    ctx.add_kek(source.clone(), kek);
    ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut secured_bundle,
        &ctx,
        false,
    )
    .expect("BIB processing should not panic");

    match result {
        SecurityProcessingResult::BibVerificationFailed { .. } => {
            println!("✓ RFC9173-036/043: Tampered wrapped key caused BIB verification failure");
        }
        _ => panic!(
            "BIB verification should fail with tampered wrapped key: {:?}",
            result
        ),
    }
}

/// RFC9173-036 & 043: BIB with wrong KEK - verification fails
#[test]
fn test_rfc9173_036_043_bib_wrong_kek_fails() {
    // RFC 9173 §3.8.2 (043): "The HMAC key MUST be derived using the wrapped key
    // security context parameter if such a parameter is included"
    //
    // If the wrong KEK is used, unwrapping will fail or produce wrong key,
    // causing signature verification to fail.

    let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
    let wrong_kek = hex::decode("70717273747576777879808182838485").unwrap(); // Different KEK (16 bytes)
    // RFC 9173 §3.5: SHA-256 requires 32-byte HMAC key
    let content_key =
        hex::decode("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();

    let wrapped_key = keywrap::wrap_key(&kek, &content_key).expect("Key wrap");

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);

    let payload_data = b"Test payload for wrong-KEK BIB";
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(timestamp)
        .lifetime(60_000)
        .payload(payload_data.to_vec())
        .build()
        .unwrap();

    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: content_key.clone(),
        wrapped_key: Some(wrapped_key.clone()),
        scope_flags: 0x00,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).expect("Generate BIB");

    let mut secured_bundle = bundle;
    let mut bib_with_number = bib_block;
    bib_with_number.block_number = 2;
    secured_bundle.blocks.push(bib_with_number);

    // Try to verify with WRONG KEK
    let mut ctx = SecurityContext::new();
    ctx.add_kek(source.clone(), wrong_kek); // Wrong KEK!
    ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    // Wrong KEK causes unwrapping to fail, which returns an error
    let result = interplanetary_sdk::bpa::security_processing::process_bibs(
        &mut secured_bundle,
        &ctx,
        false,
    );

    match result {
        Err(e) if e.to_string().contains("unwrapping failed") => {
            println!("✓ RFC9173-036/043: Wrong KEK caused unwrapping failure (error returned)");
        }
        Ok(SecurityProcessingResult::BibVerificationFailed { .. }) => {
            println!("✓ RFC9173-036/043: Wrong KEK caused BIB verification failure");
        }
        other => panic!(
            "BIB verification should fail with wrong KEK, got: {:?}",
            other
        ),
    }
}
