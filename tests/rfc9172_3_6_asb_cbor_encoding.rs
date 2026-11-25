//! RFC 9172 §3.6 Abstract Security Block CBOR Encoding Tests
//!
//! Tests verify that security block fields are encoded with correct CBOR types
//! per RFC 9172 §3.6 requirements.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::{
    bp::*,
    security::{AesGcmVariant, HmacVariant, bcb, bib},
    types::*,
};
use std::io::Cursor;

/// Helper to create a test bundle
fn create_test_bundle() -> Bundle {
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();

    BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(1000000)
        .crc_type(CrcType::None)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap()
}

/// RFC9172-032: "This field SHALL be represented as a CBOR unsigned integer."
/// (Security Context Id field)
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_032_security_context_id_cbor_unsigned() {
    let bundle = create_test_bundle();
    let security_source = EndpointId::ipn(0, 1, 1).unwrap();

    // Generate BIB
    let key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: security_source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // payload
        },
        sha_variant: HmacVariant::Sha256,
        key: key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    // Parse CBOR manually to verify field types
    // BIB block data structure per RFC 9172 §3.6:
    // [targets_array, context_id, context_flags, security_source, params, results]
    let mut cursor = Cursor::new(&bib_block.data);

    // Skip targets array
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap();

    // Security Context Id - MUST be CBOR unsigned integer
    let context_id_val = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    match context_id_val {
        Value::Integer(n) => {
            assert!(n >= 0.into(), "Context ID must be non-negative integer");
            let id: u64 = n.try_into().unwrap();
            assert_eq!(id, 1, "BIB-HMAC-SHA2 context ID is 1");
        }
        _ => panic!(
            "RFC9172-032: Security Context Id SHALL be CBOR unsigned integer, got {:?}",
            context_id_val
        ),
    }
}

/// RFC9172-033: "This field SHALL be represented by the applicable CBOR representation
/// of the parameter, in accordance with Section 3.10."
/// (Parameter Value field within security context parameters)
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_033_parameter_value_cbor_representation() {
    let bundle = create_test_bundle();
    let security_source = EndpointId::ipn(0, 1, 1).unwrap();

    let key = vec![0xAB; 64]; // SHA512 requires 64 bytes
    let bib_config = bib::BibConfig {
        security_source: security_source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha512,
        key,
        scope_flags: 0x03, // Include primary and target header
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    // Parse to parameters array
    let mut cursor = Cursor::new(&bib_block.data);
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // targets
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // context_id
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // flags
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // source

    let params_val = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    let params_array = match params_val {
        Value::Array(arr) => arr,
        _ => panic!("Parameters must be array"),
    };

    // Check each parameter: [param_id, param_value]
    for param in &params_array {
        match param {
            Value::Array(pair) if pair.len() == 2 => {
                let param_id = match &pair[0] {
                    Value::Integer(n) => {
                        let id: u64 = (*n).try_into().unwrap();
                        id
                    }
                    _ => panic!("Parameter ID must be unsigned integer"),
                };

                // RFC9172-033: Parameter value SHALL be represented by applicable CBOR type
                // per RFC 9173 security context definitions
                if param_id == 1 {
                    // SHA variant - RFC 9173 §3.3.1 requires unsigned integer
                    match &pair[1] {
                        Value::Integer(n) => {
                            assert!(n >= &0.into(), "SHA variant must be unsigned");
                        }
                        _ => panic!("RFC9172-033: SHA variant value must be CBOR unsigned integer"),
                    }
                } else if param_id == 3 {
                    // Scope flags - RFC 9173 §3.3.3 requires unsigned integer
                    match &pair[1] {
                        Value::Integer(n) => {
                            assert!(n >= &0.into(), "Scope flags must be unsigned");
                        }
                        _ => panic!("RFC9172-033: Scope flags value must be CBOR unsigned integer"),
                    }
                }
            }
            _ => panic!("Each parameter must be [id, value] array"),
        }
    }
}

/// RFC9172-038: "This field SHALL be represented by the applicable CBOR representation
/// of the result value, in accordance with Section 3.10."
/// (Result Value field within security results)
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_038_result_value_cbor_representation() {
    let bundle = create_test_bundle();
    let security_source = EndpointId::ipn(0, 1, 1).unwrap();

    let key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: security_source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    // Parse to results array
    let mut cursor = Cursor::new(&bib_block.data);
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // targets
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // context_id
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // flags
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // source
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // params

    let results_val = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    let results_array = match results_val {
        Value::Array(arr) => arr,
        _ => panic!("Results must be array"),
    };

    // Each entry is target results: array of [result_id, result_value]
    for target_results in &results_array {
        match target_results {
            Value::Array(results) => {
                for result in results {
                    match result {
                        Value::Array(pair) if pair.len() == 2 => {
                            let result_id = match &pair[0] {
                                Value::Integer(n) => {
                                    let id: u64 = (*n).try_into().unwrap();
                                    id
                                }
                                _ => panic!("Result ID must be unsigned integer"),
                            };

                            // RFC9172-038: Result value SHALL be represented by applicable CBOR type
                            // per RFC 9173 security context definitions
                            if result_id == 1 {
                                // Expected authentication tag - RFC 9173 §3.4.3 requires byte string
                                match &pair[1] {
                                    Value::Bytes(b) => {
                                        assert!(!b.is_empty(), "HMAC signature must be non-empty");
                                    }
                                    _ => panic!(
                                        "RFC9172-038: HMAC signature value must be CBOR byte string"
                                    ),
                                }
                            }
                        }
                        _ => panic!("Each result must be [id, value] array"),
                    }
                }
            }
            _ => panic!("Each target results must be array"),
        }
    }
}

/// RFC9172-032 for BCB: Security Context Id as CBOR unsigned integer
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_032_bcb_context_id_cbor_unsigned() {
    let bundle = create_test_bundle();
    let security_source = EndpointId::ipn(0, 1, 1).unwrap();

    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];
    let bcb_config = bcb::BcbConfig {
        security_source: security_source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1], // payload
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, _) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();

    // Parse CBOR to verify Security Context Id is unsigned integer
    let mut cursor = Cursor::new(&bcb_block.data);
    ciborium::from_reader::<Value, _>(&mut cursor).unwrap(); // targets

    let context_id_val = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    match context_id_val {
        Value::Integer(n) => {
            assert!(n >= 0.into(), "Context ID must be non-negative");
            let id: u64 = n.try_into().unwrap();
            assert_eq!(id, 2, "BCB-AES-GCM context ID is 2");
        }
        _ => panic!(
            "RFC9172-032: Security Context Id SHALL be CBOR unsigned integer, got {:?}",
            context_id_val
        ),
    }
}
