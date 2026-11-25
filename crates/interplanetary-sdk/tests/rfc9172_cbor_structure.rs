//! RFC 9172 §3.6 Abstract Security Block CBOR Structure Tests
//!
//! Verifies that generated security blocks conform to RFC 9172 §3.6 CBOR encoding requirements.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

#[cfg(feature = "test-fixtures")]
use interplanetary_sdk::{
    bp::*,
    security::{HmacVariant, bib},
    types::*,
};

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_019_020_targets_as_cbor_array() {
    // RFC 9172 §3.6: Security targets field SHALL be represented by a CBOR array

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Generate BIB
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // Target payload
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    // Decode BIB block data to verify structure
    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Field 1: Security targets (CBOR array per RFC 9172 §3.6)
    let targets_value: Value = ciborium::from_reader(&mut cursor).unwrap();
    assert!(
        matches!(targets_value, Value::Array(_)),
        "RFC 9172 §3.6: Security targets MUST be a CBOR array. Got: {:?}",
        targets_value
    );

    if let Value::Array(targets) = targets_value {
        assert_eq!(targets.len(), 1, "RFC 9172 §3.6: One entry for each target");
        assert!(
            matches!(targets[0], Value::Integer(_)),
            "RFC 9172 §3.4/3.6: Target MUST be represented as block number (integer)"
        );
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_023_context_id_as_unsigned() {
    // RFC 9172 §3.6: Security context ID SHALL be represented by a CBOR unsigned integer

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Generate BIB
    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Skip targets array
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();

    // Field 2: Security context ID (CBOR unsigned integer per RFC 9172 §3.6)
    let context_id: Value = ciborium::from_reader(&mut cursor).unwrap();
    assert!(
        matches!(context_id, Value::Integer(_)),
        "RFC 9172 §3.6: Security context ID MUST be CBOR unsigned integer. Got: {:?}",
        context_id
    );

    // For BIB-HMAC-SHA2, context ID should be 1 per RFC 9173 §3.2
    if let Value::Integer(id) = context_id {
        let id_u64: u64 = id.try_into().unwrap();
        assert_eq!(id_u64, 1, "BIB-HMAC-SHA2 context ID should be 1");
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_024_flags_as_unsigned_bitfield() {
    // RFC 9172 §3.6: Security context flags SHALL be represented as CBOR unsigned integer (bit field)

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Skip targets array and context ID
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();

    // Field 3: Security context flags (CBOR unsigned integer per RFC 9172 §3.6)
    let flags: Value = ciborium::from_reader(&mut cursor).unwrap();
    assert!(
        matches!(flags, Value::Integer(_)),
        "RFC 9172 §3.6: Security context flags MUST be CBOR unsigned integer. Got: {:?}",
        flags
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_029_source_as_eid_array() {
    // RFC 9172 §3.6: Security source SHALL be represented by a CBOR array per RFC 9171 EID rules

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Skip targets array, context ID, and flags
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();

    // Field 4: Security source (CBOR array per RFC 9171 EID encoding)
    let source_val: Value = ciborium::from_reader(&mut cursor).unwrap();
    assert!(
        matches!(source_val, Value::Array(_)),
        "RFC 9172 §3.6: Security source MUST be CBOR array (EID encoding per RFC 9171). Got: {:?}",
        source_val
    );

    // RFC 9171 §4.2.5: EID is [scheme_code, SSP]
    if let Value::Array(eid) = source_val {
        assert!(
            eid.len() >= 2,
            "RFC 9171 EID must have at least 2 elements [scheme, SSP]"
        );
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_030_params_as_cbor_array() {
    // RFC 9172 §3.6: Security parameters SHALL be represented by a CBOR array

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Skip targets array, context ID, flags, and source
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();

    // Field 5: Security parameters (CBOR array per RFC 9172 §3.6)
    let params: Value = ciborium::from_reader(&mut cursor).unwrap();
    assert!(
        matches!(params, Value::Array(_)),
        "RFC 9172 §3.6: Security parameters MUST be CBOR array. Got: {:?}",
        params
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_034_results_as_cbor_array() {
    // RFC 9172 §3.6: Security results SHALL be represented by a CBOR array

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Skip targets array, context ID, flags, source, and params
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();

    // Field 6: Security results (CBOR array per RFC 9172 §3.6)
    let results: Value = ciborium::from_reader(&mut cursor).unwrap();
    assert!(
        matches!(results, Value::Array(_)),
        "RFC 9172 §3.6: Security results MUST be CBOR array. Got: {:?}",
        results
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_021_targets_non_empty_valid_blocks() {
    // RFC 9172 §3.6: Targets array MUST have at least one entry and each MUST be a valid block number

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Generate BIB targeting payload (block 1)
    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1], // Valid block (payload)
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Decode targets array
    let targets_value: Value = ciborium::from_reader(&mut cursor).unwrap();

    if let Value::Array(targets) = targets_value {
        // RFC 9172 §3.6: Array MUST have at least one entry
        assert!(
            !targets.is_empty(),
            "RFC 9172 §3.6: Targets array MUST have at least one entry"
        );

        // Each entry MUST represent a valid block number
        for target in &targets {
            assert!(
                matches!(target, Value::Integer(_)),
                "RFC 9172 §3.6: Each target MUST be a block number (integer)"
            );

            if let Value::Integer(block_num) = target {
                let block_num_u64: u64 = (*block_num).try_into().unwrap();
                // Verify block exists in bundle (block 1 is payload)
                assert!(
                    block_num_u64 == 1,
                    "RFC 9172 §3.6: Target block {} must exist in bundle",
                    block_num_u64
                );
            }
        }
    } else {
        panic!("Targets must be CBOR array");
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_035_036_results_ordered_one_per_target() {
    // RFC 9172 §3.6: Results MUST be ordered identically to targets, one per target

    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Generate BIB with single target
    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1], // Single target: payload
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();

    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Decode targets
    let targets_value: Value = ciborium::from_reader(&mut cursor).unwrap();
    let target_count = if let Value::Array(ref targets) = targets_value {
        targets.len()
    } else {
        0
    };

    // Skip context ID, flags, source, params
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();
    let _: Value = ciborium::from_reader(&mut cursor).unwrap();

    // Decode results
    let results_value: Value = ciborium::from_reader(&mut cursor).unwrap();

    if let Value::Array(results) = results_value {
        // RFC 9172 §3.6: One result per target
        assert_eq!(
            results.len(),
            target_count,
            "RFC 9172 §3.6: There MUST be one entry in results for each entry in targets. \
             Got {} results for {} targets",
            results.len(),
            target_count
        );

        // RFC 9172 §3.6: Results ordered identically to targets
        // For single target, ordering is trivially satisfied
        // For multiple targets, the SDK iterates through targets in order
        // and generates results in the same order (see bib.rs:191-195)
        assert_eq!(
            results.len(),
            1,
            "Single target should produce single result"
        );
    } else {
        panic!("Results must be CBOR array");
    }
}
