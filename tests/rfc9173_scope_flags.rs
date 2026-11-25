//! RFC 9173 Scope Flags Tests
//!
//! Tests that scope flags affect IPPT/AAD construction per RFC 9173 §3.3.3 (BIB) and §4.3.4 (BCB).
//!
//! Scope flags control which optional data is included in integrity protection:
//! - Bit 0: Include primary block
//! - Bit 1: Include target header  
//! - Bit 2: Include security header
//! - Bits 3-7: Reserved (MUST be 0)
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{
    bp::*,
    security::{AesGcmVariant, HmacVariant, bcb, bib, construct_aad, construct_ippt},
    types::*,
};

fn create_test_bundle() -> Bundle {
    BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Test data".to_vec())
        .build()
        .unwrap()
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9173_022_scope_flags_included_in_ippt() {
    // RFC 9173 §3.7: "While integrity scope flags might not be included in the BIB
    // representing the security operation, they MUST be included in the IPPT value itself."
    //
    // This test verifies that changing scope flags produces different IPPT values,
    // proving the flags are included in IPPT construction per the RFC.

    let bundle = create_test_bundle();
    let target_block_num = 1; // payload

    // Test different scope flag values
    // RFC 9173 §3.3.3: Bit 0=primary, Bit 1=target header, Bit 2=security header
    let scope_0x00 = construct_ippt(&bundle, target_block_num, 0x00).unwrap();
    let scope_0x01 = construct_ippt(&bundle, target_block_num, 0x01).unwrap(); // +primary
    let scope_0x02 = construct_ippt(&bundle, target_block_num, 0x02).unwrap(); // +target header
    let scope_0x04 = construct_ippt(&bundle, target_block_num, 0x04).unwrap(); // +security header
    let scope_0x07 = construct_ippt(&bundle, target_block_num, 0x07).unwrap(); // all flags

    // RFC 9173 §3.7: Scope flags MUST be included in IPPT
    // Each different scope flag value MUST produce different IPPT
    assert_ne!(
        scope_0x00, scope_0x01,
        "Scope flag bit 0 (primary) MUST affect IPPT construction"
    );
    assert_ne!(
        scope_0x00, scope_0x02,
        "Scope flag bit 1 (target header) MUST affect IPPT construction"
    );
    assert_ne!(
        scope_0x00, scope_0x04,
        "Scope flag bit 2 (security header) MUST affect IPPT construction"
    );
    assert_ne!(
        scope_0x00, scope_0x07,
        "Scope flag combination MUST produce unique IPPT"
    );

    // All scope flag values should produce different IPPTs
    assert_ne!(scope_0x01, scope_0x02);
    assert_ne!(scope_0x01, scope_0x04);
    assert_ne!(scope_0x02, scope_0x04);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9173_023_primary_block_flag_includes_primary() {
    // RFC 9173 §3.7.1 Step 2: "If the primary block flag of the integrity scope flags
    // is set to 1 and the security target is not the bundle's primary block, then a
    // canonical form of the bundle's primary block MUST be calculated and the result
    // appended to the IPPT value."

    let bundle = create_test_bundle();
    let target_block_num = 1; // payload (not primary)

    // Scope without primary block flag (bit 0 = 0)
    let ippt_without_primary = construct_ippt(&bundle, target_block_num, 0x00).unwrap();

    // Scope with primary block flag (bit 0 = 1)
    let ippt_with_primary = construct_ippt(&bundle, target_block_num, 0x01).unwrap();

    // RFC 9173 §3.7.1: Primary block flag=1 MUST include primary block in IPPT
    assert!(
        ippt_with_primary.len() > ippt_without_primary.len(),
        "IPPT with primary block flag MUST be longer (includes canonical primary block)"
    );

    // The difference should be substantial (primary block is encoded)
    let size_diff = ippt_with_primary.len() - ippt_without_primary.len();
    assert!(
        size_diff > 20,
        "Primary block contribution MUST be substantial, got {} bytes",
        size_diff
    );
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9173_086_aad_scope_flags_included() {
    // RFC 9173 §4.7.2: "While the AAD scope flags might not be included in the BCB
    // representing the security operation, they MUST be included in the AAD value itself."
    //
    // This test verifies scope flags affect AAD construction for BCB.

    let bundle = create_test_bundle();
    let target_block_num = 1; // payload
    let security_block_num = 2; // hypothetical BCB block number

    // Test different AAD scope flag values
    // Note: We test flags 0x00, 0x01, 0x02, 0x03 (not 0x04 which requires BCB block)
    let aad_0x00 = construct_aad(&bundle, target_block_num, security_block_num, 0x00).unwrap();
    let aad_0x01 = construct_aad(&bundle, target_block_num, security_block_num, 0x01).unwrap(); // +primary block
    let aad_0x02 = construct_aad(&bundle, target_block_num, security_block_num, 0x02).unwrap(); // +target header
    let aad_0x03 = construct_aad(&bundle, target_block_num, security_block_num, 0x03).unwrap(); // primary+target

    // RFC 9173 §4.7.2: AAD scope flags MUST be included in AAD
    // Each different scope flag value MUST produce different AAD
    assert_ne!(
        aad_0x00, aad_0x01,
        "AAD scope flag bit 0 (primary) MUST affect AAD construction"
    );
    assert_ne!(
        aad_0x00, aad_0x02,
        "AAD scope flag bit 1 (target header) MUST affect AAD construction"
    );
    assert_ne!(
        aad_0x00, aad_0x03,
        "AAD scope flag combination MUST produce unique AAD"
    );

    assert_ne!(aad_0x01, aad_0x02);
    assert_ne!(aad_0x01, aad_0x03);
    assert_ne!(aad_0x02, aad_0x03);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9173_087_primary_block_flag_in_aad() {
    // RFC 9173 §4.7.2 Step 2: "If the primary block flag of the AAD scope flags is
    // set to 1, then a canonical form of the bundle's primary block MUST be calculated
    // and the result appended to the AAD."

    let bundle = create_test_bundle();
    let target_block_num = 1;
    let security_block_num = 2;

    // AAD without primary block flag
    let aad_without_primary =
        construct_aad(&bundle, target_block_num, security_block_num, 0x00).unwrap();

    // AAD with primary block flag (bit 0 = 1)
    let aad_with_primary =
        construct_aad(&bundle, target_block_num, security_block_num, 0x01).unwrap();

    // RFC 9173 §4.7.2: Primary block flag=1 MUST include primary block in AAD
    assert!(
        aad_with_primary.len() > aad_without_primary.len(),
        "AAD with primary block flag MUST be longer (includes canonical primary block)"
    );

    let size_diff = aad_with_primary.len() - aad_without_primary.len();
    assert!(
        size_diff > 20,
        "Primary block contribution to AAD MUST be substantial, got {} bytes",
        size_diff
    );
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_008_scope_flags_always_in_ippt() {
    // RFC 9173 §3.2: "IPPT scope The determination of which optional types of information
    // were used when constructing the IPPT MUST always be included in the IPPT."
    //
    // This comprehensive test verifies that:
    // 1. Scope flags are always included in IPPT (changing them changes output)
    // 2. Each flag bit has a distinct effect on IPPT construction

    let bundle = create_test_bundle();
    let target_num = 1;

    let mut ippts = std::collections::HashMap::new();

    // Test all 8 possible combinations of 3 flag bits
    for flags in 0..8u8 {
        let ippt = construct_ippt(&bundle, target_num, flags).unwrap();
        ippts.insert(flags, ippt);
    }

    // RFC 9173 §3.2: Scope determination MUST always be included
    // Every unique scope flag combination MUST produce unique IPPT
    for (flags1, ippt1) in &ippts {
        for (flags2, ippt2) in &ippts {
            if flags1 != flags2 {
                assert_ne!(
                    ippt1, ippt2,
                    "Scope flags {:#04x} and {:#04x} MUST produce different IPPTs per RFC 9173 §3.2",
                    flags1, flags2
                );
            }
        }
    }
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_bib_generation_with_scope_flags() {
    // Integration test: BIB generation with different scope flags produces different signatures
    // RFC 9173 §3.8.1: "Any local flags used to generate the IPPT MUST be placed in the
    // integrity scope flags security context parameter for the BIB"

    let bundle = create_test_bundle();
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xAB; 32];

    // Generate BIB with scope_flags = 0x00
    let bib_config_00 = bib::BibConfig {
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
    let bib_00 = bib::generate_bib(&bundle, &bib_config_00).unwrap();

    // Generate BIB with scope_flags = 0x07 (all flags)
    let bib_config_07 = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key,
        scope_flags: 0x07,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };
    let bib_07 = bib::generate_bib(&bundle, &bib_config_07).unwrap();

    // RFC 9173 §3.3.3: Different scope flags MUST produce different BIB blocks
    assert_ne!(
        bib_00.data, bib_07.data,
        "BIBs with different scope flags MUST have different block data (different signatures)"
    );

    // The BIBs should contain the scope flags in their parameters
    // We can verify they're different by checking the signatures are different
    // (since different IPPT -> different signature)
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_bcb_generation_with_scope_flags() {
    // Integration test: BCB generation with different scope flags produces different auth tags
    // RFC 9173 §4.8.1: "Any local flags used to generate AAD for this cipher MUST be placed
    // in the AAD scope flags security context parameter for the BCB"

    let bundle = create_test_bundle();
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];

    // Generate BCB with scope_flags = 0x00
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

    // Generate BCB with scope_flags = 0x07 (all flags)
    let bcb_config_07 = bcb::BcbConfig {
        security_source: source,
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0x07,
        key_id: None,
        skip_source_validation: true,
    };
    let (bcb_07, _) = bcb::generate_bcb(&bundle, &bcb_config_07, None).unwrap();

    // RFC 9173 §4.3.4: Different scope flags MUST produce different BCB blocks
    assert_ne!(
        bcb_00.data, bcb_07.data,
        "BCBs with different scope flags MUST have different block data (different auth tags)"
    );
}

/// RFC9173-017: Reserved bits in scope flags MUST be set to 0
///
/// RFC 9173 §3.3.3: "Implementations MUST set reserved and unassigned bits in this field
/// to 0 when constructing these flags at a security source."
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_017_reserved_bits_zero_in_bib() {
    // RFC 9173 §3.3.3: Only bits 0, 1, 2 are defined. Bits 3-7 are reserved.
    // Implementations MUST set reserved bits to 0.

    let bundle = create_test_bundle();
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xAB; 32];

    // Test that BIB generation masks out reserved bits (bits 3-7)
    // Try to set a reserved bit (e.g., bit 3 = 0x08) in scope_flags
    let bib_config_with_reserved = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: key.clone(),
        scope_flags: 0x0F, // 0b00001111 - includes reserved bit 3
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config_with_reserved).unwrap();

    // Decode BIB to check scope flags in security context parameters
    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bib_block.data);

    // Field 1: Security targets
    let _targets: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 2: Security context ID
    let _context_id: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 3: Security context flags
    let _flags: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 4: Security source
    let _source: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 5: Security context parameters (array of [id, value] pairs)
    let params: Value = ciborium::from_reader(&mut cursor).unwrap();

    if let Value::Array(param_list) = params {
        // Look for scope flags parameter (id=1 per RFC 9173 §3.3.1)
        for param in param_list {
            if let Value::Array(pair) = param
                && pair.len() == 2
                && let (Value::Integer(id), Value::Integer(value)) = (&pair[0], &pair[1])
            {
                let id_i64: i64 = (*id).try_into().unwrap();
                if id_i64 == 1 {
                    // Found scope flags parameter
                    let scope_flags_value: u64 = (*value).try_into().unwrap();
                    // RFC 9173 §3.3.3: Reserved bits (3-7) MUST be 0
                    assert_eq!(
                        scope_flags_value & 0xF8,
                        0,
                        "RFC 9173 §3.3.3: Reserved bits (3-7) in scope flags MUST be 0. Got: {:#04x}",
                        scope_flags_value
                    );
                    // Only bits 0-2 should be set
                    assert_eq!(
                        scope_flags_value & !0x07,
                        0,
                        "RFC 9173 §3.3.3: Only bits 0-2 are defined in scope flags. Got: {:#04x}",
                        scope_flags_value
                    );
                    return; // Test passed
                }
            }
        }
        panic!("Scope flags parameter (id=1) not found in BIB security context parameters");
    } else {
        panic!("Security context parameters must be a CBOR array");
    }
}

/// RFC9173-017: Reserved bits in AAD scope flags MUST be set to 0
///
/// RFC 9173 §4.3.4: Same requirement for BCB AAD scope flags
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_017_reserved_bits_zero_in_bcb() {
    // RFC 9173 §4.3.4: AAD scope flags have same reserved bit requirement

    let bundle = create_test_bundle();
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];

    // Test that BCB generation masks out reserved bits
    let bcb_config_with_reserved = bcb::BcbConfig {
        security_source: source,
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0xFF, // 0b11111111 - all reserved bits set
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, _) = bcb::generate_bcb(&bundle, &bcb_config_with_reserved, None).unwrap();

    // Decode BCB to check scope flags in security context parameters
    use ciborium::Value;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&bcb_block.data);

    // Field 1: Security targets
    let _targets: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 2: Security context ID
    let _context_id: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 3: Security context flags
    let _flags: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 4: Security source
    let _source: Value = ciborium::from_reader(&mut cursor).unwrap();
    // Field 5: Security context parameters (array of [id, value] pairs)
    let params: Value = ciborium::from_reader(&mut cursor).unwrap();

    if let Value::Array(param_list) = params {
        // Look for AAD scope flags parameter (id=4 per RFC 9173 §4.3.1 Table 4)
        for param in param_list {
            if let Value::Array(pair) = param
                && pair.len() == 2
                && let (Value::Integer(id), Value::Integer(value)) = (&pair[0], &pair[1])
            {
                let id_i64: i64 = (*id).try_into().unwrap();
                if id_i64 == 4 {
                    // Found AAD scope flags parameter
                    let scope_flags_value: u64 = (*value).try_into().unwrap();
                    // RFC 9173 §4.3.4: Reserved bits (3-7) MUST be 0
                    assert_eq!(
                        scope_flags_value & 0xF8,
                        0,
                        "RFC 9173 §4.3.4: Reserved bits (3-7) in AAD scope flags MUST be 0. Got: {:#04x}",
                        scope_flags_value
                    );
                    // Only bits 0-2 should be set
                    assert_eq!(
                        scope_flags_value & !0x07,
                        0,
                        "RFC 9173 §4.3.4: Only bits 0-2 are defined in AAD scope flags. Got: {:#04x}",
                        scope_flags_value
                    );
                    return; // Test passed
                }
            }
        }
        panic!("AAD scope flags parameter (id=4) not found in BCB security context parameters");
    } else {
        panic!("Security context parameters must be a CBOR array");
    }
}
