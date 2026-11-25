//! RFC 9173 Erratum 7002: One Target Per BCB
//!
//! Erratum 7002 requires that each BCB encrypt exactly one target to ensure
//! unique IV/nonce per operation (AES-GCM security requirement).
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{
    bp::*,
    security::AesGcmVariant,
    security::bcb::{BcbConfig, BcbTargets, generate_bcb},
    types::*,
};

#[test]
fn test_erratum_7002_bcb_rejects_two_targets() {
    // RFC 9173 erratum 7002: BCB generation MUST reject multi-target requests
    // to prevent IV reuse across encrypted blocks

    // Build a simple bundle with two extension blocks
    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add a hop count extension block (block number 2)
    let hop_count_block = CanonicalBlock {
        block_type: BlockType::HopCount,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x82, 0x1e, 0x00], // [30, 0] - limit 30, count 0
    };
    bundle.blocks.insert(0, hop_count_block);

    // Now bundle has: primary + hop count (block 2) + payload (block 1)

    // Try to create BCB with TWO targets (hop count + payload)
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1, 2], // TWO targets - violates erratum 7002
        },
        aes_variant: AesGcmVariant::Aes128,
        key: vec![0xAB; 16],
        iv: vec![0xCD; 12],
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
    };

    // This MUST fail per erratum 7002
    let result = generate_bcb(&bundle, &config, None);

    assert!(
        result.is_err(),
        "BCB generation MUST fail with 2 targets per RFC 9173 erratum 7002"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string().to_lowercase();

    assert!(
        err_msg.contains("7002")
            || err_msg.contains("one target")
            || err_msg.contains("exactly one"),
        "Error message should reference erratum 7002 or single-target requirement. Got: {}",
        err
    );
}

#[test]
fn test_erratum_7002_bcb_accepts_one_target() {
    // Positive test: BCB with exactly one target MUST succeed

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Create BCB with ONE target (payload only) - compliant with erratum 7002
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1], // ONE target - compliant
        },
        aes_variant: AesGcmVariant::Aes128,
        key: vec![0xAB; 16],
        iv: vec![0xCD; 12],
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);

    assert!(
        result.is_ok(),
        "BCB generation MUST succeed with 1 target. Got error: {:?}",
        result.err()
    );

    let (bcb, _ciphertexts) = result.unwrap();
    assert_eq!(bcb.block_type, BlockType::Bcb);
}

#[test]
fn test_erratum_7002_bcb_rejects_zero_targets() {
    // Edge case: BCB with zero targets MUST also fail

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Create BCB with ZERO targets
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![], // ZERO targets
        },
        aes_variant: AesGcmVariant::Aes128,
        key: vec![0xAB; 16],
        iv: vec![0xCD; 12],
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);

    assert!(result.is_err(), "BCB generation MUST fail with 0 targets");
}
