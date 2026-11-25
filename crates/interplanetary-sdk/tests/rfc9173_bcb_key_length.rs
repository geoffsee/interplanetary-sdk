//! RFC 9173 §4.8.1: AES encryption key length validation
//!
//! "The encryption key MUST have the appropriate length as required by local security policy."
//! For AES-128-GCM: 16 bytes (128 bits)
//! For AES-256-GCM: 32 bytes (256 bits)
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

#[cfg(feature = "test-fixtures")]
use interplanetary_sdk::bp::BundleBuilder;
#[cfg(feature = "test-fixtures")]
use interplanetary_sdk::security::AesGcmVariant;
#[cfg(feature = "test-fixtures")]
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
#[cfg(feature = "test-fixtures")]
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// Test that AES-128 rejects wrong key lengths at generation
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_092_aes128_wrong_key_length_generation() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Test with 32-byte key (wrong for AES-128, correct for AES-256)
    let wrong_key = vec![0x42; 32];
    let iv = vec![0x01; 12];

    let config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: wrong_key,
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_err(),
        "RFC 9173 §4.8.1: Must reject 32-byte key for AES-128"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("AES-128") || err_msg.contains("16"),
        "Error message should reference AES-128 or 16-byte requirement: {}",
        err_msg
    );

    // Test with 8-byte key (wrong for AES-128)
    let short_key = vec![0x42; 8];
    let config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: short_key,
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_err(),
        "RFC 9173 §4.8.1: Must reject 8-byte key for AES-128"
    );
}

/// Test that AES-256 rejects wrong key lengths at generation
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_092_aes256_wrong_key_length_generation() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Test with 16-byte key (wrong for AES-256, correct for AES-128)
    let wrong_key = vec![0x42; 16];
    let iv = vec![0x01; 12];

    let config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes256,
        key: wrong_key,
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_err(),
        "RFC 9173 §4.8.1: Must reject 16-byte key for AES-256"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("AES-256") || err_msg.contains("32"),
        "Error message should reference AES-256 or 32-byte requirement: {}",
        err_msg
    );

    // Test with 24-byte key (wrong for AES-256)
    let wrong_key_24 = vec![0x42; 24];
    let config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes256,
        key: wrong_key_24,
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_err(),
        "RFC 9173 §4.8.1: Must reject 24-byte key for AES-256"
    );
}

/// Test that correct key lengths ARE accepted
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9173_092_correct_key_lengths_accepted() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let iv = vec![0x01; 12];

    // AES-128 with 16-byte key
    let key_128 = vec![0x42; 16];
    let config_128 = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: key_128,
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    assert!(
        generate_bcb(&bundle, &config_128, None).is_ok(),
        "RFC 9173 §4.8.1: Must accept 16-byte key for AES-128"
    );

    // AES-256 with 32-byte key
    let key_256 = vec![0x42; 32];
    let config_256 = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes256,
        key: key_256,
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    assert!(
        generate_bcb(&bundle, &config_256, None).is_ok(),
        "RFC 9173 §4.8.1: Must accept 32-byte key for AES-256"
    );
}

/// Test that wrong key lengths are rejected on receive/decrypt
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_092_wrong_key_length_on_receive() {
    use interplanetary_sdk::SimInstant;
    use interplanetary_sdk::bp::codec::BundleCodec;
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;
    use interplanetary_sdk::types::{Bytes, NodeId};

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Generate a valid BCB bundle with AES-128
    let correct_key = vec![0xAA; 16];
    let iv = vec![0x01; 12];

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    let bcb_config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: correct_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    let bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver with WRONG key length (32 bytes for AES-128)
    let mut sec_ctx = SecurityContext::new();
    let wrong_key = vec![0xAA; 32]; // Wrong length!
    sec_ctx.add_aes_key(source.clone(), wrong_key);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: Default::default(),
        cla_mtu: None,
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: Default::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);
    let _ = agent.receive_bytes_from_cla(&bundle_bytes);
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Bundle MUST NOT be delivered - wrong key length causes decryption to fail
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        0,
        "RFC 9173 §4.8.1: BCB with wrong key length MUST be rejected on receive"
    );
}
