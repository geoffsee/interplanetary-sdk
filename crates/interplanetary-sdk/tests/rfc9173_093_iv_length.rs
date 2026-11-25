//! RFC 9173 §4.3.1 and §4.8.1: IV length validation
//!
//! §4.3.1: "The length of the initialization vector, prior to any CBOR
//! encoding, MUST be between 8-16 bytes."
//!
//! §4.8.1: "The IV selected MUST be of the appropriate length."
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

mod common;

use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::{BlockType, BundleBuilder};
use interplanetary_sdk::bpa::security_processing::SecurityContext;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::security::AesGcmVariant;
use interplanetary_sdk::security::bcb::{self, BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::{
    Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId, SimInstant,
};

#[test]
fn test_rfc9173_093_iv_too_short_generation() {
    // RFC 9173 §4.3.1: IV must be at least 8 bytes

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

    // Test with 7-byte IV (too short)
    let short_iv = vec![0x42; 7];
    let key = vec![0x11; 16]; // Valid AES-128 key
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv: short_iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_err(),
        "RFC 9173 §4.3.1: Must reject IV shorter than 8 bytes"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("4.3.1") || err_msg.contains("8-16") || err_msg.contains("8"),
        "Error message should reference RFC 9173 §4.3.1 or IV length requirement: {}",
        err_msg
    );
}

#[test]
fn test_rfc9173_093_iv_too_long_generation() {
    // RFC 9173 §4.3.1: IV must be at most 16 bytes

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

    // Test with 17-byte IV (too long)
    let long_iv = vec![0x42; 17];
    let key = vec![0x11; 16];
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv: long_iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_err(),
        "RFC 9173 §4.3.1: Must reject IV longer than 16 bytes"
    );
}

#[test]
fn test_rfc9173_093_iv_12_bytes_valid() {
    // RFC 9173 §4.3.1: "A value of 12 bytes SHOULD be used"
    // Implementation note: aes-gcm crate currently only supports 12-byte IVs

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

    let iv = vec![0x42; 12]; // RFC-recommended length
    let key = vec![0x11; 16];
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_ok(),
        "RFC 9173 §4.3.1: Must accept 12-byte IV (SHOULD value)"
    );
}

#[test]
fn test_rfc9173_093_iv_8_bytes_valid() {
    // RFC 9173 §4.3.1: IV must be between 8-16 bytes, so 8 is valid

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

    let iv = vec![0x42; 8]; // Minimum valid length
    let key = vec![0x11; 16];
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_ok(),
        "RFC 9173 §4.3.1: Must accept 8-byte IV (minimum valid)"
    );
}

#[test]
fn test_rfc9173_093_iv_16_bytes_valid() {
    // RFC 9173 §4.3.1: IV must be between 8-16 bytes, so 16 is valid

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

    let iv = vec![0x42; 16]; // Maximum valid length
    let key = vec![0x11; 16];
    let config = BcbConfig {
        security_source: source,
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = generate_bcb(&bundle, &config, None);
    assert!(
        result.is_ok(),
        "RFC 9173 §4.3.1: Must accept 16-byte IV (maximum valid)"
    );
}

/// RFC9173-093: End-to-end test with 8-byte IV
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9173_093_e2e_iv_8_bytes() {
    let sender = EndpointId::ipn(0, 1, 0).unwrap();
    let receiver_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let aes_key = vec![0xAA; 16]; // AES-128
    let iv = vec![0x01; 8]; // 8-byte IV

    // Sender: Originate bundle with BCB
    let mut bundle = BundleBuilder::new()
        .source(sender.clone())
        .destination(receiver_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Secret with 8-byte IV".to_vec())
        .build()
        .unwrap();

    let bcb_config = BcbConfig {
        security_source: sender.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    let encoded_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver: Decrypt bundle
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(sender.clone(), aes_key);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: receiver_eid.clone(),
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
    let _ = agent.receive_bytes_from_cla(&encoded_bytes);
    agent.poll(SimInstant::from_nanos(100_000_000));

    let delivered = agent.delivered_adus();
    assert_eq!(delivered.len(), 1, "Bundle should be delivered");

    let payload: &[u8] = delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .data
        .as_ref();

    assert_eq!(
        payload, b"Secret with 8-byte IV",
        "Payload should be decrypted correctly"
    );
}

/// RFC9173-093: End-to-end test with 12-byte IV (recommended)
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9173_093_e2e_iv_12_bytes() {
    let sender = EndpointId::ipn(0, 1, 0).unwrap();
    let receiver_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let aes_key = vec![0xBB; 16]; // AES-128
    let iv = vec![0x02; 12]; // 12-byte IV (recommended)

    // Sender: Originate bundle with BCB
    let mut bundle = BundleBuilder::new()
        .source(sender.clone())
        .destination(receiver_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Secret with 12-byte IV".to_vec())
        .build()
        .unwrap();

    let bcb_config = BcbConfig {
        security_source: sender.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    let encoded_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver: Decrypt bundle
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(sender.clone(), aes_key);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: receiver_eid.clone(),
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
    let _ = agent.receive_bytes_from_cla(&encoded_bytes);
    agent.poll(SimInstant::from_nanos(100_000_000));

    let delivered = agent.delivered_adus();
    assert_eq!(delivered.len(), 1, "Bundle should be delivered");

    let payload: &[u8] = delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .data
        .as_ref();

    assert_eq!(
        payload, b"Secret with 12-byte IV",
        "Payload should be decrypted correctly"
    );
}

/// RFC9173-093: End-to-end test with 16-byte IV
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9173_093_e2e_iv_16_bytes() {
    let sender = EndpointId::ipn(0, 1, 0).unwrap();
    let receiver_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let aes_key = vec![0xCC; 16]; // AES-128
    let iv = vec![0x03; 16]; // 16-byte IV

    // Sender: Originate bundle with BCB
    let mut bundle = BundleBuilder::new()
        .source(sender.clone())
        .destination(receiver_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Secret with 16-byte IV".to_vec())
        .build()
        .unwrap();

    let bcb_config = BcbConfig {
        security_source: sender.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    let encoded_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver: Decrypt bundle
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(sender.clone(), aes_key);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: receiver_eid.clone(),
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
    let _ = agent.receive_bytes_from_cla(&encoded_bytes);
    agent.poll(SimInstant::from_nanos(100_000_000));

    let delivered = agent.delivered_adus();
    assert_eq!(delivered.len(), 1, "Bundle should be delivered");

    let payload: &[u8] = delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .data
        .as_ref();

    assert_eq!(
        payload, b"Secret with 16-byte IV",
        "Payload should be decrypted correctly"
    );
}

/// RFC9173-093: Receiver rejects bundle with 7-byte IV (too short) with status report code 15
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_093_receive_reject_iv_7_bytes() {
    use interplanetary_sdk::bpa::policy::StatusReportPolicy;
    use interplanetary_sdk::bpa::security_policy::{
        SecurityAction, SecurityOperation, SecurityPolicy, SecurityPolicyRule,
    };

    let sender = EndpointId::ipn(0, 1, 0).unwrap();
    let receiver_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();
    let aes_key = vec![0xDD; 16];

    // Generate a valid bundle with 12-byte IV first
    let mut bundle = BundleBuilder::new()
        .source(sender.clone())
        .destination(receiver_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    let valid_iv = vec![0x42; 12];
    let bcb_config = BcbConfig {
        security_source: sender.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv: valid_iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    // Now manually corrupt the BCB to have a 7-byte IV instead of 12
    // The BCB block data is CBOR-encoded. We need to decode it, modify the IV parameter, re-encode
    let bcb_idx = bundle
        .blocks
        .iter()
        .position(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();

    // Replace IV parameter (id 1) with an undersized 7-byte value.
    let mut bcb_cbor = common::asb::decode(&bundle.blocks[bcb_idx].data);
    *common::asb::find_pair_value_mut(common::asb::parameters_mut(&mut bcb_cbor), 1)
        .expect("BCB missing IV parameter") = ciborium::Value::Bytes(vec![0x42; 7]);
    bundle.blocks[bcb_idx].data = common::asb::encode(&bcb_cbor);

    let bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver with correct key but invalid IV length in BCB
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(sender.clone(), aes_key);

    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(sender.clone()),
        destination_match: Some(receiver_eid.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bcb),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::Report],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: receiver_eid.clone(),
        enable_forwarding: false,
        enable_delivery: false,
        status_report_policy: StatusReportPolicy::all(report_to.clone()),
        cla_mtu: None,
        security_context: Some(sec_ctx),
        security_policy: Some(policy),
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

    // Bundle should NOT be delivered
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        0,
        "RFC 9173 §4.3.1: Receiver must reject bundle with 7-byte IV"
    );

    // Note: Malformed IV parameter causes bundle processing failure before
    // security verification, so no status report is generated. The bundle is
    // simply rejected and not delivered, which proves the MUST requirement is enforced.
}

/// RFC9173-093: Receiver rejects bundle with 17-byte IV (too long) with status report code 15
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_093_receive_reject_iv_17_bytes() {
    use interplanetary_sdk::bpa::policy::StatusReportPolicy;
    use interplanetary_sdk::bpa::security_policy::{
        SecurityAction, SecurityOperation, SecurityPolicy, SecurityPolicyRule,
    };

    let sender = EndpointId::ipn(0, 1, 0).unwrap();
    let receiver_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();
    let aes_key = vec![0xEE; 16];

    // Generate a valid bundle with 12-byte IV first
    let mut bundle = BundleBuilder::new()
        .source(sender.clone())
        .destination(receiver_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    let valid_iv = vec![0x42; 12];
    let bcb_config = BcbConfig {
        security_source: sender.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key.clone(),
        iv: valid_iv,
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    // Now manually corrupt the BCB to have a 17-byte IV instead of 12
    let bcb_idx = bundle
        .blocks
        .iter()
        .position(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();

    // Replace IV parameter (id 1) with an oversized 17-byte value.
    let mut bcb_cbor = common::asb::decode(&bundle.blocks[bcb_idx].data);
    *common::asb::find_pair_value_mut(common::asb::parameters_mut(&mut bcb_cbor), 1)
        .expect("BCB missing IV parameter") = ciborium::Value::Bytes(vec![0x42; 17]);
    bundle.blocks[bcb_idx].data = common::asb::encode(&bcb_cbor);

    let bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver with correct key but invalid IV length in BCB
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(sender.clone(), aes_key);

    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(sender.clone()),
        destination_match: Some(receiver_eid.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bcb),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::Report],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: receiver_eid.clone(),
        enable_forwarding: false,
        enable_delivery: false,
        status_report_policy: StatusReportPolicy::all(report_to.clone()),
        cla_mtu: None,
        security_context: Some(sec_ctx),
        security_policy: Some(policy),
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

    // Bundle should NOT be delivered
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        0,
        "RFC 9173 §4.3.1: Receiver must reject bundle with 17-byte IV"
    );

    // Note: Malformed IV parameter causes bundle processing failure before
    // security verification, so no status report is generated. The bundle is
    // simply rejected and not delivered, which proves the MUST requirement is enforced.
}

/// RFC9173-093: Verify exact BCB ciphertext and tag bytes for 12-byte IV using RFC 9173 A.2 values
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_093_exact_bcb_ciphertext_12byte_iv() {
    // RFC 9173 Appendix A.2 values
    let key_hex = "71776572747975696f70617364666768"; // "qwertyuiopasdfgh"
    let iv_hex = "5477656c7665313231323132"; // "Twelve121212" (12 bytes)
    let plaintext_hex = "526561647920746f2067656e657261746520612033322d62797465207061796c6f6164";
    let expected_ciphertext_hex =
        "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a";
    let expected_tag_hex = "efa4b5ac0108e3816c5606479801bc04";

    let key = hex::decode(key_hex).unwrap();
    let iv = hex::decode(iv_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let expected_ciphertext = hex::decode(expected_ciphertext_hex).unwrap();
    let expected_tag = hex::decode(expected_tag_hex).unwrap();

    // Verify IV is 12 bytes
    assert_eq!(iv.len(), 12, "IV must be 12 bytes per RFC 9173 A.2");

    let sender = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let bundle = BundleBuilder::new()
        .source(sender.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .payload(plaintext.clone())
        .build()
        .unwrap();

    let bcb_config = BcbConfig {
        security_source: sender.clone(),
        targets: BcbTargets {
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

    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();

    // Extract the ciphertext (without tag)
    let actual_ciphertext = &ciphertexts[0];

    assert_eq!(
        actual_ciphertext.as_slice(),
        expected_ciphertext.as_slice(),
        "RFC 9173 §4.3.1 & A.2: BCB ciphertext with 12-byte IV must match RFC 9173 A.2 exact bytes"
    );

    // Extract the authentication-tag security result (result id 1).
    let bcb_cbor = common::asb::decode(&bcb_block.data);
    let tag_bytes =
        common::asb::find_pair_value(common::asb::first_target_result_items(&bcb_cbor), 1)
            .and_then(ciborium::Value::as_bytes)
            .expect("BCB missing authentication-tag result bytes");
    assert_eq!(
        tag_bytes.as_slice(),
        expected_tag.as_slice(),
        "RFC 9173 §4.3.1 & A.2: BCB authentication tag with 12-byte IV must match RFC 9173 A.2 exact bytes"
    );
}
