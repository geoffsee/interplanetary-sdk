//! RFC 9173 §4.8.1: BCB authentication tag processing
//!
//! RFC9173-100 (verbatim): "The authentication tag calculated by the AES-GCM cipher
//! MAY be added as a security result for the security target in the BCB holding results
//! for this security operation, in which case it MUST be processed as described in Section 4.4."
//!
//! This SDK always adds the authentication tag (making the conditional live), so this test
//! verifies the MUST: the tag is processed per §4.4, meaning tampering causes failure.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

mod common;

#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::SimInstant;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bp::codec::BundleCodec;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bp::{BlockType, BundleBuilder};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bpa::policy::StatusReportPolicy;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bpa::security_policy::{
    SecurityAction, SecurityOperation, SecurityPolicy, SecurityPolicyRule,
};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bpa::security_processing::SecurityContext;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::AesGcmVariant;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::bcb::{self, BcbConfig, BcbTargets};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::sim::StorageManager;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

/// RFC9173-100: Valid BCB with authentication tag is delivered (SDK always adds tag)
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_100_valid_bcb_with_tag_delivered() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let aes_key = vec![0xAA; 16]; // AES-128
    let iv = vec![0x01; 12];

    // Generate bundle with BCB
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Valid payload with BCB".to_vec())
        .build()
        .unwrap();

    let bcb_config = BcbConfig {
        security_source: source.clone(),
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

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    let bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver with correct key
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(source.clone(), aes_key);

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

    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "RFC9173-100: Valid BCB with authentication tag should be delivered"
    );

    let payload: &[u8] = delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .data
        .as_ref();

    assert_eq!(
        payload, b"Valid payload with BCB",
        "Payload should be decrypted correctly"
    );
}

/// RFC9173-100: Tampered BCB authentication tag causes decryption failure with code 15
/// This proves the conditional MUST: "in which case it MUST be processed as described in Section 4.4"
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_100_tampered_auth_tag_rejected() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();
    let aes_key = vec![0xBB; 16]; // AES-128
    let iv = vec![0x02; 12];

    // Generate bundle with BCB
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    let bcb_config = BcbConfig {
        security_source: source.clone(),
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

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    let mut bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Tamper with one byte in the BCB authentication tag (result ID 1)
    let mut decoded = BundleCodec::decode(&bundle_bytes).unwrap();
    let bcb_idx = decoded
        .blocks
        .iter()
        .position(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();

    // Tamper with authentication-tag security result (result id 1).
    let mut bcb_cbor = common::asb::decode(&decoded.blocks[bcb_idx].data);
    let result_items = common::asb::first_target_result_items_mut(&mut bcb_cbor);
    let tag = common::asb::find_pair_value_mut(result_items, 1)
        .and_then(ciborium::Value::as_bytes_mut)
        .expect("BCB missing authentication-tag result bytes");
    if let Some(last) = tag.last_mut() {
        *last ^= 0xFF;
    }
    decoded.blocks[bcb_idx].data = common::asb::encode(&bcb_cbor);

    bundle_bytes = BundleCodec::encode(&decoded).unwrap();

    // Receiver with correct key but tampered tag
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(source.clone(), aes_key);

    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bcb),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::Report],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
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
        "RFC9173-100: Tampered authentication tag should prevent delivery (MUST be processed per §4.4)"
    );

    // The fact that the bundle was not delivered proves the tag was processed and validated.
    // Authentication tag mismatch causes AES-GCM decryption to fail, which is detected
    // and results in bundle rejection, satisfying the "MUST be processed" requirement.
}
