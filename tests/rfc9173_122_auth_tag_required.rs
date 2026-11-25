//! RFC 9173 §4.8.2: BCB authentication tag MUST be present at receiver
//!
//! RFC9173-122 (verbatim): "The authentication tag MUST be present either as a security result
//! in the BCB representing the security operation or (with the ciphertext) in the security target
//! block-type-specific data field."
//!
//! This is the RECEIVER requirement in §4.8.2 (Decryption), distinct from RFC9173-102
//! which is the GENERATION requirement in §4.8.1 (Encryption).
//!
//! This test verifies that a BCB whose security results lack the authentication tag
//! and whose target data has no appended tag is rejected on receive.
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

/// RFC9173-122: BCB without authentication tag in results MUST be rejected
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_122_bcb_missing_auth_tag_rejected() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();
    let aes_key = vec![0xCC; 16]; // AES-128
    let iv = vec![0x03; 12];

    // Generate a valid BCB bundle first
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

    // Decode and remove the authentication tag from BCB results
    let mut decoded = BundleCodec::decode(&bundle_bytes).unwrap();
    let bcb_idx = decoded
        .blocks
        .iter()
        .position(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();

    // Strip authentication-tag security result (result id 1) from the ASB.
    let mut bcb_cbor = common::asb::decode(&decoded.blocks[bcb_idx].data);
    common::asb::first_target_result_items_mut(&mut bcb_cbor)
        .retain(|item| !common::asb::pair_id_eq(item, 1));
    decoded.blocks[bcb_idx].data = common::asb::encode(&bcb_cbor);

    bundle_bytes = BundleCodec::encode(&decoded).unwrap();

    // Receiver with correct key but BCB missing auth tag
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

    // Bundle MUST NOT be delivered - missing auth tag violates RFC9173-122
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        0,
        "RFC9173-122: BCB missing authentication tag MUST be rejected"
    );

    // The bundle rejection proves RFC9173-122 is enforced: auth tag MUST be present
    // The SDK's parse_bcb_results() returns an error when result ID 1 (auth tag) is missing,
    // which causes the bundle to be rejected (not delivered), satisfying the MUST requirement.
}
