//! RFC 9172 §5, §8 Security Policy Enforcement Tests
//!
//! Tests for required security operations and missing security operation detection
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::SimInstant;
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bp::{BlockType, BundleBuilder};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bpa::security_policy::{
    SecurityAction, SecurityOperation, SecurityPolicy, SecurityPolicyRule,
};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bpa::security_processing::{SecurityContext, SecurityFailurePolicy};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::security::HmacVariant;
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::security::bib::{self, BibConfig, BibTargets};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::sim::StorageManager;
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

/// RFC9172-084: If security policy specifies that a node should have applied confidentiality
/// to a specific security target and no such BCB is present, follow policy actions.
///
/// RFC 9172 §5.1.1: "If the security policy of a node specifies that a node should have applied
/// confidentiality to a specific security target and no such BCB is present in the bundle,
/// then the node MUST process this security target in accordance with the security policy."
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_084_missing_required_bcb() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Create bundle WITHOUT BCB (no confidentiality protection)
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Sensitive data".to_vec())
        .build()
        .unwrap();

    // Create receiver with policy requiring BCB for payload
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bcb),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::DeleteBundle],
    });

    let mut sec_ctx = SecurityContext::new();
    sec_ctx.set_bcb_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
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

    // RFC9172-084: Bundle should be rejected due to missing required BCB
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "RFC 9172 §5: Bundle with missing required BCB MUST be rejected per security policy"
    );

    // Verify bundle was not delivered
    agent.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Bundle without required BCB must not be delivered"
    );
}

/// RFC9172-098: If security policy specifies that a node should have applied integrity
/// to a specific security target and no such BIB is present, follow policy actions.
///
/// RFC 9172 §5.1.2: "If the security policy of a node specifies that a node should have applied
/// integrity to a specific security target and no such BIB is present in the bundle, then
/// the node MUST process this security target in accordance with the security policy."
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_098_missing_required_bib() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Create bundle WITHOUT BIB (no integrity protection)
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 1))
        .lifetime(60_000)
        .payload(b"Important data".to_vec())
        .build()
        .unwrap();

    // Create receiver with policy requiring BIB for payload
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bib),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::DeleteBundle],
    });

    let mut sec_ctx = SecurityContext::new();
    sec_ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
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

    // RFC9172-098: Bundle should be rejected due to missing required BIB
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "RFC 9172 §5: Bundle with missing required BIB MUST be rejected per security policy"
    );

    // Verify bundle was not delivered
    agent.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Bundle without required BIB must not be delivered"
    );
}

/// RFC9172-098: Bundle with required BIB present should be accepted
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_098_required_bib_present() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let hmac_key = vec![0xAB; 32];

    // Create bundle WITH BIB (integrity protection present)
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3000), 1))
        .lifetime(60_000)
        .payload(b"Important data".to_vec())
        .build()
        .unwrap();

    // Add BIB protecting payload
    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1], // Payload block
        },
        sha_variant: HmacVariant::Sha256,
        key: hmac_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };
    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Create receiver with policy requiring BIB for payload
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bib),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::DeleteBundle],
    });

    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), hmac_key);
    sec_ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
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

    // RFC9172-098: Bundle with required BIB should be accepted
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_ok(),
        "Bundle with required BIB should be accepted"
    );

    // Verify bundle was delivered
    agent.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(
        agent.delivered_adus().len(),
        1,
        "Bundle with required BIB should be delivered"
    );
}

/// RFC9172-086: If the removed security target is the payload block, the bundle MUST be discarded.
///
/// This tests the case where BIB verification fails and the target is payload.
#[test]
#[cfg(feature = "bpsec-default")]
fn test_failed_bib_verification_on_payload_discards_bundle() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let correct_key = vec![0xAB; 32];
    let wrong_key = vec![0xCD; 32];

    // Create bundle with BIB (using correct key)
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(4000), 1))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: correct_key,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };
    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Create receiver with wrong key (verification will fail)
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), wrong_key); // Wrong key!
    sec_ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
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

    // RFC9172-086: Bundle with failed BIB on payload MUST be discarded
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "RFC 9172 §5.1.1: Bundle with failed BIB verification MUST be deleted per policy"
    );

    // Verify bundle was not delivered
    agent.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "RFC9172-086: Bundle with failed BIB on payload block MUST be discarded"
    );
}
