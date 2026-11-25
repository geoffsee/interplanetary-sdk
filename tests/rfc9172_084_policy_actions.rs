//! RFC 9172 §5.1.1 & §5.1.2: Security Policy-Driven Processing Tests
//!
//! These tests prove that security policy actions (DeleteBundle, RemoveTarget, Report)
//! actually drive observable behavior via the production path (receive_bytes_from_cla + poll).
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
use interplanetary_sdk::bpa::security_processing::SecurityContext;
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::sim::StorageManager;
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

/// RFC9172-084: Missing BCB with DeleteBundle policy -> nothing delivered, no forwarding
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_084_delete_bundle_action() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle WITHOUT required BCB
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Policy: DeleteBundle when BCB missing on payload
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

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    // RFC9172-084: DeleteBundle action -> receive fails
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(
        result.is_err(),
        "RFC 9172 §5.1.1: DeleteBundle action must reject bundle"
    );

    // Verify: nothing delivered, nothing in storage
    agent.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(agent.delivered_adus().len(), 0);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

/// RFC9172-084: Missing BCB with Report policy -> status report with reason code 12
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_084_report_action() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    // Bundle WITHOUT required BCB, with report-to EID
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Policy: Report when BCB missing on payload
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
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::all(
            report_to.clone(),
        ),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    // RFC9172-084: Report action -> bundle rejected but report generated
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(result.is_err(), "Bundle must be rejected");

    // Poll to generate reports
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify: status report generated with reason code 12 (Missing security operation)
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1, "One status report must be generated");

    // RFC 9172 §11.2: Verify reason code 12 (Missing security operation)
    let report = &reports[0];
    assert_eq!(
        report.reason_code as u8, 12,
        "Reason code must be 12 (MissingSecurityOperation) per RFC 9172 §11.2"
    );
    assert!(report.deleted.asserted, "Deleted flag must be set");
}

/// RFC9172-098: Missing BIB with DeleteBundle policy -> nothing delivered
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_098_delete_bundle_action() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle WITHOUT required BIB
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(5000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Policy: DeleteBundle when BIB missing on payload
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

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    // RFC9172-098: DeleteBundle action -> receive fails
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(
        result.is_err(),
        "RFC 9172 §5.1.2: DeleteBundle action must reject bundle"
    );

    agent.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(agent.delivered_adus().len(), 0);
}

/// RFC9172-098: Missing BIB with Report policy -> status report generated
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_098_report_action() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    // Bundle WITHOUT required BIB
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(6000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Policy: Report when BIB missing on payload
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bib),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::Report],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::all(
            report_to.clone(),
        ),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    // RFC9172-098: Report action -> bundle rejected but report generated
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(result.is_err(), "Bundle must be rejected");

    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify: status report generated with reason code 12 (Missing security operation)
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1, "One status report must be generated");

    // RFC 9172 §11.2: Verify reason code 12 (Missing security operation)
    let report = &reports[0];
    assert_eq!(
        report.reason_code as u8, 12,
        "Reason code must be 12 (MissingSecurityOperation) per RFC 9172 §11.2"
    );
    assert!(report.deleted.asserted, "Deleted flag must be set");
}

/// RFC9172-098: Missing BIB with RemoveTarget on non-payload -> bundle delivered
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_098_remove_nonpayload_target() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle with PreviousNode extension block but no BIB protecting it
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(7000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    // Add PreviousNode block
    use interplanetary_sdk::bp::extensions::PreviousNodeBlock;
    let prev_node_block = PreviousNodeBlock::new(2, source.clone());
    bundle
        .blocks
        .insert(0, prev_node_block.to_canonical().unwrap());

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Policy: RemoveTarget when BIB missing on PreviousNode block
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::PreviousNode),
        required_operation: Some(SecurityOperation::Bib),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::RemoveTarget],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    // RemoveTarget on non-payload -> bundle accepted, block removed
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(result.is_ok(), "Bundle must be accepted");

    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify: bundle delivered with PreviousNode block removed
    let delivered_bundles = agent.delivered_adus();
    assert_eq!(delivered_bundles.len(), 1, "Bundle must be delivered");

    let delivered_bundle = &delivered_bundles[0];
    let has_prev_node = delivered_bundle
        .blocks
        .iter()
        .any(|b| b.block_type == BlockType::PreviousNode);
    assert!(!has_prev_node, "PreviousNode block must be removed");
}

/// Verify SecurityFailureReason uses correct registry values per RFC 9172 §11.2
#[test]
#[cfg(feature = "bpsec-default")]
fn test_security_failure_reason_registry_values() {
    use interplanetary_sdk::bpa::security_policy::SecurityFailureReason;

    // RFC 9172 §11.2: Bundle Status Report Reason Codes
    // These values MUST match the IANA registry exactly
    assert_eq!(SecurityFailureReason::MissingSecurityOperation as u8, 12);
    assert_eq!(SecurityFailureReason::UnknownSecurityOperation as u8, 13);
    assert_eq!(SecurityFailureReason::UnexpectedSecurityOperation as u8, 14);
    assert_eq!(SecurityFailureReason::FailedSecurityOperation as u8, 15);
    assert_eq!(
        SecurityFailureReason::ConflictingSecurityOperation as u8,
        16
    );

    // RFC 9171 §6.1.1 uses code 11 for BlockUnsupported
    // RFC 9172 codes start at 12 to avoid conflict
}

/// RFC9172-086: RemoveTarget on payload -> bundle discarded
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_086_remove_payload_target() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Policy: RemoveTarget when BCB missing on payload
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: Some(SecurityOperation::Bcb),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::RemoveTarget],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    // RFC9172-086: RemoveTarget on payload -> bundle MUST be discarded
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(
        result.is_err(),
        "RFC 9172 §5.1.1: Bundle with removed payload MUST be discarded"
    );

    agent.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(agent.delivered_adus().len(), 0, "Nothing delivered");
}

/// RFC9172: RemoveTarget on non-payload extension block -> bundle kept, block removed
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_remove_nonpayload_target() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle with PreviousNode extension block (block type 6)
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(4000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    // Add PreviousNode block
    use interplanetary_sdk::bp::extensions::PreviousNodeBlock;
    let prev_node_block = PreviousNodeBlock::new(2, source.clone());
    bundle
        .blocks
        .insert(0, prev_node_block.to_canonical().unwrap());

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Policy: RemoveTarget when BCB missing on PreviousNode block
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::PreviousNode),
        required_operation: Some(SecurityOperation::Bcb),
        forbidden_operation: None,
        failure_actions: vec![SecurityAction::RemoveTarget],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    // RemoveTarget on non-payload -> bundle accepted, block removed
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(result.is_ok(), "Bundle must be accepted");

    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify: bundle delivered
    let delivered_bundles = agent.delivered_adus();
    assert_eq!(delivered_bundles.len(), 1, "Bundle must be delivered");

    // Verify: PreviousNode block was removed
    let delivered_bundle = &delivered_bundles[0];
    let has_prev_node = delivered_bundle
        .blocks
        .iter()
        .any(|b| b.block_type == BlockType::PreviousNode);
    assert!(!has_prev_node, "PreviousNode block must be removed");
}

/// Test failed BIB verification generates report with reason code 15
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_failed_bib_verification_report_code_15() {
    use interplanetary_sdk::security::HmacVariant;
    use interplanetary_sdk::security::bib::{BibConfig, BibTargets};

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let security_source = EndpointId::ipn(0, 1, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    // Create bundle
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(8000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    // Generate BIB with specific key
    let sender_key = vec![0x01; 32];
    let payload_block_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;

    let bib_config = BibConfig {
        security_source: security_source.clone(),
        targets: BibTargets {
            block_numbers: vec![payload_block_num],
        },
        sha_variant: HmacVariant::Sha256,
        key: sender_key.clone(),
        wrapped_key: None,
        scope_flags: 0,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = interplanetary_sdk::security::bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Configure agent with WRONG key (verification will fail)
    let mut sec_ctx = SecurityContext::new();
    let wrong_key = vec![0xFF; 32];
    sec_ctx.add_hmac_key(security_source.clone(), wrong_key);
    sec_ctx.set_bib_failure_policy(
        interplanetary_sdk::bpa::security_processing::SecurityFailurePolicy::DeleteBundle,
    );

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::all(
            report_to.clone(),
        ),
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

    // BIB verification fails, bundle deleted
    let result = agent.receive_bytes_from_cla(&bundle_bytes);
    assert!(
        result.is_err(),
        "Bundle must be rejected due to BIB verification failure"
    );

    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify: status report generated with reason code 15 (Failed security operation)
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1, "One status report must be generated");

    let report = &reports[0];
    assert_eq!(
        report.reason_code as u8, 15,
        "Reason code must be 15 (FailedSecurityOperation) per RFC 9172 §11.2"
    );
    assert!(report.deleted.asserted, "Deleted flag must be set");
}
