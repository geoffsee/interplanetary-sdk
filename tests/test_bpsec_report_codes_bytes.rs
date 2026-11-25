//! RFC 9172 §11.2: BPSec Status Report Reason Code Tests
//!
//! These tests verify that BPSec security failures generate status reports
//! with the correct reason codes per RFC 9172 §11.2, by decoding actual
//! report bundle bytes (not internal structs).
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::SimInstant;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bp::{BlockType, BundleBuilder};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bpa::security_policy::{
    SecurityAction, SecurityOperation, SecurityPolicy, SecurityPolicyRule,
};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bpa::security_processing::SecurityContext;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::HmacVariant;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::bib::{BibConfig, BibTargets};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::sim::StorageManager;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

/// Helper to decode reason code from report bundle bytes
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn decode_reason_code_from_bundle_bytes(bundle_bytes: &[u8]) -> u8 {
    use interplanetary_sdk::bp::codec::BundleCodec;

    let bundle = BundleCodec::decode(bundle_bytes).unwrap();
    let payload_data = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .data
        .as_ref();

    let (report, _) = interplanetary_sdk::bpa::admin::decode_status_report(payload_data).unwrap();
    report.reason_code as u8
}

/// RFC 9172 §11.2 Code 12: Missing security operation
/// Test decodes report bundle BYTES to verify reason code
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_code_12_missing_security_operation_from_bytes() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

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

    let _ = agent.receive_bytes_from_cla(&bundle_bytes);
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Encode report to bundle and verify reason code from BYTES
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    let report_bundle = interplanetary_sdk::bpa::admin::create_status_report_bundle(
        reports[0].clone(),
        &dest,
        &report_to,
        SimInstant::from_nanos(100_000_000),
        1,
        false,
    )
    .unwrap();

    let report_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&report_bundle).unwrap();
    let reason_code = decode_reason_code_from_bundle_bytes(&report_bytes);

    assert_eq!(
        reason_code, 12,
        "RFC 9172 §11.2: Missing security operation must report code 12"
    );
}

/// RFC 9172 §11.2 Code 15: Failed security operation
/// Test decodes report bundle BYTES to verify reason code
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_code_15_failed_security_operation_from_bytes() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    // Generate BIB with one key
    let sender_key = vec![0x01; 32];
    let payload_block_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![payload_block_num],
        },
        sha_variant: HmacVariant::Sha256,
        key: sender_key,
        wrapped_key: None,
        scope_flags: 0,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = interplanetary_sdk::security::bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Configure agent with WRONG key (verification fails)
    let mut sec_ctx = SecurityContext::new();
    let wrong_key = vec![0xFF; 32];
    sec_ctx.add_hmac_key(source.clone(), wrong_key);
    sec_ctx.set_bib_failure_policy(
        interplanetary_sdk::bpa::security_processing::SecurityFailurePolicy::DeleteBundle,
    );

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: false,
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

    let _ = agent.receive_bytes_from_cla(&bundle_bytes);
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Encode report to bundle and verify reason code from BYTES
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    let report_bundle = interplanetary_sdk::bpa::admin::create_status_report_bundle(
        reports[0].clone(),
        &dest,
        &report_to,
        SimInstant::from_nanos(100_000_000),
        1,
        false,
    )
    .unwrap();

    let report_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&report_bundle).unwrap();
    let reason_code = decode_reason_code_from_bundle_bytes(&report_bytes);

    assert_eq!(
        reason_code, 15,
        "RFC 9172 §11.2: Failed security operation must report code 15"
    );
}

/// RFC 9172 §11.2 Code 14: Unexpected security operation (forbidden by policy)
/// Test decodes report bundle BYTES to verify reason code
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_code_14_forbidden_security_operation_from_bytes() {
    use interplanetary_sdk::security::HmacVariant;
    use interplanetary_sdk::security::bib::{BibConfig, BibTargets};

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    // Create bundle with BIB on payload
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(4000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000;

    let payload_block_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![payload_block_num],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0x01; 32],
        wrapped_key: None,
        scope_flags: 0,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = interplanetary_sdk::security::bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Configure policy that EXPLICITLY FORBIDS BIB on payload
    let mut policy = SecurityPolicy::new();
    policy.add_rule(SecurityPolicyRule {
        source_match: Some(source.clone()),
        destination_match: Some(dest.clone()),
        security_source_match: None,
        target_block_type: Some(BlockType::Payload),
        required_operation: None,
        forbidden_operation: Some(SecurityOperation::Bib), // Explicitly forbid BIB
        failure_actions: vec![SecurityAction::DeleteBundle, SecurityAction::Report],
    });

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: false,
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

    let _ = agent.receive_bytes_from_cla(&bundle_bytes);
    agent.poll(SimInstant::from_nanos(100_000_000));

    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    let report_bundle = interplanetary_sdk::bpa::admin::create_status_report_bundle(
        reports[0].clone(),
        &dest,
        &report_to,
        SimInstant::from_nanos(100_000_000),
        1,
        false,
    )
    .unwrap();

    let report_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&report_bundle).unwrap();
    let reason_code = decode_reason_code_from_bundle_bytes(&report_bytes);

    assert_eq!(
        reason_code, 14,
        "RFC 9172 §11.2: Forbidden security operation must report code 14"
    );

    // Verify bundle was NOT delivered (action was DeleteBundle)
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        0,
        "Bundle with forbidden operation must not be delivered"
    );
}

/// RFC 9172 §11.2 Code 13: Unknown security context
/// Test decodes report bundle BYTES to verify reason code
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_code_13_unknown_security_context_from_bytes() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    // Create bundle with BIB that has an unknown context ID (not 1)
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(5000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000;

    let payload_block_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![payload_block_num],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0x01; 32],
        wrapped_key: None,
        scope_flags: 0,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let mut bib_block =
        interplanetary_sdk::security::bib::generate_bib(&bundle, &bib_config).unwrap();

    // Manually alter the context_id in the BIB block data to an unknown value (99 instead of 1)
    // BIB block-type-specific data: concatenated CBOR items [targets, context_id, flags, source, params, results]
    {
        use ciborium::Value;
        use std::io::Cursor;

        let mut cursor = Cursor::new(bib_block.data.as_slice());

        // Decode all CBOR values
        let targets: Value = ciborium::de::from_reader(&mut cursor).unwrap();
        let _context_id: Value = ciborium::de::from_reader(&mut cursor).unwrap();
        let flags: Value = ciborium::de::from_reader(&mut cursor).unwrap();
        let source: Value = ciborium::de::from_reader(&mut cursor).unwrap();
        let params: Value = ciborium::de::from_reader(&mut cursor).unwrap();
        let results: Value = ciborium::de::from_reader(&mut cursor).unwrap();

        // Re-encode with modified context_id (99 instead of 1)
        let mut new_data = Vec::new();
        ciborium::into_writer(&targets, &mut new_data).unwrap();
        ciborium::into_writer(&Value::Integer(99.into()), &mut new_data).unwrap(); // Unknown context ID
        ciborium::into_writer(&flags, &mut new_data).unwrap();
        ciborium::into_writer(&source, &mut new_data).unwrap();
        ciborium::into_writer(&params, &mut new_data).unwrap();
        ciborium::into_writer(&results, &mut new_data).unwrap();
        bib_block.data = new_data;
    }

    bundle.blocks.insert(0, bib_block);
    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: false,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::all(
            report_to.clone(),
        ),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    let report_bundle = interplanetary_sdk::bpa::admin::create_status_report_bundle(
        reports[0].clone(),
        &dest,
        &report_to,
        SimInstant::from_nanos(100_000_000),
        1,
        false,
    )
    .unwrap();

    let report_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&report_bundle).unwrap();
    let reason_code = decode_reason_code_from_bundle_bytes(&report_bytes);

    assert_eq!(
        reason_code, 13,
        "RFC 9172 §11.2: Unknown security context must report code 13"
    );
}

/// RFC 9172 §11.2 Code 16: Conflicting security operation
/// Test decodes report bundle BYTES to verify reason code
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_code_16_conflicting_security_operation_from_bytes() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(6000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();
    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000;

    let payload_block_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![payload_block_num],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0x01; 32],
        wrapped_key: None,
        scope_flags: 0,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    // Add TWO BIBs for the same target (conflicting operations)
    let mut bib_block_1 =
        interplanetary_sdk::security::bib::generate_bib(&bundle, &bib_config).unwrap();
    let mut bib_block_2 =
        interplanetary_sdk::security::bib::generate_bib(&bundle, &bib_config).unwrap();

    // Assign different block numbers to avoid them being seen as duplicates
    bib_block_1.block_number = 100;
    bib_block_2.block_number = 101;

    // Insert BIBs before the payload (payload must remain last per RFC 9171 §4.1)
    bundle.blocks.insert(0, bib_block_1);
    bundle.blocks.insert(1, bib_block_2);
    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: false,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::all(
            report_to.clone(),
        ),
        cla_mtu: None,
        security_context: Some(SecurityContext::new()),
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

    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    let report_bundle = interplanetary_sdk::bpa::admin::create_status_report_bundle(
        reports[0].clone(),
        &dest,
        &report_to,
        SimInstant::from_nanos(100_000_000),
        1,
        false,
    )
    .unwrap();

    let report_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&report_bundle).unwrap();
    let reason_code = decode_reason_code_from_bundle_bytes(&report_bytes);

    assert_eq!(
        reason_code, 16,
        "RFC 9172 §11.2: Conflicting security operations must report code 16"
    );
}

/// RFC 9172 §11.2 Code 14: Verify NEGATIVE case
/// Valid secured bundle with no matching policy MUST be delivered (not rejected)
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_code_14_valid_secured_bundle_no_policy_delivered() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(7000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    let payload_block_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![payload_block_num],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0x01; 32],
        wrapped_key: None,
        scope_flags: 0,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = interplanetary_sdk::security::bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);
    let bundle_bytes = interplanetary_sdk::bp::codec::BundleCodec::encode(&bundle).unwrap();

    // Configure agent with NO security policy (no rules)
    let policy = SecurityPolicy::new(); // Empty policy with no rules

    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), vec![0x01; 32]);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true, // Enable delivery to verify bundle is accepted
        status_report_policy: Default::default(),
        cla_mtu: None,
        security_context: Some(sec_ctx),
        security_policy: Some(policy), // Policy with no rules (doesn't forbid anything)
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

    // Verify bundle was delivered (not rejected with code 14)
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "RFC 9172 §11.2: Valid secured bundle with no policy rule must be delivered (not rejected with code 14)"
    );

    // Verify NO report was generated (bundle was accepted)
    let reports = agent.generated_reports();
    assert_eq!(
        reports.len(),
        0,
        "No code 14 report should be generated for valid bundle with no matching policy rule"
    );
}
