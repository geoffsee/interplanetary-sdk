//! RFC 9173 §3.8.2: BIB HMAC verification and tamper detection
//!
//! RFC9173-046: "The calculated HMAC output MUST be compared to the expected
//! HMAC output encoded in the security results of the BIB for the security target."
//!
//! RFC9173-047: "If the calculated HMAC and expected HMAC are identical, the
//! verification MUST be considered a success."
//!
//! These tests verify that:
//! 1. Valid BIB-protected bundles are delivered successfully
//! 2. Tampered payload is detected and rejected with status report code 15
//! 3. Tampered BIB signature is detected and rejected with status report code 15
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

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
use interplanetary_sdk::security::HmacVariant;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::bib::{self, BibConfig, BibTargets};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::sim::StorageManager;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

/// Helper to decode reason code from report bundle bytes
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn decode_reason_code_from_bundle_bytes(bundle_bytes: &[u8]) -> u8 {
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

/// RFC9173-046/047: Unmodified BIB-protected bundle is delivered successfully
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_046_047_valid_bib_delivered() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let hmac_key = vec![0xAA; 32]; // 32 bytes for HMAC-SHA256 (strict)

    // Generate bundle with BIB
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Valid payload".to_vec())
        .build()
        .unwrap();

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: hmac_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        #[cfg(feature = "test-fixtures")]
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    let bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Receiver with correct key
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), hmac_key);

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
        "RFC9173-046/047: Valid BIB-protected bundle should be delivered"
    );

    let payload: &[u8] = delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .data
        .as_ref();

    assert_eq!(payload, b"Valid payload", "Payload should match original");
}

/// RFC9173-046/047: Tampered payload byte causes BIB verification failure with code 15
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_046_047_tampered_payload_rejected() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();
    let hmac_key = vec![0xBB; 32]; // 32 bytes for HMAC-SHA256 (strict)

    // Generate bundle with BIB
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Original payload".to_vec())
        .build()
        .unwrap();

    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: hmac_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        #[cfg(feature = "test-fixtures")]
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    let mut bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Tamper with one byte in the payload
    // Find the payload block in the encoded bytes and flip one byte
    let mut decoded = BundleCodec::decode(&bundle_bytes).unwrap();
    let payload_idx = decoded
        .blocks
        .iter()
        .position(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();

    if !decoded.blocks[payload_idx].data.is_empty() {
        decoded.blocks[payload_idx].data[0] ^= 0xFF; // Flip first byte
    }

    bundle_bytes = BundleCodec::encode(&decoded).unwrap();

    // Receiver with correct key but tampered bundle
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), hmac_key);

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
        "RFC9173-046: Tampered payload should not be delivered"
    );

    // Should generate status report with code 15 (Failed security operation)
    let reports = agent.generated_reports();
    assert!(!reports.is_empty(), "Should generate status report");

    let report_bundle = interplanetary_sdk::bpa::admin::create_status_report_bundle(
        reports[0].clone(),
        &dest,
        &report_to,
        SimInstant::from_nanos(100_000_000),
        1,
        false,
    )
    .unwrap();

    let report_bytes = BundleCodec::encode(&report_bundle).unwrap();
    let reason_code = decode_reason_code_from_bundle_bytes(&report_bytes);

    assert_eq!(
        reason_code, 15,
        "RFC9173-046: Tampered payload should generate reason code 15 (Failed security operation)"
    );
}

/// RFC9173-046/047: Tampered BIB signature byte causes verification failure with code 15
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_046_047_tampered_bib_rejected() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let report_to = EndpointId::ipn(0, 3, 0).unwrap();
    let hmac_key = vec![0xCC; 32]; // 32 bytes for HMAC-SHA256 (strict)

    // Generate bundle with BIB
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Original payload".to_vec())
        .build()
        .unwrap();

    bundle.primary.report_to = report_to.clone();
    bundle.primary.bundle_flags |= 0x040000; // REQUEST_REPORT_DELETION

    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: hmac_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        #[cfg(feature = "test-fixtures")]
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    let mut bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Tamper with one byte in the BIB result (HMAC signature)
    let mut decoded = BundleCodec::decode(&bundle_bytes).unwrap();
    let bib_idx = decoded
        .blocks
        .iter()
        .position(|b| matches!(b.block_type, BlockType::Bib))
        .unwrap();

    // The BIB block data contains CBOR-encoded security results
    // Flip a byte in the BIB block data to corrupt the HMAC
    if !decoded.blocks[bib_idx].data.is_empty() {
        let len = decoded.blocks[bib_idx].data.len();
        decoded.blocks[bib_idx].data[len - 1] ^= 0xFF; // Flip last byte of HMAC
    }

    bundle_bytes = BundleCodec::encode(&decoded).unwrap();

    // Receiver with correct key but tampered BIB
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), hmac_key);

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
        "RFC9173-046: Tampered BIB signature should not be delivered"
    );

    // Should generate status report with code 15 (Failed security operation)
    let reports = agent.generated_reports();
    assert!(!reports.is_empty(), "Should generate status report");

    let report_bundle = interplanetary_sdk::bpa::admin::create_status_report_bundle(
        reports[0].clone(),
        &dest,
        &report_to,
        SimInstant::from_nanos(100_000_000),
        1,
        false,
    )
    .unwrap();

    let report_bytes = BundleCodec::encode(&report_bundle).unwrap();
    let reason_code = decode_reason_code_from_bundle_bytes(&report_bytes);

    assert_eq!(
        reason_code, 15,
        "RFC9173-046: Tampered BIB signature should generate reason code 15 (Failed security operation)"
    );
}
