//! RFC 9172 Node-Level Behavioral Tests
//!
//! Tests drive BundleAgent through receive_from_cla() and assert observable outcomes:
//! - delivered_adus (successful delivery)
//! - cla_tx_queue (forwarded bundles)
//! - generated_reports (status reports)
//! - bundle deletion (security policy enforcement)
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::{BlockType, BundleBuilder};
use interplanetary_sdk::bpa::{
    BpaConfig, BundleAgent, SecurityContext, SecurityFailurePolicy, StatusReportPolicy,
};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant, bcb, bib};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

fn create_test_agent_with_security(
    local_eid: EndpointId,
    security_context: SecurityContext,
) -> BundleAgent {
    let local_node = match local_eid.clone() {
        EndpointId::Ipn {
            allocator, node, ..
        } => NodeId::ipn(allocator, node),
        _ => panic!("Test requires IPN EID"),
    };
    let config = BpaConfig {
        local_node,
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::all(local_eid),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: Some(security_context),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    BundleAgent::new(config, storage)
}

/// RFC9172-077: Receiving node determines if it is security acceptor for BCB
///
/// RFC 9172 §4.4: "If a received bundle contains a BCB, the receiving node MUST
/// determine whether it is the security acceptor for any of the security operations
/// in the BCB."
///
/// Test: Node at destination is BCB acceptor and must attempt decryption
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_077_node_determines_bcb_acceptor_at_destination() {
    let local_eid = EndpointId::ipn(0, 3, 0).unwrap(); // We are destination
    let source = EndpointId::ipn(0, 1, 0).unwrap();

    let mut security_ctx = SecurityContext::new();
    let aes_key = vec![0xAB; 16]; // AES-128 key
    security_ctx.add_aes_key(source.clone(), aes_key.clone());
    security_ctx.set_bcb_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let mut agent = create_test_agent_with_security(local_eid.clone(), security_ctx);

    // Create bundle with BCB protecting payload (block 1)
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(local_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"secret payload".to_vec())
        .build()
        .unwrap();

    // Add BCB using correct key
    let iv = vec![0xCD; 12]; // 96-bit IV for AES-GCM
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1], // payload
        },
        aes_variant: AesGcmVariant::Aes128,
        key: aes_key,
        iv: iv.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
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

    // RFC9172-077: Node determines it is security acceptor (we are destination)
    // BCB processing should succeed, decrypt payload, and deliver
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Bundle should be delivered locally (BCB decryption succeeded)
    agent.deliver_local(&bundle_id).unwrap();
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "BCB acceptor must decrypt and deliver bundle"
    );

    // Verify BCB was removed after processing
    let delivered_bundle = &delivered[0];
    let has_bcb = delivered_bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Bcb));
    assert!(
        !has_bcb,
        "BCB must be removed after successful decryption at acceptor"
    );
}

/// RFC9172-078: BCB acceptor with wrong key fails per security policy
///
/// RFC 9172 §4.4: Receiving node determines acceptor status and processes BCB.
/// If decryption fails, security policy (DeleteBundle) is applied.
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_078_bcb_acceptor_decryption_failure_deletes_bundle() {
    let local_eid = EndpointId::ipn(0, 3, 0).unwrap();
    let source = EndpointId::ipn(0, 1, 0).unwrap();

    let mut security_ctx = SecurityContext::new();
    let wrong_key = vec![0xCD; 16]; // Wrong AES key
    security_ctx.add_aes_key(source.clone(), wrong_key);
    security_ctx.set_bcb_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let mut agent = create_test_agent_with_security(local_eid.clone(), security_ctx);

    // Create bundle with BCB using correct key
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(local_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"secret payload".to_vec())
        .build()
        .unwrap();

    let correct_key = vec![0xAB; 16];
    let iv = vec![0xCD; 12];
    let bcb_config = bcb::BcbConfig {
        security_source: source.clone(),
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key: correct_key,
        iv: iv.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
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

    // RFC9172-078: Decryption fails (wrong key), DeleteBundle policy applied
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle must be rejected when BCB decryption fails with DeleteBundle policy"
    );

    // Verify bundle was not delivered or stored
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Failed BCB decryption must not deliver bundle"
    );
    assert_eq!(
        agent.storage().enumerate().len(),
        0,
        "Bundle must not be stored after BCB decryption failure"
    );
}

/// RFC9172-092: Receiving node determines if it is security acceptor for BIB
///
/// RFC 9172 §4.3: "If a received bundle contains a BIB, the receiving node MUST
/// determine whether it is the security acceptor for any of the security operations
/// in the BIB."
///
/// Test: Node at destination is BIB acceptor and must verify signature
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_092_node_determines_bib_acceptor_at_destination() {
    let local_eid = EndpointId::ipn(0, 3, 0).unwrap(); // We are destination
    let source = EndpointId::ipn(0, 1, 0).unwrap();

    let mut security_ctx = SecurityContext::new();
    let hmac_key = vec![0xAB; 32];
    security_ctx.add_hmac_key(source.clone(), hmac_key.clone());
    security_ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let mut agent = create_test_agent_with_security(local_eid.clone(), security_ctx);

    // Create bundle with BIB protecting payload
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(local_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"authenticated payload".to_vec())
        .build()
        .unwrap();

    // Add BIB using correct key
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // payload
        },
        sha_variant: HmacVariant::Sha256,
        key: hmac_key,
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // RFC9172-092: Node determines it is security acceptor (we are destination)
    // BIB verification should succeed and deliver
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Bundle should be delivered locally (BIB verification succeeded)
    agent.deliver_local(&bundle_id).unwrap();
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "BIB acceptor must verify and deliver bundle"
    );

    // Verify BIB was removed after processing
    let delivered_bundle = &delivered[0];
    let has_bib = delivered_bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Bib));
    assert!(
        !has_bib,
        "BIB must be removed after successful verification at acceptor"
    );
}

/// RFC9172-093: BIB acceptor with wrong key fails per security policy
///
/// RFC 9172 §4.3: Receiving node determines acceptor status and processes BIB.
/// If verification fails, security policy (DeleteBundle) is applied.
#[test]
#[cfg(feature = "test-fixtures")]
fn test_rfc9172_093_bib_acceptor_verification_failure_deletes_bundle() {
    let local_eid = EndpointId::ipn(0, 3, 0).unwrap();
    let source = EndpointId::ipn(0, 1, 0).unwrap();

    let mut security_ctx = SecurityContext::new();
    let wrong_key = vec![0xCD; 32]; // Wrong HMAC key
    security_ctx.add_hmac_key(source.clone(), wrong_key);
    security_ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let mut agent = create_test_agent_with_security(local_eid.clone(), security_ctx);

    // Create bundle with BIB using correct key
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(local_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"authenticated payload".to_vec())
        .build()
        .unwrap();

    let correct_key = vec![0xAB; 32];
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
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

    // RFC9172-093: Verification fails (wrong key), DeleteBundle policy applied
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle must be rejected when BIB verification fails with DeleteBundle policy"
    );

    // Verify bundle was not delivered or stored
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Failed BIB verification must not deliver bundle"
    );
    assert_eq!(
        agent.storage().enumerate().len(),
        0,
        "Bundle must not be stored after BIB verification failure"
    );
}
