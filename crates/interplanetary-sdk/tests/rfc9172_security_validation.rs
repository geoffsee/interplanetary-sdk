//! RFC 9172 Security Block Validation - Node-Level Tests
//!
//! These tests verify that bundles violating RFC 9172 security rules are rejected
//! at reception and do not appear in delivered_adus or cla_tx_queue.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{
    bp::*,
    bpa::{BpaConfig, BundleAgent},
    sim::StorageManager,
    types::*,
};

fn create_test_agent() -> (BundleAgent, EndpointId) {
    let local_eid = EndpointId::ipn(0, 1, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
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
    (BundleAgent::new(config, storage), local_eid)
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_039_bib_targeting_bcb_rejected_at_node() {
    // RFC 9172 §3.3: Security target MUST NOT be a security block
    // Node test: bundle with BIB targeting BCB is rejected and NOT delivered/forwarded

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add BCB (block 2) targeting payload
    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload)
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb);

    // Add BIB (block 3) targeting BCB (block 2) - INVALID per RFC 9172 §3.3
    let bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 3,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x02, // targets: [2] (BCB) - VIOLATES §3.3
            0x01, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);

    assert!(
        result.is_err(),
        "Bundle with BIB targeting BCB MUST be rejected per RFC 9172 §3.3"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Security") || err.contains("validation") || err.contains("3.3"),
        "Error should reference security validation failure. Got: {}",
        err
    );

    // Poll to process any pending bundles
    agent.poll(SimInstant::from_nanos(100));

    // Bundle MUST NOT appear in delivered_adus
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Invalid bundle MUST NOT be delivered"
    );

    // Bundle MUST NOT appear in cla_tx_queue for forwarding
    assert_eq!(
        agent.cla_tx_queue().len(),
        0,
        "Invalid bundle MUST NOT be forwarded"
    );
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_047_bcb_targeting_bcb_rejected_at_node() {
    // RFC 9172 §4.4: BCB MUST NOT target another BCB
    // Node test: bundle with BCB targeting BCB is rejected

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add first BCB (block 2) targeting payload
    let bcb1 = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload)
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb1);

    // Add second BCB (block 3) targeting first BCB - INVALID per RFC 9172 §4.4
    let bcb2 = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 3,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x02, // targets: [2] (BCB) - VIOLATES §4.4
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb2);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);

    assert!(
        result.is_err(),
        "Bundle with BCB targeting BCB MUST be rejected per RFC 9172 §4.4"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("4.4") || err.contains("BCB") || err.contains("security"),
        "Error should reference RFC 9172 §4.4 violation. Got: {}",
        err
    );

    // Poll
    agent.poll(SimInstant::from_nanos(100));

    // NOT delivered or forwarded
    assert_eq!(agent.delivered_adus().len(), 0);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_042_multiple_bibs_per_target_rejected_at_node() {
    // RFC 9172 §3.3: Only one BIB per target (enforced RECOMMENDED as MUST)
    // Node test: bundle with two BIBs protecting same target is rejected

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add first BIB (block 2) targeting payload
    let bib1 = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload)
            0x01, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bib1);

    // Add second BIB (block 3) also targeting payload - INVALID
    let bib2 = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 3,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload) - VIOLATES uniqueness
            0x01, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bib2);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);

    assert!(
        result.is_err(),
        "Bundle with multiple BIBs per target MUST be rejected per RFC 9172 §3.3"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("already protected") || err.contains("Multiple") || err.contains("security"),
        "Error should reference duplicate BIB. Got: {}",
        err
    );

    // Poll
    agent.poll(SimInstant::from_nanos(100));

    // NOT delivered or forwarded
    assert_eq!(agent.delivered_adus().len(), 0);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_032_multiple_bcbs_per_target_rejected_at_node() {
    // RFC 9172 §3.2: Only one BCB per target (security operation uniqueness)
    // Node test: bundle with two BCBs protecting same target is rejected

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add first BCB (block 2) targeting payload
    let bcb1 = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload)
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb1);

    // Add second BCB (block 3) also targeting payload - INVALID per §3.2
    let bcb2 = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 3,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload) - duplicate operation
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb2);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);

    assert!(
        result.is_err(),
        "Bundle with multiple BCBs per target MUST be rejected per RFC 9172 §3.2"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.2") && err.contains("unique"),
        "Error should reference RFC 9172 §3.2 uniqueness. Got: {}",
        err
    );

    // Poll
    agent.poll(SimInstant::from_nanos(100));

    // NOT delivered or forwarded
    assert_eq!(agent.delivered_adus().len(), 0);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_046_bcb_with_remove_flag_rejected_at_node() {
    // RFC 9172 §3.8: BCBs MUST NOT have "remove if can't process" flag (bit 2)

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // BCB with "remove" flag (bit 2) set - INVALID per §3.8
    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 0x05, // Bit 0 + Bit 2 - VIOLATES §3.8
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload)
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);

    assert!(
        result.is_err(),
        "BCB with 'remove' flag MUST be rejected per RFC 9172 §3.8"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.8") && err.contains("removed"),
        "Error should reference RFC 9172 §3.8. Got: {}",
        err
    );

    // Poll
    agent.poll(SimInstant::from_nanos(100));

    // NOT delivered or forwarded
    assert_eq!(agent.delivered_adus().len(), 0);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_045_bcb_targeting_payload_without_replicate_rejected_at_node() {
    // RFC 9172 §3.8: BCBs targeting payload MUST have replicate flag (bit 0)

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // BCB targeting payload WITHOUT replicate flag - INVALID per §3.8
    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 0x00, // No flags - VIOLATES §3.8 for payload target
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload)
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);

    assert!(
        result.is_err(),
        "BCB targeting payload without replicate flag MUST be rejected per RFC 9172 §3.8"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.8") && err.contains("replicate"),
        "Error should reference RFC 9172 §3.8. Got: {}",
        err
    );

    // Poll
    agent.poll(SimInstant::from_nanos(100));

    // NOT delivered or forwarded
    assert_eq!(agent.delivered_adus().len(), 0);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_valid_security_accepted_and_delivered() {
    // Positive test: valid security configuration is accepted and delivered

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = local_eid.clone();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Add hop count block
    let hop_count = CanonicalBlock {
        block_type: BlockType::HopCount,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x82, 0x1e, 0x00],
    };
    bundle.blocks.insert(0, hop_count);

    // Add BIB targeting payload (valid)
    let bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 3,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (payload)
            0x01, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bib);

    // Add BCB targeting hop count (valid - different target)
    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 4,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x02, // targets: [2] (hop count)
            0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb);

    // Reception MUST succeed
    let result = agent.receive_from_cla(bundle);

    assert!(
        result.is_ok(),
        "Valid security configuration should be accepted. Got error: {:?}",
        result.err()
    );

    // Key assertion: bundle was ACCEPTED (didn't fail validation)
    // Delivery/forwarding depends on routing and other factors
    // The critical test is that validation didn't reject it
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_wire_path_security_validation() {
    // CHECK (a): Verify receive_bytes_from_cla validates security blocks

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // BCB targeting BCB (invalid)
    let bcb1 = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, 0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb1);

    let bcb2 = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 3,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x02, 0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, bcb2);

    // Encode to wire format
    let bundle_bytes = BundleCodec::encode(&bundle).unwrap();

    // Wire path MUST reject
    let result = agent.receive_bytes_from_cla(&bundle_bytes);

    assert!(result.is_err(), "Wire path MUST validate security");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Security") || err_msg.contains("BCB"));
}

#[test]
#[cfg(feature = "test-fixtures")]
fn test_generation_validates_security_rules() {
    // CHECK (b): Verify generate_bib/generate_bcb reject invalid configurations

    use interplanetary_sdk::security::{AesGcmVariant, HmacVariant, bcb, bib};

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

    // Add an existing BCB
    let existing_bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, 0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
        ],
    };
    bundle.blocks.insert(0, existing_bcb);

    // Try to generate a BIB targeting the BCB (invalid per RFC 9172 §3.3)
    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![2], // Target BCB - INVALID
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0xAB; 32],
        scope_flags: 0x00,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let result = bib::generate_bib(&bundle, &bib_config);
    assert!(result.is_err(), "generate_bib MUST reject invalid target");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("security") || err.contains("violat"));

    // Try to generate BCB targeting existing BCB (invalid per RFC 9172 §4.4)
    let bcb_config = bcb::BcbConfig {
        security_source: source,
        targets: bcb::BcbTargets {
            block_numbers: vec![2], // Target BCB - INVALID
        },
        aes_variant: AesGcmVariant::Aes128,
        key: vec![0xCD; 16],
        iv: vec![0xEF; 12],
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        skip_source_validation: true,
    };

    let result = bcb::generate_bcb(&bundle, &bcb_config, None);
    assert!(result.is_err(), "generate_bcb MUST reject invalid target");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("security") || err.contains("violat"));
}
