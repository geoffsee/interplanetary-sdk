//! RFC 9172 §5.1 Node-Level Security Processing Tests
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bp::{BlockType, BundleBuilder};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bpa::security_processing::{SecurityContext, SecurityFailurePolicy};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::security::bcb::{self, BcbConfig, BcbTargets};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::security::bib::{self, BibConfig, BibTargets};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::sim::{BundleStore, StorageManager};
#[cfg(feature = "bpsec-default")]
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

/// RFC9172-076: When BIBs and BCBs share a security target, BCBs MUST be evaluated first and BIBs second.
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_076_bcb_evaluated_before_bib_on_shared_target() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let original_payload = b"Test payload".to_vec();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(original_payload.clone())
        .build()
        .unwrap();

    // Keys
    let aes_key = vec![0x01; 32];
    let hmac_key = vec![0x02; 32];
    let iv = vec![0xAB; 12];

    // Step 1: Add BIB (protects plaintext payload at block 1)
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
    let mut bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bib_block.block_number = 3;
    bundle.blocks.insert(0, bib_block);

    // Step 2: Per RFC 9172 §3.9, when BCB targets match a BIB's targets the BIB
    // MUST also be encrypted. Erratum 7002: one target per BCB — encrypt BIB first,
    // then payload (each with its own IV).
    let bcb_bib_config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![3], // encrypt the BIB
        },
        aes_variant: AesGcmVariant::Aes256,
        key: aes_key.clone(),
        iv: vec![0xCD; 12],
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
    };
    let (mut bcb_for_bib, bib_cts) = bcb::generate_bcb(&bundle, &bcb_bib_config, None).unwrap();
    bcb_for_bib.block_number = 4;
    if let Some(b) = bundle.blocks.iter_mut().find(|b| b.block_number == 3) {
        b.data = bib_cts[0].clone();
    }
    bundle.blocks.insert(0, bcb_for_bib);

    let bcb_payload_config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes256,
        key: aes_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
    };
    let (mut bcb_block, ciphertexts) =
        bcb::generate_bcb(&bundle, &bcb_payload_config, None).unwrap();
    bcb_block.block_number = 2;
    bundle.blocks.insert(0, bcb_block);

    // Replace payload with ciphertext
    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    bundle.blocks[payload_idx].data = ciphertexts[0].clone();

    // Create receiver with both keys
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(source.clone(), aes_key);
    sec_ctx.add_hmac_key(source.clone(), hmac_key);
    sec_ctx.set_bcb_failure_policy(SecurityFailurePolicy::DeleteBundle);
    sec_ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // Receive bundle
    let bundle_bytes = interplanetary_sdk::bp::encode(&bundle).unwrap();
    let bundle_id = agent
        .receive_bytes_from_cla(&bundle_bytes)
        .expect("RFC9172-076: BCB decryption and BIB verification should succeed");

    // Verify: Security blocks removed, payload decrypted
    let received = agent.storage().get(&bundle_id).unwrap();

    let has_bcb = received
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Bcb));
    let has_bib = received
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Bib));

    assert!(
        !has_bcb,
        "RFC9172-076: BCB MUST be removed after successful decryption"
    );
    assert!(
        !has_bib,
        "RFC9172-076: BIB MUST be removed after successful verification at destination"
    );

    let payload_block = received
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("Payload block must exist");

    assert_eq!(
        payload_block.data, original_payload,
        "RFC9172-076: Payload MUST be decrypted (BCB processed first) so BIB can verify plaintext"
    );
}

/// RFC9172-079: BCB decryption failure with DeleteBundle policy
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_079_bcb_failure_delete_bundle_policy() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    // Generate BCB
    let correct_key = vec![0x01; 32];
    let iv = vec![0xAB; 12];
    let bcb_config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes256,
        key: correct_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        #[cfg(feature = "test-fixtures")]
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

    // Receiver with WRONG key
    let mut sec_ctx = SecurityContext::new();
    let wrong_key = vec![0xFF; 32];
    sec_ctx.add_aes_key(source.clone(), wrong_key);
    sec_ctx.set_bcb_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    let bundle_bytes = interplanetary_sdk::bp::encode(&bundle).unwrap();
    let result = agent.receive_bytes_from_cla(&bundle_bytes);

    assert!(
        result.is_err(),
        "RFC9172-079: Bundle MUST be rejected when BCB decryption fails with DeleteBundle policy"
    );
}

/// RFC9172-079: BIB verification failure with DeleteBundle policy
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_079_bib_failure_delete_bundle_policy() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    // Generate BIB
    let correct_key = vec![0x01; 32];
    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: correct_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        #[cfg(feature = "test-fixtures")]
        hmac_key_policy: None,
    };
    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Receiver with WRONG key
    let mut sec_ctx = SecurityContext::new();
    let wrong_key = vec![0xFF; 32];
    sec_ctx.add_hmac_key(source.clone(), wrong_key);
    sec_ctx.set_bib_failure_policy(SecurityFailurePolicy::DeleteBundle);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    let bundle_bytes = interplanetary_sdk::bp::encode(&bundle).unwrap();
    let result = agent.receive_bytes_from_cla(&bundle_bytes);

    assert!(
        result.is_err(),
        "RFC9172-079: Bundle MUST be rejected when BIB verification fails with DeleteBundle policy"
    );
}

/// RFC9172-079: BCB decryption failure with StripSecurityBlock policy
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_079_bcb_failure_strip_policy() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"Test payload".to_vec())
        .build()
        .unwrap();

    // Generate BCB
    let correct_key = vec![0x01; 32];
    let iv = vec![0xAB; 12];
    let bcb_config = BcbConfig {
        security_source: source.clone(),
        targets: BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes256,
        key: correct_key.clone(),
        iv: iv.clone(),
        wrapped_key: None,
        scope_flags: 0x00,
        key_id: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
    };
    let (bcb_block, ciphertexts) = bcb::generate_bcb(&bundle, &bcb_config, None).unwrap();
    bundle.blocks.insert(0, bcb_block);

    let payload_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_number == 1)
        .unwrap();
    let ciphertext = ciphertexts[0].clone();
    bundle.blocks[payload_idx].data = ciphertext.clone();

    // Receiver with WRONG key but StripSecurityBlock policy
    let mut sec_ctx = SecurityContext::new();
    let wrong_key = vec![0xFF; 32];
    sec_ctx.add_aes_key(source.clone(), wrong_key);
    sec_ctx.set_bcb_failure_policy(SecurityFailurePolicy::StripSecurityBlock);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    let bundle_bytes = interplanetary_sdk::bp::encode(&bundle).unwrap();
    let bundle_id = agent
        .receive_bytes_from_cla(&bundle_bytes)
        .expect("RFC9172-079: Bundle MUST be admitted with StripSecurityBlock policy");

    let received = agent.storage().get(&bundle_id).unwrap();

    let has_bcb = received
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Bcb));
    assert!(
        !has_bcb,
        "RFC9172-079: Failed BCB MUST be stripped with StripSecurityBlock policy"
    );

    let payload_block = received
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_eq!(
        payload_block.data, ciphertext,
        "RFC9172-079: Payload MUST remain as ciphertext when BCB decryption fails"
    );
}

/// RFC9172-079: BIB verification failure with StripSecurityBlock policy
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_079_bib_failure_strip_policy() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let plaintext = b"Test payload".to_vec();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(plaintext.clone())
        .build()
        .unwrap();

    // Generate BIB
    let correct_key = vec![0x01; 32];
    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: correct_key.clone(),
        scope_flags: 0x00,
        wrapped_key: None,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true,
        #[cfg(feature = "test-fixtures")]
        hmac_key_policy: None,
    };
    let bib_block = bib::generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Receiver with WRONG key but StripSecurityBlock policy
    let mut sec_ctx = SecurityContext::new();
    let wrong_key = vec![0xFF; 32];
    sec_ctx.add_hmac_key(source.clone(), wrong_key);
    sec_ctx.set_bib_failure_policy(SecurityFailurePolicy::StripSecurityBlock);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: interplanetary_sdk::bpa::policy::StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    let bundle_bytes = interplanetary_sdk::bp::encode(&bundle).unwrap();
    let bundle_id = agent
        .receive_bytes_from_cla(&bundle_bytes)
        .expect("RFC9172-079: Bundle MUST be admitted with StripSecurityBlock policy");

    let received = agent.storage().get(&bundle_id).unwrap();

    let has_bib = received
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Bib));
    assert!(
        !has_bib,
        "RFC9172-079: Failed BIB MUST be stripped with StripSecurityBlock policy"
    );

    let payload_block = received
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_eq!(
        payload_block.data, plaintext,
        "RFC9172-079: Payload MUST be preserved unmodified when BIB verification fails"
    );
}
