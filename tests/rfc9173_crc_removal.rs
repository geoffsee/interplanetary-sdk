//! RFC 9173 CRC Removal Tests
//!
//! RFC 9173 §3.8.1: "Prior to the generation of the IPPT, if a CRC value is present
//! for the target block of the BIB, then that CRC value MUST be removed from the target block."
//!
//! RFC 9173 §4.7.1: "Prior to encryption, if a CRC value is present for the target block,
//! then that CRC value MUST be removed."
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{bp::*, types::*};

/// Helper to create a bundle with a payload block that HAS a CRC
fn create_bundle_with_crc_payload(crc_type: CrcType) -> Bundle {
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Test data with CRC".to_vec())
        .build()
        .unwrap();

    // Add CRC to payload block
    bundle.blocks[0].crc_type = crc_type;

    bundle
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_029_bib_crc_removal_crc16() {
    // RFC 9173 §3.8.1: "Prior to the generation of the IPPT, if a CRC value is present
    // for the target block of the BIB, then that CRC value MUST be removed from the target block."
    //
    // Test: Create bundle with CRC-16 on payload. Generate BIB. Verify IPPT was computed
    // with CRC removed (by comparing against IPPT of identical block without CRC).

    use interplanetary_sdk::security::{HmacVariant, bib, construct_ippt};

    // Create bundle WITH CRC-16 on payload
    let bundle_with_crc = create_bundle_with_crc_payload(CrcType::Crc16);
    assert_eq!(
        bundle_with_crc.blocks[0].crc_type,
        CrcType::Crc16,
        "Payload must have CRC-16"
    );

    // Create identical bundle WITHOUT CRC
    let bundle_without_crc = create_bundle_with_crc_payload(CrcType::None);
    assert_eq!(
        bundle_without_crc.blocks[0].crc_type,
        CrcType::None,
        "Payload must have no CRC"
    );

    // Verify payload data is identical
    assert_eq!(
        bundle_with_crc.blocks[0].data, bundle_without_crc.blocks[0].data,
        "Payload data must be identical"
    );

    // Generate BIB for bundle WITH CRC
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xAA; 32];
    let scope_flags = 0x00;

    let bib_config = bib::BibConfig {
        security_source: source.clone(),
        targets: bib::BibTargets {
            block_numbers: vec![1], // Payload block
        },
        sha_variant: HmacVariant::Sha256,
        key: key.clone(),
        scope_flags,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_block_with_crc = bib::generate_bib(&bundle_with_crc, &bib_config).unwrap();

    // Generate BIB for bundle WITHOUT CRC
    let bib_block_without_crc = bib::generate_bib(&bundle_without_crc, &bib_config).unwrap();

    // Extract HMAC signatures from BIB results
    use ciborium::Value;
    use std::io::Cursor;

    let extract_signature = |bib_data: &[u8]| -> Vec<u8> {
        let mut cursor = Cursor::new(bib_data);
        // Skip: targets, context_id, flags, source, params
        for _ in 0..5 {
            ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
        }
        // Read results
        let results: Value = ciborium::from_reader(&mut cursor).unwrap();
        if let Value::Array(result_sets) = results
            && let Value::Array(result_set) = &result_sets[0]
            && let Value::Array(pair) = &result_set[0]
            && let Value::Bytes(sig) = &pair[1]
        {
            return sig.clone();
        }
        panic!("Failed to extract signature");
    };

    let sig_with_crc = extract_signature(&bib_block_with_crc.data);
    let sig_without_crc = extract_signature(&bib_block_without_crc.data);

    // RFC 9173 §3.8.1: IPPT computed with CRC removed MUST equal IPPT of block without CRC
    assert_eq!(
        sig_with_crc, sig_without_crc,
        "RFC 9173 §3.8.1: HMAC must be identical whether CRC was present or not (proves CRC was removed before IPPT generation)"
    );

    // Also verify by constructing IPPT directly
    let ippt_with_crc = construct_ippt(&bundle_with_crc, 1, scope_flags).unwrap();
    let ippt_without_crc = construct_ippt(&bundle_without_crc, 1, scope_flags).unwrap();

    assert_eq!(
        ippt_with_crc, ippt_without_crc,
        "RFC 9173 §3.8.1: IPPT must be identical (CRC removed before generation)"
    );

    // Now test end-to-end: receiver must accept bundle with CRC on target
    use interplanetary_sdk::SimInstant;
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let mut bundle = bundle_with_crc.clone();
    let mut bib = bib_block_with_crc;
    bib.block_number = 2;
    bib.block_flags = 0x01;
    bundle.blocks.insert(0, bib);

    let encoded = BundleCodec::encode(&bundle).unwrap();

    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source, key);

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

    let storage = StorageManager::new(interplanetary_sdk::types::Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    agent.receive_bytes_from_cla(&encoded).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "Bundle with CRC on BIB target must be accepted (CRC removed for verification)"
    );

    let payload = &delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("Bundle must have payload")
        .data;
    assert_eq!(payload.as_slice(), b"Test data with CRC");
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_029_bib_crc_removal_crc32() {
    // Same test with CRC-32C

    use interplanetary_sdk::security::{HmacVariant, bib, construct_ippt};

    let bundle_with_crc = create_bundle_with_crc_payload(CrcType::Crc32);
    let bundle_without_crc = create_bundle_with_crc_payload(CrcType::None);

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xAA; 32];
    let scope_flags = 0x00;

    // Verify IPPT is identical whether CRC present or not
    let ippt_with_crc = construct_ippt(&bundle_with_crc, 1, scope_flags).unwrap();
    let ippt_without_crc = construct_ippt(&bundle_without_crc, 1, scope_flags).unwrap();

    assert_eq!(
        ippt_with_crc, ippt_without_crc,
        "RFC 9173 §3.8.1: IPPT must be identical for CRC-32C (CRC removed before generation)"
    );

    // Generate BIBs and compare signatures
    let bib_config = bib::BibConfig {
        security_source: source,
        targets: bib::BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key,
        scope_flags,
        wrapped_key: None,
        skip_source_validation: true,
        hmac_key_policy: None,
    };

    let bib_with_crc = bib::generate_bib(&bundle_with_crc, &bib_config).unwrap();
    let bib_without_crc = bib::generate_bib(&bundle_without_crc, &bib_config).unwrap();

    // Signatures must be identical
    assert_eq!(
        bib_with_crc.data, bib_without_crc.data,
        "RFC 9173 §3.8.1: BIB must be identical whether CRC was present (proves CRC removal)"
    );
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_091_bcb_crc_removal_crc16() {
    // RFC 9173 §4.7.1: "Prior to encryption, if a CRC value is present for the target block,
    // then that CRC value MUST be removed."

    use interplanetary_sdk::security::{AesGcmVariant, bcb};

    // Create bundle WITH CRC-16 on payload
    let bundle_with_crc = create_bundle_with_crc_payload(CrcType::Crc16);
    let bundle_without_crc = create_bundle_with_crc_payload(CrcType::None);

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xBB; 16];
    let iv = vec![0xCC; 12];
    let scope_flags = 0x00;

    let bcb_config = bcb::BcbConfig {
        security_source: source,
        targets: bcb::BcbTargets {
            block_numbers: vec![1],
        },
        aes_variant: AesGcmVariant::Aes128,
        key,
        iv,
        wrapped_key: None,
        scope_flags,
        key_id: None,
        skip_source_validation: true,
    };

    // Generate BCB for both bundles
    let (bcb_with_crc, ciphertexts_with_crc) =
        bcb::generate_bcb(&bundle_with_crc, &bcb_config, None).unwrap();
    let (bcb_without_crc, ciphertexts_without_crc) =
        bcb::generate_bcb(&bundle_without_crc, &bcb_config, None).unwrap();

    // RFC 9173 §4.7.1: Ciphertext must be identical whether CRC was present
    // (proves plaintext was same, i.e., CRC was removed before encryption)
    assert_eq!(
        ciphertexts_with_crc[0], ciphertexts_without_crc[0],
        "RFC 9173 §4.7.1: Ciphertext must be identical whether CRC present (proves CRC removed before encryption)"
    );

    // BCB blocks (including auth tags) must also be identical
    assert_eq!(
        bcb_with_crc.data, bcb_without_crc.data,
        "RFC 9173 §4.7.1: BCB must be identical whether CRC present"
    );
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_091_bcb_crc_removal_crc32() {
    // Same test with CRC-32C

    use interplanetary_sdk::security::{AesGcmVariant, bcb};

    let bundle_with_crc = create_bundle_with_crc_payload(CrcType::Crc32);
    let bundle_without_crc = create_bundle_with_crc_payload(CrcType::None);

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xBB; 16];
    let iv = vec![0xCC; 12];

    let bcb_config = bcb::BcbConfig {
        security_source: source,
        targets: bcb::BcbTargets {
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

    let (_, ciphertexts_with_crc) = bcb::generate_bcb(&bundle_with_crc, &bcb_config, None).unwrap();
    let (_, ciphertexts_without_crc) =
        bcb::generate_bcb(&bundle_without_crc, &bcb_config, None).unwrap();

    assert_eq!(
        ciphertexts_with_crc[0], ciphertexts_without_crc[0],
        "RFC 9173 §4.7.1: Ciphertext identical for CRC-32C (CRC removed before encryption)"
    );
}
