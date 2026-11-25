//! RFC 9172 / 9173 gap-closing production-path tests (batch 1)
//!
//! - RFC9172-056: BIB MUST NOT target a block already targeted by a BCB
//! - RFC9172-107: BCB/BIB MUST NOT be added to a fragment
//! - RFC9173-099: ciphertext MUST replace plaintext in target block data
//! - RFC9173-105: IV MUST be present as BCB security context parameter
//! - RFC9173-085: non-data block fields MUST NOT be part of encryption
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, OutboundBcbConfig, StatusReportPolicy};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

fn agent_with_routes(outbound: Option<OutboundBcbConfig>) -> BundleAgent {
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut routes = HashMap::new();
    routes.insert(dest, NodeId::ipn(0, 2));
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: EndpointId::ipn(0, 1, 1).unwrap(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: Default::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: outbound,
    };
    BundleAgent::new(config, StorageManager::new(Bytes::from_mib(10).unwrap()))
}

fn extract_bcb_iv(bcb_data: &[u8]) -> Vec<u8> {
    let mut cursor = Cursor::new(bcb_data);
    for _ in 0..4 {
        let _ = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    }
    let params = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    let Value::Array(arr) = params else {
        panic!("params must be array");
    };
    for p in arr {
        if let Value::Array(pair) = p
            && pair.len() == 2
            && let (Value::Integer(id), Value::Bytes(iv)) = (&pair[0], &pair[1])
        {
            let id: u64 = (*id).try_into().unwrap();
            if id == 1 {
                return iv.clone();
            }
        }
    }
    panic!("missing IV parameter");
}

/// RFC9172-056: plaintext BIB on a BCB-protected target is rejected.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_056_bib_on_bcb_target_rejected_at_agent() {
    let local = EndpointId::ipn(0, 1, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: local.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: None,
        security_context: None,
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: Default::default(),
        outbound_bcb: None,
    };
    let mut agent = BundleAgent::new(config, StorageManager::new(Bytes::from_mib(10).unwrap()));

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(local)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(1_000_000)
        .crc_type(CrcType::Crc16)
        .payload(b"secret".to_vec())
        .build()
        .unwrap();

    // BCB on payload
    let (mut bcb, cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![1],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0x11; 16],
            iv: vec![0x22; 12],
            wrapped_key: None,
            scope_flags: 0,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    bcb.block_number = 2;
    if let Some(p) = bundle.blocks.iter_mut().find(|b| b.block_number == 1) {
        p.data = cts[0].clone();
    }
    bundle.blocks.insert(0, bcb);

    // Attempt to add plaintext BIB on same target — MUST fail (generator path)
    let bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source,
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: vec![0x33; 32],
            wrapped_key: None,
            scope_flags: 0,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    );
    assert!(
        bib.is_err(),
        "RFC9172-056: generate_bib MUST refuse BIB on existing BCB target"
    );

    // Also craft a hand-built violating bundle and reject at agent reception
    let mut violating = BundleBuilder::new()
        .source(EndpointId::ipn(0, 2, 1).unwrap())
        .destination(EndpointId::ipn(0, 1, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 2))
        .lifetime(1_000_000)
        .crc_type(CrcType::Crc16)
        .payload(b"x".to_vec())
        .build()
        .unwrap();

    // Minimal ASB: BCB targets [1], BIB targets [1], BIB not encrypted
    let bcb_asb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, 0x02, 0x01, 0x82, 0x02, 0x82, 0x02, 0x01, 0x80, 0x81, 0x81, 0x82, 0x01,
            0x40,
        ],
    };
    let bib_asb = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 3,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, 0x01, 0x01, 0x82, 0x02, 0x82, 0x02, 0x01, 0x80, 0x81, 0x81, 0x82, 0x01,
            0x40,
        ],
    };
    violating.blocks.insert(0, bcb_asb);
    violating.blocks.insert(0, bib_asb);

    let encoded = BundleCodec::encode(&violating).unwrap();
    let result = agent.receive_bytes_from_cla(&encoded);
    assert!(
        result.is_err(),
        "RFC9172-056: agent MUST reject plaintext BIB sharing a BCB target"
    );
    agent.poll(SimInstant::ZERO);
    assert_eq!(agent.delivered_adus().len(), 0);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

/// RFC9172-107: cannot add BCB to a fragment via BundleAgent::send.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_107_no_bcb_on_fragment_via_agent_send() {
    let outbound = OutboundBcbConfig::aes128(b"k".to_vec(), vec![0xAB; 16]);
    let mut agent = agent_with_routes(Some(outbound));

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"frag-payload".to_vec())
        .build()
        .unwrap();

    bundle.primary.fragment_offset = Some(0);
    bundle.primary.total_app_data_length = Some(12);

    let result = agent.send(bundle);
    assert!(
        result.is_err(),
        "RFC9172-107: send MUST NOT add BCB to a fragment"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("fragment") || err.contains("5.2") || err.contains("9172"),
        "Error should cite fragment / RFC 9172 §5.2, got: {err}"
    );
    agent.poll(SimInstant::ZERO);
    assert_eq!(agent.cla_tx_queue().len(), 0);
}

/// RFC9173-099 + RFC9173-105 + RFC9173-085 via agent origination.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_099_105_085_outbound_bcb_cla_bytes() {
    let plaintext = b"plaintext-payload-xyz".to_vec();
    let outbound = OutboundBcbConfig::aes128(b"prod-key".to_vec(), vec![0xCD; 16]);
    let mut agent = agent_with_routes(Some(outbound));

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(plaintext.clone())
        .build()
        .unwrap();

    let payload_flags_before = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .map(|b| (b.block_type, b.block_number, b.block_flags))
        .unwrap();

    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    assert_eq!(agent.cla_tx_queue().len(), 1);
    let emitted = &agent.cla_tx_queue()[0].bundle;
    let encoded = BundleCodec::encode(emitted).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    let payload = decoded
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("payload present");

    // RFC9173-099: ciphertext replaced plaintext bytes
    assert_ne!(
        payload.data, plaintext,
        "RFC9173-099: payload data MUST be ciphertext, not plaintext"
    );
    assert_eq!(
        payload.data.len(),
        plaintext.len(),
        "AES-GCM ciphertext length equals plaintext (tag is in BCB result)"
    );

    // RFC9173-085: header fields not part of encryption — unchanged
    assert_eq!(
        (
            payload.block_type,
            payload.block_number,
            payload.block_flags
        ),
        payload_flags_before,
        "RFC9173-085: block type/number/flags MUST NOT change under encryption"
    );

    let bcb = decoded
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .expect("BCB present");

    // RFC9173-105: IV parameter present
    let iv = extract_bcb_iv(&bcb.data);
    assert_eq!(
        iv.len(),
        12,
        "RFC9173-105: IV parameter MUST be present (12 bytes)"
    );
}
