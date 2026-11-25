//! Gap-closing batch 3: RFC 9171 / 9172 / 9173 production-path tests
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, OutboundBcbConfig, StatusReportPolicy};
use interplanetary_sdk::security::HmacVariant;
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

fn forwarding_agent(outbound: Option<OutboundBcbConfig>, mtu: Option<Bytes>) -> BundleAgent {
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut routes = HashMap::new();
    routes.insert(dest, NodeId::ipn(0, 2));
    BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 1).unwrap(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: mtu,
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
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    )
}

/// RFC9171-4-060: total ADU length present iff bundle is a fragment.
#[test]
fn test_rfc9171_4_060_total_adu_length_iff_fragment_via_agent() {
    // Non-fragment: total_app_data_length MUST be absent
    let mut agent = forwarding_agent(None, None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"small".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    assert_eq!(agent.cla_tx_queue().len(), 1);
    let non_frag = &agent.cla_tx_queue()[0].bundle;
    assert!(
        !non_frag.primary.is_fragment(),
        "control: non-fragment bundle"
    );
    assert!(
        non_frag.primary.total_app_data_length.is_none(),
        "RFC9171-4-060: total ADU length MUST be absent when not a fragment"
    );

    // Fragment via MTU: total_app_data_length MUST be present
    let mut agent = forwarding_agent(None, Some(Bytes::from_bytes(80)));
    let payload = vec![0x7Au8; 200];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(payload.clone())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    assert!(
        agent.cla_tx_queue().len() >= 2,
        "MTU must produce fragments"
    );
    for tx in agent.cla_tx_queue() {
        assert!(
            tx.bundle.primary.is_fragment(),
            "emitted bundle MUST be fragment"
        );
        let total = tx
            .bundle
            .primary
            .total_app_data_length
            .expect("RFC9171-4-060: total ADU length SHALL be present for fragments");
        assert_eq!(total, payload.len() as u64);
    }
}

/// RFC9171-4-006 / RFC9171-4-007: wire bundle is indefinite array of primary then canonicals.
#[test]
fn test_rfc9171_4_006_007_primary_then_canonicals_via_agent() {
    let mut agent = forwarding_agent(None, None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"struct".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let encoded = BundleCodec::encode(&agent.cla_tx_queue()[0].bundle).unwrap();
    assert_eq!(encoded[0], 0x9F, "bundle MUST be CBOR indefinite array");
    assert_eq!(*encoded.last().unwrap(), 0xFF);

    let mut cur = Cursor::new(&encoded[1..encoded.len() - 1]);
    let mut blocks: Vec<Value> = Vec::new();
    while (cur.position() as usize) < encoded.len() - 2 {
        match ciborium::from_reader::<Value, _>(&mut cur) {
            Ok(v) => blocks.push(v),
            Err(_) => break,
        }
    }
    assert!(
        blocks.len() >= 2,
        "MUST have primary + ≥1 canonical, got {}",
        blocks.len()
    );

    // Primary: version 7 at element 0, length 8–11
    let Value::Array(primary) = &blocks[0] else {
        panic!("RFC9171-4-006: first block MUST be primary array");
    };
    assert!(
        (8..=11).contains(&primary.len()),
        "primary length 8–11, got {}",
        primary.len()
    );
    match &primary[0] {
        Value::Integer(v) => {
            let ver: u64 = (*v).try_into().unwrap();
            assert_eq!(ver, 7, "RFC9171-4-006: primary version MUST be 7");
        }
        other => panic!("version MUST be integer, got {other:?}"),
    }

    // Exactly one primary: remaining blocks are canonical (5 or 6 elements)
    for (i, block) in blocks[1..].iter().enumerate() {
        let Value::Array(arr) = block else {
            panic!("RFC9171-4-007: block {} MUST be canonical array", i + 1);
        };
        assert!(
            arr.len() == 5 || arr.len() == 6,
            "RFC9171-4-007: canonical must have 5 or 6 elements, block {} got {}",
            i + 1,
            arr.len()
        );
        // First element is block type code (not version 7 as sole primary marker)
        match &arr[0] {
            Value::Integer(t) => {
                let ty: u64 = (*t).try_into().unwrap();
                assert_ne!(
                    ty, 7,
                    "canonical block type MUST NOT be confused with primary version"
                );
            }
            other => panic!("block type MUST be integer, got {other:?}"),
        }
    }
}

/// RFC9172-066: security blocks added while preserving RFC 9171 ordering (payload last).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_066_block_order_payload_last_with_bcb() {
    let mut agent = forwarding_agent(
        Some(OutboundBcbConfig::aes128(
            b"ord-key".to_vec(),
            vec![0x55; 16],
        )),
        None,
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"order".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let emitted = &agent.cla_tx_queue()[0].bundle;
    assert!(
        emitted
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bcb)),
        "BCB MUST be present"
    );
    let last = emitted.blocks.last().expect("blocks non-empty");
    assert!(
        matches!(last.block_type, BlockType::Payload),
        "RFC9172-066: last block MUST remain payload per RFC 9171, got {:?}",
        last.block_type
    );
}

/// RFC9172-114: security context MUST be uniquely identifiable (context id in ASB).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_114_context_id_identifiable_via_agent() {
    let mut agent = forwarding_agent(
        Some(OutboundBcbConfig::aes128(
            b"ctx-key".to_vec(),
            vec![0x66; 16],
        )),
        None,
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 2))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"ctx".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let bcb = agent.cla_tx_queue()[0]
        .bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .expect("BCB");
    let mut cur = Cursor::new(&bcb.data);
    let _targets = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let ctx = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    match ctx {
        Value::Integer(id) => {
            let id_u: u64 = id.try_into().unwrap();
            assert_eq!(
                id_u, 2,
                "RFC9172-114: BCB-AES-GCM context id MUST be uniquely 2"
            );
        }
        other => panic!("context id MUST be integer, got {other:?}"),
    }
}

/// RFC9172-074: reserved/unassigned block flags MUST be 0 in BPSec canonical form (IPPT).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_074_reserved_block_flags_zeroed_in_ippt() {
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let bundle_a = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .payload(b"same".to_vec())
        .build()
        .unwrap();
    let mut bundle_b = bundle_a.clone();
    // Set unassigned block processing flags on payload of B only
    if let Some(p) = bundle_b
        .blocks
        .iter_mut()
        .find(|b| matches!(b.block_type, BlockType::Payload))
    {
        p.block_flags |= 0x10 | 0x20;
    }

    let cfg = BibConfig {
        security_source: source,
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0x99; 32],
        wrapped_key: None,
        // Include target header so block_flags enter IPPT
        scope_flags: 0x02,
        skip_source_validation: true,
        hmac_key_policy: None,
    };
    let bib_a = generate_bib(&bundle_a, &cfg).unwrap();
    let bib_b = generate_bib(&bundle_b, &cfg).unwrap();
    assert_eq!(
        bib_a.data, bib_b.data,
        "RFC9172-074: IPPT/HMAC MUST ignore reserved/unassigned block flags (canonical form zeros them)"
    );
}

/// RFC9173-074: BCB keys MUST have length matching AES variant (via agent outbound).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_074_key_length_enforced_via_agent() {
    // Wrong length for AES-128 (32 bytes) MUST fail at send
    let mut agent = forwarding_agent(
        Some(OutboundBcbConfig {
            key_id: b"bad".to_vec(),
            key: vec![0x42; 32].into(),
            aes_variant: interplanetary_sdk::security::AesGcmVariant::Aes128,
            next_iv_counter: 1,
            pre_bib_targets: None,
            bib_hmac_key: None,
            bib_sha_variant: None,
        }),
        None,
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"k".to_vec())
        .build()
        .unwrap();
    let err = agent.send(bundle).expect_err("wrong key length MUST fail");
    let msg = err.to_string();
    assert!(
        msg.contains("AES-128") || msg.contains("16") || msg.contains("key"),
        "RFC9173-074: error must cite key length, got {msg}"
    );

    // Correct 16-byte key succeeds and emits BCB
    let mut agent = forwarding_agent(
        Some(OutboundBcbConfig::aes128(b"good".to_vec(), vec![0x42; 16])),
        None,
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"k".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    assert!(
        agent.cla_tx_queue()[0]
            .bundle
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bcb))
    );
}
