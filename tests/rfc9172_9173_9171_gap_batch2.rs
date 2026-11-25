//! Gap-closing batch 2: RFC 9172 / 9173 / 9171 production-path tests
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::retention::RetentionConstraint;
use interplanetary_sdk::bpa::{
    BpaConfig, BundleAgent, OutboundBcbConfig, StatusReportPolicy,
    security_processing::{SecurityContext, SecurityProcessingResult, process_bibs},
};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

fn forwarding_agent(outbound: Option<OutboundBcbConfig>) -> BundleAgent {
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
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    )
}

/// RFC9171-4-022: unrecognized block processing flags MUST be ignored.
#[test]
fn test_rfc9171_4_022_unrecognized_block_flags_ignored_at_agent() {
    let local = EndpointId::ipn(0, 1, 0).unwrap();
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: local.clone(),
            enable_forwarding: false,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: Default::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 2, 1).unwrap())
        .destination(local)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::None)
        .payload(b"flags".to_vec())
        .build()
        .unwrap();
    // Set reserved/unrecognized high bits on payload block flags
    if let Some(p) = bundle
        .blocks
        .iter_mut()
        .find(|b| matches!(b.block_type, BlockType::Payload))
    {
        p.block_flags |= 0x10 | 0x20; // unassigned bits (above bit 3 reserved)
        p.crc_type = CrcType::None;
    }
    let encoded = BundleCodec::encode(&bundle).unwrap();
    let result = agent.receive_bytes_from_cla(&encoded);
    assert!(
        result.is_ok(),
        "RFC9171-4-022: unrecognized block flags MUST be ignored, got {:?}",
        result.err()
    );
    agent.poll(SimInstant::ZERO);
    assert_eq!(agent.delivered_adus().len(), 1);
}

/// RFC9171-4-059: fragment offset is CBOR unsigned integer (via agent MTU fragmentation).
#[test]
fn test_rfc9171_4_059_fragment_offset_cbor_unsigned_via_agent() {
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut routes = HashMap::new();
    routes.insert(dest.clone(), NodeId::ipn(0, 2));
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 1).unwrap(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: Some(Bytes::from_bytes(80)),
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes),
            forwarding_failed_policy: Default::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );

    let payload = vec![0x42u8; 200];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(payload)
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    assert!(
        agent.cla_tx_queue().len() >= 2,
        "MTU fragmentation must emit multiple fragments"
    );
    for tx in agent.cla_tx_queue() {
        let encoded = BundleCodec::encode(&tx.bundle).unwrap();
        let decoded = BundleCodec::decode(&encoded).unwrap();
        assert!(
            decoded.primary.fragment_offset.is_some(),
            "fragment MUST have offset"
        );
        // Re-encode primary and parse CBOR: fragment offset field is unsigned
        let prim = BundleCodec::encode_primary(&decoded.primary).unwrap();
        let val: Value = ciborium::from_reader(prim.as_slice()).unwrap();
        let Value::Array(arr) = val else {
            panic!("primary must be array");
        };
        // fragment offset is element 8 when fragmented
        match &arr[8] {
            Value::Integer(n) => {
                assert!(*n >= 0.into(), "RFC9171-4-059: offset MUST be unsigned");
            }
            other => panic!("RFC9171-4-059: fragment offset MUST be CBOR uint, got {other:?}"),
        }
    }
}

/// RFC9171-5-002: send() creates outbound bundle with DispatchPending.
#[test]
fn test_rfc9171_5_002_send_sets_dispatch_pending() {
    let mut agent = forwarding_agent(None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"adu".to_vec())
        .build()
        .unwrap();

    let id = agent.send(bundle).unwrap();
    assert!(
        agent.has_retention_constraint(&id, RetentionConstraint::DispatchPending),
        "RFC9171-5-002: outbound bundle MUST have DispatchPending"
    );
}

/// RFC9171-4-046 / RFC9171-4-047: primary block immutable across forward.
#[test]
fn test_rfc9171_4_046_047_primary_immutable_on_forward() {
    let mut agent = forwarding_agent(None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(100), 3))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"x".to_vec())
        .build()
        .unwrap();

    let primary_before = BundleCodec::encode_primary(&bundle.primary).unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(0));

    assert_eq!(agent.cla_tx_queue().len(), 1);
    let emitted = &agent.cla_tx_queue()[0].bundle;
    let primary_after = BundleCodec::encode_primary(&emitted.primary).unwrap();
    assert_eq!(
        primary_before, primary_after,
        "RFC9171-4-046/047: primary CBOR MUST be unchanged after forward"
    );
}

/// RFC9172-028: when context-flags bit0 is set, parameters field MUST be present.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_028_params_present_when_flag_set_via_agent() {
    let mut agent = forwarding_agent(Some(OutboundBcbConfig::aes128(
        b"k".to_vec(),
        vec![0x11; 16],
    )));
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"p".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let bcb = agent.cla_tx_queue()[0]
        .bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .expect("BCB present");

    let mut cur = Cursor::new(&bcb.data);
    let _targets = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let _ctx = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let flags = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let Value::Integer(f) = flags else {
        panic!("flags must be integer");
    };
    let flags_u: u64 = f.try_into().unwrap();
    assert_eq!(flags_u & 0x01, 1, "parameters-present flag MUST be set");
    let _source = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let params = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    match params {
        Value::Array(a) => assert!(!a.is_empty(), "RFC9172-028: params field MUST be included"),
        other => panic!("params MUST be array, got {other:?}"),
    }
}

/// RFC9172-060: BIBs MUST be added before BCBs for a given target (generator refuses reverse).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_060_bib_before_bcb_enforced() {
    // BCB first on payload, then attempt BIB — refused (056/060 ordering).
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .payload(b"data".to_vec())
        .build()
        .unwrap();

    let (mut bcb, cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![1],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0x22; 16],
            iv: vec![0x33; 12],
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

    let bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source,
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: vec![0x44; 32],
            wrapped_key: None,
            scope_flags: 0,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    );
    assert!(
        bib.is_err(),
        "RFC9172-060: BIB MUST NOT be added after BCB for same target"
    );
}

/// RFC9172-057: BIB integrity MUST NOT be checked if the BIB itself is a BCB target.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_057_encrypted_bib_not_checked() {
    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 1, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(1_000_000)
        .payload(b"p".to_vec())
        .build()
        .unwrap();

    bundle.blocks.insert(
        0,
        CanonicalBlock {
            block_type: BlockType::HopCount,
            block_number: 2,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![0x82, 0x1E, 0x00],
        },
    );

    let hmac_key = vec![0xAB; 32];
    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![2],
            },
            sha_variant: HmacVariant::Sha256,
            key: hmac_key.clone(),
            wrapped_key: None,
            scope_flags: 0,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    bib.block_number = 3;
    bundle.blocks.insert(0, bib);

    // Encrypt the BIB (wrong AES key later would make decrypt fail; we only test process_bibs skip)
    let aes_key = vec![0xCD; 16];
    let (mut bcb, cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![3],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: aes_key,
            iv: vec![0x01; 12],
            wrapped_key: None,
            scope_flags: 0,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    bcb.block_number = 4;
    if let Some(b) = bundle.blocks.iter_mut().find(|b| b.block_number == 3) {
        b.data = cts[0].clone();
    }
    bundle.blocks.insert(0, bcb);

    // WRONG hmac key — if encrypted BIB were checked, verification would fail hard / panic on parse
    let mut ctx = SecurityContext::new();
    ctx.add_hmac_key(source, vec![0xFF; 32]);

    let result = process_bibs(&mut bundle, &ctx, false).unwrap();
    assert!(
        matches!(result, SecurityProcessingResult::Success),
        "RFC9172-057: encrypted BIB MUST NOT be integrity-checked (skip succeeds)"
    );
}

/// RFC9172-058 / 097: BIB integrity MUST NOT be checked when target is BCB-protected.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_058_bib_target_bcb_protected_not_checked() {
    // Reuse production helper semantics via process_bibs with BCB still present
    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 1, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(1_000_000)
        .payload(b"shared".to_vec())
        .build()
        .unwrap();

    let hmac_key = vec![0x11; 32];
    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: hmac_key,
            wrapped_key: None,
            scope_flags: 0,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    bib.block_number = 3;
    bundle.blocks.insert(0, bib);

    let (mut bcb, cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![1],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0x22; 16],
            iv: vec![0x33; 12],
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

    let mut ctx = SecurityContext::new();
    // Deliberately no HMAC key / wrong — must still succeed by skipping BCB-protected target
    ctx.add_hmac_key(source, vec![0x00; 32]);

    let result = process_bibs(&mut bundle, &ctx, false).unwrap();
    assert!(
        matches!(result, SecurityProcessingResult::Success),
        "RFC9172-058: BIB over BCB-protected target MUST NOT be checked"
    );
}

/// RFC9172-065 / RFC9172-049: BCB holds AEAD auth tag as security result.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_065_049_bcb_holds_auth_tag_via_agent() {
    let mut agent = forwarding_agent(Some(OutboundBcbConfig::aes128(
        b"tag".to_vec(),
        vec![0x77; 16],
    )));
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"auth".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let bcb = agent.cla_tx_queue()[0]
        .bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();
    let mut cur = Cursor::new(&bcb.data);
    for _ in 0..5 {
        let _ = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    }
    let results = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let Value::Array(target_results) = results else {
        panic!("results must be array");
    };
    let Value::Array(res0) = &target_results[0] else {
        panic!("target results must be array");
    };
    let Value::Array(pair) = &res0[0] else {
        panic!("result pair");
    };
    match &pair[1] {
        Value::Bytes(tag) => {
            assert_eq!(tag.len(), 16, "RFC9172-065: AES-GCM auth tag in BCB result");
        }
        _ => panic!("RFC9172-065: auth tag MUST be in BCB security result"),
    }
}

/// RFC9172-112: mandatory security contexts BIB-HMAC-SHA2 and BCB-AES-GCM are supported.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_112_mandatory_contexts_via_agent() {
    // BCB-AES-GCM via outbound agent path
    let mut agent = forwarding_agent(Some(OutboundBcbConfig::aes128(
        b"mand".to_vec(),
        vec![0x55; 16],
    )));
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"m".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let bcb = agent.cla_tx_queue()[0]
        .bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();
    let mut cur = Cursor::new(&bcb.data);
    let _t = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let ctx_id = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    match ctx_id {
        Value::Integer(n) => {
            let id: u64 = n.try_into().unwrap();
            assert_eq!(id, 2, "BCB-AES-GCM context id MUST be 2");
        }
        _ => panic!("context id must be integer"),
    }

    // BIB-HMAC-SHA2 via generator (context id 1) then agent reception of integrity-only bundle
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let mut bib_bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(60_000)
        .payload(b"i".to_vec())
        .build()
        .unwrap();
    let mut bib = generate_bib(
        &bib_bundle,
        &BibConfig {
            security_source: source,
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: vec![0x66; 32],
            wrapped_key: None,
            scope_flags: 0,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    bib.block_number = 2;
    bib_bundle.blocks.insert(0, bib);
    let mut cur = Cursor::new(&bib_bundle.blocks[0].data);
    let _t = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let ctx_id = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    match ctx_id {
        Value::Integer(n) => {
            let id: u64 = n.try_into().unwrap();
            assert_eq!(id, 1, "BIB-HMAC-SHA2 context id MUST be 1");
        }
        _ => panic!("context id must be integer"),
    }
}
