//! Gap-closing batch 4: RFC 9171 / 9172 production-path tests
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::validation::validate_security_blocks_ex;
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

fn forwarding_agent(mtu: Option<Bytes>) -> BundleAgent {
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
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    )
}

/// RFC9171-4-058: fragment offset present iff bundle is a fragment.
#[test]
fn test_rfc9171_4_058_fragment_offset_iff_fragment_via_agent() {
    let mut agent = forwarding_agent(None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"nf".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let nf = &agent.cla_tx_queue()[0].bundle;
    assert!(!nf.primary.is_fragment());
    assert!(
        nf.primary.fragment_offset.is_none(),
        "RFC9171-4-058: offset MUST be absent when not a fragment"
    );

    let mut agent = forwarding_agent(Some(Bytes::from_bytes(80)));
    let payload = vec![0xABu8; 200];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 1))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(payload)
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    assert!(agent.cla_tx_queue().len() >= 2);
    for tx in agent.cla_tx_queue() {
        assert!(tx.bundle.primary.is_fragment());
        assert!(
            tx.bundle.primary.fragment_offset.is_some(),
            "RFC9171-4-058: offset SHALL be present for fragments"
        );
        // Representation: CBOR unsigned integer
        let prim = BundleCodec::encode_primary(&tx.bundle.primary).unwrap();
        let val: Value = ciborium::from_reader(prim.as_slice()).unwrap();
        let Value::Array(arr) = val else {
            panic!("primary array");
        };
        match &arr[8] {
            Value::Integer(n) => assert!(*n >= 0.into()),
            other => panic!("offset MUST be CBOR uint, got {other:?}"),
        }
    }
}

/// RFC9171-4-001: agent-emitted bundles SHALL conform to CBOR (RFC 8949).
#[test]
fn test_rfc9171_4_001_agent_emitted_is_cbor() {
    let mut agent = forwarding_agent(None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"cbor".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let encoded = BundleCodec::encode(&agent.cla_tx_queue()[0].bundle).unwrap();
    assert_eq!(encoded[0], 0x9F);
    assert_eq!(*encoded.last().unwrap(), 0xFF);
    // Every top-level element must parse as CBOR
    let mut cur = Cursor::new(&encoded[1..encoded.len() - 1]);
    let mut n = 0;
    while (cur.position() as usize) < encoded.len() - 2 {
        match ciborium::from_reader::<Value, _>(&mut cur) {
            Ok(_) => n += 1,
            Err(_) => break,
        }
    }
    assert!(n >= 2, "RFC9171-4-001: emitted bundle MUST be valid CBOR");
    // Round-trip decode proves structural CBOR conformance
    BundleCodec::decode(&encoded).expect("RFC9171-4-001: CBOR decode MUST succeed");
}

/// RFC9171-4-002: field encodings MUST be deterministic (same logical values → same bytes).
#[test]
fn test_rfc9171_4_002_deterministic_encoding_via_agent() {
    let mut agent = forwarding_agent(None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 3))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"det".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let once = BundleCodec::encode(&agent.cla_tx_queue()[0].bundle).unwrap();
    let decoded = BundleCodec::decode(&once).unwrap();
    let twice = BundleCodec::encode(&decoded).unwrap();
    assert_eq!(
        once, twice,
        "RFC9171-4-002: re-encode MUST be byte-identical (deterministic CBOR)"
    );
}

/// RFC9171-4-062: primary CRC SHALL be present when no BIB targets the primary.
#[test]
fn test_rfc9171_4_062_primary_crc_present_without_bib_via_agent() {
    let mut agent = forwarding_agent(None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 4))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"crc".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let emitted = &agent.cla_tx_queue()[0].bundle;
    assert!(
        !emitted
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bib)),
        "control: no BIB on bundle"
    );
    assert_ne!(
        emitted.primary.crc_type,
        CrcType::None,
        "RFC9171-4-062: CRC type MUST be non-zero without primary BIB"
    );
    let prim = BundleCodec::encode_primary(&emitted.primary).unwrap();
    let val: Value = ciborium::from_reader(prim.as_slice()).unwrap();
    let Value::Array(arr) = val else {
        panic!("primary");
    };
    // CRC type at index 2; CRC bytes last when type != None
    match &arr[2] {
        Value::Integer(t) => {
            let tv: u64 = (*t).try_into().unwrap();
            assert_ne!(tv, 0, "CRC type code MUST be non-zero");
        }
        other => panic!("CRC type MUST be integer, got {other:?}"),
    }
    match arr.last() {
        Some(Value::Bytes(b)) if b.len() == 2 => {}
        other => panic!("RFC9171-4-062: CRC-16 bytes MUST be present, got {other:?}"),
    }
}

/// RFC9172-051/052: when BCB targets cover all of an existing BIB's targets, BIB MUST be encrypted.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_051_052_bib_encrypted_when_bcb_covers_all_bib_targets() {
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .payload(b"shared".to_vec())
        .build()
        .unwrap();

    // BIB covering payload (sole target)
    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: vec![0x11; 32],
            wrapped_key: None,
            scope_flags: 0,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    bib.block_number = 2;
    bundle.blocks.insert(0, bib);

    // Add BCB on same payload — covers ALL of BIB's targets
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
    bcb.block_number = 3;
    if let Some(p) = bundle.blocks.iter_mut().find(|b| b.block_number == 1) {
        p.data = cts[0].clone();
    }
    bundle.blocks.insert(0, bcb);

    // Without encrypting the BIB: §3.9 / 051–052 violation
    let bad = validate_security_blocks_ex(&bundle, true);
    assert!(
        bad.is_err(),
        "RFC9172-051/052: BIB covering BCB target MUST be encrypted, got Ok"
    );

    // Encrypt the BIB (erratum 7002: separate BCB for BIB block)
    let bib_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bib))
        .map(|b| b.block_number)
        .unwrap();
    let (mut bcb_bib, bib_cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source,
            targets: BcbTargets {
                block_numbers: vec![bib_num],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0x44; 16],
            iv: vec![0x55; 12],
            wrapped_key: None,
            scope_flags: 0,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    bcb_bib.block_number = 4;
    if let Some(b) = bundle.blocks.iter_mut().find(|b| b.block_number == bib_num) {
        b.data = bib_cts[0].clone();
    }
    bundle.blocks.insert(0, bcb_bib);

    validate_security_blocks_ex(&bundle, true)
        .expect("RFC9172-051/052: encrypting the BIB MUST satisfy the rule");
}
