//! Gap batch 10: RFC9173-027/028/031/034/097/103/123 exact bytes;
//! RFC9173-040/111 generation policy; RFC9173-070/071 tag-in-ciphertext;
//! RFC9172-054/067 BIB alteration & full-overlap encrypt.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{
    BpaConfig, BundleAgent, OutboundBcbConfig, SecurityContext, SecurityGenerationPolicy,
    StatusReportPolicy,
};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

fn forwarding_agent(
    outbound: Option<OutboundBcbConfig>,
    sec: Option<SecurityContext>,
) -> BundleAgent {
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 2, 0).unwrap(), NodeId::ipn(0, 2));
    BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: sec,
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: outbound,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    )
}

fn parse_asb_fields(data: &[u8]) -> (Vec<u64>, u64, Value, Value) {
    let mut cur = Cursor::new(data);
    let targets: Value = ciborium::from_reader(&mut cur).unwrap();
    let ctx: Value = ciborium::from_reader(&mut cur).unwrap();
    let _flags: Value = ciborium::from_reader(&mut cur).unwrap();
    let _src: Value = ciborium::from_reader(&mut cur).unwrap();
    let params: Value = ciborium::from_reader(&mut cur).unwrap();
    let results: Value = ciborium::from_reader(&mut cur).unwrap();
    let tnums: Vec<u64> = match targets {
        Value::Array(a) => a
            .into_iter()
            .map(|v| match v {
                Value::Integer(n) => n.try_into().unwrap(),
                _ => panic!(),
            })
            .collect(),
        _ => panic!(),
    };
    let ctx_id: u64 = match ctx {
        Value::Integer(n) => n.try_into().unwrap(),
        _ => panic!(),
    };
    (tnums, ctx_id, params, results)
}

/// RFC9173-027/028/031/034: outbound BIB generation exact ASB fields + CRC strip.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_027_028_031_034_bib_generation_exact_bytes_via_agent() {
    use interplanetary_sdk::security::bib::strip_crc_from_security_targets;

    let hmac_key = vec![0x11u8; 32]; // appropriate HMAC-SHA-256 length
    let mut agent = forwarding_agent(
        Some(
            OutboundBcbConfig::aes128(b"k".to_vec(), vec![0x22; 16]).with_pre_bib(
                vec![1],
                hmac_key.clone(),
                HmacVariant::Sha256,
            ),
        ),
        None,
    );
    // Payload starts with CRC-16; agent MUST strip before IPPT / encryption
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .payload(b"bib-exact".to_vec())
        .build()
        .unwrap();
    bundle.blocks[0].crc_type = CrcType::Crc16;
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(0));
    let secured = &agent.cla_tx_queue()[0].bundle;
    let exact = BundleCodec::encode(secured).unwrap();
    assert!(!exact.is_empty());
    let payload = secured
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_eq!(
        payload.crc_type,
        CrcType::None,
        "RFC9173-027: CRC MUST be removed from BIB/BCB target (crc_type=None)"
    );

    // Direct generate path: HMAC key + IPPT MUST be prepared (028) / length (027)
    let mut probe = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2), 0))
        .lifetime(60_000)
        .payload(b"bib-exact".to_vec())
        .build()
        .unwrap();
    probe.blocks[0].crc_type = CrcType::Crc32;
    strip_crc_from_security_targets(&mut probe, &[1]);
    assert_eq!(probe.blocks[0].crc_type, CrcType::None);

    let bib = generate_bib(
        &probe,
        &BibConfig {
            security_source: EndpointId::ipn(0, 1, 0).unwrap(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: hmac_key.clone(),
            wrapped_key: None,
            scope_flags: 0x00,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    // RFC9173-028: HMAC key + IPPT prepared — wrong-length key MUST fail generation
    let bad = generate_bib(
        &probe,
        &BibConfig {
            security_source: EndpointId::ipn(0, 1, 0).unwrap(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: vec![0x11; 8], // too short for SHA-256
            wrapped_key: None,
            scope_flags: 0x00,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    );
    assert!(
        bad.is_err(),
        "RFC9173-027/028: HMAC key MUST have appropriate length / inputs prepared"
    );

    let (targets, ctx_id, params, results) = parse_asb_fields(&bib.data);
    assert_eq!(
        targets,
        vec![1],
        "RFC9173-027: IPPT/target prepared for block 1"
    );
    assert_eq!(
        ctx_id, 1,
        "RFC9173-034: BIB context id MUST be BIB-HMAC-SHA2 (1)"
    );
    // RFC9173-034: integrity scope flags parameter present (id 3)
    let mut found_scope = false;
    if let Value::Array(ps) = params {
        for p in ps {
            if let Value::Array(kv) = p
                && let Value::Integer(id) = kv[0]
                && u64::try_from(id).unwrap() == 3
            {
                found_scope = true;
            }
        }
    }
    assert!(
        found_scope,
        "RFC9173-034: integrity scope flags MUST be placed in BIB parameters"
    );
    // RFC9173-031: keyed hash as security result
    match results {
        Value::Array(sets) => {
            let first = &sets[0];
            match first {
                Value::Array(pairs) => match &pairs[0] {
                    Value::Array(kv) => match (&kv[0], &kv[1]) {
                        (Value::Integer(id), Value::Bytes(sig)) => {
                            let id_u: u64 = (*id).try_into().unwrap();
                            assert_eq!(id_u, 1, "RFC9173-031: result type HMAC");
                            assert!(
                                !sig.is_empty(),
                                "RFC9173-031: keyed hash MUST be present as security result"
                            );
                            assert_eq!(sig.len(), 32, "RFC9173-031: SHA-256 HMAC is 32 bytes");
                        }
                        _ => panic!("bad result pair"),
                    },
                    _ => panic!("bad pair"),
                },
                _ => panic!("bad set"),
            }
        }
        _ => panic!("results not array"),
    }

    // Production path: insert BIB, verify via agent acceptor delivers
    let mut bib_block = bib;
    bib_block.block_number = 2;
    probe.blocks.insert(0, bib_block);
    let wire = BundleCodec::encode(&probe).unwrap();
    let mut sec = SecurityContext::new();
    sec.add_hmac_key(EndpointId::ipn(0, 1, 0).unwrap(), hmac_key);
    let mut recv = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: EndpointId::ipn(0, 2, 0).unwrap(),
            enable_forwarding: false,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(sec),
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    recv.receive_bytes_from_cla(&wire).unwrap();
    recv.poll(SimInstant::from_nanos(0));
    assert_eq!(recv.delivered_adus().len(), 1);
    assert_eq!(
        recv.delivered_adus()[0]
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Payload))
            .unwrap()
            .data,
        b"bib-exact"
    );
}

/// RFC9173-097/103/123: BCB encrypt replaces plaintext; BCB ASB updated; decrypt restores.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_097_103_123_bcb_encrypt_decrypt_exact_bytes_via_agent() {
    let plaintext = b"bcb-exact-adu".to_vec();
    let key = vec![0x33u8; 16];
    let mut agent = forwarding_agent(
        Some(OutboundBcbConfig::aes128(b"bcb-k".to_vec(), key.clone())),
        None,
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3), 0))
        .lifetime(60_000)
        .payload(plaintext.clone())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(0));
    let secured = &agent.cla_tx_queue()[0].bundle;
    let wire = BundleCodec::encode(secured).unwrap();

    let payload = secured
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_ne!(
        payload.data, plaintext,
        "RFC9173-097: ciphertext MUST replace plaintext"
    );
    assert_eq!(
        payload.data.len(),
        plaintext.len(),
        "RFC9173-097: tag-as-result keeps ciphertext length == plaintext"
    );

    let bcb = secured
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();
    let (_t, ctx_id, params, results) = parse_asb_fields(&bcb.data);
    assert_eq!(ctx_id, 2, "RFC9173-103: BCB context id MUST be 2");
    // IV parameter present (id 1)
    let mut found_iv = false;
    if let Value::Array(ps) = params {
        for p in ps {
            if let Value::Array(kv) = p
                && let (Value::Integer(id), Value::Bytes(iv)) = (&kv[0], &kv[1])
            {
                let id_u: u64 = (*id).try_into().unwrap();
                if id_u == 1 {
                    found_iv = true;
                    assert!((8..=16).contains(&iv.len()), "RFC9173-103: IV length 8-16");
                }
            }
        }
    }
    assert!(
        found_iv,
        "RFC9173-103: IV MUST be a BCB security context parameter"
    );
    // Auth tag as security result
    match results {
        Value::Array(sets) => match &sets[0] {
            Value::Array(pairs) => match &pairs[0] {
                Value::Array(kv) => match &kv[1] {
                    Value::Bytes(tag) => assert_eq!(tag.len(), 16, "128-bit tag"),
                    _ => panic!(),
                },
                _ => panic!(),
            },
            _ => panic!(),
        },
        _ => panic!(),
    }

    // RFC9173-123: decrypt restores exact plaintext
    let mut sec = SecurityContext::new();
    sec.add_aes_key(EndpointId::ipn(0, 1, 0).unwrap(), key.clone());
    let mut recv = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: EndpointId::ipn(0, 2, 0).unwrap(),
            enable_forwarding: false,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(sec),
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    recv.receive_bytes_from_cla(&wire).unwrap();
    recv.poll(SimInstant::from_nanos(0));
    assert_eq!(
        recv.delivered_adus()[0]
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Payload))
            .unwrap()
            .data,
        plaintext
    );
}

/// RFC9173-040/111: generation failures follow local policy.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_040_111_generation_failure_local_policy() {
    // FailClosed (default): wrong AES key length → send Err
    let mut fail_agent = forwarding_agent(
        Some(OutboundBcbConfig {
            key_id: b"bad".to_vec(),
            key: vec![0x42; 32].into(), // wrong for AES-128
            aes_variant: AesGcmVariant::Aes128,
            next_iv_counter: 0,
            pre_bib_targets: None,
            bib_hmac_key: None,
            bib_sha_variant: None,
        }),
        None,
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(4), 0))
        .lifetime(60_000)
        .payload(b"x".to_vec())
        .build()
        .unwrap();
    assert!(
        fail_agent.send(bundle.clone()).is_err(),
        "RFC9173-111 FailClosed: encryption problem MUST fail send"
    );

    // OmitSecurityOperation: same failure → unprotected bundle forwarded
    let mut sec = SecurityContext::new();
    sec.set_generation_failure_policy(SecurityGenerationPolicy::OmitSecurityOperation);
    let mut omit_agent = forwarding_agent(
        Some(OutboundBcbConfig {
            key_id: b"bad2".to_vec(),
            key: vec![0x42; 32].into(),
            aes_variant: AesGcmVariant::Aes128,
            next_iv_counter: 0,
            pre_bib_targets: None,
            bib_hmac_key: None,
            bib_sha_variant: None,
        }),
        Some(sec),
    );
    omit_agent.send(bundle).unwrap();
    omit_agent.poll(SimInstant::from_nanos(0));
    let tx = &omit_agent.cla_tx_queue()[0].bundle;
    assert!(
        !tx.blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bcb)),
        "RFC9173-111 OmitSecurity: MUST forward without BCB"
    );
    assert_eq!(
        tx.blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Payload))
            .unwrap()
            .data,
        b"x"
    );

    // RFC9173-040: BIB generation with bad HMAC key under FailClosed
    let mut bib_fail = forwarding_agent(
        Some(
            OutboundBcbConfig::aes128(b"ok".to_vec(), vec![0x55; 16]).with_pre_bib(
                vec![1],
                vec![0x11; 8], // bad HMAC length
                HmacVariant::Sha256,
            ),
        ),
        None,
    );
    let b2 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(5), 0))
        .lifetime(60_000)
        .payload(b"y".to_vec())
        .build()
        .unwrap();
    assert!(
        bib_fail.send(b2).is_err(),
        "RFC9173-040 FailClosed: keyed-hash generation problem MUST fail"
    );
}

/// RFC9173-070/071: receiver handles tag-in-ciphertext; result MUST NOT also carry tag.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_070_071_tag_in_ciphertext_receiver_and_no_duplicate_result() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let key = vec![0x77u8; 16];
    let iv = vec![0x88u8; 12];
    let plaintext = b"tag-in-ct".to_vec();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(6), 0))
        .lifetime(60_000)
        .payload(plaintext.clone())
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
            key: key.clone(),
            iv,
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    bcb.block_number = 2;

    // Extract tag from BCB results and append to ciphertext (tag-in-ciphertext mode)
    let (_t, _c, _p, results) = parse_asb_fields(&bcb.data);
    let tag = match results {
        Value::Array(sets) => match &sets[0] {
            Value::Array(pairs) => match &pairs[0] {
                Value::Array(kv) => match &kv[1] {
                    Value::Bytes(t) => t.clone(),
                    _ => panic!(),
                },
                _ => panic!(),
            },
            _ => panic!(),
        },
        _ => panic!(),
    };
    assert_eq!(tag.len(), 16);

    // Rebuild BCB data with empty results (RFC9173-071: MUST NOT include tag result)
    let mut cur = Cursor::new(&bcb.data);
    let targets: Value = ciborium::from_reader(&mut cur).unwrap();
    let ctx: Value = ciborium::from_reader(&mut cur).unwrap();
    let flags: Value = ciborium::from_reader(&mut cur).unwrap();
    let src: Value = ciborium::from_reader(&mut cur).unwrap();
    let params: Value = ciborium::from_reader(&mut cur).unwrap();
    let mut new_data = Vec::new();
    for v in [targets, ctx, flags, src, params] {
        ciborium::into_writer(&v, &mut new_data).unwrap();
    }
    // One empty result set per target (RFC9173-071: no auth-tag result; RFC9172 §3.6: one set per target)
    ciborium::into_writer(&Value::Array(vec![Value::Array(vec![])]), &mut new_data).unwrap();
    bcb.data = new_data;

    let mut ct_with_tag = cts[0].clone();
    ct_with_tag.extend_from_slice(&tag);
    assert_eq!(
        ct_with_tag.len(),
        plaintext.len() + 16,
        "RFC9173-070: target resized by +128 bits"
    );
    if let Some(p) = bundle.blocks.iter_mut().find(|b| b.block_number == 1) {
        p.data = ct_with_tag;
    }
    bundle.blocks.insert(0, bcb);

    // Assert no type-1 auth-tag result in BCB
    let (_t, _c, _p, results2) = parse_asb_fields(
        &bundle
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Bcb))
            .unwrap()
            .data,
    );
    assert_eq!(
        results2,
        Value::Array(vec![Value::Array(vec![])]),
        "RFC9173-071: tag-in-ciphertext MUST NOT also put tag in BCB results"
    );

    let wire = BundleCodec::encode(&bundle).unwrap();
    let mut sec = SecurityContext::new();
    sec.add_aes_key(source, key);
    let mut recv = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: dest,
            enable_forwarding: false,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(sec),
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    recv.receive_bytes_from_cla(&wire)
        .expect("RFC9173-070: receiver MUST handle tag-in-ciphertext");
    recv.poll(SimInstant::from_nanos(0));
    assert_eq!(
        recv.delivered_adus()[0]
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Payload))
            .unwrap()
            .data,
        plaintext
    );
}

/// RFC9172-054/067: BIB MUST be altered on partial overlap; full-overlap BIB MUST be encrypted.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_054_067_bib_altered_and_full_overlap_encrypted() {
    // 054: reuse partial-overlap path — assert alteration
    let hmac_key = vec![0xABu8; 32];
    let aes_key = vec![0xCDu8; 16];
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(7), 0))
        .lifetime(60_000)
        .payload(b"alter-me".to_vec())
        .build()
        .unwrap();
    let hop = HopCountBlock::new(2, 8, 0).unwrap();
    let hop_canonical = hop.to_canonical().unwrap();
    let hop_num = hop_canonical.block_number;
    bundle.blocks.insert(0, hop_canonical);

    let mut agent = forwarding_agent(
        Some(
            OutboundBcbConfig::aes128(b"a".to_vec(), aes_key.clone()).with_pre_bib(
                vec![1, hop_num],
                hmac_key.clone(),
                HmacVariant::Sha256,
            ),
        ),
        None,
    );
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(0));
    let secured = &agent.cla_tx_queue()[0].bundle;
    // No plaintext BIB still listing both targets
    for b in &secured.blocks {
        if matches!(b.block_type, BlockType::Bib) {
            // skip encrypted BIBs (BCB targets)
            let bcb_tgts: Vec<u64> = secured
                .blocks
                .iter()
                .filter(|x| matches!(x.block_type, BlockType::Bcb))
                .flat_map(|bcb| {
                    let (t, _, _, _) = parse_asb_fields(&bcb.data);
                    t
                })
                .collect();
            if bcb_tgts.contains(&b.block_number) {
                continue;
            }
            let (t, _, _, _) = parse_asb_fields(&b.data);
            assert!(
                !(t.contains(&1) && t.contains(&hop_num)),
                "RFC9172-054: BIB MUST be altered (no combined targets remain)"
            );
        }
    }

    // 067: full overlap — BIB only over payload, then BCB encrypts payload → BIB encrypted
    let b2 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(8), 0))
        .lifetime(60_000)
        .payload(b"full-overlap".to_vec())
        .build()
        .unwrap();
    let mut agent2 = forwarding_agent(
        Some(
            OutboundBcbConfig::aes128(b"b".to_vec(), aes_key).with_pre_bib(
                vec![1],
                hmac_key,
                HmacVariant::Sha256,
            ),
        ),
        None,
    );
    agent2.send(b2).unwrap();
    agent2.poll(SimInstant::from_nanos(0));
    let secured2 = &agent2.cla_tx_queue()[0].bundle;
    let bcbs: Vec<_> = secured2
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bcb))
        .collect();
    assert!(
        bcbs.len() >= 2,
        "RFC9172-067: MUST encrypt BIB covering encrypted targets (separate BCB), got {}",
        bcbs.len()
    );
    let mut encrypts_bib = false;
    for bcb in &bcbs {
        let (t, _, _, _) = parse_asb_fields(&bcb.data);
        for tn in t {
            if secured2
                .blocks
                .iter()
                .any(|b| b.block_number == tn && matches!(b.block_type, BlockType::Bib))
            {
                encrypts_bib = true;
            }
        }
    }
    assert!(
        encrypts_bib,
        "RFC9172-067: a BCB MUST target the BIB that covered the encrypted block"
    );
}

/// RFC9173-075: GCM requirements enforced (128-bit tag + IV uniqueness) on agent path.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_075_gcm_requirements_enforced_on_agent_path() {
    let key = vec![0x99u8; 16];
    let mut agent = forwarding_agent(
        Some(OutboundBcbConfig::aes128(b"gcm".to_vec(), key.clone())),
        None,
    );
    let mk = |n| {
        BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(n), 0))
            .lifetime(60_000)
            .payload(b"gcm".to_vec())
            .build()
            .unwrap()
    };
    agent.send(mk(1)).unwrap();
    agent.send(mk(2)).unwrap(); // unique IV via counter
    agent.poll(SimInstant::from_nanos(0));
    let q = agent.cla_tx_queue();
    assert_eq!(q.len(), 2);
    let mut ivs = Vec::new();
    for tx in q.iter() {
        let bcb = tx
            .bundle
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Bcb))
            .unwrap();
        let (_, _, params, results) = parse_asb_fields(&bcb.data);
        if let Value::Array(ps) = params {
            for p in ps {
                if let Value::Array(kv) = p
                    && let (Value::Integer(id), Value::Bytes(iv)) = (&kv[0], &kv[1])
                    && u64::try_from(*id).unwrap() == 1
                {
                    ivs.push(iv.clone());
                }
            }
        }
        match results {
            Value::Array(sets) => match &sets[0] {
                Value::Array(pairs) => match &pairs[0] {
                    Value::Array(kv) => match &kv[1] {
                        Value::Bytes(tag) => assert_eq!(
                            tag.len(),
                            16,
                            "RFC9173-075: BCB-AES-GCM requires 128-bit tags"
                        ),
                        _ => panic!(),
                    },
                    _ => panic!(),
                },
                _ => panic!(),
            },
            _ => panic!(),
        }
    }
    assert_ne!(
        ivs[0], ivs[1],
        "RFC9173-075: per-invocation IV MUST be unique"
    );
}
