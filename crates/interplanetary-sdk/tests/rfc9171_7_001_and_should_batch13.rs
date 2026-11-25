//! Batch 13: SHOULD items 038/109/085/099 (7-001 covered in tcpcl/session.rs unit test).
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{
    BpaConfig, BundleAgent, OutboundBcbConfig, SecurityContext, StatusReportPolicy,
};
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;

/// RFC9173-038: SHA variant SHOULD be added when ≠ default (6 = HMAC384).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_038_sha_variant_param_when_not_default() {
    use ciborium::Value;
    use std::io::Cursor;
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .payload(b"sha-var".to_vec())
        .build()
        .unwrap();
    // Sha256 ≠ default 6
    let bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: EndpointId::ipn(0, 1, 0).unwrap(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: vec![0x11; 32],
            wrapped_key: None,
            scope_flags: 0x00,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    let mut cur = Cursor::new(&bib.data);
    for _ in 0..4 {
        let _: Value = ciborium::from_reader(&mut cur).unwrap();
    }
    let params: Value = ciborium::from_reader(&mut cur).unwrap();
    let mut found = None;
    if let Value::Array(ps) = params {
        for p in ps {
            if let Value::Array(kv) = p
                && let (Value::Integer(id), Value::Integer(v)) = (&kv[0], &kv[1])
                && u64::try_from(*id).unwrap() == 1
            {
                found = Some(u64::try_from(*v).unwrap());
            }
        }
    }
    assert_eq!(
        found,
        Some(5),
        "RFC9173-038: SHA-256 (5) SHOULD be present when ≠ default 6"
    );
}

/// RFC9173-109: AES variant SHOULD be added when ≠ default (3 = A256GCM).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_109_aes_variant_param_when_not_default() {
    use ciborium::Value;
    use std::io::Cursor;
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 2, 0).unwrap(), NodeId::ipn(0, 2));
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: None,
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: Some(OutboundBcbConfig::aes128(b"k".to_vec(), vec![0x22; 16])),
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2), 0))
        .lifetime(60_000)
        .payload(b"aes-var".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(0));
    let bcb = agent.cla_tx_queue()[0]
        .bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .unwrap();
    let mut cur = Cursor::new(&bcb.data);
    for _ in 0..4 {
        let _: Value = ciborium::from_reader(&mut cur).unwrap();
    }
    let params: Value = ciborium::from_reader(&mut cur).unwrap();
    let mut found = None;
    if let Value::Array(ps) = params {
        for p in ps {
            if let Value::Array(kv) = p
                && let (Value::Integer(id), Value::Integer(v)) = (&kv[0], &kv[1])
                && u64::try_from(*id).unwrap() == 2
            {
                found = Some(u64::try_from(*v).unwrap());
            }
        }
    }
    assert_eq!(
        found,
        Some(1),
        "RFC9173-109: AES-128 (1) SHOULD be present when ≠ default 3"
    );
    let _ = AesGcmVariant::Aes128; // keep import used when cfg
}

/// RFC9172-085/099: RECOMMENDED remove non-payload security target on BCB failure.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_085_099_discard_non_payload_target_on_bcb_failure() {
    // Production path already implemented (RFC9172-088); assert recommended discard.
    use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3), 0))
        .lifetime(60_000)
        .payload(b"keep".to_vec())
        .build()
        .unwrap();
    let hop = HopCountBlock::new(2, 8, 0).unwrap().to_canonical().unwrap();
    let hop_num = hop.block_number;
    bundle.blocks.insert(0, hop);
    let (mut bcb, cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![hop_num],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0x11; 16],
            iv: vec![0x33; 12],
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    bcb.block_number = 3;
    if let Some(h) = bundle.blocks.iter_mut().find(|b| b.block_number == hop_num) {
        h.data = cts[0].clone();
    }
    bundle.blocks.insert(0, bcb);
    let wire = BundleCodec::encode(&bundle).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_aes_key(source, vec![0xFF; 16]); // wrong key → decrypt fail
    let mut agent = BundleAgent::new(
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
    agent.receive_bytes_from_cla(&wire).unwrap();
    agent.poll(SimInstant::from_nanos(0));
    let delivered = &agent.delivered_adus()[0];
    assert!(
        !delivered.blocks.iter().any(|b| b.block_number == hop_num),
        "RFC9172-085/099: non-payload security target SHOULD be removed on BCB failure"
    );
    assert_eq!(
        delivered
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Payload))
            .unwrap()
            .data,
        b"keep"
    );
}

/// RFC9173-016: missing integrity scope flags → assume 7 (all assigned fields).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_016_default_integrity_scope_flags_to_7() {
    use ciborium::Value;
    use interplanetary_sdk::bpa::security_processing::{SecurityContext, process_bibs};
    use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
    use std::io::Cursor;

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let key = vec![0xAAu8; 48]; // SHA-384 default length
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(9), 0))
        .lifetime(60_000)
        .payload(b"scope-default".to_vec())
        .build()
        .unwrap();

    // Generate with explicit scope 7, then strip scope param from ASB
    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha384,
            key: key.clone(),
            wrapped_key: None,
            scope_flags: 0x07,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();

    // Rebuild ASB without scope flags parameter (id 3)
    let mut cur = Cursor::new(&bib.data);
    let targets: Value = ciborium::from_reader(&mut cur).unwrap();
    let ctx: Value = ciborium::from_reader(&mut cur).unwrap();
    let flags: Value = ciborium::from_reader(&mut cur).unwrap();
    let src: Value = ciborium::from_reader(&mut cur).unwrap();
    let params: Value = ciborium::from_reader(&mut cur).unwrap();
    let results: Value = ciborium::from_reader(&mut cur).unwrap();
    let mut new_params = Vec::new();
    if let Value::Array(ps) = params {
        for p in ps {
            if let Value::Array(kv) = &p
                && let Value::Integer(id) = &kv[0]
                && u64::try_from(*id).unwrap() == 3
            {
                continue; // omit scope flags
            }
            new_params.push(p);
        }
    }
    let mut new_data = Vec::new();
    for v in [targets, ctx, flags, src, Value::Array(new_params), results] {
        ciborium::into_writer(&v, &mut new_data).unwrap();
    }
    bib.data = new_data;
    bib.block_number = 2;
    bundle.blocks.insert(0, bib);

    let mut sec = SecurityContext::new();
    sec.add_hmac_key(source, key);
    // Would fail if default were 0 instead of 7 (IPPT mismatch → BibVerificationFailed)
    let result = process_bibs(&mut bundle, &sec, true).expect("process_bibs Result");
    assert!(
        matches!(
            result,
            interplanetary_sdk::bpa::SecurityProcessingResult::Success
        ),
        "RFC9173-016: default scope 7 MUST verify, got {result:?}"
    );
    assert!(
        !bundle
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bib)),
        "acceptor removed BIB after verify with defaulted scope 7"
    );
}

/// RFC9173-079: short tags SHOULD be avoided — BCB-AES-GCM requires 128-bit tags.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_079_rejects_short_auth_tags() {
    use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(10), 0))
        .lifetime(60_000)
        .payload(b"taglen".to_vec())
        .build()
        .unwrap();
    let (bcb, _cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: EndpointId::ipn(0, 1, 0).unwrap(),
            targets: BcbTargets {
                block_numbers: vec![1],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0x55; 16],
            iv: vec![0x66; 12],
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    use ciborium::Value;
    use std::io::Cursor;
    let mut cur = Cursor::new(&bcb.data);
    for _ in 0..5 {
        let _: Value = ciborium::from_reader(&mut cur).unwrap();
    }
    let results: Value = ciborium::from_reader(&mut cur).unwrap();
    match results {
        Value::Array(sets) => match &sets[0] {
            Value::Array(pairs) => match &pairs[0] {
                Value::Array(kv) => match &kv[1] {
                    Value::Bytes(tag) => assert_eq!(
                        tag.len(),
                        16,
                        "RFC9173-079: short tags avoided; BCB uses 128-bit tags"
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
