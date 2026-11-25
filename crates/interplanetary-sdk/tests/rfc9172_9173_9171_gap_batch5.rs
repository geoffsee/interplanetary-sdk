//! Gap-closing batch 5: RFC 9173 production-path tests
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::security_processing::SecurityContext;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::bib::{
    BibConfig, BibTargets, construct_ippt, construct_ippt_with_security_header, generate_bib,
};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::io::Cursor;

/// RFC9173-025: security-header scope appends BIB type, number, flags (in that order) to IPPT.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_025_security_header_appended_to_ippt() {
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .payload(b"ippt".to_vec())
        .build()
        .unwrap();

    let without = construct_ippt(&bundle, 1, 0x00).unwrap();
    let with = construct_ippt_with_security_header(&bundle, 1, 0x04, Some((7, 1))).unwrap();
    assert_ne!(
        without, with,
        "security header flag MUST change IPPT beyond the flags byte"
    );

    // With only bit 2 set: [flags][security_header][target_data]
    let mut cur = Cursor::new(&with[1..]);
    let hdr: Value = ciborium::from_reader(&mut cur).unwrap();
    match hdr {
        Value::Array(arr) => {
            assert_eq!(arr.len(), 3, "header MUST be [type, number, flags]");
            match (&arr[0], &arr[1], &arr[2]) {
                (Value::Integer(t), Value::Integer(n), Value::Integer(f)) => {
                    let ty: u64 = (*t).try_into().unwrap();
                    let num: u64 = (*n).try_into().unwrap();
                    let fl: u64 = (*f).try_into().unwrap();
                    assert_eq!(ty, 11, "RFC9173-025: BIB block type MUST be 11");
                    assert_eq!(num, 7, "RFC9173-025: BIB block number MUST match");
                    assert_eq!(fl, 1, "RFC9173-025: BIB flags MUST match (canonical)");
                }
                other => panic!("header elements MUST be integers, got {other:?}"),
            }
        }
        other => panic!("security header MUST be CBOR array, got {other:?}"),
    }

    let bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: EndpointId::ipn(0, 1, 1).unwrap(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: vec![0xAB; 32],
            wrapped_key: None,
            scope_flags: 0x04,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .expect("generate_bib with security-header scope MUST succeed");
    assert!(!bib.data.is_empty());
}

/// RFC9173-084/119/125/136: agent decrypt uses raw block-type-specific ciphertext;
/// plaintext length restored; AES-GCM processes ct+tag (tamper fails).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_084_119_125_136_decrypt_ciphertext_and_tag_via_agent() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let plaintext = b"secret-adu-payload".to_vec();
    let key = vec![0x5A; 16];
    let iv = vec![0x01; 12];

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
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
    if let Some(p) = bundle.blocks.iter_mut().find(|b| b.block_number == 1) {
        p.data = cts[0].clone();
    }
    bundle.blocks.insert(0, bcb);

    let payload = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    let ct_len = payload.data.len();
    assert_ne!(payload.data, plaintext);
    assert_eq!(
        ct_len,
        plaintext.len(),
        "RFC9173-084: ciphertext (sans tag) length equals plaintext; tag is in BCB result"
    );

    let wire = BundleCodec::encode(&bundle).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_aes_key(source.clone(), key.clone());
    let mut recv = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: dest.clone(),
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
    recv.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(recv.delivered_adus().len(), 1);
    let delivered_payload = recv.delivered_adus()[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("delivered payload");
    assert_eq!(
        delivered_payload.data.as_slice(),
        plaintext.as_slice(),
        "RFC9173-125/119: plaintext MUST replace ciphertext; length corrected"
    );
    let mut tampered = BundleCodec::decode(&wire).unwrap();
    if let Some(p) = tampered
        .blocks
        .iter_mut()
        .find(|b| matches!(b.block_type, BlockType::Payload))
    {
        p.data[0] ^= 0xFF;
    }
    let bad_wire = BundleCodec::encode(&tampered).unwrap();
    let mut sec2 = SecurityContext::new();
    sec2.add_aes_key(source, key);
    let mut recv2 = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: dest,
            enable_forwarding: false,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(sec2),
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    let _ = recv2.receive_bytes_from_cla(&bad_wire);
    recv2.poll(SimInstant::from_nanos(100_000_000));
    assert!(
        recv2.delivered_adus().is_empty(),
        "RFC9173-136: tampered ciphertext+tag MUST fail AES-GCM at acceptor"
    );
}
