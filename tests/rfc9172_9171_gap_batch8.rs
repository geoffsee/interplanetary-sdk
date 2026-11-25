//! Gap-closing batch 8: RFC9172-088 discard, RFC9172-053/055 BIB split,
//! RFC9171-5-004 disavowal, RFC9171-5-038 skip remaining reception steps.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::security_processing::{SecurityProcessingResult, process_bcbs};
use interplanetary_sdk::bpa::{
    BpaConfig, BundleAgent, OutboundBcbConfig, SecurityContext, StatusReportPolicy,
};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;

fn read_bib_targets(block: &CanonicalBlock) -> Vec<u64> {
    use ciborium::Value;
    use std::io::Cursor;
    let mut cur = Cursor::new(&block.data);
    let targets_val: Value = ciborium::from_reader(&mut cur).unwrap();
    match targets_val {
        Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                Value::Integer(n) => {
                    let u: u64 = n.try_into().unwrap();
                    u
                }
                _ => panic!("target not int"),
            })
            .collect(),
        _ => panic!("targets not array"),
    }
}

/// RFC9172-088: non-payload BCB decrypt failure discards target + associated security blocks
/// on the BundleAgent receive path; payload is delivered.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_088_agent_discards_non_payload_target_and_security_blocks() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let plaintext = b"keep-me".to_vec();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(plaintext.clone())
        .build()
        .unwrap();

    let hop = HopCountBlock::new(2, 16, 0).unwrap();
    let hop_canonical = hop.to_canonical().unwrap();
    let hop_num = hop_canonical.block_number;
    bundle.blocks.insert(0, hop_canonical);

    let key = vec![0x11u8; 16];
    let wrong_key = vec![0x22u8; 16];
    let iv = vec![0x33u8; 12];
    let (mut bcb, cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![hop_num],
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
    let bcb_num = bundle
        .blocks
        .iter()
        .map(|b| b.block_number)
        .max()
        .unwrap_or(0)
        + 1;
    bcb.block_number = bcb_num;
    if let Some(h) = bundle.blocks.iter_mut().find(|b| b.block_number == hop_num) {
        h.data = cts[0].clone();
    }
    bundle.blocks.insert(0, bcb);

    let wire = BundleCodec::encode(&bundle).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_aes_key(source.clone(), wrong_key.clone());

    let mut agent = BundleAgent::new(
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

    let _bundle_id = agent
        .receive_bytes_from_cla(&wire)
        .expect("RFC9172-088: bundle with failed non-payload BCB MUST still be admitted");
    agent.poll(SimInstant::from_nanos(0));

    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "RFC9172-088: payload MUST still be deliverable after non-payload discard"
    );
    assert_eq!(delivered[0].primary.destination, dest);
    assert!(
        !delivered[0]
            .blocks
            .iter()
            .any(|blk| blk.block_number == hop_num || matches!(blk.block_type, BlockType::Bcb)),
        "RFC9172-088: delivered ADU MUST NOT retain discarded hop target or BCB"
    );

    let mut again = BundleCodec::decode(&wire).unwrap();
    let mut sec2 = SecurityContext::new();
    sec2.add_aes_key(source, wrong_key);
    let result = process_bcbs(&mut again, &mut sec2).unwrap();
    assert!(
        matches!(result, SecurityProcessingResult::Success),
        "RFC9172-088: non-payload failure yields Success after discard, got {:?}",
        result
    );
    assert!(
        !again
            .blocks
            .iter()
            .any(|b| b.block_number == hop_num || matches!(b.block_type, BlockType::Bcb)),
        "RFC9172-088: process_bcbs MUST discard hop target and associated BCB"
    );
    assert!(
        again
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Payload)),
        "RFC9172-088: payload block MUST remain"
    );
}

/// RFC9172-053/055: outbound BCB with partial BIB overlap splits BIB and encrypts the new BIB.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_053_055_bib_split_on_outbound_bcb_partial_overlap() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let hmac_key = vec![0xABu8; 32];
    let aes_key = vec![0xCDu8; 16];

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(5000), 0))
        .lifetime(60_000)
        .payload(b"adu-for-split".to_vec())
        .build()
        .unwrap();

    let hop = HopCountBlock::new(2, 8, 0).unwrap();
    let hop_canonical = hop.to_canonical().unwrap();
    let hop_num = hop_canonical.block_number;
    let payload_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;
    bundle.blocks.insert(0, hop_canonical);

    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: source.clone(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: None,
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some({
                let mut r = HashMap::new();
                r.insert(dest.clone(), NodeId::ipn(0, 2));
                r
            }),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: Some(
                OutboundBcbConfig::aes128(b"kek-id".to_vec(), aes_key).with_pre_bib(
                    vec![payload_num, hop_num],
                    hmac_key,
                    HmacVariant::Sha256,
                ),
            ),
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );

    let bundle_id = agent
        .send(bundle)
        .expect("send with §3.9 split MUST succeed");
    agent.poll(SimInstant::from_nanos(0));

    let tx = agent.cla_tx_queue();
    assert!(
        !tx.is_empty(),
        "RFC9172-053: secured bundle MUST be queued for CLA tx"
    );
    let secured = &tx[0].bundle;
    let exact_bytes = BundleCodec::encode(secured).expect("tx bundle must encode");
    assert!(!exact_bytes.is_empty());

    let bibs: Vec<_> = secured
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bib))
        .collect();
    let bcbs: Vec<_> = secured
        .blocks
        .iter()
        .filter(|b| matches!(b.block_type, BlockType::Bcb))
        .collect();

    assert!(
        bcbs.len() >= 2,
        "RFC9172-053/055: MUST have BCB for payload and BCB for new BIB, got {}",
        bcbs.len()
    );

    // BCB security-target lists (encrypted BIBs still have BlockType::Bib but ciphertext data)
    let mut bcb_target_nums = Vec::new();
    for bcb in &bcbs {
        let mut cur = std::io::Cursor::new(&bcb.data);
        let targets_val: ciborium::Value = ciborium::from_reader(&mut cur).unwrap();
        if let ciborium::Value::Array(arr) = targets_val {
            for v in arr {
                if let ciborium::Value::Integer(n) = v {
                    let u: u64 = n.try_into().unwrap();
                    bcb_target_nums.push(u);
                }
            }
        }
    }
    assert!(
        bcb_target_nums.contains(&payload_num),
        "RFC9172-053: one BCB MUST target the payload"
    );
    let encrypted_bibs: Vec<_> = bibs
        .iter()
        .filter(|b| bcb_target_nums.contains(&b.block_number))
        .collect();
    assert!(
        !encrypted_bibs.is_empty(),
        "RFC9172-055: newly created BIB MUST be encrypted (listed as a BCB target)"
    );

    let mut found_hop_only_bib = false;
    for bib in &bibs {
        if bcb_target_nums.contains(&bib.block_number) {
            continue; // ciphertext — not parseable as ASB
        }
        let targets = read_bib_targets(bib);
        if targets == vec![hop_num] {
            found_hop_only_bib = true;
        }
        assert!(
            !(targets.contains(&payload_num) && targets.contains(&hop_num)),
            "RFC9172-053: original multi-target BIB MUST be altered (no combined targets)"
        );
    }
    assert!(
        found_hop_only_bib,
        "RFC9172-055: remaining BIB MUST keep non-overlapping hop target"
    );

    let payload = secured
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_ne!(
        payload.data.as_slice(),
        b"adu-for-split",
        "RFC9172-053: payload MUST be replaced with ciphertext"
    );

    assert_eq!(tx[0].bundle_id, bundle_id);
}

/// RFC9171-5-004: after local delivery, node SHALL NOT forward the bundle to itself.
#[test]
fn test_rfc9171_5_004_disavow_destination_membership_no_self_forward() {
    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let mut routes = HashMap::new();
    routes.insert(local_eid.clone(), NodeId::ipn(0, 2));

    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: local_eid.clone(),
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
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(local_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(42), 0))
        .lifetime(60_000)
        .payload(b"local-only".to_vec())
        .build()
        .unwrap();

    let wire = BundleCodec::encode(&bundle).unwrap();
    let id = agent.receive_bytes_from_cla(&wire).unwrap();
    agent.poll(SimInstant::from_nanos(0));

    assert!(
        agent
            .delivered_adus()
            .iter()
            .any(|b| b.primary.destination == local_eid),
        "RFC9171-5-004: local membership MUST trigger delivery"
    );
    assert!(
        !agent.cla_tx_queue().iter().any(|tx| tx.bundle_id == id),
        "RFC9171-5-004: node SHALL NOT forward the bundle to itself after delivery"
    );
}

/// RFC9171-5-038: on CRC failure, deletion procedure runs and remaining reception steps are skipped.
#[test]
fn test_rfc9171_5_038_crc_failure_skips_remaining_reception_steps() {
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: dest.clone(),
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::all(dest.clone()),
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

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(7), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"crc-me".to_vec())
        .build()
        .unwrap();

    let mut wire = BundleCodec::encode(&bundle).unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 0xFF;

    let result = agent.receive_bytes_from_cla(&wire);
    assert!(
        result.is_err(),
        "RFC9171-5-038: CRC failure MUST reject/delete the bundle (not admitted)"
    );
    agent.poll(SimInstant::from_nanos(0));

    assert!(
        agent.delivered_adus().is_empty(),
        "RFC9171-5-038: remaining reception steps (delivery) MUST be skipped"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "RFC9171-5-038: remaining reception steps (forward) MUST be skipped"
    );
}
