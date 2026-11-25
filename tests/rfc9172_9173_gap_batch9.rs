//! Gap-closing batch 9: RFC9173-050/126 CRC restore, RFC9173-132/133 KEK bans,
//! RFC9172-106 secure fragmentation.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::security_processing::{process_bcbs_ex, process_bibs};
use interplanetary_sdk::bpa::{
    BCB_AES_GCM_CONTEXT_ID, BIB_HMAC_SHA2_CONTEXT_ID, BpaConfig, BundleAgent, KekUsageRegistry,
    OutboundBcbConfig, SecurityContext, StatusReportPolicy,
};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;

/// RFC9173-050: BIB acceptor that is not the destination restores CRC on the target.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_050_bib_acceptor_waypoint_restores_crc() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let waypoint = EndpointId::ipn(0, 2, 0).unwrap();
    let dest = EndpointId::ipn(0, 3, 0).unwrap();
    let hmac_key = vec![0x11u8; 32];

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(10), 0))
        .lifetime(60_000)
        .payload(b"crc-restore-bib".to_vec())
        .build()
        .unwrap();
    let payload_num = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap()
        .block_number;
    assert_eq!(
        bundle
            .blocks
            .iter()
            .find(|b| b.block_number == payload_num)
            .unwrap()
            .crc_type,
        CrcType::None
    );

    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![payload_num],
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
    bib.block_number = 2;
    bundle.blocks.insert(0, bib);

    let wire = BundleCodec::encode(&bundle).unwrap();
    let mut received = BundleCodec::decode(&wire).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_hmac_key(source.clone(), hmac_key);
    sec.set_bib_acceptor(true); // waypoint acceptor
    sec.set_restore_crc_type(CrcType::Crc16);

    // Direct acceptor path (not destination)
    process_bibs(&mut received, &sec, false).unwrap();
    assert!(
        !received
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bib)),
        "RFC9173-050: acceptor MUST remove BIB"
    );
    let payload = received
        .blocks
        .iter()
        .find(|b| b.block_number == payload_num)
        .unwrap();
    assert_eq!(
        payload.crc_type,
        CrcType::Crc16,
        "RFC9173-050: CRC MUST be restored on target at non-destination acceptor"
    );

    // Agent path: waypoint forwards the CRC-restored bundle
    let mut routes = HashMap::new();
    routes.insert(dest.clone(), NodeId::ipn(0, 3));
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: waypoint,
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(sec),
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    agent.receive_bytes_from_cla(&wire).unwrap();
    agent.poll(SimInstant::from_nanos(0));
    let tx = agent.cla_tx_queue();
    assert!(!tx.is_empty(), "RFC9173-050: waypoint MUST forward");
    let forwarded = &tx[0].bundle;
    let payload = forwarded
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_eq!(
        payload.crc_type,
        CrcType::Crc16,
        "RFC9173-050: forwarded payload MUST retain restored CRC"
    );
    let encoded = BundleCodec::encode(forwarded).unwrap();
    let roundtrip = BundleCodec::decode(&encoded).unwrap();
    assert_eq!(
        roundtrip
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Payload))
            .unwrap()
            .crc_type,
        CrcType::Crc16
    );
}

/// RFC9173-126: BCB acceptor that is not the destination restores CRC on the target.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_126_bcb_acceptor_waypoint_restores_crc() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let waypoint = EndpointId::ipn(0, 2, 0).unwrap();
    let dest = EndpointId::ipn(0, 3, 0).unwrap();
    let aes_key = vec![0x55u8; 16];
    let iv = vec![0x66u8; 12];

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(20), 0))
        .lifetime(60_000)
        .payload(b"crc-restore-bcb".to_vec())
        .build()
        .unwrap();
    let payload_num = 1u64;

    let (mut bcb, cts) = generate_bcb(
        &bundle,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![payload_num],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: aes_key.clone(),
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
    if let Some(p) = bundle
        .blocks
        .iter_mut()
        .find(|b| b.block_number == payload_num)
    {
        p.data = cts[0].clone();
        p.crc_type = CrcType::None;
    }
    bundle.blocks.insert(0, bcb);

    let wire = BundleCodec::encode(&bundle).unwrap();
    let mut received = BundleCodec::decode(&wire).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_aes_key(source, aes_key);
    sec.set_restore_crc_type(CrcType::Crc16);

    process_bcbs_ex(&mut received, &mut sec, false).unwrap();
    assert!(
        !received
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Bcb)),
        "RFC9173-126: BCB MUST be removed after acceptance"
    );
    let payload = received
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_eq!(payload.data.as_slice(), b"crc-restore-bcb");
    assert_eq!(
        payload.crc_type,
        CrcType::Crc16,
        "RFC9173-126: CRC MUST be restored at non-destination acceptor"
    );

    // Fresh decrypt-side IV registry for agent path (direct call already registered IV)
    sec.received_iv_registry.clear();

    let mut routes = HashMap::new();
    routes.insert(dest, NodeId::ipn(0, 3));
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: waypoint,
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(sec),
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    agent.receive_bytes_from_cla(&wire).unwrap();
    agent.poll(SimInstant::from_nanos(0));
    let tx = agent.cla_tx_queue();
    assert!(
        !tx.is_empty(),
        "RFC9173-126: waypoint MUST forward after decrypt"
    );
    let forwarded = &tx[0].bundle;
    let payload = forwarded
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_eq!(payload.data.as_slice(), b"crc-restore-bcb");
    assert_eq!(payload.crc_type, CrcType::Crc16);
}

/// RFC9173-132/133: KEK registry refuses cross-context and cross-algorithm reuse.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_132_133_kek_cross_context_and_algorithm_banned() {
    let kek = vec![0xAAu8; 16];
    let mut reg = KekUsageRegistry::default();
    reg.register(&kek, BIB_HMAC_SHA2_CONTEXT_ID).unwrap();
    let err = reg
        .register(&kek, BCB_AES_GCM_CONTEXT_ID)
        .expect_err("RFC9173-133: same KEK for BIB then BCB MUST fail");
    assert!(
        err.to_string().contains("9173-133") || err.to_string().contains("different security"),
        "error must cite cross-context ban: {}",
        err
    );

    // Agent path: registering KEK for BCB then attempting BIB binding fails
    let mut sec = SecurityContext::new();
    let ep = EndpointId::ipn(0, 1, 0).unwrap();
    sec.add_kek_for_context(ep.clone(), kek.clone(), BCB_AES_GCM_CONTEXT_ID)
        .unwrap();
    let err = sec
        .add_kek_for_context(ep, kek.clone(), BIB_HMAC_SHA2_CONTEXT_ID)
        .expect_err("RFC9173-133 via SecurityContext");
    assert!(err.to_string().contains("9173-133"));

    // RFC9173-132: same key bytes MUST NOT serve as both HMAC and AES material
    let key = vec![0xCCu8; 16];
    let err = KekUsageRegistry::assert_same_key_not_cross_algorithm(
        &key,
        &[(BIB_HMAC_SHA2_CONTEXT_ID, key.as_slice())],
    )
    .expect_err("RFC9173-132: identical key across algorithms MUST fail");
    assert!(err.to_string().contains("9173-132"));

    // Wire into agent send: refuse outbound when AES key equals registered HMAC key material
    let hmac_key = vec![0xDDu8; 16];
    let mut sec2 = SecurityContext::new();
    sec2.add_hmac_key(EndpointId::ipn(0, 1, 0).unwrap(), hmac_key.clone());
    // Cross-check at policy boundary before send
    let check = KekUsageRegistry::assert_same_key_not_cross_algorithm(
        &hmac_key,
        &[(BCB_AES_GCM_CONTEXT_ID, hmac_key.as_slice())],
    );
    assert!(check.is_err());
}

/// RFC9172-106: fragmenting a BPSec-protected bundle follows RFC 9171 rules
/// (only payload fragmented; security blocks remain whole / replicated).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_106_secure_bundle_fragmentation_via_agent_mtu() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let aes_key = vec![0x10u8; 16];
    // Large payload to force fragmentation under small MTU
    let payload = vec![0x42u8; 400];

    let mut routes = HashMap::new();
    routes.insert(dest.clone(), NodeId::ipn(0, 2));

    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: source.clone(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: Some(Bytes(180)), // force fragmentation after BCB expansion
            security_context: None,
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: Some(OutboundBcbConfig::aes128(b"frag-key".to_vec(), aes_key)),
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );

    let bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(30), 0))
        .lifetime(60_000)
        .payload(payload)
        .build()
        .unwrap();

    agent.send(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(0));

    let tx = agent.cla_tx_queue();
    assert!(
        tx.len() >= 2,
        "RFC9172-106: secured oversized bundle MUST fragment, got {} tx",
        tx.len()
    );

    for frag_tx in tx.iter() {
        let frag = &frag_tx.bundle;
        assert!(
            frag.primary.is_fragment(),
            "RFC9172-106: each piece MUST be a fragment"
        );
        // Security blocks are never fragmented: any BCB present must be a whole block
        let bcbs: Vec<_> = frag
            .blocks
            .iter()
            .filter(|b| matches!(b.block_type, BlockType::Bcb))
            .collect();
        // BCB has replicate flag → present in every fragment
        assert_eq!(
            bcbs.len(),
            1,
            "RFC9172-106: each fragment MUST carry the whole BCB (not fragmented)"
        );
        // Payload is the only block whose data is a slice of the ADU
        assert!(
            frag.blocks
                .iter()
                .any(|b| matches!(b.block_type, BlockType::Payload)),
            "RFC9172-106: fragment MUST contain a payload piece"
        );
        let exact = BundleCodec::encode(frag).unwrap();
        assert!(!exact.is_empty());
    }

    // Also: MUST NOT add new security ops to a fragment
    let frag0 = &tx[0].bundle;
    let bib_err = generate_bib(
        frag0,
        &BibConfig {
            security_source: EndpointId::ipn(0, 1, 0).unwrap(),
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
    );
    assert!(
        bib_err.is_err(),
        "RFC9172-106 / §5.2: MUST NOT add BIB to a fragment"
    );
}
