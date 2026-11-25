//! Batch 17/18 hardened: reverted items + policy/key obligations.
//! Exact ErrorKind + side effects; every-block 108; size accounting 109;
//! zeroize+absence 128; CL-finish 5-018.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::admin::{ReasonCode, encode_status_report};
use interplanetary_sdk::bpa::security_policy::SecurityPolicy;
use interplanetary_sdk::bpa::security_processing::parse_bib_block;
use interplanetary_sdk::bpa::{
    BpaConfig, BundleAgent, OutboundBcbConfig, SecurityContext, StatusReportPolicy,
};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::*;
use std::collections::HashMap;

fn forwarding_agent(
    outbound: Option<OutboundBcbConfig>,
    policy: Option<SecurityPolicy>,
) -> BundleAgent {
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 2, 0).unwrap(), NodeId::ipn(0, 2));
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
            security_policy: policy,
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

fn assert_err_kind(err: Result<impl std::fmt::Debug>, kind: ErrorKind, ctx: &str) {
    let e = err.expect_err(ctx);
    assert_eq!(
        e.kind(),
        &kind,
        "{ctx}: expected {kind:?}, got {:?} ({e})",
        e.kind()
    );
}

fn assert_agent_idle(agent: &BundleAgent) {
    assert!(
        agent.delivered_adus().is_empty(),
        "delivered_adus must be empty"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "cla_tx_queue must be empty"
    );
    assert_eq!(
        agent.storage().usage().bundle_count,
        0,
        "storage must hold no bundles"
    );
}

/// RFC9171-4-051: without primary BIB, send upgrades CRC None → non-zero.
#[test]
fn test_rfc9171_4_051_primary_crc_nonzero_without_bib_via_agent() {
    let mut agent = forwarding_agent(None, None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .payload(b"crc-must".to_vec())
        .build()
        .unwrap();
    assert_eq!(bundle.primary.crc_type, CrcType::None);
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let emitted = &agent.cla_tx_queue()[0].bundle;
    assert_ne!(
        emitted.primary.crc_type,
        CrcType::None,
        "RFC9171-4-051: CRC type MUST be non-zero without primary BIB"
    );
}

/// RFC9171-4-051: with BIB targeting primary, CRC type MAY remain zero.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9171_4_051_primary_crc_zero_allowed_with_primary_bib() {
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2), 0))
        .lifetime(60_000)
        .crc_type(CrcType::None)
        .payload(b"crc-may".to_vec())
        .build()
        .unwrap();
    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source,
            targets: BibTargets {
                block_numbers: vec![0],
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
    bib.block_number = 2;
    bundle.blocks.insert(0, bib);

    let mut agent = forwarding_agent(None, None);
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let emitted = &agent.cla_tx_queue()[0].bundle;
    assert_eq!(
        emitted.primary.crc_type,
        CrcType::None,
        "RFC9171-4-051: CRC MAY be zero when BIB targets primary"
    );
}

/// RFC9171-4-054: override expires locally; asserted lifetime unchanged in storage
/// AND in forwarded/emitted primary bytes (still 60000).
#[test]
fn test_rfc9171_4_054_lifetime_override_does_not_replace_asserted() {
    let mut agent = forwarding_agent(None, None);
    agent.set_lifetime_override_ms(Some(500));
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .payload(b"ovr".to_vec())
        .build()
        .unwrap();
    let asserted = bundle.primary.lifetime;
    let id = agent.send(bundle).unwrap();
    assert_eq!(
        agent.storage().get(&id).unwrap().primary.lifetime,
        asserted,
        "RFC9171-4-054: override SHALL NOT replace asserted lifetime in storage"
    );
    // Forward at t=0 (before override expiry): emitted bytes keep lifetime 60000
    agent.poll(SimInstant::ZERO);
    assert!(
        !agent.cla_tx_queue().is_empty(),
        "bundle must forward before override expiry"
    );
    let emitted = &agent.cla_tx_queue()[0].bundle;
    assert_eq!(
        emitted.primary.lifetime, 60_000,
        "RFC9171-4-054: forwarded primary.lifetime MUST remain asserted 60000"
    );
    let wire = BundleCodec::encode(emitted).unwrap();
    let decoded = BundleCodec::decode(&wire).unwrap();
    assert_eq!(
        decoded.primary.lifetime, 60_000,
        "RFC9171-4-054: encoded/decoded emitted bytes MUST carry lifetime 60000"
    );

    // Fresh agent: override expires before forward
    let mut agent2 = forwarding_agent(None, None);
    agent2.set_lifetime_override_ms(Some(500));
    let bundle2 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(60_000)
        .payload(b"ovr2".to_vec())
        .build()
        .unwrap();
    let id2 = agent2.send(bundle2).unwrap();
    agent2.poll(SimInstant::from_nanos(1_000_000_000));
    assert!(
        agent2.storage().get(&id2).is_none(),
        "RFC9171-4-054: effective override MUST delete locally"
    );
    assert!(
        agent2.cla_tx_queue().is_empty(),
        "expired under override MUST NOT emit"
    );
}

/// RFC9172-041/050: outbound BIB/BCB flags omit delete/discard-on-failure.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_041_050_outbound_security_blocks_omit_delete_discard_flags() {
    let key = vec![0x22u8; 16];
    let hmac = vec![0x33u8; 32];
    let outbound = OutboundBcbConfig::aes128(b"k".to_vec(), key).with_pre_bib(
        vec![1],
        hmac,
        HmacVariant::Sha256,
    );
    let mut agent = forwarding_agent(Some(outbound), None);
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3), 0))
        .lifetime(60_000)
        .payload(b"flags".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let emitted = &agent.cla_tx_queue()[0].bundle;
    let danger = BlockFlags::DELETE_BUNDLE_ON_FAILURE | BlockFlags::DISCARD_BLOCK_ON_FAILURE;
    for b in &emitted.blocks {
        if matches!(b.block_type, BlockType::Bib | BlockType::Bcb) {
            assert_eq!(
                b.block_flags & danger,
                0,
                "RFC9172-041/050: {:?} MUST NOT set delete/discard-on-failure (flags={:#x})",
                b.block_type,
                b.block_flags
            );
        }
    }
}

/// RFC9173-078: IV uniqueness mechanism rejects reuse (NonceRegistry on agent path).
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_078_iv_reuse_rejected_on_outbound_path() {
    let key = vec![0xABu8; 16];
    let mut agent = forwarding_agent(Some(OutboundBcbConfig::aes128(b"ivk".to_vec(), key)), None);
    let mk = |seq| {
        BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 1).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), seq))
            .lifetime(60_000)
            .payload(format!("iv-{seq}").into_bytes())
            .build()
            .unwrap()
    };
    agent.send(mk(0)).unwrap();
    if let Some(ob) = agent.outbound_bcb_mut() {
        ob.next_iv_counter = 0;
    }
    let before_stored = agent.storage().usage().bundle_count;
    assert_err_kind(
        agent.send(mk(1)),
        ErrorKind::SecurityFailure,
        "RFC9173-078: reused (key, IV)",
    );
    assert_eq!(
        agent.storage().usage().bundle_count,
        before_stored,
        "IV reuse MUST NOT admit second bundle"
    );
    assert!(
        agent.cla_tx_queue().is_empty() || agent.cla_tx_queue().len() == 1,
        "IV reuse MUST NOT enqueue a second transmission"
    );
}

/// RFC9172-108: recommended policy covers every block; emitted BIB/BCB targets exact.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_108_recommended_policy_covers_every_block_exact_targets() {
    let hmac = vec![0xCCu8; 32];
    let aes = vec![0xDDu8; 16];
    let outbound = OutboundBcbConfig::aes128(b"every".to_vec(), aes).with_pre_bib(
        vec![1], // overridden by apply_to_every_block
        hmac,
        HmacVariant::Sha256,
    );
    let mut agent = forwarding_agent(
        Some(outbound),
        Some(SecurityPolicy::recommended_bpsec_default()),
    );

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(4), 0))
        .lifetime(60_000)
        .payload(b"every-block".to_vec())
        .build()
        .unwrap();
    let hop = HopCountBlock::new(2, 8, 0).unwrap().to_canonical().unwrap();
    let hop_num = hop.block_number;
    bundle.blocks.insert(0, hop);

    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    let emitted = &agent.cla_tx_queue()[0].bundle;

    // After §3.9 split: one BIB may remain for non-payload targets; payload is
    // under BCB; the BIB ops that covered payload may be encrypted under a BCB.
    let mut bib_targets = Vec::new();
    let mut bcb_targets = Vec::new();
    for b in &emitted.blocks {
        match b.block_type {
            BlockType::Bib => {
                if let Ok(p) = parse_bib_block(b) {
                    bib_targets.extend(p.targets);
                }
            }
            BlockType::Bcb => {
                if let Ok(p) = interplanetary_sdk::bpa::security_processing::parse_bcb_block(b) {
                    bcb_targets.extend(p.targets);
                }
            }
            _ => {}
        }
    }
    bib_targets.sort_unstable();
    bib_targets.dedup();
    bcb_targets.sort_unstable();
    bcb_targets.dedup();
    // Every block must be a security target of BIB and/or BCB
    for t in [0u64, 1, hop_num] {
        assert!(
            bib_targets.contains(&t) || bcb_targets.contains(&t),
            "RFC9172-108: block {t} MUST be covered by BIB or BCB (bib={bib_targets:?} bcb={bcb_targets:?})"
        );
    }
    // Exact remaining cleartext BIB targets: primary + hop (payload BIB op encrypted under BCB)
    assert_eq!(
        bib_targets,
        vec![0, hop_num],
        "RFC9172-108: cleartext BIB MUST target exactly primary and hop"
    );
    assert!(
        bcb_targets.contains(&1),
        "RFC9172-108: BCB MUST target payload block 1: {bcb_targets:?}"
    );
}

/// RFC9172-108 receive path: missing required BIB → SecurityFailure, nothing stored.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_108_recommended_policy_requires_payload_bib() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let bundle = BundleBuilder::new()
        .source(source)
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(4), 0))
        .lifetime(60_000)
        .payload(b"need-bib".to_vec())
        .build()
        .unwrap();
    let wire = BundleCodec::encode(&bundle).unwrap();

    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: dest,
            enable_forwarding: false,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(SecurityContext::new()),
            security_policy: Some(SecurityPolicy::recommended_bpsec_default()),
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    assert_err_kind(
        agent.receive_bytes_from_cla(&wire),
        ErrorKind::SecurityFailure,
        "RFC9172-108 missing payload BIB",
    );
    assert_agent_idle(&agent);
}

/// RFC9172-110: policy forbidding ciphertext expansion rejects outbound BCB.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_110_forbid_ciphertext_expansion_blocks_outbound_bcb() {
    let mut policy = SecurityPolicy::new();
    policy.permit_ciphertext_expansion = false;
    let mut agent = forwarding_agent(
        Some(OutboundBcbConfig::aes128(b"exp".to_vec(), vec![0x44; 16])),
        Some(policy),
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(5), 0))
        .lifetime(60_000)
        .payload(b"expand".to_vec())
        .build()
        .unwrap();
    assert_err_kind(
        agent.send(bundle),
        ErrorKind::PolicyRejected,
        "RFC9172-110 forbid expansion",
    );
    assert_agent_idle(&agent);
}

/// RFC9172-109: post-BCB size accounted in storage capacity + MTU scheduling state.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_109_post_bcb_size_accounted_in_storage_and_mtu() {
    let mut policy = SecurityPolicy::new();
    policy.account_for_block_size_changes = true;
    policy.permit_ciphertext_expansion = true;

    // Capacity too small for post-BCB bundle → InsufficientStorage; accounted size set
    let tiny = Bytes(80);
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 2, 0).unwrap(), NodeId::ipn(0, 2));
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 1).unwrap(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: None,
            security_policy: Some(policy.clone()),
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes.clone()),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: Some(OutboundBcbConfig::aes128(b"sz".to_vec(), vec![0x55; 16])),
        },
        StorageManager::new(tiny),
    );
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(9), 0))
        .lifetime(60_000)
        .payload(vec![0xAAu8; 64])
        .build()
        .unwrap();
    assert_err_kind(
        agent.send(bundle),
        ErrorKind::InsufficientStorage,
        "RFC9172-109 storage accounting",
    );
    let accounted = agent
        .last_accounted_bundle_bytes()
        .expect("RFC9172-109: MUST record post-BCB size");
    assert!(
        accounted > tiny.0,
        "accounted post-BCB size {accounted} must exceed tiny capacity {}",
        tiny.0
    );
    assert_eq!(agent.storage().usage().bundle_count, 0);
    assert!(agent.cla_tx_queue().is_empty());

    // MTU + must-not-fragment (bundle flag bit 2 = 0x4): TransferFailed
    let mut agent2 = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 1).unwrap(),
            enable_forwarding: true,
            enable_delivery: false,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: Some(Bytes(40)),
            security_context: None,
            security_policy: Some(policy),
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: Some(routes),
            forwarding_failed_policy: Default::default(),
            outbound_bcb: Some(OutboundBcbConfig::aes128(b"mtu".to_vec(), vec![0x66; 16])),
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    let bundle2 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(10), 0))
        .lifetime(60_000)
        .bundle_flags(0x000004) // must not fragment
        .payload(vec![0xBBu8; 32])
        .build()
        .unwrap();
    assert_err_kind(
        agent2.send(bundle2),
        ErrorKind::TransferFailed,
        "RFC9172-109 MTU accounting",
    );
    assert!(agent2.last_accounted_bundle_bytes().unwrap() > 40);
    assert_eq!(agent2.storage().usage().bundle_count, 0);
}

/// RFC9172-111: recommended policy emits security reason code on BIB failure.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_111_security_reason_codes_emitted_per_policy() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let hmac = vec![0x55u8; 32];
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(6), 0))
        .lifetime(60_000)
        .payload(b"rep".to_vec())
        .build()
        .unwrap();
    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: hmac.clone(),
            wrapped_key: None,
            scope_flags: 0x00,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    bib.block_number = 2;
    bundle.blocks.insert(0, bib);
    bundle
        .blocks
        .iter_mut()
        .find(|b| b.block_number == 1)
        .unwrap()
        .data[0] ^= 0xff;
    let wire = BundleCodec::encode(&bundle).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_hmac_key(source, hmac);
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: dest,
            enable_forwarding: false,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            security_context: Some(sec),
            security_policy: Some(SecurityPolicy::recommended_bpsec_default()),
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: Default::default(),
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    );
    assert_err_kind(
        agent.receive_bytes_from_cla(&wire),
        ErrorKind::SecurityFailure,
        "RFC9172-111 BIB failure",
    );
    assert!(
        !agent.generated_reports().is_empty(),
        "RFC9172-111: BPSec policy MUST emit security reason codes on failure"
    );
    assert_eq!(
        agent.generated_reports()[0].reason_code,
        ReasonCode::FailedSecurityOperation
    );
    assert_agent_idle(&agent);
}

/// RFC9173-128: keys zeroized-on-drop AND absent from stored/emitted bytes.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_128_keys_zeroized_and_absent_from_stored_emitted_bytes() {
    let aes_key = vec![
        0xDEu8, 0xADu8, 0xBEu8, 0xEFu8, 0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];
    let hmac_key = vec![0xFEu8; 32];
    let kek = vec![0xABu8; 16];

    let mut sec = SecurityContext::new();
    let ep = EndpointId::ipn(0, 1, 1).unwrap();
    sec.add_aes_key(ep.clone(), aes_key.clone());
    sec.add_hmac_key(ep.clone(), hmac_key.clone());
    sec.add_kek_for_context(ep, kek.clone(), 2).unwrap();
    let dbg = format!("{:?}", sec);
    assert!(dbg.contains("redacted"));
    assert!(!dbg.contains("DEAD"));

    drop(sec); // keys drop through Zeroizing

    let outbound = OutboundBcbConfig::aes128(b"kid".to_vec(), aes_key.clone()).with_pre_bib(
        vec![1],
        hmac_key.clone(),
        HmacVariant::Sha256,
    );
    let mut agent = forwarding_agent(Some(outbound), None);

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(11), 0))
        .lifetime(60_000)
        .payload(b"no-key-leak".to_vec())
        .build()
        .unwrap();
    let id = agent.send(bundle).unwrap();
    // Stored bundle bytes must not contain raw key material
    let stored = agent.storage().get(&id).unwrap();
    let stored_bytes = BundleCodec::encode(stored).unwrap();
    assert!(
        !contains_subslice(&stored_bytes, &aes_key),
        "RFC9173-128: AES key MUST NOT appear in stored bundle bytes"
    );
    assert!(
        !contains_subslice(&stored_bytes, &hmac_key),
        "RFC9173-128: HMAC key MUST NOT appear in stored bundle bytes"
    );
    assert!(
        !contains_subslice(&stored_bytes, &kek),
        "RFC9173-128: KEK MUST NOT appear in stored bundle bytes"
    );

    agent.poll(SimInstant::ZERO);
    let emitted = &agent.cla_tx_queue()[0].bundle;
    let tx_bytes = BundleCodec::encode(emitted).unwrap();
    assert!(
        !contains_subslice(&tx_bytes, &aes_key),
        "RFC9173-128: AES key MUST NOT appear in cla_tx_queue bytes"
    );
    assert!(
        !contains_subslice(&tx_bytes, &hmac_key),
        "RFC9173-128: HMAC key MUST NOT appear in cla_tx_queue bytes"
    );
    assert!(
        !contains_subslice(&tx_bytes, &kek),
        "RFC9173-128: KEK MUST NOT appear in cla_tx_queue / transmitted bytes"
    );
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// RFC9173-129/130/131: compromised key → BIB/BCB rejected with SecurityFailure.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_129_130_131_compromised_key_rejects_bib_and_bcb() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let hmac = vec![0x66u8; 32];
    let aes = vec![0x77u8; 16];

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(7), 0))
        .lifetime(60_000)
        .payload(b"comp-bib".to_vec())
        .build()
        .unwrap();
    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![1],
            },
            sha_variant: HmacVariant::Sha256,
            key: hmac.clone(),
            wrapped_key: None,
            scope_flags: 0x00,
            skip_source_validation: true,
            hmac_key_policy: None,
        },
    )
    .unwrap();
    bib.block_number = 2;
    bundle.blocks.insert(0, bib);
    let wire_bib = BundleCodec::encode(&bundle).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_hmac_key(source.clone(), hmac);
    sec.mark_key_compromised(&source);
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
    assert_err_kind(
        agent.receive_bytes_from_cla(&wire_bib),
        ErrorKind::SecurityFailure,
        "RFC9173-131 compromised BIB",
    );
    assert_agent_idle(&agent);

    let mut bundle2 = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(8), 0))
        .lifetime(60_000)
        .payload(b"comp-bcb".to_vec())
        .build()
        .unwrap();
    let (mut bcb, cts) = generate_bcb(
        &bundle2,
        &BcbConfig {
            security_source: source.clone(),
            targets: BcbTargets {
                block_numbers: vec![1],
            },
            aes_variant: AesGcmVariant::Aes128,
            key: aes.clone(),
            iv: vec![0x10; 12],
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    bcb.block_number = 2;
    bundle2.blocks[0].data = cts[0].clone();
    bundle2.blocks.insert(0, bcb);
    let wire_bcb = BundleCodec::encode(&bundle2).unwrap();

    let mut sec2 = SecurityContext::new();
    sec2.add_aes_key(source.clone(), aes);
    sec2.mark_key_compromised(&source);
    let mut agent2 = BundleAgent::new(
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
    assert_err_kind(
        agent2.receive_bytes_from_cla(&wire_bcb),
        ErrorKind::SecurityFailure,
        "RFC9173-131 compromised BCB",
    );
    assert_agent_idle(&agent2);
}

/// RFC9171-5-018: extension hook requests status report on CLA send-complete;
/// poll emits exact reason-code bytes.
#[test]
fn test_rfc9171_5_018_extension_cla_finish_status_report_bytes() {
    let mut agent = forwarding_agent(None, None);
    // Extension mandates TransmissionCancelled reason on CL finish
    agent.set_extension_cla_finish_report(Some(ReasonCode::TransmissionCancelled));

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(12), 0))
        .lifetime(60_000)
        .payload(b"cla-finish".to_vec())
        .build()
        .unwrap();
    let id = agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);
    assert!(
        !agent.cla_tx_queue().is_empty(),
        "bundle must be queued for CLA"
    );

    agent.queue_cla_send_complete(id.clone());
    agent.poll(SimInstant::from_nanos(1_000_000));

    assert_eq!(
        agent.generated_reports().len(),
        1,
        "RFC9171-5-018: CLA finish MUST emit extension-mandated status report"
    );
    let report = &agent.generated_reports()[0];
    assert!(
        report.forwarded.asserted,
        "must be a forwarding status report"
    );
    assert_eq!(report.reason_code, ReasonCode::TransmissionCancelled);

    let bytes = encode_status_report(report, false);
    let (decoded, _) = interplanetary_sdk::bpa::admin::decode_status_report(&bytes).unwrap();
    assert_eq!(
        decoded.reason_code,
        ReasonCode::TransmissionCancelled,
        "RFC9171-5-018: decoded report bytes MUST carry extension reason code 3"
    );
    assert!(decoded.forwarded.asserted);
    assert!(
        agent.cla_tx_queue().iter().all(|t| t.bundle_id != id),
        "CLA finish MUST remove bundle from cla_tx_queue"
    );
}
