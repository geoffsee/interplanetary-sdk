//! Batch 16: RFC9173-020 ct_eq; 080 failed-verify limit; 081 decrypt replay;
//! RFC9171-4-053 expiry→delete; RFC9172-015 multi-op ASB; RFC9172-103 waypoint.
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, SecurityContext, StatusReportPolicy};
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::security::{AesGcmVariant, HmacVariant, constant_time_eq};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::*;
use std::collections::HashMap;

fn assert_err_kind(err: Result<impl std::fmt::Debug>, kind: ErrorKind, ctx: &str) {
    let e = err.expect_err(ctx);
    assert_eq!(
        e.kind(),
        &kind,
        "{ctx}: expected {kind:?}, got {:?} ({e})",
        e.kind()
    );
}

/// RFC9173-020: production constant_time_eq rejects last-byte mismatch, accepts match.
#[test]
fn test_rfc9173_020_constant_time_eq_via_production_fn() {
    let tag = vec![0x11u8; 32];
    let mut bad = tag.clone();
    bad[31] ^= 0xff;
    assert!(
        constant_time_eq(&tag, &tag),
        "RFC9173-020: matching tags MUST be accepted"
    );
    assert!(
        !constant_time_eq(&tag, &bad),
        "RFC9173-020: last-byte mismatch MUST be rejected"
    );
}

/// RFC9173-080: limit unsuccessful BCB decrypt attempts per key.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_080_failed_bcb_verify_limit_enforced() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let key = vec![0x42u8; 16];
    let wrong = vec![0x99u8; 16];
    let plaintext = b"limit-me".to_vec();

    let make = |iv_tail| {
        let mut bundle = BundleBuilder::new()
            .source(source.clone())
            .destination(dest.clone())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(iv_tail), 0))
            .lifetime(60_000)
            .payload(plaintext.clone())
            .build()
            .unwrap();
        let mut iv = vec![0u8; 12];
        iv[11] = iv_tail as u8;
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
        bundle.blocks[0].data = cts[0].clone();
        bundle.blocks.insert(0, bcb);
        BundleCodec::encode(&bundle).unwrap()
    };

    let mut sec = SecurityContext::new();
    sec.add_aes_key(source.clone(), wrong); // wrong key → decrypt fails
    sec.set_max_failed_bcb_verifies_per_key(Some(2));

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

    // Two failures count toward limit
    assert_err_kind(
        agent.receive_bytes_from_cla(&make(1)),
        ErrorKind::SecurityFailure,
        "RFC9173-080 fail 1",
    );
    assert_err_kind(
        agent.receive_bytes_from_cla(&make(2)),
        ErrorKind::SecurityFailure,
        "RFC9173-080 fail 2",
    );
    // Swap in the correct key: limit must still block (proves counter, not key)
    if let Some(ctx) = agent.security_context_mut() {
        ctx.add_aes_key(source.clone(), key.clone());
    }
    assert_err_kind(
        agent.receive_bytes_from_cla(&make(3)),
        ErrorKind::SecurityFailure,
        "RFC9173-080 after limit with correct key",
    );
    assert!(agent.delivered_adus().is_empty());
    assert_eq!(agent.storage().usage().bundle_count, 0);
    assert!(agent.cla_tx_queue().is_empty());
}

/// RFC9173-081: decrypt-side replay detection rejects replayed bundle.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_081_decrypt_rejects_replayed_iv() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let key = vec![0x55u8; 16];
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(20), 0))
        .lifetime(60_000)
        .payload(b"replay".to_vec())
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
            iv: vec![0x77u8; 12],
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: true,
        },
        None,
    )
    .unwrap();
    bcb.block_number = 2;
    bundle.blocks[0].data = cts[0].clone();
    bundle.blocks.insert(0, bcb);
    let wire = BundleCodec::encode(&bundle).unwrap();

    let mut sec = SecurityContext::new();
    sec.add_aes_key(source, key);
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
    assert_eq!(agent.delivered_adus().len(), 1);

    // Replay same ciphertext+IV
    let delivered_before = agent.delivered_adus().len();
    assert_err_kind(
        agent.receive_bytes_from_cla(&wire),
        ErrorKind::SecurityFailure,
        "RFC9173-081 replayed IV",
    );
    assert_eq!(
        agent.delivered_adus().len(),
        delivered_before,
        "RFC9173-081: replay MUST NOT deliver again"
    );
}

/// RFC9171-4-053: when age exceeds lifetime, bundle SHOULD be deleted (agent path).
#[test]
fn test_rfc9171_4_053_expiry_deletes_bundle_from_storage() {
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
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(1_000) // 1 second
        .payload(b"expire-me".to_vec())
        .build()
        .unwrap();
    let id = agent.send(bundle).unwrap();
    // Before expiry: still stored
    assert!(agent.storage().get(&id).is_some());
    // Advance past lifetime
    agent.poll(SimInstant::from_nanos(2_000_000_000)); // 2s
    assert!(
        agent.storage().get(&id).is_none(),
        "RFC9171-4-053: expired bundle SHOULD be deleted from storage"
    );
    // Must not be forwarded after expiry
    assert!(
        agent.cla_tx_queue().iter().all(|t| t.bundle_id != id),
        "RFC9171-4-053: expired bundle MUST NOT remain for forwarding"
    );
}

/// RFC9172-015: if any security operation in a block is processed, process all.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_015_process_all_security_operations_in_block() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let hmac = vec![0xABu8; 32];
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(30), 0))
        .lifetime(60_000)
        .payload(b"multi-op".to_vec())
        .build()
        .unwrap();
    let hop = HopCountBlock::new(2, 8, 0).unwrap().to_canonical().unwrap();
    let hop_num = hop.block_number;
    bundle.blocks.insert(0, hop);

    let mut bib = generate_bib(
        &bundle,
        &BibConfig {
            security_source: source.clone(),
            targets: BibTargets {
                block_numbers: vec![1, hop_num],
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
    bib.block_number = 3;
    bundle.blocks.insert(0, bib);

    // Tamper hop only — first target (payload) still valid; second op must still run
    if let Some(h) = bundle.blocks.iter_mut().find(|b| b.block_number == hop_num) {
        h.data[0] ^= 0xff;
    }
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
        agent.receive_bytes_from_cla(&wire),
        ErrorKind::SecurityFailure,
        "RFC9172-015 second-target failure",
    );
    assert!(
        agent.delivered_adus().is_empty(),
        "RFC9172-015: must not deliver when later security operation fails"
    );
    assert_eq!(agent.storage().usage().bundle_count, 0);
    assert!(agent.cla_tx_queue().is_empty());
}

/// RFC9172-103: waypoint payload integrity failure ≡ destination failure policy.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_103_waypoint_payload_integrity_failure_like_destination() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let waypoint = EndpointId::ipn(0, 2, 0).unwrap();
    let dest = EndpointId::ipn(0, 3, 0).unwrap();
    let hmac = vec![0xCDu8; 32];
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(40), 0))
        .lifetime(60_000)
        .payload(b"wp-fail".to_vec())
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
    // Tamper payload after BIB
    bundle
        .blocks
        .iter_mut()
        .find(|b| b.block_number == 1)
        .unwrap()
        .data[0] ^= 0xff;
    let wire = BundleCodec::encode(&bundle).unwrap();

    let mut routes = HashMap::new();
    routes.insert(dest, NodeId::ipn(0, 3));
    let mut sec = SecurityContext::new();
    sec.add_hmac_key(source, hmac);
    // waypoint verifies but is not destination
    let mut wp = BundleAgent::new(
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
    assert_err_kind(
        wp.receive_bytes_from_cla(&wire),
        ErrorKind::SecurityFailure,
        "RFC9172-103 waypoint integrity failure",
    );
    assert!(wp.cla_tx_queue().is_empty());
    assert_eq!(wp.storage().usage().bundle_count, 0);
    assert!(wp.delivered_adus().is_empty());
}
