//! Gap-closing batch 7: RFC 9171 §5–6 + RFC 9173-012 production-path tests
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::admin::{ReasonCode, bundle_flags};
use interplanetary_sdk::bpa::security_processing::SecurityContext;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
use interplanetary_sdk::security::AesGcmVariant;
use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

/// RFC9171-6-019: admin record for a fragment MUST contain fragment offset and length.
/// RFC9171-6-020: transmission of that admin record MUST be presented to the BPA.
#[test]
fn test_rfc9171_6_019_020_fragment_status_report_via_agent() {
    let local = EndpointId::ipn(0, 1, 0).unwrap();
    let report_to = EndpointId::ipn(0, 9, 0).unwrap();
    let mut routes = HashMap::new();
    routes.insert(report_to.clone(), NodeId::ipn(0, 9));

    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: local.clone(),
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy {
                report_on_reception: false,
                report_on_forwarding: false,
                report_on_delivery: false,
                report_on_deletion: true,
                report_to: Some(report_to.clone()),
            },
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

    let frag_payload = vec![0xAAu8; 40];
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 2, 1).unwrap())
        .destination(local)
        .report_to(report_to)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .crc_type(CrcType::None)
        .payload(frag_payload.clone())
        .build()
        .unwrap();
    bundle.primary.bundle_flags |=
        bundle_flags::IS_FRAGMENT | bundle_flags::REQUEST_REPORT_DELETION;
    bundle.primary.fragment_offset = Some(80);
    bundle.primary.total_app_data_length = Some(200);

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let bundle_id = agent.receive_bytes_from_cla(&encoded).unwrap();

    agent
        .delete_bundle(&bundle_id, ReasonCode::LifetimeExpired)
        .unwrap();

    // 6-019: generated report carries fragment offset + length
    assert!(
        !agent.generated_reports().is_empty(),
        "deletion report MUST be generated"
    );
    let report = &agent.generated_reports()[0];
    assert_eq!(
        report.fragment_offset,
        Some(80),
        "RFC9171-6-019: fragment offset MUST be present"
    );
    assert_eq!(
        report.fragment_length,
        Some(frag_payload.len() as u64),
        "RFC9171-6-019: fragment length MUST be present"
    );

    // 6-020: admin bundle presented for transmission (on cla_tx_queue after poll)
    agent.poll(SimInstant::ZERO);
    let admin_tx = agent
        .cla_tx_queue()
        .iter()
        .find(|tx| (tx.bundle.primary.bundle_flags & bundle_flags::IS_ADMIN_RECORD) != 0);
    assert!(
        admin_tx.is_some(),
        "RFC9171-6-020: admin-record transmission MUST be presented to BPA (cla_tx_queue)"
    );
}

/// RFC9171-5-066: cancel_transmission deletes undiscarded bundle for Transmission cancelled.
#[test]
fn test_rfc9171_5_066_cancel_transmission_via_agent() {
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
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"cancel-me".to_vec())
        .build()
        .unwrap();
    let id = agent.send(bundle).unwrap();
    // Not yet discarded (still in storage with DispatchPending)
    agent.cancel_transmission(&id).unwrap();
    assert_eq!(
        agent.get_state(&id),
        Some(interplanetary_sdk::bpa::BundleState::Deleted),
        "RFC9171-5-066: cancelled transmission MUST delete the bundle"
    );
    agent.poll(SimInstant::ZERO);
    assert!(
        agent.cla_tx_queue().is_empty(),
        "cancelled bundle MUST NOT be forwarded"
    );
}

/// RFC9171-4-064: primary CRC SHALL be present unless BIB targets primary.
#[test]
fn test_rfc9171_4_064_primary_crc_unless_bib_via_agent() {
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
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 2))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"crc64".to_vec())
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
        "control: no primary BIB"
    );
    assert_ne!(emitted.primary.crc_type, CrcType::None);
    let prim = BundleCodec::encode_primary(&emitted.primary).unwrap();
    let val: Value = ciborium::from_reader(prim.as_slice()).unwrap();
    let Value::Array(arr) = val else {
        panic!("primary");
    };
    match arr.last() {
        Some(Value::Bytes(b)) if b.len() == 2 => {}
        other => panic!("RFC9171-4-064: CRC bytes MUST be present, got {other:?}"),
    }
}

/// RFC9173-012: without wrapped-key parameter, acceptor MUST use local policy key.
#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_012_local_policy_key_when_no_wrapped_key() {
    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let key = vec![0x77; 16];
    let plaintext = b"policy-key".to_vec();

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
            iv: vec![0x02; 12],
            wrapped_key: None, // parameter absent
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

    // Confirm ASB has no wrapped-key param (id 3)
    let mut cur = Cursor::new(&bundle.blocks[0].data);
    let _targets = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let _ctx = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let _flags = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let _src = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    let params = ciborium::from_reader::<Value, _>(&mut cur).unwrap();
    if let Value::Array(ps) = params {
        for p in &ps {
            if let Value::Array(kv) = p
                && let Some(Value::Integer(id)) = kv.first()
            {
                assert_ne!(
                    u64::try_from(*id).unwrap_or(0),
                    3,
                    "control: wrapped-key param MUST be absent"
                );
            }
        }
    }

    let wire = BundleCodec::encode(&bundle).unwrap();
    let mut sec = SecurityContext::new();
    sec.add_aes_key(source, key); // local policy key
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
    recv.receive_bytes_from_cla(&wire).unwrap();
    recv.poll(SimInstant::from_nanos(100_000_000));
    assert_eq!(recv.delivered_adus().len(), 1);
    let pl = recv.delivered_adus()[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .unwrap();
    assert_eq!(
        pl.data, plaintext,
        "RFC9173-012: local policy key MUST decrypt when wrapped-key param absent"
    );
}
