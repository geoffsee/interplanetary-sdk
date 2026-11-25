//! Gap-closing batch 6: RFC 9171 production-path tests

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::admin::{ReasonCode, StatusReport, create_status_report_bundle};
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

fn forwarding_agent() -> BundleAgent {
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
            outbound_bcb: None,
        },
        StorageManager::new(Bytes::from_mib(10).unwrap()),
    )
}

/// RFC9171-4-035: ipn scheme-specific part SHALL be a CBOR array of two items (allocator 0).
#[test]
fn test_rfc9171_4_035_ipn_ssp_two_element_via_agent() {
    let mut agent = forwarding_agent();
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"ipn".to_vec())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let prim = BundleCodec::encode_primary(&agent.cla_tx_queue()[0].bundle.primary).unwrap();
    let val: Value = ciborium::from_reader(prim.as_slice()).unwrap();
    let Value::Array(arr) = val else {
        panic!("primary array");
    };
    // destination EID at index 3: [scheme=2, ssp]
    let Value::Array(dest) = &arr[3] else {
        panic!("dest EID array");
    };
    assert_eq!(dest.len(), 2);
    match &dest[0] {
        Value::Integer(s) => assert_eq!(u64::try_from(*s).unwrap(), 2),
        other => panic!("scheme MUST be int, got {other:?}"),
    }
    match &dest[1] {
        Value::Array(ssp) => {
            assert_eq!(
                ssp.len(),
                2,
                "RFC9171-4-035: ipn SSP SHALL be CBOR array of two items"
            );
        }
        other => panic!("SSP MUST be array, got {other:?}"),
    }
}

/// RFC9171-4-043: block-type-specific data SHALL be CBOR encoding of block content.
#[test]
fn test_rfc9171_4_043_btsd_cbor_via_agent() {
    let mut agent = forwarding_agent();
    let adu = b"block-content".to_vec();
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 1).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 1))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(adu.clone())
        .build()
        .unwrap();
    agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let encoded = BundleCodec::encode(&agent.cla_tx_queue()[0].bundle).unwrap();
    assert_eq!(encoded[0], 0x9F);
    let mut cur = Cursor::new(&encoded[1..encoded.len() - 1]);
    let mut payload_arr: Option<Vec<Value>> = None;
    while (cur.position() as usize) < encoded.len() - 2 {
        let Ok(val) = ciborium::from_reader::<Value, _>(&mut cur) else {
            break;
        };
        if let Value::Array(arr) = &val {
            // Canonical payload: type code 1 at element 0
            if let Some(Value::Integer(t)) = arr.first()
                && u64::try_from(*t).unwrap_or(0) == 1
                && arr.len() >= 5
            {
                payload_arr = Some(arr.clone());
            }
        }
    }
    let arr = payload_arr.expect("payload canonical block on wire");
    match &arr[4] {
        Value::Bytes(data) => {
            assert_eq!(
                data.as_slice(),
                adu.as_slice(),
                "RFC9171-4-043: BTSD MUST be CBOR byte string of block content"
            );
        }
        other => panic!("BTSD MUST be CBOR bytes, got {other:?}"),
    }
}

/// RFC9171-4-065/066: primary CRC length/nature per type; computed over bytes with CRC field zeroed.
#[test]
fn test_rfc9171_4_065_066_primary_crc_zeroed_computation_via_agent() {
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

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 2, 1).unwrap())
        .destination(local)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc16)
        .payload(b"crc".to_vec())
        .build()
        .unwrap();
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Valid CRC-16 accepted
    agent.receive_bytes_from_cla(&encoded).unwrap();
    agent.poll(SimInstant::ZERO);
    assert_eq!(agent.delivered_adus().len(), 1);

    // Flip a mid-bundle data byte so recomputed CRC (over zeroed CRC field) mismatches
    let mut bad = encoded.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    let err = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
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
    )
    .receive_bytes_from_cla(&bad);
    assert!(
        err.is_err(),
        "RFC9171-4-065/066: CRC computed over zeroed CRC field MUST reject corruption"
    );

    // CRC-16 field is 2 bytes (nature/length per type)
    let prim = BundleCodec::encode_primary(&bundle.primary).unwrap();
    assert_eq!(prim[prim.len() - 3], 0x42, "CRC-16 CBOR bstr header");
}

/// RFC9171-4-025: admin / null-source bundles MUST have block report-on-failure flag zero.
#[test]
fn test_rfc9171_4_025_admin_block_report_flag_zero_via_agent() {
    let reporting = EndpointId::ipn(0, 1, 0).unwrap();
    let report_to = EndpointId::ipn(0, 2, 0).unwrap();
    let report = StatusReport::deletion(
        EndpointId::ipn(0, 3, 1).unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(1), 0),
        ReasonCode::LifetimeExpired,
        None,
    );
    let admin =
        create_status_report_bundle(report, &reporting, &report_to, SimInstant::ZERO, 1, false)
            .unwrap();
    for b in &admin.blocks {
        assert_eq!(
            b.block_flags & 0x02,
            0,
            "RFC9171-4-025: generated admin block MUST clear report-on-failure"
        );
    }

    // Receive valid admin at BPA
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: NodeId::ipn(0, 2),
            local_eid: report_to.clone(),
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
    let good = BundleCodec::encode(&admin).unwrap();
    agent.receive_bytes_from_cla(&good).unwrap();

    // Mutate report-on-failure on payload → receive MUST reject
    let mut bad_admin = admin;
    if let Some(p) = bad_admin
        .blocks
        .iter_mut()
        .find(|b| matches!(b.block_type, BlockType::Payload))
    {
        p.block_flags |= 0x02;
    }
    let bad = BundleCodec::encode(&bad_admin).unwrap();
    let err = agent.receive_bytes_from_cla(&bad);
    assert!(
        err.is_err(),
        "RFC9171-4-025: admin with report-on-failure set MUST be rejected, got {err:?}"
    );
}
