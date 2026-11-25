//! RFC9173-076 / RFC9173-094: Unique (key, IV) pairing on production path
//!
//! Originate two bundles through BundleAgent::send + poll with the same AES key.
//! Assert the BCB IV security-context parameters parsed from cla_tx_queue bytes
//! are distinct (NonceRegistry-backed unique IV minting).
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use ciborium::Value;
use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, OutboundBcbConfig, StatusReportPolicy};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;
use std::collections::HashMap;
use std::io::Cursor;

/// Extract BCB IV parameter (parameter ID 1) from an encoded bundle's BCB block.
fn extract_bcb_iv(bundle_bytes: &[u8]) -> Vec<u8> {
    let bundle = BundleCodec::decode(bundle_bytes).expect("decode emitted bundle");
    let bcb = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .expect("emitted bundle must contain a BCB");

    let mut cursor = Cursor::new(&bcb.data);
    // targets, context_id, flags, source
    let _targets = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    let _ctx = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    let _flags = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    let _source = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();
    let params = ciborium::from_reader::<Value, _>(&mut cursor).unwrap();

    let arr = match params {
        Value::Array(a) => a,
        other => panic!("BCB params must be array, got {other:?}"),
    };
    for param in arr {
        if let Value::Array(pair) = param
            && pair.len() == 2
            && let Value::Integer(id) = &pair[0]
        {
            let id: u64 = (*id).try_into().unwrap();
            if id == 1 {
                // IV parameter
                if let Value::Bytes(iv) = &pair[1] {
                    return iv.clone();
                }
                panic!("IV parameter value must be byte string");
            }
        }
    }
    panic!("BCB missing IV parameter (ID 1)");
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_076_094_distinct_ivs_from_agent_cla_tx() {
    // Same key for both originations; agent must mint distinct IVs.
    let key_id = b"prod-key-1".to_vec();
    let key = vec![0xAB; 16];

    let dest = EndpointId::ipn(0, 2, 0).unwrap();
    let mut routes = HashMap::new();
    routes.insert(dest.clone(), NodeId::ipn(0, 2));

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: EndpointId::ipn(0, 1, 1).unwrap(),
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
        outbound_bcb: Some(OutboundBcbConfig::aes128(key_id, key)),
    };

    let mut agent = BundleAgent::new(config, StorageManager::new(Bytes::from_mib(10).unwrap()));

    for seq in 0u64..2 {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 1).unwrap())
            .destination(dest.clone())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), seq))
            .lifetime(60_000)
            .crc_type(CrcType::Crc16)
            .payload(format!("payload-{seq}").into_bytes())
            .build()
            .unwrap();
        agent.send(bundle).unwrap();
    }

    agent.poll(SimInstant::from_nanos(0));

    let queue = agent.cla_tx_queue();
    assert_eq!(
        queue.len(),
        2,
        "Both secured bundles must be queued for CLA transmission"
    );

    let bytes0 = BundleCodec::encode(&queue[0].bundle).unwrap();
    let bytes1 = BundleCodec::encode(&queue[1].bundle).unwrap();

    let iv0 = extract_bcb_iv(&bytes0);
    let iv1 = extract_bcb_iv(&bytes1);

    assert_eq!(iv0.len(), 12, "AES-GCM IV must be 12 bytes");
    assert_eq!(iv1.len(), 12, "AES-GCM IV must be 12 bytes");
    assert_ne!(
        iv0, iv1,
        "RFC9173-076/094: same key MUST NOT reuse IV; IVs from cla_tx_queue must differ"
    );
}
