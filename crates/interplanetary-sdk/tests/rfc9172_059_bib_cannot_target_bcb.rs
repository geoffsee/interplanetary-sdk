//! RFC9172-059: BIB MUST NOT have a BCB as its security target (§3.9)
//!
//! Production path: encode a violating bundle and feed it through
//! BundleAgent::receive_bytes_from_cla + poll. Assert rejection and no
//! delivery / no CLA transmission.

use interplanetary_sdk::bp::codec::BundleCodec;
use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;

fn create_agent(local: EndpointId) -> BundleAgent {
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: local,
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
        static_routes: None,
        forwarding_failed_policy: Default::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    BundleAgent::new(config, StorageManager::new(Bytes::from_mib(10).unwrap()))
}

/// RFC9172-059: Bundle with BIB targeting a BCB is rejected on the production path.
#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_059_bib_targeting_bcb_rejected_receive_bytes() {
    let local = EndpointId::ipn(0, 1, 0).unwrap();
    let mut agent = create_agent(local.clone());

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 1))
        .lifetime(1_000_000)
        .crc_type(CrcType::Crc16)
        .payload(vec![0x42; 32])
        .build()
        .unwrap();

    // BCB targeting payload (block 1)
    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 1,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1]
            0x02, // context ID 2
            0x01, // flags
            0x82, 0x02, 0x82, 0x02, 0x01, // source EID (minimal ipn-ish)
            0x80, // params
            0x81, 0x81, 0x82, 0x01, 0x40, // results
        ],
    };
    bundle.blocks.insert(0, bcb);

    // BIB targeting the BCB (block 2) — VIOLATES RFC 9172 §3.9 / §3.7
    let bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 3,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x02, // targets: [2] (BCB)
            0x01, // context ID 1
            0x01, // flags
            0x82, 0x02, 0x82, 0x02, 0x01, // source
            0x80, // params
            0x81, 0x81, 0x82, 0x01, 0x40, // results
        ],
    };
    bundle.blocks.insert(0, bib);

    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Production reception path
    let result = agent.receive_bytes_from_cla(&encoded);
    assert!(
        result.is_err(),
        "RFC9172-059: BIB targeting BCB MUST be rejected by BundleAgent"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Security") || err.contains("validation") || err.contains("3.3"),
        "Error must cite security validation failure, got: {err}"
    );

    agent.poll(SimInstant::from_nanos(0));

    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Violating bundle MUST NOT be delivered"
    );
    assert_eq!(
        agent.cla_tx_queue().len(),
        0,
        "Violating bundle MUST NOT be forwarded"
    );
}
