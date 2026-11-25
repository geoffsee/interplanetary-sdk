//! RFC 9172 §3.6 Malformed ASB Rejection Tests
//!
//! Verifies that bundles with malformed security blocks are rejected at reception.
//! Tests receiver-side validation of CBOR structure per RFC 9172 §3.6.
#![cfg(feature = "bpsec-default")]

use interplanetary_sdk::{
    bp::*,
    bpa::{BpaConfig, BundleAgent},
    sim::StorageManager,
    types::*,
};

fn create_test_agent() -> (BundleAgent, EndpointId) {
    let local_eid = EndpointId::ipn(0, 1, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    (BundleAgent::new(config, storage), local_eid)
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_019_020_targets_not_array_rejected() {
    // RFC 9172 §3.6: Security targets SHALL be CBOR array (receiver must reject non-array)

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with targets as integer (not array) - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x01, // targets: integer 1 (should be array [1]) - VIOLATES §3.6
            0x01, // context ID
            0x01, // flags
            0x82, 0x01, 0x00, // source: ipn:1.0
            0x80, // params: []
            0x80, // results: []
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with targets not CBOR array MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("array"),
        "Error should reference RFC 9172 §3.6 and array. Got: {}",
        err
    );

    // NOT delivered
    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_021_empty_targets_rejected() {
    // RFC 9172 §3.6: Targets array MUST have at least one entry

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with empty targets array - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x80, // targets: empty array [] - VIOLATES §3.6 "at least one entry"
            0x01, // context ID
            0x01, // flags
            0x82, 0x01, 0x00, // source: ipn:1.0
            0x80, // params: []
            0x80, // results: []
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with empty targets array MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("at least one"),
        "Error should reference RFC 9172 §3.6 and 'at least one'. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_016_target_not_integer_rejected() {
    // RFC 9172 §3.4/3.6: Target MUST be represented as block number (integer)

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with target as string (not integer) - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x61, 0x31, // targets: ["1"] (string, not integer) - VIOLATES §3.4/3.6
            0x01, // context ID
            0x01, // flags
            0x82, 0x01, 0x00, // source
            0x80, // params
            0x80, // results
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with target not integer MUST be rejected per RFC 9172 §3.4/3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.4") || err.contains("3.6"),
        "Error should reference RFC 9172 §3.4 or §3.6. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_023_context_id_not_integer_rejected() {
    // RFC 9172 §3.6: Context ID SHALL be CBOR unsigned integer

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with context ID as string - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1]
            0x62, 0x30, 0x31, // context ID: "01" (string) - VIOLATES §3.6
            0x01, // flags
            0x82, 0x01, 0x00, // source
            0x80, // params
            0x80, // results
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with context ID not integer MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("context ID"),
        "Error should reference RFC 9172 §3.6 and context ID. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_036_results_count_mismatch_rejected() {
    // RFC 9172 §3.6: One result per target

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with 1 target but 2 results - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1] (one target)
            0x01, // context ID
            0x01, // flags
            0x82, 0x01, 0x00, // source
            0x80, // params
            // results: 2 results for 1 target - VIOLATES §3.6
            0x82, // array of 2
            0x81, 0x81, 0x01, 0x40, // result 1
            0x81, 0x81, 0x01, 0x40, // result 2
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with result count != target count MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("one result per target"),
        "Error should reference RFC 9172 §3.6 and result count. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_030_params_not_array_rejected() {
    // RFC 9172 §3.6: Parameters SHALL be CBOR array

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with params as integer - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1]
            0x01, // context ID
            0x01, // flags
            0x82, 0x01, 0x00, // source
            0x00, // params: integer 0 (not array) - VIOLATES §3.6
            0x80, // results
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with params not array MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("parameters"),
        "Error should reference RFC 9172 §3.6 and parameters. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_034_results_not_array_rejected() {
    // RFC 9172 §3.6: Results SHALL be CBOR array

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with results as integer - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1]
            0x01, // context ID
            0x01, // flags
            0x82, 0x01, 0x00, // source
            0x80, // params: []
            0x00, // results: integer 0 (not array) - VIOLATES §3.6
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with results not array MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("results"),
        "Error should reference RFC 9172 §3.6 and results. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_024_flags_not_integer_rejected() {
    // RFC 9172 §3.6: Flags SHALL be CBOR unsigned integer

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with flags as array - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1]
            0x01, // context ID
            0x80, // flags: empty array [] (not integer) - VIOLATES §3.6
            0x82, 0x01, 0x00, // source
            0x80, // params
            0x80, // results
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with flags not integer MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("flags"),
        "Error should reference RFC 9172 §3.6 and flags. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}

#[test]
#[cfg(feature = "bpsec-default")]
fn test_rfc9172_029_source_not_eid_array_rejected() {
    // RFC 9172 §3.6: Source SHALL be CBOR EID array per RFC 9171

    let (mut agent, local_eid) = create_test_agent();

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(local_eid)
        .creation_timestamp(timestamp)
        .lifetime(1000000)
        .payload(vec![0x42; 100])
        .build()
        .unwrap();

    // Hand-craft BIB with source as integer (not EID array) - MALFORMED
    let malformed_bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![
            0x81, 0x01, // targets: [1]
            0x01, // context ID
            0x01, // flags
            0x01, // source: integer 1 (not array) - VIOLATES §3.6
            0x80, // params
            0x80, // results
        ],
    };
    bundle.blocks.insert(0, malformed_bib);

    // Reception MUST fail
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with source not EID array MUST be rejected per RFC 9172 §3.6"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("3.6") && err.contains("source"),
        "Error should reference RFC 9172 §3.6 and source. Got: {}",
        err
    );

    agent.poll(SimInstant::from_nanos(100));
    assert_eq!(agent.delivered_adus().len(), 0);
}
