//! RFC 9171 §5.8 Bundle Fragmentation at the Node
//!
//! Tests node-level fragmentation behavior when bundles exceed CLA MTU limits.

use interplanetary_sdk::bp::{BlockType, BundleBuilder};
use interplanetary_sdk::bpa::policy::StatusReportPolicy;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

fn create_test_agent_with_mtu(mtu: Bytes) -> BundleAgent {
    use std::collections::HashMap;

    // Default route for ipn:0.2.0 destination used by fragmentation tests
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 2, 0).unwrap(), NodeId::ipn(0, 2));

    let config = BpaConfig {
        local_node: NodeId::dtn("node1"),
        local_eid: EndpointId::dtn("node1").unwrap(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: Some(mtu),
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    BundleAgent::new(config, storage)
}

#[test]
fn test_rfc9171_5_051_fragment_bundle_exceeding_mtu() {
    // RFC 9171 §5.8: "To fragment a bundle whose payload is of size M is to replace
    // it with two 'fragments' -- new bundles with the same source node ID and
    // creation timestamp as the original bundle -- whose payloads MUST be the
    // first N and the last (M - N) bytes of the original bundle's payload"

    use interplanetary_sdk::types::SimInstant;

    let mut agent = create_test_agent_with_mtu(Bytes(200));

    // Create large bundle that will exceed MTU (received from another node)
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 42))
        .lifetime(60_000)
        .payload(vec![0xAA; 500]) // Large payload
        .build()
        .unwrap();

    // Production path: receive from CLA, poll triggers automatic forward with fragmentation
    let _bundle_id = agent.receive_from_cla(bundle.clone()).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Should have multiple fragments queued
    let fragments = agent.cla_tx_queue();
    assert!(fragments.len() >= 2, "Should produce multiple fragments");

    // Verify fragments have same source and timestamp
    for frag_tx in fragments {
        let frag = &frag_tx.bundle;
        assert_eq!(
            frag.primary.source, bundle.primary.source,
            "Fragment source must match original"
        );
        assert_eq!(
            frag.primary.creation_timestamp, bundle.primary.creation_timestamp,
            "Fragment timestamp must match original"
        );
        assert!(
            frag.primary.fragment_offset.is_some(),
            "Fragment must have offset"
        );
        assert_eq!(
            frag.primary.total_app_data_length,
            Some(500),
            "Fragment must have total ADU length"
        );
    }

    // Verify payload concatenation would be identical
    let mut reconstructed = Vec::new();
    let mut sorted_frags: Vec<_> = fragments.iter().collect();
    sorted_frags.sort_by_key(|tx| tx.bundle.primary.fragment_offset.unwrap());

    for frag_tx in sorted_frags {
        let payload = frag_tx
            .bundle
            .blocks
            .iter()
            .find(|b| b.block_type == BlockType::Payload)
            .unwrap();
        reconstructed.extend_from_slice(&payload.data);
    }

    assert_eq!(
        reconstructed.len(),
        500,
        "Concatenated payload length must match"
    );
    assert_eq!(reconstructed[0], 0xAA, "Payload content must be preserved");
}

#[test]
fn test_rfc9171_5_056_fragment_offset_and_total_length() {
    // RFC 9171 §5.8: "The primary block of each fragment MUST differ from that
    // of the fragmented bundle, in that the bundle processing control flags of
    // the fragment MUST indicate that the bundle is a fragment and both fragment
    // offset and total application data unit length must be provided."

    use interplanetary_sdk::types::SimInstant;

    let mut agent = create_test_agent_with_mtu(Bytes(150));

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0xBB; 300])
        .build()
        .unwrap();

    // Production path: receive from CLA, poll triggers automatic forward with fragmentation
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    let fragments = agent.cla_tx_queue();
    assert!(fragments.len() >= 2, "Should produce fragments");

    for frag_tx in fragments {
        let frag = &frag_tx.bundle;

        // Verify is-fragment flag is set (bit 20)
        assert!(
            frag.primary.is_fragment(),
            "Fragment must have is-fragment flag"
        );

        // Verify offset and total length are present
        assert!(
            frag.primary.fragment_offset.is_some(),
            "Fragment offset must be provided"
        );
        assert_eq!(
            frag.primary.total_app_data_length,
            Some(300),
            "Total ADU length must be provided"
        );

        let offset = frag.primary.fragment_offset.unwrap();
        let payload = frag
            .blocks
            .iter()
            .find(|b| b.block_type == BlockType::Payload)
            .unwrap();
        let frag_len = payload.data.len() as u64;

        // Verify offset + length <= total
        assert!(
            offset + frag_len <= 300,
            "Fragment must not exceed total length"
        );
    }
}

#[test]
fn test_rfc9171_5_052_must_not_fragment_flag_honored() {
    // RFC 9171 §5.8: "Any bundle whose primary block's bundle processing control
    // flags do NOT indicate that it must not be fragmented MAY be fragmented"
    // (Implicit: if flag is set, bundle MUST NOT be fragmented)

    use interplanetary_sdk::types::SimInstant;

    let mut agent = create_test_agent_with_mtu(Bytes(100));

    // Create large bundle with must-not-fragment flag (received from another node)
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0xCC; 500])
        .build()
        .unwrap();

    // Set must-not-fragment flag (bit 2)
    bundle.primary.bundle_flags |= 0x000004;

    // Production path: receive from CLA, poll triggers automatic forward attempt
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Bundle should be deleted (exceeds MTU but cannot be fragmented)
    // No fragments should be queued
    let fragments = agent.cla_tx_queue();
    assert_eq!(
        fragments.len(),
        0,
        "No fragments should be created when must-not-fragment is set"
    );
}

#[test]
fn test_rfc9171_5_058_extension_blocks_in_first_fragment() {
    // RFC 9171 §5.8: "If the fragmented bundle is not a fragment or is the
    // fragment with offset zero, then all extension blocks of the fragmented
    // bundle MUST be replicated in the fragment whose offset is zero."

    use interplanetary_sdk::types::SimInstant;

    let mut agent = create_test_agent_with_mtu(Bytes(200));

    // Create bundle (received from another node) - forward will add previous node extension block
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0xDD; 400])
        .build()
        .unwrap();

    // Production path: receive from CLA, poll triggers automatic forward with fragmentation
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    let fragments = agent.cla_tx_queue();
    assert!(fragments.len() >= 2, "Should produce fragments");

    // Find first fragment (offset 0)
    let first_frag = fragments
        .iter()
        .find(|tx| tx.bundle.primary.fragment_offset == Some(0))
        .expect("First fragment must exist");

    // Find non-first fragment
    let other_frag = fragments
        .iter()
        .find(|tx| tx.bundle.primary.fragment_offset != Some(0))
        .expect("Other fragment must exist");

    // Count extension blocks (excluding payload)
    let first_ext_count = first_frag
        .bundle
        .blocks
        .iter()
        .filter(|b| b.block_type != BlockType::Payload)
        .count();

    let other_ext_count = other_frag
        .bundle
        .blocks
        .iter()
        .filter(|b| b.block_type != BlockType::Payload)
        .count();

    // First fragment should have more or equal extension blocks than other fragments
    assert!(
        first_ext_count >= other_ext_count,
        "First fragment must contain at least as many extension blocks as others"
    );
}

#[test]
fn test_rfc9171_5_059_replicate_in_every_fragment() {
    // RFC 9171 §5.8: "Each of the fragmented bundle's extension blocks whose
    // 'Block must be replicated in every fragment' flag is set to 1 MUST be
    // replicated in every fragment."

    use interplanetary_sdk::types::SimInstant;

    let mut agent = create_test_agent_with_mtu(Bytes(180));

    // Create bundle - previous node block added by forward doesn't have replicate flag
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0xEE; 350])
        .build()
        .unwrap();

    // Production path: receive from CLA, poll triggers automatic forward with fragmentation
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    let fragments = agent.cla_tx_queue();
    assert!(fragments.len() >= 2, "Should produce multiple fragments");

    // Count how many fragments have previous node block
    let with_prev_node = fragments
        .iter()
        .filter(|tx| {
            tx.bundle
                .blocks
                .iter()
                .any(|b| b.block_type == BlockType::PreviousNode)
        })
        .count();

    // Previous node block should be in first fragment only (no replicate flag)
    assert!(
        with_prev_node < fragments.len() || with_prev_node == 1,
        "Previous node block should not be in all fragments (no replicate flag)"
    );
}

#[test]
fn test_rfc9171_5_057_fragment_crc_recomputed() {
    // RFC 9171 §5.8: "Additionally, the CRC of the primary block of the
    // fragmented bundle, if any, MUST be replaced in each fragment by a new
    // CRC computed for the primary block of that fragment."

    use interplanetary_sdk::types::SimInstant;

    let mut agent = create_test_agent_with_mtu(Bytes(150));

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0xFF; 280])
        .build()
        .unwrap();

    // Production path: receive from CLA, poll triggers automatic forward with fragmentation
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    let fragments = agent.cla_tx_queue();

    // Verify each fragment can be encoded/decoded (CRC is valid)
    for frag_tx in fragments {
        let encoded = interplanetary_sdk::bp::encode(&frag_tx.bundle)
            .expect("Fragment must encode with valid CRC");

        let decoded = interplanetary_sdk::bp::decode(&encoded)
            .expect("Fragment must decode successfully (CRC valid)");

        assert_eq!(
            decoded.primary.fragment_offset, frag_tx.bundle.primary.fragment_offset,
            "Decoded fragment must match"
        );
    }
}

#[test]
fn test_node_fragmentation_no_mtu_no_fragmentation() {
    use std::collections::HashMap;

    // When no MTU is configured, bundle should forward without fragmentation
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 2, 0).unwrap(), NodeId::ipn(0, 2));

    let config = BpaConfig {
        local_node: NodeId::dtn("node1"),
        local_eid: EndpointId::dtn("node1").unwrap(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: None, // No MTU limit,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0xAA; 1000]) // Large payload
        .build()
        .unwrap();

    // Production path: receive from CLA, poll triggers automatic forward (no fragmentation)
    use interplanetary_sdk::types::SimInstant;
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    let transmitted = agent.cla_tx_queue();
    assert_eq!(
        transmitted.len(),
        1,
        "Should forward single bundle when no MTU limit"
    );
    assert!(
        transmitted[0].bundle.primary.fragment_offset.is_none(),
        "Bundle should not be a fragment"
    );
}
