//! RFC 9758 Behavioral Constraints - LocalNode and Private Use EID restrictions

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
#[cfg(feature = "tcpclv4-model")]
use interplanetary_sdk::tcpcl::{Role, SessionConfig, TcpclSession};
use interplanetary_sdk::types::{Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

/// RFC9758-022, 023: LocalNode source/destination MUST NOT leave local node
///
/// RFC 9758 §5.4: "any bundle using a LocalNode ipn EID as a bundle source or bundle
/// destination MUST NOT be allowed to leave the local node."
#[test]
fn test_rfc9758_022_023_localnode_source_dest_blocked() {
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();
    let local_node = NodeId::ipn(0, 100);

    let config = BpaConfig {
        local_node,
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: true,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config, storage);

    // Test 1: LocalNode source
    let localnode_source = EndpointId::ipn(0, 4294967295, 0).unwrap();
    assert!(localnode_source.is_local_node(), "Verify LocalNode EID");

    let bundle_localnode_src = BundleBuilder::new()
        .source(localnode_source)
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0xAA])
        .build()
        .unwrap();

    // Production path: receive bundle with LocalNode source, poll triggers forward attempt
    use interplanetary_sdk::types::SimInstant;
    let _bundle_id = agent.receive_from_cla(bundle_localnode_src).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Bundle should be deleted (LocalNode source cannot leave node)
    assert!(
        agent.storage().enumerate().is_empty(),
        "Bundle with LocalNode source must be deleted"
    );

    // CLA queue must be empty
    assert!(
        agent.cla_tx_queue().is_empty(),
        "LocalNode bundle must not appear in CLA tx queue"
    );

    // Test 2: LocalNode destination
    let bundle_localnode_dst = BundleBuilder::new()
        .source(local_eid.clone())
        .destination(EndpointId::ipn(0, 4294967295, 1).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 0))
        .lifetime(3600)
        .payload(vec![0xBB])
        .build()
        .unwrap();

    // Production path: receive bundle with LocalNode destination, poll triggers forward attempt
    let _bundle_id2 = agent.receive_from_cla(bundle_localnode_dst).unwrap();
    agent.poll(SimInstant::from_nanos(200_000_000));

    // Bundle should be deleted (LocalNode destination cannot leave node)
    assert!(
        agent.storage().enumerate().is_empty(),
        "Bundle with LocalNode destination must be deleted"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "LocalNode destination bundle must not appear in CLA tx queue"
    );
}

/// RFC9758-024, 025: LocalNode in report-to MUST NOT leave local node
///
/// RFC 9758 §5.4: "LocalNode ipn EIDs MUST NOT be present in any other part of a bundle
/// that is transmitted off of the local node."
#[test]
fn test_rfc9758_024_025_localnode_report_to_blocked() {
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();
    let local_node = NodeId::ipn(0, 100);

    let config = BpaConfig {
        local_node,
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: true,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config, storage);

    // Create bundle with LocalNode report-to
    let localnode_eid = EndpointId::ipn(0, 4294967295, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(local_eid.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .report_to(localnode_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3000), 0))
        .lifetime(3600)
        .payload(vec![0xCC])
        .build()
        .unwrap();

    // Production path: receive bundle with LocalNode report-to, poll triggers forward attempt
    use interplanetary_sdk::types::SimInstant;
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Bundle should be deleted (LocalNode report-to cannot leave node)
    assert!(
        agent.storage().enumerate().is_empty(),
        "Bundle with LocalNode report-to must be deleted"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "LocalNode report-to bundle must not appear in CLA tx queue"
    );
}

/// RFC9758-028: LocalNode MUST NOT be advertised in TCPCLv4 node_id
///
/// RFC 9758 §5.4: "For example, a LocalNode ipn EID MUST NOT be advertised as the
/// peer Node ID during session negotiation in [RFC9174]."
#[test]
#[cfg(feature = "tcpclv4-model")]
fn test_rfc9758_028_localnode_tcpcl_node_id_rejected() {
    // Attempt to create TCPCL session with LocalNode as node_id
    let localnode_string = "ipn:4294967295.0";

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: localnode_string.to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    // This must return an error per RFC 9758 §5.4
    let result = TcpclSession::new(config);
    assert!(result.is_err(), "LocalNode node_id must be rejected");
    assert!(
        result.unwrap_err().to_string().contains("LocalNode"),
        "Error must mention LocalNode"
    );
}

/// RFC9758-029, 031: Private Use EIDs MUST NOT cross administrative domains
///
/// RFC 9758 §5.5: "source or bundle destination MUST NOT be allowed to cross
/// administrative domains."
///
/// Note: We interpret any forwarding as crossing domains since the test harness
/// cannot determine administrative domain boundaries.
#[test]
fn test_rfc9758_029_031_private_use_blocked() {
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let local_eid = EndpointId::ipn(0, 100, 0).unwrap();
    let local_node = NodeId::ipn(0, 100);

    let config = BpaConfig {
        local_node,
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: false,
        status_report_policy: Default::default(),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: true,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let mut agent = BundleAgent::new(config, storage);

    // Test 1: Private Use source (node 1-16777215)
    let private_use_src = EndpointId::ipn(0, 100000, 0).unwrap();
    assert!(
        private_use_src.is_private_use_ipn(),
        "Verify Private Use EID"
    );

    let bundle_private_src = BundleBuilder::new()
        .source(private_use_src)
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(4000), 0))
        .lifetime(3600)
        .payload(vec![0xDD])
        .build()
        .unwrap();

    // Production path: receive bundle with Private Use source, poll triggers forward attempt
    use interplanetary_sdk::types::SimInstant;
    let _bundle_id = agent.receive_from_cla(bundle_private_src).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Bundle should be deleted (Private Use source cannot cross domains)
    assert!(
        agent.storage().enumerate().is_empty(),
        "Bundle with Private Use source must be deleted"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "Private Use bundle must not appear in CLA tx queue"
    );

    // Test 2: Private Use destination
    let private_use_dst = EndpointId::ipn(0, 50000, 1).unwrap();
    assert!(
        private_use_dst.is_private_use_ipn(),
        "Verify Private Use destination"
    );

    let bundle_private_dst = BundleBuilder::new()
        .source(local_eid.clone())
        .destination(private_use_dst)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(5000), 0))
        .lifetime(3600)
        .payload(vec![0xEE])
        .build()
        .unwrap();

    // Production path: receive bundle with Private Use destination, poll triggers forward attempt
    let _bundle_id2 = agent.receive_from_cla(bundle_private_dst).unwrap();
    agent.poll(SimInstant::from_nanos(200_000_000));

    // Bundle should be deleted (Private Use destination cannot cross domains)
    assert!(
        agent.storage().enumerate().is_empty(),
        "Bundle with Private Use destination must be deleted"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "Private Use destination bundle must not appear in CLA tx queue"
    );

    // Test 3: Private Use in report-to
    let bundle_private_report_to = BundleBuilder::new()
        .source(local_eid.clone())
        .destination(EndpointId::ipn(0, 300, 0).unwrap())
        .report_to(EndpointId::ipn(0, 75000, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(6000), 0))
        .lifetime(3600)
        .payload(vec![0xFF])
        .build()
        .unwrap();

    // Production path: receive bundle with Private Use report-to, poll triggers forward attempt
    let _bundle_id3 = agent.receive_from_cla(bundle_private_report_to).unwrap();
    agent.poll(SimInstant::from_nanos(300_000_000));

    // Bundle should be deleted (Private Use report-to cannot cross domains)
    assert!(
        agent.storage().enumerate().is_empty(),
        "Bundle with Private Use report-to must be deleted"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "Private Use report-to bundle must not appear in CLA tx queue"
    );
}
