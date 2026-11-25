//! RFC 9174 §5.2.4-121/122: BPA retry behaviour after XFER_REFUSE

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, RetentionConstraint, StatusReportPolicy};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::{
    Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId, SimInstant,
};
use std::collections::HashMap;

const NO_RESOURCES: u8 = 0x02;
const NOT_ACCEPTABLE: u8 = 0x04;

fn forwarding_agent(mtu: Option<u64>) -> BundleAgent {
    let local_node = NodeId::ipn(0, 100);
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 50, 0).unwrap(), NodeId::ipn(0, 50));
    let config = BpaConfig {
        local_node,
        local_eid: EndpointId::ipn(0, 100, 0).unwrap(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: mtu.map(Bytes),
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
    };
    BundleAgent::new(config, StorageManager::new(Bytes::from_mib(4).unwrap()))
}

/// RFC 9174 §5.2.4-121: After No Resources, next TX is reactively fragmented
#[test]
fn test_rfc9174_5_2_4_121_no_resources_reactive_fragment_retry() {
    let mut agent = forwarding_agent(None);
    let payload = vec![0xABu8; 2000];
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 100, 0).unwrap())
        .destination(EndpointId::ipn(0, 50, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1_000_000), 0))
        .lifetime(3_600_000)
        .payload(payload)
        .build()
        .unwrap();

    let _bundle_id = agent.send(bundle).unwrap();
    agent.poll(SimInstant::ZERO);

    let before = agent.cla_tx_queue().len();
    assert_eq!(before, 1, "initial transmission is one whole bundle");
    assert!(
        !agent.cla_tx_queue()[0].bundle.primary.is_fragment(),
        "initial TX must not be fragmented"
    );

    let tx_id = agent.cla_tx_queue()[0].bundle_id.clone();
    agent
        .notify_cla_transfer_refused(&tx_id, NO_RESOURCES)
        .unwrap();

    let queue = agent.cla_tx_queue();
    assert!(
        queue.len() > 1,
        "after No Resources, reactive fragments must be queued; got {}",
        queue.len()
    );
    assert!(
        queue.iter().all(|t| t.bundle.primary.is_fragment()),
        "queued items after No Resources must be fragments"
    );
}

/// RFC 9174 §5.2.4-122: After Not Acceptable, same bundle+extensions never re-sent
#[test]
fn test_rfc9174_5_2_4_122_not_acceptable_blocks_same_retry() {
    let mut agent = forwarding_agent(None);
    let make_bundle = || {
        BundleBuilder::new()
            .source(EndpointId::ipn(0, 100, 0).unwrap())
            .destination(EndpointId::ipn(0, 50, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2_000_000), 7))
            .lifetime(3_600_000)
            .payload(b"same-extensions-payload".to_vec())
            .build()
            .unwrap()
    };

    let _bundle_id = agent.send(make_bundle()).unwrap();
    agent.poll(SimInstant::ZERO);
    assert_eq!(agent.cla_tx_queue().len(), 1);
    let tx_id = agent.cla_tx_queue()[0].bundle_id.clone();

    agent
        .notify_cla_transfer_refused(&tx_id, NOT_ACCEPTABLE)
        .unwrap();
    assert!(agent.cla_tx_queue().is_empty());

    // Retry: re-dispatch the same stored bundle (same identity + extensions)
    agent
        .add_retention_constraint(&tx_id, RetentionConstraint::DispatchPending)
        .unwrap();
    agent.poll(SimInstant::from_nanos(1_000_000));
    assert!(
        agent.cla_tx_queue().is_empty(),
        "RFC 9174 §5.2.4-122: SHOULD NOT retry same bundle with same extensions"
    );

    // Different creation timestamp is a different bundle → allowed
    let different = BundleBuilder::new()
        .source(EndpointId::ipn(0, 100, 0).unwrap())
        .destination(EndpointId::ipn(0, 50, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2_000_001), 7))
        .lifetime(3_600_000)
        .payload(b"same-extensions-payload".to_vec())
        .build()
        .unwrap();
    let _ = agent.send(different).unwrap();
    agent.poll(SimInstant::from_nanos(2_000_000));
    assert_eq!(
        agent.cla_tx_queue().len(),
        1,
        "a different bundle identity may still be transmitted"
    );
}
