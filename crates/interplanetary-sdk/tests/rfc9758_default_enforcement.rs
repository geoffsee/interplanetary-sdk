//! RFC 9758 §5.5: Private Use enforcement ON BY DEFAULT proof test

use interplanetary_sdk::bp::{BundleBuilder, CreationTimestamp};
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::{Bytes, DtnTimeMs, EndpointId, NodeId};

/// RFC9758-029/031: Proof that BpaConfig::default() enforces Private Use restrictions
///
/// This test uses BpaConfig::default() with NO explicit enforce_private_use_restrictions
/// setting, proving that the DEFAULT behavior is to enforce RFC 9758 §5.5.
#[test]
fn test_rfc9758_default_config_enforces_private_use() {
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());

    // Use DEFAULT config - no explicit enforce_private_use_restrictions
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 100),
        local_eid: EndpointId::ipn(0, 100, 0).unwrap(),
        ..BpaConfig::default()
    };

    let mut agent = BundleAgent::new(config, storage);

    // Create bundle with Private Use source (node 100000 is in range 1-16777215)
    let private_use_src = EndpointId::ipn(0, 100000, 0).unwrap();
    assert!(
        private_use_src.is_private_use_ipn(),
        "Verify test uses Private Use EID"
    );

    let bundle = BundleBuilder::new()
        .source(private_use_src)
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0xAA])
        .build()
        .unwrap();

    // Production path: receive bundle with Private Use, poll triggers forward attempt
    use interplanetary_sdk::types::SimInstant;
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Bundle should be deleted (default enforcement blocks Private Use across domains)
    assert!(
        agent.storage().enumerate().is_empty(),
        "BpaConfig::default() MUST enforce Private Use restrictions (RFC 9758 §5.5)"
    );
    assert!(
        agent.cla_tx_queue().is_empty(),
        "Private Use bundle must not appear in CLA tx queue"
    );

    // No CLA transmission should occur
    assert!(
        agent.cla_tx_queue().is_empty(),
        "CLA tx queue must be empty - no forwarding of Private Use by default"
    );
}
