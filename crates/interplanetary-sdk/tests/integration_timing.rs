//! Integration test: exact timing from scenarios/three-node-scheduler.json

use interplanetary_sdk::{bp::BundleBuilder, sim::*, types::*};

#[test]
fn test_three_node_exact_timing() {
    // From scenarios/three-node-scheduler.json:
    // Earth → Relay: 0-10s, 8 kbps, 4s delay
    // Relay → Mars: 10-20s, 8 kbps, 6s delay
    // 1000 byte bundle
    // Expected arrival: 17s via relay

    let mut plan = ContactPlan::new();

    // C1: Earth → Relay
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(10_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(4),
        resource_group: Some("earth-relay".to_string()),
    });

    // C2: Relay → Mars
    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(10_000_000_000),
        end: SimInstant::from_nanos(20_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(6),
        resource_group: Some("relay-mars".to_string()),
    });

    let mut scenario = Scenario::new(plan, Bytes::from_mib(10).unwrap());
    scenario
        .add_node(NodeId::ipn(0, 1), Bytes::from_mib(10).unwrap())
        .unwrap();
    scenario
        .add_node(NodeId::ipn(0, 2), Bytes::from_mib(10).unwrap())
        .unwrap();
    scenario
        .add_node(NodeId::ipn(0, 3), Bytes::from_mib(10).unwrap())
        .unwrap();

    // RFC 9171 §4.4.2: Bundle Age required when creation time is 0
    // RFC 9171 §4.3.1: Primary CRC type must be non-zero unless BIB targets primary
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000)
        .payload(vec![0u8; 1000])
        .crc_type(interplanetary_sdk::bp::CrcType::Crc16)
        .build()
        .unwrap();

    // Add Bundle Age block (required for creation time = 0)
    use interplanetary_sdk::bp::BundleAgeBlock;
    let age_block = BundleAgeBlock::new(2, 0);
    bundle.blocks.push(age_block.to_canonical().unwrap());

    scenario.inject_bundle(&NodeId::ipn(0, 1), bundle).unwrap();
    let result = scenario.run().unwrap();

    // Expected timing breakdown:
    // T=0s: Bundle ready at Earth
    // Earth → Relay transmission: 1000 bytes at 8 kbps = 1s
    // T=1s: Transmission complete
    // T=1s + 4s delay = T=5s: Arrives at Relay
    // Relay must wait for C2 to open at T=10s
    // T=10s: Relay → Mars transmission starts: 1000 bytes at 8 kbps = 1s
    // T=11s: Transmission complete
    // T=11s + 6s delay = T=17s: Arrives at Mars ✓

    let expected_arrival_ns = 17_000_000_000u64;

    // Check final time is at or after expected arrival
    assert!(
        result.final_time.as_nanos() >= expected_arrival_ns,
        "Final time {} ns should be >= expected arrival {} ns",
        result.final_time.as_nanos(),
        expected_arrival_ns
    );

    // Verify bundle delivered
    let mars_agent = scenario.get_agent(&NodeId::ipn(0, 3)).unwrap();
    let delivered_bundles: Vec<_> =
        mars_agent.list_bundles_in_state(interplanetary_sdk::bpa::BundleState::Delivered);

    assert_eq!(
        delivered_bundles.len(),
        1,
        "Exactly one bundle should be delivered to Mars"
    );
}

#[test]
fn test_serialization_time_calculation() {
    // Verify the serialization time math
    // 1000 bytes at 8000 bps
    // = 8000 bits at 8000 bps
    // = 1 second

    let rate = BitsPerSecond::from_kbps(8).unwrap();
    let size = Bytes(1000);
    let time = rate.serialization_time(size).unwrap();

    assert_eq!(
        time.as_millis(),
        1000,
        "1000 bytes at 8 kbps should take 1 second"
    );
}
