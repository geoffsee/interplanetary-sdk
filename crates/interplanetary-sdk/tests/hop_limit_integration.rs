//! End-to-end 3-node scenario test for hop limit exceeded deletion
//!
//! Per RFC 9171 §4.4.3 and §5.4, verifies that:
//! - Hop Count is incremented on forward
//! - Bundle is deleted when hop limit is exceeded
//! - Deletion reason code 9 is used per RFC 9171 §6.1.1 Table 1
//! - Deterministic behavior across repeated runs with identical event traces

use interplanetary_sdk::{
    bp::{BundleBuilder, CrcType, DeletionReason, HopCountBlock},
    sim::{Contact, ContactId, ContactPlan, Scenario},
    types::{
        BitsPerSecond, Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId, SimDuration,
        SimInstant,
    },
};

/// Create 3-node scenario: Node 1 -> Node 2 -> Node 3
fn create_3_node_scenario_with_hop_limit_1() -> (Scenario, ContactId, ContactId) {
    let mut plan = ContactPlan::new();

    // Contact 1: Node 1 -> Node 2
    let contact1 = Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(10_000_000_000), // 10 seconds
        rate: BitsPerSecond::from_kbps(100).unwrap(),
        delay: SimDuration::from_millis(100),
        resource_group: None,
    };
    plan.add_contact(contact1);

    // Contact 2: Node 2 -> Node 3
    let contact2 = Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(10_000_000_000), // 10 seconds
        rate: BitsPerSecond::from_kbps(100).unwrap(),
        delay: SimDuration::from_millis(100),
        resource_group: None,
    };
    plan.add_contact(contact2);

    let mut scenario = Scenario::new(plan, Bytes::from_mib(1).unwrap());

    // Add 3 nodes
    scenario
        .add_node(NodeId::ipn(0, 1), Bytes::from_mib(1).unwrap())
        .unwrap();
    scenario
        .add_node(NodeId::ipn(0, 2), Bytes::from_mib(1).unwrap())
        .unwrap();
    scenario
        .add_node(NodeId::ipn(0, 3), Bytes::from_mib(1).unwrap())
        .unwrap();

    (scenario, ContactId(1), ContactId(2))
}

#[test]
fn test_hop_limit_deletion_3_node_deterministic() {
    // Run scenario 3 times and verify identical outcomes
    let mut event_logs = Vec::new();
    let mut deletion_times = Vec::new();

    for run in 0..3 {
        let (mut scenario, _, _) = create_3_node_scenario_with_hop_limit_1();

        // Create bundle at Node 1 destined for Node 3
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000) // 24 hours
            .payload(b"test payload".to_vec())
            .crc_type(CrcType::Crc16)
            .build()
            .unwrap();

        // Add hop count block with limit = 1 (allows exactly 1 hop)
        let hop_block = HopCountBlock::new(2, 1, 0).unwrap();
        bundle.blocks.push(hop_block.to_canonical().unwrap());

        // Inject bundle at Node 1
        let bundle_id = scenario.inject_bundle(&NodeId::ipn(0, 1), bundle).unwrap();

        // Run simulation
        let result = scenario.run().unwrap();

        // Extract deletion event
        let deletion_event = result
            .event_log
            .iter()
            .find(|(_, e)| matches!(e, interplanetary_sdk::sim::Event::BundleDeleted { .. }));

        if let Some((
            time,
            interplanetary_sdk::sim::Event::BundleDeleted {
                bundle_id: del_id,
                node,
                reason,
            },
        )) = deletion_event
        {
            // Verify deletion happened at Node 2
            assert_eq!(
                *node,
                NodeId::ipn(0, 2),
                "Bundle should be deleted at Node 2 (run {})",
                run
            );

            // Verify reason is hop limit exceeded
            assert_eq!(
                *reason,
                interplanetary_sdk::bpa::admin::ReasonCode::HopLimitExceeded,
                "Deletion reason should be HopLimitExceeded (run {})",
                run
            );

            // Verify it's the right bundle
            assert_eq!(
                *del_id, bundle_id,
                "Deleted bundle ID should match (run {})",
                run
            );

            deletion_times.push(*time);
        } else {
            panic!("Bundle should have been deleted at Node 2 (run {})", run);
        }

        // Verify bundle did NOT reach Node 3
        let node3_agent = scenario.get_agent(&NodeId::ipn(0, 3)).unwrap();
        assert!(
            node3_agent.get_bundle(&bundle_id).is_none(),
            "Bundle should not reach Node 3 (run {})",
            run
        );

        // Record event log length for determinism check
        event_logs.push(result.event_log.len());
    }

    // Verify deterministic behavior: all runs should have identical event counts
    assert_eq!(
        event_logs[0], event_logs[1],
        "Event counts should match between run 1 and 2"
    );
    assert_eq!(
        event_logs[1], event_logs[2],
        "Event counts should match between run 2 and 3"
    );

    // Verify deterministic timing: all deletion events should occur at the same time
    assert_eq!(
        deletion_times[0], deletion_times[1],
        "Deletion times should match between run 1 and 2"
    );
    assert_eq!(
        deletion_times[1], deletion_times[2],
        "Deletion times should match between run 2 and 3"
    );
}

#[test]
fn test_hop_limit_allows_one_hop_to_reach_node2() {
    // Verify that with hop_limit=1, bundle reaches Node 2 but not Node 3
    let (mut scenario, _, _) = create_3_node_scenario_with_hop_limit_1();

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap()) // Destination is Node 2
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test".to_vec())
        .crc_type(CrcType::Crc16)
        .build()
        .unwrap();

    // Hop limit = 1
    let hop_block = HopCountBlock::new(2, 1, 0).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    let bundle_id = scenario.inject_bundle(&NodeId::ipn(0, 1), bundle).unwrap();

    // Run simulation
    let result = scenario.run().unwrap();

    // Bundle should be delivered at Node 2 (destination)
    let delivery_event = result
        .event_log
        .iter()
        .find(|(_, e)| matches!(e, interplanetary_sdk::sim::Event::BundleDelivered { .. }));

    assert!(
        delivery_event.is_some(),
        "Bundle should be delivered at Node 2"
    );

    if let Some((
        _,
        interplanetary_sdk::sim::Event::BundleDelivered {
            bundle_id: del_id,
            node,
        },
    )) = delivery_event
    {
        assert_eq!(*node, NodeId::ipn(0, 2), "Should be delivered at Node 2");
        assert_eq!(*del_id, bundle_id, "Delivered bundle ID should match");
    }
}

#[test]
fn test_deletion_reason_code_value() {
    // Verify RFC 9171 §6.1.1 Table 1: Hop limit exceeded = 9
    assert_eq!(DeletionReason::HopLimitExceeded.to_u8(), 9);
}

#[test]
fn test_hop_limit_two_allows_two_hops() {
    // With hop_limit=2, bundle should reach Node 3 via Node 2
    let (mut scenario, _, _) = create_3_node_scenario_with_hop_limit_1();

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .crc_type(CrcType::Crc16)
        .build()
        .unwrap();

    // Hop limit = 2 (allows 2 hops: 1->2, 2->3)
    let hop_block = HopCountBlock::new(2, 2, 0).unwrap();
    bundle.blocks.push(hop_block.to_canonical().unwrap());

    let bundle_id = scenario.inject_bundle(&NodeId::ipn(0, 1), bundle).unwrap();

    // Run simulation
    let result = scenario.run().unwrap();

    // Bundle should be delivered at Node 3
    let delivery_event = result
        .event_log
        .iter()
        .find(|(_, e)| matches!(e, interplanetary_sdk::sim::Event::BundleDelivered { .. }));

    assert!(
        delivery_event.is_some(),
        "Bundle should be delivered at Node 3 with hop_limit=2"
    );

    if let Some((
        _,
        interplanetary_sdk::sim::Event::BundleDelivered {
            bundle_id: del_id,
            node,
        },
    )) = delivery_event
    {
        assert_eq!(*node, NodeId::ipn(0, 3), "Should be delivered at Node 3");
        assert_eq!(*del_id, bundle_id);
    }

    // Verify no deletion event
    let deletion_event = result
        .event_log
        .iter()
        .find(|(_, e)| matches!(e, interplanetary_sdk::sim::Event::BundleDeleted { .. }));
    assert!(
        deletion_event.is_none(),
        "Bundle should not be deleted with sufficient hop limit"
    );
}
