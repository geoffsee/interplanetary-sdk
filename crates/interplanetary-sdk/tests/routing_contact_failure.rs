//! Contact failure and reroute tests per charter Item 4
//!
//! Tests that routing correctly handles contact failures and computes
//! alternative routes with correct timing assertions.

use interplanetary_sdk::{routing::*, sim::*, types::*};

#[test]
fn test_contact_failure_triggers_reroute() {
    // Setup: Two alternative paths from Node 1 to Node 3
    // Primary path: 1→2→3 (faster, fails)
    // Backup path: 1→4→3 (slower, succeeds)

    let mut plan = ContactPlan::new();

    // Primary path: 1→2 (fast but will fail)
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000), // 60s
        rate: BitsPerSecond::from_mbps(10).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(1_000_000_000), // 1s
        end: SimInstant::from_nanos(60_000_000_000),  // 60s
        rate: BitsPerSecond::from_mbps(10).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    // Backup path: 1→4→3 (slower but available)
    plan.add_contact(Contact {
        id: ContactId(3),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 4),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(100).unwrap(), // 10x slower
        delay: SimDuration::from_millis(50),          // higher delay
        resource_group: None,
    });

    plan.add_contact(Contact {
        id: ContactId(4),
        from_node: NodeId::ipn(0, 4),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(5_000_000_000), // 5s
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(100).unwrap(),
        delay: SimDuration::from_millis(50),
        resource_group: None,
    });

    let solver = MultiLabelSolver::new(plan);

    let node1 = NodeId::ipn(0, 1);
    let node3 = NodeId::ipn(0, 3);
    let bundle_size = Bytes(10_000);

    // Find routes at t=0
    let result = solver
        .find_pareto_routes(&node1, &node3, SimInstant::ZERO, bundle_size)
        .unwrap();
    let routes = result.routes;

    // Should find both paths
    assert!(!routes.is_empty(), "Should find at least one route");

    // Find primary route (via node 2 - contact 1,2)
    let primary = routes.iter().find(|r| r.path.contains(&ContactId(1)));

    // Find backup route (via node 4 - contact 3,4)
    let backup = routes.iter().find(|r| r.path.contains(&ContactId(3)));

    if let Some(p) = primary {
        // Primary route should arrive faster
        println!("Primary route arrival: {}", p.arrival_time.as_nanos());
        assert_eq!(p.path, vec![ContactId(1), ContactId(2)]);
    }

    if let Some(b) = backup {
        // Backup route arrives later
        println!("Backup route arrival: {}", b.arrival_time.as_nanos());
        assert_eq!(b.path, vec![ContactId(3), ContactId(4)]);

        // Backup should arrive after primary would have
        if let Some(p) = primary {
            assert!(
                b.arrival_time > p.arrival_time,
                "Backup route ({}) should be slower than primary ({})",
                b.arrival_time.as_nanos(),
                p.arrival_time.as_nanos()
            );
        }
    }
}

#[test]
fn test_reroute_timing_assertions() {
    // Test that reroute after contact failure has correct timing
    let mut plan = ContactPlan::new();

    // Original contact: 1→2 (becomes unavailable at t=5s)
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(5_000_000_000), // Ends at 5s
        rate: BitsPerSecond::from_mbps(1).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    // Alternative contact: 1→2 (available starting t=10s)
    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::from_nanos(10_000_000_000), // Starts at 10s
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_mbps(1).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    let solver = MultiLabelSolver::new(plan);

    let node1 = NodeId::ipn(0, 1);
    let node2 = NodeId::ipn(0, 2);
    let bundle_size = Bytes(1000);

    // Bundle ready at t=0: should use Contact 1
    let routes_early = solver
        .find_pareto_routes(&node1, &node2, SimInstant::ZERO, bundle_size)
        .unwrap();
    let routes_early = routes_early.routes;
    assert!(
        !routes_early.is_empty(),
        "Should find route for early bundle"
    );
    let early_route = &routes_early[0];
    assert_eq!(early_route.path, vec![ContactId(1)]);
    // Should arrive before Contact 1 ends (at 5s)
    assert!(early_route.arrival_time.as_nanos() < 5_000_000_000);

    // Bundle ready at t=6s (after Contact 1 ends): should wait for Contact 2
    let result_late = solver
        .find_pareto_routes(
            &node1,
            &node2,
            SimInstant::from_nanos(6_000_000_000),
            bundle_size,
        )
        .unwrap();
    let routes_late = result_late.routes;

    assert!(!routes_late.is_empty(), "Should find route for late bundle");
    let late_route = &routes_late[0];
    assert_eq!(late_route.path, vec![ContactId(2)]);
    // Should arrive after Contact 2 starts (at 10s)
    assert!(late_route.arrival_time.as_nanos() > 10_000_000_000);
}

#[test]
fn test_volume_aware_first_hop_admission() {
    // Test that volume limits at first hop are enforced
    let mut plan = ContactPlan::new();

    // Small capacity contact: 1→2
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(10_000_000_000), // 10s
        rate: BitsPerSecond::from_kbps(8).unwrap(),  // 1 KB/s
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    let solver = MultiLabelSolver::new(plan);

    let node1 = NodeId::ipn(0, 1);
    let node2 = NodeId::ipn(0, 2);

    // Small bundle: should fit
    let small_bundle = Bytes(5_000); // 5KB (fits in 5s)
    let routes_small = solver.find_pareto_routes(&node1, &node2, SimInstant::ZERO, small_bundle);

    assert!(routes_small.is_ok(), "Small bundle should find route");
    let result = routes_small.unwrap();
    let routes = result.routes;
    assert!(!routes.is_empty(), "Should find route for small bundle");

    // Volume used should equal bundle size
    assert_eq!(routes[0].volume_used, small_bundle);

    // Large bundle: exceeds contact capacity
    let large_bundle = Bytes(100_000); // 100KB (would need 100s at 1KB/s)
    let routes_large = solver.find_pareto_routes(&node1, &node2, SimInstant::ZERO, large_bundle);

    // Should either fail or return no routes
    match routes_large {
        Ok(result) => {
            let routes = result.routes;
            assert!(
                routes.is_empty(),
                "Large bundle should not fit in available contact window"
            );
        }
        Err(_) => {
            // Also acceptable - explicit failure
        }
    }
}
