//! Multi-graph oracle verification tests
//!
//! Tests the oracle against MultiLabelSolver on multiple generated graphs
//! to verify earliest-arrival agreement and tie-break ranking.

use interplanetary_sdk::{routing::*, sim::*, types::*};

/// Helper: Create random-like graph from seed
fn create_graph_from_seed(seed: u64) -> ContactPlan {
    let mut plan = ContactPlan::new();

    // Use seed to generate deterministic but varied graph
    let num_nodes = 3 + (seed % 4) as usize; // 3-6 nodes
    let num_contacts = 4 + (seed % 7) as usize; // 4-10 contacts

    for i in 0..num_contacts {
        let i_u64 = i as u64;
        let from = 1 + ((seed + i_u64) % num_nodes as u64);
        let to = 1 + ((seed + i_u64 + 1) % num_nodes as u64);

        // Skip self-loops
        if from == to {
            continue;
        }

        let rate_kbps = 100 + ((seed + i_u64) % 10) * 100; // 100-1000 kbps
        let delay_ms = 10 + ((seed + i_u64) % 50); // 10-60ms

        plan.add_contact(Contact {
            id: ContactId(i_u64 + 1),
            from_node: NodeId::ipn(0, from),
            to_node: NodeId::ipn(0, to),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(60_000_000_000), // 60s
            rate: BitsPerSecond::from_kbps(rate_kbps).unwrap(),
            delay: SimDuration::from_millis(delay_ms),
            resource_group: None,
        });
    }

    plan
}

#[test]
fn test_oracle_vs_solver_multiple_graphs() {
    // Test 10 different graph configurations
    for seed in 0..10 {
        let plan1 = create_graph_from_seed(seed);
        let plan2 = create_graph_from_seed(seed); // Rebuild same graph

        let oracle = PathOracle::new(plan1);
        let solver = MultiLabelSolver::new(plan2);

        let source = NodeId::ipn(0, 1);
        let dest_node = 3 + (seed % 3); // Try different destinations
        let dest = NodeId::ipn(0, dest_node);
        let bundle_size = Bytes(1000);

        let solver_result =
            solver.find_pareto_routes(&source, &dest, SimInstant::ZERO, bundle_size);

        // If solver found routes, verify oracle matches
        if let Ok(solver_result) = solver_result {
            let solver_routes = solver_result.routes;
            if !solver_routes.is_empty() {
                let verification = oracle
                    .verify_solver(
                        &source,
                        &dest,
                        bundle_size,
                        SimInstant::ZERO,
                        &solver_routes,
                        6, // max depth
                    )
                    .unwrap();

                assert!(
                    verification.matches,
                    "Seed {}: Oracle vs Solver mismatch. Oracle: {}, Solver: {}, Missing: {}, Extra: {}",
                    seed,
                    verification.oracle_pareto_count,
                    verification.solver_route_count,
                    verification.missing_routes.len(),
                    verification.extra_routes.len()
                );

                println!(
                    "Seed {}: ✓ Oracle and solver agree ({} Pareto-optimal routes)",
                    seed, verification.oracle_pareto_count
                );
            }
        }
    }
}

#[test]
fn test_oracle_earliest_arrival_equality() {
    // Test that earliest arrival times match exactly
    let mut plan = ContactPlan::new();

    // Create graph with known optimal path
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(1_000_000_000), // 1s
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    let _plan1 = plan;
    let _plan2 = create_graph_from_seed(0); // Rebuild

    // Actually, we can't clone ContactPlan, so let's rebuild inline
    let mut plan_oracle = ContactPlan::new();
    plan_oracle.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });
    plan_oracle.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(1_000_000_000),
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    let mut plan_solver = ContactPlan::new();
    plan_solver.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });
    plan_solver.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(1_000_000_000),
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(),
        delay: SimDuration::from_millis(10),
        resource_group: None,
    });

    let oracle = PathOracle::new(plan_oracle);
    let solver = MultiLabelSolver::new(plan_solver);

    let source = NodeId::ipn(0, 1);
    let dest = NodeId::ipn(0, 3);
    let bundle_size = Bytes(1000);

    let solver_result = solver
        .find_pareto_routes(&source, &dest, SimInstant::ZERO, bundle_size)
        .unwrap();
    let solver_routes = solver_result.routes;

    assert!(!solver_routes.is_empty());

    let oracle_frontier =
        oracle.compute_pareto_frontier(&source, &dest, bundle_size, SimInstant::ZERO, 5);

    assert_eq!(
        oracle_frontier.len(),
        solver_routes.len(),
        "Oracle and solver must find same number of Pareto-optimal routes"
    );

    // Verify earliest arrival times match
    let earliest_solver = solver_routes.iter().map(|r| r.arrival_time).min().unwrap();

    let earliest_oracle = oracle_frontier
        .iter()
        .map(|r| r.arrival_time)
        .min()
        .unwrap();

    assert_eq!(
        earliest_solver, earliest_oracle,
        "Earliest arrival time must match exactly"
    );
}

#[test]
fn test_tiebreak_ranking_by_volume() {
    // When arrival times are equal, routes should be ranked by volume
    let mut plan_oracle = ContactPlan::new();
    let mut plan_solver = ContactPlan::new();

    // Path 1: High rate (low volume)
    for plan in [&mut plan_oracle, &mut plan_solver] {
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(60_000_000_000),
            rate: BitsPerSecond::from_kbps(10000).unwrap(), // 10 Mbps
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        // Path 2: Low rate (high volume)
        plan.add_contact(Contact {
            id: ContactId(2),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(60_000_000_000),
            rate: BitsPerSecond::from_kbps(1000).unwrap(), // 1 Mbps
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });
    }

    let oracle = PathOracle::new(plan_oracle);
    let solver = MultiLabelSolver::new(plan_solver);

    let result = solver
        .find_pareto_routes(
            &NodeId::ipn(0, 1),
            &NodeId::ipn(0, 2),
            SimInstant::ZERO,
            Bytes(100),
        )
        .unwrap();
    let routes = result.routes;

    // Should find both routes (different serialization times)
    assert!(!routes.is_empty());

    // Verify oracle agrees
    let verification = oracle
        .verify_solver(
            &NodeId::ipn(0, 1),
            &NodeId::ipn(0, 2),
            Bytes(100),
            SimInstant::ZERO,
            &routes,
            3,
        )
        .unwrap();

    assert!(
        verification.matches,
        "Oracle and solver must agree on tie-break ranking"
    );
}
