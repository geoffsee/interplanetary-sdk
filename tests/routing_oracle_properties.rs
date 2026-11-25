//! Property tests for routing oracle vs MultiLabelSolver
//!
//! Uses proptest to generate many small random contact graphs and verifies
//! that the exhaustive oracle and the MultiLabelSolver produce identical
//! results for earliest-arrival routing.

use interplanetary_sdk::{routing::*, sim::*, types::*};
use proptest::prelude::*;

/// Contact data for rebuilding ContactPlan
#[derive(Debug, Clone)]
struct ContactData {
    id: u64,
    from_node: u64,
    to_node: u64,
    rate_kbps: u64,
    delay_ms: u64,
    duration_secs: u64,
}

/// Generate contact data for a small random graph
fn arb_contact_data() -> impl Strategy<Value = Vec<ContactData>> {
    (3usize..=6, 3usize..=10).prop_flat_map(|(num_nodes, num_contacts)| {
        prop::collection::vec(
            (
                0..num_nodes,    // from_node
                0..num_nodes,    // to_node
                1000u64..=10000, // rate_kbps (1-10 Mbps)
                1u64..=100,      // delay_ms
                10u64..=60,      // duration_secs
            ),
            num_contacts..=num_contacts,
        )
        .prop_map(move |contacts| {
            let mut contact_data = Vec::new();
            for (id, (from, to, rate_kbps, delay_ms, duration_secs)) in
                contacts.into_iter().enumerate()
            {
                // Skip self-loops
                if from == to {
                    continue;
                }
                contact_data.push(ContactData {
                    id: id as u64 + 1,
                    from_node: from as u64 + 1,
                    to_node: to as u64 + 1,
                    rate_kbps,
                    delay_ms,
                    duration_secs,
                });
            }
            contact_data
        })
    })
}

/// Build ContactPlan from contact data
fn build_contact_plan(contact_data: &[ContactData]) -> ContactPlan {
    let mut plan = ContactPlan::new();
    for data in contact_data {
        let start = SimInstant::ZERO;
        let end = SimInstant::from_nanos(data.duration_secs * 1_000_000_000);

        plan.add_contact(Contact {
            id: ContactId(data.id),
            from_node: NodeId::ipn(0, data.from_node),
            to_node: NodeId::ipn(0, data.to_node),
            start,
            end,
            rate: BitsPerSecond::from_kbps(data.rate_kbps).unwrap(),
            delay: SimDuration::from_millis(data.delay_ms),
            resource_group: None,
        });
    }
    plan
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 20,  // Run 20 random test cases
        max_shrink_iters: 100,
        ..ProptestConfig::default()
    })]

    /// Property: Oracle and solver must agree on earliest arrival time
    ///
    /// For any small random contact graph, the exhaustive oracle's Pareto
    /// frontier must match the MultiLabelSolver's output.
    #[test]
    fn prop_oracle_matches_solver(contact_data in arb_contact_data()) {
        // Skip empty graphs
        if contact_data.is_empty() {
            return Ok(());
        }

        // Build identical plans for oracle and solver
        let plan_oracle = build_contact_plan(&contact_data);
        let plan_solver = build_contact_plan(&contact_data);

        let oracle = PathOracle::new(plan_oracle);
        let solver = MultiLabelSolver::new(plan_solver);

        // Try routing between first and last nodes
        let source = NodeId::ipn(0, 1);
        let dest = NodeId::ipn(0, 6);
        let bundle_size = Bytes(1000);
        let ready_time = SimInstant::ZERO;

        // Get solver routes
        let solver_result = solver.find_pareto_routes(
            &source,
            &dest,
            ready_time,
            bundle_size,
        );

        // If solver found routes, oracle should find same set
        if let Ok(solver_result) = solver_result {
            let solver_routes = solver_result.routes;
            if !solver_routes.is_empty() {
                let verification = oracle.verify_solver(
                    &source,
                    &dest,
                    bundle_size,
                    ready_time,
                    &solver_routes,
                    6, // max depth = max nodes
                )?;

                // Oracle and solver must agree
                prop_assert!(
                    verification.matches,
                    "Oracle found {} routes, solver found {}. Missing: {}, Extra: {}",
                    verification.oracle_pareto_count,
                    verification.solver_route_count,
                    verification.missing_routes.len(),
                    verification.extra_routes.len()
                );
            }
        }
    }

    /// Property: Solver routes are non-dominated
    #[test]
    fn prop_solver_routes_non_dominated(contact_data in arb_contact_data()) {
        if contact_data.is_empty() {
            return Ok(());
        }

        let plan = build_contact_plan(&contact_data);
        let solver = MultiLabelSolver::new(plan);

        let source = NodeId::ipn(0, 1);
        let dest = NodeId::ipn(0, 4);
        let bundle_size = Bytes(1000);

        let solver_result = solver.find_pareto_routes(
            &source,
            &dest,
            SimInstant::ZERO,
            bundle_size,
        );

        if let Ok(result) = solver_result {
            let routes = result.routes;
            // Check no route dominates another
            for (i, r1) in routes.iter().enumerate() {
                for (j, r2) in routes.iter().enumerate() {
                    if i != j {
                        let r1_label = RouteLabel {
                            arrival_time: r1.arrival_time,
                            volume_used: r1.volume_used,
                        };
                        let r2_label = RouteLabel {
                            arrival_time: r2.arrival_time,
                            volume_used: r2.volume_used,
                        };
                        prop_assert!(
                            !r1_label.dominates(&r2_label),
                            "Route {} dominates route {}: {:?} vs {:?}",
                            i, j, r1_label, r2_label
                        );
                    }
                }
            }
        }
    }
}

/// Test earliest-arrival tie-breaking
///
/// When multiple routes arrive at the same time, they should all be in
/// the Pareto frontier (neither dominates the other).
#[test]
fn test_earliest_arrival_tiebreak_ranking() {
    let mut plan = ContactPlan::new();

    // Two paths with same arrival time but different volumes

    // Path 1: 1→2→3 (low volume, high rate)
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(10000).unwrap(), // 10 Mbps - very fast
        delay: SimDuration::from_millis(5),
        resource_group: None,
    });

    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(10000).unwrap(),
        delay: SimDuration::from_millis(5),
        resource_group: None,
    });

    // Path 2: 1→4→3 (higher volume, lower rate but same total delay)
    plan.add_contact(Contact {
        id: ContactId(3),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 4),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(), // 1 Mbps - slower
        delay: SimDuration::from_millis(5),
        resource_group: None,
    });

    plan.add_contact(Contact {
        id: ContactId(4),
        from_node: NodeId::ipn(0, 4),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(60_000_000_000),
        rate: BitsPerSecond::from_kbps(1000).unwrap(),
        delay: SimDuration::from_millis(5),
        resource_group: None,
    });

    let solver = MultiLabelSolver::new(plan);

    let result = solver
        .find_pareto_routes(
            &NodeId::ipn(0, 1),
            &NodeId::ipn(0, 3),
            SimInstant::ZERO,
            Bytes(100), // Small bundle
        )
        .unwrap();
    let routes = result.routes;

    // Should find at least one route
    assert!(!routes.is_empty(), "Should find at least one route");

    // All routes in Pareto frontier should be non-dominated
    for (i, r1) in routes.iter().enumerate() {
        for (j, r2) in routes.iter().enumerate() {
            if i != j {
                let r1_label = RouteLabel {
                    arrival_time: r1.arrival_time,
                    volume_used: r1.volume_used,
                };
                let r2_label = RouteLabel {
                    arrival_time: r2.arrival_time,
                    volume_used: r2.volume_used,
                };
                assert!(
                    !r1_label.dominates(&r2_label),
                    "Route {} should not dominate route {}",
                    i,
                    j
                );
            }
        }
    }
}
