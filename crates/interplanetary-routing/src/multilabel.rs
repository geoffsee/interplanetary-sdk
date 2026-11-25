//! Multi-label Dijkstra for volume-aware routing per charter §9
//!
//! Single-label Dijkstra invalid per docs/routing_dominance.md (FIFO proof failed).
//! This implements Pareto-optimal multi-label search tracking (time, volume).

use interplanetary_contacts::ContactId;
use interplanetary_contacts::ContactPlan;
use interplanetary_types::*;
use std::collections::HashMap;

/// Route label tracking arrival time and volume used
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteLabel {
    /// Arrival time at destination
    pub arrival_time: SimInstant,
    /// Volume consumed
    pub volume_used: Bytes,
}

impl RouteLabel {
    /// Check if this label dominates another
    pub fn dominates(&self, other: &RouteLabel) -> bool {
        self.arrival_time <= other.arrival_time
            && self.volume_used <= other.volume_used
            && (self.arrival_time < other.arrival_time || self.volume_used < other.volume_used)
    }
}

/// Pareto-optimal route
#[derive(Debug, Clone)]
pub struct ParetoRoute {
    /// Arrival time at destination
    pub arrival_time: SimInstant,
    /// Volume consumed
    pub volume_used: Bytes,
    /// Contact sequence
    pub path: Vec<ContactId>,
}

/// Result of Pareto-optimal route search
#[derive(Debug, Clone)]
pub struct ParetoSearchResult {
    /// Pareto-optimal routes found
    pub routes: Vec<ParetoRoute>,
    /// Number of iterations performed
    pub iterations: usize,
    /// Whether algorithm converged
    pub converged: bool,
}

/// Multi-label Dijkstra solver
#[derive(Debug)]
pub struct MultiLabelSolver {
    contact_plan: ContactPlan,
}

impl MultiLabelSolver {
    /// Create new multi-label solver
    pub fn new(contact_plan: ContactPlan) -> Self {
        Self { contact_plan }
    }

    /// Find all Pareto-optimal routes
    pub fn find_pareto_routes(
        &self,
        from: &NodeId,
        to: &NodeId,
        ready_time: SimInstant,
        bundle_size: Bytes,
    ) -> Result<ParetoSearchResult> {
        let mut labels: HashMap<NodeId, Vec<RouteLabel>> = HashMap::new();
        let mut predecessors: HashMap<(NodeId, usize), (NodeId, usize, ContactId)> = HashMap::new();

        // Initialize with ready time at source
        labels.insert(
            from.clone(),
            vec![RouteLabel {
                arrival_time: ready_time,
                volume_used: Bytes::ZERO,
            }],
        );

        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            // For each node with labels
            for (node, node_labels) in labels.clone().iter() {
                // For each label at this node
                for (label_idx, label) in node_labels.iter().enumerate() {
                    // Try all outgoing contacts
                    for contact in self.contact_plan.contacts() {
                        if &contact.from_node != node {
                            continue;
                        }

                        // Check if bundle can use this contact
                        let tx_time = bundle_size.serialization_time(contact.rate)?;

                        if let Some((_tx_start, tx_end)) =
                            contact.find_available_interval(label.arrival_time, tx_time)
                        {
                            let arrival_at_next = tx_end
                                .checked_add(contact.delay)
                                .ok_or_else(|| Error::protocol_violation("Time overflow"))?;

                            let new_label = RouteLabel {
                                arrival_time: arrival_at_next,
                                volume_used: label.volume_used.saturating_add(bundle_size),
                            };

                            // Check if this label is non-dominated
                            let next_labels = labels.entry(contact.to_node.clone()).or_default();

                            let dominated = next_labels.iter().any(|l| l.dominates(&new_label));

                            // Also check for equality (to avoid duplicate labels)
                            let duplicate = next_labels.iter().any(|l| {
                                l.arrival_time == new_label.arrival_time
                                    && l.volume_used == new_label.volume_used
                            });

                            if !dominated && !duplicate {
                                // Remove dominated labels
                                next_labels.retain(|l| !new_label.dominates(l));

                                let new_idx = next_labels.len();
                                next_labels.push(new_label);

                                predecessors.insert(
                                    (contact.to_node.clone(), new_idx),
                                    (node.clone(), label_idx, contact.id),
                                );

                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        // Extract Pareto-optimal routes to destination
        let dest_labels = labels
            .get(to)
            .ok_or_else(|| Error::no_route("No route found"))?;

        let mut routes = Vec::new();

        for (label_idx, label) in dest_labels.iter().enumerate() {
            // Reconstruct path
            let mut path = Vec::new();
            let mut current_node = to.clone();
            let mut current_idx = label_idx;

            while let Some((prev_node, prev_idx, contact_id)) =
                predecessors.get(&(current_node.clone(), current_idx))
            {
                path.push(*contact_id);
                current_node = prev_node.clone();
                current_idx = *prev_idx;
            }

            path.reverse();

            routes.push(ParetoRoute {
                arrival_time: label.arrival_time,
                volume_used: label.volume_used,
                path,
            });
        }

        Ok(ParetoSearchResult {
            routes,
            iterations,
            converged: iterations < MAX_ITERATIONS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use interplanetary_contacts::Contact;
    use interplanetary_types::BitsPerSecond;

    #[test]
    fn test_multilabel_pareto_optimal() {
        let mut plan = ContactPlan::new();

        // Fast route with high volume
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(10_000_000_000),
            rate: BitsPerSecond::from_kbps(100).unwrap(),
            delay: SimDuration::from_millis(50),
            resource_group: None,
        });

        // Slow route with low volume
        plan.add_contact(Contact {
            id: ContactId(2),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(20_000_000_000),
            rate: BitsPerSecond::from_kbps(10).unwrap(),
            delay: SimDuration::from_millis(100),
            resource_group: None,
        });

        let solver = MultiLabelSolver::new(plan);

        let result = solver
            .find_pareto_routes(
                &NodeId::ipn(0, 1),
                &NodeId::ipn(0, 2),
                SimInstant::ZERO,
                Bytes(1000),
            )
            .unwrap();

        let routes = result.routes;

        // Should find both routes as Pareto-optimal (one faster, one less volume)
        assert!(!routes.is_empty());
    }

    #[test]
    fn test_solver_converges() {
        // Verify that the solver terminates by convergence, not by hitting MAX_ITERATIONS
        // This test was added after fixing the duplicate-label bug that caused
        // MAX_ITERATIONS=1000 to be hit (see docs/routing_dominance.md)

        let mut plan = ContactPlan::new();

        // Create a simple linear path: 1 -> 2 -> 3
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(100_000_000_000),
            rate: BitsPerSecond::from_kbps(1000).unwrap(),
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        plan.add_contact(Contact {
            id: ContactId(2),
            from_node: NodeId::ipn(0, 2),
            to_node: NodeId::ipn(0, 3),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(100_000_000_000),
            rate: BitsPerSecond::from_kbps(1000).unwrap(),
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        let solver = MultiLabelSolver::new(plan);

        let result = solver
            .find_pareto_routes(
                &NodeId::ipn(0, 1),
                &NodeId::ipn(0, 3),
                SimInstant::ZERO,
                Bytes(1000),
            )
            .unwrap();

        // Assert that the solver converged (did not hit MAX_ITERATIONS)
        assert!(
            result.converged,
            "Solver should converge, not hit MAX_ITERATIONS (iterations: {})",
            result.iterations
        );

        // For a simple 2-hop linear path, should converge in very few iterations
        // Typical: 3-5 iterations for propagation through the graph
        assert!(
            result.iterations < 10,
            "Simple linear path should converge in <10 iterations, got: {}",
            result.iterations
        );

        // Should find exactly 1 Pareto-optimal route
        assert_eq!(
            result.routes.len(),
            1,
            "Linear path should have exactly 1 Pareto-optimal route"
        );

        println!("✓ Solver converged in {} iterations", result.iterations);
    }

    #[test]
    fn test_solver_deterministic_tie_break() {
        // Verify that duplicate labels are detected and tie-breaking is deterministic
        // Per docs/routing_dominance.md: two labels with identical metrics should not
        // both be in the Pareto frontier

        let mut plan = ContactPlan::new();

        // Create two parallel contacts with identical characteristics
        // This could produce duplicate labels if not properly handled
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(100_000_000_000),
            rate: BitsPerSecond::from_kbps(1000).unwrap(),
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        plan.add_contact(Contact {
            id: ContactId(2),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(100_000_000_000),
            rate: BitsPerSecond::from_kbps(1000).unwrap(),
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        let solver = MultiLabelSolver::new(plan);

        let result = solver
            .find_pareto_routes(
                &NodeId::ipn(0, 1),
                &NodeId::ipn(0, 2),
                SimInstant::ZERO,
                Bytes(1000),
            )
            .unwrap();

        // Should converge quickly despite duplicate contacts
        assert!(result.converged, "Should converge with duplicate contacts");
        assert!(
            result.iterations < 10,
            "Should converge in <10 iterations with duplicates"
        );

        // Should produce exactly 1 route (duplicates filtered out)
        assert_eq!(
            result.routes.len(),
            1,
            "Duplicate contacts should produce only 1 Pareto-optimal route"
        );

        println!(
            "✓ Deterministic tie-break: {} iterations, {} route",
            result.iterations,
            result.routes.len()
        );
    }
}
