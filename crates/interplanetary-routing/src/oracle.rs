//! Exhaustive feasible-path enumeration oracle for routing verification
//!
//! This oracle enumerates ALL feasible paths through small contact graphs
//! to verify that the multi-label solver finds optimal routes correctly.
//! Only practical for test graphs with <10 contacts.

use crate::ParetoRoute;
use interplanetary_contacts::ContactId;
use interplanetary_contacts::ContactPlan;
use interplanetary_types::*;
use std::collections::HashSet;

/// A complete enumerated path through the contact graph
#[derive(Debug, Clone)]
pub struct EnumeratedPath {
    /// Contact sequence
    pub contacts: Vec<ContactId>,
    /// Arrival time at destination
    pub arrival_time: SimInstant,
    /// Total volume consumed
    pub volume_used: Bytes,
    /// Whether path is valid
    pub valid: bool,
    /// Optional reason if invalid
    pub failure_reason: Option<String>,
}

/// Exhaustive path enumeration oracle
///
/// ## Complexity
///
/// This enumerates ALL possible paths through the graph, which is exponential
/// in the number of contacts. Only use for test graphs with <100 paths.
///
/// ## Verification Strategy
///
/// 1. Enumerate all paths from source to destination
/// 2. Simulate bundle transmission on each path (serialization + propagation)
/// 3. Filter to feasible paths (fits within contact windows)
/// 4. Compute Pareto frontier of (arrival_time, volume_used)
/// 5. Compare against MultiLabelSolver output
#[derive(Debug)]
pub struct PathOracle {
    plan: ContactPlan,
}

impl PathOracle {
    /// Create oracle for a contact plan
    pub fn new(plan: ContactPlan) -> Self {
        Self { plan }
    }

    /// Enumerate all paths from source to destination
    ///
    /// Uses depth-first search with cycle detection.
    /// Limits search to max_depth hops to prevent infinite loops.
    pub fn enumerate_all_paths(
        &self,
        from: &NodeId,
        to: &NodeId,
        max_depth: usize,
    ) -> Vec<Vec<ContactId>> {
        let mut all_paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited = HashSet::new();

        visited.insert(from.clone());
        self.dfs_enumerate(
            from,
            to,
            &mut current_path,
            &mut visited,
            &mut all_paths,
            max_depth,
        );

        all_paths
    }

    /// Depth-first search helper for path enumeration
    fn dfs_enumerate(
        &self,
        current: &NodeId,
        target: &NodeId,
        path: &mut Vec<ContactId>,
        visited: &mut HashSet<NodeId>,
        all_paths: &mut Vec<Vec<ContactId>>,
        remaining_depth: usize,
    ) {
        // Found destination
        if current == target {
            all_paths.push(path.clone());
            return;
        }

        // Depth limit reached
        if remaining_depth == 0 {
            return;
        }

        // Try each outgoing contact from current node
        for contact in self.plan.contacts() {
            if &contact.from_node != current {
                continue;
            }

            // Avoid cycles
            if visited.contains(&contact.to_node) {
                continue;
            }

            // Explore this edge
            path.push(contact.id);
            visited.insert(contact.to_node.clone());

            self.dfs_enumerate(
                &contact.to_node,
                target,
                path,
                visited,
                all_paths,
                remaining_depth - 1,
            );

            // Backtrack
            path.pop();
            visited.remove(&contact.to_node);
        }
    }

    /// Simulate bundle transmission along a path
    ///
    /// Returns arrival time and volume if feasible, or error reason if not.
    pub fn simulate_path(
        &self,
        contact_path: &[ContactId],
        bundle_size: Bytes,
        ready_time: SimInstant,
    ) -> Result<(SimInstant, Bytes)> {
        let mut current_time = ready_time;
        let mut total_volume = Bytes::ZERO;

        // Simulate each hop
        for &contact_id in contact_path {
            let contact = self
                .plan
                .get_contact(contact_id)
                .ok_or_else(|| Error::not_found(format!("Contact {} not found", contact_id.0)))?;

            // Check bundle is ready before contact starts
            let tx_start = std::cmp::max(current_time, contact.start);

            // Check contact hasn't ended
            if tx_start >= contact.end {
                return Err(Error::no_route(format!(
                    "Contact {} unavailable: ready at {} but contact ends at {}",
                    contact_id.0, tx_start, contact.end
                )));
            }

            // Compute transmission duration
            let tx_time = bundle_size.serialization_time(contact.rate)?;
            let tx_end = tx_start
                .checked_add(tx_time)
                .ok_or_else(|| Error::protocol_violation("Time overflow"))?;

            // Check transmission completes before contact ends
            if tx_end > contact.end {
                return Err(Error::no_route(format!(
                    "Contact {} too short: need {} but have {}",
                    contact_id.0,
                    tx_time,
                    contact
                        .end
                        .duration_since(tx_start)
                        .unwrap_or(SimDuration::ZERO)
                )));
            }

            // Propagate to next node
            current_time = tx_end
                .checked_add(contact.delay)
                .ok_or_else(|| Error::protocol_violation("Time overflow"))?;

            total_volume = total_volume.saturating_add(bundle_size);
        }

        Ok((current_time, total_volume))
    }

    /// Find all feasible paths and their metrics
    pub fn find_all_feasible(
        &self,
        from: &NodeId,
        to: &NodeId,
        bundle_size: Bytes,
        ready_time: SimInstant,
        max_depth: usize,
    ) -> Vec<EnumeratedPath> {
        let all_paths = self.enumerate_all_paths(from, to, max_depth);

        all_paths
            .into_iter()
            .map(
                |contacts| match self.simulate_path(&contacts, bundle_size, ready_time) {
                    Ok((arrival_time, volume_used)) => EnumeratedPath {
                        contacts,
                        arrival_time,
                        volume_used,
                        valid: true,
                        failure_reason: None,
                    },
                    Err(e) => EnumeratedPath {
                        contacts,
                        arrival_time: SimInstant::ZERO,
                        volume_used: Bytes::ZERO,
                        valid: false,
                        failure_reason: Some(e.to_string()),
                    },
                },
            )
            .collect()
    }

    /// Extract Pareto frontier from feasible paths
    ///
    /// Returns paths that are not dominated by any other path.
    /// A path dominates another if it arrives earlier AND uses less volume.
    pub fn compute_pareto_frontier(
        &self,
        from: &NodeId,
        to: &NodeId,
        bundle_size: Bytes,
        ready_time: SimInstant,
        max_depth: usize,
    ) -> Vec<EnumeratedPath> {
        let feasible = self.find_all_feasible(from, to, bundle_size, ready_time, max_depth);

        // Filter to valid paths only
        let valid_paths: Vec<_> = feasible.into_iter().filter(|p| p.valid).collect();

        // Compute Pareto frontier
        let mut frontier = Vec::new();

        for path in &valid_paths {
            let dominated = valid_paths.iter().any(|other| {
                // A path dominates another if it's better in at least one dimension
                // and not worse in the other
                other.arrival_time <= path.arrival_time
                    && other.volume_used <= path.volume_used
                    && (other.arrival_time < path.arrival_time
                        || other.volume_used < path.volume_used)
            });

            if !dominated {
                frontier.push(path.clone());
            }
        }

        frontier
    }

    /// Verify multi-label solver against oracle
    ///
    /// Returns true if solver found all Pareto-optimal routes.
    pub fn verify_solver(
        &self,
        from: &NodeId,
        to: &NodeId,
        bundle_size: Bytes,
        ready_time: SimInstant,
        solver_routes: &[ParetoRoute],
        max_depth: usize,
    ) -> Result<VerificationResult> {
        let oracle_frontier =
            self.compute_pareto_frontier(from, to, bundle_size, ready_time, max_depth);

        // Check each oracle route is in solver output
        let mut missing_routes = Vec::new();

        for oracle_path in &oracle_frontier {
            let found = solver_routes.iter().any(|solver_route| {
                // Routes match if they have same contacts and metrics
                solver_route.path == oracle_path.contacts
                    && solver_route.arrival_time == oracle_path.arrival_time
                    && solver_route.volume_used == oracle_path.volume_used
            });

            if !found {
                missing_routes.push(oracle_path.clone());
            }
        }

        // Check solver didn't return non-Pareto routes
        let mut extra_routes = Vec::new();

        for solver_route in solver_routes {
            let found = oracle_frontier
                .iter()
                .any(|oracle_path| solver_route.path == oracle_path.contacts);

            if !found {
                // Solver found a route oracle didn't - could be bug
                extra_routes.push(solver_route.clone());
            }
        }

        let matches = missing_routes.is_empty() && extra_routes.is_empty();

        Ok(VerificationResult {
            oracle_pareto_count: oracle_frontier.len(),
            solver_route_count: solver_routes.len(),
            missing_routes,
            extra_routes,
            matches,
        })
    }
}

/// Result of oracle verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Number of Pareto-optimal routes from oracle
    pub oracle_pareto_count: usize,
    /// Number of routes from solver
    pub solver_route_count: usize,
    /// Routes found by oracle but not solver
    pub missing_routes: Vec<EnumeratedPath>,
    /// Routes found by solver but not oracle
    pub extra_routes: Vec<ParetoRoute>,
    /// Whether oracle and solver agree
    pub matches: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MultiLabelSolver;
    use interplanetary_contacts::Contact;
    use interplanetary_contacts::ContactPlan;
    use interplanetary_types::BitsPerSecond;

    /// Helper: create simple 3-node linear graph
    fn make_linear_graph() -> ContactPlan {
        let mut plan = ContactPlan::new();

        // Node 1 → Node 2 (fast)
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(100_000_000_000), // 100 seconds
            rate: BitsPerSecond::from_kbps(100).unwrap(),
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        // Node 2 → Node 3 (fast)
        plan.add_contact(Contact {
            id: ContactId(2),
            from_node: NodeId::ipn(0, 2),
            to_node: NodeId::ipn(0, 3),
            start: SimInstant::from_nanos(1_000_000_000), // 1 second
            end: SimInstant::from_nanos(100_000_000_000),
            rate: BitsPerSecond::from_kbps(100).unwrap(),
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        plan
    }

    #[test]
    fn test_oracle_enumerate_linear_path() {
        let plan = make_linear_graph();
        let oracle = PathOracle::new(plan);

        let paths = oracle.enumerate_all_paths(&NodeId::ipn(0, 1), &NodeId::ipn(0, 3), 5);

        // Should find exactly one path: 1→2→3
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![ContactId(1), ContactId(2)]);
    }

    #[test]
    fn test_oracle_simulate_linear_path() {
        let plan = make_linear_graph();
        let oracle = PathOracle::new(plan);

        let path = vec![ContactId(1), ContactId(2)];
        let result = oracle.simulate_path(&path, Bytes(1000), SimInstant::ZERO);

        assert!(result.is_ok());
        let (arrival, volume) = result.unwrap();

        // Should arrive after: tx1 + delay1 + tx2 + delay2
        // tx time ≈ 80ms each (1000 bytes at 100kbps)
        // Total: ~180ms
        assert!(arrival > SimInstant::from_nanos(180_000_000)); // 180ms
        assert!(arrival < SimInstant::from_nanos(2_000_000_000)); // 2 seconds

        assert_eq!(volume, Bytes(2000)); // 1000 per hop
    }

    #[test]
    fn test_oracle_vs_solver_linear() {
        let plan1 = make_linear_graph();
        let plan2 = make_linear_graph(); // Create separate instance for solver

        let oracle = PathOracle::new(plan1);
        let solver = MultiLabelSolver::new(plan2);

        let node1 = NodeId::ipn(0, 1);
        let node3 = NodeId::ipn(0, 3);
        let bundle_size = Bytes(1000);
        let ready_time = SimInstant::ZERO;

        // Get solver routes
        let solver_result = solver
            .find_pareto_routes(&node1, &node3, ready_time, bundle_size)
            .unwrap();

        let solver_routes = solver_result.routes;

        // Verify against oracle
        let verification = oracle
            .verify_solver(&node1, &node3, bundle_size, ready_time, &solver_routes, 5)
            .unwrap();

        assert!(verification.matches, "Solver should match oracle");
        assert_eq!(verification.oracle_pareto_count, 1);
        assert_eq!(verification.solver_route_count, 1);
    }

    #[test]
    fn test_oracle_pareto_frontier_multi_path() {
        let mut plan = ContactPlan::new();

        // Node 1 → Node 2: Fast route
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(100_000_000_000), // 100 seconds
            rate: BitsPerSecond::from_kbps(1000).unwrap(), // Fast
            delay: SimDuration::from_millis(10),
            resource_group: None,
        });

        // Node 1 → Node 2: Slow route (different timing)
        plan.add_contact(Contact {
            id: ContactId(2),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::from_nanos(5_000_000_000),
            end: SimInstant::from_nanos(100_000_000_000),
            rate: BitsPerSecond::from_kbps(10).unwrap(), // Slow
            delay: SimDuration::from_millis(50),
            resource_group: None,
        });

        let oracle = PathOracle::new(plan);

        let frontier = oracle.compute_pareto_frontier(
            &NodeId::ipn(0, 1),
            &NodeId::ipn(0, 2),
            Bytes(1000),
            SimInstant::ZERO,
            3,
        );

        // Should find at least one feasible route
        assert!(!frontier.is_empty());

        // All frontier routes should be valid
        for route in &frontier {
            assert!(route.valid);
        }
    }
}
