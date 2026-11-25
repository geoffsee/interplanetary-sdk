//! Contact Graph Routing approximation (CgrApproxV1)
//!
//! Simplified routing: earliest arrival via Dijkstra-like search over contacts.

use crate::sim::{ContactId, ContactPlan};
use crate::types::{Bytes, Error, NodeId, Result, SimInstant};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

/// CGR configuration
#[derive(Debug, Clone)]
pub struct CgrConfig {
    /// Maximum search depth (hops)
    pub max_hops: u32,
    /// Earliest transmission time
    pub earliest_start: SimInstant,
}

impl Default for CgrConfig {
    fn default() -> Self {
        Self {
            max_hops: 10,
            earliest_start: SimInstant::ZERO,
        }
    }
}

/// Route information
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Next hop node
    pub next_hop: NodeId,
    /// First contact to use
    pub via_contact: ContactId,
    /// Estimated arrival time
    pub arrival_time: SimInstant,
    /// Full contact path
    pub path: Vec<ContactId>,
}

/// Path search state for Dijkstra
#[derive(Debug, Clone)]
struct SearchNode {
    node: NodeId,
    arrival_time: SimInstant,
    path: Vec<ContactId>,
    hops: u32,
}

impl Ord for SearchNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Earlier arrival is better (reverse for min-heap)
        other.arrival_time.cmp(&self.arrival_time)
    }
}

impl PartialOrd for SearchNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SearchNode {
    fn eq(&self, other: &Self) -> bool {
        self.arrival_time == other.arrival_time
    }
}

impl Eq for SearchNode {}

/// Earliest-arrival contact-graph router (approximation, not full ION CGR).
///
/// Searches the [`ContactPlan`] for a feasible path
/// under hop and volume constraints. Prefer this for scheduler-style what-if
/// analysis; use [`crate::sim::Scenario`] when you need inject → deliver.
///
/// # Examples
///
/// ```
/// use interplanetary_sdk::routing::{CgrConfig, CgrRouter};
/// use interplanetary_sdk::sim::{Contact, ContactId, ContactPlan};
/// use interplanetary_sdk::types::*;
///
/// # fn main() -> Result<()> {
/// let mut plan = ContactPlan::new();
/// plan.add_contact(Contact {
///     id: ContactId(1),
///     from_node: NodeId::ipn(0, 1),
///     to_node: NodeId::ipn(0, 2),
///     start: SimInstant::ZERO,
///     end: SimInstant::from_nanos(10_000_000_000),
///     rate: BitsPerSecond::from_kbps(8)?,
///     delay: SimDuration::from_secs(4),
///     resource_group: None,
/// });
///
/// let router = CgrRouter::new(CgrConfig::default());
/// let route = router.compute_route(
///     &NodeId::ipn(0, 1),
///     &NodeId::ipn(0, 2),
///     Bytes(1_000),
///     SimInstant::ZERO,
///     &plan,
/// )?;
/// assert_eq!(route.next_hop, NodeId::ipn(0, 2));
/// assert_eq!(route.via_contact, ContactId(1));
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CgrRouter {
    config: CgrConfig,
}

impl CgrRouter {
    /// Create new CGR router
    pub fn new(config: CgrConfig) -> Self {
        Self { config }
    }

    /// Compute earliest-arrival route from `from` to `to`.
    ///
    /// `bundle_size` is checked against remaining contact volume;
    /// `ready_time` is the earliest the bundle can leave `from`.
    pub fn compute_route(
        &self,
        from: &NodeId,
        to: &NodeId,
        bundle_size: Bytes,
        ready_time: SimInstant,
        plan: &ContactPlan,
    ) -> Result<RouteInfo> {
        // Priority queue for search (min-heap by arrival time)
        let mut queue = BinaryHeap::new();
        let mut best_arrival: HashMap<NodeId, SimInstant> = HashMap::new();

        // Start search from source
        queue.push(SearchNode {
            node: from.clone(),
            arrival_time: ready_time,
            path: Vec::new(),
            hops: 0,
        });
        best_arrival.insert(from.clone(), ready_time);

        // Search for earliest arrival
        while let Some(current) = queue.pop() {
            // Check if reached destination
            if &current.node == to {
                // Found route
                if current.path.is_empty() {
                    return Err(Error::no_route("No contacts in path"));
                }

                let first_contact_id = current.path[0];
                let first_contact = plan
                    .get_contact(first_contact_id)
                    .ok_or_else(|| Error::no_route("Contact not found"))?;

                return Ok(RouteInfo {
                    next_hop: first_contact.to_node.clone(),
                    via_contact: first_contact_id,
                    arrival_time: current.arrival_time,
                    path: current.path,
                });
            }

            // Check hop limit
            if current.hops >= self.config.max_hops {
                continue;
            }

            // Explore outgoing contacts from current node
            let contacts = plan.find_contacts_from(&current.node, current.arrival_time);

            for contact in contacts {
                // Check if bundle fits and contact is usable
                let tx_time = match contact.serialization_time(bundle_size) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                // Find when transmission can start
                let interval = match contact.find_available_interval(current.arrival_time, tx_time)
                {
                    Some(i) => i,
                    None => continue,
                };

                // Compute arrival at next hop
                let tx_complete = interval.1;
                let arrival = match tx_complete.checked_add(contact.delay) {
                    Some(a) => a,
                    None => continue,
                };

                // Check if this is better than previous arrival at this node
                let neighbor = &contact.to_node;
                if let Some(&prev_arrival) = best_arrival.get(neighbor)
                    && arrival >= prev_arrival
                {
                    continue; // Not better
                }

                // Update best arrival and enqueue
                best_arrival.insert(neighbor.clone(), arrival);

                let mut new_path = current.path.clone();
                new_path.push(contact.id);

                queue.push(SearchNode {
                    node: neighbor.clone(),
                    arrival_time: arrival,
                    path: new_path,
                    hops: current.hops + 1,
                });
            }
        }

        Err(Error::no_route(format!("No route from {} to {}", from, to)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::Contact;
    use crate::types::BitsPerSecond;
    use crate::types::SimDuration;

    #[test]
    fn test_cgr_direct_route() {
        let mut plan = ContactPlan::new();

        // Single direct contact
        let contact = Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(10_000_000_000),
            rate: BitsPerSecond::from_kbps(8).unwrap(),
            delay: SimDuration::ZERO,
            resource_group: None,
        };
        plan.add_contact(contact);

        let router = CgrRouter::new(CgrConfig::default());
        let route = router
            .compute_route(
                &NodeId::ipn(0, 1),
                &NodeId::ipn(0, 2),
                Bytes(100),
                SimInstant::ZERO,
                &plan,
            )
            .unwrap();

        assert_eq!(route.next_hop, NodeId::ipn(0, 2));
        assert_eq!(route.via_contact, ContactId(1));
    }

    #[test]
    fn test_cgr_two_hop_route() {
        let mut plan = ContactPlan::new();

        // Earth → Relay
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(10_000_000_000),
            rate: BitsPerSecond::from_kbps(8).unwrap(),
            delay: SimDuration::from_secs(4),
            resource_group: None,
        });

        // Relay → Mars
        plan.add_contact(Contact {
            id: ContactId(2),
            from_node: NodeId::ipn(0, 2),
            to_node: NodeId::ipn(0, 3),
            start: SimInstant::from_nanos(10_000_000_000),
            end: SimInstant::from_nanos(20_000_000_000),
            rate: BitsPerSecond::from_kbps(8).unwrap(),
            delay: SimDuration::from_secs(6),
            resource_group: None,
        });

        let router = CgrRouter::new(CgrConfig::default());
        let route = router
            .compute_route(
                &NodeId::ipn(0, 1),
                &NodeId::ipn(0, 3),
                Bytes(1000),
                SimInstant::ZERO,
                &plan,
            )
            .unwrap();

        // Should route via relay
        assert_eq!(route.next_hop, NodeId::ipn(0, 2));
        assert_eq!(route.path.len(), 2);
    }

    #[test]
    fn test_cgr_no_route() {
        let plan = ContactPlan::new();
        let router = CgrRouter::new(CgrConfig::default());

        let result = router.compute_route(
            &NodeId::ipn(0, 1),
            &NodeId::ipn(0, 2),
            Bytes(100),
            SimInstant::ZERO,
            &plan,
        );

        assert!(result.is_err());
    }
}
