//! Contact plan management per charter §8

use crate::types::{BitsPerSecond, Bytes, NodeId, Result, SimDuration, SimInstant};
use std::collections::HashMap;

/// Contact identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContactId(pub u64);

impl ContactId {
    /// Create new contact identifier
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Plan version for cache invalidation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanVersion(pub u64);

impl PlanVersion {
    /// Initial plan version
    pub fn initial() -> Self {
        Self(0)
    }

    /// Increment to next version
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

/// Directional contact with resource constraints
#[derive(Debug, Clone)]
pub struct Contact {
    /// Unique contact identifier
    pub id: ContactId,
    /// Source node of this contact
    pub from_node: NodeId,
    /// Destination node of this contact
    pub to_node: NodeId,
    /// Contact start time
    pub start: SimInstant,
    /// Contact end time
    pub end: SimInstant,
    /// Data rate in bits per second
    pub rate: BitsPerSecond,
    /// Propagation delay
    pub delay: SimDuration,
    /// Optional resource group for shared capacity
    pub resource_group: Option<String>,
}

impl Contact {
    /// Check if contact is active at given time
    pub fn is_active(&self, time: SimInstant) -> bool {
        time >= self.start && time < self.end
    }

    /// Get contact duration
    pub fn duration(&self) -> Option<SimDuration> {
        self.end.duration_since(self.start)
    }

    /// Compute serialization time for given bytes
    pub fn serialization_time(&self, bytes: Bytes) -> Result<SimDuration> {
        self.rate.serialization_time(bytes)
    }

    /// Find earliest available interval for transmission starting at or after ready_time
    pub fn find_available_interval(
        &self,
        ready_time: SimInstant,
        duration: SimDuration,
    ) -> Option<(SimInstant, SimInstant)> {
        // Start time is max(ready_time, contact.start)
        let start = if ready_time >= self.start {
            ready_time
        } else {
            self.start
        };

        // Check if transmission fits before contact end
        if let Some(end_time) = start.checked_add(duration)
            && end_time <= self.end
        {
            return Some((start, end_time));
        }

        None
    }
}

/// Versioned set of directional contacts used by routing and [`crate::sim::Scenario`].
///
/// # Examples
///
/// ```
/// use interplanetary_sdk::sim::{Contact, ContactId, ContactPlan};
/// use interplanetary_sdk::types::*;
///
/// # fn main() -> Result<()> {
/// let mut plan = ContactPlan::new();
/// plan.add_contact(Contact {
///     id: ContactId(1),
///     from_node: NodeId::ipn(0, 1), // Earth
///     to_node: NodeId::ipn(0, 2),   // Relay
///     start: SimInstant::ZERO,
///     end: SimInstant::from_nanos(10_000_000_000),
///     rate: BitsPerSecond::from_kbps(8)?,
///     delay: SimDuration::from_secs(4),
///     resource_group: Some("earth-relay".into()),
/// });
/// assert!(plan.get_contact(ContactId(1)).unwrap().is_active(SimInstant::ZERO));
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ContactPlan {
    contacts: HashMap<ContactId, Contact>,
    version: PlanVersion,
    next_id: u64,
}

impl ContactPlan {
    /// Create new empty plan
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
            version: PlanVersion::initial(),
            next_id: 1,
        }
    }

    /// Add contact to plan
    pub fn add_contact(&mut self, contact: Contact) {
        self.contacts.insert(contact.id, contact);
        self.version = self.version.next();
    }

    /// Remove contact from plan
    pub fn remove_contact(&mut self, id: ContactId) -> Option<Contact> {
        let removed = self.contacts.remove(&id);
        if removed.is_some() {
            self.version = self.version.next();
        }
        removed
    }

    /// Get all contacts (read-only)
    pub fn contacts(&self) -> Vec<Contact> {
        self.contacts.values().cloned().collect()
    }

    /// Get contact by ID
    pub fn get_contact(&self, id: ContactId) -> Option<&Contact> {
        self.contacts.get(&id)
    }

    /// Get current plan version
    pub fn version(&self) -> PlanVersion {
        self.version
    }

    /// Find contacts from node active at or after time
    pub fn find_contacts_from(&self, from_node: &NodeId, after_time: SimInstant) -> Vec<&Contact> {
        self.contacts
            .values()
            .filter(|c| &c.from_node == from_node && c.end > after_time)
            .collect()
    }

    /// Find all contacts between two nodes
    pub fn find_contacts_between(&self, from_node: &NodeId, to_node: &NodeId) -> Vec<&Contact> {
        self.contacts
            .values()
            .filter(|c| &c.from_node == from_node && &c.to_node == to_node)
            .collect()
    }

    /// Generate new contact ID
    pub fn next_contact_id(&mut self) -> ContactId {
        let id = ContactId(self.next_id);
        self.next_id += 1;
        id
    }
}

impl Default for ContactPlan {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_active() {
        let contact = Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::from_nanos(1000),
            end: SimInstant::from_nanos(2000),
            rate: BitsPerSecond::from_kbps(1).unwrap(),
            delay: SimDuration::from_millis(100),
            resource_group: None,
        };

        assert!(!contact.is_active(SimInstant::from_nanos(999)));
        assert!(contact.is_active(SimInstant::from_nanos(1000)));
        assert!(contact.is_active(SimInstant::from_nanos(1500)));
        assert!(!contact.is_active(SimInstant::from_nanos(2000)));
    }

    #[test]
    fn test_contact_find_interval() {
        let contact = Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::from_nanos(1000),
            end: SimInstant::from_nanos(3000),
            rate: BitsPerSecond::from_kbps(1).unwrap(),
            delay: SimDuration::from_millis(100),
            resource_group: None,
        };

        // Ready before contact starts
        let interval = contact
            .find_available_interval(SimInstant::from_nanos(500), SimDuration::from_nanos(500));
        assert_eq!(
            interval,
            Some((SimInstant::from_nanos(1000), SimInstant::from_nanos(1500)))
        );

        // Ready during contact
        let interval = contact
            .find_available_interval(SimInstant::from_nanos(1500), SimDuration::from_nanos(500));
        assert_eq!(
            interval,
            Some((SimInstant::from_nanos(1500), SimInstant::from_nanos(2000)))
        );

        // Duration too long
        let interval = contact
            .find_available_interval(SimInstant::from_nanos(1000), SimDuration::from_nanos(3000));
        assert_eq!(interval, None);
    }

    #[test]
    fn test_contact_plan_versioning() {
        let mut plan = ContactPlan::new();
        assert_eq!(plan.version(), PlanVersion(0));

        let contact = Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(1000),
            rate: BitsPerSecond::from_kbps(1).unwrap(),
            delay: SimDuration::ZERO,
            resource_group: None,
        };

        plan.add_contact(contact);
        assert_eq!(plan.version(), PlanVersion(1));

        plan.remove_contact(ContactId(1));
        assert_eq!(plan.version(), PlanVersion(2));
    }

    #[test]
    fn test_serialization_time() {
        let contact = Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(10_000_000_000),
            rate: BitsPerSecond::from_kbps(8).unwrap(), // 8000 bps = 1000 bytes/sec
            delay: SimDuration::ZERO,
            resource_group: None,
        };

        let time = contact.serialization_time(Bytes(100)).unwrap();
        // 100 bytes at 1000 bytes/sec = 0.1 sec = 100 ms
        assert_eq!(time.as_millis(), 100);
    }
}
