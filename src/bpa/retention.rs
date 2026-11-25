//! Retention constraints per RFC 9171 §5.3
//!
//! "Each bundle has zero or more 'retention constraints', each of which
//! asserts that the bundle must temporarily be retained in the node's bundle
//! storage even though it has not yet been delivered (if it ever can be)."

use std::collections::HashSet;

/// Retention constraint types per RFC 9171 §5.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetentionConstraint {
    /// RFC 9171 §5.3: "Dispatch pending" - bundle not yet transmitted
    DispatchPending,

    /// RFC 9171 §5.3: "Forward pending" - bundle awaiting forwarding
    ForwardPending,

    /// RFC 9171 §5.3: "Reassembly pending" - bundle is a fragment awaiting reassembly
    ReassemblyPending,

    /// RFC 9171 §5.3: "Custody accepted" (deprecated in BPv7, included for completeness)
    #[allow(dead_code)]
    CustodyAccepted,
}

/// Retention constraint set for a bundle
#[derive(Debug, Clone, Default)]
pub struct RetentionConstraintSet {
    constraints: HashSet<RetentionConstraint>,
}

impl RetentionConstraintSet {
    /// Create new empty constraint set
    pub fn new() -> Self {
        Self {
            constraints: HashSet::new(),
        }
    }

    /// Add a retention constraint
    ///
    /// RFC 9171 §5.3: Constraints are added as bundles enter different
    /// processing states (dispatch, forward, reassembly)
    pub fn add(&mut self, constraint: RetentionConstraint) {
        self.constraints.insert(constraint);
    }

    /// Remove a retention constraint
    ///
    /// RFC 9171 §5.4: Constraints are removed when the associated action
    /// completes (bundle transmitted, forwarded, reassembled)
    pub fn remove(&mut self, constraint: RetentionConstraint) {
        self.constraints.remove(&constraint);
    }

    /// Check if any constraints remain
    ///
    /// RFC 9171 §5.4: "As soon as a bundle has no remaining retention
    /// constraints, the bundle MAY be deleted from the node's bundle storage"
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    /// Check if a specific constraint is present
    pub fn has(&self, constraint: RetentionConstraint) -> bool {
        self.constraints.contains(&constraint)
    }

    /// Get count of active constraints
    pub fn count(&self) -> usize {
        self.constraints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_constraint_lifecycle() {
        let mut constraints = RetentionConstraintSet::new();

        // RFC 9171 §5.3: Start with no constraints
        assert!(constraints.is_empty());
        assert_eq!(constraints.count(), 0);

        // Add dispatch pending constraint
        constraints.add(RetentionConstraint::DispatchPending);
        assert!(!constraints.is_empty());
        assert!(constraints.has(RetentionConstraint::DispatchPending));
        assert_eq!(constraints.count(), 1);

        // Add forward pending constraint
        constraints.add(RetentionConstraint::ForwardPending);
        assert_eq!(constraints.count(), 2);

        // Remove dispatch pending (bundle transmitted)
        constraints.remove(RetentionConstraint::DispatchPending);
        assert!(!constraints.has(RetentionConstraint::DispatchPending));
        assert!(constraints.has(RetentionConstraint::ForwardPending));
        assert_eq!(constraints.count(), 1);

        // Remove forward pending (bundle forwarded)
        constraints.remove(RetentionConstraint::ForwardPending);

        // RFC 9171 §5.4: Bundle may be deleted when no constraints remain
        assert!(constraints.is_empty());
    }

    #[test]
    fn test_reassembly_pending_constraint() {
        let mut constraints = RetentionConstraintSet::new();

        // RFC 9171 §5.9: Fragments have reassembly pending constraint
        constraints.add(RetentionConstraint::ReassemblyPending);
        assert!(constraints.has(RetentionConstraint::ReassemblyPending));

        // RFC 9171 §5.9: Constraint removed after successful reassembly
        constraints.remove(RetentionConstraint::ReassemblyPending);
        assert!(constraints.is_empty());
    }

    #[test]
    fn test_multiple_constraints() {
        let mut constraints = RetentionConstraintSet::new();

        // Bundle can have multiple constraints simultaneously
        constraints.add(RetentionConstraint::DispatchPending);
        constraints.add(RetentionConstraint::ForwardPending);
        constraints.add(RetentionConstraint::ReassemblyPending);

        assert_eq!(constraints.count(), 3);

        // RFC 9171 §5.4: Bundle retained until ALL constraints removed
        constraints.remove(RetentionConstraint::DispatchPending);
        assert!(
            !constraints.is_empty(),
            "Bundle retained while constraints remain"
        );

        constraints.remove(RetentionConstraint::ForwardPending);
        assert!(
            !constraints.is_empty(),
            "Bundle retained while constraints remain"
        );

        constraints.remove(RetentionConstraint::ReassemblyPending);
        assert!(
            constraints.is_empty(),
            "Bundle may be deleted when all constraints removed"
        );
    }

    #[test]
    fn test_idempotent_operations() {
        let mut constraints = RetentionConstraintSet::new();

        // Adding same constraint multiple times is idempotent
        constraints.add(RetentionConstraint::DispatchPending);
        constraints.add(RetentionConstraint::DispatchPending);
        assert_eq!(constraints.count(), 1);

        // Removing non-existent constraint is safe
        constraints.remove(RetentionConstraint::ForwardPending);
        assert_eq!(constraints.count(), 1);
    }
}
