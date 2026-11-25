//! RFC 9171 §5.10-5.12 Bundle Deletion, Discarding, and Canceling tests
//!
//! Tests deletion procedures and retention constraints

use interplanetary_sdk::bpa::admin::ReasonCode;
use interplanetary_sdk::bpa::retention::{RetentionConstraint, RetentionConstraintSet};

/// Test RFC 9171 §5.3-5.4: Retention constraint lifecycle
#[test]
fn test_rfc9171_5_3_retention_constraint_basic() {
    // RFC 9171 §5.3: "Each bundle has zero or more 'retention constraints',
    // each of which asserts that the bundle must temporarily be retained in
    // the node's bundle storage"

    let mut constraints = RetentionConstraintSet::new();

    // Initially no constraints
    assert!(
        constraints.is_empty(),
        "New bundle should have no retention constraints"
    );

    // Add dispatch pending constraint
    constraints.add(RetentionConstraint::DispatchPending);
    assert!(!constraints.is_empty());
    assert!(constraints.has(RetentionConstraint::DispatchPending));
}

/// Test RFC 9171 §5.4: Bundle deletion when constraints removed
#[test]
fn test_rfc9171_5_4_deletion_when_no_constraints() {
    // RFC 9171 §5.4: "As soon as a bundle has no remaining retention
    // constraints, the bundle MAY be deleted from the node's bundle storage"

    let mut constraints = RetentionConstraintSet::new();

    // Add constraint (bundle retained)
    constraints.add(RetentionConstraint::DispatchPending);
    assert!(
        !constraints.is_empty(),
        "Bundle with constraints must be retained"
    );

    // Remove constraint
    constraints.remove(RetentionConstraint::DispatchPending);

    // RFC 9171 §5.4: Now bundle MAY be deleted
    assert!(
        constraints.is_empty(),
        "Bundle with no constraints may be deleted per §5.4"
    );
}

/// Test RFC 9171 §5.10: Deletion reason codes exist
#[test]
fn test_rfc9171_5_10_deletion_reason_codes_section5_10() {
    // RFC 9171 §5.10 Table 5: Status report reason codes
    // Verify key reason codes exist in implementation

    let _ = ReasonCode::LifetimeExpired;
    let _ = ReasonCode::TransmissionCancelled;
    let _ = ReasonCode::DepletedStorage;
    let _ = ReasonCode::NoKnownRoute;
    let _ = ReasonCode::NoTimelyContact;
    let _ = ReasonCode::BlockUnintelligible;
    let _ = ReasonCode::HopLimitExceeded;
    let _ = ReasonCode::BlockUnsupported;
}

/// Test RFC 9171 §5.10: Multiple retention constraints
#[test]
fn test_rfc9171_5_10_multiple_constraints() {
    // RFC 9171 §5.10 Step 2: "All of the bundle's retention constraints
    // MUST be removed"

    let mut constraints = RetentionConstraintSet::new();

    // Bundle with multiple constraints
    constraints.add(RetentionConstraint::DispatchPending);
    constraints.add(RetentionConstraint::ForwardPending);
    constraints.add(RetentionConstraint::ReassemblyPending);

    assert_eq!(constraints.count(), 3);

    // RFC 9171 §5.10 Step 2: Remove ALL constraints
    constraints.remove(RetentionConstraint::DispatchPending);
    constraints.remove(RetentionConstraint::ForwardPending);
    constraints.remove(RetentionConstraint::ReassemblyPending);

    // RFC 9171 §5.4: Bundle may now be deleted
    assert!(
        constraints.is_empty(),
        "All retention constraints must be removed per §5.10 Step 2"
    );
}

/// Test RFC 9171 §5.9: Reassembly pending constraint
#[test]
fn test_rfc9171_5_9_reassembly_pending_constraint() {
    // RFC 9171 §5.9: "The 'Reassembly pending' retention constraint MUST be
    // removed from the reassembled bundle"

    let mut constraints = RetentionConstraintSet::new();

    // Fragment has reassembly pending constraint
    constraints.add(RetentionConstraint::ReassemblyPending);
    assert!(constraints.has(RetentionConstraint::ReassemblyPending));

    // After successful reassembly, constraint MUST be removed
    constraints.remove(RetentionConstraint::ReassemblyPending);

    assert!(
        !constraints.has(RetentionConstraint::ReassemblyPending),
        "Reassembly pending constraint MUST be removed per §5.9"
    );
}

/// Test RFC 9171 §5.10: Deletion procedure ordering
#[test]
fn test_rfc9171_5_10_deletion_procedure() {
    // RFC 9171 §5.10: Deletion procedure has specific steps:
    // Step 1: Status report (if requested)
    // Step 2: Remove all retention constraints
    // Step 3: Bundle deleted

    let mut constraints = RetentionConstraintSet::new();
    constraints.add(RetentionConstraint::DispatchPending);

    // Step 1: Generate deletion status report (tested elsewhere)
    // (Would check bundle flags for REQUEST_REPORT_DELETION)

    // Step 2: Remove ALL retention constraints
    constraints.remove(RetentionConstraint::DispatchPending);
    assert!(
        constraints.is_empty(),
        "Step 2: All retention constraints MUST be removed"
    );

    // Step 3: Bundle is deleted (would be removed from storage)
    // In real BPA, storage.delete(bundle_id) would be called here
}

/// Test RFC 9171 §5.11: Discarding vs deletion
#[test]
fn test_rfc9171_5_11_discarding_distinction() {
    // RFC 9171 §5.11: "Discarding a bundle is a procedural step that may
    // result in deletion of the bundle but is not the same as deletion"

    // Discarding removes specific retention constraint
    let mut constraints = RetentionConstraintSet::new();
    constraints.add(RetentionConstraint::DispatchPending);
    constraints.add(RetentionConstraint::ForwardPending);

    // Discard only removes one constraint (e.g., forward pending)
    constraints.remove(RetentionConstraint::ForwardPending);

    // Bundle NOT deleted if other constraints remain
    assert!(
        !constraints.is_empty(),
        "Discarding does not delete bundle if constraints remain per §5.11"
    );

    // Bundle only deleted when ALL constraints removed
    constraints.remove(RetentionConstraint::DispatchPending);
    assert!(
        constraints.is_empty(),
        "Deletion occurs only when all constraints removed per §5.11"
    );
}

/// Test RFC 9171 §5.3: Dispatch pending constraint
#[test]
fn test_rfc9171_5_3_dispatch_pending() {
    // RFC 9171 §5.3: "Dispatch pending" - bundle queued for transmission

    let mut constraints = RetentionConstraintSet::new();

    // When bundle admitted for transmission
    constraints.add(RetentionConstraint::DispatchPending);
    assert!(constraints.has(RetentionConstraint::DispatchPending));

    // After transmission completes
    constraints.remove(RetentionConstraint::DispatchPending);
    assert!(!constraints.has(RetentionConstraint::DispatchPending));
}

/// Test RFC 9171 §5.3: Forward pending constraint
#[test]
fn test_rfc9171_5_3_forward_pending() {
    // RFC 9171 §5.3: "Forward pending" - bundle awaiting forwarding decision

    let mut constraints = RetentionConstraintSet::new();

    // When bundle awaiting forwarding
    constraints.add(RetentionConstraint::ForwardPending);
    assert!(constraints.has(RetentionConstraint::ForwardPending));

    // After forwarding decision made
    constraints.remove(RetentionConstraint::ForwardPending);
    assert!(!constraints.has(RetentionConstraint::ForwardPending));
}
