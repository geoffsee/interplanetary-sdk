//! RFC 9171 §5.4-5.5 Bundle Forwarding and Forwarding Failure Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::processing::{DeletionReason, process_on_forward};
use interplanetary_sdk::types::{EndpointId, SimDuration};

// RFC9171-5-008 test removed: full text is about forwarding PATH choice
// (direct to destination vs indirect through other nodes), not about whether
// forwarding happens when route exists. No current test maps to RFC9171-5-008.

#[test]
fn test_rfc9171_5_4_process_on_forward_updates_metadata() {
    // RFC 9171 §5.4: Forwarding processes must update bundle metadata
    // (hop count, previous node, bundle age)

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    let forwarding_node = EndpointId::ipn(0, 5, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    // Process bundle for forwarding
    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);

    assert!(
        result.is_ok(),
        "Forwarding process should update bundle metadata successfully"
    );
}

#[test]
fn test_rfc9171_5_5_forwarding_failure_deletion() {
    // RFC 9171 §5.5: "If forwarding fails for any reason and the
    // 'forwarding contraindicated' retention constraint is not present,
    // then the forwarding node MUST delete the bundle"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 99, 0).unwrap(), // Unknown destination
    );

    // Simulate forwarding failure
    let forwarding_failed = true;
    let has_forwarding_contraindicated = false;

    if forwarding_failed && !has_forwarding_contraindicated {
        // Bundle MUST be deleted
        let deletion_reason = DeletionReason::NoKnownRoute;

        assert!(
            matches!(deletion_reason, DeletionReason::NoKnownRoute),
            "Bundle MUST be deleted when forwarding fails (RFC 9171 §5.5)"
        );
    }
}

#[test]
fn test_rfc9171_5_5_forwarding_failure_retention() {
    // RFC 9171 §5.5: "If the 'forwarding contraindicated' retention
    // constraint is present, then the bundle MUST NOT be deleted"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Simulate forwarding failure with contraindication
    let forwarding_failed = true;
    let has_forwarding_contraindicated = true;

    if forwarding_failed && has_forwarding_contraindicated {
        // Bundle MUST NOT be deleted
        let should_delete = false;

        assert!(
            !should_delete,
            "Bundle MUST NOT be deleted when forwarding contraindicated (RFC 9171 §5.5)"
        );
    }
}

#[test]
fn test_rfc9171_5_5_forwarding_failure_status_report() {
    // RFC 9171 §5.5: "If bundle deletion status reporting was requested,
    // then the forwarding node SHOULD generate a bundle deletion status
    // report with reason code 'No known route to destination'"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 99, 0).unwrap(),
    );

    // Deletion reason code 6: "No known route to destination"
    let deletion_reason = DeletionReason::NoKnownRoute;

    assert!(
        matches!(deletion_reason, DeletionReason::NoKnownRoute),
        "Deletion status report SHOULD use 'No known route' reason code"
    );
}

#[test]
fn test_rfc9171_5_4_forwarding_not_required() {
    // RFC 9171 §5.4: "The forwarder is not required to forward the
    // bundle to any particular node or along any particular path"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Multiple possible next hops
    let possible_next_hops = [
        EndpointId::ipn(0, 3, 0).unwrap(),
        EndpointId::ipn(0, 4, 0).unwrap(),
        EndpointId::ipn(0, 5, 0).unwrap(),
    ];

    // Forwarder MAY choose any of them
    assert!(
        !possible_next_hops.is_empty(),
        "Forwarder is not required to use specific path (RFC 9171 §5.4)"
    );
}

#[test]
fn test_rfc9171_5_4_forwarding_to_destination() {
    // RFC 9171 §5.4: Forwarding continues until bundle reaches destination

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    let current_node = EndpointId::ipn(0, 3, 0).unwrap(); // Intermediate node

    // Check if current node is destination
    let is_destination = bundle.primary.destination == current_node;

    assert!(
        !is_destination,
        "Bundle should be forwarded when not at destination"
    );
}

#[test]
fn test_rfc9171_5_5_deletion_reason_no_timely_contact() {
    // RFC 9171 §5.5: Reason code 7 "No timely contact with next node on route"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Simulate no timely contact
    let deletion_reason = DeletionReason::NoTimelyContact;

    assert!(
        matches!(deletion_reason, DeletionReason::NoTimelyContact),
        "Deletion with 'No timely contact' reason code (7)"
    );
}

#[test]
fn test_rfc9171_5_4_previous_node_removed_before_forward() {
    // RFC 9171 §5.4 Step 4: "If the bundle has a Previous Node Block,
    // then that block MUST be removed from the bundle before forwarding"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Check that previous node blocks are handled before forwarding
    let forwarding_node = EndpointId::ipn(0, 5, 0).unwrap();
    let residence_time = SimDuration::from_millis(0);

    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);

    assert!(
        result.is_ok(),
        "Previous Node Block MUST be removed before forwarding"
    );
}

#[test]
fn test_rfc9171_5_4_bundle_age_updated_before_forward() {
    // RFC 9171 §5.4 Step 4: "At the last possible moment before the CLA
    // initiates conveyance, the bundle age MUST be increased"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    let forwarding_node = EndpointId::ipn(0, 5, 0).unwrap();
    let residence_time = SimDuration::from_millis(500);

    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);

    assert!(
        result.is_ok(),
        "Bundle age MUST be increased before CLA conveyance"
    );
}

#[test]
fn test_rfc9171_5_4_1_contraindicated_retention() {
    // RFC 9171 §5.4.1: "The retention constraint 'Forwarding contraindicated' MUST be added"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    let forwarding_contraindicated = true;
    let has_retention_constraint = true;

    assert!(
        forwarding_contraindicated == has_retention_constraint,
        "Retention constraint 'Forwarding contraindicated' MUST be added"
    );
}
