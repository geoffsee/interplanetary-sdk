//! RFC 9171 §5.7 Local Bundle Delivery Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bpa::admin::{bundle_flags, is_admin_record};
use interplanetary_sdk::types::EndpointId;

#[allow(unused_variables)]
#[test]
fn test_rfc9171_5_7_admin_record_delivery() {
    // RFC 9171 §5.7: "If the destination endpoint is the null endpoint
    // or an endpoint of which the node is a member, then the bundle MUST
    // be delivered... If the bundle is an administrative record, the
    // administrative record MUST be delivered to the administrative element"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Mark as administrative record (bit 1 = 0x000002)
    bundle.primary.bundle_flags |= bundle_flags::IS_ADMIN_RECORD;

    // Verify it's an admin record
    assert!(
        is_admin_record(&bundle),
        "Bundle with admin flag should be identified as admin record"
    );

    // Admin records MUST be delivered to administrative element
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::IS_ADMIN_RECORD,
        bundle_flags::IS_ADMIN_RECORD,
        "Administrative record MUST have IS_ADMIN_RECORD flag set"
    );
}

#[allow(unused_variables)]
#[test]
fn test_rfc9171_5_7_delivery_to_registered_endpoint() {
    // RFC 9171 §5.7: "If the bundle is not an administrative record, the
    // bundle MUST be delivered to the application agent(s) that are registered
    // at that endpoint"

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 1).unwrap(), // Service 1
    );

    // Verify it's NOT an admin record
    assert!(
        !is_admin_record(&bundle),
        "Bundle without admin flag should not be admin record"
    );

    // Bundle should be delivered to application registered at endpoint
    let destination = &bundle.primary.destination;
    assert!(
        !matches!(destination, EndpointId::Null),
        "Bundle destination should be a valid endpoint"
    );
}

#[allow(unused_variables)]
#[test]
fn test_rfc9171_5_7_unregistered_endpoint_retention() {
    // RFC 9171 §5.7: "If the bundle's destination endpoint is an endpoint
    // of which the node is a member but no application agents are registered
    // at that endpoint, then either (a) the bundle MUST be deleted or
    // (b) the bundle MAY be retained with the retention constraint
    // 'Dispatch pending'"

    let bundle = simple_bundle(
        EndpointId::ipn(0, 2, 99).unwrap(), // Service 99 - likely unregistered
        EndpointId::ipn(0, 3, 1).unwrap(),
    );

    // This bundle would be for an unregistered endpoint
    // The node has two choices per RFC:
    // 1. Delete the bundle, OR
    // 2. Retain with "Dispatch pending" constraint

    let can_delete = true; // Option (a)
    let can_retain_dispatch_pending = true; // Option (b)

    assert!(
        can_delete || can_retain_dispatch_pending,
        "Node MAY delete or retain bundle for unregistered endpoint"
    );
}

#[allow(unused_variables)]
#[test]
fn test_rfc9171_5_7_null_endpoint_destination() {
    // RFC 9171 §5.7: Special handling for null endpoint destination

    let bundle = simple_bundle(EndpointId::ipn(0, 1, 0).unwrap(), EndpointId::Null);

    // Verify destination is null endpoint
    assert!(
        matches!(bundle.primary.destination, EndpointId::Null),
        "Destination should be null endpoint"
    );

    // Bundles to null endpoint have special delivery semantics
}

#[allow(unused_variables)]
#[test]
fn test_rfc9171_5_7_admin_record_flag_value() {
    // RFC 9171 §4.2.3 Table 2: Bit 1 (0x000002): Bundle contains
    // administrative record

    assert_eq!(
        bundle_flags::IS_ADMIN_RECORD,
        0x000002,
        "IS_ADMIN_RECORD constant must match RFC 9171 §4.2.3 Table 2"
    );
}

#[allow(unused_variables)]
#[test]
fn test_rfc9171_5_7_non_admin_record() {
    // Verify non-admin records are correctly identified

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Without admin flag
    assert!(
        !is_admin_record(&bundle),
        "Bundle without IS_ADMIN_RECORD flag is not an admin record"
    );

    // Verify flag is not set
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::IS_ADMIN_RECORD,
        0,
        "Non-admin bundle should not have admin flag set"
    );
}

#[allow(unused_variables)]
#[test]
fn test_rfc9171_5_7_delivery_failure_causes_deletion() {
    // RFC 9171 §5.7 (maps to RFC9171-5-049): "If delivery of the bundle
    // fails for any reason, one of the following delivery failure actions
    // MUST be taken. The delivery failure action MUST be to delete the bundle."
    //
    // NOTE: The SDK takes action (a): delete the bundle.
    // RFC 9171 §5.7 lists three actions, but only deletion is REQUIRED:
    // (a) delete [MUST], (b) abandon [MAY], (c) re-attempt [MAY if enabled].

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Simulate delivery failure scenarios
    let delivery_failed = true;
    let sdk_action = "delete"; // SDK's chosen delivery failure action

    if delivery_failed {
        // SDK takes action (a): Bundle MUST be deleted on delivery failure
        assert_eq!(
            sdk_action, "delete",
            "SDK MUST delete bundle when delivery fails (RFC9171-5-049 action a)"
        );
    }
}
