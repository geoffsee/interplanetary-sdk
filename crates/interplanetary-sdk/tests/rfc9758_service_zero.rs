//! RFC 9758 Service Number 0 Administrative Endpoint tests
//!
//! Tests for administrative endpoint constraints per RFC 9758 §6.3

use interplanetary_sdk::bpa::admin::{ReasonCode, StatusReport, create_status_report_bundle};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId, SimInstant};

/// Test RFC 9758 §6.3: Service number 0 is the administrative endpoint
#[test]
fn test_rfc9758_6_3_service_zero_administrative() {
    // RFC 9758 §6.3: "The service identified by a Service Number of zero (0)
    // MUST be an administrative endpoint"

    // Create an administrative endpoint with service 0
    let admin_endpoint = EndpointId::ipn(0, 1, 0).unwrap();

    // Verify service number is 0
    if let EndpointId::Ipn { service, .. } = admin_endpoint {
        assert_eq!(
            service, 0,
            "Administrative endpoint MUST have service number 0 per RFC 9758 §6.3"
        );
    } else {
        panic!("Expected IPN endpoint");
    }

    // Verify administrative bundles use service 0
    let status_report = StatusReport::deletion(
        EndpointId::ipn(0, 2, 0).unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1),
        ReasonCode::LifetimeExpired,
        None,
    );

    let bundle = create_status_report_bundle(
        status_report,
        &EndpointId::ipn(0, 1, 0).unwrap(), // Source (reporting node)
        &EndpointId::ipn(0, 2, 0).unwrap(), // Destination (report-to)
        SimInstant::from_nanos(2_000_000_000),
        1,
        false, // Don't include status time
    )
    .unwrap();

    // RFC 9758 §6.3: Status reports use service 0
    if let EndpointId::Ipn { service, .. } = bundle.primary.source {
        assert_eq!(
            service, 0,
            "Status report source MUST use service 0 per RFC 9758 §6.3"
        );
    }
}

/// Test RFC 9758 §6.3: Non-zero service numbers are not administrative
#[test]
fn test_rfc9758_6_3_nonzero_service_not_administrative() {
    // RFC 9758 §6.3: "Non-zero Service Numbers MUST NOT be used to identify
    // the administrative endpoint"

    // Application endpoint with non-zero service
    let app_endpoint = EndpointId::ipn(0, 1, 5).unwrap();

    if let EndpointId::Ipn { service, .. } = app_endpoint {
        assert_ne!(
            service, 0,
            "Non-administrative endpoint uses non-zero service number"
        );
        assert_eq!(service, 5, "Application endpoint has service number 5");
    }

    // Verify various non-zero service numbers
    for service_num in 1..10 {
        let endpoint = EndpointId::ipn(0, 1, service_num).unwrap();
        if let EndpointId::Ipn { service, .. } = endpoint {
            assert_ne!(
                service, 0,
                "Service {} MUST NOT be the administrative endpoint per RFC 9758 §6.3",
                service
            );
        }
    }
}

/// Test RFC 9758 §6.3: NodeId to EndpointId conversion uses service 0
#[test]
fn test_rfc9758_6_3_node_id_to_admin_endpoint() {
    // RFC 9758 §6.3: When converting a NodeId to an administrative endpoint,
    // service 0 MUST be used

    use interplanetary_sdk::types::NodeId;

    let node = NodeId::ipn(0, 1);
    let endpoint = node.to_endpoint_id().unwrap();

    // Verify conversion uses service 0 (administrative endpoint)
    if let EndpointId::Ipn {
        allocator,
        node: node_num,
        service,
    } = endpoint
    {
        assert_eq!(allocator, 0);
        assert_eq!(node_num, 1);
        assert_eq!(
            service, 0,
            "NodeId.to_endpoint_id() MUST produce service 0 per RFC 9758 §6.3"
        );
    } else {
        panic!("Expected IPN endpoint");
    }
}

/// Test RFC 9758 §6.3: Administrative records destination format
#[test]
fn test_rfc9758_6_3_administrative_record_destination() {
    // RFC 9758 §6.3: Administrative records (like status reports) are
    // destined to the report-to EID, which by convention uses service 0

    let reporting_node = EndpointId::ipn(0, 1, 0).unwrap(); // Service 0
    let report_to = EndpointId::ipn(0, 2, 0).unwrap(); // Service 0

    // Create status report bundle
    let status_report = StatusReport::reception(
        EndpointId::ipn(0, 3, 5).unwrap(), // Original bundle source (any service)
        CreationTimestamp::new(DtnTimeMs::ZERO, 1),
        None,
    );

    let bundle = create_status_report_bundle(
        status_report,
        &reporting_node,
        &report_to,
        SimInstant::from_nanos(1_000_000_000),
        1,
        false,
    )
    .unwrap();

    // Verify administrative bundle uses service 0 for both source and destination
    if let EndpointId::Ipn {
        service: src_service,
        ..
    } = bundle.primary.source
    {
        assert_eq!(
            src_service, 0,
            "Administrative record source uses service 0"
        );
    }

    if let EndpointId::Ipn {
        service: dst_service,
        ..
    } = bundle.primary.destination
    {
        assert_eq!(
            dst_service, 0,
            "Administrative record destination uses service 0"
        );
    }
}

/// Test RFC 9758 §6.3: Status report bundle structure
#[test]
fn test_rfc9758_6_3_status_report_endpoint_format() {
    // RFC 9758 §6.3 + RFC 9171 §6.1: Status reports are administrative records
    // that use service 0

    let subject_source = EndpointId::ipn(0, 10, 7).unwrap(); // Original bundle (any service)
    let reporting_node = EndpointId::ipn(0, 5, 0).unwrap(); // Must be service 0
    let report_to = EndpointId::ipn(0, 10, 0).unwrap(); // Must be service 0

    let deletion_report = StatusReport::deletion(
        subject_source.clone(),
        CreationTimestamp::new(DtnTimeMs::from_millis(5000), 3),
        ReasonCode::HopLimitExceeded,
        None,
    );

    let bundle = create_status_report_bundle(
        deletion_report,
        &reporting_node,
        &report_to,
        SimInstant::from_nanos(6_000_000_000),
        1,
        false,
    )
    .unwrap();

    // RFC 9171 §4.2.3: Administrative records have IS_ADMIN_RECORD flag (bit 1, 0x02)
    assert_eq!(
        bundle.primary.bundle_flags & 0x02,
        0x02,
        "Administrative record MUST have IS_ADMIN_RECORD flag set"
    );

    // RFC 9758 §6.3: Administrative bundles use service 0
    if let EndpointId::Ipn { service, .. } = bundle.primary.source {
        assert_eq!(service, 0, "Status report source MUST be service 0");
    }

    if let EndpointId::Ipn { service, .. } = bundle.primary.destination {
        assert_eq!(service, 0, "Status report destination MUST be service 0");
    }
}

/// Test RFC 9758 §6.3: Multiple administrative endpoints per node
#[test]
fn test_rfc9758_6_3_single_administrative_endpoint_per_node() {
    // RFC 9758 §6.3: Each node has exactly one administrative endpoint,
    // identified by service number 0

    let node_1_admin = EndpointId::ipn(0, 1, 0).unwrap();
    let node_2_admin = EndpointId::ipn(0, 2, 0).unwrap();
    let node_1_app = EndpointId::ipn(0, 1, 5).unwrap();

    // Different nodes have different administrative endpoints
    assert_ne!(node_1_admin, node_2_admin);

    // Same node has same administrative endpoint (service 0)
    if let EndpointId::Ipn {
        allocator: a1,
        node: n1,
        service: s1,
    } = node_1_admin
        && let EndpointId::Ipn {
            allocator: a2,
            node: n2,
            service: s2,
        } = node_1_app
    {
        assert_eq!(a1, a2);
        assert_eq!(n1, n2);
        assert_eq!(s1, 0, "Administrative endpoint uses service 0");
        assert_ne!(s2, 0, "Application endpoint uses non-zero service");
    }
}
