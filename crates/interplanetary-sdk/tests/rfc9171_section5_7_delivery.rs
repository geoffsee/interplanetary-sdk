//! RFC 9171 §5.7 Local Bundle Delivery integration tests
//!
//! Tests the local bundle delivery procedure including:
//! - Delivery status report generation per bit 17
//! - Delivery to local applications
//! - No status reports for administrative records

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::bpa::admin::{
    StatusReport, bundle_flags, is_admin_record, requests_delivery_report,
};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId, SimInstant};

/// Test RFC 9171 §5.7: Delivery status report requested (bit 17)
#[test]
fn test_rfc9171_5_7_delivery_status_report_requested() {
    // RFC 9171 §4.2.3 Table 2: "Bit 17 (0x020000): Request reporting of bundle delivery"
    // RFC 9171 §5.7: "If reporting of bundle delivery is enabled, then a bundle
    // delivery status report SHOULD be generated"

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .bundle_flags(bundle_flags::REQUEST_REPORT_DELIVERY)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    assert!(
        requests_delivery_report(&bundle),
        "Bundle should request delivery report (bit 17)"
    );

    assert!(
        !is_admin_record(&bundle),
        "Payload bundle should not be an admin record"
    );
}

/// Test RFC 9171 §5.7: Delivery status report generation
#[test]
fn test_rfc9171_5_7_delivery_status_report_generation() {
    // Create delivery status report per §5.7
    let source_eid = EndpointId::ipn(0, 1, 0).unwrap();
    let creation_ts = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1);
    let delivery_time = SimInstant::from_nanos(5_000_000_000); // 5 seconds in nanos

    let report = StatusReport::delivery(source_eid.clone(), creation_ts, Some(delivery_time));

    // Verify delivery status report structure per RFC 9171 §6.1.1
    assert!(
        report.delivered.asserted,
        "Delivered status should be asserted"
    );
    assert_eq!(
        report.delivered.time,
        Some(delivery_time),
        "Delivery time should be recorded"
    );

    assert!(
        !report.received.asserted,
        "Received should not be asserted in delivery report"
    );
    assert!(
        !report.forwarded.asserted,
        "Forwarded should not be asserted in delivery report"
    );
    assert!(
        !report.deleted.asserted,
        "Deleted should not be asserted in delivery report"
    );

    // Verify subject bundle identification
    assert_eq!(report.source_eid, source_eid);
    assert_eq!(report.creation_timestamp, creation_ts);
}

/// Test RFC 9171 §5.7: No delivery reports for administrative records
#[test]
fn test_rfc9171_5_7_no_delivery_reports_for_admin_records() {
    // RFC 9171 §6.1: "A bundle node MUST NOT generate a status report in response
    // to the receipt, forwarding, delivery, or deletion of an administrative record."
    //
    // Also, per RFC 9171 §4.2.3: "If the bundle processing control flags indicate
    // that the bundle's ADU is an administrative record, then all status report
    // request flag values MUST be zero."

    let admin_bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .bundle_flags(bundle_flags::IS_ADMIN_RECORD) // Admin records MUST have zero status report flags
        .payload(b"status report data".to_vec())
        .build()
        .unwrap();

    assert!(
        is_admin_record(&admin_bundle),
        "Bundle should be marked as admin record (bit 1)"
    );

    assert!(
        !requests_delivery_report(&admin_bundle),
        "Admin record must NOT have delivery report flag set (RFC 9171 §4.2.3)"
    );

    // The BPA must NOT generate status reports for admin records
    // This check is enforced by is_admin_record() before calling the status report generator
}

/// Test RFC 9171 §5.7: Bundle destination matching for local delivery
#[test]
fn test_rfc9171_5_7_bundle_destination_matching() {
    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(local_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"deliver me".to_vec())
        .build()
        .unwrap();

    // Verify destination matches local endpoint
    assert_eq!(bundle.primary.destination, local_eid);

    // In a full BPA implementation, this bundle would trigger local delivery
    // per RFC 9171 §5.7
}

/// Test RFC 9171 §5.7: Delivery to local endpoint
#[test]
fn test_rfc9171_5_7_local_endpoint_delivery() {
    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle destined for this node's endpoint
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(local_eid.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"local delivery".to_vec())
        .build()
        .unwrap();

    // Verify destination matches local endpoint
    assert_eq!(bundle.primary.destination, local_eid);

    // In a full implementation, this bundle would be automatically delivered
    // per RFC 9171 §5.7: "the bundle MUST be delivered automatically as soon
    // as it is received"
}

/// Test RFC 9171 §5.7: Delivery status report with status time requested
#[test]
fn test_rfc9171_5_7_delivery_report_with_status_time() {
    // RFC 9171 §4.2.3: Bit 6 (REQUEST_STATUS_TIME) requests time in reports
    // RFC 9171 §5.7: Delivery report SHOULD include delivery time when requested

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .bundle_flags(bundle_flags::REQUEST_REPORT_DELIVERY | bundle_flags::REQUEST_STATUS_TIME)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    assert!(requests_delivery_report(&bundle));
    assert!((bundle.primary.bundle_flags & bundle_flags::REQUEST_STATUS_TIME) != 0);

    // Generate delivery report with time
    let delivery_time = SimInstant::from_nanos(10_000_000_000); // 10 seconds in nanos
    let report = StatusReport::delivery(
        bundle.primary.source.clone(),
        bundle.primary.creation_timestamp,
        Some(delivery_time),
    );

    assert_eq!(report.delivered.time, Some(delivery_time));
}

/// Test RFC 9171 §5.7: Delivery status report without status time
#[test]
fn test_rfc9171_5_7_delivery_report_without_status_time() {
    // When status time is not requested, time field should be None

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .bundle_flags(bundle_flags::REQUEST_REPORT_DELIVERY)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    assert!(requests_delivery_report(&bundle));
    assert!((bundle.primary.bundle_flags & bundle_flags::REQUEST_STATUS_TIME) == 0);

    // Generate delivery report without time
    let report = StatusReport::delivery(
        bundle.primary.source.clone(),
        bundle.primary.creation_timestamp,
        None,
    );

    assert!(report.delivered.asserted);
    assert_eq!(report.delivered.time, None);
}
