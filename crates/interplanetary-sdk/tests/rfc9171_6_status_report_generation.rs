//! RFC 9171 §6: Status report generation through BPA
//!
//! Tests that the BPA generates status reports when REQUEST_REPORT flags are set,
//! respects policy settings, and never generates reports for admin records.

use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::*;
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;

fn create_test_bpa(policy: StatusReportPolicy) -> BundleAgent {
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: EndpointId::ipn(0, 2, 0).unwrap(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: policy,
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
    BundleAgent::new(config, storage)
}

fn create_bundle_with_flags(flags: u64) -> Bundle {
    BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(flags)
        .payload(b"test data".to_vec())
        .build()
        .unwrap()
}

/// RFC9171-5-034: Bundle reception status report generated when flag set
#[test]
fn test_rfc9171_5_034_reception_status_report_generated() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create bundle with reception report flag
    let bundle = create_bundle_with_flags(bundle_flags::REQUEST_REPORT_RECEPTION);

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Generate reception status report
    let report = bpa.generate_reception_status_report(&bundle_id, time);

    assert!(
        report.is_some(),
        "Reception report should be generated when flag is set and policy allows"
    );

    let report = report.unwrap();
    assert!(
        report.received.asserted,
        "Received status should be asserted"
    );
    assert!(
        !report.forwarded.asserted,
        "Forwarded status should not be asserted"
    );
    assert!(
        !report.delivered.asserted,
        "Delivered status should not be asserted"
    );
    assert!(
        !report.deleted.asserted,
        "Deleted status should not be asserted"
    );
    assert_eq!(report.reason_code, ReasonCode::NoAdditionalInformation);
}

/// RFC9171-5-017: Bundle forwarding status report generated when flag set
#[test]
fn test_rfc9171_5_017_forwarding_status_report_generated() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create bundle with forwarding report flag
    let bundle = create_bundle_with_flags(bundle_flags::REQUEST_REPORT_FORWARD);

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Generate forwarding status report
    let report = bpa.generate_forwarding_status_report(&bundle_id, time);

    assert!(
        report.is_some(),
        "Forwarding report should be generated when flag is set and policy allows"
    );

    let report = report.unwrap();
    assert!(
        !report.received.asserted,
        "Received status should not be asserted"
    );
    assert!(
        report.forwarded.asserted,
        "Forwarded status should be asserted"
    );
    assert!(
        !report.delivered.asserted,
        "Delivered status should not be asserted"
    );
    assert!(
        !report.deleted.asserted,
        "Deleted status should not be asserted"
    );
    assert_eq!(report.reason_code, ReasonCode::NoAdditionalInformation);
}

/// RFC9171-5-050: Bundle delivery status report generated when flag set
#[test]
fn test_rfc9171_5_050_delivery_status_report_generated() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create bundle with delivery report flag
    let bundle = create_bundle_with_flags(bundle_flags::REQUEST_REPORT_DELIVERY);

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Generate delivery status report
    let report = bpa.generate_delivery_status_report(&bundle_id, time);

    assert!(
        report.is_some(),
        "Delivery report should be generated when flag is set and policy allows"
    );

    let report = report.unwrap();
    assert!(
        !report.received.asserted,
        "Received status should not be asserted"
    );
    assert!(
        !report.forwarded.asserted,
        "Forwarded status should not be asserted"
    );
    assert!(
        report.delivered.asserted,
        "Delivered status should be asserted"
    );
    assert!(
        !report.deleted.asserted,
        "Deleted status should not be asserted"
    );
    assert_eq!(report.reason_code, ReasonCode::NoAdditionalInformation);
}

/// RFC9171-5-063: Bundle deletion status report generated when flag set
#[test]
fn test_rfc9171_5_063_deletion_status_report_generated() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create bundle with deletion report flag
    let bundle = create_bundle_with_flags(bundle_flags::REQUEST_REPORT_DELETION);

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Generate deletion status report
    let report = bpa.generate_deletion_status_report(&bundle_id, ReasonCode::LifetimeExpired, time);

    assert!(
        report.is_some(),
        "Deletion report should be generated when flag is set and policy allows"
    );

    let report = report.unwrap();
    assert!(
        !report.received.asserted,
        "Received status should not be asserted"
    );
    assert!(
        !report.forwarded.asserted,
        "Forwarded status should not be asserted"
    );
    assert!(
        !report.delivered.asserted,
        "Delivered status should not be asserted"
    );
    assert!(report.deleted.asserted, "Deleted status should be asserted");
    assert_eq!(report.reason_code, ReasonCode::LifetimeExpired);
}

/// RFC9171-5-001: Status reports MUST be disabled by default
#[test]
fn test_rfc9171_5_001_status_reports_disabled_by_default() {
    // Use the SDK's actual default policy (not explicit none())
    let policy = StatusReportPolicy::default();
    let mut bpa = create_test_bpa(policy);

    // Create bundle with all report flags set
    let bundle = create_bundle_with_flags(
        bundle_flags::REQUEST_REPORT_RECEPTION
            | bundle_flags::REQUEST_REPORT_FORWARD
            | bundle_flags::REQUEST_REPORT_DELIVERY
            | bundle_flags::REQUEST_REPORT_DELETION,
    );

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Try to generate reports - all should return None due to policy
    assert!(
        bpa.generate_reception_status_report(&bundle_id, time)
            .is_none(),
        "Reception report should NOT be generated when policy disables it"
    );
    assert!(
        bpa.generate_forwarding_status_report(&bundle_id, time)
            .is_none(),
        "Forwarding report should NOT be generated when policy disables it"
    );
    assert!(
        bpa.generate_delivery_status_report(&bundle_id, time)
            .is_none(),
        "Delivery report should NOT be generated when policy disables it"
    );
    assert!(
        bpa.generate_deletion_status_report(&bundle_id, ReasonCode::LifetimeExpired, time)
            .is_none(),
        "Deletion report should NOT be generated when policy disables it"
    );
}

/// Test: Status reports NOT generated when flags are not set
#[test]
fn test_no_reports_when_flags_not_set() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create bundle with NO report flags
    let bundle = create_bundle_with_flags(0);

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Try to generate reports - all should return None due to missing flags
    assert!(
        bpa.generate_reception_status_report(&bundle_id, time)
            .is_none(),
        "Reception report should NOT be generated when flag is not set"
    );
    assert!(
        bpa.generate_forwarding_status_report(&bundle_id, time)
            .is_none(),
        "Forwarding report should NOT be generated when flag is not set"
    );
    assert!(
        bpa.generate_delivery_status_report(&bundle_id, time)
            .is_none(),
        "Delivery report should NOT be generated when flag is not set"
    );
    assert!(
        bpa.generate_deletion_status_report(&bundle_id, ReasonCode::LifetimeExpired, time)
            .is_none(),
        "Deletion report should NOT be generated when flag is not set"
    );
}

/// RFC 9171 §6.1: Admin records never trigger status reports
#[test]
fn test_admin_records_never_generate_status_reports() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create admin record (correctly has zero status report flags per RFC9171-4-018)
    let admin_bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(bundle_flags::IS_ADMIN_RECORD) // Admin flag only, no status report flags
        .payload(b"admin data".to_vec())
        .build()
        .unwrap();

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(admin_bundle, time).unwrap();

    // Try to generate reports - all should return None for admin records
    assert!(
        bpa.generate_reception_status_report(&bundle_id, time)
            .is_none(),
        "Reception report must NOT be generated for admin records (RFC 9171 §6.1)"
    );
    assert!(
        bpa.generate_forwarding_status_report(&bundle_id, time)
            .is_none(),
        "Forwarding report must NOT be generated for admin records (RFC 9171 §6.1)"
    );
    assert!(
        bpa.generate_delivery_status_report(&bundle_id, time)
            .is_none(),
        "Delivery report must NOT be generated for admin records (RFC 9171 §6.1)"
    );
    assert!(
        bpa.generate_deletion_status_report(&bundle_id, ReasonCode::LifetimeExpired, time)
            .is_none(),
        "Deletion report must NOT be generated for admin records (RFC 9171 §6.1)"
    );
}

/// Test: Status time included when REQUEST_STATUS_TIME flag is set
#[test]
fn test_status_time_included_when_requested() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create bundle with reception report flag AND status time flag
    let bundle = create_bundle_with_flags(
        bundle_flags::REQUEST_REPORT_RECEPTION | bundle_flags::REQUEST_STATUS_TIME,
    );

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Generate reception status report
    let report = bpa
        .generate_reception_status_report(&bundle_id, time)
        .unwrap();

    assert!(
        report.received.time.is_some(),
        "Status time should be included when REQUEST_STATUS_TIME flag is set"
    );
    assert_eq!(
        report.received.time.unwrap(),
        time,
        "Status time should match the generation time"
    );
}

/// Test: Status time NOT included when REQUEST_STATUS_TIME flag is not set
#[test]
fn test_status_time_not_included_when_not_requested() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    let mut bpa = create_test_bpa(policy);

    // Create bundle with reception report flag but NO status time flag
    let bundle = create_bundle_with_flags(bundle_flags::REQUEST_REPORT_RECEPTION);

    // Admit bundle
    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Generate reception status report
    let report = bpa
        .generate_reception_status_report(&bundle_id, time)
        .unwrap();

    assert!(
        report.received.time.is_none(),
        "Status time should NOT be included when REQUEST_STATUS_TIME flag is not set"
    );
}
