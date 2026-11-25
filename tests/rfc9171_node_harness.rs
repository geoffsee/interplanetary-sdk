//! Node-level harness API tests for RFC 9171 §5/§6 behavioral obligations
//!
//! Tests drive the BundleAgent through receive_from_cla(), poll(), and observable outputs.

use interplanetary_sdk::bp::{Bundle, BundleBuilder};
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
use interplanetary_sdk::sim::{BundleStore, StorageManager};
use interplanetary_sdk::types::{
    Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId, SimInstant,
};

/// Create test BundleAgent
fn create_test_agent() -> BundleAgent {
    use std::collections::HashMap;

    // Default route: ipn:0.3.0 -> node ipn:0.3
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 3, 0).unwrap(), NodeId::ipn(0, 3));

    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::all(local_eid),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    BundleAgent::new(config, storage)
}

/// Create test bundle with given flags
fn create_test_bundle(flags: u64) -> Bundle {
    BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(flags)
        .payload(b"test data".to_vec())
        .build()
        .unwrap()
}

/// RFC9171-5-033: DispatchPending retention constraint added on reception
///
/// RFC 9171 §5.6: "The node SHALL add a 'dispatch pending' retention constraint to the bundle."
#[test]
fn test_rfc9171_5_033_dispatch_pending_constraint_on_reception() {
    let mut agent = create_test_agent();

    let bundle = create_test_bundle(0);
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // RFC 9171 §5.6: Bundle must have DispatchPending retention constraint
    assert!(
        agent.has_retention_constraints(&bundle_id),
        "Bundle must have retention constraints after reception"
    );

    // Verify bundle is in storage
    assert!(
        agent.storage().get(&bundle_id).is_some(),
        "Bundle must be in storage"
    );
}

/// RFC9171-5-034: Reception status report generated when requested
///
/// RFC 9171 §5.6: "If the bundle's status report request field's 'Report reception'
/// flag is set to 1 and status reporting is enabled, then the node SHALL generate
/// a reception status report."
#[test]
fn test_rfc9171_5_034_reception_status_report_generated_harness() {
    let mut agent = create_test_agent();

    // Create bundle requesting reception report (bit 14 = 0x004000)
    let bundle = create_test_bundle(0x004000);

    agent.clear_generated_reports();
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // RFC 9171 §5.6: Reception status report must be generated
    let reports = agent.generated_reports();
    assert_eq!(
        reports.len(),
        1,
        "Reception status report must be generated"
    );

    // Verify it's a reception report
    let report = &reports[0];
    assert!(report.received.asserted, "Reception must be asserted");
    assert!(
        !report.forwarded.asserted,
        "Forwarding must not be asserted"
    );
    assert!(!report.delivered.asserted, "Delivery must not be asserted");
    assert!(!report.deleted.asserted, "Deletion must not be asserted");

    // Verify bundle reference
    let bundle_ref = agent.storage().get(&bundle_id).unwrap();
    assert_eq!(report.source_eid, bundle_ref.primary.source);
    assert_eq!(
        report.creation_timestamp,
        bundle_ref.primary.creation_timestamp
    );
}

/// RFC9171-5-067: Bundle deleted when lifetime expires
///
/// RFC 9171 §5.11: "When a bundle's lifetime has expired, the node SHALL delete
/// the bundle for reason code 'lifetime expired'."
#[test]
fn test_rfc9171_5_067_delete_expired_bundle_lifetime_expired() {
    let mut agent = create_test_agent();

    // Create bundle with 1 second lifetime and deletion report requested (bit 18 = 0x040000)
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(1000) // 1 second
        .bundle_flags(0x040000) // Request deletion report
        .payload(b"expires".to_vec())
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();
    assert!(agent.storage().get(&bundle_id).is_some());

    // Poll before expiration - bundle should still exist
    agent.poll(SimInstant::from_nanos(500_000_000)); // 0.5 seconds
    assert!(
        agent.storage().get(&bundle_id).is_some(),
        "Bundle should exist before expiration"
    );

    // Poll after expiration - bundle should be deleted
    agent.clear_generated_reports();
    agent.poll(SimInstant::from_nanos(1_100_000_000)); // 1.1 seconds
    assert!(
        agent.storage().get(&bundle_id).is_none(),
        "Bundle must be deleted after lifetime expires"
    );

    // RFC 9171 §5.11: Deletion status report with LifetimeExpired reason
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1, "Deletion status report must be generated");
    assert!(reports[0].deleted.asserted);
    assert_eq!(
        reports[0].reason_code as u8,
        1, // LifetimeExpired
        "Reason code must be 'lifetime expired'"
    );
}

/// RFC9171-5-064: All retention constraints removed on deletion
///
/// RFC 9171 §5.13: "The node SHALL remove all of the bundle's retention constraints."
#[test]
fn test_rfc9171_5_064_remove_all_retention_constraints_on_deletion() {
    let mut agent = create_test_agent();

    let bundle = create_test_bundle(0);
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Bundle should have retention constraints
    assert!(
        agent.has_retention_constraints(&bundle_id),
        "Bundle should have retention constraints"
    );

    // Delete bundle
    use interplanetary_sdk::bpa::admin::ReasonCode;
    agent
        .delete_bundle(&bundle_id, ReasonCode::NoAdditionalInformation)
        .unwrap();

    // RFC 9171 §5.13: All retention constraints must be removed
    assert!(
        !agent.has_retention_constraints(&bundle_id),
        "All retention constraints must be removed on deletion"
    );
}

/// RFC9171-5-035: CRC computation on reception
///
/// RFC 9171 §5.6 Step 3: "CRCs SHOULD be computed for every block of the bundle
/// that has an attached CRC. If any CRC in the bundle fails to validate, then the
/// node SHALL delete the bundle for reason code 'Block unintelligible'."
#[test]
fn test_rfc9171_5_035_crc_computation_on_reception() {
    use interplanetary_sdk::bp::CrcType;
    use interplanetary_sdk::bp::codec::BundleCodec;

    let mut agent = create_test_agent();

    // Create a valid bundle WITH CRC-32 and encode it
    let valid_bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .crc_type(CrcType::Crc32) // RFC 9171 §4.2.2: Enable CRC-32
        .payload(b"test data with CRC".to_vec())
        .build()
        .unwrap();

    let valid_encoded = BundleCodec::encode(&valid_bundle).unwrap();

    // Test 1: Valid bundle with correct CRC is accepted
    let result = agent.receive_bytes_from_cla(&valid_encoded);
    assert!(
        result.is_ok(),
        "Valid bundle with correct CRC must be accepted"
    );
    let bundle_id = result.unwrap();
    assert!(
        agent.storage().get(&bundle_id).is_some(),
        "Valid bundle must be stored"
    );

    // Test 2: Corrupted bundle with bad CRC is rejected
    agent = create_test_agent(); // Fresh agent
    let mut corrupted = valid_encoded.clone();

    // Corrupt a byte in the CBOR payload data (not in the CRC itself)
    // This will cause CRC validation to fail
    let mid_index = corrupted.len() / 2;
    if corrupted.len() > 20 {
        corrupted[mid_index] ^= 0xFF;
    }

    let result = agent.receive_bytes_from_cla(&corrupted);
    // RFC 9171 §5.6: Bundle with bad CRC must be rejected (decode fails)
    assert!(
        result.is_err(),
        "Bundle with corrupted data/bad CRC must be rejected"
    );

    // Verify nothing was stored, delivered, or forwarded
    assert_eq!(
        agent
            .list_bundles_in_state(interplanetary_sdk::bpa::BundleState::Admitted)
            .len(),
        0,
        "Corrupted bundle must not be stored"
    );
    assert_eq!(
        agent.delivered_adus().len(),
        0,
        "Corrupted bundle must not be delivered"
    );
    assert_eq!(
        agent.cla_tx_queue().len(),
        0,
        "Corrupted bundle must not be forwarded"
    );
}

/// RFC9171-5-041: Skip remaining steps after deletion
///
/// RFC 9171 §5.6 Step 4: "The Bundle Deletion procedure defined in Section 5.10
/// MUST be followed, and all remaining steps of the Bundle Reception procedure
/// MUST be skipped."
#[test]
fn test_rfc9171_5_041_skip_remaining_steps_after_deletion() {
    let mut agent = create_test_agent();

    // Create bundle with short lifetime
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(100) // Very short lifetime
        .payload(b"deleted".to_vec())
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Poll to trigger expiration/deletion
    agent.poll(SimInstant::from_nanos(200_000_000)); // 0.2 seconds

    // RFC 9171 §5.6 + §5.10: Bundle must be deleted
    assert!(
        agent.storage().get(&bundle_id).is_none(),
        "Deleted bundle must not remain in storage"
    );

    // RFC 9171 §5.6: Remaining reception steps are skipped
    // This is verified by the fact that the bundle is gone and cannot
    // be forwarded, delivered, or further processed

    // Additional verification: deleted bundles are not in delivered set
    assert!(
        !agent
            .delivered_adus()
            .iter()
            .any(|b| { b.primary.source == EndpointId::ipn(0, 1, 0).unwrap() }),
        "Deleted bundle must not be delivered"
    );
}

/// RFC9171-6-001: No status reports for administrative records
///
/// RFC 9171 §6.1: "A bundle node MUST NOT generate a status report in response
/// to the receipt, forwarding, delivery, or deletion of an administrative record."
/// RFC 9171 §4.2.3: "Administrative records must have zero status report flags."
#[test]
fn test_rfc9171_6_001_no_status_reports_for_admin_records() {
    let mut agent = create_test_agent();

    // RFC 9171 §4.2.3: Admin records must have zero status report flags
    // First verify that SDK rejects admin bundles with status flags
    let invalid_admin_flags = 0x000002 | 0x004000; // Admin + report reception
    let invalid_result = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(invalid_admin_flags)
        .payload(b"admin".to_vec())
        .build();
    assert!(
        invalid_result.is_err(),
        "Admin records with status flags must be rejected"
    );

    // Create valid administrative record bundle (bit 1 = 0x000002, no status flags)
    let admin_bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x000002) // Admin record only, no status flags
        .payload(b"admin".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    let bundle_id = agent.receive_from_cla(admin_bundle).unwrap();

    // RFC 9171 §6.1: No status reports must be generated for admin records
    assert_eq!(
        agent.generated_reports().len(),
        0,
        "Must not generate status reports for administrative records"
    );

    // Even on deletion
    use interplanetary_sdk::bpa::admin::ReasonCode;
    agent
        .delete_bundle(&bundle_id, ReasonCode::NoAdditionalInformation)
        .unwrap();
    assert_eq!(
        agent.generated_reports().len(),
        0,
        "Must not generate deletion status report for admin record"
    );
}

/// RFC9171-5-063: Deletion status report with reason code
///
/// RFC 9171 §5.13: "If the 'request reporting of bundle deletion' flag in the
/// bundle's status report request field is set to 1 and status reporting is enabled,
/// then the node SHALL generate a deletion status report with appropriate reason code."
#[test]
fn test_rfc9171_5_063_deletion_status_report_with_reason() {
    let mut agent = create_test_agent();

    // Create bundle requesting deletion report (bit 18 = 0x040000)
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(100) // Short lifetime
        .bundle_flags(0x040000) // Request deletion report
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    agent.receive_from_cla(bundle).unwrap();
    agent.clear_generated_reports();

    // Poll to trigger expiration and deletion
    agent.poll(SimInstant::from_nanos(200_000_000)); // 0.2 seconds

    // RFC 9171 §5.13: Deletion status report must be generated
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1, "Deletion status report must be generated");

    let report = &reports[0];
    assert!(report.deleted.asserted, "Deletion must be asserted");
    assert_eq!(
        report.reason_code as u8,
        1, // LifetimeExpired per RFC 9171 §6.1.1 Table 1
        "Reason code must be 'lifetime expired'"
    );
}

/// RFC9171-6-012: Status report includes source EID (report-to)
///
/// RFC 9171 §6.1.1: Status reports are sent to the report-to EID from the
/// bundle's primary block. Tests decode the report and verify the report-to EID.
#[test]
fn test_rfc9171_6_012_status_report_includes_source_eid() {
    let mut agent = create_test_agent();

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 3, 0).unwrap();

    // Create bundle with reception report requested
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x004000) // Request reception report
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    agent.receive_from_cla(bundle).unwrap();

    // Verify report was generated with correct source EID
    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    let report = &reports[0];
    // RFC 9171 §6.1.1: Report references the bundle's source EID
    assert_eq!(
        report.source_eid, source,
        "Report must reference bundle source EID"
    );
}

/// RFC9171-6-006: Status report includes correct assertion flags
///
/// RFC 9171 §6.1.1: First element is status info array with 4 items (received,
/// forwarded, delivered, deleted). Each is [bool] or [bool, time].
#[test]
fn test_rfc9171_6_006_status_assertions() {
    let mut agent = create_test_agent();

    // Test reception report
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x004000) // Request reception report only
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    agent.receive_from_cla(bundle).unwrap();

    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    // RFC 9171 §6.1.1: Status info array structure
    let report = &reports[0];
    assert!(report.received.asserted, "Received must be asserted");
    assert!(!report.forwarded.asserted, "Forwarded must not be asserted");
    assert!(!report.delivered.asserted, "Delivered must not be asserted");
    assert!(!report.deleted.asserted, "Deleted must not be asserted");
}

/// RFC9171-6-010: Status report includes time when requested
///
/// RFC 9171 §6.1.1: If the bundle's status report request field includes the
/// 'report status time' flag, status items must include timestamps.
#[test]
fn test_rfc9171_6_010_status_time_when_requested() {
    let mut agent = create_test_agent();

    // Create bundle with reception report AND status time requested
    // Bit 6 (0x000040) = request status time
    // Bit 14 (0x004000) = request reception report
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x000040 | 0x004000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    agent.receive_from_cla(bundle).unwrap();

    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    // RFC 9171 §6.1.1: Status time must be included when requested
    let report = &reports[0];
    assert!(
        report.received.time.is_some(),
        "Status time must be included when flag is set"
    );
}

/// RFC9171-6-010: Status report excludes time when not requested  
///
/// RFC 9171 §6.1.1: If status time flag is not set, timestamps are not included.
#[test]
fn test_rfc9171_6_010_no_status_time_when_not_requested() {
    let mut agent = create_test_agent();

    // Create bundle with reception report but NO status time
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x004000) // Only reception report, no status time
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    agent.receive_from_cla(bundle).unwrap();

    let reports = agent.generated_reports();
    assert_eq!(reports.len(), 1);

    // RFC 9171 §6.1.1: No status time when flag is not set
    let report = &reports[0];
    assert!(
        report.received.time.is_none(),
        "Status time must not be included when flag is not set"
    );
}

/// RFC9171-4-079: Previous node block inserted on forward
///
/// RFC 9171 §4.4.1: "When a bundle is forwarded, the node SHALL insert a Previous
/// Node block... If a Previous Node block already exists, it SHALL be replaced."
#[test]
fn test_rfc9171_4_079_previous_node_inserted_on_forward() {
    use interplanetary_sdk::bp::BlockType;

    let mut agent = create_test_agent();

    let bundle = create_test_bundle(0);
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Auto-forward via production path
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Check CLA transmission queue
    let tx_queue = agent.cla_tx_queue();
    assert_eq!(tx_queue.len(), 1, "Bundle must be queued for transmission");

    // RFC 9171 §4.4.1: Previous node block must be present
    let forwarded = &tx_queue[0].bundle;
    let prev_node_exists = forwarded
        .blocks
        .iter()
        .any(|b| b.block_type == BlockType::PreviousNode);
    assert!(
        prev_node_exists,
        "Previous node block must be inserted on forward"
    );
}

/// RFC9171-4-086: Hop limit exceeded causes deletion
///
/// RFC 9171 §4.4.3: "If the hop count value exceeds the hop limit value, then the
/// bundle SHALL be deleted for the reason 'hop limit exceeded'."
#[test]
fn test_rfc9171_4_086_hop_limit_exceeded_causes_deletion() {
    use interplanetary_sdk::bp::extensions::HopCountBlock;
    use interplanetary_sdk::bpa::admin::ReasonCode;

    let mut agent = create_test_agent();

    // Test 1: Bundle with hop count at limit should be deleted
    let mut bundle_at_limit = create_test_bundle(0x040000); // Request deletion report (bit 18)
    let hop_block_at_limit = HopCountBlock::new(2, 5, 5).unwrap(); // limit 5, count 5 (at limit)
    bundle_at_limit
        .blocks
        .insert(0, hop_block_at_limit.to_canonical().unwrap());

    agent.clear_generated_reports();
    let bundle_id_at_limit = agent.receive_from_cla(bundle_at_limit).unwrap();

    // Auto-forward via production path - hop count is already at limit
    // Forward should fail and delete
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Bundle should be deleted (hop count 5 == limit 5, forward would make it 6 > limit)
    assert!(
        agent.storage().get(&bundle_id_at_limit).is_none(),
        "Bundle at hop limit must be deleted when forward would exceed limit"
    );

    // RFC 9171 §4.4.3: Deletion with HopLimitExceeded reason
    let reports = agent.generated_reports();
    assert!(!reports.is_empty(), "Deletion report must be generated");
    assert_eq!(
        reports[0].reason_code,
        ReasonCode::HopLimitExceeded,
        "Reason must be HopLimitExceeded"
    );

    // Test 2: Bundle with hop count below limit should forward successfully
    agent.clear_cla_tx_queue();
    agent.clear_generated_reports();

    let mut bundle_below_limit = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 0))
        .lifetime(60_000)
        .payload(b"below limit".to_vec())
        .build()
        .unwrap();
    let hop_block_below = HopCountBlock::new(2, 10, 4).unwrap(); // limit 10, count 4
    bundle_below_limit
        .blocks
        .insert(0, hop_block_below.to_canonical().unwrap());

    let _bundle_id_below = agent.receive_from_cla(bundle_below_limit).unwrap();

    // Auto-forward via production path - should succeed
    agent.poll(SimInstant::from_nanos(200_000_000));

    // Bundle should be forwarded (hop count 4 < limit 10)
    assert_eq!(
        agent.cla_tx_queue().len(),
        1,
        "Bundle below hop limit must be forwarded"
    );
}

/// RFC9171-5-028: Bundle age accumulated on forward
///
/// RFC 9171 §4.4.2: "The bundle age value SHALL be increased by the node's current
/// estimate of the time elapsed since the bundle's creation time."
#[test]
fn test_rfc9171_5_028_bundle_age_accumulated() {
    use interplanetary_sdk::bp::BlockType;
    use interplanetary_sdk::bp::extensions::BundleAgeBlock;

    let mut agent = create_test_agent();

    // Create bundle with bundle age block
    let mut bundle = create_test_bundle(0);
    let age_block = BundleAgeBlock::new(2, 1000); // Initial age 1000ms
    bundle.blocks.insert(0, age_block.to_canonical().unwrap());

    let _bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Advance time and auto-forward via production path
    agent.poll(SimInstant::from_nanos(500_000_000)); // 0.5 seconds

    // Check that bundle was forwarded with increased age
    let tx_queue = agent.cla_tx_queue();
    assert_eq!(tx_queue.len(), 1);

    let forwarded = &tx_queue[0].bundle;
    let age_idx = forwarded
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::BundleAge)
        .expect("Bundle age block must exist");

    let age_block = BundleAgeBlock::from_canonical(&forwarded.blocks[age_idx]).unwrap();

    // RFC 9171 §4.4.2: Age must be increased by residence time
    assert!(
        age_block.age_ms > 1000,
        "Bundle age must increase during residence (was 1000, now {})",
        age_block.age_ms
    );
}

/// RFC9171-5-050: Delivery status report generated
///
/// RFC 9171 §5.7: "If the 'request reporting of bundle delivery' flag is set,
/// a delivery status report SHALL be generated."
#[test]
fn test_rfc9171_5_050_delivery_status_report_generated_harness() {
    let mut agent = create_test_agent();

    // Create bundle requesting delivery report (bit 17 = 0x020000)
    // and destined for local node
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap()) // Local node
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x020000) // Request delivery report
        .payload(b"local delivery".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Deliver locally
    agent.deliver_local(&bundle_id).unwrap();

    // RFC 9171 §5.7: Delivery status report must be generated
    let reports = agent.generated_reports();
    let delivery_reports: Vec<_> = reports.iter().filter(|r| r.delivered.asserted).collect();

    assert!(
        !delivery_reports.is_empty(),
        "Delivery status report must be generated"
    );
}

/// RFC9171-5-048: Local delivery of bundles
///
/// RFC 9171 §5.7: Bundles destined for local endpoints are delivered to applications.
#[test]
fn test_rfc9171_5_048_local_delivery() {
    let mut agent = create_test_agent();

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap()) // Local node
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"local delivery test".to_vec())
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Deliver locally
    agent.deliver_local(&bundle_id).unwrap();

    // RFC 9171 §5.7: Bundle must be in delivered ADUs
    let delivered = agent.delivered_adus();
    assert_eq!(delivered.len(), 1, "Bundle must be delivered");
    assert_eq!(
        delivered[0].primary.destination,
        EndpointId::ipn(0, 2, 0).unwrap()
    );
}

/// RFC9171-5-017: Forwarding status report generated
///
/// RFC 9171 §5.4: "If the 'request reporting of bundle forwarding' flag is set,
/// a forwarding status report SHALL be generated."
#[test]
fn test_rfc9171_5_017_forwarding_status_report_generated_harness() {
    let mut agent = create_test_agent();

    // Create bundle requesting forwarding report (bit 16 = 0x010000)
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x010000) // Request forwarding report
        .payload(b"forward test".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    let _bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Auto-forward via production path
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4: Forwarding status report must be generated
    let reports = agent.generated_reports();
    let forward_reports: Vec<_> = reports.iter().filter(|r| r.forwarded.asserted).collect();

    assert!(
        !forward_reports.is_empty(),
        "Forwarding status report must be generated"
    );
}

/// RFC9171-5-056: Unintelligible block with DELETE_BUNDLE_ON_FAILURE
///
/// RFC 9171 §5.6: "If the 'Delete bundle if block can't be processed' flag (bit 2)
/// is 1 in the block's block processing control flags, then the BPA MUST delete
/// the bundle for the reason 'Block unsupported'"
#[test]
fn test_rfc9171_5_056_delete_bundle_on_unintelligible_block() {
    use interplanetary_sdk::bp::blocks::{BlockFlags, BlockType, CanonicalBlock};
    use interplanetary_sdk::bp::crc::CrcType;

    let mut agent = create_test_agent();

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    // RFC 9171 §5.6: Add unsupported block with DELETE_BUNDLE_ON_FAILURE flag (bit 2)
    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::Unknown(999),
        block_number: 10,
        block_flags: BlockFlags::DELETE_BUNDLE_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0xDE, 0xAD],
    });

    // Node should reject bundle with unintelligible critical block
    let result = agent.receive_from_cla(bundle);
    assert!(
        result.is_err(),
        "Bundle with unintelligible critical block should be rejected"
    );

    // No bundles should be in storage
    assert_eq!(agent.storage().enumerate().len(), 0);
}

/// RFC9171-5-057: Unintelligible block with DISCARD_BLOCK_ON_FAILURE
///
/// RFC 9171 §5.6: "If the 'Discard block if it can't be processed' flag (bit 4)
/// is 1 in the block's block processing control flags, then the BPA MUST remove
/// this block from the bundle"
#[test]
fn test_rfc9171_5_057_discard_unintelligible_block() {
    use interplanetary_sdk::bp::blocks::{BlockFlags, BlockType, CanonicalBlock};
    use interplanetary_sdk::bp::crc::CrcType;

    let mut agent = create_test_agent();

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let initial_block_count = bundle.blocks.len();

    // RFC 9171 §5.6: Add unsupported block with DISCARD_BLOCK_ON_FAILURE flag (bit 4)
    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::Unknown(888),
        block_number: 11,
        block_flags: BlockFlags::DISCARD_BLOCK_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0xFF, 0xFF],
    });

    // Node should accept bundle after discarding unintelligible block
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Bundle should be in storage
    assert_eq!(agent.storage().enumerate().len(), 1);

    // Retrieve and verify the unintelligible block was removed
    let stored = agent.storage().get(&bundle_id).unwrap();
    assert_eq!(
        stored.blocks.len(),
        initial_block_count,
        "Unintelligible block should have been discarded"
    );
    assert!(
        !stored
            .blocks
            .iter()
            .any(|b| matches!(b.block_type, BlockType::Unknown(888))),
        "Block 888 should not be present after discarding"
    );
}

/// RFC9171-5-039: Report status if block can't be processed
///
/// RFC 9171 §5.6: "If the 'Report if block can't be processed' flag (bit 1) is 1 in the
/// block's block processing control flags, then a bundle status report with reason code
/// 'Block unsupported' SHOULD be generated"
#[test]
fn test_rfc9171_5_039_report_status_on_unintelligible_block() {
    use interplanetary_sdk::bp::blocks::{BlockFlags, BlockType, CanonicalBlock};
    use interplanetary_sdk::bp::crc::CrcType;
    use interplanetary_sdk::bpa::admin::ReasonCode;

    let mut agent = create_test_agent();

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(86_400_000)
        .bundle_flags(0x004000) // Request reception report (bit 14)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    // RFC 9171 §5.6: Add unsupported block with REPORT_ON_FAILURE flag (bit 1)
    bundle.blocks.push(CanonicalBlock {
        block_type: BlockType::Unknown(777),
        block_number: 10,
        block_flags: BlockFlags::REPORT_ON_FAILURE,
        crc_type: CrcType::None,
        data: vec![0xAB, 0xCD],
    });

    agent.clear_generated_reports();

    // Node should accept bundle and generate status report
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Bundle should be in storage (not deleted)
    assert_eq!(agent.storage().enumerate().len(), 1);

    // RFC 9171 §5.6: Status report must be generated with BlockUnsupported reason
    let reports = agent.generated_reports();
    let unintelligible_reports: Vec<_> = reports
        .iter()
        .filter(|r| r.reason_code == ReasonCode::BlockUnsupported)
        .collect();

    assert!(
        !unintelligible_reports.is_empty(),
        "Status report with BlockUnsupported reason must be generated"
    );

    // Verify the report references the correct bundle
    let report = unintelligible_reports[0];
    assert_eq!(
        report.source_eid,
        agent.storage().get(&bundle_id).unwrap().primary.source,
        "Report must reference bundle source EID"
    );
}

/// RFC9171-5-005: ForwardPending constraint added on forward
///
/// RFC 9171 §5.4 Step 1: "The retention constraint 'Forward pending' MUST be added
/// to the bundle"
#[test]
fn test_rfc9171_5_005_forward_pending_constraint_added() {
    use interplanetary_sdk::bpa::retention::RetentionConstraint;

    let mut agent = create_test_agent();

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"forward test".to_vec())
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Before forward, should have DispatchPending (tested in RFC9171-5-033)
    assert!(
        agent.has_retention_constraint(&bundle_id, RetentionConstraint::DispatchPending),
        "Should have DispatchPending before forward"
    );

    // Auto-forward via production path
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4 Step 1: ForwardPending must be added
    assert!(
        agent.has_retention_constraint(&bundle_id, RetentionConstraint::ForwardPending),
        "ForwardPending constraint must be added on forward"
    );

    // DispatchPending should be removed
    assert!(
        !agent.has_retention_constraint(&bundle_id, RetentionConstraint::DispatchPending),
        "DispatchPending should be removed when ForwardPending is added"
    );
}

/// RFC9171-5-025: ForwardPending removed after successful transmission
///
/// RFC 9171 §5.4: "The bundle's 'Forward pending' retention constraint MUST be
/// removed" after successful transmission.
#[test]
fn test_rfc9171_5_025_forward_pending_removed_on_success() {
    use interplanetary_sdk::bpa::retention::RetentionConstraint;

    let mut agent = create_test_agent();

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"forward test".to_vec())
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Auto-forward via production path - adds ForwardPending
    agent.poll(SimInstant::from_nanos(100_000_000));
    assert!(
        agent.has_retention_constraint(&bundle_id, RetentionConstraint::ForwardPending),
        "ForwardPending should be present after forward"
    );

    // Simulate successful CLA transmission
    agent.confirm_transmission_success(&bundle_id).unwrap();

    // RFC 9171 §5.4: ForwardPending must be removed after success
    assert!(
        !agent.has_retention_constraint(&bundle_id, RetentionConstraint::ForwardPending),
        "ForwardPending constraint must be removed after successful transmission"
    );
}

/// RFC9171-5-007: Forwarding contraindicated check
///
/// RFC 9171 §5.4 Step 2: "The BPA MUST determine whether or not forwarding is
/// contraindicated (that is, rendered inadvisable) for any of the reasons listed
/// in the IANA Bundle Protocol registry"
#[test]
fn test_rfc9171_5_007_forwarding_contraindicated_no_route() {
    use interplanetary_sdk::bpa::admin::ReasonCode;
    use std::collections::HashMap;

    // Set up routing: only ipn:0.3.0 is reachable
    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 3, 0).unwrap(), NodeId::ipn(0, 3));

    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::all(local_eid),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // Try to forward to ipn:0.99.0 (not in routing table)
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 99, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x040000) // Request deletion report (bit 18)
        .payload(b"unreachable".to_vec())
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Auto-forward via production path - will fail due to no route
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4.1: Forwarding is contraindicated (no known route)
    // RFC 9171 §5.4.2: Bundle should be deleted with NoKnownRoute reason
    assert!(
        agent.storage().get(&bundle_id).is_none(),
        "Bundle must be deleted when no route available"
    );

    // Check that a deletion report was generated
    let reports = agent.generated_reports();
    let deletion_reports: Vec<_> = reports
        .iter()
        .filter(|r| r.deleted.asserted && r.reason_code == ReasonCode::NoKnownRoute)
        .collect();

    assert!(
        !deletion_reports.is_empty(),
        "Deletion report with NoKnownRoute must be generated"
    );
}

/// RFC9171-5-027: Delete bundle when forwarding fails
///
/// RFC 9171 §5.4.2: "Otherwise, the bundle MUST be deleted: the Bundle Deletion
/// procedure defined in Section 5.10 MUST be followed, citing the reason for which
/// forwarding was determined to be contraindicated"
#[test]
fn test_rfc9171_5_027_delete_bundle_forwarding_failed() {
    use std::collections::HashMap;

    // Empty routing table = no routes
    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::all(local_eid),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(HashMap::new()), // Empty routes = all forwarding contraindicated,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 99, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"unreachable".to_vec())
        .build()
        .unwrap();

    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Bundle should be in storage before forward attempt
    assert_eq!(agent.storage().enumerate().len(), 1);

    // Auto-forward via production path - fails due to no route
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4.2: Bundle MUST be deleted when forwarding fails
    assert!(
        agent.storage().get(&bundle_id).is_none(),
        "Bundle must be deleted when forwarding fails"
    );
}

/// RFC9171-5-003: Bundle dispatching determines local delivery vs forwarding
///
/// RFC 9171 §5.3: "The steps in dispatching a bundle are as follows: Step 1: If the
/// bundle's destination endpoint is an endpoint of which the node is a member, the
/// Bundle Delivery procedure defined in Section 5.7 MUST be followed."
#[test]
fn test_rfc9171_5_003_dispatch_local_delivery_vs_forward() {
    use std::collections::HashMap;

    let mut routes = HashMap::new();
    routes.insert(EndpointId::ipn(0, 3, 0).unwrap(), NodeId::ipn(0, 3));

    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::all(local_eid),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(routes),
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // Test 1: Bundle with local destination -> local delivery
    let local_bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap()) // Local node
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .payload(b"local".to_vec())
        .build()
        .unwrap();

    let local_id = agent.receive_from_cla(local_bundle).unwrap();

    // Poll to trigger dispatch
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.3: Local destination -> delivery procedure
    let delivered = agent.delivered_adus();
    assert!(
        delivered.iter().any(|b| {
            b.primary.source == EndpointId::ipn(0, 1, 0).unwrap()
                && b.primary.destination == EndpointId::ipn(0, 2, 0).unwrap()
        }),
        "Bundle with local destination must be delivered locally"
    );

    // Should NOT be in CLA transmission queue
    let tx_queue = agent.cla_tx_queue();
    assert!(
        !tx_queue.iter().any(|tx| tx.bundle_id == local_id),
        "Local bundle must not be forwarded"
    );

    agent.clear_cla_tx_queue();

    // Test 2: Bundle with remote destination -> forwarding procedure
    let remote_bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap()) // Remote node
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(2000), 0))
        .lifetime(60_000)
        .payload(b"remote".to_vec())
        .build()
        .unwrap();

    let remote_id = agent.receive_from_cla(remote_bundle).unwrap();

    // Poll to trigger dispatch
    agent.poll(SimInstant::from_nanos(200_000_000));

    // RFC 9171 §5.3: Remote destination -> forwarding procedure
    let tx_queue = agent.cla_tx_queue();
    assert!(
        tx_queue.iter().any(|tx| tx.bundle_id == remote_id),
        "Bundle with remote destination must be forwarded"
    );

    // Should NOT be in delivered set
    let delivered = agent.delivered_adus();
    assert!(
        !delivered
            .iter()
            .any(|b| { b.primary.destination == EndpointId::ipn(0, 3, 0).unwrap() }),
        "Remote bundle must not be delivered locally"
    );
}

/// RFC9171-5-021: Forwarding contraindicated leads to forwarding failed
///
/// RFC 9171 §5.4.1: "If forwarding of the bundle is contraindicated (for example, there is
/// no known route to the bundle's destination), then the Forwarding Contraindicated
/// procedure MUST be followed."
/// RFC 9171 §5.4.2: "If forwarding failure is declared, then the Forwarding Failed procedure
/// defined in Section 5.4.2 MUST be followed."
#[test]
fn test_rfc9171_5_021_forwarding_contraindicated_leads_to_failed() {
    use interplanetary_sdk::bpa::admin::ReasonCode;
    use std::collections::HashMap;

    // Empty routing table = all forwarding contraindicated
    let local_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::all(local_eid),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: Some(HashMap::new()), // No routes = all contraindicated,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 99, 0).unwrap()) // Unreachable
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(0x040000) // Request deletion report
        .payload(b"unreachable".to_vec())
        .build()
        .unwrap();

    agent.clear_generated_reports();
    let bundle_id = agent.receive_from_cla(bundle).unwrap();

    // Poll triggers dispatch -> contraindicated -> failed -> deletion
    agent.poll(SimInstant::from_nanos(100_000_000));

    // RFC 9171 §5.4.2: Bundle MUST be deleted with appropriate reason
    assert!(
        agent.storage().get(&bundle_id).is_none(),
        "Contraindicated bundle must be deleted per forwarding failed procedure"
    );

    // Verify deletion with correct reason code
    let reports = agent.generated_reports();
    assert!(!reports.is_empty(), "Deletion report must be generated");
    assert_eq!(
        reports[0].reason_code,
        ReasonCode::NoKnownRoute,
        "Reason code must indicate no route"
    );
}
