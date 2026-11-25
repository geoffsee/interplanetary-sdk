//! RFC 9171 §5: Bundle forwarding and lifecycle integration tests
//!
//! Tests bundle processing through reception, forwarding, delivery, and deletion
//! with extension block updates (Bundle Age, Hop Count, Previous Node).

use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::*;
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::ErrorKind;
use interplanetary_sdk::types::*;

/// Mock CLA for testing forwarding
#[derive(Debug)]
struct MockCla {
    transmitted_bundles: Vec<Bundle>,
    should_fail: bool,
}

impl MockCla {
    fn new() -> Self {
        Self {
            transmitted_bundles: Vec::new(),
            should_fail: false,
        }
    }

    fn with_failure() -> Self {
        Self {
            transmitted_bundles: Vec::new(),
            should_fail: true,
        }
    }

    /// Mock transmission (RFC9171-5-009, 5-012: BPA MUST invoke CLA services)
    fn transmit(&mut self, bundle: Bundle) -> Result<()> {
        if self.should_fail {
            return Err(Error::new(
                ErrorKind::TransferFailed,
                "Mock CLA transmission failed",
            ));
        }
        self.transmitted_bundles.push(bundle);
        Ok(())
    }

    fn transmitted_count(&self) -> usize {
        self.transmitted_bundles.len()
    }

    fn last_transmitted(&self) -> Option<&Bundle> {
        self.transmitted_bundles.last()
    }
}

fn create_test_bundle(src_node: u64, dst_node: u64, flags: u64) -> Bundle {
    BundleBuilder::new()
        .source(EndpointId::ipn(0, src_node, 0).unwrap())
        .destination(EndpointId::ipn(0, dst_node, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(60_000)
        .bundle_flags(flags)
        .payload(b"test data".to_vec())
        .build()
        .unwrap()
}

/// RFC9171-5-009, 5-012: BPA MUST select and invoke CLA for forwarding
#[test]
fn test_rfc9171_5_009_5_012_cla_selection_and_invocation() {
    // Create bundle to forward
    let mut bundle = create_test_bundle(1, 3, 0);

    // Add Hop Count block
    let hop_block = HopCountBlock::new(2, 10, 0).unwrap(); // block 2, limit 10, count 0
    bundle.blocks.insert(0, hop_block.to_canonical().unwrap());

    // Add Previous Node block
    let prev_node = EndpointId::ipn(0, 1, 0).unwrap();
    let prev_block = PreviousNodeBlock::new(3, prev_node);
    bundle.blocks.insert(0, prev_block.to_canonical().unwrap());

    // Add Bundle Age block
    let age_block = BundleAgeBlock::new(4, 0); // Initial age 0
    bundle.blocks.insert(0, age_block.to_canonical().unwrap());

    // Simulate forwarding at node 2
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(500);

    // Process bundle for forwarding (updates extension blocks)
    let mut forwarded_bundle = bundle.clone();
    process_on_forward(&mut forwarded_bundle, &forwarding_node, residence_time).unwrap();

    // Mock CLA transmission (RFC9171-5-009, 5-012)
    let mut cla = MockCla::new();
    let result = cla.transmit(forwarded_bundle);

    // Verify CLA was successfully invoked
    assert!(result.is_ok(), "CLA transmission should succeed");
    assert_eq!(cla.transmitted_count(), 1, "Should transmit one bundle");

    // Verify bundle was updated during forwarding
    let transmitted = cla.last_transmitted().unwrap();

    // Check Hop Count incremented
    let hop_block_idx = transmitted
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::HopCount)
        .unwrap();
    let hop_block = HopCountBlock::from_canonical(&transmitted.blocks[hop_block_idx]).unwrap();
    assert_eq!(hop_block.hop_count, 1, "Hop count should be incremented");

    // Check Bundle Age updated
    let age_block_idx = transmitted
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::BundleAge)
        .unwrap();
    let age_block = BundleAgeBlock::from_canonical(&transmitted.blocks[age_block_idx]).unwrap();
    assert_eq!(
        age_block.age_ms, 500,
        "Bundle age should be updated by residence time"
    );

    // Check Previous Node replaced
    let prev_block_idx = transmitted
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::PreviousNode)
        .unwrap();
    let prev_block =
        PreviousNodeBlock::from_canonical(&transmitted.blocks[prev_block_idx]).unwrap();
    assert_eq!(
        prev_block.previous_node, forwarding_node,
        "Previous node should be updated"
    );
}

/// RFC 9171 §5.4.1: Hop Count increment and limit enforcement
#[test]
fn test_rfc9171_5_4_1_hop_count_limit_enforcement() {
    // Create bundle with Hop Count at limit
    let mut bundle = create_test_bundle(1, 3, 0);

    let hop_block = HopCountBlock::new(2, 5, 4).unwrap(); // limit 5, already at 4
    bundle.blocks.insert(0, hop_block.to_canonical().unwrap());

    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    // First forward: should succeed (4 -> 5, at limit but not exceeded)
    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(result.is_ok(), "Should succeed when reaching limit");

    // Check hop count is now at limit
    let hop_block_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::HopCount)
        .unwrap();
    let hop_block = HopCountBlock::from_canonical(&bundle.blocks[hop_block_idx]).unwrap();
    assert_eq!(hop_block.hop_count, 5, "Hop count should be at limit");
    // Note: is_exceeded() checks hop_count > hop_limit, so at limit (5 == 5) returns false
    // But next increment would exceed

    // Second forward: should fail (5 -> 6, exceeds limit)
    let result = process_on_forward(&mut bundle, &forwarding_node, residence_time);
    assert!(result.is_err(), "Should fail when hop limit exceeded");

    // This should trigger deletion with reason HopLimitExceeded
}

/// RFC 9171 §4.4.2: Bundle Age update during forwarding
#[test]
fn test_rfc9171_4_4_2_bundle_age_update_on_forward() {
    // Create bundle with Bundle Age block
    let mut bundle = create_test_bundle(1, 3, 0);

    let age_block = BundleAgeBlock::new(2, 1000); // Initial age 1000ms
    bundle.blocks.insert(0, age_block.to_canonical().unwrap());

    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(500);

    // Process bundle for forwarding
    process_on_forward(&mut bundle, &forwarding_node, residence_time).unwrap();

    // Check Bundle Age was updated
    let age_block_idx = bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::BundleAge)
        .unwrap();
    let age_block = BundleAgeBlock::from_canonical(&bundle.blocks[age_block_idx]).unwrap();

    assert_eq!(
        age_block.age_ms, 1500,
        "Bundle age should be incremented by residence time (1000 + 500)"
    );
}

/// RFC 9171 §4.4.1: Previous Node block replacement
#[test]
fn test_rfc9171_4_4_1_previous_node_block_replacement() {
    // Create bundle with existing Previous Node
    let mut bundle = create_test_bundle(1, 3, 0);

    let old_prev_node = EndpointId::ipn(0, 1, 0).unwrap();
    let old_prev_block = PreviousNodeBlock::new(2, old_prev_node.clone());
    bundle
        .blocks
        .insert(0, old_prev_block.to_canonical().unwrap());

    // Forward at node 2
    let forwarding_node = EndpointId::ipn(0, 2, 0).unwrap();
    let residence_time = SimDuration::from_millis(100);

    process_on_forward(&mut bundle, &forwarding_node, residence_time).unwrap();

    // Check Previous Node was replaced
    let prev_blocks: Vec<_> = bundle
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::PreviousNode)
        .collect();

    assert_eq!(
        prev_blocks.len(),
        1,
        "Should have exactly one Previous Node block"
    );

    let prev_block = PreviousNodeBlock::from_canonical(prev_blocks[0]).unwrap();
    assert_eq!(
        prev_block.previous_node, forwarding_node,
        "Previous node should be updated to forwarding node"
    );
    assert_ne!(
        prev_block.previous_node, old_prev_node,
        "Should not be old previous node"
    );
}

/// RFC 9171 §5.4.2: Forward Failed procedure (contraindication)
#[test]
fn test_rfc9171_5_4_2_forward_failed_contraindication() {
    // Create bundle to forward
    let bundle = create_test_bundle(1, 3, bundle_flags::REQUEST_REPORT_DELETION);

    // Simulate forwarding attempt with failing CLA
    let mut cla = MockCla::with_failure();
    let result = cla.transmit(bundle.clone());

    // Verify CLA transmission failed
    assert!(result.is_err(), "CLA should fail");
    assert_eq!(
        cla.transmitted_count(),
        0,
        "No bundle should be transmitted"
    );

    // Per RFC 9171 §5.4.2, when forwarding fails:
    // - BPA MAY retry by forwarding back to previous hop (contraindication)
    // - Or MUST delete bundle with appropriate reason code
    // This test verifies the failure is detected, actual deletion/retry is BPA policy
}

/// RFC 9171 §5.10: Bundle deletion with reason codes
#[test]
fn test_rfc9171_5_10_bundle_deletion_with_reasons() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
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
    let mut bpa = BundleAgent::new(config, storage);

    // Create bundle with deletion report flag
    let bundle = create_test_bundle(1, 3, bundle_flags::REQUEST_REPORT_DELETION);

    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

    // Generate deletion status report with specific reason
    let report = bpa
        .generate_deletion_status_report(&bundle_id, ReasonCode::LifetimeExpired, time)
        .unwrap();

    assert!(report.deleted.asserted, "Deletion should be asserted");
    assert_eq!(
        report.reason_code,
        ReasonCode::LifetimeExpired,
        "Should have correct reason code"
    );

    // Test other deletion reasons
    let reasons = [
        ReasonCode::NoKnownRoute,
        ReasonCode::NoTimelyContact,
        ReasonCode::HopLimitExceeded,
        ReasonCode::DepletedStorage,
    ];

    for (i, reason) in reasons.iter().enumerate() {
        // Create unique bundle for each test (different timestamp)
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(
                DtnTimeMs::from_millis(2000 + i as u64 * 100),
                0,
            ))
            .lifetime(60_000)
            .bundle_flags(bundle_flags::REQUEST_REPORT_DELETION)
            .payload(b"test data".to_vec())
            .build()
            .unwrap();

        let bundle_id = bpa.admit_bundle(bundle, time).unwrap();

        let report = bpa
            .generate_deletion_status_report(&bundle_id, *reason, time)
            .unwrap();
        assert_eq!(
            report.reason_code, *reason,
            "Should have correct reason code"
        );
    }
}

/// RFC 9171 §5.7: Local bundle delivery
#[test]
fn test_rfc9171_5_7_local_bundle_delivery() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 2, 0).unwrap());
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
    let mut bpa = BundleAgent::new(config, storage);

    // Create bundle destined for local node (node 2)
    let bundle = create_test_bundle(1, 2, bundle_flags::REQUEST_REPORT_DELIVERY);

    let time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle.clone(), time).unwrap();

    // Check destination is local
    assert!(
        bpa.is_local_destination(&bundle.primary.destination),
        "Destination should be local"
    );

    // Deliver bundle
    bpa.deliver_bundle(&bundle_id, time).unwrap();

    // Check bundle state
    assert_eq!(
        bpa.get_state(&bundle_id),
        Some(BundleState::Delivered),
        "Bundle should be delivered"
    );

    // Generate delivery status report
    let report = bpa
        .generate_delivery_status_report(&bundle_id, time)
        .unwrap();

    assert!(report.delivered.asserted, "Delivery should be asserted");
    assert_eq!(report.reason_code, ReasonCode::NoAdditionalInformation);
}

/// RFC 9171 §5.10: Lifetime expiry and deletion
#[test]
fn test_rfc9171_5_10_lifetime_expiry() {
    let policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
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
    let mut bpa = BundleAgent::new(config, storage);

    // Create bundle with short lifetime
    let builder = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(1000) // 1 second lifetime
        .bundle_flags(bundle_flags::REQUEST_REPORT_DELETION)
        .payload(b"test data".to_vec());

    let bundle = builder.build().unwrap();

    let admit_time = SimInstant::from_nanos(1_000_000_000);
    let bundle_id = bpa.admit_bundle(bundle, admit_time).unwrap();

    // Check expiration at different times
    // Not expired at admission time
    assert!(
        !bpa.check_expiration(&bundle_id, admit_time).unwrap(),
        "Should not be expired at admission"
    );

    // Expired after lifetime
    let future_time = SimInstant::from_nanos(3_000_000_000); // 2 seconds after admission
    assert!(
        bpa.check_expiration(&bundle_id, future_time).unwrap(),
        "Should be expired after lifetime"
    );

    // Find expired bundles
    let expired = bpa.find_expired_bundles(future_time);
    assert!(expired.contains(&bundle_id), "Should find expired bundle");
}

/// Integration test: Multi-hop forwarding with extension block updates
#[test]
fn test_multi_hop_forwarding_integration() {
    // Create bundle with all extension blocks
    let mut bundle = create_test_bundle(1, 4, 0);

    // Add Hop Count (limit 10, count 0)
    let hop_block = HopCountBlock::new(2, 10, 0).unwrap();
    bundle.blocks.insert(0, hop_block.to_canonical().unwrap());

    // Add Previous Node (node 1)
    let prev_block = PreviousNodeBlock::new(3, EndpointId::ipn(0, 1, 0).unwrap());
    bundle.blocks.insert(0, prev_block.to_canonical().unwrap());

    // Add Bundle Age (initial 0)
    let age_block = BundleAgeBlock::new(4, 0);
    bundle.blocks.insert(0, age_block.to_canonical().unwrap());

    // Simulate three hops: 1 -> 2 -> 3 -> 4
    let hops = vec![
        (
            EndpointId::ipn(0, 2, 0).unwrap(),
            SimDuration::from_millis(100),
        ),
        (
            EndpointId::ipn(0, 3, 0).unwrap(),
            SimDuration::from_millis(200),
        ),
    ];

    let mut current_bundle = bundle;
    let mut cla = MockCla::new();

    for (forwarding_node, residence_time) in hops {
        // Process for forwarding
        process_on_forward(&mut current_bundle, &forwarding_node, residence_time).unwrap();

        // Transmit via CLA
        cla.transmit(current_bundle.clone()).unwrap();

        // Retrieve for next hop
        current_bundle = cla.last_transmitted().unwrap().clone();
    }

    // Verify final state after 2 hops
    let final_bundle = cla.last_transmitted().unwrap();

    // Check Hop Count: 0 -> 1 -> 2
    let hop_block_idx = final_bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::HopCount)
        .unwrap();
    let hop_block = HopCountBlock::from_canonical(&final_bundle.blocks[hop_block_idx]).unwrap();
    assert_eq!(hop_block.hop_count, 2, "Hop count should be 2 after 2 hops");

    // Check Bundle Age: 0 + 100 + 200 = 300
    let age_block_idx = final_bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::BundleAge)
        .unwrap();
    let age_block = BundleAgeBlock::from_canonical(&final_bundle.blocks[age_block_idx]).unwrap();
    assert_eq!(
        age_block.age_ms, 300,
        "Bundle age should be cumulative residence time"
    );

    // Check Previous Node: should be node 3 (last hop)
    let prev_block_idx = final_bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::PreviousNode)
        .unwrap();
    let prev_block =
        PreviousNodeBlock::from_canonical(&final_bundle.blocks[prev_block_idx]).unwrap();
    assert_eq!(
        prev_block.previous_node,
        EndpointId::ipn(0, 3, 0).unwrap(),
        "Previous node should be last forwarder"
    );

    // Verify CLA was invoked twice
    assert_eq!(
        cla.transmitted_count(),
        2,
        "CLA should have transmitted 2 times"
    );
}
