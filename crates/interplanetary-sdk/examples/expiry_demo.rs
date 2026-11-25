//! Bundle expiry demonstration
//! Shows bundles expiring when lifetime exceeded

use interplanetary_sdk::{
    bp::BundleBuilder,
    bpa::{BundleState, StatusReportPolicy, admin::ReasonCode},
    sim::*,
    types::*,
};

fn main() -> Result<()> {
    println!("Bundle Expiry Demonstration");
    println!("===========================\n");

    // Create scenario with single delayed contact
    let mut plan = ContactPlan::new();

    // Contact opens late (after bundle expires)
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::from_nanos(10_000_000_000), // 10s
        end: SimInstant::from_nanos(20_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(1),
        resource_group: None,
    });

    let mut scenario = Scenario::new(plan, Bytes::from_mib(10).unwrap());

    // Add nodes with status report policy
    let report_policy = StatusReportPolicy::all(EndpointId::ipn(0, 1, 0).unwrap());
    scenario.add_node_with_policy(
        NodeId::ipn(0, 1),
        Bytes::from_mib(10).unwrap(),
        report_policy.clone(),
    )?;
    scenario.add_node_with_policy(
        NodeId::ipn(0, 2),
        Bytes::from_mib(10).unwrap(),
        report_policy,
    )?;

    // Create bundle with short lifetime (5 seconds)
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(5_000) // 5 seconds (will expire before contact opens)
        .payload(b"Will expire".to_vec())
        .build()?;

    println!("Bundle Configuration:");
    println!("  Source: ipn:0.1.0");
    println!("  Destination: ipn:0.2.0");
    println!("  Lifetime: 5 seconds");
    println!("  Contact opens at: 10 seconds");
    println!("  Expected: Bundle expires before transmission\n");

    let bundle_id = scenario.inject_bundle(&NodeId::ipn(0, 1), bundle)?;

    // Schedule expiry check at 6 seconds (after lifetime)
    scenario.schedule_expiry_checks(SimInstant::from_nanos(6_000_000_000))?;

    // Run simulation
    let result = scenario.run()?;

    println!("Simulation Results:");
    println!("==================");
    println!(
        "  Final time: {} s",
        result.final_time.as_nanos() / 1_000_000_000
    );
    println!("  Events processed: {}", result.events_processed);

    // Check bundle state
    if let Some(agent) = scenario.get_agent(&NodeId::ipn(0, 1)) {
        if let Some(state) = agent.get_state(&bundle_id) {
            println!("\nBundle State: {:?}", state);

            if state == BundleState::Deleted {
                println!("✓ Bundle correctly expired and deleted");
            }
        }

        // Check if status report was generated
        if agent.config().status_report_policy.report_on_deletion {
            println!("✓ Status report policy active (deletion reporting enabled)");

            if let Some(report) = agent.generate_deletion_status_report(
                &bundle_id,
                ReasonCode::LifetimeExpired,
                result.final_time,
            ) {
                println!("\nGenerated Status Report:");
                println!("  Source: {:?}", report.source_eid);
                println!("  Reason: {:?}", report.reason_code);
                println!("  Deleted: {:?}", report.deleted);
            }
        }
    }

    // Event summary
    println!("\nEvent Log:");
    for (time, event) in &result.event_log {
        let time_s = time.as_nanos() / 1_000_000_000;
        match event {
            Event::BundleAdmitted { bundle_id: _, node } => {
                println!("  {}s: Bundle admitted at {}", time_s, node);
            }
            Event::BundleExpired { bundle_id: _, node } => {
                println!("  {}s: Bundle expired at {} ✓", time_s, node);
            }
            _ => {}
        }
    }

    println!("\n===========================");
    println!("Expiry Demonstration Complete");

    Ok(())
}
