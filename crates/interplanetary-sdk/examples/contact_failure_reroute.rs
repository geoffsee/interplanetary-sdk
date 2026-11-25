//! Contact failure and rerouting demonstration

use interplanetary_sdk::{bp::BundleBuilder, sim::*, types::*};

fn main() -> Result<()> {
    println!("Contact Failure and Rerouting Demo");
    println!("===================================\n");

    // Setup: Earth → Relay → Mars with backup direct route
    let mut plan = ContactPlan::new();

    // Primary path: Earth → Relay (fails early)
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(2_000_000_000), // Only 2s duration (fails early)
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(4),
        resource_group: Some("earth-relay".to_string()),
    });

    // Would-be second hop (never reached due to C1 failure)
    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(10_000_000_000),
        end: SimInstant::from_nanos(20_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(6),
        resource_group: Some("relay-mars".to_string()),
    });

    // Backup: Earth → Mars direct (slower but available later)
    plan.add_contact(Contact {
        id: ContactId(3),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(5_000_000_000), // Opens at T=5s
        end: SimInstant::from_nanos(30_000_000_000),
        rate: BitsPerSecond::from_kbps(4).unwrap(), // Slower rate
        delay: SimDuration::from_secs(20),
        resource_group: Some("earth-mars-backup".to_string()),
    });

    println!("Contact Plan:");
    println!("  C1: Earth → Relay (0-2s) - WILL CLOSE EARLY");
    println!("  C2: Relay → Mars (10-20s)");
    println!("  C3: Earth → Mars backup (5-30s, slower)\n");

    let mut scenario = Scenario::new(plan, Bytes::from_mib(10).unwrap());
    scenario.add_node(NodeId::ipn(0, 1), Bytes::from_mib(10).unwrap())?;
    scenario.add_node(NodeId::ipn(0, 2), Bytes::from_mib(10).unwrap())?;
    scenario.add_node(NodeId::ipn(0, 3), Bytes::from_mib(10).unwrap())?;

    // Bundle ready at T=3s (after C1 closes)
    // Should route via backup C3 instead
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(3000), 1))
        .lifetime(60_000)
        .payload(vec![0u8; 500])
        .build()?;

    println!("Bundle:");
    println!("  Ready at: T=3s (after C1 closes)");
    println!("  Size: 500 bytes");
    println!("  Expected: Route via backup C3\n");

    scenario.inject_bundle(&NodeId::ipn(0, 1), bundle)?;

    let result = scenario.run()?;

    println!("Simulation Results:");
    println!("==================");
    println!(
        "  Final time: {} s",
        result.final_time.as_nanos() / 1_000_000_000
    );
    println!("  Events processed: {}", result.events_processed);

    // Check which route was used
    let mut used_c1 = false;
    let mut used_c3 = false;

    for (_time, event) in &result.event_log {
        if let Event::TransmissionCompleted { contact_id, .. } = event {
            match contact_id.0 {
                1 => used_c1 = true,
                3 => used_c3 = true,
                _ => {}
            }
        }
    }

    println!("\nRoute Analysis:");
    if used_c3 && !used_c1 {
        println!("  ✓ Correctly used backup route C3 (Earth → Mars direct)");
        println!("  ✓ Avoided failed primary route C1");
    } else if used_c1 {
        println!("  ✗ Attempted to use C1 (which closes at T=2s)");
    } else {
        println!("  ? No transmission events detected");
    }

    // Check delivery
    let mars_agent = scenario.get_agent(&NodeId::ipn(0, 3)).unwrap();
    let delivered =
        mars_agent.list_bundles_in_state(interplanetary_sdk::bpa::BundleState::Delivered);

    if !delivered.is_empty() {
        println!("\n✓ Bundle successfully delivered via backup route!");
    } else {
        println!("\n✗ Bundle not delivered");
    }

    println!("\n===================================");
    println!("Contact Failure Demo Complete");

    Ok(())
}
