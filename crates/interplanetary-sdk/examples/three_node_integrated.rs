//! Three-node integrated end-to-end simulation
//! Demonstrates full BPA lifecycle: admission → routing → transmission → delivery

use interplanetary_sdk::{bp::BundleBuilder, bpa::BundleState, sim::*, types::*};

fn main() -> Result<()> {
    println!("Three-Node Integrated DTN Simulation");
    println!("====================================\n");

    // Create contact plan matching scenarios/three-node-scheduler.json
    let mut plan = ContactPlan::new();

    // C1: Earth → Relay (0-10s, 8 kbps, 4s delay)
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(10_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(4),
        resource_group: Some("earth-relay".to_string()),
    });

    // C2: Relay → Mars (10-20s, 8 kbps, 6s delay)
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

    // C3: Earth → Mars direct (0-20s, 1 kbps, 20s delay)
    plan.add_contact(Contact {
        id: ContactId(3),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(20_000_000_000),
        rate: BitsPerSecond::from_kbps(1).unwrap(),
        delay: SimDuration::from_secs(20),
        resource_group: Some("earth-mars".to_string()),
    });

    println!("Contact Plan:");
    println!("  C1: Earth → Relay (0-10s, 8 kbps, 4s delay)");
    println!("  C2: Relay → Mars (10-20s, 8 kbps, 6s delay)");
    println!("  C3: Earth → Mars (0-20s, 1 kbps, 20s delay)\n");

    // Create scenario with nodes
    let mut scenario = Scenario::new(plan, Bytes::from_mib(10).unwrap());

    scenario.add_node(NodeId::ipn(0, 1), Bytes::from_mib(10).unwrap())?; // Earth
    scenario.add_node(NodeId::ipn(0, 2), Bytes::from_mib(10).unwrap())?; // Relay
    scenario.add_node(NodeId::ipn(0, 3), Bytes::from_mib(10).unwrap())?; // Mars

    println!("Nodes:");
    println!("  Earth: ipn:0.1 (10 MiB storage)");
    println!("  Relay: ipn:0.2 (10 MiB storage)");
    println!("  Mars:  ipn:0.3 (10 MiB storage)\n");

    // Create bundle: Earth → Mars, 1000 bytes
    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 3, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000) // 60 seconds
        .payload(vec![0u8; 1000])
        .build()?;

    println!("Bundle:");
    println!("  Source: ipn:0.1.0 (Earth)");
    println!("  Destination: ipn:0.3.0 (Mars)");
    println!("  Size: 1000 bytes");
    println!("  Lifetime: 60 seconds\n");

    // Inject bundle at Earth
    let bundle_id = scenario.inject_bundle(&NodeId::ipn(0, 1), bundle)?;
    println!("Bundle {} injected at Earth\n", bundle_id);

    // Run simulation
    println!("Running simulation...\n");
    let result = scenario.run()?;

    println!("Simulation Results:");
    println!("==================");
    println!(
        "  Final time: {} ns ({} s)",
        result.final_time.as_nanos(),
        result.final_time.as_nanos() / 1_000_000_000
    );
    println!("  Events processed: {}", result.events_processed);
    println!("  Quiescent reason: {:?}\n", result.quiescent_reason);

    // Check bundle state at each node
    println!("Bundle States:");
    println!("--------------");

    if let Some(earth_agent) = scenario.get_agent(&NodeId::ipn(0, 1))
        && let Some(state) = earth_agent.get_state(&bundle_id)
    {
        println!("  Earth: {:?}", state);
    }

    if let Some(relay_agent) = scenario.get_agent(&NodeId::ipn(0, 2))
        && let Some(state) = relay_agent.get_state(&bundle_id)
    {
        println!("  Relay: {:?}", state);
    }

    if let Some(mars_agent) = scenario.get_agent(&NodeId::ipn(0, 3)) {
        if let Some(state) = mars_agent.get_state(&bundle_id) {
            println!("  Mars:  {:?}", state);

            if state == BundleState::Delivered {
                println!("\n✓ Bundle successfully delivered to Mars!");
            }
        } else {
            println!("  Mars:  (not received)");
        }
    }

    // Show event log (summary)
    println!("\nEvent Summary:");
    println!("--------------");
    let mut admission_count = 0;
    let mut transmission_count = 0;
    let mut reception_count = 0;
    let mut delivery_count = 0;

    for (_time, event) in &result.event_log {
        match event {
            Event::BundleAdmitted { .. } => admission_count += 1,
            Event::TransmissionCompleted { .. } => transmission_count += 1,
            Event::ReceptionCompleted { .. } => reception_count += 1,
            Event::BundleDelivered { .. } => delivery_count += 1,
            _ => {}
        }
    }

    println!("  Admissions: {}", admission_count);
    println!("  Transmissions: {}", transmission_count);
    println!("  Receptions: {}", reception_count);
    println!("  Deliveries: {}", delivery_count);

    println!("\n====================================");
    println!("Integrated Simulation Complete");

    Ok(())
}
