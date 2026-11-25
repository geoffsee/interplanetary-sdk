//! Three-node Earth → Relay → Mars example
//! Demonstrates routing, transmission, and delivery per charter §10 vertical slice.
//!
//! Scenario from kit/scenarios/three-node-scheduler.json:
//! - Contact C1: Earth → Relay (0-10s, 8000 bps, 4s delay)
//! - Contact C2: Relay → Mars (10-20s, 8000 bps, 6s delay)
//! - Contact C3: Earth → Mars direct (0-20s, 1000 bps, 20s delay)
//! - Bundle: 1000 bytes, Earth → Mars
//! - Expected: Route via relay, arrive at 17s (vs 28s direct)

use interplanetary_sdk::{
    bp::BundleBuilder,
    routing::{CgrConfig, CgrRouter},
    sim::*,
    types::*,
};

fn main() -> Result<()> {
    println!("Three-Node DTN Simulation");
    println!("=========================\n");

    // Create contact plan matching scenarios/three-node-scheduler.json
    let mut plan = ContactPlan::new();

    // C1: Earth → Relay (0-10s, 8 kbps, 4s delay)
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1), // Earth
        to_node: NodeId::ipn(0, 2),   // Relay
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(10_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(4),
        resource_group: Some("earth-relay".to_string()),
    });

    // C2: Relay → Mars (10-20s, 8 kbps, 6s delay)
    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2), // Relay
        to_node: NodeId::ipn(0, 3),   // Mars
        start: SimInstant::from_nanos(10_000_000_000),
        end: SimInstant::from_nanos(20_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(6),
        resource_group: Some("relay-mars".to_string()),
    });

    // C3: Earth → Mars direct (0-20s, 1 kbps, 20s delay)
    plan.add_contact(Contact {
        id: ContactId(3),
        from_node: NodeId::ipn(0, 1), // Earth
        to_node: NodeId::ipn(0, 3),   // Mars
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(20_000_000_000),
        rate: BitsPerSecond::from_kbps(1).unwrap(), // 1000 bps
        delay: SimDuration::from_secs(20),
        resource_group: Some("earth-mars".to_string()),
    });

    println!("Contact Plan:");
    println!("  C1: Earth → Relay (0-10s, 8 kbps, 4s delay)");
    println!("  C2: Relay → Mars (10-20s, 8 kbps, 6s delay)");
    println!("  C3: Earth → Mars (0-20s, 1 kbps, 20s delay)\n");

    // Create bundle: Earth → Mars, 1000 bytes
    let _bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap()) // Earth
        .destination(EndpointId::ipn(0, 3, 0).unwrap()) // Mars
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(60_000) // 60 seconds
        .payload(vec![0u8; 1000]) // 1000 bytes
        .build()?;

    println!("Bundle:");
    println!("  Source: ipn:0.1.0 (Earth)");
    println!("  Destination: ipn:0.3.0 (Mars)");
    println!("  Size: 1000 bytes");
    println!("  Lifetime: 60 seconds\n");

    // Compute route with CGR
    let router = CgrRouter::new(CgrConfig::default());
    let route = router.compute_route(
        &NodeId::ipn(0, 1), // From Earth
        &NodeId::ipn(0, 3), // To Mars
        Bytes(1000),
        SimInstant::ZERO,
        &plan,
    )?;

    println!("CGR Routing:");
    println!("  Next hop: {}", route.next_hop);
    println!("  Via contact: {:?}", route.via_contact);
    println!(
        "  Arrival time: {} ns ({} s)",
        route.arrival_time.as_nanos(),
        route.arrival_time.as_nanos() / 1_000_000_000
    );
    println!("  Path: {} hops", route.path.len());

    // Verify routing matches expectation
    if route.path.len() == 2 {
        println!("\n✓ Route uses relay (2 hops)");
    } else {
        println!("\n✗ Route does not use relay ({} hops)", route.path.len());
    }

    let expected_arrival_ns = 17_000_000_000u64;
    let actual_arrival_ns = route.arrival_time.as_nanos();

    if actual_arrival_ns == expected_arrival_ns {
        println!("✓ Arrival time matches expected 17s");
    } else {
        println!(
            "✗ Arrival time {} ns != expected {} ns",
            actual_arrival_ns, expected_arrival_ns
        );
    }

    // Compute direct route for comparison
    println!("\nDirect Route Analysis:");
    let c3 = plan.get_contact(ContactId(3)).unwrap();
    let direct_tx_time = c3.serialization_time(Bytes(1000))?;
    println!("  Transmission time: {} ms", direct_tx_time.as_millis());
    println!("  Propagation delay: {} s", c3.delay.as_secs());
    if let Some(arrival) = SimInstant::ZERO.checked_add(direct_tx_time)
        && let Some(final_arrival) = arrival.checked_add(c3.delay)
    {
        println!(
            "  Direct arrival: {} s",
            final_arrival.as_nanos() / 1_000_000_000
        );
    }

    println!("\n=========================");
    println!("Simulation Complete");

    Ok(())
}
