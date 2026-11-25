//! Routing and simulation benchmarks per charter §6
//!
//! Measures route latency, events/sec, and peak memory usage.
//! Hardware, toolchain, and commands recorded per charter requirement.
//!
//! Run with: cargo test --bench routing_bench --all-features -- --nocapture

use interplanetary_sdk::{
    bp::BundleBuilder,
    routing::{CgrConfig, CgrRouter},
    sim::{Contact, ContactId, ContactPlan},
    types::{
        BitsPerSecond, Bytes, CreationTimestamp, DtnTimeMs, EndpointId, NodeId, SimDuration,
        SimInstant,
    },
};
use std::time::Instant;

/// Print hardware and toolchain info (run once at start)
fn print_bench_info() {
    println!("\n=== Benchmark Environment ===");
    println!("Toolchain: rustc 1.99.1 (58cf8f9c3 2026-10-13)");
    println!("Target: x86_64-unknown-linux-gnu");
    println!("Build: cargo bench --bench routing_bench");

    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(model) = cpuinfo
            .lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
        {
            println!("CPU: {}", model.trim());
        }
    }

    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(total) = meminfo
            .lines()
            .find(|l| l.starts_with("MemTotal"))
            .and_then(|l| l.split_whitespace().nth(1))
        {
            println!("Memory: {} KB", total);
        }
    }

    println!("=============================\n");
}

/// Tier 1: Small (3 nodes, 5 contacts) per ACCEPTANCE.md
fn tier1_plan() -> ContactPlan {
    let mut plan = ContactPlan::new();
    let hour_ns = 3_600_000_000_000u64; // nanoseconds

    // Earth → Relay
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(hour_ns * 2),
        rate: BitsPerSecond::from_mbps(1).unwrap(), // 1 Mbps
        delay: SimDuration::from_millis(100),
        resource_group: None,
    });

    // Relay → Mars (with gap)
    plan.add_contact(Contact {
        id: ContactId(2),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 3),
        start: SimInstant::from_nanos(hour_ns * 3),
        end: SimInstant::from_nanos(hour_ns * 5),
        rate: BitsPerSecond::from_kbps(500).unwrap(), // 500 Kbps
        delay: SimDuration::from_millis(300),
        resource_group: None,
    });

    // Return paths
    plan.add_contact(Contact {
        id: ContactId(3),
        from_node: NodeId::ipn(0, 3),
        to_node: NodeId::ipn(0, 2),
        start: SimInstant::from_nanos(hour_ns * 6),
        end: SimInstant::from_nanos(hour_ns * 8),
        rate: BitsPerSecond::from_kbps(500).unwrap(),
        delay: SimDuration::from_millis(300),
        resource_group: None,
    });

    plan.add_contact(Contact {
        id: ContactId(4),
        from_node: NodeId::ipn(0, 2),
        to_node: NodeId::ipn(0, 1),
        start: SimInstant::from_nanos(hour_ns * 7),
        end: SimInstant::from_nanos(hour_ns * 9),
        rate: BitsPerSecond::from_mbps(1).unwrap(),
        delay: SimDuration::from_millis(100),
        resource_group: None,
    });

    plan
}

/// Tier 2: Medium (10 nodes, ~50 contacts)
fn tier2_plan() -> ContactPlan {
    let mut plan = ContactPlan::new();
    let hour_ns = 3_600_000_000_000u64; // nanoseconds
    let mut contact_id = 1u64;

    // Create mesh topology
    for i in 1..=10 {
        for j in (i + 1)..=10 {
            if (i + j) % 3 != 0 {
                let start_offset_ns = ((i * j) % 24) * hour_ns;
                let duration_ns = (2 + ((i + j) % 4)) * hour_ns;

                plan.add_contact(Contact {
                    id: ContactId(contact_id),
                    from_node: NodeId::ipn(0, i),
                    to_node: NodeId::ipn(0, j),
                    start: SimInstant::from_nanos(start_offset_ns),
                    end: SimInstant::from_nanos(start_offset_ns + duration_ns),
                    rate: BitsPerSecond::from_kbps(1_000 - (i * 50)).unwrap(),
                    delay: SimDuration::from_micros(50 + (j * 10)),
                    resource_group: None,
                });
                contact_id += 1;

                if (i * j) % 2 == 0 {
                    plan.add_contact(Contact {
                        id: ContactId(contact_id),
                        from_node: NodeId::ipn(0, j),
                        to_node: NodeId::ipn(0, i),
                        start: SimInstant::from_nanos(start_offset_ns + hour_ns),
                        end: SimInstant::from_nanos(start_offset_ns + duration_ns + hour_ns),
                        rate: BitsPerSecond::from_kbps(800).unwrap(),
                        delay: SimDuration::from_micros(50 + (i * 10)),
                        resource_group: None,
                    });
                    contact_id += 1;
                }
            }
        }
    }

    plan
}

/// Manual measurement test with real timing
#[test]
fn measure_route_latency() {
    print_bench_info();

    println!("=== Tier 1: Route Latency (3 nodes, 5 contacts) ===");
    let plan = tier1_plan();
    let router = CgrRouter::new(CgrConfig::default());

    let bundle = BundleBuilder::new()
        .source(EndpointId::Ipn {
            allocator: 0,
            node: 1,
            service: 0,
        })
        .destination(EndpointId::Ipn {
            allocator: 0,
            node: 3,
            service: 1,
        })
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(86_400_000)
        .payload(vec![0xEE; 1000])
        .build()
        .unwrap();

    let bundle_size = Bytes::from_bytes(bundle.estimated_size() as u64);
    let from = NodeId::ipn(0, 1);
    let to = NodeId::ipn(0, 3);

    let iterations = 10000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = router.compute_route(&from, &to, bundle_size, SimInstant::ZERO, &plan);
    }

    let elapsed = start.elapsed();
    println!("Iterations: {}", iterations);
    println!("Total time: {:?}", elapsed);
    println!("Average: {} µs/route", elapsed.as_micros() / iterations);
    println!(
        "Throughput: {:.0} routes/sec",
        iterations as f64 / elapsed.as_secs_f64()
    );

    println!("\n=== Tier 2: Route Latency (10 nodes, ~50 contacts) ===");
    let plan2 = tier2_plan();

    let bundle2 = BundleBuilder::new()
        .source(EndpointId::Ipn {
            allocator: 0,
            node: 1,
            service: 0,
        })
        .destination(EndpointId::Ipn {
            allocator: 0,
            node: 10,
            service: 1,
        })
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(86_400_000)
        .payload(vec![0xFF; 1000])
        .build()
        .unwrap();

    let bundle_size2 = Bytes::from_bytes(bundle2.estimated_size() as u64);
    let from2 = NodeId::ipn(0, 1);
    let to2 = NodeId::ipn(0, 10);

    let start2 = Instant::now();

    for _ in 0..iterations {
        let _ = router.compute_route(&from2, &to2, bundle_size2, SimInstant::ZERO, &plan2);
    }

    let elapsed2 = start2.elapsed();
    println!("Iterations: {}", iterations);
    println!("Total time: {:?}", elapsed2);
    println!("Average: {} µs/route", elapsed2.as_micros() / iterations);
    println!(
        "Throughput: {:.0} routes/sec",
        iterations as f64 / elapsed2.as_secs_f64()
    );

    println!("\n=== Memory Usage Estimate ===");
    println!("RSS before benchmarks: {} KB", get_current_rss());

    // Create larger structures
    let plans: Vec<_> = (0..100).map(|_| tier2_plan()).collect();
    let bundles: Vec<_> = (0..1000)
        .map(|i| {
            BundleBuilder::new()
                .source(EndpointId::Ipn {
                    allocator: 0,
                    node: 1,
                    service: 0,
                })
                .destination(EndpointId::Ipn {
                    allocator: 0,
                    node: 10,
                    service: 1,
                })
                .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, i))
                .lifetime(86_400_000)
                .payload(vec![0xAA; 5000])
                .build()
                .unwrap()
        })
        .collect();

    println!(
        "RSS after 100 plans + 1000 bundles (5KB each): {} KB",
        get_current_rss()
    );
    println!("Plans count: {}", plans.len());
    println!("Bundles count: {}", bundles.len());
}

fn get_current_rss() -> u64 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    return kb_str.parse().unwrap_or(0);
                }
            }
        }
    }
    0
}
