//! ION contact plan parser integration test
//!
//! Tests that ION-style contact plans can be parsed and used for routing.

use interplanetary_sdk::sim::ion_parser::IonParser;
use interplanetary_sdk::types::SimInstant;

#[test]
fn test_parse_three_node_ion_fixture() {
    // Load fixture
    let fixture = include_str!("fixtures/three_node.ionrc");

    // Parse with base time at epoch
    let base_time = SimInstant::from_nanos(0);
    let mut parser = IonParser::new(base_time);
    let plan = parser.parse_plan(fixture).unwrap();

    // Verify contacts
    let contacts = plan.contacts();
    assert_eq!(contacts.len(), 2, "Should have 2 contacts");

    // Verify Earth-Relay contact
    let earth_relay = contacts
        .iter()
        .find(|c| {
            use interplanetary_sdk::types::NodeId;
            c.from_node
                == NodeId::Ipn {
                    allocator: 0,
                    node: 1,
                }
                && c.to_node
                    == NodeId::Ipn {
                        allocator: 0,
                        node: 2,
                    }
        })
        .expect("Should have Earth-Relay contact");

    use interplanetary_sdk::types::SimDuration;
    assert_eq!(
        earth_relay.delay,
        SimDuration::from_secs(5),
        "Earth-Relay delay should be 5s"
    );

    // Verify Relay-Mars contact
    let relay_mars = contacts
        .iter()
        .find(|c| {
            use interplanetary_sdk::types::NodeId;
            c.from_node
                == NodeId::Ipn {
                    allocator: 0,
                    node: 2,
                }
                && c.to_node
                    == NodeId::Ipn {
                        allocator: 0,
                        node: 3,
                    }
        })
        .expect("Should have Relay-Mars contact");

    assert_eq!(
        relay_mars.delay,
        SimDuration::from_secs(10),
        "Relay-Mars delay should be 10s"
    );
}

#[test]
fn test_ion_contact_plan_timing() {
    // Parse the three-node fixture
    let fixture = include_str!("fixtures/three_node.ionrc");
    let base_time = SimInstant::from_nanos(0);
    let mut parser = IonParser::new(base_time);
    let plan = parser.parse_plan(fixture).unwrap();

    let contacts = plan.contacts();

    // Verify Earth-Relay timing
    use interplanetary_sdk::types::NodeId;
    let earth_relay = contacts
        .iter()
        .find(|c| {
            c.from_node
                == NodeId::Ipn {
                    allocator: 0,
                    node: 1,
                }
        })
        .unwrap();

    use interplanetary_sdk::types::SimDuration;
    assert_eq!(earth_relay.start, base_time, "Earth-Relay starts at t=0");
    assert_eq!(
        earth_relay.end,
        base_time.checked_add(SimDuration::from_secs(100)).unwrap()
    );

    // Verify Relay-Mars timing
    let relay_mars = contacts
        .iter()
        .find(|c| {
            c.from_node
                == NodeId::Ipn {
                    allocator: 0,
                    node: 2,
                }
        })
        .unwrap();

    assert_eq!(
        relay_mars.start,
        base_time.checked_add(SimDuration::from_secs(50)).unwrap()
    );
    assert_eq!(
        relay_mars.end,
        base_time.checked_add(SimDuration::from_secs(150)).unwrap()
    );
}
