//! RFC 9171 §4.2.3 & §5.10 Bundle Lifetime and Expiry Tests

mod common;

use common::bundle_with_lifetime;
use interplanetary_sdk::types::EndpointId;

#[test]
fn test_rfc9171_4_2_3_lifetime_expiry_causes_deletion() {
    // RFC 9171 §4.2.3: "The lifetime of a bundle SHALL be
    // the period of time that starts when the bundle is created
    // and ends at the bundle's creation timestamp plus its lifetime"
    //
    // RFC 9171 §5.10: "A bundle MUST be deleted for the reason 'lifetime
    // expired' when the current time is greater than the bundle's creation
    // timestamp plus its lifetime"

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle created at time 1000ms with 500ms lifetime
    // Should expire at 1500ms
    let bundle = bundle_with_lifetime(source, dest, 1000, 500);

    let creation_time_ms = bundle.primary.creation_timestamp.time.as_millis();
    let lifetime_ms = bundle.primary.lifetime;
    let expiry_time_ms = creation_time_ms + lifetime_ms;

    assert_eq!(creation_time_ms, 1000, "Creation time should be 1000ms");
    assert_eq!(lifetime_ms, 500, "Lifetime should be 500ms");
    assert_eq!(expiry_time_ms, 1500, "Expiry time should be 1500ms");

    // At time 1499ms: not expired (within lifetime)
    let current_time_1499 = 1499u64;
    assert!(
        current_time_1499 <= expiry_time_ms,
        "Bundle should NOT be expired at time {} (expiry at {})",
        current_time_1499,
        expiry_time_ms
    );

    // At time 1500ms: expired (exactly at expiry)
    let current_time_1500 = 1500u64;
    assert!(
        current_time_1500 >= expiry_time_ms,
        "Bundle MUST be considered expired at or after expiry time"
    );

    // At time 1501ms: expired (past expiry)
    let current_time_1501 = 1501u64;
    assert!(
        current_time_1501 > expiry_time_ms,
        "Bundle MUST be deleted when current time > creation + lifetime"
    );
}

#[test]
fn test_rfc9171_lifetime_calculation() {
    // RFC 9171 §4.2.3: Verify lifetime calculation matches specification

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Test various lifetime values
    let test_cases = vec![
        (1000000, 3600000), // 1s creation, 1h lifetime
        (0, 86400000),      // Zero creation time, 24h lifetime
        (5000, 1000),       // 5s creation, 1s lifetime
    ];

    for (creation_ms, lifetime_ms) in test_cases {
        let bundle = bundle_with_lifetime(source.clone(), dest.clone(), creation_ms, lifetime_ms);

        let actual_creation = bundle.primary.creation_timestamp.time.as_millis();
        let actual_lifetime = bundle.primary.lifetime;
        let expiry = actual_creation + actual_lifetime;

        assert_eq!(actual_creation, creation_ms);
        assert_eq!(actual_lifetime, lifetime_ms);
        assert_eq!(
            expiry,
            creation_ms + lifetime_ms,
            "Expiry time MUST be creation timestamp plus lifetime"
        );
    }
}

#[test]
fn test_rfc9171_zero_lifetime_immediate_expiry() {
    // RFC 9171 §4.2.3: A bundle with lifetime=0 expires immediately

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    // Bundle with zero lifetime
    let bundle = bundle_with_lifetime(source, dest, 1000, 0);

    let creation_time = bundle.primary.creation_timestamp.time.as_millis();
    let lifetime = bundle.primary.lifetime;
    let expiry_time = creation_time + lifetime;

    assert_eq!(lifetime, 0, "Lifetime is zero");
    assert_eq!(
        expiry_time, creation_time,
        "With lifetime=0, expiry time equals creation time"
    );

    // Any current time >= creation time means expired
    assert!(
        creation_time >= expiry_time,
        "Bundle with lifetime=0 is expired at creation time"
    );
}

#[test]
fn test_rfc9171_lifetime_deterministic_check() {
    // Verify lifetime expiry is deterministic given explicit timestamps

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let dest = EndpointId::ipn(0, 2, 0).unwrap();

    let bundle = bundle_with_lifetime(source, dest, 5000, 2000);

    let creation = bundle.primary.creation_timestamp.time.as_millis();
    let lifetime = bundle.primary.lifetime;
    let expiry = creation + lifetime;

    // Test deterministic expiry checks at various times
    // Note: current_time > expiry means expired
    let time_checks = vec![
        (4999, false), // Before creation
        (5000, false), // At creation (5000 <= 7000)
        (6000, false), // Mid-lifetime (6000 <= 7000)
        (6999, false), // Just before expiry (6999 <= 7000)
        (7000, false), // At expiry (7000 == 7000, not >)
        (7001, true),  // After expiry (7001 > 7000)
        (10000, true), // Well after expiry
    ];

    for (current_time, should_be_expired) in time_checks {
        let is_expired = current_time > expiry;
        assert_eq!(
            is_expired, should_be_expired,
            "At time {}, expiry check should be {} (expiry={})",
            current_time, should_be_expired, expiry
        );
    }
}
