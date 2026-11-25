#![cfg(feature = "bpv7")]

//! RFC 9171 §4.2.7: Creation timestamp sequence counter

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

#[test]
fn test_rfc9171_4_042_sequence_counter_may_reset() {
    // RFC 9171 §4.2.7: "The sequence counter MAY be reset to zero whenever the
    // current time advances by one millisecond."

    // Create bundles at different times with sequence counter reset to 0
    let time1 = DtnTimeMs::from_millis(1000);
    let time2 = DtnTimeMs::from_millis(1001); // Advanced by 1ms

    let bundle1 = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(time1, 5))
        .lifetime(3600000)
        .payload(b"test1".to_vec())
        .build()
        .unwrap();

    // Sequence counter MAY be reset to 0 when time advances
    let bundle2 = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(time2, 0)) // Reset to 0
        .lifetime(3600000)
        .payload(b"test2".to_vec())
        .build()
        .unwrap();

    assert_eq!(bundle1.primary.creation_timestamp.sequence, 5);
    assert_eq!(bundle2.primary.creation_timestamp.sequence, 0);
    assert!(bundle2.primary.creation_timestamp.time > bundle1.primary.creation_timestamp.time);

    // SDK allows resetting sequence counter when time advances
}
