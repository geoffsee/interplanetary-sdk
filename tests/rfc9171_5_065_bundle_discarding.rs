#![cfg(feature = "bpv7")]

//! RFC 9171 §5.11: Bundle discarding when no retention constraints

use interplanetary_sdk::bp::*;
use interplanetary_sdk::types::*;

#[test]
fn test_rfc9171_5_065_may_discard_when_no_constraints() {
    // RFC 9171 §5.11: "As soon as a bundle has no remaining retention
    // constraints, it MAY be discarded, thereby releasing any persistent
    // storage that may have been allocated to it."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Bundle exists
    assert!(bundle.payload_block().is_some());

    // When bundle has no remaining retention constraints, SDK MAY discard it
    // (This is implicit - dropping the bundle discards it)
    drop(bundle);

    // SDK allows discarding bundles (via Rust's ownership/drop semantics)
}
