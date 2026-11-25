#![cfg(feature = "bpv7")]

//! RFC 9171 §4.1: Implementation MAY discard or accept non-conforming bundles

use interplanetary_sdk::bp::*;

#[test]
fn test_rfc9171_4_010_may_discard_nonconforming() {
    // RFC 9171 §4.1: "An implementation of the Bundle Protocol MAY discard
    // any sequence of bytes that does not conform to the Bundle Protocol
    // specification."

    // Invalid CBOR bundle (not an indefinite array)
    let invalid_bundle = vec![0x82, 0x01, 0x02]; // Definite array, not indefinite

    // SDK MAY discard non-conforming bytes (by rejecting decode)
    let result = BundleCodec::decode(&invalid_bundle);
    assert!(
        result.is_err(),
        "Implementation MAY discard non-conforming bundles"
    );
}

#[test]
fn test_rfc9171_4_011_implementation_choice_on_nonconforming() {
    // RFC 9171 §4.1: "An implementation of the Bundle Protocol MAY accept a
    // sequence of bytes that does not conform to the Bundle Protocol
    // specification"

    // This SDK chooses to be strict and reject non-conforming bundles
    // Other implementations MAY choose to accept them

    // Malformed bundle
    let malformed = vec![0x9F, 0xFF]; // Indefinite array with immediate break, no blocks

    let result = BundleCodec::decode(&malformed);
    // This implementation chooses strict validation
    assert!(result.is_err(), "This SDK validates strictly");
}
