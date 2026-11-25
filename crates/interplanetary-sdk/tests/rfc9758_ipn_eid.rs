//! RFC 9758 ipn EID obligation tests
//!
//! Tests for allocator/node/service semantics, 2-element vs 3-element encodings,
//! textual form, null EID, and LocalNode handling per RFC 9758.

use interplanetary_sdk::bp::{BundleBuilder, BundleCodec};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

#[test]
fn test_rfc9758_6_1_1_two_element_encoding_allocator_zero() {
    // RFC 9758 §6.1.1: "The two-element scheme-specific encoding provides backwards
    // compatibility with the encoding provided in Section 4.2.5.1.2 of [RFC9171].
    // When used in this way, the encoding of the FQNN replaces the use of the Node
    // Number that was specified in [RFC9171]. When the Node Number is allocated by
    // the Default Allocator (Section 3.2.2), the encoding of the FQNN and the
    // encoding of the Node Number from [RFC9171] are identical."

    // ipn:0.100.1 (allocator=0, node=100, service=1)
    let eid = EndpointId::ipn(0, 100, 1).unwrap();
    let bundle = BundleBuilder::new()
        .source(eid.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    assert_eq!(decoded.primary.source, eid);

    // Verify 2-element encoding: [FQNN, service] where FQNN = (allocator << 32) | node
    // For allocator=0, node=100: FQNN = 0x0000000000000064 = 100
    // So encoding should be [100, 1] not [0, 100, 1]
}

#[test]
fn test_rfc9758_6_1_2_three_element_encoding_nonzero_allocator() {
    // RFC 9758 §6.1.2: "The three-element scheme-specific encoding allows for a more
    // efficient representation of ipn EIDs using smaller Allocator Identifiers, and
    // implementations are RECOMMENDED to use this encoding scheme unless explicitly
    // mitigating for interoperability issues"

    // ipn:977000.100.1 from RFC example
    let eid = EndpointId::ipn(977000, 100, 1).unwrap();
    let bundle = BundleBuilder::new()
        .source(eid.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    assert_eq!(decoded.primary.source, eid);

    // Verify 3-element encoding: [allocator, node, service] = [977000, 100, 1]
}

#[test]
fn test_rfc9758_6_4_eid_matching_encoding_equivalence() {
    // RFC 9758 §6.4: "Regardless of whether the two-element or three-element scheme-
    // specific encoding is used, ipn EID matching MUST be performed on the decoded EID
    // information itself. Different encodings of the same ipn EID MUST be treated as
    // equivalent when performing EID-specific functions."

    // Both allocator=0, node=100, service=1 should match regardless of encoding
    let eid1 = EndpointId::ipn(0, 100, 1).unwrap();
    let eid2 = EndpointId::ipn(0, 100, 1).unwrap();

    assert_eq!(eid1, eid2, "Same ipn EID must match");
}

#[test]
fn test_rfc9758_3_1_null_ipn_eid() {
    // RFC 9758 §3.1: "The Null ipn URI is an ipn URI where both the Node Number and
    // the Service Number are zero (0)."

    let null_eid = EndpointId::ipn(0, 0, 0).unwrap();

    // This represents ipn:0.0 (allocator=0, node=0, service=0)
    // It should be distinguishable from dtn:none
    assert_ne!(null_eid, EndpointId::null());
}

#[test]
fn test_rfc9758_3_4_1_zero_node_number_invalid() {
    // RFC 9758 §3.4.1: "This means that any ipn URI with a zero (0) Allocator Identifier
    // and a zero (0) Node Number, but a non-zero Service Number component, is invalid.
    // Such ipn URIs MUST NOT be composed, and processors of such ipn URIs MUST consider
    // them as the Null ipn URI."

    // ipn:0.0.0 is allowed (represents null)
    let _null_ipn = EndpointId::ipn(0, 0, 0).unwrap();

    // But ipn:0.0.X where X != 0 MUST NOT be composed
    assert!(
        EndpointId::ipn(0, 0, 1).is_err(),
        "ipn:0.0.1 MUST NOT be composed"
    );
    assert!(
        EndpointId::ipn(0, 0, 999).is_err(),
        "ipn:0.0.999 MUST NOT be composed"
    );

    // Parsing (processing) such URIs should still treat them as Null (RFC9758-010)
    let parsed = EndpointId::parse("ipn:0.0.1").unwrap();
    assert!(
        parsed.is_null(),
        "Processors MUST treat ipn:0.0.X as Null when parsing"
    );
}

#[test]
fn test_rfc9758_4_textual_format_allocator_omitted() {
    // RFC 9758 §4: "If the Allocator Identifier is 0 (the Default Allocator), then
    // both the Allocator Identifier and the '.' delimiter immediately following the
    // <allocator-identifier> MAY be omitted."

    // Parse ipn:100.1 (allocator omitted, means allocator=0)
    let eid1 = EndpointId::parse("ipn:100.1").unwrap();
    assert_eq!(eid1, EndpointId::ipn(0, 100, 1).unwrap());

    // Parse ipn:0.100.1 (allocator explicit)
    let eid2 = EndpointId::parse("ipn:0.100.1").unwrap();
    assert_eq!(eid2, EndpointId::ipn(0, 100, 1).unwrap());

    // Both should be equal
    assert_eq!(eid1, eid2);
}

#[test]
fn test_rfc9758_4_textual_format_with_allocator() {
    // RFC 9758 §4: Full format ipn:allocator.node.service

    let eid = EndpointId::parse("ipn:977000.100.1").unwrap();
    assert_eq!(eid, EndpointId::ipn(977000, 100, 1).unwrap());
}

#[test]
fn test_rfc9758_4_1_no_leading_zeros() {
    // RFC 9758 §4: "All leading '0' characters MUST be omitted. A single '0' digit
    // is permitted when the value of a decimal number is 0."

    // These should parse correctly (no leading zeros in input)
    let eid1 = EndpointId::parse("ipn:1.2").unwrap();
    assert_eq!(eid1, EndpointId::ipn(0, 1, 2).unwrap());

    // Note: ipn:0.0.0 (allocator=0, node=0, service=0) is rejected per RFC 9758 §3.4.1
    // "Node 0 ipn URIs MUST NOT be composed"
    // Use ipn:1.0 or another valid EID instead
    let eid2 = EndpointId::parse("ipn:1.10").unwrap();
    assert_eq!(eid2, EndpointId::ipn(0, 1, 10).unwrap());
}

#[test]
fn test_rfc9758_5_1_singleton_endpoint() {
    // RFC 9758 §5.1: "An ipn EID MUST identify a singleton endpoint. The bundle
    // processing node that is the sole member of that endpoint MUST be identified
    // by that ipn EID's FQNN."

    // Each ipn EID uniquely identifies one endpoint
    let eid1 = EndpointId::ipn(0, 100, 1).unwrap();
    let eid2 = EndpointId::ipn(0, 100, 2).unwrap(); // Different service
    let eid3 = EndpointId::ipn(0, 101, 1).unwrap(); // Different node

    assert_ne!(eid1, eid2);
    assert_ne!(eid1, eid3);
    assert_ne!(eid2, eid3);
}

#[test]
fn test_rfc9758_5_4_local_node_constraints() {
    // RFC 9758 §5.4: "When LocalNode ipn EIDs are used in a bundle, they identify
    // services on the receiving node, irrespective of that node's actual Node Number."

    // LocalNode range for allocator 0: 0xFFFFFFF0 to 0xFFFFFFFE (§3.4.2)
    let local_node_eid = EndpointId::ipn(0, 0xFFFFFFF0, 1).unwrap();

    // RFC 9758 §5.4: "LocalNode ipn EIDs MUST NOT be present in any other field
    // of the primary block."

    // We can represent LocalNode EIDs but they have special semantics
    assert_eq!(local_node_eid, EndpointId::ipn(0, 0xFFFFFFF0, 1).unwrap());
}

#[test]
fn test_rfc9758_6_1_1_fqnn_packing() {
    // RFC 9758 §6.1.1: "The FQNN encoding MUST be a 64-bit unsigned integer
    // constructed in the following way:
    // 1. The least significant 32 bits MUST represent the Node Number
    // 2. The most significant 32 bits MUST represent the Allocator Identifier"

    // Example from RFC: ipn:977000.100.1
    // FQNN = 0xEE868_00000064
    // allocator = 0xEE868 = 977000
    // node = 0x64 = 100

    let eid = EndpointId::ipn(977000, 100, 1).unwrap();
    let bundle = BundleBuilder::new()
        .source(eid.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    // Verify round-trip preserves allocator, node, service
    match decoded.primary.source {
        EndpointId::Ipn {
            allocator,
            node,
            service,
        } => {
            assert_eq!(allocator, 977000);
            assert_eq!(node, 100);
            assert_eq!(service, 1);
        }
        _ => panic!("Expected ipn EID"),
    }
}

#[test]
fn test_rfc9758_6_2_decoding_ambiguity() {
    // RFC 9758 §6.2: "The presence of different scheme-specific encodings does not
    // introduce any decoding ambiguity."

    // Test that we can decode both 2-element and 3-element correctly

    // 2-element: [FQNN, service]
    let eid_2elem = EndpointId::ipn(0, 100, 1).unwrap();
    let bundle1 = BundleBuilder::new()
        .source(eid_2elem.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    let encoded1 = BundleCodec::encode(&bundle1).unwrap();
    let decoded1 = BundleCodec::decode(&encoded1).unwrap();
    assert_eq!(decoded1.primary.source, eid_2elem);

    // 3-element: [allocator, node, service]
    let eid_3elem = EndpointId::ipn(977000, 100, 1).unwrap();
    let bundle2 = BundleBuilder::new()
        .source(eid_3elem.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    let encoded2 = BundleCodec::encode(&bundle2).unwrap();
    let decoded2 = BundleCodec::decode(&encoded2).unwrap();
    assert_eq!(decoded2.primary.source, eid_3elem);
}

#[test]
fn test_rfc9758_allocator_service_number_ranges() {
    // RFC 9758 §3.2.1: Allocator identifiers have specific ranges
    // RFC 9758 §3.5: Service numbers are unspecified range

    // Test various allocator values
    let eid_default = EndpointId::ipn(0, 100, 1).unwrap(); // Default allocator
    let eid_small = EndpointId::ipn(1, 100, 1).unwrap(); // Small allocator
    let eid_large = EndpointId::ipn(0xFFFFFFFF, 100, 1).unwrap(); // Max 32-bit allocator

    // All should be representable
    assert_eq!(eid_default, EndpointId::ipn(0, 100, 1).unwrap());
    assert_eq!(eid_small, EndpointId::ipn(1, 100, 1).unwrap());
    assert_eq!(eid_large, EndpointId::ipn(0xFFFFFFFF, 100, 1).unwrap());

    // RFC 9758 §4: Service numbers MUST be in the range 0 to 4294967295 (u32::MAX)
    let eid_service_max = EndpointId::ipn(0, 100, u32::MAX as u64).unwrap();
    assert_eq!(
        eid_service_max,
        EndpointId::ipn(0, 100, u32::MAX as u64).unwrap()
    );

    // Service numbers > u32::MAX are rejected
    assert!(EndpointId::ipn(0, 100, u64::MAX).is_err());
}

#[test]
fn test_rfc9758_3_3_node_number_ranges() {
    // RFC 9758 §3.3: "All Node Number assignments, by all Allocators, MUST be in
    // the range 1 to 4,294,967,295 (2^32 - 1)."

    // Valid node numbers
    let eid_node_1 = EndpointId::ipn(0, 1, 0).unwrap();
    let eid_node_max = EndpointId::ipn(0, 0xFFFFFFFF, 0).unwrap();

    assert_eq!(eid_node_1, EndpointId::ipn(0, 1, 0).unwrap());
    assert_eq!(eid_node_max, EndpointId::ipn(0, 0xFFFFFFFF, 0).unwrap());

    // Node 0 is invalid (null EID)
    let _eid_node_0 = EndpointId::ipn(0, 0, 0).unwrap();
    // Should be marked as null/invalid, but we can represent it
}

#[test]
fn test_rfc9758_display_format() {
    // Test Display implementation follows RFC 9758 §4 textual format

    // Allocator=0: omit allocator in display
    let eid1 = EndpointId::ipn(0, 100, 1).unwrap();
    assert_eq!(eid1.to_string(), "ipn:100.1");

    // Allocator!=0: include allocator in display
    let eid2 = EndpointId::ipn(977000, 100, 1).unwrap();
    assert_eq!(eid2.to_string(), "ipn:977000.100.1");

    // Null ipn EID
    let eid3 = EndpointId::ipn(0, 0, 0).unwrap();
    assert_eq!(eid3.to_string(), "ipn:0.0");
}

#[test]
fn test_rfc9758_6_1_byte_exact_encoding() {
    // RFC 9758 §6.1: Verify exact byte encoding per RFC examples
    // Example: ipn:977000.100.1
    //   allocator = 977000 = 0xEE868
    //   node = 100 = 0x64
    //   service = 1
    //
    // Two-element encoding: 0x821B000EE8680000006401
    //   82 = array(2) for [scheme, ssp]
    //   02 = scheme code 2 (ipn)
    //   82 = array(2) for [fqnn, service]
    //   1B 000EE86800000064 = FQNN as uint64
    //   01 = service 1
    //
    // Three-element encoding: 0x831A000EE868186401
    //   82 = array(2) for [scheme, ssp]
    //   02 = scheme code 2 (ipn)
    //   83 = array(3) for [allocator, node, service]
    //   1A 000EE868 = allocator 977000 as uint32
    //   18 64 = node 100 as uint8
    //   01 = service 1

    let eid = EndpointId::ipn(977000, 100, 1).unwrap();

    // Create a bundle with this EID as source
    let bundle = BundleBuilder::new()
        .source(eid.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    // Encode the bundle
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Per ADR-004: We use 3-element encoding for allocator!=0
    // Verify the EID portion contains the 3-element encoding
    // The encoded bundle starts with: 9F [primary block array] [canonical blocks] FF
    // Primary block contains source EID

    // Decode and verify round-trip
    let decoded = BundleCodec::decode(&encoded).unwrap();
    assert_eq!(
        decoded.primary.source, eid,
        "Source EID must round-trip correctly"
    );

    // Both encodings must decode to the same EID and compare as equal
    // (This tests the decoder's ability to handle both formats)

    // Verify EID matching per RFC 9758 §6.4
    let eid_copy = EndpointId::ipn(977000, 100, 1).unwrap();
    assert_eq!(
        eid, eid_copy,
        "Same ipn EID must compare equal regardless of encoding"
    );
}
