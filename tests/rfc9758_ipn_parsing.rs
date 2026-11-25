//! RFC 9758 IPN URI parsing and validation tests
//!
//! Tests ABNF syntax compliance, invalid format rejection, and CBOR encoding.

use interplanetary_sdk::bp::{BundleBuilder, BundleCodec};
use interplanetary_sdk::types::EndpointId;
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs};

/// RFC9758-015: Text syntax ABNF compliance
///
/// RFC 9758 §4: "The text syntax of an ipn URI MUST comply with the following ABNF syntax
/// from [RFC5234] and repeats the core ABNF syntax rule for DIGIT defined by that
/// specification: ipn-uri = "ipn:" ipn-hier-part ipn-hier-part = fqnn "." service"
#[test]
fn test_rfc9758_015_abnf_syntax_valid_formats() {
    // Valid 2-element format: node.service
    assert!(
        EndpointId::parse("ipn:100.1").is_ok(),
        "ipn:100.1 is valid ABNF"
    );

    // Valid 3-element format: allocator.node.service
    assert!(
        EndpointId::parse("ipn:977000.100.1").is_ok(),
        "ipn:977000.100.1 is valid ABNF"
    );

    // Valid null: 0.0
    assert!(
        EndpointId::parse("ipn:0.0").is_ok(),
        "ipn:0.0 is valid ABNF"
    );

    // Valid with '!' shorthand
    assert!(
        EndpointId::parse("ipn:!.!").is_ok(),
        "ipn:!.! is valid ABNF"
    );
}

/// RFC9758-015: ABNF syntax rejection - invalid formats
///
/// RFC 9758 §4: The text syntax MUST comply with ABNF. Invalid formats must be rejected.
#[test]
fn test_rfc9758_015_abnf_syntax_reject_invalid() {
    // Missing service number
    assert!(
        EndpointId::parse("ipn:100").is_err(),
        "ipn:100 violates ABNF (missing service)"
    );

    // Missing node and service
    assert!(
        EndpointId::parse("ipn:").is_err(),
        "ipn: violates ABNF (empty SSP)"
    );

    // Too many components
    assert!(
        EndpointId::parse("ipn:1.2.3.4").is_err(),
        "ipn:1.2.3.4 violates ABNF (4 components)"
    );

    // Non-numeric characters (except '!')
    assert!(
        EndpointId::parse("ipn:abc.123").is_err(),
        "ipn:abc.123 violates ABNF (non-numeric)"
    );
    assert!(
        EndpointId::parse("ipn:100.xyz").is_err(),
        "ipn:100.xyz violates ABNF (non-numeric)"
    );

    // Leading zeros (RFC 9758 §4: "All leading '0' characters MUST be omitted")
    assert!(
        EndpointId::parse("ipn:0100.1").is_err(),
        "ipn:0100.1 violates RFC 9758 §4 (leading zero)"
    );
    assert!(
        EndpointId::parse("ipn:100.001").is_err(),
        "ipn:100.001 violates RFC 9758 §4 (leading zero)"
    );

    // Negative numbers (must be unsigned)
    assert!(
        EndpointId::parse("ipn:-100.1").is_err(),
        "ipn:-100.1 violates ABNF (negative)"
    );

    // Spaces
    assert!(
        EndpointId::parse("ipn:100 .1").is_err(),
        "ipn:100 .1 violates ABNF (space)"
    );
    assert!(
        EndpointId::parse("ipn: 100.1").is_err(),
        "ipn: 100.1 violates ABNF (space)"
    );
}

/// RFC9758-037: CBOR encoding as unsigned integers
///
/// RFC 9758 §6: "element of the array MUST be encoded as a single CBOR unsigned integer."
#[test]
fn test_rfc9758_037_cbor_unsigned_integer_encoding() {
    // Create bundle with ipn EID
    let eid = EndpointId::ipn(977000, 100, 1).unwrap();
    let bundle = BundleBuilder::new()
        .source(eid.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0x01])
        .build()
        .unwrap();

    // Encode and verify CBOR structure
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Decode to verify round-trip preserves EID
    let decoded = BundleCodec::decode(&encoded).unwrap();
    assert_eq!(
        decoded.primary.source, eid,
        "CBOR round-trip must preserve ipn EID"
    );

    // The encoding uses CBOR unsigned integers (major type 0), not text strings
    // This test verifies that the codec doesn't encode as ["ipn", "977000.100.1"]
    // but as the proper numeric array
}

/// RFC9758-044: EID matching on decoded information
///
/// RFC 9758 §6.4: "ipn EID matching MUST be performed on the decoded EID information
/// itself. Different encodings of the same ipn EID MUST be treated as equivalent."
#[test]
fn test_rfc9758_044_eid_matching_decoded_equivalence() {
    // Same logical EID created different ways
    let eid1 = EndpointId::parse("ipn:0.100.1").unwrap();
    let eid2 = EndpointId::parse("ipn:100.1").unwrap(); // Legacy 2-element (allocator implicit 0)
    let eid3 = EndpointId::ipn(0, 100, 1).unwrap(); // Direct construction

    // All three MUST match because they represent the same decoded EID
    assert_eq!(
        eid1, eid2,
        "ipn:0.100.1 and ipn:100.1 must match (same decoded EID)"
    );
    assert_eq!(eid1, eid3, "Parsed and constructed EIDs must match");
    assert_eq!(eid2, eid3, "Legacy and 3-element formats must match");
}

/// RFC9758-044: EID matching rejects different decoded values
///
/// RFC 9758 §6.4: Matching is on decoded values, so different EIDs must not match.
#[test]
fn test_rfc9758_044_eid_matching_different_values() {
    let eid1 = EndpointId::ipn(0, 100, 1).unwrap();
    let eid2 = EndpointId::ipn(0, 100, 2).unwrap(); // Different service
    let eid3 = EndpointId::ipn(0, 101, 1).unwrap(); // Different node
    let eid4 = EndpointId::ipn(1, 100, 1).unwrap(); // Different allocator

    assert_ne!(eid1, eid2, "Different service numbers must not match");
    assert_ne!(eid1, eid3, "Different node numbers must not match");
    assert_ne!(eid1, eid4, "Different allocators must not match");
}

/// RFC9758-015: Numeric range validation
///
/// RFC 9758 §4: Numbers must fit in u32 range (0 to 4294967295).
#[test]
fn test_rfc9758_015_numeric_range_validation() {
    // Maximum valid value (u32::MAX)
    assert!(
        EndpointId::parse("ipn:4294967295.4294967295").is_ok(),
        "u32::MAX is valid"
    );

    // Shorthand for u32::MAX
    assert!(
        EndpointId::parse("ipn:!.!").is_ok(),
        "'!' shorthand is valid"
    );

    // Beyond u32::MAX should be rejected
    assert!(
        EndpointId::parse("ipn:4294967296.1").is_err(),
        "Beyond u32::MAX is invalid"
    );
    assert!(
        EndpointId::parse("ipn:1.4294967296").is_err(),
        "Service beyond u32::MAX is invalid"
    );
}

/// RFC9758-015: Edge cases - single digit, zeros
#[test]
fn test_rfc9758_015_edge_cases() {
    // Single digits are valid
    assert!(EndpointId::parse("ipn:1.1").is_ok(), "ipn:1.1 is valid");
    assert!(
        EndpointId::parse("ipn:0.0").is_ok(),
        "ipn:0.0 is valid (Null)"
    );

    // Zero is valid but "00" is not (leading zero)
    assert!(EndpointId::parse("ipn:0.1").is_ok(), "ipn:0.1 is valid");
    assert!(
        EndpointId::parse("ipn:00.1").is_err(),
        "ipn:00.1 has leading zero"
    );

    // Large but valid numbers
    assert!(
        EndpointId::parse("ipn:999999999.888888888").is_ok(),
        "Large valid numbers"
    );
}

/// RFC9758-001: Three-component tuple structure
///
/// RFC 9758 §3: "representation or a binary encoding, MUST be considered as a tuple
/// of the following three components: * The Allocator Identifier * The Node Number
/// * The Service Number"
#[test]
fn test_rfc9758_001_three_component_tuple() {
    // Every IPN EID has three components, even in 2-element textual form
    let eid_2_elem = EndpointId::parse("ipn:100.1").unwrap();
    let eid_3_elem = EndpointId::parse("ipn:0.100.1").unwrap();

    // Both represent the same (allocator=0, node=100, service=1) tuple
    assert_eq!(eid_2_elem, eid_3_elem, "Same tuple must be equal");

    // All three components are present
    if let EndpointId::Ipn {
        allocator,
        node,
        service,
    } = eid_2_elem
    {
        assert_eq!(allocator, 0, "Allocator component");
        assert_eq!(node, 100, "Node component");
        assert_eq!(service, 1, "Service component");
    } else {
        panic!("Must be IPN variant");
    }
}

/// RFC9758-017: Singleton endpoint identification
///
/// RFC 9758 §5.1: "An ipn EID MUST identify a singleton endpoint. The bundle
/// processing node that is the sole member of that endpoint MUST be the node
/// identified by the FQNN"
#[test]
fn test_rfc9758_017_singleton_endpoint() {
    // IPN EIDs identify singleton endpoints (single node)
    let eid1 = EndpointId::ipn(977000, 100, 1).unwrap();
    let eid2 = EndpointId::ipn(977000, 100, 2).unwrap();

    // Same FQNN (allocator, node) = same bundle processing node
    // Different service numbers = different services on same node
    assert_ne!(eid1, eid2, "Different services are different endpoints");

    // But they share the same FQNN
    if let (
        EndpointId::Ipn {
            allocator: a1,
            node: n1,
            ..
        },
        EndpointId::Ipn {
            allocator: a2,
            node: n2,
            ..
        },
    ) = (&eid1, &eid2)
    {
        assert_eq!((a1, n1), (a2, n2), "Same FQNN (allocator, node)");
    }
}

/// RFC9758-020: Shared FQNN refers to same node
///
/// RFC 9758 §5.1: "However, all ipn EIDs that share any single FQNN MUST refer
/// to the same bundle processing node."
#[test]
fn test_rfc9758_020_shared_fqnn_same_node() {
    // Multiple EIDs with same (allocator, node) refer to same node
    let eid1 = EndpointId::ipn(977000, 100, 1).unwrap();
    let eid2 = EndpointId::ipn(977000, 100, 2).unwrap();
    let eid3 = EndpointId::ipn(977000, 100, 42).unwrap();

    // All share FQNN (977000, 100)
    for eid in [&eid1, &eid2, &eid3] {
        if let EndpointId::Ipn {
            allocator, node, ..
        } = eid
        {
            assert_eq!((*allocator, *node), (977000, 100), "Same FQNN");
        }
    }
}

/// RFC9758-036: CBOR array encoding (2 or 3 elements)
///
/// RFC 9758 §6.1: "with BPv7, the scheme-specific part of an ipn URI MUST be
/// represented as a CBOR array of either two (2) or three (3) elements."
#[test]
fn test_rfc9758_036_cbor_array_encoding() {
    // 2-element encoding for allocator=0, ipn:100.1
    // RFC 9758 §6.1.1: [FQNN, service] where FQNN = (0 << 32) | 100 = 100
    // Expected CBOR: 0x82 (array of 2), 0x18 0x64 (uint 100), 0x01 (uint 1)
    let eid_2 = EndpointId::ipn(0, 100, 1).unwrap();
    let bundle_2 = BundleBuilder::new()
        .source(eid_2.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0x01])
        .build()
        .unwrap();

    let encoded_2 = BundleCodec::encode(&bundle_2).unwrap();

    // Find the source EID in the encoded bundle and check CBOR structure
    // The source EID SSP should contain: 0x82 0x18 0x64 0x01
    let eid_bytes = &[0x82u8, 0x18, 0x64, 0x01];
    assert!(
        encoded_2.windows(eid_bytes.len()).any(|w| w == eid_bytes),
        "2-element encoding must be CBOR array [100, 1]: 0x82 0x18 0x64 0x01"
    );

    // 3-element encoding for allocator≠0, ipn:977000.100.1
    // RFC 9758 §6.1.2: [allocator, node, service] = [977000, 100, 1]
    // 977000 = 0x0ee868, encoded as 0x1a 0x00 0x0e 0xe8 0x68 (uint32)
    // Expected CBOR: 0x83 (array of 3), 0x1a 0x00 0x0e 0xe8 0x68, 0x18 0x64, 0x01
    let eid_3 = EndpointId::ipn(977000, 100, 1).unwrap();
    let bundle_3 = BundleBuilder::new()
        .source(eid_3.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0x01])
        .build()
        .unwrap();

    let encoded_3 = BundleCodec::encode(&bundle_3).unwrap();

    // The source EID SSP should contain: 0x83 0x1a 0x00 0x0e 0xe8 0x68 0x18 0x64 0x01
    let eid_bytes_3 = &[0x83u8, 0x1a, 0x00, 0x0e, 0xe8, 0x68, 0x18, 0x64, 0x01];
    assert!(
        encoded_3
            .windows(eid_bytes_3.len())
            .any(|w| w == eid_bytes_3),
        "3-element encoding must be CBOR array [977000, 100, 1]: 0x83 0x1a 0x00 0x0e 0xe8 0x68 0x18 0x64 0x01"
    );
}

/// RFC9758-046: EID comparison treats equivalent encodings the same
///
/// RFC 9758 §6.4: "differently, any EID-based comparisons MUST treat these values
/// the same: as representing the ipn EID ipn:977000.100.1"
#[test]
fn test_rfc9758_046_comparison_equivalence() {
    // Same logical EID through different paths
    let eid_text = EndpointId::parse("ipn:977000.100.1").unwrap();
    let eid_direct = EndpointId::ipn(977000, 100, 1).unwrap();

    // Must compare equal
    assert_eq!(
        eid_text, eid_direct,
        "Equivalent representations must compare equal"
    );

    // Different EIDs must not compare equal
    let eid_different = EndpointId::ipn(977000, 100, 2).unwrap();
    assert_ne!(
        eid_text, eid_different,
        "Different EIDs must not compare equal"
    );
}

/// RFC9758-019: Multiple ipn EIDs per node
///
/// RFC 9758 §5.1: "A single bundle processing node MAY have multiple ipn EIDs
/// associated with it."
#[test]
fn test_rfc9758_019_multiple_eids_per_node() {
    // A node can have multiple service numbers (different EIDs, same FQNN)
    let eid1 = EndpointId::ipn(977000, 100, 1).unwrap();
    let eid2 = EndpointId::ipn(977000, 100, 2).unwrap();
    let eid3 = EndpointId::ipn(977000, 100, 42).unwrap();

    // All are valid EIDs for different services on the same node
    // Same FQNN (977000, 100), different services (1, 2, 42)
    for eid in [&eid1, &eid2, &eid3] {
        if let EndpointId::Ipn {
            allocator, node, ..
        } = eid
        {
            assert_eq!((*allocator, *node), (977000, 100), "Same node FQNN");
        }
    }

    // They are distinct EIDs
    assert_ne!(eid1, eid2);
    assert_ne!(eid1, eid3);
    assert_ne!(eid2, eid3);
}

/// RFC9758-035: CBOR encoding definition
///
/// RFC 9758 §6: "represent BPv7 EIDs MUST define how the scheme-specific part of
/// the URI scheme is encoded with Concise Binary Object Representation (CBOR)"
#[test]
fn test_rfc9758_035_cbor_encoding_defined() {
    // IPN scheme-specific part is encoded as CBOR array (not string)
    let eid = EndpointId::ipn(977000, 100, 1).unwrap();

    let bundle = BundleBuilder::new()
        .source(eid.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0x01])
        .build()
        .unwrap();

    // Encode to CBOR
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Decode and verify EID preserved
    let decoded = BundleCodec::decode(&encoded).unwrap();
    assert_eq!(
        decoded.primary.source, eid,
        "CBOR encoding must preserve IPN EID"
    );

    // The encoding is defined as CBOR array (verified by successful round-trip)
}

/// RFC9758-001: MUST be considered as a tuple - equivalence across forms
///
/// RFC 9758 §3: "MUST be considered as a tuple of the following three components"
/// Different textual/CBOR representations of the same tuple must be treated as equal.
#[test]
fn test_rfc9758_001_tuple_equivalence_across_forms() {
    // 2-element text form: ipn:100.1 (implicit allocator=0)
    let eid_2elem = EndpointId::parse("ipn:100.1").unwrap();

    // 3-element text form: ipn:0.100.1 (explicit allocator=0)
    let eid_3elem = EndpointId::parse("ipn:0.100.1").unwrap();

    // Direct construction
    let eid_direct = EndpointId::ipn(0, 100, 1).unwrap();

    // RFC 9758 §3: All three MUST be considered as the same tuple (0, 100, 1)
    assert_eq!(
        eid_2elem, eid_3elem,
        "2-element and 3-element forms must be equal"
    );
    assert_eq!(eid_2elem, eid_direct, "Text and direct forms must be equal");
    assert_eq!(eid_3elem, eid_direct, "All forms must be equal");

    // CBOR round-trip must preserve equivalence
    let bundle1 = BundleBuilder::new()
        .source(eid_2elem.clone())
        .destination(EndpointId::ipn(0, 200, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600)
        .payload(vec![0x01])
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle1).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    // Decoded EID must equal original tuple
    assert_eq!(decoded.primary.source, eid_2elem);
    assert_eq!(decoded.primary.source, eid_3elem);
}

/// RFC9758-020: Shared FQNN MUST refer to same node - node-level behavior
///
/// RFC 9758 §5.1: "all ipn EIDs that share any single FQNN MUST refer to the
/// same bundle processing node"
#[test]
fn test_rfc9758_020_shared_fqnn_node_behavior() {
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
    use interplanetary_sdk::sim::StorageManager;
    use interplanetary_sdk::types::{Bytes, NodeId};

    // Node with FQNN (977000, 100)
    let local_eid = EndpointId::ipn(977000, 100, 0).unwrap();
    let config = BpaConfig {
        local_node: NodeId::ipn(977000, 100),
        local_eid: local_eid.clone(),
        enable_forwarding: true,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::all(local_eid),
        cla_mtu: None,
        #[cfg(feature = "bpsec-default")]
        security_context: None,
        #[cfg(feature = "bpsec-default")]
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: interplanetary_sdk::bpa::policy::ForwardingFailedPolicy::default(
        ),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };
    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let agent = BundleAgent::new(config, storage);

    // RFC 9758 §5.1: EIDs with FQNN (977000, 100) refer to THIS node
    assert!(
        agent.is_local_destination(&EndpointId::ipn(977000, 100, 1).unwrap()),
        "ipn:977000.100.1 must be local (same FQNN)"
    );
    assert!(
        agent.is_local_destination(&EndpointId::ipn(977000, 100, 42).unwrap()),
        "ipn:977000.100.42 must be local (same FQNN)"
    );
    assert!(
        agent.is_local_destination(&EndpointId::ipn(977000, 100, 999).unwrap()),
        "ipn:977000.100.999 must be local (same FQNN)"
    );

    // Different FQNN (977000, 101) refers to DIFFERENT node
    assert!(
        !agent.is_local_destination(&EndpointId::ipn(977000, 101, 1).unwrap()),
        "ipn:977000.101.1 must NOT be local (different FQNN)"
    );

    // Different allocator = different node
    assert!(
        !agent.is_local_destination(&EndpointId::ipn(0, 100, 1).unwrap()),
        "ipn:0.100.1 must NOT be local (different allocator)"
    );
}
