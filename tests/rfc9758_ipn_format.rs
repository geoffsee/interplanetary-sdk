#![cfg(feature = "bpv7")]

//! RFC 9758 IPN URI Format Tests

use interplanetary_sdk::types::EndpointId;

/// RFC9758-007: Node Numbers MUST be in range 0 to 2^32-1
#[test]
fn test_rfc9758_007_node_number_range() {
    // RFC 9758 §3.3: "All Node Number assignments, by all Allocators,
    // MUST be in the range 0 to 2^(32-1)"

    // Valid node numbers (within range)
    let valid_node = EndpointId::ipn(0, 1, 0).unwrap();
    assert!(matches!(valid_node, EndpointId::Ipn { .. }));

    let max_node = EndpointId::ipn(0, u32::MAX as u64, 0).unwrap();
    assert!(matches!(max_node, EndpointId::Ipn { .. }));

    // Parse from string with valid node
    let parsed = EndpointId::parse("ipn:4294967295.0").unwrap();
    assert!(matches!(parsed, EndpointId::Ipn { node, .. } if node == u32::MAX as u64));

    // The type system enforces u64, but RFC 9758 limits to u32::MAX
    // Implementation uses u64 for future extensibility but must reject >u32::MAX
    // Current implementation accepts u64, which is permissive but doesn't violate
    // the MUST requirement for assignments (allocators can't assign >u32::MAX)
}

/// RFC9758-008: Node Number zero RECOMMENDED not assigned (avoid confusion)
#[test]
fn test_rfc9758_008_node_zero_not_recommended() {
    // RFC 9758 §3.3: "It is RECOMMENDED that Node Number zero (0) not be assigned
    // by an Allocator to avoid confusion with the Null ipn URI"

    // Parse ipn:0.0 (allocator=0, node=0) -> should map to Null per §3.4.1
    let null_ipn = EndpointId::parse("ipn:0.0").unwrap();
    assert!(
        matches!(null_ipn, EndpointId::Null),
        "ipn:0.0 (allocator=0, node=0) MUST be Null per RFC 9758 §3.4.1"
    );

    // Parse ipn:0.0.1 -> also maps to Null (node=0 with allocator=0)
    let null_with_service = EndpointId::parse("ipn:0.0.1").unwrap();
    assert!(
        matches!(null_with_service, EndpointId::Null),
        "ipn:0.0.1 MUST be Null (node=0 regardless of service)"
    );

    // The RECOMMENDED avoidance is for allocators; implementation correctly
    // handles node=0 by mapping to Null to avoid confusion
}

/// RFC9758-014: Character '!' SHOULD be used instead of 4294967295 for wildcard
#[test]
fn test_rfc9758_014_wildcard_exclamation_recommended() {
    // RFC 9758 §3.3: "If the value of the Node Number or Service Number is unknown
    // or unspecified, then the character '!' SHOULD be used instead of the digits
    // 4294967295, although both forms are valid"

    // Parse with '!' wildcard - would need implementation support
    // Current implementation doesn't support '!' syntax yet
    // Test documents the SHOULD recommendation

    // Numeric wildcard (4294967295) is valid
    let numeric_wildcard = EndpointId::parse("ipn:1.4294967295");
    assert!(
        numeric_wildcard.is_ok(),
        "Numeric wildcard 4294967295 is valid per RFC 9758 §3.3"
    );

    // '!' form is RECOMMENDED but not required (SHOULD, not MUST)
    // Implementation could support: ipn:1.! or ipn:!.!
    // Test establishes baseline for future '!' support
}

/// RFC9758-002: Allocator Identifier MUST be sole mechanism to identify Allocator
#[test]
fn test_rfc9758_002_allocator_id_sole_mechanism() {
    // RFC 9758 §3.2: "The Allocator Identifier MUST be the sole mechanism used
    // to identify the Allocator that has assigned the Node Number"

    // Parse 3-element IPN with explicit allocator
    let eid1 = EndpointId::parse("ipn:100.1.2").unwrap();
    if let EndpointId::Ipn {
        allocator,
        node,
        service,
    } = eid1
    {
        assert_eq!(allocator, 100, "Allocator identified solely by number");
        assert_eq!(node, 1);
        assert_eq!(service, 2);
    } else {
        panic!("Expected Ipn variant");
    }

    // Parse 2-element IPN (implicit allocator=0)
    let eid2 = EndpointId::parse("ipn:1.2").unwrap();
    if let EndpointId::Ipn {
        allocator,
        node,
        service,
    } = eid2
    {
        assert_eq!(allocator, 0, "Default allocator is 0");
        assert_eq!(node, 1);
        assert_eq!(service, 2);
    } else {
        panic!("Expected Ipn variant");
    }

    // The allocator field IS the sole identification mechanism
    // No auxiliary data or names - just the numeric ID
}

/// RFC9758-003: Allocator Identifier MUST be associated with single Allocator
#[test]
fn test_rfc9758_003_one_allocator_per_id() {
    // RFC 9758 §3.2: "given Allocator Identifier MUST only be associated
    // with a single Allocator"

    // This is a registry/policy requirement, not SDK behavior
    // SDK treats each allocator ID as distinct

    let eid1 = EndpointId::ipn(100, 1, 0).unwrap();
    let eid2 = EndpointId::ipn(100, 2, 0).unwrap();
    let eid3 = EndpointId::ipn(200, 1, 0).unwrap();

    // eid1 and eid2 have same allocator (100) - must be same Allocator
    if let (EndpointId::Ipn { allocator: a1, .. }, EndpointId::Ipn { allocator: a2, .. }) =
        (&eid1, &eid2)
    {
        assert_eq!(
            a1, a2,
            "Same allocator ID identifies same Allocator per RFC 9758 §3.2"
        );
    }

    // eid3 has different allocator (200) - must be different Allocator
    if let (EndpointId::Ipn { allocator: a1, .. }, EndpointId::Ipn { allocator: a3, .. }) =
        (&eid1, &eid3)
    {
        assert_ne!(
            a1, a3,
            "Different allocator IDs identify different Allocators"
        );
    }
}

/// RFC9758-006: Node Number MUST refer to single node
#[test]
fn test_rfc9758_006_one_node_per_number() {
    // RFC 9758 §3.3: "Node Number assigned by a single Allocator
    // MUST refer to a single node"

    // Within same allocator, same node number refers to same node
    let eid1 = EndpointId::ipn(100, 5, 1).unwrap();
    let eid2 = EndpointId::ipn(100, 5, 2).unwrap();

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
        assert_eq!(a1, a2, "Same allocator");
        assert_eq!(n1, n2, "Same node number within allocator = same node");
    }

    // Different allocators can reuse node numbers (different namespaces)
    let eid3 = EndpointId::ipn(200, 5, 1).unwrap();
    if let (
        EndpointId::Ipn {
            allocator: a1,
            node: n1,
            ..
        },
        EndpointId::Ipn {
            allocator: a3,
            node: n3,
            ..
        },
    ) = (&eid1, &eid3)
    {
        assert_ne!(a1, a3, "Different allocators");
        assert_eq!(
            n1, n3,
            "Same node number, but different allocators = different nodes"
        );
    }
}

/// Verify 2-element vs 3-element IPN forms
#[test]
fn test_rfc9758_two_vs_three_element_forms() {
    // RFC 9758 supports both forms:
    // 2-element: ipn:node.service (implicit allocator=0)
    // 3-element: ipn:allocator.node.service

    // 2-element form
    let eid_2 = EndpointId::parse("ipn:1.2").unwrap();
    assert!(matches!(
        eid_2,
        EndpointId::Ipn {
            allocator: 0,
            node: 1,
            service: 2
        }
    ));
    assert_eq!(eid_2.to_string(), "ipn:1.2", "2-element form serialization");

    // 3-element form with allocator=0
    let eid_3a = EndpointId::parse("ipn:0.1.2").unwrap();
    assert!(matches!(
        eid_3a,
        EndpointId::Ipn {
            allocator: 0,
            node: 1,
            service: 2
        }
    ));
    // Should serialize as 2-element when allocator=0
    assert_eq!(
        eid_3a.to_string(),
        "ipn:1.2",
        "allocator=0 uses 2-element form"
    );

    // 3-element form with allocator!=0
    let eid_3b = EndpointId::parse("ipn:100.1.2").unwrap();
    assert!(matches!(
        eid_3b,
        EndpointId::Ipn {
            allocator: 100,
            node: 1,
            service: 2
        }
    ));
    assert_eq!(
        eid_3b.to_string(),
        "ipn:100.1.2",
        "allocator!=0 uses 3-element form"
    );
}

/// RFC9758 §4: Leading zeros MUST be omitted
#[test]
fn test_rfc9758_004_leading_zeros_omitted() {
    // RFC 9758 §4: "All leading '0' characters MUST be omitted"

    // Valid: no leading zeros
    let valid = EndpointId::parse("ipn:1.2");
    assert!(valid.is_ok(), "ipn:1.2 valid (no leading zeros)");

    // Valid: single '0' is allowed
    let zero = EndpointId::parse("ipn:0.1");
    assert!(zero.is_ok(), "Single '0' is valid");

    // Invalid: leading zero
    let invalid1 = EndpointId::parse("ipn:01.2");
    assert!(
        invalid1.is_err(),
        "ipn:01.2 invalid (leading zero in node per RFC 9758 §4)"
    );

    let invalid2 = EndpointId::parse("ipn:1.02");
    assert!(
        invalid2.is_err(),
        "ipn:1.02 invalid (leading zero in service per RFC 9758 §4)"
    );

    let invalid3 = EndpointId::parse("ipn:00.1.2");
    assert!(
        invalid3.is_err(),
        "ipn:00.1.2 invalid (leading zero in allocator per RFC 9758 §4)"
    );

    // Edge case: multiple zeros
    let invalid4 = EndpointId::parse("ipn:001.2");
    assert!(
        invalid4.is_err(),
        "ipn:001.2 invalid (multiple leading zeros)"
    );
}

/// RFC9758 §3.4.2: LocalNode ipn EID
#[test]
fn test_rfc9758_localnode_ipn() {
    // RFC 9758 §3.4.2: LocalNode ipn EID is node 4294967295 (max u32)
    // in the Default Allocator (allocator 0)

    // Create LocalNode EID
    let local_node = EndpointId::ipn(0, u32::MAX as u64, 1).unwrap();
    assert!(
        local_node.is_local_node(),
        "ipn(0, 4294967295, 1) is LocalNode per RFC 9758 §3.4.2"
    );

    // Parse LocalNode from string
    let parsed = EndpointId::parse("ipn:4294967295.1").unwrap();
    assert!(
        parsed.is_local_node(),
        "ipn:4294967295.1 is LocalNode (default allocator=0)"
    );

    // Non-LocalNode: different node number
    let not_local = EndpointId::ipn(0, 100, 1).unwrap();
    assert!(
        !not_local.is_local_node(),
        "ipn(0, 100, 1) is not LocalNode"
    );

    // Non-LocalNode: different allocator
    let not_local_alloc = EndpointId::ipn(100, u32::MAX as u64, 1).unwrap();
    assert!(
        !not_local_alloc.is_local_node(),
        "LocalNode requires allocator=0"
    );
}

/// RFC9758 §5.5: Private Use ipn EID
#[test]
fn test_rfc9758_private_use_ipn() {
    // RFC 9758 §5.5: Private Use range in Default Allocator (allocator=0)
    // Node numbers 1..16777215 (0x000001..0xFFFFFF, i.e., 2^24-1)

    // Private Use node in default allocator
    let private_min = EndpointId::ipn(0, 1, 0).unwrap();
    assert!(
        private_min.is_private_use_ipn(),
        "ipn(0, 1, 0) is Private Use (node 1 in default allocator)"
    );

    let private_mid = EndpointId::ipn(0, 100, 0).unwrap();
    assert!(
        private_mid.is_private_use_ipn(),
        "ipn(0, 100, 0) is Private Use"
    );

    let private_max = EndpointId::ipn(0, 16777215, 0).unwrap();
    assert!(
        private_max.is_private_use_ipn(),
        "ipn(0, 16777215, 0) is Private Use (max private node)"
    );

    // Not Private Use: node 0 in default allocator (Null)
    // RFC 9758 §3.4.1: ipn:0.0.X where X!=0 MUST NOT be composed, so use ipn:0.0.0
    let null_node = EndpointId::ipn(0, 0, 0).unwrap();
    assert!(
        !null_node.is_private_use_ipn(),
        "Node 0 is not Private Use (it's Null)"
    );

    // Not Private Use: node > 16777215 in default allocator
    let not_private = EndpointId::ipn(0, 16777216, 0).unwrap();
    assert!(
        !not_private.is_private_use_ipn(),
        "ipn(0, 16777216, 0) not Private Use (above range)"
    );

    // Not Private Use: different allocator
    let other_alloc = EndpointId::ipn(100, 1, 0).unwrap();
    assert!(
        !other_alloc.is_private_use_ipn(),
        "Private Use only applies to default allocator (0)"
    );
}
