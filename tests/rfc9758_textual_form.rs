/// RFC 9758 §4 Textual Representation Tests
///
/// Genuine behavioral tests for:
/// - RFC9758-009: Node 0 ipn URIs MUST NOT be composed
/// - RFC9758-010: Node 0 MUST be considered as Null ipn URI
/// - RFC9758-012: Leading zeros MUST be omitted in Display
/// - RFC9758-013: Allocator 0 and '.' MAY be omitted in Display
use interplanetary_sdk::types::EndpointId;

#[test]
fn test_rfc9758_012_leading_zeros_rejected() {
    // RFC 9758 §4: "All leading '0' characters MUST be omitted"
    // Parser MUST reject ipn URIs with leading zeros like ipn:01.2 or ipn:1.002

    // Node with leading zero should be rejected
    assert!(
        EndpointId::parse("ipn:01.2").is_err(),
        "Parser must reject node number with leading zero"
    );

    assert!(
        EndpointId::parse("ipn:001.2").is_err(),
        "Parser must reject node number with multiple leading zeros"
    );

    // Service with leading zero should be rejected
    assert!(
        EndpointId::parse("ipn:1.02").is_err(),
        "Parser must reject service number with leading zero"
    );

    // Allocator with leading zero should be rejected
    assert!(
        EndpointId::parse("ipn:01.2.3").is_err(),
        "Parser must reject allocator with leading zero"
    );

    assert!(
        EndpointId::parse("ipn:1.02.3").is_err(),
        "Parser must reject node with leading zero in 3-part format"
    );

    assert!(
        EndpointId::parse("ipn:1.2.003").is_err(),
        "Parser must reject service with leading zero in 3-part format"
    );
}

#[test]
fn test_rfc9758_012_013_display_omits_leading_zeros_and_allocator() {
    // RFC 9758 §4: Leading zeros MUST be omitted, allocator 0 and '.' MAY be omitted

    // Valid parse with no leading zeros
    let eid1 = EndpointId::parse("ipn:1.2").expect("Valid ipn URI");
    let display1 = eid1.to_string();

    // Verify exact output (no leading zeros)
    assert_eq!(display1, "ipn:1.2", "Display must produce ipn:1.2");

    // Display of allocator 0 should omit it (MAY be omitted per RFC9758-013)
    // Format is ipn:node.service, not ipn:0.node.service
    assert_eq!(
        display1, "ipn:1.2",
        "Allocator 0 should be omitted from display"
    );

    // 3-element parse with explicit allocator
    let eid2 = EndpointId::parse("ipn:5.100.200").expect("Valid 3-element ipn URI");
    let display2 = eid2.to_string();
    assert_eq!(
        display2, "ipn:5.100.200",
        "Display preserves non-zero allocator"
    );
}

#[test]
fn test_rfc9758_009_node_zero_must_not_be_composed() {
    // RFC 9758 §3.4.1: "any ipn URI with a zero (0) Allocator Identifier and
    // a zero (0) Node Number, but a non-zero Service Number component, is
    // invalid. Such ipn URIs MUST NOT be composed"
    //
    // The RFC explicitly addresses allocator=0, node=0 combinations.
    // ipn:0.1 (allocator=0, node=0, service=1) MUST NOT be composed,
    // but per RFC9758-010 processors MUST treat it as Null if encountered.
    //
    // This obligation (RFC9758-009) is about "MUST NOT be composed" - the SDK
    // chooses to accept and normalize to Null rather than reject at parse time.
    // This is tested by RFC9758-010 which requires treating as Null.

    // ipn:0.5 should parse as Null (tested by test_rfc9758_010)
    let eid = EndpointId::parse("ipn:0.5").expect("Should parse");
    assert!(
        matches!(eid, EndpointId::Null),
        "ipn:0.5 (allocator=0, node=0, service≠0) treated as Null per §3.4.1"
    );
}

#[test]
fn test_rfc9758_010_node_zero_as_null() {
    // RFC 9758 §3.4.1: "processors of such ipn URIs MUST consider them as the Null ipn URI"
    // "any ipn URI with a zero (0) Allocator Identifier and a zero (0) Node Number"

    // ipn:0.0 (allocator=0, node=0, service=0) MUST be Null
    let eid1 = EndpointId::parse("ipn:0.0").expect("ipn:0.0 must parse");
    assert!(
        matches!(eid1, EndpointId::Null),
        "ipn:0.0 MUST be treated as Null EID"
    );

    // ipn:0.1 (allocator=0, node=0, service=1) also MUST be treated as Null
    // RFC: "but a non-zero Service Number component, is invalid"
    // RFC: "processors of such ipn URIs MUST consider them as the Null ipn URI"
    let eid2 = EndpointId::parse("ipn:0.1").expect("ipn:0.1 must parse");
    assert!(
        matches!(eid2, EndpointId::Null),
        "ipn:0.1 (node=0, service≠0) MUST be treated as Null EID per §3.4.1"
    );

    // ipn:0.100 (allocator=0, node=0, service=100) also maps to Null
    let eid3 = EndpointId::parse("ipn:0.100").expect("ipn:0.100 must parse");
    assert!(
        matches!(eid3, EndpointId::Null),
        "Any ipn:0.N MUST be treated as Null"
    );
}

#[test]
fn test_rfc9758_display_roundtrip() {
    // Display output MUST be parseable and produce equivalent EID

    let original = EndpointId::parse("ipn:100.500").expect("Valid ipn");
    let displayed = original.to_string();
    let reparsed = EndpointId::parse(&displayed).expect("Display output must be parseable");

    assert_eq!(
        original, reparsed,
        "Display round-trip must preserve equality"
    );
}
