use interplanetary_sdk::types::EndpointId;

/// RFC9758-014: SDK MUST parse '!' as 4294967295 (u32::MAX) in node position
#[test]
fn test_rfc9758_014_parse_wildcard_node() {
    // RFC 9758 §4: '!' is shorthand for 4294967295
    let eid = EndpointId::parse("ipn:!.1").unwrap();

    if let EndpointId::Ipn {
        allocator,
        node,
        service,
    } = eid
    {
        assert_eq!(allocator, 0);
        assert_eq!(node, u32::MAX as u64, "! must parse as u32::MAX");
        assert_eq!(service, 1);
    } else {
        panic!("Expected Ipn endpoint");
    }
}

/// RFC9758-014: SDK MUST parse '!' as 4294967295 (u32::MAX) in service position
#[test]
fn test_rfc9758_014_parse_wildcard_service() {
    // RFC 9758 §4: '!' is shorthand for 4294967295
    let eid = EndpointId::parse("ipn:1.!").unwrap();

    if let EndpointId::Ipn {
        allocator,
        node,
        service,
    } = eid
    {
        assert_eq!(allocator, 0);
        assert_eq!(node, 1);
        assert_eq!(service, u32::MAX as u64, "! must parse as u32::MAX");
    } else {
        panic!("Expected Ipn endpoint");
    }
}

/// RFC9758-014: SDK MUST parse '!' in three-element form
#[test]
fn test_rfc9758_014_parse_wildcard_three_element() {
    // RFC 9758 §4: '!' works in all positions
    let eid = EndpointId::parse("ipn:!.!.!").unwrap();

    if let EndpointId::Ipn {
        allocator,
        node,
        service,
    } = eid
    {
        assert_eq!(allocator, u32::MAX as u64, "! must parse as u32::MAX");
        assert_eq!(node, u32::MAX as u64, "! must parse as u32::MAX");
        assert_eq!(service, u32::MAX as u64, "! must parse as u32::MAX");
    } else {
        panic!("Expected Ipn endpoint");
    }
}

/// RFC9758-014: SDK MUST emit '!' when formatting u32::MAX values
#[test]
fn test_rfc9758_014_format_wildcard() {
    // RFC 9758 §4: u32::MAX should be formatted as '!'
    let eid = EndpointId::ipn(0, u32::MAX as u64, 1).unwrap();
    let formatted = format!("{}", eid);
    assert_eq!(formatted, "ipn:!.1", "u32::MAX must be formatted as '!'");
}

/// RFC9758-014: SDK MUST emit '!' for service when formatting
#[test]
fn test_rfc9758_014_format_wildcard_service() {
    // RFC 9758 §4: u32::MAX should be formatted as '!'
    let eid = EndpointId::ipn(0, 1, u32::MAX as u64).unwrap();
    let formatted = format!("{}", eid);
    assert_eq!(formatted, "ipn:1.!", "u32::MAX must be formatted as '!'");
}

/// RFC9758-014: SDK MUST emit '!' for all positions in three-element form
#[test]
fn test_rfc9758_014_format_wildcard_three_element() {
    // RFC 9758 §4: u32::MAX should be formatted as '!'
    let eid = EndpointId::ipn(u32::MAX as u64, u32::MAX as u64, u32::MAX as u64).unwrap();
    let formatted = format!("{}", eid);
    assert_eq!(formatted, "ipn:!.!.!", "u32::MAX must be formatted as '!'");
}

/// RFC9758-014: Roundtrip test - parse '!' and format back to '!'
#[test]
fn test_rfc9758_014_wildcard_roundtrip() {
    // Parse
    let eid = EndpointId::parse("ipn:!.!").unwrap();

    // Format
    let formatted = format!("{}", eid);
    assert_eq!(formatted, "ipn:!.!", "Roundtrip must preserve '!' notation");

    // Parse again
    let eid2 = EndpointId::parse(&formatted).unwrap();
    assert_eq!(eid, eid2, "Roundtrip must produce equivalent endpoint");
}
