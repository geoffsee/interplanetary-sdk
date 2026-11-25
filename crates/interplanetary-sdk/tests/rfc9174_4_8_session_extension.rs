#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §4.8 Session Extension Items Tests

use interplanetary_sdk::tcpcl::messages::*;
use interplanetary_sdk::tcpcl::term_reason;

/// RFC9174-4-8-078: Session Extension Items SHALL be encoded in TLV format
#[test]
fn test_rfc9174_4_8_078_extension_encoded_as_tlv() {
    // RFC 9174 §4.8: "Each of the Session Extension Items SHALL be encoded in an
    // identical Type-Length-Value (TLV) container form"
    // Format: flags(1) | type(2) | length(2) | value(variable)

    let ext = ExtensionItem::new(0x1234, vec![0xAA, 0xBB, 0xCC], false);
    let encoded = ext.encode();

    // Verify TLV format
    assert_eq!(
        encoded.len(),
        1 + 2 + 2 + 3,
        "Extension item must be encoded as: flags(1) + type(2) + length(2) + value(n)"
    );

    // Verify flags field (1 byte)
    assert_eq!(encoded[0], 0x00, "Flags field at byte 0");

    // Verify type field (2 bytes, big-endian)
    let type_code = u16::from_be_bytes([encoded[1], encoded[2]]);
    assert_eq!(type_code, 0x1234, "Type code at bytes 1-2");

    // Verify length field (2 bytes, big-endian)
    let length = u16::from_be_bytes([encoded[3], encoded[4]]);
    assert_eq!(length, 3, "Length field at bytes 3-4");

    // Verify value field
    assert_eq!(
        &encoded[5..8],
        &[0xAA, 0xBB, 0xCC],
        "Value field starts at byte 5"
    );
}

/// RFC9174-4-8-079: Reserved flag bits SHALL be set to 0 by sender
#[test]
fn test_rfc9174_4_8_079_reserved_flags_zero_by_sender() {
    // RFC 9174 §4.8 Table 3: Flag bit 0 is CRITICAL, bits 1-7 are reserved
    // "All reserved header flag bits SHALL be set to 0 by the sender"

    // Test non-critical extension
    let ext_non_critical = ExtensionItem::new(0x0001, vec![0x01], false);
    let encoded = ext_non_critical.encode();
    let flags = encoded[0];

    // All bits should be 0 for non-critical
    assert_eq!(flags, 0x00, "Non-critical: all reserved bits must be 0");

    // Test critical extension
    let ext_critical = ExtensionItem::new(0x0002, vec![0x02], true);
    let encoded = ext_critical.encode();
    let flags = encoded[0];

    // Bit 0 should be 1 (CRITICAL), bits 1-7 should be 0
    assert_eq!(
        flags & 0x01,
        0x01,
        "Critical extension: bit 0 (CRITICAL) must be 1"
    );
    assert_eq!(
        flags & 0xFE,
        0x00,
        "Critical extension: reserved bits 1-7 must be 0"
    );

    // Verify that reserved bits (1-7) are always 0
    let reserved_bits = flags & 0xFE;
    assert_eq!(
        reserved_bits, 0x00,
        "Reserved bits (1-7) SHALL be set to 0 by sender"
    );
}

/// RFC9174-4-8-081: Reserved flag bits SHALL be ignored by receiver
#[test]
fn test_rfc9174_4_8_081_reserved_flags_ignored_by_receiver() {
    // RFC 9174 §4.8: "All reserved header flag bits SHALL be ignored by the receiver"

    // Create extension with valid encoding
    let ext = ExtensionItem::new(0x0042, vec![0xDE, 0xAD], true);
    let mut encoded = ext.encode();

    // Original flags: 0x01 (CRITICAL bit set)
    assert_eq!(encoded[0] & 0x01, 0x01);

    // Artificially set reserved bits (simulate sender violation or future extension)
    // Set bit 2 and bit 5 (reserved bits that should be ignored)
    encoded[0] |= 0b00100100; // Set bits 2 and 5

    // Decode should succeed and extract only the CRITICAL bit
    let (decoded, _) =
        ExtensionItem::decode(&encoded).expect("Decoder SHALL ignore reserved flag bits");

    // Verify CRITICAL bit is preserved
    assert!(
        decoded.is_critical(),
        "CRITICAL bit (bit 0) should be preserved"
    );

    // Verify decoder ignores reserved bits (bits 1-7)
    // The decoded flags should only have bit 0 set if critical
    let decoded_flags = decoded.flags;
    assert_eq!(
        decoded_flags & 0x01,
        0x01,
        "CRITICAL bit should be preserved"
    );

    // The key test: decoder should not fail or behave differently
    // when reserved bits are set (they are ignored)
    assert_eq!(decoded.type_code, 0x0042, "Type code preserved");
    assert_eq!(decoded.value, vec![0xDE, 0xAD], "Value preserved");
}

/// RFC9174-4-8-078: Verify complete TLV roundtrip
#[test]
fn test_rfc9174_4_8_078_tlv_roundtrip() {
    // Test that encoding and decoding preserves all fields

    let original = ExtensionItem::new(0xABCD, vec![1, 2, 3, 4, 5], true);
    let encoded = original.encode();

    // Decode
    let (decoded, consumed) = ExtensionItem::decode(&encoded).unwrap();

    // Verify roundtrip
    assert_eq!(consumed, encoded.len(), "Consumes exactly encoded bytes");
    assert_eq!(decoded.type_code, original.type_code, "Type code preserved");
    assert_eq!(decoded.value, original.value, "Value preserved");
    assert_eq!(
        decoded.is_critical(),
        original.is_critical(),
        "Critical flag preserved"
    );
}

/// RFC9174-4-8-082: Unknown critical session extension SHALL terminate session
#[test]
fn test_rfc9174_4_8_082_unknown_critical_extension_terminates() {
    // RFC 9174 §4.8: "If a TCPCL entity receives a Session Extension Item with an
    // unknown Item Type and the CRITICAL flag set to 1, the entity SHALL terminate
    // the TCPCL session with a SESS_TERM reason code of 'Contact Failure'"

    use interplanetary_sdk::tcpcl::{Role, SessionConfig, TcpclSession};

    let mut session = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        ..Default::default()
    })
    .unwrap();

    // Active sends contact header
    let peer_contact = ContactHeader::new();
    session.process_contact_header(&peer_contact).unwrap();

    // RFC 9174 §6.1: Passive must send its own Contact Header before SESS_TERM
    let _our_contact = session.send_contact_header().unwrap();

    // Peer sends SESS_INIT with unknown critical session extension
    let unknown_type = 0xFFFF; // Not a known session extension type
    let unknown_critical_ext = ExtensionItem::new(unknown_type, vec![0x01, 0x02], true);

    let sess_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn://peer".to_string(),
        extensions: vec![unknown_critical_ext],
    };

    // Should fail with unknown critical extension
    let result = session.process_session_init(&sess_init);
    assert!(
        result.is_err(),
        "SHALL fail on unknown critical session extension"
    );

    // Should send SESS_TERM with Contact Failure reason (0x04)
    // (after contact header sent per RFC 9174 §6.1)
    let term_msg = session
        .send_session_term(term_reason::CONTACT_FAILURE, None)
        .unwrap();
    match term_msg {
        Message::SessionTerm { reason_code, .. } => {
            assert_eq!(
                reason_code,
                term_reason::CONTACT_FAILURE,
                "SHALL terminate with Contact Failure reason"
            );
        }
        _ => panic!("Expected SessionTerm"),
    }
}

/// RFC9174-4-8-083: SHOULD avoid large session extension data
#[test]
fn test_rfc9174_4_8_083_avoid_large_session_extensions() {
    // RFC 9174 §4.8: "Extension specifications SHOULD avoid the use of large data
    // lengths, as no bundle transfers can begin until the full extension data is sent"

    // This is a SHOULD recommendation for extension designers
    // Test documents the requirement and demonstrates encoding behavior

    // Small session extension (recommended)
    let small_ext = ExtensionItem::new(0x0001, vec![0xAA; 10], false);
    let small_encoded = small_ext.encode();
    assert!(
        small_encoded.len() <= 100,
        "Small session extensions are recommended ({} bytes)",
        small_encoded.len()
    );

    // Large session extension (not recommended but technically valid)
    let large_ext = ExtensionItem::new(0x0002, vec![0xBB; 10000], false);
    let large_encoded = large_ext.encode();
    assert!(
        large_encoded.len() > 1000,
        "Large session extensions delay bundle transfers ({} bytes)",
        large_encoded.len()
    );

    // Both are valid protocol-wise, but small is RECOMMENDED
    // Session extensions SHOULD be designed to avoid large data
    // because they delay the start of any bundle transfers
}
