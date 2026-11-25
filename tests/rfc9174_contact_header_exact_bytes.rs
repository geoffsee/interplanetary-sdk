//! RFC 9174 §4.2 Contact Header Exact Byte Validation
//!
//! Tests verify exact byte sequences emitted by TcpclSession for contact headers,
//! including magic, version, and flags per RFC 9174 §4.2.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §4.2: Contact Header magic string exact bytes
///
/// "Contact Header Magic: The Contact Header starts with a four-octet field
/// that always contains the octet sequence 0x64 0x74 0x6E 0x21, i.e., the
/// text string 'dtn!' in US-ASCII (and UTF-8)."
///
/// This test drives TcpclSession to emit a contact header and verifies the exact bytes.
#[test]
fn test_contact_header_magic_bytes_0x64_0x74_0x6e_0x21() {
    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn:test".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Active session sends contact header first
    let header = session.send_contact_header().unwrap();
    let bytes = header.encode();

    // RFC 9174 §4.2: Contact header SHALL be exactly 6 bytes (magic + version + flags)
    assert_eq!(bytes.len(), 6, "Contact header must be exactly 6 bytes");

    // RFC 9174 §4.2: Magic bytes SHALL be 0x64 0x74 0x6E 0x21 ('dtn!')
    assert_eq!(bytes[0], 0x64, "Magic byte 0 must be 0x64");
    assert_eq!(bytes[1], 0x74, "Magic byte 1 must be 0x74");
    assert_eq!(bytes[2], 0x6E, "Magic byte 2 must be 0x6E");
    assert_eq!(bytes[3], 0x21, "Magic byte 3 must be 0x21");

    // Also check as a slice for clarity
    assert_eq!(
        &bytes[0..4],
        &[0x64, 0x74, 0x6E, 0x21],
        "Magic must be 'dtn!' (0x64 0x74 0x6E 0x21)"
    );
}

/// RFC 9174 §4.2: Contact Header version field exact byte
///
/// "Version: A one-octet field value that is the binary representation of the
/// version of the TCPCL protocol. This document defines version 4."
///
/// This test verifies TCPCLv4 emits version byte 0x04.
#[test]
fn test_contact_header_version_byte_0x04() {
    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn:test".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();
    let header = session.send_contact_header().unwrap();
    let bytes = header.encode();

    // RFC 9174 §4.2: Version byte SHALL be 4 for TCPCLv4
    assert_eq!(
        bytes[4], 0x04,
        "Version byte must be 0x04 (decimal 4) for TCPCLv4"
    );
}

/// RFC 9174 §4.2: Contact Header flags field exact byte
///
/// "Flags: A one-octet field containing optional connection flags."
/// "CAN_TLS (0x01): Indicates that the sending peer has enabled TLS security."
///
/// This test verifies the flags byte is 0x00 when TLS is not enabled.
#[test]
fn test_contact_header_flags_byte_0x00_when_no_tls() {
    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn:test".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();
    let header = session.send_contact_header().unwrap();
    let bytes = header.encode();

    // RFC 9174 §4.2: Flags byte SHALL be 0x00 when no flags are set
    assert_eq!(bytes[5], 0x00, "Flags byte must be 0x00 when no flags set");
}

/// RFC 9174 §4.3: Invalid magic string rejection
///
/// "If the "magic string" is not present or is not valid, the connection
/// MUST be terminated."
///
/// This test verifies TcpclSession rejects contact headers with invalid magic.
#[test]
fn test_contact_header_invalid_magic_rejected() {
    let config = SessionConfig {
        role: Role::Passive,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn:test".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let _session = TcpclSession::new(config).unwrap();

    // Create contact header with wrong magic
    let mut invalid_bytes = vec![0x64, 0x74, 0x6E, 0x22]; // Last byte wrong (0x22 instead of 0x21)
    invalid_bytes.push(0x04); // version
    invalid_bytes.push(0x00); // flags

    let result = ContactHeader::decode(&invalid_bytes);

    // RFC 9174 §4.3: Invalid magic MUST cause rejection
    assert!(result.is_err(), "Invalid magic must be rejected");
    assert!(
        result.unwrap_err().contains("Invalid magic"),
        "Error must mention invalid magic"
    );
}

/// RFC 9174 §4.3: Version mismatch rejection
///
/// "If the passive entity receives a Contact Header containing a version that
/// is not a version of the protocol that the passive entity implements, then
/// the passive entity MUST close the TCP connection."
///
/// This test verifies TcpclSession rejects contact headers with wrong version.
#[test]
fn test_contact_header_version_mismatch_rejected() {
    let config = SessionConfig {
        role: Role::Passive,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn:test".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Create contact header with wrong version (3 instead of 4)
    let header_v3 = ContactHeader {
        version: 3,
        flags: 0,
    };

    // RFC 9174 §4.3: Wrong version MUST cause rejection
    let result = session.process_contact_header(&header_v3);
    assert!(result.is_err(), "Version mismatch must be rejected");
}

/// RFC 9174 §4.2: Complete contact header byte sequence
///
/// This test verifies the complete 6-byte sequence for a contact header
/// with no TLS: magic(4) + version(1) + flags(1) = 0x64 0x74 0x6E 0x21 0x04 0x00
#[test]
fn test_contact_header_complete_6_byte_sequence_no_tls() {
    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn:test".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();
    let header = session.send_contact_header().unwrap();
    let bytes = header.encode();

    // RFC 9174 §4.2: Complete sequence for TCPCLv4 with no TLS
    let expected = vec![0x64, 0x74, 0x6E, 0x21, 0x04, 0x00];
    assert_eq!(
        bytes, expected,
        "Contact header must be exactly [0x64, 0x74, 0x6E, 0x21, 0x04, 0x00] for TCPCLv4 with no TLS"
    );
}
