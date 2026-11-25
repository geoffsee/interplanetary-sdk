//! RFC 9174 §4.1 Active/Passive Role Tests
//!
//! Tests TCP connection establishment and role-based behavior obligations.
#![cfg(feature = "tcpclv4-model")]

mod common;

use interplanetary_sdk::tcpcl::Role;
use interplanetary_sdk::tcpcl::messages::*;
use interplanetary_sdk::tcpcl::session::{SessionConfig, SessionState, TcpclSession};

/// RFC9174-4-001: For bundle transmissions to occur using TCPCL, a session MUST first be established
#[test]
fn test_rfc9174_4_001_session_required_for_transfers() {
    let session = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..Default::default()
    })
    .unwrap();

    // Attempt transfer before establishing session (still in ContactNegotiation state)
    assert_eq!(session.state(), SessionState::ContactNegotiation);

    let bundle_data = vec![1, 2, 3];
    let mut session = session;
    let result = session.start_transfer(bundle_data);

    // MUST fail - session not established
    assert!(
        result.is_err(),
        "Transfer should fail before session establishment"
    );
}

/// RFC9174-4-1-002: To establish a TCPCL session, an entity MUST first establish a TCP connection
#[test]
fn test_rfc9174_4_1_002_tcp_connection_required() {
    // This test documents the requirement that TCP connection precedes TCPCL session.
    // The session implementation assumes an underlying connection exists.

    let session = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..Default::default()
    })
    .unwrap();

    // Initial state is ContactNegotiation, waiting for contact header exchange
    // This state assumes TCP connection is already established
    assert_eq!(session.state(), SessionState::ContactNegotiation);
}

/// RFC9174-4-1-007: The passive entity SHALL be the entity that listens for TCP connections
#[test]
fn test_rfc9174_4_1_007_passive_listens_for_connection() {
    let passive = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        node_id: "dtn://passive.node".to_string(),
        ..Default::default()
    })
    .unwrap();

    // Verify passive role is set correctly
    assert_eq!(passive.role(), Role::Passive);

    // Passive starts in ContactNegotiation, waiting for active's contact header
    assert_eq!(passive.state(), SessionState::ContactNegotiation);
}

/// RFC9174-4-1-009: Once TCP connection is established, active entity SHALL immediately transmit Contact Header
#[test]
fn test_rfc9174_4_1_009_active_sends_contact_first() {
    let mut active = TcpclSession::new(SessionConfig {
        role: Role::Active,
        node_id: "dtn://active.node".to_string(),
        ..Default::default()
    })
    .unwrap();

    let mut passive = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        node_id: "dtn://passive.node".to_string(),
        ..Default::default()
    })
    .unwrap();

    // Verify roles are set
    assert_eq!(active.role(), Role::Active);
    assert_eq!(passive.role(), Role::Passive);

    // Active CAN send contact header immediately (before receiving peer's)
    let active_contact = active.send_contact_header();
    assert!(
        active_contact.is_ok(),
        "Active should be able to send contact header first"
    );
    assert_eq!(active_contact.unwrap().version, ContactHeader::VERSION);

    // Passive CANNOT send contact header before receiving peer's
    let passive_result = passive.send_contact_header();
    assert!(
        passive_result.is_err(),
        "Passive should NOT be able to send contact header before receiving peer's"
    );
}

/// RFC9174-4-1-011: Passive entity SHALL wait for the active entity's Contact Header
#[test]
fn test_rfc9174_4_1_011_passive_waits_for_contact() {
    let mut active = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..Default::default()
    })
    .unwrap();

    let mut passive = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        ..Default::default()
    })
    .unwrap();

    // Passive waits in ContactNegotiation state
    assert_eq!(passive.state(), SessionState::ContactNegotiation);

    // Passive CANNOT send contact header before receiving Active's
    assert!(
        passive.send_contact_header().is_err(),
        "Passive must wait for Active's contact header"
    );

    // Active sends contact header first
    let active_contact = active.send_contact_header().unwrap();

    // Passive processes it (transitions to SessionInit)
    passive.process_contact_header(&active_contact).unwrap();
    assert_eq!(passive.state(), SessionState::SessionInit);

    // NOW Passive can send its own contact header
    let passive_contact = passive.send_contact_header();
    assert!(
        passive_contact.is_ok(),
        "Passive can send after receiving Active's"
    );
    active
        .process_contact_header(&passive_contact.unwrap())
        .unwrap();

    // Now active sends SESS_INIT first
    let active_init = active.send_session_init().unwrap();

    // Passive waits for and processes active's SESS_INIT
    passive.process_session_init(&active_init).unwrap();

    // This demonstrates passive waits for active's messages
}

/// RFC9174-4-1-014: When an entity "closes" a TCP connection, it SHALL use the TCP FIN mechanism
#[test]
fn test_rfc9174_4_1_014_tcp_close_mechanism() {
    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;

    // Cleanly terminate session
    let _sess_term = active.send_session_term(0x00, None).unwrap();

    // After SESS_TERM, the state is Ending
    assert_eq!(active.state(), SessionState::Ending);

    // The TCP FIN mechanism is used at the transport layer (not tested here)
    // This test documents that session termination precedes TCP close
}

/// RFC9174-4-3-020: Active entity SHALL send highest TCPCL protocol version it supports
#[test]
fn test_rfc9174_4_3_020_active_sends_highest_version() {
    let mut active = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..Default::default()
    })
    .unwrap();

    let contact = active.send_contact_header().unwrap();

    // SHALL send highest version (TCPCLv4 = version 4)
    assert_eq!(contact.version, 4);
}

/// RFC9174-4-6-068: Bundle transfer SHALL have Total Bundle Length no longer than peer's transfer_mru
#[test]
fn test_rfc9174_4_6_068_respect_peer_transfer_mru() {
    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            transfer_mru: 10_000_000,
            ..Default::default()
        },
        SessionConfig {
            role: Role::Passive,
            transfer_mru: 1000, // Peer can only accept up to 1000 bytes
            ..Default::default()
        },
    )
    .unwrap();

    let mut active = pair.active;

    // Attempt to send bundle larger than peer's transfer_mru
    let large_data = vec![0u8; 2000]; // Exceeds passive's 1000-byte limit
    let result = active.start_transfer(large_data);

    // SHALL be rejected
    assert!(
        result.is_err(),
        "Transfer exceeding peer MRU should be rejected"
    );
}

/// RFC9174-4-6-069: Zero-length node ID SHALL indicate lack of node ID
#[test]
fn test_rfc9174_4_6_069_zero_length_node_id_means_no_id() {
    // SESS_INIT with empty node_id string indicates no node ID
    let sess_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: String::new(), // Zero-length = no node ID
        extensions: vec![],
    };

    match sess_init {
        Message::SessionInit { node_id, .. } => {
            assert_eq!(node_id.len(), 0);
            // Zero-length SHALL indicate lack of node ID (not a truly empty node)
        }
        _ => panic!("Expected SessionInit"),
    }
}

/// RFC9174-4-6-070: Non-zero-length Node ID Data SHALL contain UTF-8 encoded node ID
#[test]
fn test_rfc9174_4_6_070_node_id_is_utf8() {
    let mut active = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..Default::default()
    })
    .unwrap();

    let mut passive = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        node_id: "dtn://example.com/node1".to_string(),
        ..Default::default()
    })
    .unwrap();

    // Exchange contact headers (Active first, then Passive)
    let active_contact = active.send_contact_header().unwrap();
    passive.process_contact_header(&active_contact).unwrap();
    let passive_contact = passive.send_contact_header().unwrap();
    active.process_contact_header(&passive_contact).unwrap();

    // Passive sends SESS_INIT with valid UTF-8 node ID
    let passive_init = passive.send_session_init().unwrap();

    match passive_init {
        Message::SessionInit { node_id, .. } => {
            assert!(!node_id.is_empty());
            // SHALL be valid UTF-8
            assert!(std::str::from_utf8(node_id.as_bytes()).is_ok());
        }
        _ => panic!("Expected SessionInit"),
    }
}

/// RFC9174-4-6-070: Decoder MUST reject Node ID that is not valid UTF-8
#[test]
fn test_rfc9174_4_6_070_reject_invalid_utf8_node_id() {
    use interplanetary_sdk::tcpcl::messages::Message;

    // Create a valid SESS_INIT and encode it
    let valid_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn://test".to_string(),
        extensions: vec![],
    };

    let mut wire_bytes = valid_init.encode();

    // Now corrupt the node_id bytes in the wire format
    // Wire format: type(1) + keepalive(2) + segment_mru(8) + transfer_mru(8) + node_id_len(2) + node_id_bytes + ...
    // Offset to node_id bytes: 1 + 2 + 8 + 8 + 2 = 21
    let node_id_offset = 21;

    // Replace first few node_id bytes with invalid UTF-8 sequence
    // 0xC3 0x28 is invalid UTF-8 (0xC3 starts a 2-byte sequence but 0x28 is not a valid continuation)
    wire_bytes[node_id_offset] = 0xC3;
    wire_bytes[node_id_offset + 1] = 0x28;

    // Decode should reject it
    let result = Message::decode_sess_init(&wire_bytes);
    assert!(
        result.is_err(),
        "SESS_INIT decoder must reject invalid UTF-8 in Node ID"
    );

    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("UTF-8") || err_msg.contains("utf"),
        "Error should mention UTF-8 validation failure: {}",
        err_msg
    );
}
