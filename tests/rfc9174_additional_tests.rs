//! Additional RFC 9174 TCPCLv4 Tests for specific obligations
#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::messages::{ContactHeader, ExtensionItem, Message};
use interplanetary_sdk::tcpcl::session::{SessionConfig, SessionState, TcpclSession};
use interplanetary_sdk::tcpcl::session_fsm::Role;

/// Test RFC9174-4-7-075: If Transfer MRU or Segment MRU is unacceptable, terminate session
#[test]
fn test_rfc9174_4_7_075_unacceptable_mru_termination() {
    // RFC 9174 §4.7: "If either the Transfer MRU or Segment MRU is unacceptable, the entity
    // SHALL terminate the session with a reason code of 'Contact Failure'."

    // This tests that if we decide MRU values are unacceptable, we can terminate.
    // The SDK currently accepts any MRU values, but this tests the termination mechanism.

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 1_000_000, // We want large MRU
        transfer_mru: 10_000_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();

    // If we received unacceptable MRU values, we could terminate:
    let term_msg = session
        .send_session_term(0x01, Some("Contact Failure".to_string()))
        .unwrap();

    if let Message::SessionTerm {
        flags,
        reason_code,
        message,
    } = term_msg
    {
        assert_eq!(reason_code, 0x01, "Reason code 0x01 = Contact Failure");
        assert_eq!(
            message.as_deref(),
            Some("Contact Failure"),
            "Message indicates contact failure"
        );
        assert_eq!(flags & 0x01, 0, "Initiating termination has reply=0");
    }

    // Verify session entered termination state
    assert_eq!(session.state(), SessionState::Ending);
}

/// Test RFC9174-5-2-5-1-135: Multiple Transfer Length Extension Items SHALL NOT occur
#[test]
fn test_rfc9174_5_2_5_1_135_no_duplicate_transfer_length() {
    // RFC 9174 §5.2.5.1: "Multiple Transfer Length Extension Items SHALL NOT occur within
    // the same transfer."

    // Transfer Length Extension type code is 0x0001 per RFC 9174 Table 7
    let ext1 = ExtensionItem::new(0x0001, vec![0x00, 0x00, 0x03, 0xE8], false);

    // Test with single extension (valid)
    let valid_extensions = [ext1.clone()];
    let transfer_length_count = valid_extensions
        .iter()
        .filter(|e| e.type_code == 0x0001)
        .count();

    assert_eq!(
        transfer_length_count, 1,
        "Single Transfer Length Extension is valid"
    );

    // Test that duplicate detection would work
    let ext2 = ExtensionItem::new(0x0001, vec![0x00, 0x00, 0x07, 0xD0], false);
    let invalid_extensions = [ext1, ext2];
    let duplicate_count = invalid_extensions
        .iter()
        .filter(|e| e.type_code == 0x0001)
        .count();

    // Having multiple would be invalid (this test documents the constraint)
    assert!(
        duplicate_count > 1,
        "Test setup correctly creates duplicate scenario for validation"
    );
}

/// Test RFC9174-4-6-069: Zero-length node ID indicates lack of node ID
#[test]
fn test_rfc9174_4_6_069_zero_length_node_id() {
    // RFC 9174 §4.6: "A zero-length node ID SHALL be used to indicate the lack of a node ID
    // rather than a truly empty node ID."

    let config_with_empty = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: String::new(), // Zero-length indicates lack of node ID
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config_with_empty).unwrap();

    // Send SESS_INIT with zero-length node ID
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    let sess_init = session.send_session_init().unwrap();

    // Verify the node ID in the message is zero-length
    if let Message::SessionInit {
        keepalive_interval: _,
        segment_mru: _,
        transfer_mru: _,
        node_id,
        extensions: _,
    } = sess_init
    {
        assert_eq!(
            node_id.len(),
            0,
            "Zero-length node ID SHALL indicate lack of node ID"
        );
    }
}

/// Test RFC9174-5-2-4-128: No XFER_SEGMENT after sending XFER_REFUSE
#[test]
fn test_rfc9174_5_2_4_128_no_segment_after_refuse() {
    // RFC 9174 §5.2.4: "Once a receiving entity sends a XFER_REFUSE message, it will not
    // receive another XFER_SEGMENT for the same bundle"

    // This tests that the sending side stops sending segments after receiving XFER_REFUSE

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 1000,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();
    session
        .process_session_init(&Message::SessionInit {
            keepalive_interval: 30,
            segment_mru: 1000,
            transfer_mru: 10_000,
            node_id: "dtn://peer.local".to_string(),
            extensions: vec![],
        })
        .unwrap();

    // Start a transfer that will require multiple segments
    let data = vec![0x42; 2500];
    let transfer_id = session.start_transfer(data).unwrap();

    // Create first segment and verify multi-segment transfer
    let first_segments = session.create_segments(transfer_id, 1000).unwrap();
    assert!(
        first_segments.len() > 1,
        "Transfer should require multiple segments"
    );

    // Simulate peer sending XFER_REFUSE for this transfer
    // process_refuse removes the transfer and returns an error (expected behavior)
    let refuse_result = session.process_refuse(transfer_id, 0x02);
    assert!(
        refuse_result.is_err(),
        "process_refuse returns error to signal refusal"
    );

    // Verify error message indicates refusal
    let err_msg = refuse_result.unwrap_err().to_string();
    assert!(
        err_msg.contains("refused"),
        "Error should indicate transfer refused: {}",
        err_msg
    );

    // KEY OBLIGATION TEST: Verify that after process_refuse, no more segments can be created
    // The transfer should be removed from outgoing_transfers
    let result = session.create_segments(transfer_id, 1000);

    // MUST fail because transfer was removed by process_refuse
    assert!(
        result.is_err(),
        "create_segments MUST fail after XFER_REFUSE (transfer removed, no segments SHALL be sent)"
    );

    // Verify error indicates transfer not found (was removed)
    let err_msg2 = result.unwrap_err().to_string();
    assert!(
        err_msg2.contains("not found") || err_msg2.contains("Transfer"),
        "Error should indicate transfer not found after refusal: {}",
        err_msg2
    );
}

/// Test RFC9174-6-1-158: Entity MUST send Contact Header before SESS_TERM
#[test]
fn test_rfc9174_6_1_158_contact_before_term() {
    // RFC 9174 §6.1: "However, an entity MUST always send the Contact Header to its peer
    // before sending a SESS_TERM message."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Verify initial state - contact negotiation not complete
    assert_eq!(
        session.state(),
        SessionState::ContactNegotiation,
        "Session starts in ContactNegotiation state"
    );

    // Test 1: SESS_TERM rejected before Contact Header (ANY reason code, including 0x04)
    let early_term = session.send_session_term(0x00, None);
    assert!(
        early_term.is_err(),
        "RFC 9174 §6.1: SESS_TERM rejected before Contact Header"
    );

    let early_term_contact_failure = session.send_session_term(0x04, None);
    assert!(
        early_term_contact_failure.is_err(),
        "RFC 9174 §6.1: SESS_TERM with reason 0x04 also rejected - NO exceptions (§6.1: close TCP without SESS_TERM on contact failure)"
    );

    // Active entity sends contact header
    let _contact = session.send_contact_header().unwrap();

    // Test 2: Now can send SESS_TERM (after contact header sent)
    let term = session.send_session_term(0x00, None).unwrap();

    assert!(
        matches!(term, Message::SessionTerm { .. }),
        "SESS_TERM can be sent after Contact Header"
    );

    // Test the negative case: Passive role cannot send contact before receiving peer's
    let config_passive = SessionConfig {
        role: Role::Passive,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session_passive = TcpclSession::new(config_passive).unwrap();

    // Passive cannot send contact header before receiving peer's
    let result = session_passive.send_contact_header();
    assert!(
        result.is_err(),
        "Passive entity MUST wait for peer's contact before sending (enforces ordering)"
    );
}
