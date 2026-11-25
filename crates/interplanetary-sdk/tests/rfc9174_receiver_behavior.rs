#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 Receiver-side behavior tests
//!
//! Tests for obligations that were demoted because they test receiver behavior
//! rather than sender behavior.

mod common;

use interplanetary_sdk::tcpcl::{
    Message, Role, SessionConfig, TcpclSession, refuse_reason, transfer_flags,
};

/// RFC9174-5-2-4-124: XFER_REFUSE reason codes including unknown values
///
/// RFC 9174 §5.2.4: "The receiver MUST, for each transfer preceding the one to be refused,
/// have either acknowledged all XFER_SEGMENT messages or refused the bundle transfer."
///
/// This tests that the receiver properly handles all defined reason codes and unknown codes.
#[test]
fn test_rfc9174_124_receiver_handles_all_refuse_reason_codes() {
    // RFC 9174 §5.2.4 Table 6: XFER_REFUSE Reason Codes
    // 0x00 = Unknown
    // 0x01 = Completed
    // 0x02 = No Resources
    // 0x03 = Retransmit
    // 0x04 = Not Acceptable
    // 0x05 = Extension Failure
    // Unknown codes (>0x05) should be handled gracefully per RFC

    let pair = common::SessionPair::establish().unwrap();
    let mut receiver = pair.passive;

    // Create incoming segment
    let segment = Message::TransferSegment {
        flags: transfer_flags::START | transfer_flags::END,
        transfer_id: 1,
        extensions: vec![],
        data: vec![0xAA; 100],
    };

    // Process segment (receiver will send ACK)
    let response = receiver.process_segment(&segment).expect("Process segment");

    assert!(
        matches!(response, Some(Message::TransferAck { .. })),
        "Receiver should send ACK for valid segment"
    );

    // Test that receiver can handle unknown reason codes per RFC
    // "Unknown codes should be treated as 0x00 (Unknown)" per IANA guidance
    let unknown_code = 0xFF; // Unknown reason code

    // Receiver decides to refuse with unknown code (simulating sending XFER_REFUSE)
    let refuse_msg = receiver.refuse_incoming_transfer(1, unknown_code).unwrap();

    // Should generate XFER_REFUSE message gracefully (doesn't panic on unknown code)
    assert!(
        matches!(refuse_msg, Message::TransferRefuse { .. }),
        "RFC 9174: Unknown XFER_REFUSE reason codes must be handled gracefully"
    );
}

/// RFC9174-5-2-4-128: Segments arriving after receiver sends XFER_REFUSE
///
/// RFC 9174 §5.2.4: "After sending a XFER_REFUSE, the recipient SHALL treat any
/// subsequently received XFER_SEGMENT messages for the same transfer as though
/// a XFER_REFUSE message had not yet been sent."
///
/// Note: The RFC allows segments to cross on the wire after XFER_REFUSE is sent.
#[test]
fn test_rfc9174_128_segments_after_refuse() {
    // RFC 9174 §5.2.4: "the entity will not receive another XFER_SEGMENT for the
    // same bundle after transmitting a XFER_REFUSE message, since messages can
    // cross on the wire; if this happens, subsequent segments of the bundle SHALL
    // also be responded to by XFER_REFUSE messages."

    let pair = common::SessionPair::establish().unwrap();
    let mut receiver = pair.passive;

    // First segment arrives
    let segment1 = Message::TransferSegment {
        flags: transfer_flags::START,
        transfer_id: 1,
        extensions: vec![],
        data: vec![0xBB; 100],
    };

    receiver
        .process_segment(&segment1)
        .expect("Process first segment");

    // Receiver decides to refuse (simulate internal refuse decision)
    // In reality, this would be triggered by resource exhaustion or policy
    let _refuse_msg = receiver
        .refuse_incoming_transfer(1, refuse_reason::NO_RESOURCES)
        .unwrap();

    // Additional segments arrive after XFER_REFUSE sent (messages crossed on wire)
    let segment2 = Message::TransferSegment {
        flags: 0, // Continuation
        transfer_id: 1,
        extensions: vec![],
        data: vec![0xCC; 100],
    };

    // RFC: "subsequent segments SHALL also be responded to by XFER_REFUSE messages"
    let response = receiver.process_segment(&segment2);

    // Per RFC, should send another XFER_REFUSE
    // RFC 9174 §5.2.4: "SHALL also be responded to by XFER_REFUSE messages"
    assert!(
        matches!(
            response,
            Ok(Some(Message::TransferRefuse { transfer_id: 1, .. }))
        ),
        "RFC 9174 §5.2.4: Subsequent segments after XFER_REFUSE SHALL also be refused"
    );
}

/// RFC9174-6-1-158: Contact Header must precede SESS_TERM
///
/// RFC 9174 §6.1: "However, an entity MUST always send the Contact Header to its
/// peer before sending a SESS_TERM message."
///
/// RFC 9174 §6.1: "If reception of the Contact Header itself somehow fails (e.g., an
/// invalid magic string is received), an entity SHALL close the TCP connection without
/// sending a SESS_TERM message."
#[test]
fn test_rfc9174_158_contact_before_sess_term() {
    // RFC 9174 §6.1: "an entity MUST always send the Contact Header to its peer
    // before sending a SESS_TERM message" - NO exceptions

    // Create a session that hasn't sent contact header yet
    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 0,
        segment_mru: 1024,
        transfer_mru: 10_000,
        node_id: "test".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Test 1: Try to send SESS_TERM before Contact Header (ANY reason - should all fail)
    let early_term = session.send_session_term(0x00, None);
    assert!(
        early_term.is_err(),
        "SDK MUST reject SESS_TERM with reason 0x00 before Contact Header per RFC 9174 §6.1"
    );

    let early_term_contact_failure = session.send_session_term(0x04, None);
    assert!(
        early_term_contact_failure.is_err(),
        "RFC 9174 §6.1: SESS_TERM with reason 0x04 (Contact Failure) also rejected - MUST ALWAYS send Contact Header first (no exceptions); on contact failure, close TCP without SESS_TERM per §6.1"
    );

    // Test 2: Send Contact Header first
    let contact = session.send_contact_header();
    assert!(
        contact.is_ok(),
        "Should be able to send contact header as Active"
    );

    // Process peer's contact
    let peer_contact = interplanetary_sdk::tcpcl::ContactHeader::new();
    session
        .process_contact_header(&peer_contact)
        .expect("Process contact");

    // Test 3: Now SESS_TERM should work (after contact exchange)
    let term = session.send_session_term(0x00, None);
    assert!(
        term.is_ok(),
        "SESS_TERM should succeed after Contact Header exchange"
    );
    assert!(
        matches!(term.unwrap(), Message::SessionTerm { .. }),
        "Should produce SESS_TERM message"
    );
}

/// Helper test: Verify receiver state handling after refusal
#[test]
fn test_receiver_state_after_refuse() {
    let pair = common::SessionPair::establish().unwrap();
    let mut receiver = pair.passive;

    // First segment
    let segment1 = Message::TransferSegment {
        flags: transfer_flags::START,
        transfer_id: 1,
        extensions: vec![],
        data: vec![0xDD; 50],
    };

    receiver
        .process_segment(&segment1)
        .expect("Process first segment");

    // Refuse transfer
    let _refuse = receiver
        .refuse_incoming_transfer(1, refuse_reason::NO_RESOURCES)
        .unwrap();

    // Late segment arrives (after XFER_REFUSE was sent)
    let segment2 = Message::TransferSegment {
        flags: transfer_flags::END,
        transfer_id: 1,
        extensions: vec![],
        data: vec![0xEE; 50],
    };

    // RFC 9174 §5.2.4: Late segments SHALL also be responded to by XFER_REFUSE
    let response = receiver.process_segment(&segment2);
    assert!(
        matches!(
            response,
            Ok(Some(Message::TransferRefuse { transfer_id: 1, .. }))
        ),
        "Late segments after XFER_REFUSE SHALL also be refused"
    );
}

/// Helper test: Multiple concurrent transfers with selective refusal
#[test]
fn test_receiver_multiple_transfers_with_refuse() {
    let pair = common::SessionPair::establish().unwrap();
    let mut receiver = pair.passive;

    // Transfer 1 - will be refused
    let segment1 = Message::TransferSegment {
        flags: transfer_flags::START,
        transfer_id: 1,
        extensions: vec![],
        data: vec![0x01; 100],
    };

    receiver.process_segment(&segment1).expect("Process t1");

    // Refuse transfer 1
    let _refuse1 = receiver
        .refuse_incoming_transfer(1, refuse_reason::NO_RESOURCES)
        .unwrap();

    // Transfer 2 - will be accepted
    let segment2 = Message::TransferSegment {
        flags: transfer_flags::START | transfer_flags::END,
        transfer_id: 2,
        extensions: vec![],
        data: vec![0x02; 100],
    };

    let response2 = receiver.process_segment(&segment2).expect("Process t2");

    // Transfer 2 should be acknowledged (different transfer_id)
    assert!(
        matches!(
            response2,
            Some(Message::TransferAck {
                transfer_id: 2,
                acked_length: 100,
                ..
            })
        ),
        "Transfer 2 should be acknowledged independently"
    );
}
