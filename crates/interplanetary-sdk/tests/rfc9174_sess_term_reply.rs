#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §6.1 SESS_TERM REPLY Flag Tests
//!
//! Tests SESS_TERM reply handshake per RFC 9174 Table 2

mod common;

use interplanetary_sdk::tcpcl::messages::*;

#[test]
fn test_rfc9174_6_1_initiating_term_reply_flag_zero() {
    // RFC 9174 §6.1: "When sent to initiate a termination, the REPLY flag
    // of a SESS_TERM message SHALL be 0"

    let pair = common::SessionPair::establish().unwrap();
    let mut session = pair.active;

    // Send initial SESS_TERM (initiating)
    let term_msg = session
        .send_session_term(0x00, Some("test".to_string()))
        .unwrap();

    match term_msg {
        Message::SessionTerm { flags, .. } => {
            assert_eq!(
                flags & 0x01,
                0,
                "Initiating SESS_TERM must have REPLY flag (bit 0) = 0"
            );
        }
        _ => panic!("Expected SessionTerm message"),
    }
}

#[test]
fn test_rfc9174_6_1_acknowledging_term_reply_flag_set() {
    // RFC 9174 §6.1: "Upon receiving a SESS_TERM message after not sending
    // a SESS_TERM message in the same session, an entity SHALL send an
    // acknowledging SESS_TERM message. When sent to acknowledge a termination,
    // a SESS_TERM message SHALL have... the REPLY flag, which is set to 1"

    let pair = common::SessionPair::establish().unwrap();
    let mut session = pair.active;

    // Receive SESS_TERM without having sent one
    let incoming_term = Message::SessionTerm {
        flags: 0,
        reason_code: 0x00,
        message: Some("peer terminates".to_string()),
    };

    let reply = session
        .process_session_term(&incoming_term)
        .expect("Should process SESS_TERM");

    // Should generate acknowledging SESS_TERM
    assert!(reply.is_some(), "Should generate acknowledging SESS_TERM");

    match reply.unwrap() {
        Message::SessionTerm {
            flags,
            reason_code,
            message,
        } => {
            assert_eq!(
                flags & 0x01,
                0x01,
                "Acknowledging SESS_TERM must have REPLY flag (bit 0) = 1"
            );
            assert_eq!(reason_code, 0x00, "Should echo reason code");
            assert_eq!(
                message,
                Some("peer terminates".to_string()),
                "Should echo message"
            );
        }
        _ => panic!("Expected SessionTerm message"),
    }
}

#[test]
fn test_rfc9174_6_1_reply_handshake_complete() {
    // RFC 9174 §6.1: Test full handshake
    // 1. Local initiates with REPLY=0
    // 2. Remote acknowledges with REPLY=1

    let pair = common::SessionPair::establish().unwrap();
    let mut local = pair.active;
    let mut remote = pair.passive;

    // Step 1: Local initiates
    let local_term = local
        .send_session_term(0x00, Some("closing".to_string()))
        .unwrap();

    match &local_term {
        Message::SessionTerm { flags, .. } => {
            assert_eq!(flags & 0x01, 0, "Initiating REPLY flag = 0");
        }
        _ => panic!("Expected SessionTerm"),
    }

    // Step 2: Remote receives and sends acknowledging SESS_TERM
    let remote_reply = remote
        .process_session_term(&local_term)
        .expect("Should process")
        .expect("Should generate reply");

    match &remote_reply {
        Message::SessionTerm { flags, .. } => {
            assert_eq!(flags & 0x01, 0x01, "Acknowledging REPLY flag = 1");
        }
        _ => panic!("Expected SessionTerm"),
    }

    // Step 3: Local receives acknowledgment (no further reply)
    let no_reply = local
        .process_session_term(&remote_reply)
        .expect("Should process ack");

    assert!(
        no_reply.is_none(),
        "Should not generate further reply after receiving acknowledgment"
    );
}

#[test]
fn test_rfc9174_6_1_both_initiate_simultaneously() {
    // Edge case: both sides send SESS_TERM simultaneously
    // Each should NOT send acknowledgment since they already sent SESS_TERM

    let pair = common::SessionPair::establish().unwrap();
    let mut session1 = pair.active;
    let mut session2 = pair.passive;

    // Both initiate
    let term1 = session1.send_session_term(0x00, None).unwrap();
    let term2 = session2.send_session_term(0x00, None).unwrap();

    // session1 receives session2's SESS_TERM (should not reply, already sent)
    let reply1 = session1
        .process_session_term(&term2)
        .expect("Should process");
    assert!(
        reply1.is_none(),
        "Should not reply when already sent SESS_TERM"
    );

    // session2 receives session1's SESS_TERM (should not reply, already sent)
    let reply2 = session2
        .process_session_term(&term1)
        .expect("Should process");
    assert!(
        reply2.is_none(),
        "Should not reply when already sent SESS_TERM"
    );
}
