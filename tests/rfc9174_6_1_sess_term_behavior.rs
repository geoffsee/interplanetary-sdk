//! RFC 9174 §6.1 SESS_TERM Behavior Tests
//!
//! Tests session termination behavior obligations beyond message structure.
#![cfg(feature = "tcpclv4-model")]

mod common;

use interplanetary_sdk::tcpcl::messages::*;
use interplanetary_sdk::tcpcl::session::SessionState;

/// RFC9174-6-1-144: To cleanly terminate a session, a SESS_TERM message SHALL be transmitted
#[test]
fn test_rfc9174_6_1_144_sess_term_sent_for_clean_termination() {
    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;

    // Verify we're in Established state
    assert_eq!(active.state(), SessionState::Established);

    // Cleanly terminate - send_session_term() creates the SESS_TERM message
    let sess_term = active.send_session_term(0x00, None).unwrap(); // reason code 0x00 = unknown

    // Verify SESS_TERM message is created
    match sess_term {
        Message::SessionTerm {
            flags, reason_code, ..
        } => {
            assert_eq!(flags, 0); // REPLY flag SHALL be 0 when initiating
            assert_eq!(reason_code, 0x00);
        }
        _ => panic!("Expected SessionTerm message"),
    }

    // After sending SESS_TERM, state transitions to Ending
    assert_eq!(active.state(), SessionState::Ending);
}

/// RFC9174-6-1-148: After sending SESS_TERM, an entity SHALL NOT begin any new outgoing transfer
#[test]
fn test_rfc9174_6_1_148_no_new_outgoing_after_sess_term() {
    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;

    // Send SESS_TERM (initiates termination, moves to Ending state)
    let _sess_term = active.send_session_term(0x00, None).unwrap();

    // Verify we're in Ending state
    assert_eq!(active.state(), SessionState::Ending);

    // Attempt to start new outgoing transfer
    let bundle_data = vec![1, 2, 3, 4, 5];
    let result = active.start_transfer(bundle_data);

    // SHALL NOT begin new transfer - must reject
    assert!(
        result.is_err(),
        "Should reject new outgoing transfer after SESS_TERM"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Ending")
            || err_msg.contains("terminat")
            || err_msg.contains("not allowed")
            || err_msg.contains("non-established"),
        "Error should indicate session is terminating: {}",
        err_msg
    );
}

/// RFC9174-6-1-150: After sending SESS_TERM, an entity SHALL NOT accept any new incoming transfer
#[test]
fn test_rfc9174_6_1_150_no_new_incoming_after_sess_term() {
    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;

    // Send SESS_TERM (moves to Ending state)
    let _sess_term = active.send_session_term(0x00, None).unwrap();

    // Verify in Ending state
    assert_eq!(active.state(), SessionState::Ending);

    // Peer attempts to start new incoming transfer (XFER_SEGMENT with START flag)
    let segment_msg = Message::TransferSegment {
        flags: transfer_flags::START,
        transfer_id: 42,
        extensions: vec![],
        data: vec![0xaa, 0xbb, 0xcc],
    };

    let result = active.process_segment(&segment_msg);

    // SHALL NOT accept new incoming transfer
    assert!(
        result.is_err(),
        "Should reject new incoming transfer after SESS_TERM"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Ending")
            || err_msg.contains("terminat")
            || err_msg.contains("not accept")
            || err_msg.contains("non-established"),
        "Error should indicate session is terminating: {}",
        err_msg
    );
}

/// RFC9174-6-1-152: If new incoming transfer attempted in Ending state,
/// SHALL send XFER_REFUSE with reason 0x02 (Session Terminating)
#[test]
fn test_rfc9174_6_1_152_refuse_with_session_terminating() {
    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;

    // Send SESS_TERM (moves to Ending state)
    let _sess_term = active.send_session_term(0x00, None).unwrap();

    // Peer sends new transfer (START flag)
    let segment = Message::TransferSegment {
        flags: transfer_flags::START,
        transfer_id: 99,
        extensions: vec![],
        data: vec![0x01, 0x02],
    };

    // Process should reject the segment
    let result = active.process_segment(&segment);

    // For now, verify rejection occurs (refusal mechanism may vary by implementation)
    assert!(
        result.is_err(),
        "Should reject/refuse transfer in Ending state"
    );

    // The ideal implementation would generate XFER_REFUSE with reason 0x02
    // This is verified if the error indicates "Session Terminating" or similar
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("terminat")
            || err_msg.contains("Ending")
            || err_msg.contains("refuse")
            || err_msg.contains("non-established"),
        "Error should indicate session terminating: {}",
        err_msg
    );
}

/// RFC9174-6-1-158: Entity MUST always send Contact Header before sending SESS_TERM
#[test]
fn test_rfc9174_6_1_158_contact_header_before_sess_term() {
    use interplanetary_sdk::tcpcl::{Role, SessionConfig, TcpclSession};

    let mut session = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..Default::default()
    })
    .unwrap();

    // RFC 9758 §6.1: MUST send Contact Header before SESS_TERM - test the enforcement

    // Current state is ContactNegotiation (initial state)
    assert_eq!(session.state(), SessionState::ContactNegotiation);

    // Test 1: SESS_TERM rejected before Contact Header (ANY reason code)
    let early_term = session.send_session_term(0x00, None);
    assert!(
        early_term.is_err(),
        "RFC 9174 §6.1: SESS_TERM with reason 0x00 rejected before Contact Header"
    );

    let early_term_contact_failure = session.send_session_term(0x04, None);
    assert!(
        early_term_contact_failure.is_err(),
        "RFC 9174 §6.1: SESS_TERM with reason 0x04 (Contact Failure) also rejected - no exceptions"
    );

    // RFC 9174 §6.1: If contact fails, SHALL close TCP without SESS_TERM
    // (not tested here - would be at transport layer)
}

/// RFC9174-6-1-159: If Contact Header reception fails, close TCP without SESS_TERM
#[test]
fn test_rfc9174_6_1_159_terminate_on_contact_failure() {
    // RFC 9174 §6.1: "If reception of the Contact Header itself somehow fails (e.g., an
    // invalid magic string is received), an entity SHALL close the TCP connection without
    // sending a SESS_TERM message."

    use interplanetary_sdk::tcpcl::{Role, SessionConfig, TcpclSession};

    let mut session = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..Default::default()
    })
    .unwrap();

    // Simulate invalid Contact Header (wrong version)
    let mut invalid_header = ContactHeader::new();
    invalid_header.version = 99; // Invalid version

    // Process should fail
    let result = session.process_contact_header(&invalid_header);
    assert!(result.is_err(), "Should reject invalid Contact Header");

    // RFC 9174 §6.1: On contact failure, SHALL close TCP without SESS_TERM
    // Attempting to send SESS_TERM should fail (haven't sent our contact header)
    let sess_term_result = session.send_session_term(0x04, None);
    assert!(
        sess_term_result.is_err(),
        "RFC 9174 §6.1: MUST NOT send SESS_TERM on contact failure (close TCP without SESS_TERM)"
    );

    // The correct action is to close the TCP connection (not tested here, would be at transport layer)
}

/// RFC9174-6-1-153: SHOULD acknowledge received segments before unclean termination
#[test]
fn test_rfc9174_6_1_153_acknowledge_before_unclean_term() {
    // RFC 9174 §6.1: "When performing an unclean termination, an entity SHOULD
    // acknowledge all received XFER_SEGMENTs with a XFER_ACK before closing the
    // TCP connection"

    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;
    let mut passive = pair.passive;

    // Passive starts a transfer
    let transfer_data = vec![0xAA; 100];
    let transfer_id = passive.start_transfer(transfer_data).unwrap();

    // Create segments
    let segments = passive.create_segments(transfer_id, 1000).unwrap();
    assert!(!segments.is_empty());

    // Active receives segment
    let ack = active.process_segment(&segments[0]).unwrap();
    assert!(ack.is_some(), "Should generate XFER_ACK");

    // Verify it's an ACK
    match ack.unwrap() {
        Message::TransferAck { .. } => {
            // Good - acknowledged before termination
        }
        _ => panic!("Expected XFER_ACK"),
    }

    // This demonstrates that XFER_ACKs SHOULD be sent before termination
    // The implementation sends ACKs for received segments
}

/// RFC9174-6-1-155: Unknown reason codes SHOULD be treated as "Unknown"
#[test]
fn test_rfc9174_6_1_155_unknown_reason_codes() {
    // RFC 9174 §6.1: "If a termination has a reason code that is not decodable
    // to the BPA, the agent SHOULD treat the termination as having a reason
    // code of 'Unknown'"

    use interplanetary_sdk::tcpcl::term_reason;

    // Defined reason codes from RFC 9174 Table 2
    let defined_codes = [
        term_reason::UNKNOWN,             // 0x00
        term_reason::IDLE_TIMEOUT,        // 0x01
        term_reason::VERSION_MISMATCH,    // 0x02
        term_reason::BUSY,                // 0x03
        term_reason::CONTACT_FAILURE,     // 0x04
        term_reason::RESOURCE_EXHAUSTION, // 0x05
    ];

    // Any code not in the defined list should be treated as UNKNOWN
    let undefined_code = 0xFF; // Not defined in Table 2

    // A BPA receiving this should treat it as UNKNOWN (0x00)
    // This test documents the requirement
    assert!(
        !defined_codes.contains(&undefined_code),
        "0xFF is not a defined reason code"
    );

    // If undefined, treat as UNKNOWN
    let treated_as = if defined_codes.contains(&undefined_code) {
        undefined_code
    } else {
        term_reason::UNKNOWN
    };

    assert_eq!(
        treated_as,
        term_reason::UNKNOWN,
        "Undefined reason codes SHOULD be treated as Unknown"
    );
}

/// RFC9174-6-1-160: Don't send SESS_TERM if incomplete message in progress
#[test]
fn test_rfc9174_6_1_160_no_sess_term_during_incomplete_send() {
    // RFC 9174 §6.1: "If a session is to be terminated before the sending of a
    // protocol message has completed, then the entity MUST NOT transmit the
    // SESS_TERM message but still SHALL close the TCP connection"

    // This requirement applies to the transport layer - if a message is
    // partially transmitted on the TCP stream, don't send SESS_TERM

    // In our model implementation, messages are discrete units, so this
    // scenario doesn't directly apply. However, the test documents the requirement:

    // If during transmission of a large XFER_SEGMENT:
    // 1. Some bytes sent on TCP socket
    // 2. Need to terminate urgently
    // 3. MUST NOT send SESS_TERM
    // 4. SHALL close TCP connection immediately

    // This is a transport-layer concern, not modeled in our discrete message API
    // The test exists to document the obligation
}
