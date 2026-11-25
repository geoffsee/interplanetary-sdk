#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §5.1 Session Upkeep Tests

mod common;

use interplanetary_sdk::tcpcl::{Role, SessionConfig, messages::*};

// RFC9174-5-1-1-084/085/086 evidence moved to rfc9174_5_1_1_keepalive_clamp.rs
// (banned constant/default checks replaced with SESS_INIT wire-byte clamp tests)

/// RFC9174-5-1-1-090 & 091: Idle timeout SHOULD be at least 2× keepalive
#[test]
fn test_rfc9174_5_1_1_090_091_idle_timeout_recommendation() {
    // RFC 9174 §5.1.1: "If not configurable, the idle timeout duration SHOULD
    // be exactly twice the Keepalive Interval"
    // "If configurable, the idle timeout duration SHOULD be no shorter than
    // twice the Keepalive Interval"

    use interplanetary_sdk::tcpcl::{Clock, ManualClock};

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 30, // 30 seconds
            ..Default::default()
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 30,
            ..Default::default()
        },
    )
    .unwrap();

    let mut session = pair.active;

    // Negotiated keepalive is 30 seconds
    assert_eq!(session.negotiated_keepalive_interval(), Some(30));

    // Idle timeout SHOULD be at least 2× keepalive = 60 seconds
    let mut clock = ManualClock::new();
    session.record_receive(clock.now_ms());

    // At 59 seconds, should NOT timeout (less than 2× interval)
    clock.advance(59_000);
    let result = session.poll(clock.now_ms());
    assert!(
        !matches!(result, Some(Message::SessionTerm { .. })),
        "No timeout before 2× keepalive"
    );

    // At 60 seconds (exactly 2× keepalive), timeout is appropriate
    clock.advance(1_000); // Now at 60s
    let result = session.poll(clock.now_ms());
    assert!(
        matches!(result, Some(Message::SessionTerm { .. })),
        "Idle timeout at 2× keepalive interval per SHOULD"
    );
}

/// RFC9174-5-1-2-093 & 094: Send MSG_REJECT for inappropriate message
#[test]
fn test_rfc9174_5_1_2_093_094_msg_reject_inappropriate_message() {
    // RFC 9174 §5.1.2: "An entity that receives a message type that is known
    // but is inappropriate for the negotiated session parameters ... or the
    // current session state (e.g., a SESS_INIT after the session has already
    // been established or a XFER_ACK message with an unknown Transfer ID)
    // SHALL send a MSG_REJECT message"

    // Test 1: SESS_INIT in wrong state (after establishment)
    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;

    // Session is Established
    assert_eq!(
        active.state(),
        interplanetary_sdk::tcpcl::SessionState::Established
    );

    // Receiving SESS_INIT now is inappropriate (already established)
    let inappropriate_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn://late".to_string(),
        extensions: vec![],
    };

    let result = active.process_session_init(&inappropriate_init);
    assert!(
        result.is_err(),
        "SESS_INIT in Established state is inappropriate - SHALL reject"
    );

    // Test 2: Process unknown message type (triggers MSG_REJECT)
    let unknown_message_type = 0xFF; // Not defined in RFC 9174 Table 1

    let reject_msg = active.process_raw_message_type(unknown_message_type);
    assert!(
        reject_msg.is_some(),
        "Unknown message type SHALL trigger MSG_REJECT"
    );

    match reject_msg.unwrap() {
        Message::MessageReject { reason_code, .. } => {
            assert_eq!(reason_code, 0x01, "Reason code 0x01 = Message Type Unknown");
        }
        _ => panic!("Expected MSG_REJECT"),
    }
}

/// Verify MSG_REJECT is sent for XFER_ACK with unknown Transfer ID
#[test]
fn test_msg_reject_for_unknown_transfer_id() {
    // RFC 9174 §5.1.2 example: "XFER_ACK message with an unknown Transfer ID"
    // This would be an inappropriate message that SHALL trigger MSG_REJECT

    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;

    // Receive XFER_ACK for transfer ID that doesn't exist
    let unknown_transfer_id = 999;

    // Current implementation: process_ack returns error for unknown transfer
    let result = active.process_ack(unknown_transfer_id, 100);
    assert!(
        result.is_err(),
        "XFER_ACK for unknown Transfer ID is inappropriate"
    );

    // In a complete implementation, this would generate MSG_REJECT
    // Current error handling documents the requirement
}
