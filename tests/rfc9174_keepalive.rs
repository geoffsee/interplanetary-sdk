#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §5.1.1 Session Upkeep (KEEPALIVE) Tests

mod common;

use interplanetary_sdk::tcpcl::{
    Clock, ManualClock, Role, SessionConfig, SessionState, messages::*,
};

#[test]
fn test_rfc9174_5_1_1_keepalive_sent_after_interval() {
    // RFC 9174 §5.1.1: "Both sides SHALL send a KEEPALIVE message whenever
    // the negotiated interval has elapsed with no transmission of any message
    // (KEEPALIVE or other)"

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 30, // 30 seconds
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "test".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 30,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "peer".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    let mut clock = ManualClock::new();

    // Initialize by recording first send
    session.record_send(clock.now_ms());

    // At t=29s, no keepalive due
    clock.advance(29_000);
    assert!(
        session.poll(clock.now_ms()).is_none(),
        "No keepalive before interval expires"
    );

    // At t=30s, keepalive due
    clock.advance(1_000); // now at 30s
    let result = session.poll(clock.now_ms());
    assert!(result.is_some(), "Keepalive due after 30s");
    assert!(
        matches!(result, Some(Message::Keepalive)),
        "Should return KEEPALIVE message"
    );
}

#[test]
fn test_rfc9174_5_1_1_idle_timeout_terminates_session() {
    // RFC 9174 §5.1.1: "If no message (KEEPALIVE or other) has been received
    // in a session after some implementation-defined time duration, then the
    // entity SHALL terminate the session by transmitting a SESS_TERM message
    // with a reason code of 'Idle timeout'"
    //
    // "If not configurable, the idle timeout duration SHOULD be exactly
    // twice the Keepalive Interval"

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 30,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "test".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 30,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "peer".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    let mut clock = ManualClock::new();

    // Record initial receive
    session.record_receive(clock.now_ms());

    // At t=59s (less than 2× interval), no timeout
    clock.advance(59_000);
    let result = session.poll(clock.now_ms());
    assert!(
        !matches!(result, Some(Message::SessionTerm { .. })),
        "No timeout before 2× keepalive interval"
    );

    // At t=60s (exactly 2× interval), timeout
    clock.advance(1_000); // now at 60s
    let result = session.poll(clock.now_ms());
    assert!(result.is_some(), "Timeout due at 2× keepalive interval");

    match result {
        Some(Message::SessionTerm {
            reason_code,
            message,
            ..
        }) => {
            assert_eq!(
                reason_code,
                term_reason::IDLE_TIMEOUT,
                "Reason code must be Idle timeout (0x01)"
            );
            assert!(message.is_some(), "Should include diagnostic message");
        }
        _ => panic!("Expected SESS_TERM with Idle timeout"),
    }

    assert_eq!(
        session.state(),
        SessionState::Ending,
        "Session state should be Ending"
    );
}

#[test]
fn test_rfc9174_5_1_1_keepalive_disabled_with_interval_zero() {
    // RFC 9174 §5.1.1: "If the negotiated Session Keepalive is zero
    // (i.e., one or both SESS_INIT messages contain a zero Keepalive Interval),
    // then the keepalive feature is disabled"

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 0, // Disabled
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "test".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 0,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "peer".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    let mut clock = ManualClock::new();
    session.record_send(clock.now_ms());

    // Advance by a long time
    clock.advance(600_000); // 10 minutes

    // No keepalive or timeout should be triggered
    let result = session.poll(clock.now_ms());
    assert!(result.is_none(), "Keepalive disabled when interval is 0");
}

#[test]
fn test_rfc9174_keepalive_resets_on_any_message() {
    // RFC 9174 §5.1.1: interval applies to "any message (KEEPALIVE or other)"

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 30,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "test".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 30,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "peer".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    let mut clock = ManualClock::new();
    session.record_send(clock.now_ms());

    // Advance 20s
    clock.advance(20_000);
    assert!(session.poll(clock.now_ms()).is_none(), "No keepalive yet");

    // Send another message (resets timer)
    session.record_send(clock.now_ms());

    // Advance another 20s (total 40s from initial, but 20s from last send)
    clock.advance(20_000);
    assert!(
        session.poll(clock.now_ms()).is_none(),
        "Keepalive timer reset by message send"
    );

    // Advance 10 more seconds (30s since last send)
    clock.advance(10_000);
    let result = session.poll(clock.now_ms());
    assert!(
        matches!(result, Some(Message::Keepalive)),
        "Keepalive due 30s after last send"
    );
}
