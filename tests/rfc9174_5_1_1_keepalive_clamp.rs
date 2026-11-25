//! RFC 9174 §5.1.1-084/085/086: Keepalive interval clamping
//!
//! Asserts SESS_INIT wire bytes carry clamped keepalive values.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

fn establish_active_with(keepalive: u16) -> TcpclSession {
    let mut active = TcpclSession::new(SessionConfig {
        role: Role::Active,
        keepalive_interval: keepalive,
        node_id: "dtn://active".to_string(),
        ..SessionConfig::default()
    })
    .unwrap();
    let mut passive = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        keepalive_interval: 60,
        node_id: "dtn://passive".to_string(),
        ..SessionConfig::default()
    })
    .unwrap();

    let ac = active.send_contact_header().unwrap();
    passive.process_contact_header(&ac).unwrap();
    let pc = passive.send_contact_header().unwrap();
    active.process_contact_header(&pc).unwrap();
    active
}

/// RFC 9174 §5.1.1-084: SHOULD choose Keepalive Interval no shorter than 30 seconds
#[test]
fn test_rfc9174_5_1_1_084_sess_init_clamps_below_30() {
    let mut active = establish_active_with(10); // too short → clamp to 30
    assert_eq!(active.local_keepalive_interval(), 30);

    let init = active.send_session_init().unwrap();
    let bytes = init.encode();
    assert_eq!(bytes[0], Message::TYPE_SESS_INIT);
    let keepalive = u16::from_be_bytes([bytes[1], bytes[2]]);
    assert_eq!(
        keepalive, 30,
        "SESS_INIT keepalive must be clamped to 30 for shared-network SHOULD"
    );
}

/// RFC 9174 §5.1.1-085: SHOULD choose Keepalive Interval no longer than 600 seconds
#[test]
fn test_rfc9174_5_1_1_085_sess_init_clamps_above_600() {
    let mut active = establish_active_with(900); // too long → clamp to 600
    assert_eq!(active.local_keepalive_interval(), 600);

    let init = active.send_session_init().unwrap();
    let bytes = init.encode();
    assert_eq!(bytes[0], Message::TYPE_SESS_INIT);
    let keepalive = u16::from_be_bytes([bytes[1], bytes[2]]);
    assert_eq!(keepalive, 600, "SESS_INIT keepalive must be clamped to 600");
}

/// RFC 9174 §5.1.1-086: SHOULD NOT be too short (clamped via same floor as 084)
#[test]
fn test_rfc9174_5_1_1_086_sess_init_rejects_too_short_via_clamp() {
    let mut active = establish_active_with(1);
    let init = active.send_session_init().unwrap();
    let bytes = init.encode();
    let keepalive = u16::from_be_bytes([bytes[1], bytes[2]]);
    assert!(
        keepalive >= 30,
        "too-short keepalive must not appear on the wire; got {}",
        keepalive
    );
}
