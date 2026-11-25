//! RFC 9174 §4.7-076: Terminate if keepalive interval unacceptable
//!
//! "If the Session Keepalive Interval is unacceptable, the entity SHALL
//! terminate the session with a reason code of 'Contact Failure'."

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

fn handshake_to_session_init(
    local: &mut TcpclSession,
    remote: &mut TcpclSession,
) -> (Message, Message) {
    let local_contact = local.send_contact_header().unwrap();
    remote.process_contact_header(&local_contact).unwrap();
    let remote_contact = remote.send_contact_header().unwrap();
    local.process_contact_header(&remote_contact).unwrap();
    let local_init = local.send_session_init().unwrap();
    let remote_init = remote.send_session_init().unwrap();
    (local_init, remote_init)
}

/// RFC 9174 §4.7-076: SHALL terminate with Contact Failure SESS_TERM bytes
#[test]
fn test_rfc9174_4_7_076_reject_excessive_peer_keepalive() {
    let mut local = TcpclSession::new(SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        max_peer_keepalive: Some(600),
        ..SessionConfig::default()
    })
    .unwrap();

    let mut remote = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        keepalive_interval: 300,
        ..SessionConfig::default()
    })
    .unwrap();

    let (local_init, _remote_init) = handshake_to_session_init(&mut local, &mut remote);
    assert!(remote.process_session_init(&local_init).is_ok());

    // Inject peer keepalive above local max (bypasses local clamp; peer wire value)
    let bad_peer_init = Message::SessionInit {
        keepalive_interval: 900,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn://peer".to_string(),
        extensions: vec![],
    };

    let result = local.process_session_init(&bad_peer_init);
    assert!(result.is_err());
    assert_eq!(local.state(), SessionState::Ending);

    let term = local.take_outbound().expect("SESS_TERM must be queued");
    let bytes = term.encode();
    assert_eq!(bytes[0], Message::TYPE_SESS_TERM, "SESS_TERM type 0x05");
    assert_eq!(bytes[1], 0, "REPLY flag SHALL be 0 when initiating");
    assert_eq!(
        bytes[2],
        term_reason::CONTACT_FAILURE,
        "reason Contact Failure 0x04"
    );
    assert_eq!(
        local.transport_close_kind(),
        Some(CloseKind::Fin),
        "termination closes transport with FIN"
    );
}

/// RFC 9174 §4.7-076: Accept keepalive within acceptable range
#[test]
fn test_rfc9174_4_7_076_accept_acceptable_keepalive() {
    let mut local = TcpclSession::new(SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        max_peer_keepalive: Some(600),
        ..SessionConfig::default()
    })
    .unwrap();

    let mut remote = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        keepalive_interval: 300,
        ..SessionConfig::default()
    })
    .unwrap();

    let (local_init, remote_init) = handshake_to_session_init(&mut local, &mut remote);
    assert!(local.process_session_init(&remote_init).is_ok());
    assert!(remote.process_session_init(&local_init).is_ok());
    assert_eq!(local.state(), SessionState::Established);
    assert_eq!(remote.state(), SessionState::Established);
}

/// RFC 9174 §4.7-076: Default config (max_peer_keepalive=None) accepts any wire value
#[test]
fn test_rfc9174_4_7_076_default_accepts_any_keepalive() {
    let mut local = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut remote = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        ..SessionConfig::default()
    })
    .unwrap();

    let (local_init, _remote_init) = handshake_to_session_init(&mut local, &mut remote);

    let huge_peer_init = Message::SessionInit {
        keepalive_interval: 10000,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn://peer".to_string(),
        extensions: vec![],
    };

    assert!(local.process_session_init(&huge_peer_init).is_ok());
    assert!(remote.process_session_init(&local_init).is_ok());
    assert_eq!(local.state(), SessionState::Established);
}

/// RFC 9174 §4.7-076: Boundary — 601 rejected, 600 accepted when max=600
#[test]
fn test_rfc9174_4_7_076_boundary_rejection() {
    let mut local = TcpclSession::new(SessionConfig {
        role: Role::Active,
        max_peer_keepalive: Some(600),
        ..SessionConfig::default()
    })
    .unwrap();

    let mut remote = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        ..SessionConfig::default()
    })
    .unwrap();

    let (_local_init, _remote_init) = handshake_to_session_init(&mut local, &mut remote);

    let over = Message::SessionInit {
        keepalive_interval: 601,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn://peer".to_string(),
        extensions: vec![],
    };
    assert!(local.process_session_init(&over).is_err());
    assert_eq!(local.state(), SessionState::Ending);
    let term = local.take_outbound().unwrap();
    assert_eq!(term.encode()[2], term_reason::CONTACT_FAILURE);

    let mut local2 = TcpclSession::new(SessionConfig {
        role: Role::Active,
        max_peer_keepalive: Some(600),
        ..SessionConfig::default()
    })
    .unwrap();
    let mut remote2 = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        keepalive_interval: 600,
        ..SessionConfig::default()
    })
    .unwrap();
    let (l2, r2) = handshake_to_session_init(&mut local2, &mut remote2);
    assert!(remote2.process_session_init(&l2).is_ok());
    assert!(local2.process_session_init(&r2).is_ok());
    assert_eq!(local2.state(), SessionState::Established);
}
