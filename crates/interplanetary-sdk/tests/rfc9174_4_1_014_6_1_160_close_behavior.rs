//! RFC 9174 §4.1-014 and §6.1-160: TCP close behavior

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §4.1-014: SHALL use FIN mechanism, not RST
#[test]
fn test_rfc9174_4_1_014_close_uses_fin_not_rst() {
    let mut stream = VirtualStream::new();
    stream.write(b"test data").unwrap();
    stream.close();
    assert_eq!(stream.close_kind(), Some(CloseKind::Fin));
    assert_ne!(stream.close_kind(), Some(CloseKind::Rst));
}

/// RFC 9174 §4.1-014: Contact header timeout closes with FIN
#[test]
fn test_rfc9174_4_1_014_timeout_close_uses_fin() {
    let mut stream = VirtualStream::new();
    let mut session = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Active,
            contact_header_timeout: 10,
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    session.poll(10000);
    assert_eq!(session.state(), SessionState::Terminated);
    assert_eq!(session.transport_close_kind(), Some(CloseKind::Fin));

    // Production path also closes the attached simulated transport with FIN
    session.close_transport(&mut stream);
    assert_eq!(stream.close_kind(), Some(CloseKind::Fin));
}

/// RFC 9174 §4.1-014: Normal session termination closes with FIN
#[test]
fn test_rfc9174_4_1_014_normal_termination_uses_fin() {
    let mut stream = VirtualStream::new();
    let mut local = TcpclSession::new_at_time(SessionConfig::default(), 0).unwrap();
    let mut remote = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Passive,
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    let lc = local.send_contact_header().unwrap();
    remote.process_contact_header(&lc).unwrap();
    let rc = remote.send_contact_header().unwrap();
    local.process_contact_header(&rc).unwrap();
    let li = local.send_session_init().unwrap();
    let ri = remote.send_session_init().unwrap();
    local.process_session_init(&ri).unwrap();
    remote.process_session_init(&li).unwrap();

    let _term = local.send_session_term(term_reason::UNKNOWN, None).unwrap();
    assert_eq!(local.transport_close_kind(), Some(CloseKind::Fin));
    local.close_transport(&mut stream);
    assert_eq!(stream.close_kind(), Some(CloseKind::Fin));
}

/// RFC 9174 §6.1-160: Abort mid-message emits no SESS_TERM, closes with FIN
#[test]
fn test_rfc9174_6_1_160_abort_mid_message_no_sess_term_but_close() {
    let mut stream = VirtualStream::new();
    let mut local = TcpclSession::new_at_time(SessionConfig::default(), 0).unwrap();
    let mut remote = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Passive,
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    let lc = local.send_contact_header().unwrap();
    remote.process_contact_header(&lc).unwrap();
    let rc = remote.send_contact_header().unwrap();
    local.process_contact_header(&rc).unwrap();
    let li = local.send_session_init().unwrap();
    let ri = remote.send_session_init().unwrap();
    local.process_session_init(&ri).unwrap();
    remote.process_session_init(&li).unwrap();

    // Simulate in-progress message bytes on the transport
    stream.write(b"partial-xfer-segment").unwrap();
    let before = stream.available();

    local.abort_mid_message(&mut stream);

    assert_eq!(local.state(), SessionState::Terminated);
    assert!(
        local.take_outbound().is_none(),
        "MUST NOT transmit SESS_TERM when aborting mid-message"
    );
    assert_eq!(stream.close_kind(), Some(CloseKind::Fin));
    assert_eq!(
        stream.available(),
        before,
        "no SESS_TERM bytes appended on abort"
    );
}

/// RFC 9174 §6.1-160 / §4.1-014: SDK-initiated closes always use FIN
#[test]
fn test_rfc9174_6_1_160_close_always_uses_fin() {
    let mut stream = VirtualStream::new();
    stream.close();
    assert_eq!(stream.close_kind(), Some(CloseKind::Fin));
    assert_ne!(stream.close_kind(), Some(CloseKind::Rst));
}
