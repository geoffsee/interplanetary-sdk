//! RFC 9174 §4.1-012/013: Contact Header reception timeout
//!
//! Tests verify that the SDK timeouts if no Contact Header is received
//! within the configured duration.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §4.1-012: SHALL close connection if no Contact Header received
///
/// "If either entity does not receive a Contact Header after some
/// implementation-defined time duration after the TCP connection is
/// established, the waiting entity SHALL close the TCP connection."
///
/// Timeout is measured from connection establishment (construction time),
/// not from first poll. This ensures a late first poll still times out correctly.
#[test]
fn test_rfc9174_4_1_012_contact_header_timeout() {
    // Create session at t=0 (connection establishment time)
    let mut session = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 30,
            contact_header_timeout: 10, // 10 second timeout
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    // Session starts in ContactNegotiation
    assert_eq!(session.state(), SessionState::ContactNegotiation);

    // Poll at 9000ms (9 seconds) - no timeout yet
    let result = session.poll(9000);
    assert!(result.is_none(), "Should not timeout before 10s");
    assert_eq!(
        session.state(),
        SessionState::ContactNegotiation,
        "Should remain in ContactNegotiation"
    );

    // Poll at 10000ms (10 seconds) - timeout occurs
    let result = session.poll(10000);
    assert!(
        result.is_none(),
        "No SESS_TERM - timeout before protocol establishment"
    );

    // Session should transition to Terminated (connection closed)
    assert_eq!(
        session.state(),
        SessionState::Terminated,
        "RFC 9174 §4.1-012: SHALL close connection after timeout"
    );
    assert_eq!(
        session.transport_close_kind(),
        Some(CloseKind::Fin),
        "RFC 9174 §4.1-012/014: timeout SHALL close transport with FIN"
    );
}

/// RFC 9174 §4.1-012: Timeout measured from connection establishment, not first poll
///
/// This verifies that a late first poll doesn't delay the timeout.
#[test]
fn test_rfc9174_4_1_012_timeout_from_establishment_not_first_poll() {
    // Connection established at t=0, but first poll is much later
    let mut session = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Active,
            contact_header_timeout: 10, // 10 second timeout
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    // First poll at t=15000 (15 seconds after establishment)
    // Should already be timed out (10s timeout expired at t=10000)
    let result = session.poll(15000);
    assert_eq!(
        session.state(),
        SessionState::Terminated,
        "Should timeout relative to establishment (t=0), not first poll (t=15000)"
    );
    assert!(
        result.is_none(),
        "No SESS_TERM - timeout before protocol establishment"
    );
    assert_eq!(
        session.transport_close_kind(),
        Some(CloseKind::Fin),
        "timeout must close the transport"
    );
}

/// RFC 9174 §4.1-012: No timeout if Contact Header received
#[test]
fn test_rfc9174_4_1_012_no_timeout_after_contact_received() {
    let mut local = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Active,
            contact_header_timeout: 10,
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    let mut remote = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Passive,
            contact_header_timeout: 10,
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    // Poll at 5 seconds - no timeout
    assert!(local.poll(5000).is_none());

    // Exchange contact headers at 7 seconds
    let local_contact = local.send_contact_header().unwrap();
    remote.process_contact_header(&local_contact).unwrap();
    let remote_contact = remote.send_contact_header().unwrap();
    local.process_contact_header(&remote_contact).unwrap();

    // Now in SessionInit state
    assert_eq!(local.state(), SessionState::SessionInit);

    // Poll at 15 seconds (past timeout) - no timeout because contact received
    let result = local.poll(15000);
    assert!(result.is_none());
    assert_eq!(
        local.state(),
        SessionState::SessionInit,
        "Should not timeout after contact header received"
    );
}

/// RFC 9174 §4.1-013: Config validation clamps values >60s to 60s
///
/// "Entities SHOULD choose a Contact Header reception timeout interval
/// no longer than one minute (60 seconds)."
#[test]
fn test_rfc9174_4_1_013_clamps_excessive_timeout() {
    // The session was created with 120s timeout, but should be clamped to 60s
    // We'll verify by checking that timeout occurs at 60s, not 120s
    let mut session = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Active,
            contact_header_timeout: 120, // Will be clamped to 60
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    // Poll at 60000ms - should timeout (clamped to 60s)
    session.poll(60000);
    assert_eq!(
        session.state(),
        SessionState::Terminated,
        "Config with 120s timeout should be clamped to 60s and timeout at 60s"
    );
}

/// RFC 9174 §4.1-013: Timeout at exactly 60 seconds works
#[test]
fn test_rfc9174_4_1_013_60s_timeout_works() {
    let mut session = TcpclSession::new_at_time(
        SessionConfig {
            role: Role::Passive,
            contact_header_timeout: 60, // Exactly 60 seconds
            ..SessionConfig::default()
        },
        0,
    )
    .unwrap();

    assert_eq!(session.state(), SessionState::ContactNegotiation);

    // Poll at 59000ms (59 seconds) - no timeout
    assert!(session.poll(59000).is_none());
    assert_eq!(session.state(), SessionState::ContactNegotiation);

    // Poll at 60000ms (60 seconds) - timeout occurs
    session.poll(60000);
    assert_eq!(
        session.state(),
        SessionState::Terminated,
        "Should timeout at 60s"
    );
}

/// RFC 9174 §4.1-012: Config validation rejects timeout=0
///
/// A timeout of 0 would allow violating the SHALL requirement to close
/// the connection if no Contact Header is received. The SDK rejects this.
#[test]
fn test_rfc9174_4_1_012_zero_timeout_rejected() {
    let result = TcpclSession::new(SessionConfig {
        role: Role::Active,
        contact_header_timeout: 0, // Invalid - would violate SHALL
        ..SessionConfig::default()
    });

    assert!(
        result.is_err(),
        "RFC 9174 §4.1-012: timeout=0 should be rejected (violates SHALL)"
    );

    let error_msg = format!("{:?}", result.unwrap_err());
    assert!(
        error_msg.contains("cannot be 0") || error_msg.contains("violate SHALL"),
        "Error should explain that 0 violates SHALL requirement"
    );
}
