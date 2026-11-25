//! RFC 9174 TCP Connection Closing Behavior
//!
//! Tests document how the SDK handles session termination at the protocol layer.
//! Actual TCP FIN/RST operations are the integrator's responsibility.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §4.1-014: TCP close using FIN mechanism
///
/// "Within this specification, when an entity is said to 'close' a TCP
/// connection the entity SHALL use the TCP FIN mechanism and not the RST
/// mechanism."
///
/// At the protocol layer, the SDK generates SESS_TERM messages to signal
/// session termination. The actual TCP FIN operation is the integrator's
/// responsibility when the protocol layer indicates termination is complete.
#[test]
fn test_rfc9174_4_1_014_protocol_layer_termination_signal() {
    let mut session = TcpclSession::new(SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "ipn:1.1".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    })
    .unwrap();

    // Establish session
    session.send_contact_header().unwrap();
    let peer_contact = ContactHeader {
        version: 4,
        flags: 0,
    };
    session.process_contact_header(&peer_contact).unwrap();

    // Send SESS_TERM to initiate graceful termination
    let sess_term = session.send_session_term(0x00, None).unwrap();

    // Session enters Ending state
    assert_eq!(session.state(), SessionState::Ending);

    // The SESS_TERM message is the protocol-layer signal for termination
    // After both entities exchange SESS_TERM (or reply), the session
    // transitions to Terminated

    // At the protocol layer, we've signaled termination cleanly
    // The integrator should then close the TCP connection using FIN
    // (not RST) per RFC 9174 §4.1-014

    match sess_term {
        Message::SessionTerm { .. } => {
            // SESS_TERM sent successfully - clean protocol termination
        }
        _ => panic!("Expected SESS_TERM"),
    }

    // This test documents that the SDK provides the protocol-layer termination
    // signal (SESS_TERM). The TCP FIN mechanism is applied by the integrator
    // after the protocol layer completes.
}

/// RFC 9174 §6.1-160: Emergency termination without SESS_TERM
///
/// "If a session is to be terminated before the sending of a protocol message
/// has completed, then the entity MUST NOT transmit the SESS_TERM message but
/// still SHALL close the TCP connection."
///
/// In the deterministic model, messages are created atomically. Emergency
/// termination (closing connection without SESS_TERM) is an integrator action.
/// This test documents that session states and messages are independent of
/// TCP-layer emergency shutdown.
#[test]
fn test_rfc9174_6_1_160_emergency_termination_no_sess_term() {
    let session = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "ipn:2.1".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    })
    .unwrap();

    // RFC 9174 §6.1-160: "If a session is to be terminated before the sending
    // of a protocol message has completed, then the entity MUST NOT transmit
    // the SESS_TERM message but still SHALL close the TCP connection"

    // In the deterministic model:
    // - Messages are created atomically (no partial sending)
    // - Emergency termination = integrator closes TCP without calling send_session_term()

    // The session object can be in any state
    assert_eq!(session.state(), SessionState::ContactNegotiation);

    // For emergency termination, the integrator simply:
    // 1. Does NOT call send_session_term()
    // 2. Closes the TCP connection immediately (outside the SDK)

    // The SDK does not need to send SESS_TERM for emergency shutdown
    // This is a TCP-layer decision by the integrator

    // Test documents: Emergency termination means NOT generating SESS_TERM
    // and letting the integrator close TCP immediately with FIN
}

/// RFC 9174 §6.1: Clean vs. unclean termination
///
/// This test documents the difference between clean (with SESS_TERM) and
/// unclean (emergency, without SESS_TERM) termination at the protocol layer.
#[test]
fn test_rfc9174_clean_vs_unclean_termination() {
    // Clean termination: Send SESS_TERM, wait for reply/ack, then close TCP with FIN
    let mut clean_session = TcpclSession::new(SessionConfig {
        role: Role::Active,
        ..SessionConfig::default()
    })
    .unwrap();

    // Send contact header
    clean_session.send_contact_header().unwrap();
    let peer_contact = ContactHeader {
        version: 4,
        flags: 0,
    };
    clean_session.process_contact_header(&peer_contact).unwrap();

    // Clean termination: generate SESS_TERM
    let _sess_term = clean_session.send_session_term(0x00, None).unwrap();
    assert_eq!(clean_session.state(), SessionState::Ending);

    // Unclean termination: DON'T generate SESS_TERM for emergency cases
    // (e.g., RFC 9174 §6.1-160: termination before message sending completes)
    // The integrator simply closes TCP immediately

    // Both methods eventually result in TCP FIN (not RST) per §4.1-014
}
