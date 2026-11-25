//! RFC 9174 §4.1-002: TCP connection required before TCPCL session
//!
//! "To establish a TCPCL session, an entity MUST first establish a TCP
//! connection with the intended peer entity, typically by using the services
//! provided by the operating system."

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §4.1-002: Transfers require established session (and thus connection)
///
/// This test verifies that bundle transfers cannot occur without an established
/// session, which in turn requires a TCP connection (represented by TcpclSession).
#[test]
fn test_rfc9174_4_1_002_transfers_require_established_session() {
    let mut session = TcpclSession::new(SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "ipn:2.1".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    })
    .unwrap();

    // Attempt to start a transfer before session is established
    // Session is in ContactNegotiation, not yet Established
    assert_eq!(session.state(), SessionState::ContactNegotiation);

    let data = vec![0x01, 0x02, 0x03];
    let result = session.start_transfer(data);

    // RFC 9174 §4.1: Transfers require established session
    // which requires TCP connection first
    assert!(
        result.is_err(),
        "Transfer must fail before session establishment (which requires TCP connection)"
    );
}
