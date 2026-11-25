#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::{Message, Role, SessionConfig, SessionState, TcpclSession};

/// RFC 9174 §6.1-155: Unknown termination reason codes normalized to UNKNOWN (0x00)
///
/// "If a termination has a reason code that is not decodable to the BPA,
/// the agent SHOULD treat the termination as having a reason code of 'Unknown'."
#[test]
fn test_rfc9174_6_1_155_unknown_term_reason_normalized() {
    let mut local = TcpclSession::new(SessionConfig {
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

    let mut remote = TcpclSession::new(SessionConfig {
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

    // Establish session
    let local_contact = local.send_contact_header().unwrap();
    remote.process_contact_header(&local_contact).unwrap();
    let remote_contact = remote.send_contact_header().unwrap();
    local.process_contact_header(&remote_contact).unwrap();

    let local_init = local.send_session_init().unwrap();
    let remote_init = remote.send_session_init().unwrap();
    remote.process_session_init(&local_init).unwrap();
    local.process_session_init(&remote_init).unwrap();

    assert_eq!(local.state(), SessionState::Established);

    // Create SESS_TERM with invalid reason code 0xFF
    let invalid_term = Message::SessionTerm {
        flags: 0x00,       // Not REPLY
        reason_code: 0xFF, // Invalid reason code (> 0x05)
        message: None,
    };

    // Process the termination with invalid reason
    // The reply should normalize the invalid reason to 0x00 (UNKNOWN)
    let reply = local.process_session_term(&invalid_term).unwrap();

    // Should generate a reply SESS_TERM
    assert!(reply.is_some(), "Should generate reply to SESS_TERM");

    let reply_msg = reply.unwrap();
    let reply_bytes = reply_msg.encode();

    // Verify reply SESS_TERM uses normalized reason 0x00
    assert_eq!(
        reply_bytes[0], 0x05,
        "Should be SESS_TERM message type (0x05)"
    );
    assert_eq!(
        reply_bytes[1] & 0x01,
        0x01,
        "REPLY flag should be set in response"
    );
    assert_eq!(
        reply_bytes[2], 0x00,
        "Invalid reason 0xFF should be normalized to 0x00 (UNKNOWN)"
    );
}

/// RFC 9174 §6.1-155: Test various invalid termination reason codes
#[test]
fn test_rfc9174_6_1_155_various_invalid_reasons() {
    let invalid_codes = [0x06, 0x07, 0x10, 0xAA, 0xFF];

    for invalid_reason in invalid_codes {
        let mut local = TcpclSession::new(SessionConfig {
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

        let mut remote = TcpclSession::new(SessionConfig {
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

        // Establish session
        let local_contact = local.send_contact_header().unwrap();
        remote.process_contact_header(&local_contact).unwrap();
        let remote_contact = remote.send_contact_header().unwrap();
        local.process_contact_header(&remote_contact).unwrap();

        let local_init = local.send_session_init().unwrap();
        let remote_init = remote.send_session_init().unwrap();
        remote.process_session_init(&local_init).unwrap();
        local.process_session_init(&remote_init).unwrap();

        // Create SESS_TERM with invalid reason code
        let invalid_term = Message::SessionTerm {
            flags: 0x00,
            reason_code: invalid_reason,
            message: None,
        };

        // Process termination - should normalize invalid reason to 0x00
        let reply = local.process_session_term(&invalid_term).unwrap();
        assert!(reply.is_some(), "Should generate reply");

        let reply_bytes = reply.unwrap().encode();

        // All invalid codes should be normalized to 0x00 in the reply
        assert_eq!(
            reply_bytes[2], 0x00,
            "Invalid reason 0x{:02X} should be normalized to 0x00",
            invalid_reason
        );
    }
}

/// RFC 9174 §6.1-155: Valid termination reason codes preserved unchanged
#[test]
fn test_rfc9174_6_1_155_valid_term_reasons_unchanged() {
    let valid_codes = [
        0x00, // UNKNOWN
        0x01, // IDLE_TIMEOUT
        0x02, // VERSION_MISMATCH
        0x03, // BUSY
        0x04, // CONTACT_FAILURE
        0x05, // RESOURCE_EXHAUSTION
    ];

    for valid_reason in valid_codes {
        let mut local = TcpclSession::new(SessionConfig {
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

        let mut remote = TcpclSession::new(SessionConfig {
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

        // Establish session
        let local_contact = local.send_contact_header().unwrap();
        remote.process_contact_header(&local_contact).unwrap();
        let remote_contact = remote.send_contact_header().unwrap();
        local.process_contact_header(&remote_contact).unwrap();

        let local_init = local.send_session_init().unwrap();
        let remote_init = remote.send_session_init().unwrap();
        remote.process_session_init(&local_init).unwrap();
        local.process_session_init(&remote_init).unwrap();

        // Create SESS_TERM with valid reason code
        let term = Message::SessionTerm {
            flags: 0x00,
            reason_code: valid_reason,
            message: None,
        };

        // Process termination - valid codes should be preserved
        let reply = local.process_session_term(&term).unwrap();
        assert!(reply.is_some(), "Should generate reply");

        let reply_bytes = reply.unwrap().encode();

        // Valid codes should be preserved unchanged in the reply
        assert_eq!(
            reply_bytes[2], valid_reason,
            "Valid reason 0x{:02X} should be preserved",
            valid_reason
        );
    }
}
