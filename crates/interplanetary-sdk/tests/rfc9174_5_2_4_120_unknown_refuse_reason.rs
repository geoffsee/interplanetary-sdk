#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::{Role, SessionConfig, TcpclSession};

/// RFC 9174 §5.2.4-120: Unknown refusal reason codes normalized to UNKNOWN (0x00)
///
/// "If a transfer refusal has a reason code that is not decodable to the BPA,
/// the agent SHOULD treat the refusal as having a reason code of 'Unknown'."
#[test]
fn test_rfc9174_5_2_4_120_unknown_refuse_reason_normalized() {
    let mut sender = TcpclSession::new(SessionConfig {
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

    let mut receiver = TcpclSession::new(SessionConfig {
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
    let sender_contact = sender.send_contact_header().unwrap();
    receiver.process_contact_header(&sender_contact).unwrap();
    let receiver_contact = receiver.send_contact_header().unwrap();
    sender.process_contact_header(&receiver_contact).unwrap();

    let sender_init = sender.send_session_init().unwrap();
    let receiver_init = receiver.send_session_init().unwrap();
    receiver.process_session_init(&sender_init).unwrap();
    sender.process_session_init(&receiver_init).unwrap();

    // Sender starts a transfer
    let data = vec![0xAA; 100];
    let transfer_id = sender.start_transfer(data).unwrap();

    // RFC 9174 §5.2.4-120: Receiver sends XFER_REFUSE with invalid reason code
    // Test several invalid codes: 0x06, 0x07, 0xFF
    let invalid_reason_codes = [0x06, 0x07, 0x10, 0xFF];

    for invalid_reason in invalid_reason_codes {
        // Sender processes XFER_REFUSE with invalid reason code
        let result = sender.process_refuse(transfer_id, invalid_reason);

        // Should fail (transfer refused)
        assert!(result.is_err(), "Transfer should be refused");

        // The error message should contain normalized reason 0x00, not the invalid code
        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(
            error_msg.contains("reason 0") || error_msg.contains("reason: 0"),
            "Error should reference normalized reason 0x00 (UNKNOWN), got: {}",
            error_msg
        );

        // Restart transfer for next test
        let data = vec![0xBB; 100];
        sender.start_transfer(data).unwrap();
    }
}

/// RFC 9174 §5.2.4-120: Valid refusal reason codes preserved unchanged
#[test]
fn test_rfc9174_5_2_4_120_valid_refuse_reasons_unchanged() {
    let mut sender = TcpclSession::new(SessionConfig {
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

    let mut receiver = TcpclSession::new(SessionConfig {
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
    let sender_contact = sender.send_contact_header().unwrap();
    receiver.process_contact_header(&sender_contact).unwrap();
    let receiver_contact = receiver.send_contact_header().unwrap();
    sender.process_contact_header(&receiver_contact).unwrap();

    let sender_init = sender.send_session_init().unwrap();
    let receiver_init = receiver.send_session_init().unwrap();
    receiver.process_session_init(&sender_init).unwrap();
    sender.process_session_init(&receiver_init).unwrap();

    // Test valid reason codes 0x00-0x05
    let valid_codes = [
        (0x00, "reason 0"), // UNKNOWN
        (0x01, "reason 1"), // COMPLETED
        (0x02, "reason 2"), // NO_RESOURCES
        (0x03, "reason 3"), // RETRANSMIT
        (0x04, "reason 4"), // NOT_ACCEPTABLE
        (0x05, "reason 5"), // EXTENSION_FAILURE
    ];

    for (code, expected_text) in valid_codes {
        let data = vec![0xCC; 100];
        let transfer_id = sender.start_transfer(data).unwrap();

        let result = sender.process_refuse(transfer_id, code);
        assert!(
            result.is_err(),
            "Transfer should be refused with code {}",
            code
        );

        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(
            error_msg.contains(expected_text),
            "Error for code {} should contain '{}', got: {}",
            code,
            expected_text,
            error_msg
        );
    }
}
