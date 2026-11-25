#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §5.1.2 MSG_REJECT Tests
//!
//! Tests MSG_REJECT behavior per RFC 9174 Table 5

use interplanetary_sdk::tcpcl::{messages::*, session::*};

#[test]
fn test_rfc9174_5_1_2_emit_msg_reject_on_unknown_type() {
    // RFC 9174 §5.1.2: "the entity SHALL send a MSG_REJECT message with a reason code of 0x01 (Message Type Unknown)"

    let config = SessionConfig::default();
    let session = TcpclSession::new(config).unwrap();

    // Test unknown message types (0x08-0xFF are unassigned per RFC 9174 Table 1)
    // Known types: 0x01-0x07
    for unknown_type in [0x00, 0x08, 0x09, 0x10, 0xAA, 0xFF] {
        let result = session.process_raw_message_type(unknown_type);

        assert!(
            result.is_some(),
            "Unknown type 0x{:02X} should trigger MSG_REJECT",
            unknown_type
        );

        if let Some(msg) = result {
            let encoded = msg.encode();

            // Verify MSG_REJECT encoding per RFC 9174 §5.1.2
            assert_eq!(
                encoded[0], 0x06,
                "First byte must be MSG_REJECT type (0x06)"
            );
            assert_eq!(
                encoded[1], 0x01,
                "Reason code must be 0x01 (Message Type Unknown)"
            );
            assert_eq!(
                encoded[2], unknown_type,
                "Third byte must be rejected message header (0x{:02X})",
                unknown_type
            );
        }
    }
}

#[test]
fn test_rfc9174_5_1_2_known_types_not_rejected() {
    // RFC 9174 Table 1: Known message types should NOT trigger MSG_REJECT

    let config = SessionConfig::default();
    let session = TcpclSession::new(config).unwrap();

    // Known types from RFC 9174 Table 1
    let known_types = [
        0x01, // XFER_SEGMENT
        0x02, // XFER_ACK
        0x03, // XFER_REFUSE
        0x04, // KEEPALIVE
        0x05, // SESS_TERM
        0x06, // MSG_REJECT
        0x07, // SESS_INIT
    ];

    for known_type in known_types {
        let result = session.process_raw_message_type(known_type);

        assert!(
            result.is_none(),
            "Known type 0x{:02X} should NOT trigger MSG_REJECT",
            known_type
        );
    }
}

#[test]
fn test_rfc9174_5_1_2_msg_reject_reason_code_unknown() {
    // RFC 9174 §5.1.2 Table 5: Reason code 0x01 = Message Type Unknown

    let config = SessionConfig::default();
    let session = TcpclSession::new(config).unwrap();

    let unknown_type = 0xFF;
    let msg_reject = session
        .process_raw_message_type(unknown_type)
        .expect("Should generate MSG_REJECT");

    match msg_reject {
        Message::MessageReject {
            reason_code,
            rejected_message_header,
        } => {
            assert_eq!(reason_code, 0x01, "Reason code must be 0x01");
            assert_eq!(
                rejected_message_header, unknown_type,
                "Rejected header must match input"
            );
        }
        _ => panic!("Expected MessageReject variant"),
    }
}
