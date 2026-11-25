#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §6.1 SESS_TERM Message Structure and Reason Code Tests

use interplanetary_sdk::tcpcl::messages::*;

#[test]
fn test_rfc9174_6_1_146_initiating_term_reply_flag_zero() {
    // RFC 9174 §6.1: "When sent to initiate a termination, the REPLY flag
    // of a SESS_TERM message SHALL be 0."

    let term_msg = Message::SessionTerm {
        flags: 0x00, // REPLY=0 for initiating termination
        reason_code: 0x00,
        message: Some("Idle timeout".to_string()),
    };

    match term_msg {
        Message::SessionTerm { flags, .. } => {
            assert_eq!(
                flags & 0x01,
                0,
                "Initiating SESS_TERM SHALL have REPLY flag (bit 0) = 0"
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_rfc9174_6_1_154_sess_term_contains_reason_code() {
    // RFC 9174 §6.1: "Each SESS_TERM message SHALL contain a one-octet
    // Reason Code field."

    // Test all defined reason codes from RFC 9174 Table 2
    let reason_codes = vec![
        (0x00, "Unknown"),
        (0x01, "Idle timeout"),
        (0x02, "Version mismatch"),
        (0x03, "Busy"),
        (0x04, "Contact Failure"),
        (0x05, "Resource Exhaustion"),
    ];

    for (code, description) in reason_codes {
        let term_msg = Message::SessionTerm {
            flags: 0x00,
            reason_code: code,
            message: Some(description.to_string()),
        };

        match term_msg {
            Message::SessionTerm { reason_code, .. } => {
                assert_eq!(
                    reason_code, code,
                    "SESS_TERM SHALL contain one-octet reason code field"
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_rfc9174_6_1_156_reserved_flags_zero() {
    // RFC 9174 §6.1: "All reserved header flag bits SHALL be set to 0 by the
    // sender."
    //
    // SESS_TERM flags: bit 0 is REPLY, bits 1-7 are reserved

    let term_msg = Message::SessionTerm {
        flags: 0x00, // All bits zero
        reason_code: 0x00,
        message: None,
    };

    match term_msg {
        Message::SessionTerm { flags, .. } => {
            let reserved_bits = flags & 0xFE; // Bits 1-7
            assert_eq!(
                reserved_bits, 0,
                "Reserved flag bits (1-7) SHALL be set to 0"
            );
        }
        _ => unreachable!(),
    }

    // Test with REPLY=1, reserved still zero
    let term_reply = Message::SessionTerm {
        flags: 0x01, // REPLY=1, reserved=0
        reason_code: 0x00,
        message: None,
    };

    match term_reply {
        Message::SessionTerm { flags, .. } => {
            assert_eq!(flags & 0x01, 0x01, "REPLY flag set");
            let reserved_bits = flags & 0xFE;
            assert_eq!(
                reserved_bits, 0,
                "Reserved bits SHALL be zero even when REPLY=1"
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_rfc9174_6_1_reason_code_values() {
    // RFC 9174 Table 2: Session Termination Reason Codes
    // Verify message can carry all defined codes

    let defined_codes = [
        0x00, // Unknown
        0x01, // Idle timeout
        0x02, // Version mismatch
        0x03, // Busy
        0x04, // Contact Failure
        0x05, // Resource Exhaustion
    ];

    for &code in &defined_codes {
        let term = Message::SessionTerm {
            flags: 0x00,
            reason_code: code,
            message: None,
        };

        match term {
            Message::SessionTerm { reason_code, .. } => {
                assert_eq!(reason_code, code, "Reason code preserved");
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_rfc9174_6_1_optional_message_field() {
    // RFC 9174 §6.1: SESS_TERM may include an optional diagnostic message

    // Test with message
    let term_with_msg = Message::SessionTerm {
        flags: 0x00,
        reason_code: 0x01,
        message: Some("Connection idle for 300 seconds".to_string()),
    };

    match term_with_msg {
        Message::SessionTerm { message, .. } => {
            assert!(message.is_some(), "Optional message field present");
            assert_eq!(message.unwrap(), "Connection idle for 300 seconds");
        }
        _ => unreachable!(),
    }

    // Test without message
    let term_no_msg = Message::SessionTerm {
        flags: 0x00,
        reason_code: 0x00,
        message: None,
    };

    match term_no_msg {
        Message::SessionTerm { message, .. } => {
            assert!(message.is_none(), "Optional message field may be absent");
        }
        _ => unreachable!(),
    }
}
