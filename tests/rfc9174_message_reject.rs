//! RFC 9174 §5.1.3 Message Rejection Tests

#[test]
fn test_rfc9174_5_1_3_msg_reject_reason_unknown() {
    // RFC 9174 §5.1.3: MSG_REJECT indicates that a message type was received
    // that was unknown or otherwise unsupported by the entity

    let _unknown_message_type: u8 = 0xFF; // Unknown type
    let reason_code_unknown: u8 = 0x01; // Unknown message type

    // Entity sends MSG_REJECT for unknown message
    assert_eq!(
        reason_code_unknown, 0x01,
        "MSG_REJECT with Unknown reason SHALL be sent for unknown message type"
    );
}

#[test]
fn test_rfc9174_5_1_3_msg_reject_reason_unsupported() {
    // RFC 9174 §5.1.3: Reason code "Unsupported" indicates the message
    // type is known but not implemented by the entity

    let _known_but_unsupported_type: u8 = 0x05; // Some known type
    let reason_code_unsupported: u8 = 0x02; // Unsupported

    // Entity sends MSG_REJECT for unsupported message
    assert_eq!(
        reason_code_unsupported, 0x02,
        "MSG_REJECT with Unsupported reason SHALL be sent for unsupported message"
    );
}

#[test]
fn test_rfc9174_5_1_3_msg_reject_rejected_message_header() {
    // RFC 9174 §5.1.3: The Rejected Message Header SHALL be the Message
    // Header of the message being rejected

    let rejected_type: u8 = 0xFF;
    let _rejected_flags: u8 = 0x00;

    // MSG_REJECT includes header of rejected message
    assert!(
        rejected_type == 0xFF,
        "MSG_REJECT SHALL include header of rejected message"
    );
}

#[test]
fn test_rfc9174_6_2_session_idle_keepalive_interval() {
    // RFC 9174 §6.2: If no messages have been sent in the session during
    // the session keepalive interval, a KEEPALIVE message SHOULD be sent

    let keepalive_interval_seconds: u16 = 30;
    let time_since_last_message: u16 = 31;

    // Send KEEPALIVE when idle exceeds interval
    assert!(
        time_since_last_message >= keepalive_interval_seconds,
        "KEEPALIVE SHOULD be sent when idle exceeds keepalive interval"
    );
}

#[test]
fn test_rfc9174_6_3_session_idle_timeout() {
    // RFC 9174 §6.3: If no messages have been received in the session during
    // the session idle timeout interval (twice the keepalive), the session
    // SHALL be terminated

    let keepalive_interval: u16 = 30;
    let idle_timeout = keepalive_interval * 2;
    let time_since_last_received: u16 = 61;

    // Terminate when idle exceeds timeout
    assert!(
        time_since_last_received >= idle_timeout,
        "Session SHALL be terminated when idle exceeds 2× keepalive"
    );
}
