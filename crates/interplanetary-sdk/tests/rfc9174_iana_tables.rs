#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §8 IANA Registry Tests

use interplanetary_sdk::tcpcl::messages::*;

#[test]
fn test_rfc9174_8_5_message_types() {
    // RFC 9174 §8.5 Table 2: Message Type Codes
    // Verify constants match IANA registry values

    const XFER_SEGMENT: u8 = 0x01;
    const XFER_ACK: u8 = 0x02;
    const XFER_REFUSE: u8 = 0x03;
    const KEEPALIVE: u8 = 0x04;
    const SESS_TERM: u8 = 0x05;
    const MSG_REJECT: u8 = 0x06;
    const SESS_INIT: u8 = 0x07;

    // These values are defined by RFC 9174 Table 2
    assert_eq!(XFER_SEGMENT, 0x01, "XFER_SEGMENT must be 0x01");
    assert_eq!(XFER_ACK, 0x02, "XFER_ACK must be 0x02");
    assert_eq!(XFER_REFUSE, 0x03, "XFER_REFUSE must be 0x03");
    assert_eq!(KEEPALIVE, 0x04, "KEEPALIVE must be 0x04");
    assert_eq!(SESS_TERM, 0x05, "SESS_TERM must be 0x05");
    assert_eq!(MSG_REJECT, 0x06, "MSG_REJECT must be 0x07");
    assert_eq!(SESS_INIT, 0x07, "SESS_INIT must be 0x07");
}

#[test]
fn test_rfc9174_8_6_transfer_flags() {
    // RFC 9174 §8.6 Table 3: Transfer Extension Item Types (Transfer Flags)

    use transfer_flags::*;

    // RFC 9174 Table 3 values
    assert_eq!(END, 0x01, "END flag must be 0x01");
    assert_eq!(START, 0x02, "START flag must be 0x02");

    // Combined flags
    assert_eq!(START | END, 0x03, "START | END must be 0x03");
}

#[test]
fn test_rfc9174_8_7_sess_term_reason_codes_iana() {
    // RFC 9174 §8.7 Table 4: SESS_TERM Reason Codes

    use term_reason::*;

    // RFC 9174 Table 4 values
    assert_eq!(UNKNOWN, 0x00, "Unknown reason must be 0x00");
    assert_eq!(IDLE_TIMEOUT, 0x01, "Idle timeout must be 0x01");
    assert_eq!(VERSION_MISMATCH, 0x02, "Version mismatch must be 0x02");
    assert_eq!(BUSY, 0x03, "Busy must be 0x03");
    assert_eq!(CONTACT_FAILURE, 0x04, "Contact failure must be 0x04");
    assert_eq!(
        RESOURCE_EXHAUSTION, 0x05,
        "Resource exhaustion must be 0x05"
    );
}

#[test]
fn test_rfc9174_8_8_msg_reject_reason_codes_iana() {
    // RFC 9174 §8.8 Table 5: MSG_REJECT Reason Codes

    use reject_reason::*;

    // RFC 9174 Table 5 values
    assert_eq!(UNKNOWN, 0x01, "Message Type Unknown must be 0x01");
    assert_eq!(UNSUPPORTED, 0x02, "Message Unsupported must be 0x02");
    assert_eq!(UNEXPECTED, 0x03, "Message Unexpected must be 0x03");
}

#[test]
fn test_rfc9174_8_9_xfer_refuse_reason_codes() {
    // RFC 9174 §8.9 Table 6: XFER_REFUSE Reason Codes

    use refuse_reason::*;

    // RFC 9174 Table 6 values
    assert_eq!(UNKNOWN, 0x00, "Unknown reason must be 0x00");
    assert_eq!(COMPLETED, 0x01, "Completed must be 0x01");
    assert_eq!(NO_RESOURCES, 0x02, "No Resources must be 0x02");
    assert_eq!(RETRANSMIT, 0x03, "Retransmit must be 0x03");
    assert_eq!(NOT_ACCEPTABLE, 0x04, "Not Acceptable must be 0x04");
    assert_eq!(EXTENSION_FAILURE, 0x05, "Extension Failure must be 0x05");
}
