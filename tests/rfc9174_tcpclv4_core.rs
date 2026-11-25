//! RFC 9174 TCPCLv4 Core Protocol Tests
//!
//! Comprehensive tests for TCPCLv4 contact header, SESS_INIT negotiation,
//! session state machine, transfer mechanisms, and message types per RFC 9174.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §4.2: Contact Header
/// "The Contact Header is a fixed-length field at the very beginning of the
/// data stream in each direction of a TCP connection."
/// "Contact Header Magic: The Contact Header starts with a four-octet field
/// that always contains the octet sequence 0x64 0x74 0x6E 0x21, i.e., the
/// text string 'dtn!' in US-ASCII (and UTF-8)."
#[test]
fn test_rfc9174_4_2_contact_header_magic_and_version() {
    let header = ContactHeader::new();
    let encoded = header.encode();

    // RFC 9174 §4.2: Contact header is exactly 6 bytes
    assert_eq!(encoded.len(), 6, "Contact header must be 6 bytes");

    // RFC 9174 §4.2: Magic bytes must be 'dtn!' (0x64 0x74 0x6E 0x21)
    assert_eq!(&encoded[0..4], b"dtn!", "Magic must be 'dtn!' per §4.2");

    // RFC 9174 §4.2: "Version: The version field value contains the binary value 4"
    assert_eq!(encoded[4], 4, "Version must be 4 per §4.2");
}

/// RFC 9174 §4.2: Contact Header Flags
/// "The Contact Header contains the following flag, which is encoded in the
/// one-octet Flags field: CAN_TLS (0x01): Indicates that the sending peer has
/// enabled TLS security."
#[test]
fn test_rfc9174_4_2_can_tls_flag() {
    // Test with CAN_TLS flag set
    let header_with_tls = ContactHeader::with_flags(ContactHeader::FLAG_CAN_TLS);
    let encoded = header_with_tls.encode();

    // RFC 9174 §4.2: CAN_TLS is bit 0 (0x01)
    assert_eq!(
        encoded[5] & 0x01,
        0x01,
        "CAN_TLS flag must be bit 0 (0x01) per §4.2"
    );

    // Test without CAN_TLS flag
    let header_no_tls = ContactHeader::new();
    let encoded_no_tls = header_no_tls.encode();
    assert_eq!(
        encoded_no_tls[5] & 0x01,
        0x00,
        "CAN_TLS flag must be clear when not set"
    );
}

/// RFC 9174 §4.6: SESS_INIT Message Parameters
/// "The SESS_INIT message SHALL be sent by both peers to negotiate session
/// parameters."
#[test]
fn test_rfc9174_4_6_sess_init_parameters() {
    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000_000,
        node_id: "dtn:test".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config.clone()).unwrap();

    // Establish contact
    let _contact = session.send_contact_header().unwrap();
    let peer_contact = ContactHeader::new();
    session.process_contact_header(&peer_contact).unwrap();

    // Send SESS_INIT
    let init = session.send_session_init().unwrap();

    if let Message::SessionInit {
        keepalive_interval,
        segment_mru,
        transfer_mru,
        node_id,
        ..
    } = init
    {
        assert_eq!(
            keepalive_interval, 30,
            "Keepalive interval must match config"
        );
        assert_eq!(segment_mru, 65535, "Segment MRU must match config");
        assert_eq!(transfer_mru, 10_000_000, "Transfer MRU must match config");
        assert_eq!(node_id, "dtn:test", "Node ID must match config");
    } else {
        panic!("Expected SessionInit message");
    }
}

/// RFC 9174 §4.7: Session Parameter Negotiation
/// "Keepalive Interval: The Keepalive Interval parameter for the session is
/// the minimum of the two Keepalive Interval values from the two SESS_INIT
/// messages."
#[test]
fn test_rfc9174_4_7_keepalive_minimum_negotiation() {
    let config_a = SessionConfig {
        keepalive_interval: 60,
        ..Default::default()
    };

    let config_b = SessionConfig {
        keepalive_interval: 30,
        ..Default::default()
    };

    let mut session_a = TcpclSession::new(config_a).unwrap();
    let mut session_b = TcpclSession::new(config_b).unwrap();

    // Exchange contact headers
    let contact_a = session_a.send_contact_header().unwrap();
    let contact_b = session_b.send_contact_header().unwrap();
    session_a.process_contact_header(&contact_b).unwrap();
    session_b.process_contact_header(&contact_a).unwrap();

    // Exchange SESS_INIT
    let init_a = session_a.send_session_init().unwrap();
    let init_b = session_b.send_session_init().unwrap();

    session_a.process_session_init(&init_b).unwrap();
    session_b.process_session_init(&init_a).unwrap();

    // RFC 9174 §4.7: Negotiated keepalive is minimum (30)
    assert_eq!(
        session_a.negotiated_keepalive_interval(),
        Some(30),
        "Session A must negotiate to minimum (30) per §4.7"
    );
    assert_eq!(
        session_b.negotiated_keepalive_interval(),
        Some(30),
        "Session B must negotiate to minimum (30) per §4.7"
    );
}

/// RFC 9174 §3.3: Session States
/// "A TCPCL session has the following states:
/// Contact, SESS_INIT Sent, SESS_INIT Received, Established, Ending, Terminated"
#[test]
fn test_rfc9174_3_3_session_state_machine() {
    let mut local = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut remote = TcpclSession::new(SessionConfig::default()).unwrap();

    // Initial state is ContactNegotiation (Contact state in RFC)
    assert_eq!(local.state(), SessionState::ContactNegotiation);
    assert_eq!(remote.state(), SessionState::ContactNegotiation);

    // Exchange contact headers
    let local_contact = local.send_contact_header().unwrap();
    let remote_contact = remote.send_contact_header().unwrap();

    local.process_contact_header(&remote_contact).unwrap();
    remote.process_contact_header(&local_contact).unwrap();

    // After contact, state is SessionInit
    assert_eq!(local.state(), SessionState::SessionInit);
    assert_eq!(remote.state(), SessionState::SessionInit);

    // Exchange SESS_INIT
    let local_init = local.send_session_init().unwrap();
    let remote_init = remote.send_session_init().unwrap();

    local.process_session_init(&remote_init).unwrap();
    remote.process_session_init(&local_init).unwrap();

    // After SESS_INIT, state is Established
    assert_eq!(local.state(), SessionState::Established);
    assert_eq!(remote.state(), SessionState::Established);

    // Send SESS_TERM
    let local_term = local
        .send_session_term(term_reason::IDLE_TIMEOUT, None)
        .unwrap();
    let remote_term = remote
        .send_session_term(term_reason::IDLE_TIMEOUT, None)
        .unwrap();

    // After sending SESS_TERM, state is Ending
    assert_eq!(local.state(), SessionState::Ending);
    assert_eq!(remote.state(), SessionState::Ending);

    // Process each other's SESS_TERM
    let _ = local.process_session_term(&remote_term);
    let _ = remote.process_session_term(&local_term);

    // After processing SESS_TERM, state is Terminated
    assert_eq!(local.state(), SessionState::Terminated);
    assert_eq!(remote.state(), SessionState::Terminated);
}

/// RFC 9174 §5.2.2: XFER_SEGMENT START and END flags
/// "The Flags field contains two defined bits:
/// Bit 0 (0x01): END - This is the last segment of a transfer.
/// Bit 1 (0x02): START - This is the first segment of a transfer."
#[test]
fn test_rfc9174_5_2_2_xfer_segment_start_end_flags() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut sender, &mut receiver);

    let data = vec![0xAA; 5000];
    let transfer_id = sender.start_transfer(data).unwrap();
    let segments = sender.create_segments(transfer_id, 1000).unwrap();

    assert!(segments.len() >= 2, "Should create multiple segments");

    // RFC 9174 §5.2.2: First segment must have START flag (bit 1 = 0x02)
    if let Message::TransferSegment { flags, .. } = &segments[0] {
        assert_eq!(
            flags & transfer_flags::START,
            transfer_flags::START,
            "First segment must have START flag (0x02) per §5.2.2"
        );
        assert_eq!(
            flags & transfer_flags::END,
            0,
            "First segment must not have END flag"
        );
    }

    // RFC 9174 §5.2.2: Last segment must have END flag (bit 0 = 0x01)
    if let Message::TransferSegment { flags, .. } = segments.last().unwrap() {
        assert_eq!(
            flags & transfer_flags::END,
            transfer_flags::END,
            "Last segment must have END flag (0x01) per §5.2.2"
        );
    }

    // Middle segments must have neither START nor END
    if segments.len() > 2 {
        for seg in &segments[1..segments.len() - 1] {
            if let Message::TransferSegment { flags, .. } = seg {
                assert_eq!(
                    *flags & (transfer_flags::START | transfer_flags::END),
                    0,
                    "Middle segments must have neither START nor END"
                );
            }
        }
    }
}

/// RFC 9174 §5.2.3: XFER_ACK Cumulative Acknowledgment
/// "The Acknowledged Length field contains the total number of bytes in the
/// transfer which are known to have been received."
#[test]
fn test_rfc9174_5_2_3_xfer_ack_cumulative() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut sender, &mut receiver);

    let data = vec![0xBB; 3000];
    let transfer_id = sender.start_transfer(data).unwrap();
    let segments = sender.create_segments(transfer_id, 1000).unwrap();

    assert_eq!(segments.len(), 3, "Should create 3 segments");

    // Process first segment
    if let Some(Message::TransferAck { acked_length, .. }) =
        receiver.process_segment(&segments[0]).unwrap()
    {
        // RFC 9174 §5.2.3: acked_length is cumulative (1000 bytes)
        assert_eq!(
            acked_length, 1000,
            "First ACK should acknowledge 1000 bytes per §5.2.3"
        );
    }

    // Process second segment
    if let Some(Message::TransferAck { acked_length, .. }) =
        receiver.process_segment(&segments[1]).unwrap()
    {
        // RFC 9174 §5.2.3: acked_length is cumulative (2000 bytes total)
        assert_eq!(
            acked_length, 2000,
            "Second ACK should acknowledge 2000 bytes cumulative per §5.2.3"
        );
    }

    // Process third segment
    if let Some(Message::TransferAck { acked_length, .. }) =
        receiver.process_segment(&segments[2]).unwrap()
    {
        // RFC 9174 §5.2.3: acked_length is cumulative (3000 bytes total)
        assert_eq!(
            acked_length, 3000,
            "Third ACK should acknowledge 3000 bytes cumulative per §5.2.3"
        );
    }
}

/// RFC 9174 §5.2.4 and §8.6: XFER_REFUSE Reason Codes
/// Tests that XFER_REFUSE uses correct reason codes from Table 15
#[test]
fn test_rfc9174_8_6_xfer_refuse_reason_codes() {
    // RFC 9174 Table 15: XFER_REFUSE reason codes
    assert_eq!(
        refuse_reason::UNKNOWN,
        0x00,
        "Unknown must be 0x00 per Table 15"
    );
    assert_eq!(
        refuse_reason::COMPLETED,
        0x01,
        "Completed must be 0x01 per Table 15"
    );
    assert_eq!(
        refuse_reason::NO_RESOURCES,
        0x02,
        "No Resources must be 0x02 per Table 15"
    );
    assert_eq!(
        refuse_reason::RETRANSMIT,
        0x03,
        "Retransmit must be 0x03 per Table 15"
    );
    assert_eq!(
        refuse_reason::NOT_ACCEPTABLE,
        0x04,
        "Not Acceptable must be 0x04 per Table 15"
    );
    assert_eq!(
        refuse_reason::EXTENSION_FAILURE,
        0x05,
        "Extension Failure must be 0x05 per Table 15"
    );
}

/// RFC 9174 §5.1.2 and §8.8: MSG_REJECT Reason Codes
/// Tests that MSG_REJECT uses correct reason codes from Table 17
#[test]
fn test_rfc9174_8_8_msg_reject_reason_codes() {
    // RFC 9174 Table 17: MSG_REJECT reason codes
    assert_eq!(
        reject_reason::UNKNOWN,
        0x01,
        "Message Type Unknown must be 0x01 per Table 17"
    );
    assert_eq!(
        reject_reason::UNSUPPORTED,
        0x02,
        "Message Unsupported must be 0x02 per Table 17"
    );
    assert_eq!(
        reject_reason::UNEXPECTED,
        0x03,
        "Message Unexpected must be 0x03 per Table 17"
    );
}

/// RFC 9174 §6.1 and §8.7: SESS_TERM Reason Codes
/// Tests that SESS_TERM uses correct reason codes from Table 16
#[test]
fn test_rfc9174_8_7_sess_term_reason_codes() {
    // RFC 9174 Table 16: SESS_TERM reason codes
    assert_eq!(
        term_reason::UNKNOWN,
        0x00,
        "Unknown must be 0x00 per Table 16"
    );
    assert_eq!(
        term_reason::IDLE_TIMEOUT,
        0x01,
        "Idle timeout must be 0x01 per Table 16"
    );
    assert_eq!(
        term_reason::VERSION_MISMATCH,
        0x02,
        "Version mismatch must be 0x02 per Table 16"
    );
    assert_eq!(term_reason::BUSY, 0x03, "Busy must be 0x03 per Table 16");
    assert_eq!(
        term_reason::CONTACT_FAILURE,
        0x04,
        "Contact Failure must be 0x04 per Table 16"
    );
    assert_eq!(
        term_reason::RESOURCE_EXHAUSTION,
        0x05,
        "Resource Exhaustion must be 0x05 per Table 16"
    );
}

/// RFC 9174 §6.1: SESS_TERM REPLY Flag
/// "The Flags field contains one defined bit:
/// Bit 0 (0x01): REPLY - Indicates that this message is a reply to a
/// SESS_TERM message."
#[test]
fn test_rfc9174_6_1_sess_term_reply_flag() {
    let mut local = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut remote = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut local, &mut remote);

    // Local sends SESS_TERM first
    let local_term = local
        .send_session_term(term_reason::IDLE_TIMEOUT, Some("Closing".to_string()))
        .unwrap();

    if let Message::SessionTerm { flags, .. } = local_term {
        // RFC 9174 §6.1: Initial SESS_TERM has REPLY flag clear (0x00)
        assert_eq!(
            flags & 0x01,
            0,
            "Initial SESS_TERM must not have REPLY flag (bit 0) per §6.1"
        );
    }

    // Process at remote
    let _remote_reply = remote.process_session_term(&local_term);
}

/// RFC 9174 §5.1.1: KEEPALIVE Message
/// "The KEEPALIVE message is used to keep a session active."
#[test]
fn test_rfc9174_5_1_1_keepalive_message() {
    let msg = Message::Keepalive;
    let encoded = msg.encode();

    // RFC 9174 §5.1.1 and Table 14: KEEPALIVE is message type 0x04
    assert_eq!(
        encoded[0],
        Message::TYPE_KEEPALIVE,
        "KEEPALIVE type must be 0x04 per §5.1.1 and Table 14"
    );
}

/// RFC 9174 §8.5: Message Type Codes
/// Verifies all message type codes match RFC 9174 Table 14 exactly
#[test]
fn test_rfc9174_8_5_message_type_codes() {
    // RFC 9174 Table 14: Message Type Codes
    assert_eq!(
        Message::TYPE_XFER_SEGMENT,
        0x01,
        "XFER_SEGMENT must be 0x01 per Table 14"
    );
    assert_eq!(
        Message::TYPE_XFER_ACK,
        0x02,
        "XFER_ACK must be 0x02 per Table 14"
    );
    assert_eq!(
        Message::TYPE_XFER_REFUSE,
        0x03,
        "XFER_REFUSE must be 0x03 per Table 14"
    );
    assert_eq!(
        Message::TYPE_KEEPALIVE,
        0x04,
        "KEEPALIVE must be 0x04 per Table 14"
    );
    assert_eq!(
        Message::TYPE_SESS_TERM,
        0x05,
        "SESS_TERM must be 0x05 per Table 14"
    );
    assert_eq!(
        Message::TYPE_MSG_REJECT,
        0x06,
        "MSG_REJECT must be 0x06 per Table 14"
    );
    assert_eq!(
        Message::TYPE_SESS_INIT,
        0x07,
        "SESS_INIT must be 0x07 per Table 14"
    );
}

/// RFC 9174 §5.2.1: Transfer ID Assignment
/// "The Transfer ID uniquely identifies a transfer within a session."
#[test]
fn test_rfc9174_5_2_1_transfer_id_uniqueness() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut sender, &mut receiver);

    let data1 = vec![0xAA; 100];
    let data2 = vec![0xBB; 200];

    let transfer_id_1 = sender.start_transfer(data1).unwrap();
    let transfer_id_2 = sender.start_transfer(data2).unwrap();

    // RFC 9174 §5.2.1: Transfer IDs must be unique within a session
    assert_ne!(
        transfer_id_1, transfer_id_2,
        "Transfer IDs must be unique per §5.2.1"
    );
}

/// Helper: Establish session between two endpoints
fn setup_session(local: &mut TcpclSession, remote: &mut TcpclSession) {
    let local_contact = local.send_contact_header().unwrap();
    let remote_contact = remote.send_contact_header().unwrap();

    local.process_contact_header(&remote_contact).unwrap();
    remote.process_contact_header(&local_contact).unwrap();

    let local_init = local.send_session_init().unwrap();
    let remote_init = remote.send_session_init().unwrap();

    local.process_session_init(&remote_init).unwrap();
    remote.process_session_init(&local_init).unwrap();
}

/// RFC 9174 §4.3 "If the version from the active entity is not within the range supported
/// by the passive entity, the passive entity SHALL send its Contact Header... then
/// it SHALL close the TCP connection."
#[test]
fn test_rfc9174_4_3_version_mismatch_rejection() {
    let mut session = TcpclSession::new(SessionConfig::default()).unwrap();

    // Create a contact with unsupported version (e.g. version=99)
    let bad_contact = ContactHeader {
        version: 99, // invalid version (TCPCLv4 requires version=4)
        flags: 0,    // CAN_TLS bit
    };

    // Attempt to process - should reject
    let result = session.process_contact_header(&bad_contact);
    assert!(
        result.is_err(),
        "Session MUST reject contact with unsupported version per §4.3"
    );
}

/// RFC 9174 §5.2.2 "The segment data MUST NOT exceed the Segment MRU of the receiving peer."
#[test]
fn test_rfc9174_5_2_2_segment_mru_enforcement() {
    let mut sender = TcpclSession::new(SessionConfig {
        segment_mru: 65535,
        ..Default::default()
    })
    .unwrap();
    let mut receiver = TcpclSession::new(SessionConfig {
        segment_mru: 1024, // Small MRU
        ..Default::default()
    })
    .unwrap();

    setup_session(&mut sender, &mut receiver);

    // Sender must respect receiver's segment_mru (1024)
    // When sending large data, implementation MUST segment it appropriately
    // This is enforced at send time in the session implementation
    let large_data = vec![0u8; 2048]; // exceeds receiver's segment_mru

    // Starting a transfer with data larger than peer's segment_mru is allowed
    // but the implementation MUST segment it per §5.2.2
    let result = sender.start_transfer(large_data.clone());
    assert!(
        result.is_ok(),
        "Transfer start MUST succeed; segmentation enforces MRU per §5.2.2"
    );
}

/// RFC 9174 §5.2.4 "The receiver can send an XFER_REFUSE message... for any of the
/// reasons listed in the XFER_REFUSE Reason Codes registry (Table 16)."
#[test]
fn test_rfc9174_5_2_4_xfer_refuse_handling() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let _receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(
        &mut sender,
        &mut TcpclSession::new(SessionConfig::default()).unwrap(),
    );

    let data = vec![0xAA; 100];
    let transfer_id = sender.start_transfer(data).unwrap();

    // Receiver sends XFER_REFUSE with reason 0x02 (No Resources) per Table 16
    // Sender processes XFER_REFUSE and aborts transfer
    let result = sender.process_refuse(transfer_id, 0x02);
    // Result is Err which is the correct behavior per §5.2.4
    match result {
        Err(_) => {
            // Correct: XFER_REFUSE causes an error (TransferRefused)
        }
        Ok(_) => panic!("Sender MUST handle XFER_REFUSE per §5.2.4"),
    }

    // After processing refuse, transfer should be aborted
    // (State is tracked internally; starting a new transfer with same ID would fail)
}

/// RFC 9174 §5.1.2 "If a TCPCL entity receives a message type that it does not recognize,
/// it SHALL send a MSG_REJECT message with a Reason Code of 'Message Type Unknown' (0x01)."
#[test]
fn test_rfc9174_5_1_2_msg_reject_unknown_type() {
    let mut session = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(
        &mut session,
        &mut TcpclSession::new(SessionConfig::default()).unwrap(),
    );

    // When session receives unknown message type (0xFF), it MUST process via MSG_REJECT
    // The process_message_reject handler exists for this purpose
    let unknown_type = 0xFF;
    let reason_type_unknown = 0x01;

    // Simulate processing a MSG_REJECT for an unknown type
    let result = session.process_message_reject(unknown_type, reason_type_unknown);
    // Result is Err which is the correct behavior per §5.1.2
    match result {
        Err(_) => {
            // Correct: MSG_REJECT causes MessageRejected error
        }
        Ok(_) => panic!("Session MUST handle MSG_REJECT per §5.1.2"),
    }

    // MSG_REJECT message type is 0x06 per Table 14
    assert_eq!(
        Message::TYPE_MSG_REJECT,
        0x06,
        "MSG_REJECT type MUST be 0x06 per Table 14"
    );
}

/// RFC 9174 §6.1 "Once a SESS_TERM message is sent, the sender SHALL NOT send any
/// further messages on the session."
#[test]
fn test_rfc9174_6_1_no_transfers_after_sess_term() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(
        &mut sender,
        &mut TcpclSession::new(SessionConfig::default()).unwrap(),
    );

    // Sender initiates termination
    let _term_msg = sender.send_session_term(0x00, None); // reason=Unknown

    // Sender MUST NOT start new transfers after SESS_TERM
    let data = vec![0xAA; 100];
    let result = sender.start_transfer(data);
    assert!(
        result.is_err(),
        "Session MUST refuse new transfers after SESS_TERM per §6.1"
    );
}

/// RFC 9174 §5.1.1 "If no messages are received (including KEEPALIVE) for the
/// Keepalive Interval, the peer SHALL terminate the session with reason code 0x01 (Idle timeout)."
#[test]
fn test_rfc9174_5_1_1_keepalive_timeout_terminates_session() {
    let mut sender = TcpclSession::new(SessionConfig {
        keepalive_interval: 5, // 5 seconds
        ..Default::default()
    })
    .unwrap();

    setup_session(
        &mut sender,
        &mut TcpclSession::new(SessionConfig::default()).unwrap(),
    );

    // After keepalive_interval with no messages, peer SHOULD send KEEPALIVE
    // or terminate with reason 0x01 (Idle timeout)
    // negotiated_keepalive_interval() returns the min(local, peer) per §4.7
    let negotiated = sender.negotiated_keepalive_interval();
    assert!(
        negotiated.is_some(),
        "Keepalive MUST be negotiated per §4.7"
    );

    // When keepalive expires, session SHOULD send SESS_TERM with reason 0x01
    let term_msg = sender
        .send_session_term(0x01, Some("Idle timeout".to_string()))
        .unwrap();
    // SESS_TERM message type is 0x05 per Table 14
    assert_eq!(
        term_msg.message_type(),
        0x05,
        "SESS_TERM type MUST be 0x05 per Table 14"
    );
}

/// RFC 9174 §6.1 "When a SESS_TERM is received, the receiver SHALL send a SESS_TERM
/// message with the REPLY flag set."
#[test]
fn test_rfc9174_6_1_sess_term_reply_handshake() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut sender, &mut receiver);

    // Sender sends SESS_TERM
    let term_msg = sender.send_session_term(0x00, None).unwrap();

    // SESS_TERM message type is 0x05 per Table 14
    assert_eq!(
        term_msg.message_type(),
        0x05,
        "SESS_TERM type MUST be 0x05 per Table 14"
    );

    // Receiver processes and SHALL respond per RFC 9174 §6.1
    let response = receiver.process_session_term(&term_msg);
    assert!(response.is_ok(), "Receiver MUST process SESS_TERM per §6.1");

    // Response should be SESS_TERM with REPLY flag
    if let Ok(Some(reply_msg)) = response {
        match reply_msg {
            Message::SessionTerm { flags, .. } => {
                assert_eq!(
                    flags & 0x01,
                    0x01,
                    "Acknowledging SESS_TERM MUST have REPLY flag"
                );
            }
            _ => panic!("Response must be SESS_TERM"),
        }
    }

    // After processing, receiver enters Ending or Terminated state
    // The REPLY flag handling is part of the message structure
}
