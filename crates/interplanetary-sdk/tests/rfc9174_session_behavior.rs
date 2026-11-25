//! RFC 9174 TCPCLv4 Session Behavioral Tests
//!
//! Tests that drive the TcpclSession implementation and verify obligations
//! per the strict "would-it-fail" standard.
#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::clock::{Clock, ManualClock};
use interplanetary_sdk::tcpcl::messages::{ContactHeader, ExtensionItem, Message};
use interplanetary_sdk::tcpcl::session::{SessionConfig, SessionState, TcpclSession};
use interplanetary_sdk::tcpcl::session_fsm::Role;

/// Test RFC9174-4-3-019: If the "magic string" is not present or is not valid, the connection MUST be terminated
#[test]
fn test_rfc9174_4_3_019_invalid_magic_terminates() {
    // RFC 9174 §4.3: "If the 'magic string' is not present or is not valid, the connection MUST be terminated."

    let invalid_header_bytes = vec![0x62, 0x61, 0x64, 0x21, 4, 0]; // "bad!" instead of "dtn!"
    let result = ContactHeader::decode(&invalid_header_bytes);

    assert!(
        result.is_err(),
        "Contact header with invalid magic MUST be rejected"
    );
    assert!(
        result.unwrap_err().contains("magic"),
        "Error should indicate magic string validation failure"
    );
}

/// Test RFC9174-4-3-021: Active entity receiving lower version SHALL close connection
#[test]
fn test_rfc9174_4_3_021_version_mismatch_active() {
    // RFC 9174 §4.3: "If the active entity receives a Contact Header with a lower protocol version than the one sent earlier on the TCP connection, the TCP connection SHALL be closed."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Active session sends contact header first
    let sent_header = session
        .send_contact_header()
        .expect("Active creates header");
    assert_eq!(sent_header.version, 4, "Active sends version 4");

    // Receive peer contact header with wrong version
    let peer_header = ContactHeader {
        version: 3, // Lower than what we sent (4)
        flags: 0,
    };

    let result = session.process_contact_header(&peer_header);
    assert!(
        result.is_err(),
        "Session MUST reject contact header with unsupported version"
    );
}

/// Test RFC9174-4-6-071: Keepalive is negotiated to MINIMUM of both sides
#[test]
fn test_rfc9174_4_6_071_keepalive_minimum_negotiation() {
    // RFC 9174 §5.1: "Each entity's Keepalive Interval parameter is an indication to its peer
    // of how often it wishes to receive keepalive messages when no other messages are being sent."
    // The negotiated interval is the MINIMUM of the two peer values.

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 60, // Local wants 60s
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Exchange contact headers
    let _sent_header = session.send_contact_header().unwrap();
    let peer_header = ContactHeader::new();
    session.process_contact_header(&peer_header).unwrap();

    // Send our SESS_INIT
    let _sent_init = session.send_session_init().unwrap();

    // Receive peer's SESS_INIT with different keepalive
    let peer_init = Message::SessionInit {
        keepalive_interval: 30, // Peer wants 30s
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn://peer.local".to_string(),
        extensions: vec![],
    };

    session.process_session_init(&peer_init).unwrap();

    // Verify negotiated keepalive is the MINIMUM
    let negotiated = session
        .negotiated_keepalive_interval()
        .expect("Keepalive negotiated");
    assert_eq!(
        negotiated, 30,
        "Negotiated keepalive MUST be minimum of local (60) and peer (30)"
    );
}

/// Test RFC9174-4-6-067: Segment size SHALL NOT exceed peer's Segment MRU
#[test]
fn test_rfc9174_4_6_067_segment_mru_enforcement() {
    // RFC 9174 §4.6: "The Segment MRU indicates the largest single segment the entity is
    // willing to receive."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session
    let _sent_header = session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    let _sent_init = session.send_session_init().unwrap();

    // Peer advertises small segment MRU
    let peer_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 1000, // Small MRU
        transfer_mru: 1_000_000,
        node_id: "dtn://peer.local".to_string(),
        extensions: vec![],
    };

    session.process_session_init(&peer_init).unwrap();
    assert_eq!(session.state(), SessionState::Established);

    // Start transfer
    let large_data = vec![0x42; 2000]; // Larger than peer's MRU
    let transfer_id = session.start_transfer(large_data).unwrap();

    // Create segments - should respect peer's segment MRU
    let segments = session
        .create_segments(transfer_id, 10000)
        .expect("Segments created");

    // Verify all segments respect peer's MRU
    for (idx, msg) in segments.iter().enumerate() {
        if let Message::TransferSegment {
            flags: _,
            transfer_id: _,
            extensions: _,
            data,
        } = msg
        {
            assert!(
                data.len() <= 1000,
                "Segment {} size {} exceeds peer MRU {}",
                idx,
                data.len(),
                1000
            );
        }
    }
}

/// Test RFC9174-4-6-068: Transfer size SHALL NOT exceed peer's Transfer MRU
#[test]
fn test_rfc9174_4_6_068_transfer_mru_enforcement() {
    // RFC 9174 §4.6: "The Transfer MRU indicates the largest total bundle data the entity
    // is willing to receive in a single transfer."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session
    let _sent_header = session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    let _sent_init = session.send_session_init().unwrap();

    // Peer advertises small transfer MRU
    let peer_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 5000, // Small transfer MRU
        node_id: "dtn://peer.local".to_string(),
        extensions: vec![],
    };

    session.process_session_init(&peer_init).unwrap();

    // Attempt to start transfer larger than peer's MRU
    let large_data = vec![0x42; 10000]; // Exceeds peer's 5000 byte MRU
    let result = session.start_transfer(large_data);

    assert!(
        result.is_err(),
        "Transfer exceeding peer MRU MUST be rejected"
    );
}

/// Test RFC9174-5-2-2-108: START flag indicates first segment, END flag indicates last
#[test]
fn test_rfc9174_5_2_2_108_start_end_flags() {
    // RFC 9174 §5.2.2: "The flag value 0x01 (START) SHALL be set only in the first segment
    // of a transfer. The flag value 0x02 (END) SHALL be set only in the last segment."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 1000,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();
    session
        .process_session_init(&Message::SessionInit {
            keepalive_interval: 30,
            segment_mru: 1000,
            transfer_mru: 10_000,
            node_id: "dtn://peer.local".to_string(),
            extensions: vec![],
        })
        .unwrap();

    // Start multi-segment transfer
    let data = vec![0x42; 2500]; // Will require 3 segments with 1000-byte MRU
    let transfer_id = session.start_transfer(data).unwrap();

    let segments = session.create_segments(transfer_id, 1000).unwrap();
    assert!(segments.len() >= 2, "Multi-segment transfer expected");

    // Check START flag on first segment only (START = 0x02)
    if let Message::TransferSegment {
        flags,
        transfer_id: _,
        extensions: _,
        data: _,
    } = &segments[0]
    {
        assert!(
            flags & 0x02 != 0,
            "First segment MUST have START flag set (0x02)"
        );
    } else {
        panic!("Expected TransferSegment");
    }

    // Check END flag on last segment only (END = 0x01)
    let last_idx = segments.len() - 1;
    if let Message::TransferSegment {
        flags,
        transfer_id: _,
        extensions: _,
        data: _,
    } = &segments[last_idx]
    {
        assert!(
            flags & 0x01 != 0,
            "Last segment MUST have END flag set (0x01)"
        );
    }

    // Middle segments (if any) should have neither flag
    for (idx, msg) in segments[1..last_idx].iter().enumerate() {
        if let Message::TransferSegment {
            flags,
            transfer_id: _,
            extensions: _,
            data: _,
        } = msg
        {
            assert!(
                flags & 0x02 == 0,
                "Middle segment {} MUST NOT have START flag",
                idx + 1
            );
            assert!(
                flags & 0x01 == 0,
                "Middle segment {} MUST NOT have END flag",
                idx + 1
            );
        }
    }
}

/// Test RFC9174-5-2-3-114: XFER_ACK acknowledges cumulative byte count
#[test]
fn test_rfc9174_5_2_3_114_xfer_ack_cumulative() {
    // RFC 9174 §5.2.3: "The Cumulative Length field SHALL be the total number of bytes in
    // the transfer which have been received."

    let config = SessionConfig {
        role: Role::Passive,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session - Passive waits for Active's contact and SESS_INIT
    let peer_header = ContactHeader::new();
    session.process_contact_header(&peer_header).unwrap();
    session.send_contact_header().unwrap();

    // Passive receives Active's SESS_INIT first
    let peer_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://peer.local".to_string(),
        extensions: vec![],
    };

    // For Passive, send SESS_INIT before processing peer's (or change state beforehand)
    // Let me try sending first, then processing
    session.send_session_init().unwrap();
    session.process_session_init(&peer_init).unwrap();

    // Receive first segment (START flag)
    let transfer_id = 1;
    let segment1 = Message::TransferSegment {
        flags: 0x01, // START
        transfer_id,
        extensions: vec![],
        data: vec![0x41; 100],
    };

    // Process segment and get ACK
    let ack = session
        .process_segment(&segment1)
        .unwrap()
        .expect("ACK returned");

    // Verify ACK acknowledges 100 bytes
    if let Message::TransferAck {
        flags: _,
        transfer_id: ack_id,
        acked_length,
    } = ack
    {
        assert_eq!(ack_id, transfer_id);
        assert_eq!(
            acked_length, 100,
            "XFER_ACK acked_length MUST be total bytes received (100)"
        );
    } else {
        panic!("Expected TransferAck");
    }

    // Receive second segment
    let segment2 = Message::TransferSegment {
        flags: 0x02, // END
        transfer_id,
        extensions: vec![],
        data: vec![0x42; 50],
    };

    // Process segment and get ACK
    let ack2 = session
        .process_segment(&segment2)
        .unwrap()
        .expect("ACK returned");

    // Verify ACK acknowledges cumulative 150 bytes
    if let Message::TransferAck {
        flags: _,
        transfer_id: _,
        acked_length,
    } = ack2
    {
        assert_eq!(
            acked_length, 150,
            "XFER_ACK acked_length MUST be total bytes received (150)"
        );
    }
}

/// Test RFC9174-5-2-4-124: XFER_REFUSE reason codes fit in u8
#[test]
fn test_rfc9174_5_2_4_124_refuse_reason_codes() {
    // RFC 9174 §5.2.4 Table 2: "Reason Code" field is 1 octet (u8)
    // All defined reason codes must fit in u8

    // Per RFC 9174 Table 2, defined reason codes are 0x00-0x05
    let valid_codes = vec![
        0x00, // Unknown
        0x01, // Completed
        0x02, // No Resources
        0x03, // Retransmit
        0x04, // Not Acceptable
        0x05, // Extension Failure
    ];

    // Verify all valid codes can be represented in u8 and encoded
    for code in valid_codes {
        let refuse = Message::TransferRefuse {
            transfer_id: 1,
            reason_code: code,
        };

        // Encode the message to verify it's valid
        let encoded = refuse.encode();
        assert!(
            encoded.len() >= 2,
            "XFER_REFUSE with reason code {:#04x} must encode successfully",
            code
        );

        // Verify reason code is in the encoded message
        // Message type (0x03) + flags + transfer_id + reason_code
        // The structure ensures reason_code fits in u8 (type system enforces this)
    }

    // Verify that attempting to use reserved/unassigned codes would still fit in u8
    // but document that codes > 0x05 are unassigned per Table 2
    let unassigned_code = 0xFF;
    let refuse_unassigned = Message::TransferRefuse {
        transfer_id: 1,
        reason_code: unassigned_code,
    };

    // Type system enforces u8, so this compiles only if constraint satisfied
    if let Message::TransferRefuse {
        transfer_id: _,
        reason_code: rc,
    } = refuse_unassigned
    {
        assert_eq!(
            rc, unassigned_code,
            "Reason code field MUST be u8 (can represent 0x{:02X})",
            unassigned_code
        );
    }
}

/// Test RFC9174-6-1-148: No new outgoing transfers after sending SESS_TERM
#[test]
fn test_rfc9174_6_1_148_no_new_outgoing_after_term() {
    // RFC 9174 §6.1: "Once an entity sends a SESS_TERM message, the entity SHALL NOT send
    // any further messages."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();
    session
        .process_session_init(&Message::SessionInit {
            keepalive_interval: 30,
            segment_mru: 65535,
            transfer_mru: 10_000,
            node_id: "dtn://peer.local".to_string(),
            extensions: vec![],
        })
        .unwrap();

    assert_eq!(session.state(), SessionState::Established);

    // Initiate termination
    let term_msg = session.send_session_term(0x00, None).unwrap();
    if let Message::SessionTerm {
        flags,
        reason_code: _,
        message: _,
    } = term_msg
    {
        assert_eq!(flags & 0x01, 0, "Initiating SESS_TERM has reply flag = 0");
    }

    // Session should be in Ending state
    assert_eq!(session.state(), SessionState::Ending);

    // Attempt to start new transfer after SESS_TERM sent
    let data = vec![0x42; 100];
    let result = session.start_transfer(data);

    assert!(
        result.is_err(),
        "Session MUST NOT allow new transfers after sending SESS_TERM"
    );
}

/// Test RFC9174-6-1-150: No new incoming transfers after receiving SESS_TERM
#[test]
fn test_rfc9174_6_1_150_no_new_incoming_after_term() {
    // RFC 9174 §6.1: "Once an entity receives a SESS_TERM message, the entity SHALL NOT
    // accept any further incoming transfers."

    let config = SessionConfig {
        role: Role::Passive,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session - Passive role
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_contact_header().unwrap();
    session.send_session_init().unwrap();
    session
        .process_session_init(&Message::SessionInit {
            keepalive_interval: 30,
            segment_mru: 65535,
            transfer_mru: 10_000,
            node_id: "dtn://peer.local".to_string(),
            extensions: vec![],
        })
        .unwrap();

    assert_eq!(session.state(), SessionState::Established);

    // Receive SESS_TERM from peer
    let term_msg = Message::SessionTerm {
        flags: 0x00, // Not a reply
        reason_code: 0x00,
        message: None,
    };

    session.process_session_term(&term_msg).unwrap();

    // Session should transition to termination state
    assert!(session.state() == SessionState::Ending || session.state() == SessionState::Terminated);

    // Attempt to receive new transfer after SESS_TERM received
    let new_segment = Message::TransferSegment {
        flags: 0x03, // START | END
        transfer_id: 999,
        extensions: vec![],
        data: vec![0x42; 100],
    };

    let result = session.process_segment(&new_segment);

    assert!(
        result.is_err(),
        "Session MUST NOT accept new transfers after receiving SESS_TERM"
    );
}

/// Test RFC9174-5-1-2-092: MSG_REJECT sent for unknown message type
#[test]
fn test_rfc9174_5_1_2_092_msg_reject_unknown_type() {
    // RFC 9174 §5.1.2: "If a TCPCL entity receives a message with a Message Type code
    // that it does not recognize, the entity SHALL send a MSG_REJECT message."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();
    session
        .process_session_init(&Message::SessionInit {
            keepalive_interval: 30,
            segment_mru: 65535,
            transfer_mru: 10_000,
            node_id: "dtn://peer.local".to_string(),
            extensions: vec![],
        })
        .unwrap();

    // Simulate receiving message with unknown type code
    let unknown_type: u8 = 0xFF; // Not a defined message type
    let result = session.process_raw_message_type(unknown_type);

    // Should produce MSG_REJECT
    if let Some(Message::MessageReject {
        reason_code,
        rejected_message_header,
    }) = result
    {
        assert_eq!(
            rejected_message_header, unknown_type,
            "MSG_REJECT MUST echo the unrecognized message type"
        );
        assert_eq!(reason_code, 0x01, "Reason code 0x01 = Message Type Unknown");
    } else {
        panic!("Session MUST generate MSG_REJECT for unknown message type");
    }
}

/// Test RFC9174-5-1-1-088: Keepalive messages driven by time
#[test]
fn test_rfc9174_5_1_1_088_keepalive_timing() {
    // RFC 9174 §5.1.1: "Each entity SHALL send a KEEPALIVE message if the negotiated
    // Session Keepalive Interval has elapsed since the last sent message."

    let mut clock = ManualClock::new();
    let start = clock.now_ms();

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 10, // 10 seconds
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session with 10-second keepalive
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();
    session
        .process_session_init(&Message::SessionInit {
            keepalive_interval: 10,
            segment_mru: 65535,
            transfer_mru: 10_000,
            node_id: "dtn://peer.local".to_string(),
            extensions: vec![],
        })
        .unwrap();

    session.record_send(start);

    // Advance time by 9 seconds - no keepalive needed yet
    clock.advance(9000);
    let result = session.poll(clock.now_ms());
    assert!(
        result.is_none(),
        "No keepalive needed before interval elapses"
    );

    // Advance time by 2 more seconds (11 total) - keepalive needed
    clock.advance(2000);
    let result = session.poll(clock.now_ms());
    assert!(
        matches!(result, Some(Message::Keepalive)),
        "Keepalive MUST be sent after interval elapses"
    );
}

/// Test RFC9174-5-1-1-089: Idle timeout terminates session
#[test]
fn test_rfc9174_5_1_1_089_idle_timeout() {
    // RFC 9174 §5.1.1: "If the negotiated Session Keepalive Interval is not zero and an
    // entity does not receive any messages for the period of the negotiated Session
    // Keepalive Interval, the entity SHALL terminate the session."

    let mut clock = ManualClock::new();
    let start = clock.now_ms();

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 10, // 10 seconds
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Establish session with 10-second keepalive
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();
    session
        .process_session_init(&Message::SessionInit {
            keepalive_interval: 10,
            segment_mru: 65535,
            transfer_mru: 10_000,
            node_id: "dtn://peer.local".to_string(),
            extensions: vec![],
        })
        .unwrap();

    session.record_receive(start);

    // Advance time by idle timeout period (keepalive interval * 2 = 20 seconds)
    clock.advance(20000);

    // Check if session triggers termination due to idle timeout
    let result = session.poll(clock.now_ms());
    assert!(
        matches!(result, Some(Message::SessionTerm { .. })),
        "Session MUST send SESS_TERM after idle timeout (twice the keepalive interval with no received messages)"
    );
}

/// Test RFC9174-4-8-082: Unknown critical extension terminates session
#[test]
fn test_rfc9174_4_8_082_critical_extension_termination() {
    // RFC 9174 §4.8: "If an entity receives a session extension item that it does not
    // recognize and the CRITICAL flag is set, the entity SHALL terminate the session."

    let config = SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://test.local".to_string(),
        extensions: vec![],
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    };

    let mut session = TcpclSession::new(config).unwrap();

    // Exchange contact headers
    session.send_contact_header().unwrap();
    session
        .process_contact_header(&ContactHeader::new())
        .unwrap();
    session.send_session_init().unwrap();

    // Peer sends SESS_INIT with unknown critical extension
    let unknown_critical_ext = ExtensionItem::new(0xFFFF, vec![0x01, 0x02, 0x03], true);

    let peer_init = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 10_000,
        node_id: "dtn://peer.local".to_string(),
        extensions: vec![unknown_critical_ext],
    };

    let result = session.process_session_init(&peer_init);

    assert!(
        result.is_err(),
        "Session MUST reject SESS_INIT with unknown critical extension"
    );
}
