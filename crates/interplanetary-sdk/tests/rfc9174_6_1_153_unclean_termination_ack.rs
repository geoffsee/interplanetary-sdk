//! RFC 9174 §6.1-153: Acknowledge segments before unclean termination
//!
//! "When performing an unclean termination, an entity SHOULD acknowledge all
//! received XFER_SEGMENTs with a XFER_ACK before closing the TCP connection."

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §6.1-153: Generate XFER_ACK for segments before unclean termination
///
/// Unclean termination = closing TCP without SESS_TERM exchange (e.g., emergency).
/// Before closing, the entity SHOULD send XFER_ACK for all received segments.
///
/// Verifies that the SDK:
/// 1. Generates XFER_ACK responses for received XFER_SEGMENT messages
/// 2. Allows integrator to send those ACKs before terminating
#[test]
fn test_rfc9174_6_1_153_ack_segments_before_unclean_termination() {
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

    // Sender starts transfer and creates segments
    let data = vec![0xAA; 1500];
    let transfer_id = sender.start_transfer(data).unwrap();
    let segments = sender.create_segments(transfer_id, 500).unwrap();

    // Send multiple segments to receiver
    let mut ack_messages = Vec::new();

    for segment in segments.iter() {
        // Receiver processes each segment
        let ack = receiver.process_segment(segment).unwrap();

        // RFC 9174 §6.1-153: Receiver generates XFER_ACK for each segment
        assert!(
            ack.is_some(),
            "Receiver should generate XFER_ACK for received segment"
        );

        // Collect ACK messages
        if let Some(ack_msg) = ack {
            match ack_msg {
                Message::TransferAck {
                    transfer_id: ack_id,
                    acked_length,
                    ..
                } => {
                    assert_eq!(ack_id, transfer_id, "ACK should reference correct transfer");
                    assert!(acked_length > 0, "ACK should have positive acked_length");
                    ack_messages.push(ack_msg);
                }
                _ => panic!("Expected XFER_ACK message"),
            }
        }
    }

    // RFC 9174 §6.1-153: Before unclean termination, entity SHOULD send all ACKs
    assert!(
        !ack_messages.is_empty(),
        "Should have XFER_ACK messages to send before unclean termination"
    );

    // Scenario: Receiver needs to perform unclean termination (no SESS_TERM)
    // Examples: network error, resource exhaustion, emergency shutdown
    //
    // RFC 9174 §6.1-153: "SHOULD acknowledge all received XFER_SEGMENTs with
    // a XFER_ACK before closing the TCP connection"

    // The SDK has generated the XFER_ACK messages.
    // Integrator SHOULD send these ACKs before closing TCP:
    for ack in ack_messages {
        // Send ACK to sender (simulate)
        let encoded_ack = ack.encode();
        assert!(
            encoded_ack[0] == Message::TYPE_XFER_ACK,
            "ACK should encode with correct type byte"
        );

        // In real implementation, integrator would send these bytes over TCP
        // before closing the connection (unclean termination)
    }

    // After sending ACKs, integrator closes TCP without SESS_TERM (unclean)
    // This follows RFC 9174 §6.1-153 guidance: ACK segments first, then close
}

/// RFC 9174 §6.1-153: Multiple segments acknowledged before unclean termination
///
/// Verifies that all received segments are acknowledged, not just the last one.
#[test]
fn test_rfc9174_6_1_153_acknowledge_all_segments() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        ..SessionConfig::default()
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

    // Send a large transfer that will be segmented
    let large_data = vec![0xBB; 5000];
    let transfer_id = sender.start_transfer(large_data).unwrap();
    let segments = sender.create_segments(transfer_id, 1000).unwrap();

    assert!(
        segments.len() > 1,
        "Transfer should be split into multiple segments"
    );

    // Track ACKs for all segments
    let mut all_acks = Vec::new();

    for (idx, segment) in segments.iter().enumerate() {
        let ack = receiver.process_segment(segment).unwrap();

        // RFC 9174: Each segment should be acknowledged
        assert!(ack.is_some(), "Segment {} should generate XFER_ACK", idx);

        if let Some(ack_msg) = ack {
            all_acks.push(ack_msg);
        }
    }

    // RFC 9174 §6.1-153: "acknowledge all received XFER_SEGMENTs"
    assert_eq!(
        all_acks.len(),
        segments.len(),
        "Should have XFER_ACK for every received segment"
    );

    // Before unclean termination, integrator sends all these ACKs
    for (idx, ack) in all_acks.iter().enumerate() {
        match ack {
            Message::TransferAck { acked_length, .. } => {
                assert!(
                    *acked_length > 0,
                    "ACK {} should have positive acked_length",
                    idx
                );
            }
            _ => panic!("Expected XFER_ACK"),
        }
    }
}

/// RFC 9174 §6.1-153: Unclean vs clean termination
///
/// Documents the difference:
/// - Clean: Send SESS_TERM, exchange termination messages, then close
/// - Unclean: Close without SESS_TERM (emergency), but SHOULD ACK segments first
#[test]
fn test_rfc9174_6_1_153_unclean_vs_clean_termination() {
    // Clean termination scenario
    {
        let mut local = TcpclSession::new(SessionConfig::default()).unwrap();
        let mut remote = TcpclSession::new(SessionConfig {
            role: Role::Passive,
            ..SessionConfig::default()
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

        // Clean termination: Send SESS_TERM
        let sess_term = local.send_session_term(0x00, None).unwrap();

        match sess_term {
            Message::SessionTerm { .. } => {
                // Clean termination uses SESS_TERM message exchange
                assert_eq!(local.state(), SessionState::Ending);
            }
            _ => panic!("Expected SESS_TERM"),
        }

        // In clean termination, SESS_TERM is sent, reply is received,
        // then TCP is closed with FIN
    }

    // Unclean termination scenario
    {
        let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
        let mut receiver = TcpclSession::new(SessionConfig {
            role: Role::Passive,
            ..SessionConfig::default()
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

        // Send segment
        let data = vec![0xCC; 500];
        let transfer_id = sender.start_transfer(data).unwrap();
        let segments = sender.create_segments(transfer_id, 1000).unwrap();
        let segment = &segments[0];

        // Receiver processes segment
        let ack = receiver.process_segment(segment).unwrap();
        assert!(ack.is_some(), "Should generate XFER_ACK");

        // RFC 9174 §6.1-153: Unclean termination scenario
        // Receiver encounters emergency (network error, resource exhaustion, etc.)
        // No SESS_TERM is sent (unclean), but receiver SHOULD send XFER_ACK first

        // Send the ACK before closing
        let ack_msg = ack.unwrap();
        let _encoded_ack = ack_msg.encode();

        // Then close TCP without SESS_TERM (unclean termination)
        // This is RFC 9174 §6.1-153 behavior: ACK first, then close
    }
}

/// RFC 9174 §6.1-153: Partial transfer acknowledged before unclean termination
///
/// Even if transfer is incomplete, received segments SHOULD be acknowledged.
#[test]
fn test_rfc9174_6_1_153_partial_transfer_ack() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        ..SessionConfig::default()
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

    // Start a large transfer
    let large_data = vec![0xDD; 3000];
    let transfer_id = sender.start_transfer(large_data).unwrap();
    let segments = sender.create_segments(transfer_id, 1000).unwrap();

    // Receiver only gets first 2 segments (partial transfer)
    let mut acks = Vec::new();
    for segment in segments.iter().take(2) {
        let ack = receiver.process_segment(segment).unwrap();
        if let Some(ack_msg) = ack {
            acks.push(ack_msg);
        }
    }

    // RFC 9174 §6.1-153: Even for incomplete transfer, SHOULD ACK received segments
    assert!(
        !acks.is_empty(),
        "Should have ACKs for partial transfer before unclean termination"
    );

    // Emergency occurs - receiver must terminate unclean
    // RFC 9174 §6.1-153: Send the ACKs we have before closing
    for ack in acks {
        match ack {
            Message::TransferAck { .. } => {
                // Send this ACK before closing TCP
                let _encoded = ack.encode();
            }
            _ => panic!("Expected XFER_ACK"),
        }
    }

    // Close TCP without SESS_TERM (unclean) after sending partial ACKs
    // This minimizes data loss by informing sender which segments were received
}
