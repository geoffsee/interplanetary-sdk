//! TCPCLv4 arbitrary chunking tests per RFC 9174
//!
//! Tests that TCPCL message framing is robust under various byte-stream
//! chunking scenarios.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

#[test]
fn test_transfer_with_varying_chunk_sizes() {
    let data = vec![0xAA; 10000];

    // Test with different segment sizes
    for chunk_size in [100, 500, 1000, 5000, 10000] {
        let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
        let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

        // Establish session
        let sender_contact = sender.send_contact_header().unwrap();
        let receiver_contact = receiver.send_contact_header().unwrap();
        sender.process_contact_header(&receiver_contact).unwrap();
        receiver.process_contact_header(&sender_contact).unwrap();

        let sender_init = sender.send_session_init().unwrap();
        let receiver_init = receiver.send_session_init().unwrap();
        sender.process_session_init(&receiver_init).unwrap();
        receiver.process_session_init(&sender_init).unwrap();

        // Send transfer in chunks
        let transfer_id = sender.start_transfer(data.clone()).unwrap();
        let segments = sender.create_segments(transfer_id, chunk_size).unwrap();

        let mut total_acked = 0u64;

        // Process each segment at receiver
        for segment in segments {
            if let Some(ack) = receiver.process_segment(&segment).unwrap() {
                match ack {
                    Message::TransferAck {
                        acked_length,
                        transfer_id: ack_id,
                        ..
                    } => {
                        assert_eq!(ack_id, transfer_id);
                        total_acked = acked_length;
                        sender.process_ack(transfer_id, acked_length).unwrap();
                    }
                    _ => panic!("Expected XFER_ACK"),
                }
            }
        }

        // Verify complete transfer
        assert_eq!(total_acked, data.len() as u64);
        assert!(sender.is_transfer_complete(transfer_id));

        let received = receiver.get_received_transfer(transfer_id).unwrap();
        assert_eq!(received, &data[..]);
    }
}

#[test]
fn test_refused_transfer_distinguishable() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    // Establish session
    setup_session(&mut sender, &mut receiver);

    // Start transfer
    let data = vec![0xBB; 1000];
    let transfer_id = sender.start_transfer(data).unwrap();
    let _segments = sender.create_segments(transfer_id, 500).unwrap();

    // Simulate refusal at receiver (not sent)
    let _refuse = Message::TransferRefuse {
        reason_code: refuse_reason::NOT_ACCEPTABLE,
        transfer_id,
    };

    // Process refusal at sender
    let result = sender.process_refuse(transfer_id, refuse_reason::NOT_ACCEPTABLE);
    assert!(result.is_err());
    // Transfer was removed after refusal
}

#[test]
fn test_cumulative_ack_semantics() {
    // Tests RFC 9174 §6.3 cumulative acknowledgment behavior.
    // The sender processes only the final ACK, but the transfer still completes
    // because acked_length is cumulative (total bytes received, not delta).
    // NOTE: This is NOT "lost ACK recovery" - ACKs cannot be lost within a
    // reliable TCP stream. This demonstrates that later ACKs subsume earlier ones.

    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut sender, &mut receiver);

    let data = vec![0xCC; 2000];
    let transfer_id = sender.start_transfer(data.clone()).unwrap();
    let segments = sender.create_segments(transfer_id, 1000).unwrap();

    // Receiver processes both segments and generates ACKs
    let _ack1 = receiver.process_segment(&segments[0]).unwrap();
    let ack2 = receiver.process_segment(&segments[1]).unwrap();

    // Sender processes only the second (final) ACK
    // This is valid because acked_length is cumulative
    if let Some(Message::TransferAck { acked_length, .. }) = ack2 {
        assert_eq!(acked_length, 2000); // Cumulative: all bytes
        let complete = sender.process_ack(transfer_id, acked_length).unwrap();
        assert!(complete);
    }
}

#[test]
fn test_simultaneous_sess_term() {
    let mut local = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut remote = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut local, &mut remote);

    // Both sides send SESS_TERM simultaneously
    let local_term = local
        .send_session_term(term_reason::IDLE_TIMEOUT, Some("Timeout".to_string()))
        .unwrap();
    let remote_term = remote
        .send_session_term(term_reason::IDLE_TIMEOUT, Some("Timeout".to_string()))
        .unwrap();

    assert_eq!(local.state(), SessionState::Ending);
    assert_eq!(remote.state(), SessionState::Ending);

    // Process each other's SESS_TERM
    let _ = local.process_session_term(&remote_term);
    let _ = remote.process_session_term(&local_term);

    // Both reach Terminated state
    assert_eq!(local.state(), SessionState::Terminated);
    assert_eq!(remote.state(), SessionState::Terminated);
}

#[test]
fn test_unsupported_critical_extension_refusal() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    // Exchange contacts
    let sender_contact = sender.send_contact_header().unwrap();
    let receiver_contact = receiver.send_contact_header().unwrap();
    sender.process_contact_header(&receiver_contact).unwrap();
    receiver.process_contact_header(&sender_contact).unwrap();

    // Sender sends SESS_INIT with unsupported critical extension
    let init_with_ext = Message::SessionInit {
        keepalive_interval: 30,
        segment_mru: 65535,
        transfer_mru: 1_000_000,
        node_id: "dtn:sender".to_string(),
        extensions: vec![
            ExtensionItem::new(0xFFFF, vec![1, 2, 3], true), // Critical
        ],
    };

    // Receiver rejects due to unsupported critical extension
    let result = receiver.process_session_init(&init_with_ext);
    assert!(result.is_err());

    // Session not established
    assert_ne!(receiver.state(), SessionState::Established);
}

#[test]
fn test_receive_window_exhaustion() {
    let config = SessionConfig {
        transfer_mru: 500, // Small receive window
        ..Default::default()
    };

    let mut receiver = TcpclSession::new(config).unwrap();
    // Manually establish for test
    let mut temp_sender = TcpclSession::new(SessionConfig::default()).unwrap();
    setup_session(&mut temp_sender, &mut receiver);

    // Try to send data exceeding receive window
    let large_data = vec![0xDD; 1000];

    let segment = Message::TransferSegment {
        flags: transfer_flags::START | transfer_flags::END,
        transfer_id: 1,
        extensions: Vec::new(),
        data: large_data,
    };

    let response = receiver.process_segment(&segment).unwrap();

    // Should get XFER_REFUSE due to resource exhaustion
    match response {
        Some(Message::TransferRefuse {
            reason_code,
            transfer_id,
        }) => {
            assert_eq!(reason_code, refuse_reason::NO_RESOURCES);
            assert_eq!(transfer_id, 1);
        }
        _ => panic!("Expected XFER_REFUSE for exhausted receive window"),
    }
}

#[test]
fn test_segment_ordering_and_flags() {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    setup_session(&mut sender, &mut receiver);

    let data = vec![0xEE; 5000];
    let transfer_id = sender.start_transfer(data).unwrap();
    let segments = sender.create_segments(transfer_id, 1000).unwrap();

    // Verify START flag on first segment
    if let Message::TransferSegment { flags, .. } = &segments[0] {
        assert!(flags & transfer_flags::START != 0);
        assert_eq!(flags & transfer_flags::END, 0); // Not last
    }

    // Verify END flag on last segment
    if let Message::TransferSegment { flags, .. } = segments.last().unwrap() {
        assert!(flags & transfer_flags::END != 0);
    }

    // Verify middle segments have neither START nor END
    if segments.len() > 2
        && let Message::TransferSegment { flags, .. } = &segments[1]
    {
        assert_eq!(flags & transfer_flags::START, 0);
        assert_eq!(flags & transfer_flags::END, 0);
    }
}

/// Helper: establish session between two endpoints
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
