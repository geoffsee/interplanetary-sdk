//! RFC 9174 §5.2.5.1-139: Absence of Transfer Length Extension implies nothing
//!
//! "The lack of a Transfer Length Extension Item in any transfer SHALL NOT
//! imply anything regarding the potential length of the transfer."

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §5.2.5.1-139: No Transfer Length Extension implies nothing about length
///
/// When a transfer does not include a Transfer Length Extension Item, the
/// receiver SHALL NOT make any assumptions about the potential length of the
/// transfer. The transfer could be short, long, or any length.
///
/// This test drives TcpclSession to send transfers without Transfer Length
/// Extension and verifies that receivers accept them regardless of actual length.
///
/// This test would FAIL if the SDK made assumptions about transfer length
/// based on the absence of the Transfer Length Extension.
#[test]
fn test_rfc9174_5_2_5_1_139_no_length_extension_accepts_any_length() {
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

    // Establish session (contact headers + SESS_INIT)
    let sender_contact = sender.send_contact_header().unwrap();
    receiver.process_contact_header(&sender_contact).unwrap();
    let receiver_contact = receiver.send_contact_header().unwrap();
    sender.process_contact_header(&receiver_contact).unwrap();

    let sender_init = sender.send_session_init().unwrap();
    let receiver_init = receiver.send_session_init().unwrap();
    receiver.process_session_init(&sender_init).unwrap();
    sender.process_session_init(&receiver_init).unwrap();

    // Test 1: Small transfer without Transfer Length Extension
    let small_data = vec![0x11; 50];
    let transfer_id_1 = sender.start_transfer(small_data.clone()).unwrap();
    let segments_1 = sender.create_segments(transfer_id_1, 1000).unwrap();

    // Verify no Transfer Length Extension (extensions list is empty)
    for segment in &segments_1 {
        match segment {
            Message::TransferSegment { extensions, .. } => {
                // No Transfer Length Extension
                assert!(
                    !extensions.iter().any(|ext| ext.type_code == 0x0001),
                    "Transfer should not have Transfer Length Extension"
                );
            }
            _ => panic!("Expected XFER_SEGMENT"),
        }
    }

    // Receiver processes segments without knowing total length
    for segment in segments_1 {
        let _response = receiver.process_segment(&segment).unwrap();
    }

    // RFC 9174 §5.2.5.1-139: Lack of Transfer Length Extension SHALL NOT
    // imply anything about the transfer length. The receiver accepted it.
    assert!(receiver.is_transfer_complete(transfer_id_1));

    // Test 2: Large transfer without Transfer Length Extension
    let large_data = vec![0x22; 10000];
    let transfer_id_2 = sender.start_transfer(large_data.clone()).unwrap();
    let segments_2 = sender.create_segments(transfer_id_2, 1000).unwrap();

    // Multiple segments, still no Transfer Length Extension
    assert!(segments_2.len() > 1, "Should have multiple segments");

    for segment in &segments_2 {
        match segment {
            Message::TransferSegment { extensions, .. } => {
                assert!(
                    !extensions.iter().any(|ext| ext.type_code == 0x0001),
                    "Transfer should not have Transfer Length Extension"
                );
            }
            _ => panic!("Expected XFER_SEGMENT"),
        }
    }

    // Receiver processes all segments without knowing total length ahead of time
    for segment in segments_2 {
        let _response = receiver.process_segment(&segment).unwrap();
    }

    // RFC 9174 §5.2.5.1-139: The absence of Transfer Length Extension does
    // not imply a short transfer - this large transfer was also accepted.
    assert!(receiver.is_transfer_complete(transfer_id_2));

    // Test 3: Empty transfer without Transfer Length Extension
    let empty_data = vec![];
    let transfer_id_3 = sender.start_transfer(empty_data).unwrap();
    let segments_3 = sender.create_segments(transfer_id_3, 1000).unwrap();

    for segment in segments_3 {
        let _response = receiver.process_segment(&segment).unwrap();
    }

    assert!(receiver.is_transfer_complete(transfer_id_3));

    // This test demonstrates that the lack of Transfer Length Extension
    // SHALL NOT cause the receiver to make assumptions about transfer length.
    // Transfers of any length (empty, small, large) are accepted.
}

/// RFC 9174 §5.2.5.1-139: Receiver SHALL NOT reject transfer for lacking Transfer Length Extension
///
/// This test verifies that a receiver does not reject a transfer simply because
/// it lacks a Transfer Length Extension. The extension is optional.
#[test]
fn test_rfc9174_5_2_5_1_139_receiver_accepts_without_length_extension() {
    let mut sender = TcpclSession::new(SessionConfig {
        role: Role::Active,
        keepalive_interval: 30,
        segment_mru: 1000,
        transfer_mru: 100_000,
        node_id: "ipn:3.1".to_string(),
        extensions: Vec::new(),
        contact_header_timeout: 60,
        max_peer_keepalive: None,
    })
    .unwrap();

    let mut receiver = TcpclSession::new(SessionConfig {
        role: Role::Passive,
        keepalive_interval: 30,
        segment_mru: 1000,
        transfer_mru: 100_000,
        node_id: "ipn:4.1".to_string(),
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

    // Send a transfer without Transfer Length Extension
    let data = vec![0xAB; 500];
    let transfer_id = sender.start_transfer(data.clone()).unwrap();
    let segments = sender.create_segments(transfer_id, 200).unwrap();

    // Multiple segments, no Transfer Length Extension
    assert!(segments.len() > 1);

    // Receiver SHALL accept all segments
    for segment in segments {
        let response = receiver.process_segment(&segment);

        // RFC 9174 §5.2.5.1-139: Receiver SHALL NOT reject transfer
        // just because Transfer Length Extension is absent
        assert!(
            response.is_ok(),
            "Receiver must accept segments without Transfer Length Extension"
        );

        // Response might be XFER_ACK, which is fine
        if let Ok(Some(msg)) = response {
            match msg {
                Message::TransferAck { .. } => {
                    // Expected - receiver is acknowledging
                }
                Message::TransferRefuse { .. } => {
                    panic!(
                        "Receiver must NOT refuse transfer for lacking Transfer Length Extension"
                    );
                }
                _ => {}
            }
        }
    }

    // Transfer completes successfully
    assert!(
        receiver.is_transfer_complete(transfer_id),
        "Transfer without Transfer Length Extension must complete"
    );

    let received_data = receiver.get_received_transfer(transfer_id).unwrap();
    assert_eq!(received_data, data.as_slice());

    // This confirms that the lack of Transfer Length Extension SHALL NOT
    // cause rejection or imply assumptions about the transfer length.
}
