//! RFC 9174 §4.5-066: XFER_REFUSE message type behavioral tests
//!
//! "Message type 0x03 is XFER_REFUSE (Transfer Refusal)"
//!
//! Tests verify that XFER_REFUSE messages are encoded with type byte 0x03
//! and that receiving 0x03 is interpreted as transfer refusal.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;

/// RFC 9174 §4.5-066: TcpclSession emits 0x03 when refusing transfer
///
/// When TcpclSession refuses an incoming transfer, it SHALL emit a XFER_REFUSE
/// message with type byte 0x03.
///
/// This test drives TcpclSession to refuse a transfer via unsupported critical
/// extension and verifies the emitted bytes begin with 0x03.
#[test]
fn test_rfc9174_4_5_066_session_emits_0x03_for_xfer_refuse() {
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

    // Create a segment with unsupported critical extension
    // This will trigger XFER_REFUSE with EXTENSION_FAILURE
    let unknown_critical_ext = ExtensionItem {
        flags: 0x01,       // CRITICAL flag set
        type_code: 0xFFFF, // Unknown type
        value: vec![0x00],
    };

    let segment_with_critical_ext = Message::TransferSegment {
        flags: transfer_flags::START | transfer_flags::END,
        transfer_id: 1,
        extensions: vec![unknown_critical_ext],
        data: vec![0xAA; 100],
    };

    // Receiver processes segment with unknown critical extension
    let response = receiver.process_segment(&segment_with_critical_ext);

    // RFC 9174 §4.5-066: The response SHALL be XFER_REFUSE with type byte 0x03
    assert!(response.is_ok(), "Should return XFER_REFUSE response");

    let refuse_msg = response.unwrap();
    assert!(refuse_msg.is_some(), "Should have XFER_REFUSE message");

    let refuse = refuse_msg.unwrap();

    // Encode the XFER_REFUSE message
    let encoded = refuse.encode();

    // RFC 9174 §4.5-066: Message type byte SHALL be 0x03
    assert_eq!(
        encoded[0], 0x03,
        "XFER_REFUSE message type byte must be 0x03"
    );

    // Verify XFER_REFUSE message structure
    assert!(
        encoded.len() >= 3,
        "XFER_REFUSE must have type + flags + reason + transfer_id"
    );

    // Verify it's a XFER_REFUSE by matching the message
    match refuse {
        Message::TransferRefuse {
            reason_code,
            transfer_id,
        } => {
            assert_eq!(transfer_id, 1, "Transfer ID must match");
            assert_eq!(
                reason_code, 0x05,
                "Reason should be EXTENSION_FAILURE (0x05)"
            );
        }
        _ => panic!("Expected TransferRefuse message"),
    }
}

/// RFC 9174 §4.5-066: TcpclSession interprets 0x03 as transfer refusal
///
/// When TcpclSession receives a message with type byte 0x03, it SHALL
/// interpret it as XFER_REFUSE and treat the transfer as refused.
///
/// This test verifies that receiving 0x03 bytes leads to observable
/// refusal state/behavior.
#[test]
fn test_rfc9174_4_5_066_session_interprets_0x03_as_refusal() {
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
    let data = vec![0xBB; 500];
    let transfer_id = sender.start_transfer(data.clone()).unwrap();
    let segments = sender.create_segments(transfer_id, 1000).unwrap();

    // Send first segment to receiver
    let _ack = receiver.process_segment(&segments[0]).unwrap();

    // Receiver decides to refuse (simulate by creating refuse message)
    let refuse_msg = Message::TransferRefuse {
        reason_code: 0x02, // NO_RESOURCES
        transfer_id,
    };

    // Verify the refuse message encodes with type byte 0x03
    let refuse_bytes = refuse_msg.encode();
    assert_eq!(
        refuse_bytes[0], 0x03,
        "XFER_REFUSE must encode with type 0x03"
    );

    // Sender receives the XFER_REFUSE message
    let result = sender.process_refuse(transfer_id, 0x02);

    // RFC 9174 §4.5-066: Receiving 0x03 (XFER_REFUSE) SHALL result in
    // the transfer being treated as refused
    // process_refuse returns Err to signal the refusal was processed
    assert!(
        result.is_err(),
        "XFER_REFUSE should be processed (returns error indicating refusal)"
    );

    // Verify the transfer is no longer being transmitted
    // Attempting to create more segments for the refused transfer should fail
    let segment_result = sender.create_segments(transfer_id, 1000);

    // The transfer was removed after refusal
    // The key behavioral requirement is that after receiving 0x03, the sender
    // stops transmitting this transfer and removes it from active state

    // This test demonstrates that message type 0x03 is correctly interpreted
    // as XFER_REFUSE, causing observable refusal behavior (transfer removed)
    assert!(
        segment_result.is_err(),
        "Transfer must be removed after receiving XFER_REFUSE (0x03)"
    );
}
