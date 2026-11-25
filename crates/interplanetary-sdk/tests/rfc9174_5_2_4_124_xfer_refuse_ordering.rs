//! RFC 9174 §5.2.4 XFER_REFUSE ordering constraint enforcement
//!
//! RFC9174-5-2-4-124: "The receiver MUST, for each transfer preceding the one to be refused,
//! have either acknowledged all XFER_SEGMENT messages or refused the bundle transfer."
#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::{
    Message, SessionConfig, TcpclSession, refuse_reason, transfer_flags,
};

/// Helper to establish a session pair
fn setup_session_pair() -> (TcpclSession, TcpclSession) {
    let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
    let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

    // Exchange contact headers
    let sender_contact = sender.send_contact_header().unwrap();
    let receiver_contact = receiver.send_contact_header().unwrap();

    sender.process_contact_header(&receiver_contact).unwrap();
    receiver.process_contact_header(&sender_contact).unwrap();

    // Exchange SESS_INIT
    let sender_init = sender.send_session_init().unwrap();
    let receiver_init = receiver.send_session_init().unwrap();

    sender.process_session_init(&receiver_init).unwrap();
    receiver.process_session_init(&sender_init).unwrap();

    (sender, receiver)
}

/// RFC9174-5-2-4-124: Refusing transfer N while earlier transfer M is incomplete violates ordering
#[test]
fn test_rfc9174_5_2_4_124_refuse_ordering_violation() {
    let (mut sender, mut receiver) = setup_session_pair();

    // Start transfer 1 with large data to ensure multiple segments
    let transfer1_data = vec![0xAA; 2000]; // 2KB to force multiple segments with 1KB segment size
    let transfer1_id = sender.start_transfer(transfer1_data).unwrap();
    let mut segments1 = sender.create_segments(transfer1_id, 1000).unwrap();

    // Ensure we have multiple segments
    assert!(segments1.len() > 1, "Need multiple segments for this test");

    // Manually modify first segment to have START but not END
    if let Message::TransferSegment { flags, .. } = &mut segments1[0] {
        *flags = transfer_flags::START; // Only START, no END
    }

    // Send only the first segment of transfer 1 (incomplete transfer)
    let _response1 = receiver.process_segment(&segments1[0]).unwrap();

    // Now try to refuse transfer 2 (which hasn't started yet)
    // This should FAIL because transfer 1 is incomplete
    let result = receiver.refuse_incoming_transfer(2, refuse_reason::NO_RESOURCES);

    assert!(
        result.is_err(),
        "RFC9174-5-2-4-124: Must not refuse transfer 2 while transfer 1 is incomplete"
    );

    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("RFC 9174 §5.2.4"),
        "Error should reference RFC 9174 §5.2.4"
    );
    assert!(
        err.to_string().contains("transfer 1"),
        "Error should mention incomplete transfer 1"
    );
}

/// RFC9174-5-2-4-124: Can refuse transfer N after all earlier transfers are completed
#[test]
fn test_rfc9174_5_2_4_124_refuse_after_completion() {
    let (mut sender, mut receiver) = setup_session_pair();

    // Transfer 1: Complete (START + END in single segment)
    let transfer1_data = vec![0xAA; 100];
    let transfer1_id = sender.start_transfer(transfer1_data).unwrap();
    let segments1 = sender.create_segments(transfer1_id, 1000).unwrap();

    for segment in &segments1 {
        let _response = receiver.process_segment(segment).unwrap();
    }

    // Now transfer 1 is complete (ended=true)
    // Should be able to refuse transfer 2
    let result = receiver.refuse_incoming_transfer(2, refuse_reason::NO_RESOURCES);

    assert!(
        result.is_ok(),
        "RFC9174-5-2-4-124: Can refuse transfer 2 after transfer 1 is complete"
    );
}

/// RFC9174-5-2-4-124: Can refuse transfer N after all earlier transfers are refused
#[test]
fn test_rfc9174_5_2_4_124_refuse_after_earlier_refused() {
    let (mut _sender, mut receiver) = setup_session_pair();

    // Refuse transfer 1 first
    let _refuse1 = receiver
        .refuse_incoming_transfer(1, refuse_reason::NO_RESOURCES)
        .unwrap();

    // Now should be able to refuse transfer 2 (transfer 1 is refused)
    let result = receiver.refuse_incoming_transfer(2, refuse_reason::NO_RESOURCES);

    assert!(
        result.is_ok(),
        "RFC9174-5-2-4-124: Can refuse transfer 2 after transfer 1 is refused"
    );
}

/// RFC9174-5-2-4-124: Auto-refuse earlier incomplete transfers when refusing automatically
#[test]
fn test_rfc9174_5_2_4_124_auto_refuse_on_critical_extension() {
    let (mut sender, mut receiver) = setup_session_pair();

    // Start transfer 1 (incomplete)
    let transfer1_data = vec![0xAA; 100];
    let transfer1_id = sender.start_transfer(transfer1_data).unwrap();
    let mut segments1 = sender.create_segments(transfer1_id, 1000).unwrap();

    // Modify to only send START segment (incomplete)
    if let Message::TransferSegment { flags, .. } = &mut segments1[0] {
        // Keep START flag, remove END flag
        *flags = transfer_flags::START;
    }

    let _response1 = receiver.process_segment(&segments1[0]).unwrap();

    // Transfer 2: Send segment with unsupported critical extension
    // This will trigger automatic refusal
    let critical_ext = interplanetary_sdk::tcpcl::ExtensionItem {
        flags: 0x01, // Critical
        type_code: 9999,
        value: vec![],
    };

    let segment2_with_critical_ext = Message::TransferSegment {
        flags: transfer_flags::START | transfer_flags::END,
        transfer_id: 2,
        extensions: vec![critical_ext],
        data: vec![0xBB; 50],
    };

    let response2 = receiver
        .process_segment(&segment2_with_critical_ext)
        .unwrap();

    // Should get XFER_REFUSE for transfer 2 due to critical extension
    if let Some(Message::TransferRefuse {
        transfer_id,
        reason_code,
        ..
    }) = response2
    {
        assert_eq!(transfer_id, 2);
        assert_eq!(reason_code, refuse_reason::EXTENSION_FAILURE);
    } else {
        panic!("Expected XFER_REFUSE for critical extension");
    }

    // The implementation should have auto-refused transfer 1 to maintain ordering
    // Try to send another segment for transfer 1 - should get XFER_REFUSE
    let late_segment1 = Message::TransferSegment {
        flags: transfer_flags::END,
        transfer_id: transfer1_id,
        extensions: vec![],
        data: vec![0xAA; 50],
    };

    let late_response = receiver.process_segment(&late_segment1).unwrap();

    if let Some(Message::TransferRefuse { transfer_id, .. }) = late_response {
        assert_eq!(
            transfer_id, transfer1_id,
            "RFC9174-5-2-4-124: Transfer 1 should have been auto-refused to maintain ordering"
        );
    } else {
        panic!("Expected XFER_REFUSE for transfer 1 (auto-refused to maintain ordering)");
    }
}
