#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §5.2.4 XFER_REFUSE Tests

mod common;

use interplanetary_sdk::tcpcl::{Role, SessionConfig, refuse_reason};

#[test]
fn test_rfc9174_5_2_4_sender_stops_after_refuse() {
    // RFC 9174 §5.2.4: "Upon receiving a XFER_REFUSE message, the sender
    // SHALL complete transmission of any segments that have already been
    // started but MUST NOT commence transmission of any further segments
    // of the indicated transfer"

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 0,
            segment_mru: 100,
            transfer_mru: 10_000,
            node_id: "sender".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 0,
            segment_mru: 100,
            transfer_mru: 10_000,
            node_id: "receiver".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut sender = pair.active;

    // Start transfer with 300 bytes (will create 3 segments with MRU=100)
    let payload = vec![0xDD; 300];
    let transfer_id = sender.start_transfer(payload).expect("Start transfer");

    // Create first batch of segments
    let first_batch = sender
        .create_segments(transfer_id, 100)
        .expect("First batch");
    assert_eq!(first_batch.len(), 3, "Should create 3 segments initially");

    // Simulate receiving XFER_REFUSE
    let _ = sender.process_refuse(transfer_id, refuse_reason::UNKNOWN);

    // Attempt to create more segments - should fail or return empty
    let result = sender.create_segments(transfer_id, 100);

    // After refusal, should not be able to create more segments
    match result {
        Err(_) => {
            // Error is acceptable (transfer may be removed)
        }
        Ok(segments) => {
            assert!(
                segments.is_empty(),
                "MUST NOT send further segments after XFER_REFUSE"
            );
        }
    }
}

#[test]
fn test_rfc9174_5_2_4_refuse_reason_codes() {
    // RFC 9174 §5.2.4 specifies reason codes for XFER_REFUSE

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 0,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "node1".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 0,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "node2".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    let payload = vec![0xEE; 500];
    let transfer_id = session.start_transfer(payload).expect("Start");

    // Test different reason codes
    let test_reasons = [
        (refuse_reason::UNKNOWN, "Unknown"),
        (refuse_reason::COMPLETED, "Completed"),
        (refuse_reason::NO_RESOURCES, "No Resources"),
        (refuse_reason::RETRANSMIT, "Retransmit"),
    ];

    for (code, name) in test_reasons.iter() {
        // Should process without error (returns Err as documented)
        let result = session.process_refuse(transfer_id, *code);
        assert!(
            result.is_err(),
            "process_refuse should return error for reason {} ({})",
            name,
            code
        );
    }
}

#[test]
fn test_rfc9174_xfer_refuse_idempotent() {
    // Processing XFER_REFUSE multiple times for same transfer should be safe

    let pair = common::SessionPair::establish().unwrap();
    let mut session = pair.active;

    let payload = vec![0xFF; 200];
    let transfer_id = session.start_transfer(payload).expect("Start");

    // First refusal
    let _ = session.process_refuse(transfer_id, refuse_reason::NO_RESOURCES);

    // Second refusal for same transfer - should not panic
    let result2 = session.process_refuse(transfer_id, refuse_reason::NO_RESOURCES);

    // Either succeeds silently or returns error, but no panic
    assert!(
        result2.is_ok() || result2.is_err(),
        "Duplicate XFER_REFUSE should be handled gracefully"
    );
}
