#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §5.2.2 Segment MRU Tests

mod common;

use interplanetary_sdk::tcpcl::{Role, SessionConfig, messages::*, transfer_flags};

#[test]
fn test_rfc9174_5_2_2_segments_respect_peer_mru() {
    // RFC 9174 §5.2.2: Data transmission SHALL be segmented into
    // XFER_SEGMENT messages, with each segment no larger than the peer's
    // Segment MRU

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 0,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "sender".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 0,
            segment_mru: 500, // Peer has smaller MRU
            transfer_mru: 10_000,
            node_id: "receiver".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    // Create transfer with 2.5× the MRU: 500 × 2.5 = 1250 bytes
    let payload = vec![0xAA; 1250];
    let transfer_id = session.start_transfer(payload).expect("Start transfer");

    // Create segments
    let segments = session
        .create_segments(transfer_id, 1024)
        .expect("Create segments");

    // Should create 3 segments: 500 + 500 + 250
    assert_eq!(
        segments.len(),
        3,
        "Should create 3 segments for 1250 bytes with MRU=500"
    );

    // Check each segment
    for (i, segment) in segments.iter().enumerate() {
        match segment {
            Message::TransferSegment { flags, data, .. } => {
                // First segment should have START flag
                if i == 0 {
                    assert_eq!(
                        *flags & transfer_flags::START,
                        transfer_flags::START,
                        "First segment must have START flag (0x02)"
                    );
                }

                // Last segment should have END flag
                if i == segments.len() - 1 {
                    assert_eq!(
                        *flags & transfer_flags::END,
                        transfer_flags::END,
                        "Last segment must have END flag (0x01)"
                    );
                }

                // Check segment size respects MRU
                assert!(
                    data.len() <= 500,
                    "Segment {} has {} bytes, exceeds MRU of 500",
                    i,
                    data.len()
                );

                // Check expected sizes
                match i {
                    0 => assert_eq!(data.len(), 500, "First segment should be 500 bytes"),
                    1 => assert_eq!(data.len(), 500, "Second segment should be 500 bytes"),
                    2 => assert_eq!(data.len(), 250, "Third segment should be 250 bytes"),
                    _ => panic!("Unexpected segment index"),
                }
            }
            _ => panic!("Expected TransferSegment message"),
        }
    }
}

#[test]
fn test_rfc9174_5_2_2_start_end_flags_with_multiple_segments() {
    // RFC 9174 §5.2.2: START flag on first segment, END flag on last

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 0,
            segment_mru: 1024,
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
            node_id: "peer".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    let payload = vec![0xBB; 250]; // 2.5× MRU
    let transfer_id = session.start_transfer(payload).expect("Start");

    let segments = session.create_segments(transfer_id, 200).expect("Segments");

    assert_eq!(segments.len(), 3, "Should create 3 segments");

    // First segment: START flag only
    if let Message::TransferSegment { flags, .. } = &segments[0] {
        assert_eq!(*flags, transfer_flags::START, "First segment: START only");
    }

    // Middle segment: no flags
    if let Message::TransferSegment { flags, .. } = &segments[1] {
        assert_eq!(*flags, 0, "Middle segment: no flags");
    }

    // Last segment: END flag only (START was already set)
    if let Message::TransferSegment { flags, .. } = &segments[2] {
        assert_eq!(*flags, transfer_flags::END, "Last segment: END only");
    }
}

#[test]
fn test_rfc9174_5_2_2_single_segment_has_both_flags() {
    // When transfer fits in one segment, it should have both START and END

    let pair = common::SessionPair::establish_with_config(
        SessionConfig {
            role: Role::Active,
            keepalive_interval: 0,
            segment_mru: 1024,
            transfer_mru: 10_000,
            node_id: "sender".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
        SessionConfig {
            role: Role::Passive,
            keepalive_interval: 0,
            segment_mru: 1000,
            transfer_mru: 10_000,
            node_id: "peer".to_string(),
            extensions: vec![],
            contact_header_timeout: 60,
            max_peer_keepalive: None,
        },
    )
    .unwrap();

    let mut session = pair.active;

    let payload = vec![0xCC; 500]; // Less than MRU
    let transfer_id = session.start_transfer(payload).expect("Start");

    let segments = session
        .create_segments(transfer_id, 1000)
        .expect("Segments");

    assert_eq!(segments.len(), 1, "Should create 1 segment");

    if let Message::TransferSegment { flags, .. } = &segments[0] {
        assert_eq!(
            *flags,
            transfer_flags::START | transfer_flags::END,
            "Single segment must have both START and END flags"
        );
    }
}
