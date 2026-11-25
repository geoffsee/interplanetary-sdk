//! Property-based tests for TCPCL parser using deterministic seed generation (ADR 005)
//!
//! Tests arbitrary byte-stream chunking and message framing resilience.

#![cfg(feature = "tcpclv4-model")]

use interplanetary_sdk::tcpcl::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Property: Contact header decode succeeds regardless of how bytes are chunked
#[test]
fn property_contact_header_chunking_invariant() {
    let header = ContactHeader::with_flags(ContactHeader::FLAG_CAN_TLS);
    let encoded = header.encode();

    // Property: Successful decode if and only if all 6 bytes present
    for chunk_point in 0..encoded.len() {
        let chunk1 = &encoded[..chunk_point];
        let chunk2 = &encoded[chunk_point..];

        if chunk1.len() == 6 {
            // Complete header in first chunk
            assert!(ContactHeader::decode(chunk1).is_ok());
        } else {
            // Incomplete - should fail
            assert!(ContactHeader::decode(chunk1).is_err());
        }

        // Concatenated chunks give complete header
        let mut combined = chunk1.to_vec();
        combined.extend_from_slice(chunk2);
        assert!(ContactHeader::decode(&combined).is_ok());
    }
}

/// Property: Extension item encoding is self-delimiting and parseable
#[test]
fn property_extension_item_framing() {
    const NUM_SEEDS: u64 = 100;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate random extension item
        let type_code = rng.r#gen();
        let value_len = rng.gen_range(0..100);
        let value: Vec<u8> = (0..value_len).map(|_| rng.r#gen()).collect();
        let critical = rng.gen_bool(0.3);

        let ext = ExtensionItem::new(type_code, value.clone(), critical);
        let encoded = ext.encode();

        // Decode should consume exactly the right number of bytes
        let (decoded, consumed) = ExtensionItem::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.type_code, type_code);
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.is_critical(), critical);
    }
}

/// Property: Message encoding round-trips correctly
#[test]
fn property_message_encoding_roundtrip() {
    // Test XFER_ACK messages with random parameters
    const NUM_SEEDS: u64 = 50;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        let transfer_id = rng.r#gen();
        let acked_length = rng.gen_range(0..1_000_000);

        let msg = Message::TransferAck {
            flags: 0,
            transfer_id,
            acked_length,
        };

        let encoded = msg.encode();

        // Verify structure: type(1) | flags(1) | transfer_id(8) | acked_length(8)
        assert_eq!(encoded.len(), 18);
        assert_eq!(encoded[0], Message::TYPE_XFER_ACK);

        // Verify values can be extracted
        let decoded_id = u64::from_be_bytes(encoded[2..10].try_into().unwrap());
        let decoded_acked = u64::from_be_bytes(encoded[10..18].try_into().unwrap());

        assert_eq!(decoded_id, transfer_id);
        assert_eq!(decoded_acked, acked_length);
    }
}

/// Property: Transfer segmentation preserves data and flags
#[test]
fn property_transfer_segmentation() {
    const NUM_SEEDS: u64 = 50;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate random transfer data and segment size
        let data_len = rng.gen_range(100..10_000);
        let data: Vec<u8> = (0..data_len).map(|_| rng.r#gen()).collect();
        let segment_size = rng.gen_range(100..1000);

        let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
        let mut receiver = TcpclSession::new(SessionConfig::default()).unwrap();

        // Establish session
        setup_session(&mut sender, &mut receiver);

        // Create and send segments
        let transfer_id = sender.start_transfer(data.clone()).unwrap();
        let segments = sender.create_segments(transfer_id, segment_size).unwrap();

        // Property: START flag only on first segment
        if let Message::TransferSegment { flags, .. } = &segments[0] {
            assert!(
                flags & transfer_flags::START != 0,
                "First segment must have START"
            );
        }

        // Property: END flag only on last segment
        if let Message::TransferSegment { flags, .. } = segments.last().unwrap() {
            assert!(
                flags & transfer_flags::END != 0,
                "Last segment must have END"
            );
        }

        // Property: Middle segments have neither START nor END
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

        // Property: Reassembled data matches original
        let mut reassembled = Vec::new();
        for segment in segments {
            if let Message::TransferSegment { data: seg_data, .. } = segment {
                reassembled.extend_from_slice(&seg_data);
            }
        }

        assert_eq!(reassembled, data, "Segmentation must preserve data");
    }
}

/// Property: SESS_INIT keepalive negotiation is commutative (min of both sides)
#[test]
fn property_keepalive_negotiation_commutative() {
    const NUM_SEEDS: u64 = 50;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // RFC 9174 §5.1.1: SDK clamps keepalive to [30, 600] (0 disables)
        let keepalive_a = rng.gen_range(30..120);
        let keepalive_b = rng.gen_range(30..120);
        let expected_min = std::cmp::min(keepalive_a, keepalive_b);

        let config_a = SessionConfig {
            keepalive_interval: keepalive_a,
            ..Default::default()
        };

        let config_b = SessionConfig {
            keepalive_interval: keepalive_b,
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

        // Property: Both sides negotiate to the same minimum value
        assert_eq!(
            session_a.negotiated_keepalive_interval(),
            Some(expected_min)
        );
        assert_eq!(
            session_b.negotiated_keepalive_interval(),
            Some(expected_min)
        );
    }
}

/// Property: Transfer MRU enforcement prevents resource exhaustion
#[test]
fn property_transfer_mru_enforcement() {
    const NUM_SEEDS: u64 = 30;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Random MRU between 100 and 1000 bytes
        let mru = rng.gen_range(100..1000);

        let config = SessionConfig {
            transfer_mru: mru,
            ..Default::default()
        };

        let mut receiver = TcpclSession::new(config).unwrap();
        let mut sender = TcpclSession::new(SessionConfig::default()).unwrap();
        setup_session(&mut sender, &mut receiver);

        // Try to send data exceeding MRU
        let oversized_data = vec![0xFFu8; (mru + 1) as usize];

        let segment = Message::TransferSegment {
            flags: transfer_flags::START | transfer_flags::END,
            transfer_id: 1,
            extensions: Vec::new(),
            data: oversized_data,
        };

        let response = receiver.process_segment(&segment).unwrap();

        // Property: Receiver must refuse transfer with NO_RESOURCES
        match response {
            Some(Message::TransferRefuse { reason_code, .. }) => {
                assert_eq!(
                    reason_code,
                    refuse_reason::NO_RESOURCES,
                    "Oversized transfer must be refused with NO_RESOURCES"
                );
            }
            _ => panic!("Expected XFER_REFUSE for oversized transfer"),
        }
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
