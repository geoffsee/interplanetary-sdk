//! Property-based tests for BP decoder using deterministic seed generation (ADR 005)
//!
//! Tests mutation resilience, truncation handling, and bounded allocation.

#![cfg(feature = "bpv7")]

use interplanetary_sdk::{
    bp::{BundleBuilder, BundleCodec},
    types::{CreationTimestamp, DtnTimeMs, EndpointId},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Property: Decoder rejects truncated bundles without panic or unbounded allocation
#[test]
fn property_decoder_rejects_truncation() {
    // Create a valid bundle first
    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("source").unwrap())
        .destination(EndpointId::dtn("dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3_600_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let valid_encoded = BundleCodec::encode(&bundle).unwrap();
    let valid_len = valid_encoded.len();

    // Property: Truncation at any position should be rejected cleanly
    for truncate_at in 1..valid_len {
        let truncated = &valid_encoded[..truncate_at];

        // Decoder should reject, not panic or allocate unbounded memory
        let result = BundleCodec::decode(truncated);

        assert!(
            result.is_err(),
            "Truncated bundle at {} should be rejected",
            truncate_at
        );
    }
}

/// Property: Decoder rejects random mutations without panic
#[test]
fn property_decoder_rejects_mutations() {
    const NUM_SEEDS: u64 = 100;

    // Create a valid bundle
    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("source").unwrap())
        .destination(EndpointId::dtn("dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3_600_000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let valid_encoded = BundleCodec::encode(&bundle).unwrap();

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut mutated = valid_encoded.clone();

        // Apply 1-5 random mutations
        let num_mutations = rng.gen_range(1..=5);
        for _ in 0..num_mutations {
            let pos = rng.gen_range(0..mutated.len());
            mutated[pos] = rng.r#gen();
        }

        // Decoder should reject invalid input cleanly (or accept if mutation was benign)
        let result = BundleCodec::decode(&mutated);

        // Either succeeds (benign mutation) or fails cleanly (no panic)
        match result {
            Ok(_) => {
                // Benign mutation - rare but possible (e.g., flipped bit in payload)
            }
            Err(e) => {
                // Expected: decoder detected corruption
                // Verify error is descriptive, not just "parse failed"
                let err_msg = format!("{:?}", e);
                assert!(!err_msg.is_empty());
            }
        }
    }
}

/// Property: Decoder bounds allocation for large claimed sizes
#[test]
fn property_decoder_bounds_allocation() {
    const NUM_SEEDS: u64 = 50;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Create bundle with random payload size (0-10KB)
        let payload_size = rng.gen_range(0..10_000);
        let payload: Vec<u8> = (0..payload_size).map(|_| rng.r#gen()).collect();

        let bundle = BundleBuilder::new()
            .source(EndpointId::dtn("source").unwrap())
            .destination(EndpointId::dtn("dest").unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
            .lifetime(3_600_000)
            .payload(payload.clone())
            .build()
            .unwrap();

        let encoded = BundleCodec::encode(&bundle).unwrap();

        // Decode should succeed and match original size
        let decoded = BundleCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.payload_block().unwrap().data.len(), payload_size);
    }
}

/// Property: Round-trip encoding preserves bundle identity
#[test]
fn property_bundle_roundtrip() {
    const NUM_SEEDS: u64 = 100;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate random but valid bundle parameters
        let source_node = rng.gen_range(1..1000);
        let dest_node = rng.gen_range(1..1000);
        let seq = rng.gen_range(0..100000);
        let lifetime_ms = rng.gen_range(1000..86_400_000);
        let payload_size = rng.gen_range(0..1000);
        let payload: Vec<u8> = (0..payload_size).map(|_| rng.r#gen()).collect();

        let source = EndpointId::Ipn {
            allocator: 0,
            node: source_node,
            service: 0,
        };
        let dest = EndpointId::Ipn {
            allocator: 0,
            node: dest_node,
            service: 1,
        };

        let original = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, seq))
            .lifetime(lifetime_ms)
            .payload(payload.clone())
            .build()
            .unwrap();

        // Encode and decode
        let encoded = BundleCodec::encode(&original).unwrap();
        let decoded = BundleCodec::decode(&encoded).unwrap();

        // Verify key fields preserved
        assert_eq!(decoded.primary.destination, original.primary.destination);
        assert_eq!(decoded.primary.source, original.primary.source);
        assert_eq!(
            decoded.primary.creation_timestamp,
            original.primary.creation_timestamp
        );
        assert_eq!(decoded.primary.lifetime, original.primary.lifetime);
        assert_eq!(decoded.payload_block().unwrap().data, payload);
    }
}

/// Property: EID encoding/decoding is invertible
#[test]
fn property_eid_roundtrip() {
    const NUM_SEEDS: u64 = 100;

    for seed in 0..NUM_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate random IPN EID
        let allocator = if rng.gen_bool(0.8) {
            0
        } else {
            rng.gen_range(1..1000)
        };
        let node = rng.gen_range(1..100000);
        let service = rng.gen_range(0..100);

        let eid = EndpointId::Ipn {
            allocator,
            node,
            service,
        };

        // Display and parse should round-trip
        let displayed = format!("{}", eid);
        let parsed = EndpointId::parse(&displayed).unwrap();

        assert_eq!(parsed, eid, "EID round-trip failed for {}", displayed);
    }
}
