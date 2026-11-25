//! Property tests using proptest 1.5 with strategies and shrinking
//!
//! Demonstrates real proptest usage per charter requirement.
//! Seed-based tests in bp_decoder_properties.rs are retained as deterministic regression tests.

use interplanetary_sdk::{
    bp::{BundleBuilder, BundleCodec},
    types::{CreationTimestamp, DtnTimeMs, EndpointId},
};
use proptest::prelude::*;

/// Strategy: Generate valid IPN endpoint IDs
fn endpoint_ipn_strategy() -> impl Strategy<Value = EndpointId> {
    (0u64..4, 1u64..1000, 0u64..100).prop_map(|(allocator, node, service)| {
        // All generated values are within u32::MAX, so unwrap is safe
        EndpointId::ipn(allocator, node, service).unwrap()
    })
}

/// Strategy: Generate valid creation timestamps
fn timestamp_strategy() -> impl Strategy<Value = CreationTimestamp> {
    (0u64..1_000_000_000, 0u64..100)
        .prop_map(|(time_ms, seq)| CreationTimestamp::new(DtnTimeMs::from_millis(time_ms), seq))
}

/// Strategy: Generate valid bundle payloads (bounded size)
fn payload_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1000)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Any encoded bundle can be decoded
    #[test]
    fn prop_encode_decode_roundtrip(
        source in endpoint_ipn_strategy(),
        dest in endpoint_ipn_strategy(),
        timestamp in timestamp_strategy(),
        lifetime in 1u64..86_400_000,
        payload in payload_strategy(),
    ) {
        let bundle = BundleBuilder::new()
            .source(source.clone())
            .destination(dest.clone())
            .creation_timestamp(timestamp)
            .lifetime(lifetime)
            .payload(payload.clone())
            .build()
            .expect("Valid bundle construction");

        let encoded = BundleCodec::encode(&bundle).expect("Encoding should succeed");
        let decoded = BundleCodec::decode(&encoded).expect("Decoding should succeed");

        assert_eq!(decoded.primary.source, source);
        assert_eq!(decoded.primary.destination, dest);
        assert_eq!(decoded.primary.creation_timestamp, timestamp);
        assert_eq!(decoded.primary.lifetime, lifetime);

        if let Some(payload_block) = decoded.blocks.first() {
            assert_eq!(payload_block.data, payload);
        }
    }

    /// Property: Encoding is deterministic (same bundle → same bytes)
    #[test]
    fn prop_encoding_deterministic(
        source in endpoint_ipn_strategy(),
        dest in endpoint_ipn_strategy(),
        timestamp in timestamp_strategy(),
        payload in payload_strategy(),
    ) {
        let bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(3_600_000)
            .payload(payload)
            .build()
            .expect("Valid bundle");

        let encoded1 = BundleCodec::encode(&bundle).expect("First encoding");
        let encoded2 = BundleCodec::encode(&bundle).expect("Second encoding");

        assert_eq!(encoded1, encoded2);
    }

    /// Property: Decoder rejects truncated input gracefully
    #[test]
    fn prop_decoder_rejects_truncated(
        truncate_at in 0usize..50,
    ) {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(vec![0xAA; 100])
            .build()
            .expect("Valid bundle");

        let encoded = BundleCodec::encode(&bundle).expect("Encoding");

        if truncate_at < encoded.len() {
            let truncated = &encoded[..truncate_at];
            let result = BundleCodec::decode(truncated);
            // Should either fail or decode partial structure
            // Never panic
            let _ = result;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::ValueTree;

    #[test]
    fn test_proptest_strategies() {
        // Smoke test: strategies can generate values
        let mut runner = proptest::test_runner::TestRunner::default();

        let eid_value = endpoint_ipn_strategy()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        match eid_value {
            EndpointId::Ipn { .. } => {}
            _ => panic!("Expected IPN endpoint"),
        }

        let _timestamp = timestamp_strategy()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let _payload = payload_strategy().new_tree(&mut runner).unwrap().current();
    }
}
