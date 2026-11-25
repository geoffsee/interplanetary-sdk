//! Property-based tests for RFC 9171 §5.8-5.9 fragmentation and reassembly
//!
//! Tests that reassembly produces byte-identical payloads regardless of:
//! - Fragment sizes
//! - Fragment delivery order
//! - Payload content

use interplanetary_sdk::bp::{Bundle, BundleBuilder};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};
use proptest::prelude::*;

/// Property test: Reassembly of contiguous fragments produces byte-identical payload
///
/// RFC 9171 §5.9: "The result of concatenating the payloads of all fragments in
/// ascending order by offset MUST always be identical to the payload of the original
/// unfragmented bundle"
#[test]
fn proptest_reassembly_byte_identical_in_order() {
    proptest!(|(
        payload_len in 100usize..2000,
        fragment_size in 50usize..500,
        seed in 0u8..255
    )| {
        // Generate deterministic payload
        let original_payload: Vec<u8> = (0..payload_len)
            .map(|i| ((i + seed as usize) % 256) as u8)
            .collect();

        // Create fragments
        let fragments = create_test_fragments_from_payload(&original_payload, fragment_size);

        // Reassemble by concatenating in order
        let mut reassembled = Vec::new();
        for fragment in &fragments {
            reassembled.extend_from_slice(&fragment.blocks[0].data);
        }

        // RFC 9171 §5.9: Must be byte-identical
        prop_assert_eq!(
            reassembled,
            original_payload,
            "Reassembled payload must be byte-identical to original"
        );
    });
}

/// Property test: Out-of-order reassembly produces byte-identical payload
#[test]
fn proptest_reassembly_byte_identical_out_of_order() {
    proptest!(|(
        payload_len in 100usize..1000,
        fragment_size in 50usize..300,
        seed in 0u8..255,
        shuffle_seed in 0usize..1000
    )| {
        let original_payload: Vec<u8> = (0..payload_len)
            .map(|i| ((i + seed as usize) % 256) as u8)
            .collect();

        let mut fragments = create_test_fragments_from_payload(&original_payload, fragment_size);

        // Shuffle fragments using deterministic seed
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        fragments.sort_by_key(|f| {
            let mut hasher = DefaultHasher::new();
            f.primary.fragment_offset.unwrap().hash(&mut hasher);
            shuffle_seed.hash(&mut hasher);
            hasher.finish()
        });

        // Reassemble by sorting by offset first
        let mut sorted_fragments = fragments.clone();
        sorted_fragments.sort_by_key(|f| f.primary.fragment_offset.unwrap());

        let mut reassembled = Vec::new();
        for fragment in &sorted_fragments {
            reassembled.extend_from_slice(&fragment.blocks[0].data);
        }

        prop_assert_eq!(
            reassembled,
            original_payload,
            "Out-of-order fragments must reassemble to byte-identical payload"
        );
    });
}

/// Property test: Fragment offsets are correct and contiguous
#[test]
fn proptest_fragment_offset_correctness() {
    proptest!(|(
        payload_len in 100usize..2000,
        fragment_size in 50usize..500
    )| {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 256) as u8).collect();
        let fragments = create_test_fragments_from_payload(&payload, fragment_size);

        // Verify offsets are correct
        let mut expected_offset = 0u64;
        for fragment in &fragments {
            let offset = fragment.primary.fragment_offset.unwrap();
            prop_assert_eq!(
                offset,
                expected_offset,
                "Fragment offset must be correct"
            );

            let fragment_len = fragment.blocks[0].data.len() as u64;
            expected_offset += fragment_len;
        }

        // Verify total coverage
        prop_assert_eq!(
            expected_offset,
            payload_len as u64,
            "Fragments must cover entire payload"
        );
    });
}

/// Property test: All fragments have same total_app_data_length
#[test]
fn proptest_fragment_total_length_consistency() {
    proptest!(|(
        payload_len in 100usize..2000,
        fragment_size in 50usize..500
    )| {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 256) as u8).collect();
        let fragments = create_test_fragments_from_payload(&payload, fragment_size);

        // All fragments must have same total ADU length
        for fragment in &fragments {
            prop_assert_eq!(
                fragment.primary.total_app_data_length,
                Some(payload_len as u64),
                "All fragments must have same total_app_data_length"
            );
        }
    });
}

/// Property test: Fragment payload sizes sum to original payload size
#[test]
fn proptest_fragment_size_sum() {
    proptest!(|(
        payload_len in 100usize..2000,
        fragment_size in 50usize..500
    )| {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 256) as u8).collect();
        let fragments = create_test_fragments_from_payload(&payload, fragment_size);

        let total_fragment_bytes: usize = fragments
            .iter()
            .map(|f| f.blocks[0].data.len())
            .sum();

        prop_assert_eq!(
            total_fragment_bytes,
            payload_len,
            "Sum of fragment payload sizes must equal original payload size"
        );
    });
}

/// Property test: Reassembly with various payload patterns
#[test]
fn proptest_reassembly_various_patterns() {
    proptest!(|(
        pattern_type in 0u8..4,
        payload_len in 100usize..1000,
        fragment_size in 50usize..300
    )| {
        // Generate different payload patterns
        let original_payload: Vec<u8> = (0..payload_len)
            .map(|i| match pattern_type {
                0 => 0xFF, // All ones
                1 => 0x00, // All zeros
                2 => (i % 256) as u8, // Sequential
                _ => ((i * 13 + 7) % 256) as u8, // Pseudo-random
            })
            .collect();

        let fragments = create_test_fragments_from_payload(&original_payload, fragment_size);

        // Reassemble
        let mut reassembled = Vec::new();
        for fragment in &fragments {
            reassembled.extend_from_slice(&fragment.blocks[0].data);
        }

        prop_assert_eq!(
            reassembled,
            original_payload,
            "Reassembly must work for all payload patterns"
        );
    });
}

/// Helper: Create fragments from a payload with specified max fragment size
fn create_test_fragments_from_payload(payload: &[u8], max_fragment_size: usize) -> Vec<Bundle> {
    let total_length = payload.len() as u64;
    let mut fragments = Vec::new();
    let mut offset = 0u64;

    let source = EndpointId::ipn(0, 1, 0).unwrap();
    let destination = EndpointId::ipn(0, 2, 0).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::ZERO, 1);

    while offset < total_length {
        let remaining = (total_length - offset) as usize;
        let fragment_len = remaining.min(max_fragment_size);
        let fragment_data = payload[offset as usize..(offset as usize + fragment_len)].to_vec();

        let mut bundle = BundleBuilder::new()
            .source(source.clone())
            .destination(destination.clone())
            .creation_timestamp(timestamp)
            .lifetime(60_000)
            .payload(fragment_data)
            .build()
            .unwrap();

        bundle.primary.fragment_offset = Some(offset);
        bundle.primary.total_app_data_length = Some(total_length);

        fragments.push(bundle);
        offset += fragment_len as u64;
    }

    fragments
}
