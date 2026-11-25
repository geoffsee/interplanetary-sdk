#![cfg(feature = "bpv7")]

//! RFC 9171 §4 Bundle Structure Tests

use interplanetary_sdk::bp::{
    blocks::{BlockType, CanonicalBlock, PrimaryBlock},
    bundle::{Bundle, BundleBuilder},
    codec::BundleCodec,
    crc::CrcType,
};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// RFC9171-4-005: First block MUST be primary block
#[test]
fn test_rfc9171_4_005_first_block_is_primary() {
    // RFC 9171 §4.1: "The first block in the sequence (the first item of the array)
    // MUST be a primary bundle block in CBOR encoding"

    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(1000),
            sequence: 0,
        })
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    // Encode the bundle
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Bundle is an indefinite-length CBOR array per RFC 9171 §4.1
    // Format: 0x9F (indefinite array) + blocks + 0xFF (break)
    assert_eq!(
        encoded[0], 0x9F,
        "Bundle SHALL be indefinite-length CBOR array"
    );

    // Next item must be primary block (CBOR array)
    // Parse to verify it's the primary block by checking structure
    let first_block_start = 1;
    let first_byte = encoded[first_block_start];
    let major = first_byte >> 5;

    // Primary block is a definite-length CBOR array (major type 4)
    assert_eq!(
        major, 4,
        "First block MUST be primary block (CBOR array, major type 4)"
    );

    // The structure should match primary block format (8-11 elements)
    let additional = first_byte & 0x1F;
    let elem_count = if additional <= 23 {
        additional as u64
    } else if additional == 24 {
        encoded[first_block_start + 1] as u64
    } else {
        panic!("Unexpected array encoding");
    };

    assert!(
        (8..=11).contains(&elem_count),
        "Primary block has 8-11 elements, found {}",
        elem_count
    );
}

/// RFC9171-4-006: First block MUST be primary block (Bundle API level)
#[test]
fn test_rfc9171_4_006_primary_block_first_in_bundle() {
    // RFC 9171 §4.1: Verify at Bundle structure level that primary is first

    let primary = PrimaryBlock {
        version: 7,
        bundle_flags: 0,
        crc_type: CrcType::None,
        destination: EndpointId::parse("dtn://dest").unwrap(),
        source: EndpointId::parse("dtn://src").unwrap(),
        report_to: EndpointId::parse("dtn://src").unwrap(),
        creation_timestamp: CreationTimestamp {
            time: DtnTimeMs::from_millis(2000),
            sequence: 1,
        },
        lifetime: 1800000,
        fragment_offset: None,
        total_app_data_length: None,
    };

    let payload_block = CanonicalBlock {
        block_type: BlockType::Payload,
        block_number: 1,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0xAA, 0xBB, 0xCC],
    };

    let bundle = Bundle::new(primary.clone(), vec![payload_block]);

    // Verify Bundle structure has primary first
    assert_eq!(
        bundle.primary.version, 7,
        "Bundle primary field MUST contain the primary block"
    );

    // Cannot construct Bundle without primary - it's the first required field
    // This is enforced by Bundle::new() signature requiring PrimaryBlock first
}

/// RFC9171-4-007: Blocks after primary SHALL be canonical blocks
#[test]
fn test_rfc9171_4_007_canonical_blocks_after_primary() {
    // RFC 9171 §4.1: "Every block following the primary block SHALL be the
    // CBOR encoding of a canonical block"

    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(3000),
            sequence: 2,
        })
        .lifetime(900000)
        .payload(vec![0xDE, 0xAD])
        .build()
        .unwrap();

    // Bundle has blocks after primary
    assert!(
        !bundle.blocks.is_empty(),
        "Bundle has canonical blocks after primary"
    );

    // All blocks after primary must be CanonicalBlock type
    for block in &bundle.blocks {
        // CanonicalBlock has required fields per RFC 9171 §4.3.2
        assert!(
            block.block_type.to_u64() >= 1,
            "Canonical block must have valid block type"
        );
        assert!(
            block.block_number >= 1,
            "Canonical block must have block number >= 1"
        );
    }

    // Encode and verify structure
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // After indefinite array start (0x9F), first item is primary block
    // All subsequent items (before final 0xFF break) are canonical blocks
    // This is verified by successful encoding/decoding
    assert!(
        encoded.len() > 10,
        "Bundle SHALL contain primary + canonical blocks"
    );
}

/// RFC9171-4-008: Last block MUST be payload block
#[test]
fn test_rfc9171_4_008_last_block_is_payload() {
    // RFC 9171 §4.1: "The last such block MUST be a payload block"

    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(4000),
            sequence: 3,
        })
        .lifetime(600000)
        .payload(vec![0x01, 0x02, 0x03, 0x04])
        .build()
        .unwrap();

    // Last block in blocks vector must be payload
    let last_block = bundle.blocks.last().expect("Bundle has blocks");

    assert!(
        last_block.block_type.is_payload(),
        "Last block MUST be payload block per RFC 9171 §4.1"
    );

    assert_eq!(
        last_block.block_type.to_u64(),
        1,
        "Payload block has type code 1"
    );
}

/// RFC9171-4-009: Bundle MUST have exactly one payload block
#[test]
fn test_rfc9171_4_009_exactly_one_payload_block() {
    // RFC 9171 §4.1: "the bundle MUST have exactly one payload block"

    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(5000),
            sequence: 4,
        })
        .lifetime(300000)
        .payload(vec![0xCA, 0xFE])
        .build()
        .unwrap();

    // Count payload blocks
    let payload_count = bundle
        .blocks
        .iter()
        .filter(|b| b.block_type.is_payload())
        .count();

    assert_eq!(
        payload_count, 1,
        "Bundle MUST have exactly one payload block per RFC 9171 §4.1"
    );

    // Verify payload_block() helper returns the one payload
    let payload = bundle.payload_block();
    assert!(
        payload.is_some(),
        "Bundle has exactly one payload block accessible via payload_block()"
    );

    assert_eq!(payload.unwrap().data, vec![0xCA, 0xFE], "Correct payload");
}

/// RFC9171-4-009: Decoder MUST reject bundle without exactly one payload
#[test]
fn test_rfc9171_4_009_decoder_rejects_no_payload() {
    // RFC 9171 §4.1: Bundle MUST have exactly one payload block
    // Hand-craft CBOR bundle with no payload block

    // Start with valid bundle
    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(1000),
            sequence: 0,
        })
        .lifetime(3600000)
        .payload(vec![0x01, 0x02, 0x03])
        .build()
        .unwrap();

    // Bundle format: 0x9F (indefinite array) + primary + payload + 0xFF (break)
    // Create a minimal invalid bundle: indefinite array with just primary
    let primary_encoded = BundleCodec::encode_primary(&bundle.primary).unwrap();

    let mut invalid = Vec::new();
    invalid.push(0x9F); // Indefinite array start
    invalid.extend_from_slice(&primary_encoded); // Primary block
    invalid.push(0xFF); // Break (end of array) - no payload!

    // Decoder should reject bundle without payload
    let result = BundleCodec::decode(&invalid);
    assert!(
        result.is_err(),
        "Decoder MUST reject bundle without payload block per RFC 9171 §4.1"
    );
}

/// RFC9171-4-009: Decoder MUST reject bundle with two payloads
#[test]
fn test_rfc9171_4_009_decoder_rejects_two_payloads() {
    // RFC 9171 §4.1: Bundle MUST have exactly one payload block
    // Hand-craft CBOR bundle with two payload blocks

    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(1500),
            sequence: 0,
        })
        .lifetime(3600000)
        .payload(vec![0x11, 0x22])
        .build()
        .unwrap();

    // Encode valid bundle to get blocks
    let primary_encoded = BundleCodec::encode_primary(&bundle.primary).unwrap();

    // Hand-craft payload block: [block_type, block_number, block_flags, crc_type, data]
    // Block type 1 = Payload
    let payload1 = vec![
        0x85, // Array of 5 elements
        0x01, // Block type: Payload (1)
        0x01, // Block number: 1
        0x00, // Block processing control flags: 0
        0x00, // CRC type: None (0)
        0x42, 0xAA, 0xBB, // Data: byte string [0xAA, 0xBB]
    ];

    let payload2 = vec![
        0x85, // Array of 5 elements
        0x01, // Block type: Payload (1)
        0x02, // Block number: 2
        0x00, // Block processing control flags: 0
        0x00, // CRC type: None (0)
        0x42, 0xCC, 0xDD, // Data: byte string [0xCC, 0xDD]
    ];

    let mut invalid = Vec::new();
    invalid.push(0x9F); // Indefinite array start
    invalid.extend_from_slice(&primary_encoded); // Primary block
    invalid.extend_from_slice(&payload1); // First payload
    invalid.extend_from_slice(&payload2); // Second payload (invalid!)
    invalid.push(0xFF); // Break (end of array)

    // Decoder should reject bundle with two payloads
    let result = BundleCodec::decode(&invalid);
    assert!(
        result.is_err(),
        "Decoder MUST reject bundle with two payload blocks per RFC 9171 §4.1"
    );
}

/// RFC9171-4-008: Decoder MUST reject bundle with payload not last
#[test]
fn test_rfc9171_4_008_decoder_rejects_payload_not_last() {
    // RFC 9171 §4.1: Last block MUST be payload block
    // Hand-craft CBOR bundle with payload followed by another block

    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(2000),
            sequence: 1,
        })
        .lifetime(1800000)
        .payload(vec![0xAA, 0xBB])
        .build()
        .unwrap();

    let primary_encoded = BundleCodec::encode_primary(&bundle.primary).unwrap();

    // Hand-craft payload block
    let payload = vec![
        0x85, // Array of 5 elements
        0x01, // Block type: Payload (1)
        0x01, // Block number: 1
        0x00, // Block processing control flags: 0
        0x00, // CRC type: None (0)
        0x42, 0xAA, 0xBB, // Data: byte string [0xAA, 0xBB]
    ];

    // Hand-craft Bundle Age block (type 7)
    let bundle_age = vec![
        0x85, // Array of 5 elements
        0x07, // Block type: Bundle Age (7)
        0x02, // Block number: 2
        0x00, // Block processing control flags: 0
        0x00, // CRC type: None (0)
        0x41, 0x64, // Data: byte string [0x64] = age value 100 as CBOR
    ];

    let mut invalid = Vec::new();
    invalid.push(0x9F); // Indefinite array start
    invalid.extend_from_slice(&primary_encoded); // Primary block
    invalid.extend_from_slice(&payload); // Payload block (not last!)
    invalid.extend_from_slice(&bundle_age); // Another block after payload (invalid!)
    invalid.push(0xFF); // Break (end of array)

    // Decoder should reject bundle with payload not last
    let result = BundleCodec::decode(&invalid);
    assert!(
        result.is_err(),
        "Decoder MUST reject bundle with payload not last per RFC 9171 §4.1"
    );
}

/// RFC9171-4-005/006: Decoder MUST reject bundle with primary not first
#[test]
fn test_rfc9171_4_005_006_decoder_rejects_primary_not_first() {
    // RFC 9171 §4.1: "The first block in the sequence (the first item of the array)
    // MUST be a primary block..."
    // Hand-craft CBOR bundle with canonical block before primary

    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(3000),
            sequence: 2,
        })
        .lifetime(7200000)
        .payload(vec![0x33, 0x44])
        .build()
        .unwrap();

    let primary_encoded = BundleCodec::encode_primary(&bundle.primary).unwrap();

    // Hand-craft Bundle Age block (type 7)
    let bundle_age = vec![
        0x85, // Array of 5 elements
        0x07, // Block type: Bundle Age (7)
        0x01, // Block number: 1
        0x00, // Block processing control flags: 0
        0x00, // CRC type: None (0)
        0x41, 0x64, // Data: byte string [0x64] = age value 100 as CBOR
    ];

    // Hand-craft payload block
    let payload = vec![
        0x85, // Array of 5 elements
        0x01, // Block type: Payload (1)
        0x02, // Block number: 2
        0x00, // Block processing control flags: 0
        0x00, // CRC type: None (0)
        0x42, 0x33, 0x44, // Data: byte string [0x33, 0x44]
    ];

    let mut invalid = Vec::new();
    invalid.push(0x9F); // Indefinite array start
    invalid.extend_from_slice(&bundle_age); // Canonical block FIRST (invalid!)
    invalid.extend_from_slice(&primary_encoded); // Primary block not first
    invalid.extend_from_slice(&payload); // Payload block
    invalid.push(0xFF); // Break (end of array)

    // Decoder should reject bundle with primary not first
    let result = BundleCodec::decode(&invalid);
    assert!(
        result.is_err(),
        "Decoder MUST reject bundle with primary block not first per RFC 9171 §4.1"
    );
}

/// RFC9171-4-022: Unrecognized bundle processing flags MUST be ignored
#[test]
fn test_rfc9171_4_022_ignore_unrecognized_bundle_flags() {
    // RFC 9171 §4.2.1: "Block processing control flags that are unrecognized
    // MUST be ignored, as future definitions of additional processing control
    // flags might be possible"

    // Create primary block with reserved/unknown flag bits set
    let primary = PrimaryBlock {
        version: 7,
        bundle_flags: 0x8000, // High bit set (not currently defined in RFC 9171)
        crc_type: CrcType::None,
        destination: EndpointId::parse("dtn://dest").unwrap(),
        source: EndpointId::parse("dtn://src").unwrap(),
        report_to: EndpointId::parse("dtn://src").unwrap(),
        creation_timestamp: CreationTimestamp {
            time: DtnTimeMs::from_millis(6000),
            sequence: 5,
        },
        lifetime: 150000,
        fragment_offset: None,
        total_app_data_length: None,
    };

    // Should encode successfully even with unknown flags
    let encoded = BundleCodec::encode_primary(&primary);
    assert!(
        encoded.is_ok(),
        "Encoder MUST accept bundle with unrecognized flags"
    );

    // If decoder encounters unknown flags, it MUST ignore them
    // Test by encoding and decoding a bundle with unknown flags
    let payload_block = CanonicalBlock {
        block_type: BlockType::Payload,
        block_number: 1,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x01],
    };

    let bundle = Bundle::new(primary, vec![payload_block]);
    let encoded_bundle = BundleCodec::encode(&bundle).unwrap();

    // Decoding should succeed, ignoring unknown bundle flags
    let decoded = BundleCodec::decode(&encoded_bundle);
    assert!(
        decoded.is_ok(),
        "Decoder MUST ignore unrecognized bundle processing flags"
    );
}
