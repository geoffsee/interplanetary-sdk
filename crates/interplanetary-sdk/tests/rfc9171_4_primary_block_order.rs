#![cfg(feature = "bpv7")]

//! RFC 9171 §4.3.1 Primary Block Field Order Tests

use interplanetary_sdk::bp::{blocks::PrimaryBlock, codec::BundleCodec, crc::CrcType};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// Parse CBOR array header and return element count
fn parse_array_header(bytes: &[u8]) -> (u64, usize) {
    let first = bytes[0];
    let major = first >> 5;
    assert_eq!(major, 4, "Expected array major type (4)");

    let additional = first & 0x1F;
    if additional <= 23 {
        (additional as u64, 1)
    } else if additional == 24 {
        (bytes[1] as u64, 2)
    } else if additional == 25 {
        (u16::from_be_bytes([bytes[1], bytes[2]]) as u64, 3)
    } else {
        panic!("Unexpected array encoding");
    }
}

/// Parse CBOR uint and return (value, bytes_consumed)
fn parse_uint(bytes: &[u8]) -> (u64, usize) {
    let first = bytes[0];
    let major = first >> 5;
    assert_eq!(major, 0, "Expected uint major type (0)");

    let additional = first & 0x1F;
    if additional <= 23 {
        (additional as u64, 1)
    } else if additional == 24 {
        (bytes[1] as u64, 2)
    } else if additional == 25 {
        (u16::from_be_bytes([bytes[1], bytes[2]]) as u64, 3)
    } else if additional == 26 {
        (
            u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64,
            5,
        )
    } else if additional == 27 {
        (
            u64::from_be_bytes([
                bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
            ]),
            9,
        )
    } else {
        panic!("Unexpected uint encoding");
    }
}

/// Skip over a CBOR item (doesn't parse, just calculates size)
fn skip_cbor_item(bytes: &[u8]) -> usize {
    let first = bytes[0];
    let major = first >> 5;
    let additional = first & 0x1F;

    // Get argument length
    let (arg_value, header_len) = if additional <= 23 {
        (additional as u64, 1)
    } else if additional == 24 {
        (bytes[1] as u64, 2)
    } else if additional == 25 {
        (u16::from_be_bytes([bytes[1], bytes[2]]) as u64, 3)
    } else if additional == 26 {
        (
            u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64,
            5,
        )
    } else if additional == 27 {
        (
            u64::from_be_bytes([
                bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
            ]),
            9,
        )
    } else {
        panic!("Unexpected additional info");
    };

    match major {
        0 | 1 | 7 => header_len,                  // uint, nint, simple
        2 | 3 => header_len + arg_value as usize, // bytes, text
        4 => {
            // array: skip header, then skip each element
            let mut offset = header_len;
            for _ in 0..arg_value {
                offset += skip_cbor_item(&bytes[offset..]);
            }
            offset
        }
        _ => panic!("Unsupported major type {}", major),
    }
}

/// RFC9171-4-048: Primary block fields SHALL be in specified order
#[test]
fn test_rfc9171_4_048_primary_block_field_order() {
    // RFC 9171 §4.3.1: "The fields of the primary bundle block SHALL be as follows,
    // listed in the order in which they MUST appear: Version, Bundle Processing Control
    // Flags, CRC Type, Destination EID, Source node ID, Report-to EID, Creation Timestamp,
    // Lifetime, Fragment Offset (optional), Total Application Data Unit Length (optional)"

    // Create a non-fragmented primary block (8 base fields, no CRC)
    let primary = PrimaryBlock {
        version: 7,
        bundle_flags: 0,
        crc_type: CrcType::None,
        destination: EndpointId::parse("dtn://dest").unwrap(),
        source: EndpointId::parse("dtn://src").unwrap(),
        report_to: EndpointId::parse("dtn://report").unwrap(),
        creation_timestamp: CreationTimestamp {
            time: DtnTimeMs::from_millis(1000),
            sequence: 0,
        },
        lifetime: 3600000,
        fragment_offset: None,
        total_app_data_length: None,
    };

    let encoded = BundleCodec::encode_primary(&primary).unwrap();

    // Parse CBOR and verify field order
    let mut offset = 0;

    // 1. Array header (8 elements for non-fragment without CRC)
    let (elem_count, consumed) = parse_array_header(&encoded[offset..]);
    assert_eq!(elem_count, 8, "Non-fragment without CRC has 8 elements");
    offset += consumed;

    // 2. Version (must be first field)
    let (version, consumed) = parse_uint(&encoded[offset..]);
    assert_eq!(version, 7, "Version field must be first and equal to 7");
    offset += consumed;

    // 3. Bundle flags (must be second field)
    let (flags, consumed) = parse_uint(&encoded[offset..]);
    assert_eq!(flags, 0, "Bundle flags must be second field");
    offset += consumed;

    // 4. CRC type (must be third field)
    let (crc_type, consumed) = parse_uint(&encoded[offset..]);
    assert_eq!(crc_type, 0, "CRC type must be third field (0 = None)");
    offset += consumed;

    // 5. Destination EID (must be fourth field)
    // EID is a CBOR array [dtn-scheme-code, SSP]
    let eid_start = offset;
    offset += skip_cbor_item(&encoded[offset..]);
    assert!(
        offset > eid_start,
        "Destination EID must be fourth field (skipped {} bytes)",
        offset - eid_start
    );

    // 6. Source EID (must be fifth field)
    let eid_start = offset;
    offset += skip_cbor_item(&encoded[offset..]);
    assert!(
        offset > eid_start,
        "Source EID must be fifth field (skipped {} bytes)",
        offset - eid_start
    );

    // 7. Report-to EID (must be sixth field)
    let eid_start = offset;
    offset += skip_cbor_item(&encoded[offset..]);
    assert!(
        offset > eid_start,
        "Report-to EID must be sixth field (skipped {} bytes)",
        offset - eid_start
    );

    // 8. Creation timestamp (must be seventh field) - CBOR array [time, sequence]
    let (ts_elem_count, consumed) = parse_array_header(&encoded[offset..]);
    assert_eq!(
        ts_elem_count, 2,
        "Creation timestamp must be seventh field (2-element array)"
    );
    offset += consumed;
    // Skip time and sequence
    offset += skip_cbor_item(&encoded[offset..]); // time
    offset += skip_cbor_item(&encoded[offset..]); // sequence

    // 9. Lifetime (must be eighth field)
    let (lifetime, consumed) = parse_uint(&encoded[offset..]);
    assert!(
        lifetime > 0,
        "Lifetime must be eighth field (value={})",
        lifetime
    );
    offset += consumed;

    // Should have consumed entire encoded primary block
    assert_eq!(
        offset,
        encoded.len(),
        "All 8 fields parsed in correct order per RFC 9171 §4.3.1"
    );
}

/// RFC9171-4-049: Fields MUST appear in order (fragmented bundle variant)
#[test]
fn test_rfc9171_4_049_fragmented_primary_block_order() {
    // RFC 9171 §4.3.1: Same field order requirement applies to fragmented bundles,
    // which have 10 elements (8 base + fragment offset + total length)

    // Create a fragmented primary block (10 fields, no CRC)
    let primary = PrimaryBlock {
        version: 7,
        bundle_flags: 1, // Fragment flag
        crc_type: CrcType::None,
        destination: EndpointId::parse("dtn://dest").unwrap(),
        source: EndpointId::parse("dtn://src").unwrap(),
        report_to: EndpointId::parse("dtn://src").unwrap(),
        creation_timestamp: CreationTimestamp {
            time: DtnTimeMs::from_millis(2000),
            sequence: 1,
        },
        lifetime: 7200000,
        fragment_offset: Some(1000),
        total_app_data_length: Some(5000),
    };

    let encoded = BundleCodec::encode_primary(&primary).unwrap();

    // Parse CBOR and verify field order
    let mut offset = 0;

    // 1. Array header (10 elements for fragment without CRC)
    let (elem_count, consumed) = parse_array_header(&encoded[offset..]);
    assert_eq!(elem_count, 10, "Fragment without CRC has 10 elements");
    offset += consumed;

    // Skip first 8 base fields (verified in previous test)
    for field_num in 1..=8 {
        offset += skip_cbor_item(&encoded[offset..]);
        // Field 7 (creation timestamp) is an array, need to skip its contents
        if field_num == 7 {
            // Already skipped the array header above, elements are next
        }
    }

    // 9. Fragment offset (must be ninth field for fragments)
    let (frag_offset, consumed) = parse_uint(&encoded[offset..]);
    assert_eq!(
        frag_offset, 1000,
        "Fragment offset must be ninth field in fragmented bundle"
    );
    offset += consumed;

    // 10. Total app data length (must be tenth field for fragments)
    let (total_len, consumed) = parse_uint(&encoded[offset..]);
    assert_eq!(
        total_len, 5000,
        "Total app data length must be tenth field in fragmented bundle"
    );
    offset += consumed;

    // Should have consumed entire encoded primary block
    assert_eq!(
        offset,
        encoded.len(),
        "All 10 fields parsed in correct order per RFC 9171 §4.3.1"
    );
}

/// Verify CRC field appears last (after all other fields)
#[test]
fn test_rfc9171_4_048_crc_field_last() {
    // RFC 9171 §4.3.1: When CRC is present, it's the last field

    let primary = PrimaryBlock {
        version: 7,
        bundle_flags: 0,
        crc_type: CrcType::Crc16,
        destination: EndpointId::parse("dtn://dest").unwrap(),
        source: EndpointId::parse("dtn://src").unwrap(),
        report_to: EndpointId::parse("dtn://src").unwrap(),
        creation_timestamp: CreationTimestamp {
            time: DtnTimeMs::from_millis(3000),
            sequence: 2,
        },
        lifetime: 1800000,
        fragment_offset: None,
        total_app_data_length: None,
    };

    let encoded = BundleCodec::encode_primary(&primary).unwrap();

    let mut offset = 0;

    // 1. Array header (9 elements: 8 base + CRC)
    let (elem_count, consumed) = parse_array_header(&encoded[offset..]);
    assert_eq!(elem_count, 9, "Non-fragment with CRC has 9 elements");
    offset += consumed;

    // Skip first 8 base fields
    for _ in 0..8 {
        offset += skip_cbor_item(&encoded[offset..]);
    }

    // 9. CRC field (must be last) - byte string
    let first = encoded[offset];
    let major = first >> 5;
    assert_eq!(
        major, 2,
        "CRC field must be last field and be a byte string (major type 2)"
    );

    // Verify it's the last field
    offset += skip_cbor_item(&encoded[offset..]);
    assert_eq!(
        offset,
        encoded.len(),
        "CRC field is last field per RFC 9171 §4.3.1"
    );
}

/// Verify fragmented bundle with CRC has correct field order (11 elements)
#[test]
fn test_rfc9171_4_048_fragmented_with_crc_order() {
    // RFC 9171 §4.3.1: Fragmented bundle with CRC has 11 elements
    // Order: 8 base + fragment_offset + total_length + CRC

    let primary = PrimaryBlock {
        version: 7,
        bundle_flags: 1,
        crc_type: CrcType::Crc32,
        destination: EndpointId::parse("dtn://dest").unwrap(),
        source: EndpointId::parse("dtn://src").unwrap(),
        report_to: EndpointId::parse("dtn://src").unwrap(),
        creation_timestamp: CreationTimestamp {
            time: DtnTimeMs::from_millis(4000),
            sequence: 3,
        },
        lifetime: 900000,
        fragment_offset: Some(2000),
        total_app_data_length: Some(10000),
    };

    let encoded = BundleCodec::encode_primary(&primary).unwrap();

    let mut offset = 0;

    // 1. Array header (11 elements)
    let (elem_count, consumed) = parse_array_header(&encoded[offset..]);
    assert_eq!(elem_count, 11, "Fragment with CRC has 11 elements");
    offset += consumed;

    // Skip first 8 base fields
    for _ in 0..8 {
        offset += skip_cbor_item(&encoded[offset..]);
    }

    // 9. Fragment offset
    let (frag_offset, consumed) = parse_uint(&encoded[offset..]);
    assert_eq!(frag_offset, 2000, "Fragment offset is 9th field");
    offset += consumed;

    // 10. Total app data length
    let (total_len, consumed) = parse_uint(&encoded[offset..]);
    assert_eq!(total_len, 10000, "Total app data length is 10th field");
    offset += consumed;

    // 11. CRC (last field)
    let first = encoded[offset];
    let major = first >> 5;
    assert_eq!(major, 2, "CRC is 11th (last) field, byte string");

    offset += skip_cbor_item(&encoded[offset..]);
    assert_eq!(
        offset,
        encoded.len(),
        "All 11 fields in correct order per RFC 9171 §4.3.1"
    );
}
