//! RFC 9171 §4.3.1 Primary Block CBOR Structure Tests

mod common;

use ciborium::Value;
use common::simple_bundle;
use interplanetary_sdk::bp::BundleCodec;
use std::io::Cursor;

#[test]
fn test_rfc9171_4_044_primary_block_is_cbor_array() {
    // RFC 9171 §4.3.1: "Each primary block SHALL be represented as a CBOR array"

    let bundle = simple_bundle(
        interplanetary_sdk::types::EndpointId::ipn(0, 1, 0).unwrap(),
        interplanetary_sdk::types::EndpointId::ipn(0, 2, 0).unwrap(),
    );

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    // Primary block SHALL be represented as a CBOR array
    assert!(
        matches!(blocks[0], Value::Array(_)),
        "Primary block SHALL be represented as a CBOR array"
    );
}

#[test]
fn test_rfc9171_4_045_primary_block_array_length() {
    // RFC 9171 §4.3.1: "the number of elements in the array SHALL be 8 (if the
    // bundle is not a fragment and the block has no CRC), or 9 (if the bundle
    // is not a fragment and the block has a CRC), or 10 (if the bundle is a
    // fragment and the block has no CRC), or 11 (if the bundle is a fragment
    // and the block has a CRC)"

    use interplanetary_sdk::bp::{BundleBuilder, CrcType};
    use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

    // Case 1: Non-fragment, no CRC -> 8 elements
    let bundle1 = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let encoded1 = BundleCodec::encode(&bundle1).unwrap();
    let decoded1: Value = ciborium::from_reader(Cursor::new(&encoded1)).unwrap();
    let Value::Array(blocks1) = decoded1 else {
        panic!("Must be array");
    };
    let Value::Array(primary1) = &blocks1[0] else {
        panic!("Must be array");
    };
    assert_eq!(
        primary1.len(),
        8,
        "Non-fragment without CRC SHALL be 8 elements"
    );

    // Case 2: Non-fragment, with CRC -> 9 elements
    let mut bundle2 = bundle1.clone();
    bundle2.primary.crc_type = CrcType::Crc16;
    let encoded2 = BundleCodec::encode(&bundle2).unwrap();
    let decoded2: Value = ciborium::from_reader(Cursor::new(&encoded2)).unwrap();
    let Value::Array(blocks2) = decoded2 else {
        panic!("Must be array");
    };
    let Value::Array(primary2) = &blocks2[0] else {
        panic!("Must be array");
    };
    assert_eq!(
        primary2.len(),
        9,
        "Non-fragment with CRC SHALL be 9 elements"
    );

    // Case 3: Fragment, no CRC -> 10 elements
    let mut bundle3 = bundle1.clone();
    bundle3.primary.bundle_flags |= 0x000001; // Set is-fragment flag
    bundle3.primary.fragment_offset = Some(0);
    bundle3.primary.total_app_data_length = Some(1000);
    let encoded3 = BundleCodec::encode(&bundle3).unwrap();
    let decoded3: Value = ciborium::from_reader(Cursor::new(&encoded3)).unwrap();
    let Value::Array(blocks3) = decoded3 else {
        panic!("Must be array");
    };
    let Value::Array(primary3) = &blocks3[0] else {
        panic!("Must be array");
    };
    assert_eq!(
        primary3.len(),
        10,
        "Fragment without CRC SHALL be 10 elements"
    );

    // Case 4: Fragment, with CRC -> 11 elements
    let mut bundle4 = bundle3.clone();
    bundle4.primary.crc_type = CrcType::Crc16;
    let encoded4 = BundleCodec::encode(&bundle4).unwrap();
    let decoded4: Value = ciborium::from_reader(Cursor::new(&encoded4)).unwrap();
    let Value::Array(blocks4) = decoded4 else {
        panic!("Must be array");
    };
    let Value::Array(primary4) = &blocks4[0] else {
        panic!("Must be array");
    };
    assert_eq!(primary4.len(), 11, "Fragment with CRC SHALL be 11 elements");
}

// NOTE: RFC9171-4-048 and 4-049 ("fields SHALL be as follows, in the order
// they MUST appear") are NOT mapped here. These tests check individual field
// types but don't comprehensively verify the full field order for all 8-11
// positions as required by the RFC text.

#[test]
fn test_rfc9171_4_3_primary_block_crc_type_third() {
    // RFC 9171 §4.3.1: CRC type is third field

    let bundle = simple_bundle(
        interplanetary_sdk::types::EndpointId::ipn(0, 1, 0).unwrap(),
        interplanetary_sdk::types::EndpointId::ipn(0, 2, 0).unwrap(),
    );

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // Third field MUST be CRC type
    let Value::Integer(crc_type) = &primary[2] else {
        panic!("CRC type MUST be unsigned integer");
    };

    let crc_val: u64 = (*crc_type).try_into().expect("CRC type must fit in u64");

    // Must be valid CRC type (0, 1, or 2 per RFC 9171 §4.2.1)
    assert!(
        crc_val <= 2,
        "CRC type must be 0 (none), 1 (CRC-16), or 2 (CRC-32C)"
    );
}

#[test]
fn test_rfc9171_4_3_primary_block_eids_arrays() {
    // RFC 9171 §4.3.1: Destination, source, report-to EIDs are arrays

    let bundle = simple_bundle(
        interplanetary_sdk::types::EndpointId::ipn(0, 1, 0).unwrap(),
        interplanetary_sdk::types::EndpointId::ipn(0, 2, 0).unwrap(),
    );

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // Fields 3, 4, 5 are destination, source, report-to EIDs (all arrays)
    for (idx, name) in [(3, "destination"), (4, "source"), (5, "report-to")] {
        assert!(
            matches!(primary[idx], Value::Array(_)),
            "{} EID MUST be CBOR array",
            name
        );

        let Value::Array(eid) = &primary[idx] else {
            unreachable!();
        };

        // EID array must be 2 or 3 elements [scheme, ssp] or [scheme, allocator, node]
        assert!(
            eid.len() >= 2,
            "{} EID array must have at least 2 elements",
            name
        );
    }
}
