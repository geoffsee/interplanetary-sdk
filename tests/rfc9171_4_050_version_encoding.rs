#![cfg(feature = "bpv7")]

//! RFC 9171 §4.3.1: Version number CBOR encoding test

use ciborium::Value;
use interplanetary_sdk::bp::{BundleBuilder, BundleCodec};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};
use std::io::Cursor;

#[test]
fn test_rfc9171_4_050_version_as_cbor_unsigned() {
    // RFC 9171 §4.3.1: "This version number SHALL be represented as a CBOR
    // unsigned integer item."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };
    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // Version is at index 0 (first field)
    let Value::Integer(version) = &primary[0] else {
        panic!("Version number SHALL be CBOR unsigned integer");
    };

    assert_eq!(
        (*version).try_into().ok(),
        Some(7u64),
        "Version should be 7"
    );
}

#[test]
fn test_rfc9171_4_012_crc_type_as_cbor_unsigned() {
    // RFC 9171 §4.2.1: "CRC type SHALL be represented as a CBOR unsigned integer."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };
    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // CRC type is at index 2 (third field)
    let Value::Integer(crc_type) = &primary[2] else {
        panic!("CRC type SHALL be CBOR unsigned integer");
    };

    // Should be 0 or 1 or 2
    let crc_val: u64 = (*crc_type).try_into().unwrap();
    assert!(crc_val <= 2, "CRC type should be valid (0, 1, or 2)");
}

#[test]
fn test_rfc9171_4_028_eid_as_two_element_array() {
    // RFC 9171 §4.2.5.1: "Each BP endpoint ID (EID) SHALL be represented as a
    // CBOR array comprising two items."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::ipn(0, 100, 200).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };
    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // Check destination EID (at index 3)
    let Value::Array(dest_eid) = &primary[3] else {
        panic!("EID SHALL be CBOR array");
    };
    assert_eq!(dest_eid.len(), 2, "EID SHALL be array comprising two items");

    // Check source EID (at index 4)
    let Value::Array(src_eid) = &primary[4] else {
        panic!("EID SHALL be CBOR array");
    };
    assert_eq!(src_eid.len(), 2, "EID SHALL be array comprising two items");
}

#[test]
fn test_rfc9171_4_057_lifetime_as_cbor_unsigned() {
    // RFC 9171 §4.3.1: "Bundle lifetime SHALL be represented as a CBOR
    // unsigned integer item."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };
    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // Lifetime is at index 7 for non-fragment bundles
    let Value::Integer(lifetime) = &primary[7] else {
        panic!("Bundle lifetime SHALL be CBOR unsigned integer");
    };

    assert_eq!(
        (*lifetime).try_into().ok(),
        Some(3600000u64),
        "Lifetime should be 3600000"
    );
}

#[test]
fn test_rfc9171_4_003_bundle_as_indefinite_array_min_two_blocks() {
    // RFC 9171 §4.1: "Each bundle SHALL be a concatenated sequence of at least
    // two blocks, represented as a CBOR indefinite-length array."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Bundle SHALL be indefinite-length array (starts with 0x9F)
    assert_eq!(
        encoded[0], 0x9F,
        "Bundle SHALL be CBOR indefinite-length array"
    );

    // Bundle SHALL have at least two blocks (primary + payload)
    // Decode and count blocks
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();
    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be array");
    };

    assert!(
        blocks.len() >= 2,
        "Bundle SHALL be sequence of at least two blocks (found {})",
        blocks.len()
    );

    // Should have primary + payload minimum
    assert!(blocks.len() >= 2, "Primary + payload minimum");
}
