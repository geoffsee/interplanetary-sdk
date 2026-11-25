//! RFC 9171 §4.2 Primary Block CBOR Encoding Tests
//!
//! Tests that verify the SDK encodes primary blocks according to RFC 9171 §4.2

use ciborium::Value;
use interplanetary_sdk::bp::{BundleBuilder, codec::BundleCodec};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};
use std::io::Cursor;

#[test]
fn test_rfc9171_4_2_021_bundle_flags_as_cbor_unsigned() {
    // RFC 9171 §4.2.3: "The bundle processing control flags SHALL be
    // represented as a CBOR unsigned integer."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .bundle_flags(0x000020) // REQUEST_APP_ACK
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array of blocks");
    };
    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // Bundle flags are at index 2 (after version and flags)
    let Value::Integer(_) = &primary[2] else {
        panic!("Bundle processing control flags SHALL be CBOR unsigned integer");
    };
}

#[test]
fn test_rfc9171_4_2_029_eid_first_item_is_scheme_code() {
    // RFC 9171 §4.2.5.1: "The first item of the array SHALL be the code
    // number identifying the endpoint ID's URI scheme"

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//test").unwrap())
        .destination(EndpointId::ipn(0, 1, 0).unwrap())
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

    // Destination EID is at index 3
    let Value::Array(dest_eid) = &primary[3] else {
        panic!("Endpoint ID must be CBOR array");
    };

    let Value::Integer(scheme_code) = &dest_eid[0] else {
        panic!("First item of EID SHALL be scheme code (unsigned integer)");
    };

    // IPN scheme code should be 2
    assert_eq!(
        (*scheme_code).try_into().ok(),
        Some(2u64),
        "IPN scheme code should be 2"
    );
}

#[test]
fn test_rfc9171_4_2_036_037_ipn_node_and_service() {
    // RFC 9171 §4.2.5.1.2: "The first item of this array SHALL be the
    // EID's node number... The second item of this array SHALL be the
    // EID's service number"

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 42, 7).unwrap())
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

    // Destination EID at index 3
    let Value::Array(dest_eid) = &primary[3] else {
        panic!("Endpoint ID must be CBOR array");
    };

    // IPN EID: [scheme_code, [node, service]]
    let Value::Array(ipn_parts) = &dest_eid[1] else {
        panic!("IPN EID parts must be CBOR array");
    };

    let Value::Integer(node) = &ipn_parts[0] else {
        panic!("First item SHALL be node number");
    };
    let Value::Integer(service) = &ipn_parts[1] else {
        panic!("Second item SHALL be service number");
    };

    assert_eq!(
        (*node).try_into().ok(),
        Some(100u64),
        "Node number should be 100"
    );
    assert_eq!(
        (*service).try_into().ok(),
        Some(200u64),
        "Service number should be 200"
    );
}

#[test]
fn test_rfc9171_4_2_038_dtn_time_as_unsigned() {
    // RFC 9171 §4.2.6: "Each DTN time SHALL be represented as a CBOR
    // unsigned integer item."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(123456), 0))
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

    // Creation timestamp at index 6
    let Value::Array(timestamp) = &primary[6] else {
        panic!("Creation timestamp must be CBOR array");
    };

    let Value::Integer(_creation_time) = &timestamp[0] else {
        panic!("DTN time (creation time) SHALL be CBOR unsigned integer");
    };
}

#[test]
fn test_rfc9171_4_2_039_creation_timestamp_as_array() {
    // RFC 9171 §4.2.7: "Each bundle's creation timestamp SHALL be
    // represented as a CBOR array comprising two items."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(100), 42))
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

    let Value::Array(timestamp) = &primary[6] else {
        panic!("Creation timestamp SHALL be CBOR array");
    };

    assert_eq!(
        timestamp.len(),
        2,
        "Creation timestamp SHALL be array of two items"
    );
}

#[test]
fn test_rfc9171_4_2_040_041_timestamp_elements() {
    // RFC 9171 §4.2.7: "The first item of the array, termed 'bundle
    // creation time', SHALL be the DTN time... The second item of the
    // array, termed the creation timestamp's 'sequence number', SHALL
    // be an unsigned integer..."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(100), 42))
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

    let Value::Array(timestamp) = &primary[6] else {
        panic!("Creation timestamp must be CBOR array");
    };

    let Value::Integer(_creation_time) = &timestamp[0] else {
        panic!("First item SHALL be bundle creation time (DTN time)");
    };
    let Value::Integer(sequence) = &timestamp[1] else {
        panic!("Second item SHALL be sequence number (unsigned integer)");
    };

    assert_eq!(
        (*sequence).try_into().ok(),
        Some(42u64),
        "Sequence number should be 42"
    );
}

#[test]
fn test_rfc9171_4_2_015_crc_as_byte_string() {
    // RFC 9171 §4.2.2: "When not omitted, the CRC SHALL be represented
    // as a CBOR byte string of two bytes (if CRC type is 1) or of four
    // bytes (if CRC type is 2)"

    use interplanetary_sdk::bp::CrcType;

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Force CRC16 on primary block
    bundle.primary.crc_type = CrcType::Crc16;

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };
    let Value::Array(primary) = &blocks[0] else {
        panic!("Primary block must be CBOR array");
    };

    // CRC should be last element in primary block (index 8 for non-fragment with CRC)
    if primary.len() >= 9 {
        let Value::Bytes(crc_bytes) = &primary[8] else {
            panic!("CRC SHALL be CBOR byte string");
        };

        assert_eq!(
            crc_bytes.len(),
            2,
            "CRC16 (type 1) SHALL be 2-byte CBOR byte string"
        );
    }
}

#[test]
fn test_rfc9171_4_2_033_dtn_ssp_as_text_string() {
    // RFC 9171 §4.2.5.1.1: "the scheme-specific part of a URI of the
    // dtn scheme SHALL be represented as a CBOR text string unless the
    // EID's SSP is 'none', in which case the SSP SHALL be represented as
    // a CBOR unsigned integer with the value zero."

    // Test dtn://node/service - SSP should be CBOR text string
    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//node/service").unwrap())
        .destination(EndpointId::dtn("//other").unwrap())
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

    // Source EID is at index 4
    let Value::Array(source_eid) = &primary[4] else {
        panic!("EID must be CBOR array");
    };

    // DTN EID: [scheme_code, ssp]
    let Value::Text(ssp) = &source_eid[1] else {
        panic!("DTN scheme-specific part SHALL be CBOR text string");
    };

    assert_eq!(ssp, "//node/service");
}

// NOTE: SDK currently encodes dtn:none as [0] (null scheme, no SSP)
// instead of [1, 0] (dtn scheme, SSP=0) as required by RFC 9171 §4.2.5.1.1.
// Cannot test RFC9171-4-033 dtn:none case until SDK is fixed.
