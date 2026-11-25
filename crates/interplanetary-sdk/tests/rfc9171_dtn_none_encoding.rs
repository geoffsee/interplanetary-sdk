//! RFC 9171 §4.2.5.1.1 dtn:none Encoding Tests
//!
//! Tests that verify the null endpoint (dtn:none) is correctly encoded as [1, 0]
//! per RFC 9171 §4.2.5.1.1

use ciborium::Value;
use interplanetary_sdk::bp::{BundleBuilder, codec::BundleCodec};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};
use std::io::Cursor;

#[test]
fn test_rfc9171_4_2_033_dtn_none_encoded_as_scheme_1_ssp_0() {
    // RFC 9171 §4.2.5.1.1: "unless the EID's SSP is 'none', in which case
    // the SSP SHALL be represented as a CBOR unsigned integer with the value zero."
    //
    // dtn:none SHALL be encoded as [1, 0] where:
    //   1 = dtn scheme code (§4.2.5.1.1)
    //   0 = SSP as CBOR unsigned integer (not text "none")

    let bundle = BundleBuilder::new()
        .source(EndpointId::null()) // dtn:none
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

    // Source EID (dtn:none) is at index 4
    let Value::Array(source_eid) = &primary[4] else {
        panic!("EID must be CBOR array");
    };

    assert_eq!(
        source_eid.len(),
        2,
        "dtn:none SHALL be 2-element array [scheme, SSP]"
    );

    // Scheme code SHALL be 1 (dtn)
    let Value::Integer(scheme) = &source_eid[0] else {
        panic!("Scheme code SHALL be CBOR unsigned integer");
    };
    assert_eq!(
        (*scheme).try_into().ok(),
        Some(1u64),
        "Scheme code SHALL be 1 for dtn:"
    );

    // SSP SHALL be unsigned integer 0 (not text "none")
    let Value::Integer(ssp) = &source_eid[1] else {
        panic!("dtn:none SSP SHALL be CBOR unsigned integer 0, not text");
    };
    assert_eq!(
        (*ssp).try_into().ok(),
        Some(0u64),
        "dtn:none SSP SHALL be unsigned integer with value 0"
    );
}

#[test]
fn test_rfc9171_4_2_033_dtn_none_decode_roundtrip() {
    // Test that [1, 0] decodes to null endpoint and round-trips correctly

    let bundle = BundleBuilder::new()
        .source(EndpointId::null())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded_bundle = BundleCodec::decode(&encoded).unwrap();

    // Source should decode back to null endpoint
    assert!(
        decoded_bundle.primary.source.is_null(),
        "Encoded [1, 0] SHALL decode to null endpoint"
    );

    // Round-trip encoding should be identical
    let re_encoded = BundleCodec::encode(&decoded_bundle).unwrap();
    assert_eq!(
        encoded, re_encoded,
        "Null endpoint encoding SHALL round-trip identically"
    );
}

#[test]
fn test_rfc9171_4_2_033_reject_old_scheme_0_encoding() {
    // The old buggy SDK encoding [0] (scheme 0, no SSP) SHALL be rejected
    // per RFC 9171 which requires dtn:none to be [1, 0]

    // Manually construct a bundle with old [0] encoding for null endpoint
    let mut malformed_bundle = vec![
        0x9F, // Start indefinite array (bundle)
        0x88, // Primary block: 8-element array
        0x07, // Version 7
        0x00, // Bundle flags 0
        0x00, // CRC type 0
    ];

    // Destination: dtn://dest as [1, "//dest"]
    malformed_bundle.extend_from_slice(&[
        0x82, 0x01, 0x66, // Array [1, text(6)]
        b'/', b'/', b'd', b'e', b's', b't',
    ]);

    // Source: INVALID [0] encoding (old bug)
    malformed_bundle.extend_from_slice(&[
        0x81, 0x00, // Array [0] - WRONG per RFC 9171
    ]);

    // Report-to: same as dest
    malformed_bundle.extend_from_slice(&[0x82, 0x01, 0x66, b'/', b'/', b'd', b'e', b's', b't']);

    // Creation timestamp: [0, 0]
    malformed_bundle.extend_from_slice(&[0x82, 0x00, 0x00]);

    // Lifetime: 3600000
    malformed_bundle.extend_from_slice(&[0x1A, 0x00, 0x36, 0xEE, 0x80]);

    // Payload block: [1, 1, 0, 0, payload_bstr]
    malformed_bundle.extend_from_slice(&[
        0x85, 0x01, 0x01, 0x00, 0x00, 0x44, // block array + 4-byte payload
        0x74, 0x65, 0x73, 0x74, // "test"
    ]);

    malformed_bundle.push(0xFF); // End bundle array

    // Decoding SHALL fail because [0] is not a valid EID encoding
    let result = BundleCodec::decode(&malformed_bundle);
    assert!(
        result.is_err(),
        "Old [0] encoding for null endpoint SHALL be rejected (RFC requires [1, 0])"
    );
}

#[test]
fn test_rfc9171_4_2_033_dtn_none_text_strict_reject() {
    // RFC 9171 §4.2.5.1.1: dtn:none SHALL be encoded as [1, 0]
    // Strictly reject [1, "none"] as non-conformant

    // Manually construct bundle with [1, "none"] encoding (non-conformant)
    let mut bundle_bytes = vec![
        0x9F, // Start indefinite array (bundle)
        0x88, // Primary block: 8-element array
        0x07, // Version 7
        0x00, // Bundle flags 0
        0x00, // CRC type 0
    ];

    // Destination
    bundle_bytes.extend_from_slice(&[0x82, 0x01, 0x66, 0x2F, 0x2F, 0x64, 0x65, 0x73, 0x74]);

    // Source: [1, "none"] (RFC-incorrect encoding)
    bundle_bytes.extend_from_slice(&[
        0x82, 0x01, 0x64, // Array [1, text(4)]
        b'n', b'o', b'n', b'e',
    ]);

    // Report-to
    bundle_bytes.extend_from_slice(&[0x82, 0x01, 0x66, 0x2F, 0x2F, 0x64, 0x65, 0x73, 0x74]);

    // Creation timestamp, lifetime, payload block (same as above)
    bundle_bytes.extend_from_slice(&[
        0x82, 0x00, 0x00, 0x1A, 0x00, 0x36, 0xEE, 0x80, 0x85, 0x01, 0x01, 0x00, 0x00, 0x44, 0x74,
        0x65, 0x73, 0x74, 0xFF,
    ]);

    // Decoder SHALL reject [1, "none"] per RFC 9171 §4.2.5.1.1
    // "the SSP SHALL be represented as a CBOR unsigned integer with the value zero"
    let result = BundleCodec::decode(&bundle_bytes);
    assert!(
        result.is_err(),
        "Decoder MUST reject [1, \"none\"] encoding - RFC requires [1, 0]"
    );
}
