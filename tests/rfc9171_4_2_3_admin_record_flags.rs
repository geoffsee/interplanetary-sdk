//! RFC 9171 §4.2.3: Admin record flag validation
//!
//! Tests that administrative records have all status report request flags set to zero.

use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::bundle_flags;
use interplanetary_sdk::types::*;

/// RFC9171-4-018: If bundle's ADU is an administrative record, all status report
/// request flag values MUST be zero.
///
/// RFC 9171 §4.2.3:
/// "If the bundle processing control flags indicate that the bundle's ADU is an
/// administrative record, then all status report request flag values MUST be zero."
#[test]
fn test_rfc9171_4_018_admin_record_has_zero_status_flags() {
    // Create a bundle with IS_ADMIN_RECORD flag but also status report flags
    // This MUST be rejected
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);

    // Admin record flag + status report request flags (INVALID)
    let invalid_flags = bundle_flags::IS_ADMIN_RECORD
        | bundle_flags::REQUEST_REPORT_RECEPTION
        | bundle_flags::REQUEST_REPORT_DELETION;

    let result = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(60000)
        .bundle_flags(invalid_flags)
        .payload(vec![1, 2, 3])
        .build();

    // Should fail validation
    assert!(
        result.is_err(),
        "Bundle with admin flag and status report flags should be rejected"
    );
}

/// Test that admin records can be created with zero status report flags
#[test]
fn test_admin_record_valid_with_zero_status_flags() {
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);

    // Admin record flag ONLY (no status report flags) - VALID
    let valid_flags = bundle_flags::IS_ADMIN_RECORD;

    let result = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(60000)
        .bundle_flags(valid_flags)
        .payload(vec![1, 2, 3])
        .build();

    assert!(
        result.is_ok(),
        "Admin record with zero status flags should succeed"
    );

    let bundle = result.unwrap();
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::IS_ADMIN_RECORD,
        bundle_flags::IS_ADMIN_RECORD
    );
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_RECEPTION,
        0
    );
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_FORWARD,
        0
    );
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_DELIVERY,
        0
    );
    assert_eq!(
        bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_DELETION,
        0
    );
}

/// Test decoder rejects CBOR bundle with invalid admin record flags
#[test]
fn test_decoder_rejects_admin_record_with_status_flags() {
    use ciborium::Value;
    use std::io::Cursor;

    // Build a valid bundle first
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);

    let bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(60000)
        .bundle_flags(bundle_flags::IS_ADMIN_RECORD) // Valid
        .payload(vec![1, 2, 3])
        .build()
        .unwrap();

    // Encode it
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Decode the CBOR to manipulate flags
    let mut cursor = Cursor::new(encoded);
    let mut cbor: Vec<Value> = ciborium::from_reader(&mut cursor).unwrap();

    // Modify the bundle_flags field (index 2 in primary block array)
    if let Value::Array(primary) = &mut cbor[0] {
        // Set invalid flags: admin + status report
        let invalid_flags = bundle_flags::IS_ADMIN_RECORD | bundle_flags::REQUEST_REPORT_RECEPTION;
        primary[2] = Value::Integer(invalid_flags.into());
    }

    // Re-encode the modified CBOR
    let mut modified = Vec::new();
    ciborium::into_writer(&cbor, &mut modified).unwrap();

    // Try to decode - should fail
    let result = BundleCodec::decode(&modified);
    assert!(
        result.is_err(),
        "Decoder should reject admin record with status report flags"
    );
}

/// Test that each individual status report flag is rejected with admin flag
#[test]
fn test_each_status_flag_rejected_with_admin() {
    let source = EndpointId::ipn(0, 1, 1).unwrap();
    let dest = EndpointId::ipn(0, 2, 1).unwrap();
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);

    let status_flags = [
        ("RECEPTION", bundle_flags::REQUEST_REPORT_RECEPTION),
        ("FORWARD", bundle_flags::REQUEST_REPORT_FORWARD),
        ("DELIVERY", bundle_flags::REQUEST_REPORT_DELIVERY),
        ("DELETION", bundle_flags::REQUEST_REPORT_DELETION),
    ];

    for (name, flag) in &status_flags {
        let invalid_flags = bundle_flags::IS_ADMIN_RECORD | flag;

        let result = BundleBuilder::new()
            .source(source.clone())
            .destination(dest.clone())
            .creation_timestamp(timestamp)
            .lifetime(60000)
            .bundle_flags(invalid_flags)
            .payload(vec![1, 2, 3])
            .build();

        assert!(
            result.is_err(),
            "Admin record with {} flag should be rejected",
            name
        );
    }
}
