//! RFC 9171 §4.2.3 Bundle Processing Control Flags - Admin Record Constraints

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::{BundleBuilder, BundleCodec};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

#[test]
fn test_rfc9171_4_016_admin_record_must_have_zero_status_flags() {
    // RFC 9171 §4.2.3: "If the bundle processing control flags indicate that
    // the bundle's ADU is an administrative record, then all status report
    // request flag values MUST be zero."
    //
    // SDK enforcement: Decoder rejects received bundles with admin flag + non-zero status flags

    use interplanetary_sdk::bp::BundleCodec;

    // Create a manually corrupted bundle with admin flag + status flags set
    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );
    // Bit 1 (0x000002) = ADU is administrative record; bit 14 = request reception report
    bundle.primary.bundle_flags = 0x000002 | (0x1 << 14);

    let encoded = BundleCodec::encode(&bundle).unwrap();

    // SDK MUST reject this on decode
    let result = BundleCodec::decode(&encoded);

    assert!(
        result.is_err(),
        "SDK must reject admin records with non-zero status report flags"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Admin records MUST have zero status report flags"),
        "Error message must cite RFC 9171 §4.2.3 constraint"
    );
}

#[test]
fn test_rfc9171_4_017_null_source_constraints() {
    // RFC 9171 §4.2.3: "If the bundle's source node is omitted (i.e., the
    // source node ID is the ID of the null endpoint, which has no members
    // as discussed below; this option enables anonymous bundle transmission),
    // then the bundle is not uniquely identifiable and all Bundle Protocol
    // features that rely on bundle identity must therefore be disabled: the
    // 'Bundle must not be fragmented' flag value MUST be 1, and all status
    // report request flag values MUST be zero."

    let bundle = BundleBuilder::new()
        .source(EndpointId::null()) // Null endpoint
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Must not fragment flag (bit 2)
    let must_not_fragment = (bundle.primary.bundle_flags >> 2) & 0x01;
    assert_eq!(
        must_not_fragment, 1,
        "Null source MUST have 'must not fragment' flag = 1"
    );

    // Status report flags (bits 14-19) MUST be zero
    let status_flags = (bundle.primary.bundle_flags >> 14) & 0x3F;
    assert_eq!(
        status_flags, 0,
        "Null source MUST have zero status report flags"
    );

    // Round-trip encode/decode
    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    assert!(decoded.primary.source.is_null());
    assert_eq!(
        (decoded.primary.bundle_flags >> 2) & 0x01,
        1,
        "Must not fragment flag preserved"
    );
}

#[test]
fn test_rfc9171_4_018_null_source_zero_status_flags() {
    // RFC 9171 §4.2.3: Second half of null-source sentence:
    // "...and all status report request flag values MUST be zero."
    // This is part of the null endpoint constraint (with 4-017).

    let bundle = BundleBuilder::new()
        .source(EndpointId::null())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Verify all individual status report flag bits are zero
    let report_reception = (bundle.primary.bundle_flags >> 14) & 0x01;
    let report_forwarding = (bundle.primary.bundle_flags >> 16) & 0x01;
    let report_delivery = (bundle.primary.bundle_flags >> 17) & 0x01;
    let report_deletion = (bundle.primary.bundle_flags >> 18) & 0x01;

    assert_eq!(
        report_reception, 0,
        "Null source: reception report flag MUST be 0"
    );
    assert_eq!(
        report_forwarding, 0,
        "Null source: forwarding report flag MUST be 0"
    );
    assert_eq!(
        report_delivery, 0,
        "Null source: delivery report flag MUST be 0"
    );
    assert_eq!(
        report_deletion, 0,
        "Null source: deletion report flag MUST be 0"
    );
}

#[test]
fn test_rfc9171_4_019_unrecognized_flags_ignored() {
    // RFC 9171 §4.2.3: "Bundle processing control flags that are unrecognized
    // MUST be ignored, as future definitions of additional flags might not be
    // integrated simultaneously into the Bundle Protocol implementations
    // operating at all nodes."
    //
    // SDK enforcement: Decoder accepts and processes bundles with unrecognized flags

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Set high-order "unrecognized" flag (bit 63 - not defined in RFC 9171)
    bundle.primary.bundle_flags |= 0x8000000000000000;

    // SDK MUST accept: encode and decode without error
    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    // Unrecognized flags MUST be preserved through decode
    assert_eq!(
        decoded.primary.bundle_flags & 0x8000000000000000,
        0x8000000000000000,
        "Unrecognized flags MUST be preserved (not rejected)"
    );

    // Verify bundle is structurally valid and processable
    assert_eq!(decoded.primary.version, 7);
    assert_eq!(decoded.primary.source, bundle.primary.source);
    assert_eq!(decoded.primary.destination, bundle.primary.destination);
}
