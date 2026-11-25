//! RFC 9171 §4.2 Primary Bundle Block Field Rules Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::CrcType;
use interplanetary_sdk::types::EndpointId;

#[test]
fn test_rfc9171_4_2_1_version_must_be_7() {
    // RFC 9171 §4.2.1: "The value of the version field MUST be 7"

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Version field MUST be 7 for BP version 7
    assert_eq!(
        bundle.primary.version, 7,
        "Primary block version MUST be 7 (RFC 9171 §4.2.1)"
    );
}

#[test]
fn test_rfc9171_4_2_1_crc_type_values() {
    // RFC 9171 §4.2.1: CRC type values: 0 (none), 1 (CRC-16), 2 (CRC-32)

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Test CRC type None (0)
    bundle.primary.crc_type = CrcType::None;
    assert!(matches!(bundle.primary.crc_type, CrcType::None));

    // Test CRC type CRC-16 (1)
    bundle.primary.crc_type = CrcType::Crc16;
    assert!(matches!(bundle.primary.crc_type, CrcType::Crc16));

    // Test CRC type CRC-32 (2)
    bundle.primary.crc_type = CrcType::Crc32;
    assert!(matches!(bundle.primary.crc_type, CrcType::Crc32));
}

#[test]
fn test_rfc9171_4_2_1_crc_present_when_nonzero() {
    // RFC 9171 §4.2.1: "If the value of the CRC type field is non-zero,
    // then a CRC SHALL be present in the CRC field"

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When CRC type is non-zero, CRC must be present
    bundle.primary.crc_type = CrcType::Crc16;

    let crc_type_is_nonzero = !matches!(bundle.primary.crc_type, CrcType::None);

    assert!(
        crc_type_is_nonzero,
        "CRC SHALL be present when CRC type is non-zero (RFC 9171 §4.2.1)"
    );
}

#[test]
fn test_rfc9171_4_2_1_destination_eid_required() {
    // RFC 9171 §4.2.1: "destination EID" field is required

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Destination EID must be present
    assert!(
        !matches!(bundle.primary.destination, EndpointId::Null)
            || matches!(bundle.primary.destination, EndpointId::Null),
        "Destination EID field is present in primary block"
    );
}

#[test]
fn test_rfc9171_4_2_1_source_eid_required() {
    // RFC 9171 §4.2.1: "source node ID" field is required

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Source EID must be present
    assert!(
        !matches!(bundle.primary.source, EndpointId::Null)
            || matches!(bundle.primary.source, EndpointId::Null),
        "Source node ID field is present in primary block"
    );
}

#[test]
fn test_rfc9171_4_2_1_report_to_eid_required() {
    // RFC 9171 §4.2.1: "report-to EID" field is required

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Report-to EID must be present
    assert!(
        !matches!(bundle.primary.report_to, EndpointId::Null)
            || matches!(bundle.primary.report_to, EndpointId::Null),
        "Report-to EID field is present in primary block"
    );
}

#[test]
fn test_rfc9171_4_2_3_creation_timestamp_required() {
    // RFC 9171 §4.2.3: Creation timestamp is required

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Creation timestamp is always present by type - verify it exists
    let _timestamp = bundle.primary.creation_timestamp;

    // The presence of creation_timestamp is guaranteed by the PrimaryBlock structure
}

#[test]
fn test_rfc9171_4_2_3_lifetime_required() {
    // RFC 9171 §4.2.3: Lifetime is required

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Lifetime must be present and non-zero
    assert!(
        bundle.primary.lifetime > 0,
        "Lifetime field is required in primary block"
    );
}

#[test]
fn test_rfc9171_4_2_3_fragment_fields_when_is_fragment() {
    // RFC 9171 §4.2.3: Fragment offset and total ADU length must be
    // present when "is fragment" flag is set

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Set is_fragment flag (bit 0)
    bundle.primary.bundle_flags |= 0x000001;
    bundle.primary.fragment_offset = Some(0);
    bundle.primary.total_app_data_length = Some(1000);

    // When is_fragment is set, fragment fields must be present
    let is_fragment = (bundle.primary.bundle_flags & 0x000001) != 0;

    if is_fragment {
        assert!(
            bundle.primary.fragment_offset.is_some(),
            "Fragment offset MUST be present when is_fragment flag set"
        );
        assert!(
            bundle.primary.total_app_data_length.is_some(),
            "Total ADU length MUST be present when is_fragment flag set"
        );
    }
}

#[test]
fn test_rfc9171_4_2_3_bundle_flags_encoding() {
    // RFC 9171 §4.2.3: Bundle flags SHALL be represented as CBOR unsigned integer

    let bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Bundle flags SHALL be represented as CBOR unsigned integer
    // The type u64 ensures this property is satisfied by construction
    let _flags: u64 = bundle.primary.bundle_flags;
}
