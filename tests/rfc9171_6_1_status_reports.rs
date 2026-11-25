use interplanetary_sdk::bpa::admin::{self, ReasonCode, StatusInfo, StatusReport};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// RFC9171-6-001/002/003: Admin record SHALL be CBOR array [type_code, content]
#[test]
fn test_rfc9171_6_001_002_003_admin_record_structure() {
    // RFC 9171 §6.1: "Each BP administrative record SHALL be represented
    // as a CBOR array comprising two items."
    // First item: record type code (unsigned integer)
    // Second item: record content (CBOR encoding)

    let report = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report, false);

    // Parse CBOR to verify structure
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();

    // Verify it's an array with 2 elements
    let admin_array = parsed.as_array().expect("Admin record must be array");
    assert_eq!(
        admin_array.len(),
        2,
        "Admin record array MUST have 2 elements per RFC 9171 §6.1"
    );

    // First element MUST be type code (unsigned integer)
    let type_code = admin_array[0]
        .as_integer()
        .expect("Admin record type code MUST be integer");
    assert_eq!(
        type_code,
        ciborium::value::Integer::from(1),
        "Status report type code is 1"
    );

    // Second element MUST be the record content (array for status report)
    assert!(
        admin_array[1].is_array(),
        "Admin record content MUST be CBOR array per RFC 9171 §6.1"
    );
}

/// RFC9171-6-004/005: Status report SHALL be CBOR array with 4 or 6 elements
#[test]
fn test_rfc9171_6_004_005_status_report_array_length_v2() {
    // RFC 9171 §6.1.1: "The number of elements in the array SHALL be either
    // 6 (if the subject bundle is a fragment) or 4 (otherwise)."

    // Test non-fragment: should have 4 elements
    let non_fragment = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&non_fragment, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();

    assert_eq!(
        status_array.len(),
        4,
        "Non-fragment status report MUST have 4 elements per RFC 9171 §6.1.1"
    );

    // Test fragment: should have 6 elements
    let fragment = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: Some(100),
        fragment_length: Some(200),
    };

    let encoded_frag = admin::encode_status_report(&fragment, false);
    let parsed_frag: ciborium::Value = ciborium::from_reader(&encoded_frag[..]).unwrap();
    let admin_array_frag = parsed_frag.as_array().unwrap();
    let status_array_frag = admin_array_frag[1].as_array().unwrap();

    assert_eq!(
        status_array_frag.len(),
        6,
        "Fragment status report MUST have 6 elements per RFC 9171 §6.1.1"
    );
}

/// RFC9171-6-006: First element SHALL be bundle status information (CBOR array of at least 4 elements)
#[test]
fn test_rfc9171_6_006_first_element_is_status_info_array_v2() {
    // RFC 9171 §6.1.1: "The first element of the bundle status report SHALL be
    // bundle status information represented as a CBOR array of at least four elements."

    let report = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();

    // First element of status report is status information
    let status_info = status_array[0]
        .as_array()
        .expect("Status information MUST be CBOR array per RFC 9171 §6.1.1");

    assert!(
        status_info.len() >= 4,
        "Status information MUST have at least 4 elements per RFC 9171 §6.1.1"
    );

    // Verify it contains the 4 status assertions
    assert_eq!(
        status_info.len(),
        4,
        "Status information has exactly 4 elements (received/forwarded/delivered/deleted)"
    );
}

/// RFC9171-6-007: Each status information element SHALL be a bundle status item (array)
#[test]
fn test_rfc9171_6_007_each_status_item_is_array_v2() {
    // RFC 9171 §6.1.1: "Each element of the bundle status information SHALL be
    // a bundle status item encoded as a CBOR array."

    let report = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();
    let status_info = status_array[0].as_array().unwrap();

    // Each of the 4 status items must be an array
    for (i, item) in status_info.iter().enumerate() {
        assert!(
            item.is_array(),
            "Status item {} MUST be CBOR array per RFC 9171 §6.1.1",
            i
        );
    }
}

/// RFC9171-6-008: Status item SHALL have 1 or 2 elements (bool, optional time)
#[test]
fn test_rfc9171_6_008_status_item_length_v2() {
    // RFC 9171 §6.1.1: "The number of elements in each bundle status item SHALL be
    // either 2 (if the value of the first element of the bundle status item is 1 AND
    // the 'Report status time' flag was set to 1) or 1 (otherwise)."

    // Test without time
    let report_no_time = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report_no_time, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();
    let status_info = status_array[0].as_array().unwrap();

    // Each status item should have 1 element (just the bool)
    for item in status_info.iter() {
        let item_array = item.as_array().unwrap();
        assert_eq!(
            item_array.len(),
            1,
            "Status item without time MUST have 1 element per RFC 9171 §6.1.1"
        );
    }

    // Test with time (status time requested)
    use interplanetary_sdk::types::SimInstant;
    let report_with_time = StatusReport {
        received: StatusInfo::with_time(true, SimInstant::from_nanos(2_000_000)),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded_time = admin::encode_status_report(&report_with_time, true);
    let parsed_time: ciborium::Value = ciborium::from_reader(&encoded_time[..]).unwrap();
    let admin_array_time = parsed_time.as_array().unwrap();
    let status_array_time = admin_array_time[1].as_array().unwrap();
    let status_info_time = status_array_time[0].as_array().unwrap();

    // First item (received=true with time) should have 2 elements
    let received_item = status_info_time[0].as_array().unwrap();
    assert_eq!(
        received_item.len(),
        2,
        "Status item with time and asserted=true MUST have 2 elements per RFC 9171 §6.1.1"
    );
}

/// RFC9171-6-009: First element of status item SHALL be Boolean status indicator
#[test]
fn test_rfc9171_6_009_status_indicator_is_boolean() {
    // RFC 9171 §6.1.1: "The first element of each bundle status item SHALL be
    // a status indicator, a Boolean value indicating whether or not the
    // corresponding bundle status is asserted, encoded as a CBOR Boolean value."

    let report = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();
    let status_info = status_array[0].as_array().unwrap();

    // Check each status item's first element is Boolean
    for (i, item) in status_info.iter().enumerate() {
        let item_array = item.as_array().unwrap();
        assert!(
            item_array[0].is_bool(),
            "Status item {} first element MUST be Boolean per RFC 9171 §6.1.1",
            i
        );
    }

    // Verify values match
    assert!(
        status_info[0].as_array().unwrap()[0].as_bool().unwrap(),
        "Received status indicator"
    );
    assert!(
        !status_info[1].as_array().unwrap()[0].as_bool().unwrap(),
        "Forwarded status indicator"
    );
}

/// RFC9171-6-011: Second element of status report SHALL be reason code (unsigned integer)
#[test]
fn test_rfc9171_6_011_reason_code_is_unsigned_integer() {
    // RFC 9171 §6.1.1: "The second element of the bundle status report SHALL be
    // the bundle status report reason code explaining the value of the status
    // indicator, represented as a CBOR unsigned integer."

    let report = StatusReport {
        received: StatusInfo::new(false),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(true),
        reason_code: ReasonCode::LifetimeExpired,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();

    // Second element is reason code
    let reason_code = status_array[1]
        .as_integer()
        .expect("Reason code MUST be unsigned integer per RFC 9171 §6.1.1");

    assert_eq!(
        reason_code,
        ciborium::value::Integer::from(1),
        "LifetimeExpired reason code is 1"
    );
}

/// RFC9171-6-012: Reason codes from Table 1 are valid
#[test]
fn test_rfc9171_6_012_reason_code_registry_values() {
    // RFC 9171 §6.1.1 Table 1 defines reason codes 0-11
    // Values from RFC text only, never invented

    // Test all defined reason codes encode correctly
    let codes = vec![
        (ReasonCode::NoAdditionalInformation, 0),
        (ReasonCode::LifetimeExpired, 1),
        (ReasonCode::ForwardedOverUnidirectionalLink, 2),
        (ReasonCode::TransmissionCancelled, 3),
        (ReasonCode::DepletedStorage, 4),
        (ReasonCode::DestinationEndpointUnavailable, 5),
        (ReasonCode::NoKnownRoute, 6),
        (ReasonCode::NoTimelyContact, 7),
        (ReasonCode::BlockUnintelligible, 8),
        (ReasonCode::HopLimitExceeded, 9),
        (ReasonCode::TrafficPared, 10),
        (ReasonCode::BlockUnsupported, 11),
    ];

    for (code, expected_value) in codes {
        let report = StatusReport {
            received: StatusInfo::new(false),
            forwarded: StatusInfo::new(false),
            delivered: StatusInfo::new(false),
            deleted: StatusInfo::new(true),
            reason_code: code,
            source_eid: EndpointId::parse("ipn:1.0").unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
            fragment_offset: None,
            fragment_length: None,
        };

        let encoded = admin::encode_status_report(&report, false);
        let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
        let admin_array = parsed.as_array().unwrap();
        let status_array = admin_array[1].as_array().unwrap();
        let reason = status_array[1].as_integer().unwrap();

        assert_eq!(
            reason,
            ciborium::value::Integer::from(expected_value),
            "Reason code {:?} MUST encode as {} per RFC 9171 §6.1.1 Table 1",
            code,
            expected_value
        );
    }
}

/// RFC9171-6-013: Third element SHALL be source node ID
#[test]
fn test_rfc9171_6_013_source_node_id() {
    // RFC 9171 §6.1.1: "The third element of the bundle status report SHALL be
    // the source node ID identifying the source of the bundle whose status is
    // being reported, represented as described in Section 4.2.5.1.1."

    let source = EndpointId::parse("ipn:42.0").unwrap();
    let report = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: source.clone(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();

    // Third element is source EID (encoded as [scheme, ssp])
    let source_eid = status_array[2]
        .as_array()
        .expect("Source EID MUST be array per RFC 9171 §4.2.5");

    assert_eq!(
        source_eid.len(),
        2,
        "EID encoded as [scheme, ssp] per RFC 9171 §4.2.5"
    );
}

/// RFC9171-6-014: Fourth element SHALL be creation timestamp
#[test]
fn test_rfc9171_6_014_creation_timestamp() {
    // RFC 9171 §6.1.1: "The fourth element of the bundle status report SHALL be
    // the creation timestamp of the bundle whose status is being reported,
    // represented as described in Section 4.2.7."

    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(123456), 789);
    let report = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: timestamp,
        fragment_offset: None,
        fragment_length: None,
    };

    let encoded = admin::encode_status_report(&report, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();

    // Fourth element is creation timestamp [time, sequence]
    let ts_array = status_array[3]
        .as_array()
        .expect("Creation timestamp MUST be array per RFC 9171 §4.2.7");

    assert_eq!(
        ts_array.len(),
        2,
        "Creation timestamp has 2 elements [time, sequence]"
    );

    let time = ts_array[0].as_integer().unwrap();
    let seq = ts_array[1].as_integer().unwrap();

    assert_eq!(
        time,
        ciborium::value::Integer::from(123456u64),
        "Creation time"
    );
    assert_eq!(
        seq,
        ciborium::value::Integer::from(789u64),
        "Sequence number"
    );
}

/// RFC9171-6-015/016: Fragment offset and length SHALL be present for fragments
#[test]
fn test_rfc9171_6_015_016_fragment_fields() {
    // RFC 9171 §6.1.1: "The fifth element of the bundle status report SHALL be
    // present if and only if the bundle whose status is being reported contained
    // a fragment offset. If present, it SHALL be the subject bundle's fragment
    // offset represented as a CBOR unsigned integer item."
    //
    // "The sixth element of the bundle status report SHALL be present if and only
    // if the bundle whose status is being reported contained a fragment offset.
    // If present, it SHALL be the length of the subject bundle's payload
    // represented as a CBOR unsigned integer item."

    let fragment_report = StatusReport {
        received: StatusInfo::new(true),
        forwarded: StatusInfo::new(false),
        delivered: StatusInfo::new(false),
        deleted: StatusInfo::new(false),
        reason_code: ReasonCode::NoAdditionalInformation,
        source_eid: EndpointId::parse("ipn:1.0").unwrap(),
        creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
        fragment_offset: Some(500),
        fragment_length: Some(300),
    };

    let encoded = admin::encode_status_report(&fragment_report, false);
    let parsed: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let admin_array = parsed.as_array().unwrap();
    let status_array = admin_array[1].as_array().unwrap();

    // Should have 6 elements for fragment
    assert_eq!(
        status_array.len(),
        6,
        "Fragment status report has 6 elements"
    );

    // Fifth element is fragment offset
    let offset = status_array[4]
        .as_integer()
        .expect("Fragment offset MUST be unsigned integer per RFC 9171 §6.1.1");
    assert_eq!(
        offset,
        ciborium::value::Integer::from(500u64),
        "Fragment offset"
    );

    // Sixth element is fragment length
    let length = status_array[5]
        .as_integer()
        .expect("Fragment length MUST be unsigned integer per RFC 9171 §6.1.1");
    assert_eq!(
        length,
        ciborium::value::Integer::from(300u64),
        "Fragment length"
    );
}

/// Decoder MUST reject admin record that is not an array
#[test]
fn test_decoder_rejects_non_array_admin_record() {
    // RFC 9171 §6.1: Admin record SHALL be CBOR array
    // Test that decoder rejects non-array input

    // Hand-craft invalid admin record: integer instead of array
    let invalid = ciborium::Value::Integer(42i64.into());
    let mut encoded = Vec::new();
    ciborium::into_writer(&invalid, &mut encoded).unwrap();

    let result = admin::decode_status_report(&encoded);
    assert!(
        result.is_err(),
        "Decoder MUST reject non-array admin record per RFC 9171 §6.1"
    );
}

/// Decoder MUST reject admin record array with wrong element count
#[test]
fn test_decoder_rejects_wrong_admin_record_length() {
    // RFC 9171 §6.1: Admin record SHALL have exactly 2 elements
    // Test that decoder rejects arrays with != 2 elements

    // Test array with 1 element
    let invalid_1 = ciborium::Value::Array(vec![ciborium::Value::Integer(1i64.into())]);
    let mut encoded_1 = Vec::new();
    ciborium::into_writer(&invalid_1, &mut encoded_1).unwrap();

    let result_1 = admin::decode_status_report(&encoded_1);
    assert!(
        result_1.is_err(),
        "Decoder MUST reject admin record with 1 element per RFC 9171 §6.1"
    );

    // Test array with 3 elements
    let invalid_3 = ciborium::Value::Array(vec![
        ciborium::Value::Integer(1i64.into()),
        ciborium::Value::Array(vec![]),
        ciborium::Value::Integer(999i64.into()),
    ]);
    let mut encoded_3 = Vec::new();
    ciborium::into_writer(&invalid_3, &mut encoded_3).unwrap();

    let result_3 = admin::decode_status_report(&encoded_3);
    assert!(
        result_3.is_err(),
        "Decoder MUST reject admin record with 3 elements per RFC 9171 §6.1"
    );
}

/// Decoder MUST reject status report array with wrong element count
#[test]
fn test_decoder_rejects_wrong_status_report_length() {
    // RFC 9171 §6.1.1: Status report SHALL have 4 or 6 elements
    // Test that decoder rejects arrays with other lengths

    // Hand-craft admin record with status report having 3 elements
    let invalid_status = ciborium::Value::Array(vec![
        ciborium::Value::Integer(1i64.into()), // Type code: status report
        ciborium::Value::Array(vec![
            // Status report with only 3 elements (invalid!)
            ciborium::Value::Array(vec![
                // Status info array
                ciborium::Value::Array(vec![ciborium::Value::Bool(true)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
            ]),
            ciborium::Value::Integer(0i64.into()), // Reason code
            ciborium::Value::Array(vec![
                // Source EID
                ciborium::Value::Integer(2i64.into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1i64.into()),
                    ciborium::Value::Integer(0i64.into()),
                ]),
            ]),
            // Missing creation timestamp (4th element)!
        ]),
    ]);

    let mut encoded = Vec::new();
    ciborium::into_writer(&invalid_status, &mut encoded).unwrap();

    let result = admin::decode_status_report(&encoded);
    assert!(
        result.is_err(),
        "Decoder MUST reject status report with 3 elements per RFC 9171 §6.1.1"
    );
}

/// Decoder MUST reject status report with non-array status information
#[test]
fn test_decoder_rejects_non_array_status_info() {
    // RFC 9171 §6.1.1: First element SHALL be status information (CBOR array)
    // Test that decoder rejects non-array status information

    let invalid = ciborium::Value::Array(vec![
        ciborium::Value::Integer(1i64.into()), // Type code
        ciborium::Value::Array(vec![
            ciborium::Value::Integer(999i64.into()), // Status info as integer (invalid!)
            ciborium::Value::Integer(0i64.into()),   // Reason code
            ciborium::Value::Array(vec![
                // Source EID
                ciborium::Value::Integer(2i64.into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1i64.into()),
                    ciborium::Value::Integer(0i64.into()),
                ]),
            ]),
            ciborium::Value::Array(vec![
                // Timestamp
                ciborium::Value::Integer(1000i64.into()),
                ciborium::Value::Integer(0i64.into()),
            ]),
        ]),
    ]);

    let mut encoded = Vec::new();
    ciborium::into_writer(&invalid, &mut encoded).unwrap();

    let result = admin::decode_status_report(&encoded);
    assert!(
        result.is_err(),
        "Decoder MUST reject non-array status information per RFC 9171 §6.1.1"
    );
}

/// Decoder MUST reject status item that is not an array
#[test]
fn test_decoder_rejects_non_array_status_item() {
    // RFC 9171 §6.1.1: Each status item SHALL be CBOR array
    // Test that decoder rejects non-array status items

    let invalid = ciborium::Value::Array(vec![
        ciborium::Value::Integer(1i64.into()), // Type code
        ciborium::Value::Array(vec![
            ciborium::Value::Array(vec![
                // Status info array with non-array item
                ciborium::Value::Integer(1i64.into()), // Not an array! (invalid)
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
            ]),
            ciborium::Value::Integer(0i64.into()), // Reason code
            ciborium::Value::Array(vec![
                // Source EID
                ciborium::Value::Integer(2i64.into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1i64.into()),
                    ciborium::Value::Integer(0i64.into()),
                ]),
            ]),
            ciborium::Value::Array(vec![
                // Timestamp
                ciborium::Value::Integer(1000i64.into()),
                ciborium::Value::Integer(0i64.into()),
            ]),
        ]),
    ]);

    let mut encoded = Vec::new();
    ciborium::into_writer(&invalid, &mut encoded).unwrap();

    let result = admin::decode_status_report(&encoded);
    assert!(
        result.is_err(),
        "Decoder MUST reject non-array status item per RFC 9171 §6.1.1"
    );
}

/// Decoder MUST reject status item with invalid element count
#[test]
fn test_decoder_rejects_status_item_wrong_length() {
    // RFC 9171 §6.1.1: Status item SHALL have 1 or 2 elements
    // Test that decoder rejects status items with 0 or >2 elements

    // Test with 0 elements
    let invalid_0 = ciborium::Value::Array(vec![
        ciborium::Value::Integer(1i64.into()),
        ciborium::Value::Array(vec![
            ciborium::Value::Array(vec![
                ciborium::Value::Array(vec![]), // Empty status item (invalid!)
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
            ]),
            ciborium::Value::Integer(0i64.into()),
            ciborium::Value::Array(vec![
                ciborium::Value::Integer(2i64.into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1i64.into()),
                    ciborium::Value::Integer(0i64.into()),
                ]),
            ]),
            ciborium::Value::Array(vec![
                ciborium::Value::Integer(1000i64.into()),
                ciborium::Value::Integer(0i64.into()),
            ]),
        ]),
    ]);

    let mut encoded_0 = Vec::new();
    ciborium::into_writer(&invalid_0, &mut encoded_0).unwrap();

    let result_0 = admin::decode_status_report(&encoded_0);
    assert!(
        result_0.is_err(),
        "Decoder MUST reject status item with 0 elements per RFC 9171 §6.1.1"
    );

    // Test with 3 elements
    let invalid_3 = ciborium::Value::Array(vec![
        ciborium::Value::Integer(1i64.into()),
        ciborium::Value::Array(vec![
            ciborium::Value::Array(vec![
                ciborium::Value::Array(vec![
                    // Status item with 3 elements (invalid!)
                    ciborium::Value::Bool(true),
                    ciborium::Value::Integer(1000i64.into()),
                    ciborium::Value::Integer(999i64.into()),
                ]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
            ]),
            ciborium::Value::Integer(0i64.into()),
            ciborium::Value::Array(vec![
                ciborium::Value::Integer(2i64.into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1i64.into()),
                    ciborium::Value::Integer(0i64.into()),
                ]),
            ]),
            ciborium::Value::Array(vec![
                ciborium::Value::Integer(1000i64.into()),
                ciborium::Value::Integer(0i64.into()),
            ]),
        ]),
    ]);

    let mut encoded_3 = Vec::new();
    ciborium::into_writer(&invalid_3, &mut encoded_3).unwrap();

    let result_3 = admin::decode_status_report(&encoded_3);
    assert!(
        result_3.is_err(),
        "Decoder MUST reject status item with 3 elements per RFC 9171 §6.1.1"
    );
}

/// Decoder MUST reject status item with non-Boolean first element
#[test]
fn test_decoder_rejects_non_boolean_status_indicator() {
    // RFC 9171 §6.1.1: First element of status item SHALL be Boolean
    // Test that decoder rejects non-Boolean status indicators

    let invalid = ciborium::Value::Array(vec![
        ciborium::Value::Integer(1i64.into()),
        ciborium::Value::Array(vec![
            ciborium::Value::Array(vec![
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1i64.into()), // Integer not Boolean (invalid!)
                ]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
                ciborium::Value::Array(vec![ciborium::Value::Bool(false)]),
            ]),
            ciborium::Value::Integer(0i64.into()),
            ciborium::Value::Array(vec![
                ciborium::Value::Integer(2i64.into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(1i64.into()),
                    ciborium::Value::Integer(0i64.into()),
                ]),
            ]),
            ciborium::Value::Array(vec![
                ciborium::Value::Integer(1000i64.into()),
                ciborium::Value::Integer(0i64.into()),
            ]),
        ]),
    ]);

    let mut encoded = Vec::new();
    ciborium::into_writer(&invalid, &mut encoded).unwrap();

    let result = admin::decode_status_report(&encoded);
    assert!(
        result.is_err(),
        "Decoder MUST reject non-Boolean status indicator per RFC 9171 §6.1.1"
    );
}
