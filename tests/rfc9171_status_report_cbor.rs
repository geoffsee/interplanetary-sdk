//! RFC 9171 §6.1 Status Report CBOR Structure Tests
//!
//! These tests verify the CBOR encoding structure of Bundle Status Reports
//! by encoding status reports through the SDK and then directly inspecting
//! the CBOR structure.

use ciborium::Value;
use interplanetary_sdk::bpa::admin::{ReasonCode, StatusReport, encode_status_report};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId, SimInstant};
use std::io::Cursor;

#[test]
fn test_rfc9171_6_004_005_status_report_array_length() {
    // RFC 9171 §6.1.1: "Each bundle status report SHALL be represented
    // as a CBOR array. The number of elements in the array SHALL be
    // either 6 (if the subject bundle is a fragment) or 4 (otherwise)."

    // Non-fragment: 4 elements
    let report_nonfrag = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );
    let cbor_nonfrag = encode_status_report(&report_nonfrag, false);
    let decoded_nonfrag: Value = ciborium::from_reader(Cursor::new(&cbor_nonfrag)).unwrap();

    let Value::Array(admin_rec) = decoded_nonfrag else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    assert_eq!(
        status_items.len(),
        4,
        "Non-fragment status report SHALL be 4-element array"
    );

    // Fragment: 6 elements
    let mut report_frag = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );
    report_frag.fragment_offset = Some(1024);
    report_frag.fragment_length = Some(2048);

    let cbor_frag = encode_status_report(&report_frag, false);
    let decoded_frag: Value = ciborium::from_reader(Cursor::new(&cbor_frag)).unwrap();

    let Value::Array(admin_rec_frag) = decoded_frag else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items_frag) = &admin_rec_frag[1] else {
        panic!("Status report must be CBOR array");
    };
    assert_eq!(
        status_items_frag.len(),
        6,
        "Fragment status report SHALL be 6-element array"
    );
}

#[test]
fn test_rfc9171_6_006_first_element_is_status_info_array() {
    // RFC 9171 §6.1.1: "The first element of the bundle status report
    // SHALL be bundle status information represented as a CBOR array
    // of at least four elements."

    let report = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );

    let cbor = encode_status_report(&report, false);
    let decoded: Value = ciborium::from_reader(Cursor::new(&cbor)).unwrap();

    let Value::Array(admin_rec) = decoded else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    let Value::Array(status_info) = &status_items[0] else {
        panic!("First element must be status information array");
    };
    assert!(
        status_info.len() >= 4,
        "First element SHALL be bundle status information array with at least 4 elements"
    );
}

#[test]
fn test_rfc9171_6_007_each_status_item_is_array() {
    // RFC 9171 §6.1.1: "Each element of the bundle status information
    // SHALL be a bundle status item encoded as a CBOR array."

    let report = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );

    let cbor = encode_status_report(&report, false);
    let decoded: Value = ciborium::from_reader(Cursor::new(&cbor)).unwrap();

    let Value::Array(admin_rec) = decoded else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    let Value::Array(status_info) = &status_items[0] else {
        panic!("First element must be status information array");
    };

    for (i, item) in status_info.iter().enumerate() {
        let Value::Array(_) = item else {
            panic!("Status item {} must be CBOR array", i);
        };
    }
}

#[test]
fn test_rfc9171_6_008_status_item_length() {
    // RFC 9171 §6.1.1: "The number of elements in each bundle status item
    // SHALL be either 2 (if the value of the first element of the bundle
    // status report array is true and if the 'Request status time' flag
    // was set to 1 in the bundle processing control flags field) or 1
    // (otherwise)."

    // Without status time: [bool]
    let report_no_time = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );

    let cbor_no_time = encode_status_report(&report_no_time, false);
    let decoded_no_time: Value = ciborium::from_reader(Cursor::new(&cbor_no_time)).unwrap();

    let Value::Array(admin_rec) = decoded_no_time else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    let Value::Array(status_info) = &status_items[0] else {
        panic!("First element must be status information array");
    };

    for item in status_info.iter() {
        let Value::Array(inner) = item else {
            panic!("Status item must be CBOR array");
        };
        assert_eq!(
            inner.len(),
            1,
            "Status item without time SHALL be 1-element array [bool]"
        );
    }

    // With status time: [bool, time]
    let report_with_time = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        Some(SimInstant::from_nanos(5_000_000_000)),
    );

    let cbor_with_time = encode_status_report(&report_with_time, true);
    let decoded_with_time: Value = ciborium::from_reader(Cursor::new(&cbor_with_time)).unwrap();

    let Value::Array(admin_rec_time) = decoded_with_time else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items_time) = &admin_rec_time[1] else {
        panic!("Status report must be CBOR array");
    };
    let Value::Array(status_info_time) = &status_items_time[0] else {
        panic!("First element must be status information array");
    };

    // Check the "received" status item (should have time)
    let Value::Array(received_item) = &status_info_time[0] else {
        panic!("Received status item must be CBOR array");
    };
    assert_eq!(
        received_item.len(),
        2,
        "Status item with time SHALL be 2-element array [bool, time]"
    );
}

#[test]
fn test_rfc9171_6_009_first_element_is_status_indicator() {
    // RFC 9171 §6.1.1: "The first element of each bundle status item
    // SHALL be a status indicator, a Boolean value indicating whether
    // or not the bundle has been received/forwarded/delivered/deleted."

    let report = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );

    let cbor = encode_status_report(&report, false);
    let decoded: Value = ciborium::from_reader(Cursor::new(&cbor)).unwrap();

    let Value::Array(admin_rec) = decoded else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    let Value::Array(status_info) = &status_items[0] else {
        panic!("First element must be status information array");
    };

    for (i, item) in status_info.iter().enumerate() {
        let Value::Array(inner) = item else {
            panic!("Status item {} must be CBOR array", i);
        };
        let Value::Bool(_) = &inner[0] else {
            panic!("First element of status item {} must be Boolean", i);
        };
    }
}

#[test]
fn test_rfc9171_6_010_second_element_is_time() {
    // RFC 9171 §6.1.1: "If present, the second element of each bundle
    // status item SHALL indicate the time (as reported by the local
    // system clock) at which the event occurred."

    let report = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        Some(SimInstant::from_nanos(5_000_000_000)),
    );

    let cbor = encode_status_report(&report, true);
    let decoded: Value = ciborium::from_reader(Cursor::new(&cbor)).unwrap();

    let Value::Array(admin_rec) = decoded else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    let Value::Array(status_info) = &status_items[0] else {
        panic!("First element must be status information array");
    };
    let Value::Array(received_item) = &status_info[0] else {
        panic!("Received status item must be CBOR array");
    };

    if received_item.len() == 2 {
        let Value::Integer(_) = &received_item[1] else {
            panic!("Second element of status item must be time (unsigned integer)");
        };
    }
}

#[test]
fn test_rfc9171_6_011_second_element_is_reason_code() {
    // RFC 9171 §6.1.1: "The second element of the bundle status report
    // SHALL be the bundle status report reason code explaining the value
    // of the status indicator."

    let mut report = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );
    report.reason_code = ReasonCode::HopLimitExceeded;

    let cbor = encode_status_report(&report, false);
    let decoded: Value = ciborium::from_reader(Cursor::new(&cbor)).unwrap();

    let Value::Array(admin_rec) = decoded else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    assert!(
        status_items.len() >= 2,
        "Status report must have at least 2 elements"
    );
    let Value::Integer(_) = &status_items[1] else {
        panic!("Second element must be reason code (unsigned integer)");
    };
}

#[test]
fn test_rfc9171_6_013_third_element_is_source_eid() {
    // RFC 9171 §6.1.1: "The third element of the bundle status report
    // SHALL be the endpoint ID of the source of the bundle whose status
    // is being reported."

    let source = EndpointId::dtn("//test/source").unwrap();
    let report = StatusReport::reception(
        source.clone(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );

    let cbor = encode_status_report(&report, false);
    let decoded: Value = ciborium::from_reader(Cursor::new(&cbor)).unwrap();

    let Value::Array(admin_rec) = decoded else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    assert!(
        status_items.len() >= 3,
        "Status report must have at least 3 elements"
    );
    let Value::Array(_) = &status_items[2] else {
        panic!("Third element must be source endpoint ID (CBOR array)");
    };
}

#[test]
fn test_rfc9171_6_013_fourth_element_is_creation_timestamp() {
    // RFC 9171 §6.1.1: "The fourth element of the bundle status report
    // SHALL be the creation timestamp of the bundle whose status is being
    // reported."

    let report = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(12345), 0),
        None,
    );

    let cbor = encode_status_report(&report, false);
    let decoded: Value = ciborium::from_reader(Cursor::new(&cbor)).unwrap();

    let Value::Array(admin_rec) = decoded else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    assert!(
        status_items.len() >= 4,
        "Status report must have at least 4 elements"
    );
    let Value::Array(ts) = &status_items[3] else {
        panic!("Fourth element must be creation timestamp (CBOR array)");
    };
    assert_eq!(
        ts.len(),
        2,
        "Fourth element SHALL be creation timestamp [time, seq]"
    );
}

#[test]
fn test_rfc9171_6_014_015_fifth_element_fragment_offset() {
    // RFC 9171 §6.1.1: "The fifth element of the bundle status report
    // SHALL be present if and only if the bundle whose status is being
    // reported is a fragment."

    // Non-fragment: no fifth element
    let report_nonfrag = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );

    let cbor_nonfrag = encode_status_report(&report_nonfrag, false);
    let decoded_nonfrag: Value = ciborium::from_reader(Cursor::new(&cbor_nonfrag)).unwrap();

    let Value::Array(admin_rec) = decoded_nonfrag else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    assert_eq!(
        status_items.len(),
        4,
        "Non-fragment SHALL NOT have fifth element (only 4 total)"
    );

    // Fragment: fifth element present (fragment offset)
    let mut report_frag = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );
    report_frag.fragment_offset = Some(1024);
    report_frag.fragment_length = Some(2048);

    let cbor_frag = encode_status_report(&report_frag, false);
    let decoded_frag: Value = ciborium::from_reader(Cursor::new(&cbor_frag)).unwrap();

    let Value::Array(admin_rec_frag) = decoded_frag else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items_frag) = &admin_rec_frag[1] else {
        panic!("Status report must be CBOR array");
    };
    assert_eq!(
        status_items_frag.len(),
        6,
        "Fragment status report SHALL have 6 elements"
    );
    let Value::Integer(_) = &status_items_frag[4] else {
        panic!("Fifth element must be fragment offset (unsigned integer)");
    };
}

#[test]
fn test_rfc9171_6_016_017_sixth_element_fragment_length() {
    // RFC 9171 §6.1.1: "The sixth element of the bundle status report
    // SHALL be present if and only if the bundle whose status is being
    // reported is a fragment."

    // Fragment: sixth element present (fragment length)
    let mut report_frag = StatusReport::reception(
        EndpointId::dtn("//source/node").unwrap(),
        CreationTimestamp::new(DtnTimeMs::from_millis(100), 0),
        None,
    );
    report_frag.fragment_offset = Some(1024);
    report_frag.fragment_length = Some(2048);

    let cbor_frag = encode_status_report(&report_frag, false);
    let decoded_frag: Value = ciborium::from_reader(Cursor::new(&cbor_frag)).unwrap();

    let Value::Array(admin_rec) = decoded_frag else {
        panic!("Admin record must be CBOR array");
    };
    let Value::Array(status_items) = &admin_rec[1] else {
        panic!("Status report must be CBOR array");
    };
    assert_eq!(
        status_items.len(),
        6,
        "Fragment status report SHALL have 6 elements"
    );
    let Value::Integer(_) = &status_items[5] else {
        panic!("Sixth element must be fragment length (unsigned integer)");
    };
}
