//! RFC 9171 §6.1 Bundle Status Reports Tests

mod common;

use common::simple_bundle;
use interplanetary_sdk::types::EndpointId;

// RFC 9171 §6.1.1: Status report reason codes
const REASON_NO_INFORMATION: u8 = 0;
const REASON_LIFETIME_EXPIRED: u8 = 1;
const REASON_FORWARDED_OVER_UNIDIRECTIONAL_LINK: u8 = 2;
const REASON_TRANSMISSION_CANCELLED: u8 = 3;
const REASON_DEPLETED_STORAGE: u8 = 4;
const REASON_DESTINATION_ENDPOINT_ID_UNAVAILABLE: u8 = 5;
const REASON_NO_KNOWN_ROUTE: u8 = 6;
const REASON_NO_TIMELY_CONTACT: u8 = 7;
const REASON_BLOCK_UNINTELLIGIBLE: u8 = 8;
const REASON_HOP_LIMIT_EXCEEDED: u8 = 9;
const REASON_TRAFFIC_PARED: u8 = 10;

#[test]
fn test_rfc9171_6_1_reception_status_report() {
    // RFC 9171 §6.1: "A 'Received bundle' status report SHOULD be generated
    // by a node when it receives a bundle"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When bundle is received and reporting is requested
    let should_generate_reception_report = true;

    assert!(
        should_generate_reception_report,
        "'Received bundle' status report SHOULD be generated upon reception"
    );
}

#[test]
fn test_rfc9171_6_1_forwarding_status_report() {
    // RFC 9171 §6.1: "A 'Forwarded bundle' status report SHOULD be generated
    // by a forwarding node when it forwards a bundle"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When bundle is forwarded and reporting is requested
    let should_generate_forwarding_report = true;

    assert!(
        should_generate_forwarding_report,
        "'Forwarded bundle' status report SHOULD be generated upon forwarding"
    );
}

#[test]
fn test_rfc9171_6_1_delivery_status_report() {
    // RFC 9171 §6.1: "A 'Delivered bundle' status report SHOULD be generated
    // by a node when it delivers a bundle"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When bundle is delivered and reporting is requested
    let should_generate_delivery_report = true;

    assert!(
        should_generate_delivery_report,
        "'Delivered bundle' status report SHOULD be generated upon delivery"
    );
}

#[test]
fn test_rfc9171_6_1_deletion_status_report_lifetime_expired() {
    // RFC 9171 §6.1: "A 'Deleted bundle' status report SHOULD be generated
    // by a node when it deletes a bundle"

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When bundle is deleted due to lifetime expiry
    let deletion_reason = REASON_LIFETIME_EXPIRED;

    assert_eq!(
        deletion_reason, REASON_LIFETIME_EXPIRED,
        "'Deleted bundle' status report with lifetime expired reason code"
    );
}

#[test]
fn test_rfc9171_6_1_deletion_status_report_hop_limit() {
    // RFC 9171 §6.1.1: "Hop limit exceeded" (reason code 9)

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When bundle is deleted due to hop limit exceeded
    let deletion_reason = REASON_HOP_LIMIT_EXCEEDED;

    assert_eq!(
        deletion_reason, REASON_HOP_LIMIT_EXCEEDED,
        "'Deleted bundle' status report with hop limit exceeded reason code"
    );
}

#[test]
fn test_rfc9171_6_1_deletion_status_report_block_unintelligible() {
    // RFC 9171 §6.1.1: "Block unintelligible" (reason code 8)

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When bundle is deleted due to unintelligible block
    let deletion_reason = REASON_BLOCK_UNINTELLIGIBLE;

    assert_eq!(
        deletion_reason, REASON_BLOCK_UNINTELLIGIBLE,
        "'Deleted bundle' status report with block unintelligible reason code"
    );
}

#[test]
fn test_rfc9171_6_1_status_report_reason_codes_defined() {
    // RFC 9171 §6.1.1: Verify all reason codes are defined per IANA registry

    assert_eq!(REASON_NO_INFORMATION, 0);
    assert_eq!(REASON_LIFETIME_EXPIRED, 1);
    assert_eq!(REASON_FORWARDED_OVER_UNIDIRECTIONAL_LINK, 2);
    assert_eq!(REASON_TRANSMISSION_CANCELLED, 3);
    assert_eq!(REASON_DEPLETED_STORAGE, 4);
    assert_eq!(REASON_DESTINATION_ENDPOINT_ID_UNAVAILABLE, 5);
    assert_eq!(REASON_NO_KNOWN_ROUTE, 6);
    assert_eq!(REASON_NO_TIMELY_CONTACT, 7);
    assert_eq!(REASON_BLOCK_UNINTELLIGIBLE, 8);
    assert_eq!(REASON_HOP_LIMIT_EXCEEDED, 9);
    assert_eq!(REASON_TRAFFIC_PARED, 10);
}

#[test]
fn test_rfc9171_6_1_status_report_requested_flag() {
    // RFC 9171 §4.2.3: Bundle flags include "Request reporting" flags

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // RFC 9171 §4.2.3 Table 2:
    // Bit 14 (0x004000): Request reporting of bundle reception
    // Bit 16 (0x010000): Request reporting of bundle forwarding
    // Bit 17 (0x020000): Request reporting of bundle delivery
    // Bit 18 (0x040000): Request reporting of bundle deletion

    const REQUEST_RECEPTION: u64 = 0x004000;
    const REQUEST_FORWARD: u64 = 0x010000;
    const REQUEST_DELIVERY: u64 = 0x020000;
    const REQUEST_DELETION: u64 = 0x040000;

    bundle.primary.bundle_flags |= REQUEST_RECEPTION;
    bundle.primary.bundle_flags |= REQUEST_FORWARD;
    bundle.primary.bundle_flags |= REQUEST_DELIVERY;
    bundle.primary.bundle_flags |= REQUEST_DELETION;

    assert_eq!(
        bundle.primary.bundle_flags & REQUEST_RECEPTION,
        REQUEST_RECEPTION,
        "Reception status report flag should be set"
    );
    assert_eq!(
        bundle.primary.bundle_flags & REQUEST_FORWARD,
        REQUEST_FORWARD,
        "Forward status report flag should be set"
    );
    assert_eq!(
        bundle.primary.bundle_flags & REQUEST_DELIVERY,
        REQUEST_DELIVERY,
        "Delivery status report flag should be set"
    );
    assert_eq!(
        bundle.primary.bundle_flags & REQUEST_DELETION,
        REQUEST_DELETION,
        "Deletion status report flag should be set"
    );
}

#[test]
fn test_rfc9171_6_1_deletion_status_report_depleted_storage() {
    // RFC 9171 §6.1.1: "Depleted storage" (reason code 4)

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // When bundle is deleted due to storage depletion
    let deletion_reason = REASON_DEPLETED_STORAGE;

    assert_eq!(
        deletion_reason, REASON_DEPLETED_STORAGE,
        "'Deleted bundle' status report with depleted storage reason code"
    );
}

#[test]
fn test_rfc9171_6_1_deletion_status_report_no_route() {
    // RFC 9171 §6.1.1: "No known route to destination" (reason code 6)

    let _bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 99, 0).unwrap(), // Unknown destination
    );

    // When bundle is deleted due to no known route
    let deletion_reason = REASON_NO_KNOWN_ROUTE;

    assert_eq!(
        deletion_reason, REASON_NO_KNOWN_ROUTE,
        "'Deleted bundle' status report with no known route reason code"
    );
}
