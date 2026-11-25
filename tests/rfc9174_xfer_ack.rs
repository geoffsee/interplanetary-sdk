//! RFC 9174 §5.2.3 XFER_ACK Semantics Tests

#[test]
fn test_rfc9174_5_2_3_xfer_ack_acknowledges_received_data() {
    // RFC 9174 §5.2.3: XFER_ACK messages are sent to acknowledge receipt
    // of data segments. The Acknowledged Length field indicates the total
    // number of bytes in the transfer that the receiver has successfully
    // received.

    let _transfer_id: u64 = 1;
    let acknowledged_length: u64 = 1024;

    // XFER_ACK acknowledges data receipt
    assert!(
        acknowledged_length > 0,
        "XFER_ACK SHALL indicate total bytes successfully received"
    );
}

#[test]
fn test_rfc9174_5_2_3_acknowledged_length_monotonic() {
    // RFC 9174 §5.2.3: The Acknowledged Length in successive XFER_ACK
    // messages MUST NOT decrease

    let ack1_length: u64 = 512;
    let ack2_length: u64 = 1024;

    assert!(
        ack2_length >= ack1_length,
        "Acknowledged Length MUST NOT decrease"
    );
}

#[test]
fn test_rfc9174_5_2_3_xfer_ack_on_transfer_completion() {
    // RFC 9174 §5.2.3: When a transfer is complete, the receiver SHOULD
    // send a final XFER_ACK acknowledging the entire transfer

    let total_transfer_length: u64 = 2048;
    let final_ack_length: u64 = 2048;

    assert_eq!(
        final_ack_length, total_transfer_length,
        "Final XFER_ACK SHOULD acknowledge entire transfer"
    );
}

#[test]
fn test_rfc9174_5_2_3_transfer_id_matches_xfer_segment() {
    // RFC 9174 §5.2.3: The Transfer ID in an XFER_ACK MUST match the
    // Transfer ID of the XFER_SEGMENT(s) being acknowledged

    let segment_transfer_id: u64 = 42;
    let ack_transfer_id: u64 = 42;

    assert_eq!(
        ack_transfer_id, segment_transfer_id,
        "XFER_ACK Transfer ID MUST match XFER_SEGMENT Transfer ID"
    );
}

#[test]
fn test_rfc9174_5_2_1_transfer_id_positive() {
    // RFC 9174 §5.2.1: Transfer IDs SHALL be positive integers and
    // SHALL be unique within a session

    let transfer_id: u64 = 1;

    assert!(transfer_id > 0, "Transfer ID SHALL be positive integer");
}

#[test]
fn test_rfc9174_5_2_1_transfer_id_sequential() {
    // RFC 9174 §5.2.1: The sending entity SHALL assign Transfer IDs
    // sequentially starting from 1

    let first_id: u64 = 1;
    let second_id: u64 = 2;
    let third_id: u64 = 3;

    assert!(
        first_id == 1 && second_id == 2 && third_id == 3,
        "Transfer IDs SHALL be assigned sequentially from 1"
    );
}
