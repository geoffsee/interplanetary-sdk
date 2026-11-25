//! Administrative records per RFC 9171 §6

use crate::bp::Bundle;
use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId, SimInstant};
use ciborium::Value;
use std::io::Cursor;

/// Bundle processing control flags for status reports (RFC 9171 §4.2.3)
pub mod bundle_flags {
    /// Bit 0: Bundle is a fragment
    /// RFC 9171 §4.2.3: "Bit 0 (0x000001): The bundle is a fragment."
    pub const IS_FRAGMENT: u64 = 0x000001;

    /// Bit 1: ADU is an administrative record
    /// RFC 9171 §4.2.3: "Bit 1 (0x000002): ADU is an administrative record."
    pub const IS_ADMIN_RECORD: u64 = 0x000002;

    /// Bit 2: Bundle must not be fragmented
    /// RFC 9171 §4.2.3: "Bit 2 (0x000004): Bundle must not be fragmented."
    pub const MUST_NOT_FRAGMENT: u64 = 0x000004;

    /// Bit 5: Acknowledgement by application is requested
    /// RFC 9171 §4.2.3: "Bit 5 (0x000020): Acknowledgement by application is requested."
    pub const REQUEST_APP_ACK: u64 = 0x000020;

    /// Bit 6: Status time requested in reports
    /// RFC 9171 §4.2.3: "Bit 6 (0x000040): Status time requested in reports."
    pub const REQUEST_STATUS_TIME: u64 = 0x000040;

    /// Bit 14: Request reporting of bundle reception
    /// RFC 9171 §4.2.3: "Bit 14 (0x004000): Request reporting of bundle reception."
    pub const REQUEST_REPORT_RECEPTION: u64 = 0x004000;

    /// Bit 16: Request reporting of bundle forwarding
    /// RFC 9171 §4.2.3: "Bit 16 (0x010000): Request reporting of bundle forwarding."
    pub const REQUEST_REPORT_FORWARD: u64 = 0x010000;

    /// Bit 17: Request reporting of bundle delivery
    /// RFC 9171 §4.2.3: "Bit 17 (0x020000): Request reporting of bundle delivery."
    pub const REQUEST_REPORT_DELIVERY: u64 = 0x020000;

    /// Bit 18: Request reporting of bundle deletion
    /// RFC 9171 §4.2.3: "Bit 18 (0x040000): Request reporting of bundle deletion."
    pub const REQUEST_REPORT_DELETION: u64 = 0x040000;
}

/// Check if bundle requests status reports
pub fn should_generate_reports(bundle: &Bundle) -> bool {
    let flags = bundle.primary.bundle_flags;
    (flags
        & (bundle_flags::REQUEST_REPORT_RECEPTION
            | bundle_flags::REQUEST_REPORT_FORWARD
            | bundle_flags::REQUEST_REPORT_DELIVERY
            | bundle_flags::REQUEST_REPORT_DELETION))
        != 0
}

/// Check if bundle requests reception reports
pub fn requests_reception_report(bundle: &Bundle) -> bool {
    (bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_RECEPTION) != 0
}

/// Check if bundle requests forwarding reports
pub fn requests_forward_report(bundle: &Bundle) -> bool {
    (bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_FORWARD) != 0
}

/// Check if bundle requests delivery reports
pub fn requests_delivery_report(bundle: &Bundle) -> bool {
    (bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_DELIVERY) != 0
}

/// Check if bundle requests deletion reports
pub fn requests_deletion_report(bundle: &Bundle) -> bool {
    (bundle.primary.bundle_flags & bundle_flags::REQUEST_REPORT_DELETION) != 0
}

/// Check if bundle requests status time in reports
pub fn requests_status_time(bundle: &Bundle) -> bool {
    (bundle.primary.bundle_flags & bundle_flags::REQUEST_STATUS_TIME) != 0
}

/// Check if bundle is an administrative record (should not generate reports about it)
/// Per RFC 9171 §6.1: "A bundle node MUST NOT generate a status report in response
/// to the receipt, forwarding, delivery, or deletion of an administrative record."
///
/// Administrative records have Bit 1 (IS_ADMIN_RECORD flag) set in bundle_flags.
pub fn is_admin_record(bundle: &Bundle) -> bool {
    (bundle.primary.bundle_flags & bundle_flags::IS_ADMIN_RECORD) != 0
}

/// Administrative record types per RFC 9171 §6.1
#[derive(Debug, Clone)]
pub enum AdminRecord {
    /// Bundle status report (type 1)
    StatusReport(StatusReport),
}

/// Bundle status information item per RFC 9171 §6.1.1
#[derive(Debug, Clone)]
pub struct StatusInfo {
    /// Status assertion (received/forwarded/delivered/deleted)
    pub asserted: bool,
    /// Optional time (if 'request status time' flag was set)
    pub time: Option<SimInstant>,
}

impl StatusInfo {
    /// Create status info without time
    pub fn new(asserted: bool) -> Self {
        Self {
            asserted,
            time: None,
        }
    }

    /// Create status info with time
    pub fn with_time(asserted: bool, time: SimInstant) -> Self {
        Self {
            asserted,
            time: Some(time),
        }
    }
}

/// Status report per RFC 9171 §6.1.1
#[derive(Debug, Clone)]
pub struct StatusReport {
    /// Bundle received status information
    pub received: StatusInfo,
    /// Bundle forwarded status information
    pub forwarded: StatusInfo,
    /// Bundle delivered status information
    pub delivered: StatusInfo,
    /// Bundle deleted status information
    pub deleted: StatusInfo,

    /// Reason code per RFC 9171 §6.1.1 Table 1
    pub reason_code: ReasonCode,

    /// Subject bundle source endpoint
    pub source_eid: EndpointId,
    /// Subject bundle creation timestamp
    pub creation_timestamp: CreationTimestamp,

    /// Optional fragment offset if subject is a fragment
    pub fragment_offset: Option<u64>,
    /// Optional fragment length if subject is a fragment
    pub fragment_length: Option<u64>,
}

/// Status report reason codes per RFC 9171 §6.1.1 Table 1 and RFC 9172 §11.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReasonCode {
    /// No additional information (RFC 9171 §6.1.1)
    NoAdditionalInformation = 0,
    /// Lifetime expired (RFC 9171 §6.1.1)
    LifetimeExpired = 1,
    /// Forwarded over unidirectional link (RFC 9171 §6.1.1)
    ForwardedOverUnidirectionalLink = 2,
    /// Transmission cancelled (RFC 9171 §6.1.1)
    TransmissionCancelled = 3,
    /// Depleted storage (RFC 9171 §6.1.1)
    DepletedStorage = 4,
    /// Destination endpoint ID unavailable (RFC 9171 §6.1.1)
    DestinationEndpointUnavailable = 5,
    /// No known route to destination (RFC 9171 §6.1.1)
    NoKnownRoute = 6,
    /// No timely contact (RFC 9171 §6.1.1)
    NoTimelyContact = 7,
    /// Block unintelligible (RFC 9171 §6.1.1)
    BlockUnintelligible = 8,
    /// Hop limit exceeded (RFC 9171 §6.1.1)
    HopLimitExceeded = 9,
    /// Traffic pared (RFC 9171 §6.1.1)
    TrafficPared = 10,
    /// Block unsupported (RFC 9171 §6.1.1)
    BlockUnsupported = 11,
    /// Missing security operation (RFC 9172 §11.2)
    MissingSecurityOperation = 12,
    /// Unknown security context (RFC 9172 §11.2)
    UnknownSecurityContext = 13,
    /// Unexpected security operation (RFC 9172 §11.2)
    UnexpectedSecurityOperation = 14,
    /// Failed security operation (RFC 9172 §11.2)
    FailedSecurityOperation = 15,
    /// Conflicting security operation (RFC 9172 §11.2)
    ConflictingSecurityOperation = 16,
}

impl StatusReport {
    /// Create deletion status report
    pub fn deletion(
        source_eid: EndpointId,
        creation_timestamp: CreationTimestamp,
        reason_code: ReasonCode,
        time: Option<SimInstant>,
    ) -> Self {
        Self {
            received: StatusInfo::new(false),
            forwarded: StatusInfo::new(false),
            delivered: StatusInfo::new(false),
            deleted: if let Some(t) = time {
                StatusInfo::with_time(true, t)
            } else {
                StatusInfo::new(true)
            },
            reason_code,
            source_eid,
            creation_timestamp,
            fragment_offset: None,
            fragment_length: None,
        }
    }

    /// Create reception status report
    pub fn reception(
        source_eid: EndpointId,
        creation_timestamp: CreationTimestamp,
        time: Option<SimInstant>,
    ) -> Self {
        Self {
            received: if let Some(t) = time {
                StatusInfo::with_time(true, t)
            } else {
                StatusInfo::new(true)
            },
            forwarded: StatusInfo::new(false),
            delivered: StatusInfo::new(false),
            deleted: StatusInfo::new(false),
            reason_code: ReasonCode::NoAdditionalInformation,
            source_eid,
            creation_timestamp,
            fragment_offset: None,
            fragment_length: None,
        }
    }

    /// Create forwarding status report
    pub fn forwarding(
        source_eid: EndpointId,
        creation_timestamp: CreationTimestamp,
        time: Option<SimInstant>,
    ) -> Self {
        Self {
            received: StatusInfo::new(false),
            forwarded: if let Some(t) = time {
                StatusInfo::with_time(true, t)
            } else {
                StatusInfo::new(true)
            },
            delivered: StatusInfo::new(false),
            deleted: StatusInfo::new(false),
            reason_code: ReasonCode::NoAdditionalInformation,
            source_eid,
            creation_timestamp,
            fragment_offset: None,
            fragment_length: None,
        }
    }

    /// Create delivery status report
    pub fn delivery(
        source_eid: EndpointId,
        creation_timestamp: CreationTimestamp,
        time: Option<SimInstant>,
    ) -> Self {
        Self {
            received: StatusInfo::new(false),
            forwarded: StatusInfo::new(false),
            delivered: if let Some(t) = time {
                StatusInfo::with_time(true, t)
            } else {
                StatusInfo::new(true)
            },
            deleted: StatusInfo::new(false),
            reason_code: ReasonCode::NoAdditionalInformation,
            source_eid,
            creation_timestamp,
            fragment_offset: None,
            fragment_length: None,
        }
    }
}

/// Encode a StatusReport to CBOR per RFC 9171 §6.1.1
///
/// Status report structure:
/// - [status_info_array, reason_code, source_eid, creation_ts, fragment_offset?, fragment_length?]
/// - status_info_array: \[\[received\], \[forwarded\], \[delivered\], \[deleted\]\]
/// - Each status item: [bool] or [bool, dtn_time] if status time is included
pub fn encode_status_report(report: &StatusReport, include_status_time: bool) -> Vec<u8> {
    let mut status_info_array = Vec::new();

    // Encode each status item: [bool] or [bool, time]
    fn encode_status_item(info: &StatusInfo, include_time: bool) -> Value {
        if include_time && let Some(time) = info.time {
            let time_ms = time.as_nanos() / 1_000_000;
            return Value::Array(vec![
                Value::Bool(info.asserted),
                Value::Integer(time_ms.into()),
            ]);
        }
        Value::Array(vec![Value::Bool(info.asserted)])
    }

    status_info_array.push(encode_status_item(&report.received, include_status_time));
    status_info_array.push(encode_status_item(&report.forwarded, include_status_time));
    status_info_array.push(encode_status_item(&report.delivered, include_status_time));
    status_info_array.push(encode_status_item(&report.deleted, include_status_time));

    let mut report_array = vec![
        Value::Array(status_info_array),
        Value::Integer((report.reason_code as u8).into()),
    ];

    // Encode source EID
    let source_eid = match &report.source_eid {
        EndpointId::Ipn {
            allocator,
            node,
            service,
        } => {
            if *allocator == 0 {
                Value::Array(vec![
                    Value::Integer(2.into()), // ipn scheme code
                    Value::Array(vec![
                        Value::Integer((*node).into()),
                        Value::Integer((*service).into()),
                    ]),
                ])
            } else {
                Value::Array(vec![
                    Value::Integer(2.into()),
                    Value::Array(vec![
                        Value::Integer((*allocator).into()),
                        Value::Integer((*node).into()),
                        Value::Integer((*service).into()),
                    ]),
                ])
            }
        }
        EndpointId::Dtn { ssp } => {
            Value::Array(vec![Value::Integer(1.into()), Value::Text(ssp.clone())])
        }
        _ => panic!("Unsupported EID scheme for status report"),
    };
    report_array.push(source_eid);

    // Encode creation timestamp [dtn_time, sequence]
    let timestamp = Value::Array(vec![
        Value::Integer(report.creation_timestamp.time.as_millis().into()),
        Value::Integer(report.creation_timestamp.sequence.into()),
    ]);
    report_array.push(timestamp);

    // Add fragment fields if present
    if let Some(offset) = report.fragment_offset {
        report_array.push(Value::Integer(offset.into()));
        report_array.push(Value::Integer(report.fragment_length.unwrap().into()));
    }

    // Wrap in administrative record: [record_type=1, record_content]
    let admin_record = Value::Array(vec![
        Value::Integer(1.into()), // Record type 1 = Bundle status report
        Value::Array(report_array),
    ]);

    let mut buffer = Vec::new();
    ciborium::into_writer(&admin_record, &mut buffer).expect("CBOR encoding failed");
    buffer
}

/// Decode a StatusReport from CBOR per RFC 9171 §6.1.1
pub fn decode_status_report(data: &[u8]) -> crate::types::Result<(StatusReport, bool)> {
    let value: Value = ciborium::from_reader(Cursor::new(data))
        .map_err(|e| crate::types::Error::malformed_input(format!("CBOR decode failed: {}", e)))?;

    // Parse admin record: [record_type, record_content]
    let admin_array = value
        .as_array()
        .ok_or_else(|| crate::types::Error::malformed_input("Admin record not an array"))?;

    if admin_array.len() != 2 {
        return Err(crate::types::Error::malformed_input(
            "Admin record wrong length",
        ));
    }

    let record_type = admin_array[0]
        .as_integer()
        .ok_or_else(|| crate::types::Error::malformed_input("Record type not integer"))?;

    if record_type != 1.into() {
        return Err(crate::types::Error::malformed_input(format!(
            "Wrong record type: {:?}",
            record_type
        )));
    }

    let report_array = admin_array[1]
        .as_array()
        .ok_or_else(|| crate::types::Error::malformed_input("Report content not array"))?;

    if report_array.len() < 4 || report_array.len() > 6 {
        return Err(crate::types::Error::malformed_input(format!(
            "Status report wrong length: {}",
            report_array.len()
        )));
    }

    // Parse status info array
    let status_info_array = report_array[0]
        .as_array()
        .ok_or_else(|| crate::types::Error::malformed_input("Status info not array"))?;

    if status_info_array.len() != 4 {
        return Err(crate::types::Error::malformed_input(
            "Status info wrong length",
        ));
    }

    fn decode_status_item(item: &Value) -> crate::types::Result<(StatusInfo, bool)> {
        let item_array = item
            .as_array()
            .ok_or_else(|| crate::types::Error::malformed_input("Status item not array"))?;

        if item_array.is_empty() || item_array.len() > 2 {
            return Err(crate::types::Error::malformed_input(
                "Status item wrong length",
            ));
        }

        let asserted = item_array[0]
            .as_bool()
            .ok_or_else(|| crate::types::Error::malformed_input("Status asserted not bool"))?;

        let has_time = item_array.len() == 2;
        let time = if has_time {
            let time_ms = item_array[1]
                .as_integer()
                .ok_or_else(|| crate::types::Error::malformed_input("Status time not integer"))?;
            let time_ms_u64: u64 = time_ms
                .try_into()
                .map_err(|_| crate::types::Error::malformed_input("Status time out of range"))?;
            Some(SimInstant::from_nanos(time_ms_u64 * 1_000_000))
        } else {
            None
        };

        Ok((StatusInfo { asserted, time }, has_time))
    }

    let (received, r_has_time) = decode_status_item(&status_info_array[0])?;
    let (forwarded, f_has_time) = decode_status_item(&status_info_array[1])?;
    let (delivered, d_has_time) = decode_status_item(&status_info_array[2])?;
    let (deleted, del_has_time) = decode_status_item(&status_info_array[3])?;

    let has_status_time = r_has_time || f_has_time || d_has_time || del_has_time;

    // Parse reason code
    let reason_code_int = report_array[1]
        .as_integer()
        .ok_or_else(|| crate::types::Error::malformed_input("Reason code not integer"))?;
    let reason_code_u8: u8 = reason_code_int
        .try_into()
        .map_err(|_| crate::types::Error::malformed_input("Reason code out of range"))?;
    let reason_code = match reason_code_u8 {
        0 => ReasonCode::NoAdditionalInformation,
        1 => ReasonCode::LifetimeExpired,
        2 => ReasonCode::ForwardedOverUnidirectionalLink,
        3 => ReasonCode::TransmissionCancelled,
        4 => ReasonCode::DepletedStorage,
        5 => ReasonCode::DestinationEndpointUnavailable,
        6 => ReasonCode::NoKnownRoute,
        7 => ReasonCode::NoTimelyContact,
        8 => ReasonCode::BlockUnintelligible,
        9 => ReasonCode::HopLimitExceeded,
        10 => ReasonCode::TrafficPared,
        11 => ReasonCode::BlockUnsupported,
        12 => ReasonCode::MissingSecurityOperation,
        13 => ReasonCode::UnknownSecurityContext,
        14 => ReasonCode::UnexpectedSecurityOperation,
        15 => ReasonCode::FailedSecurityOperation,
        16 => ReasonCode::ConflictingSecurityOperation,
        _ => {
            return Err(crate::types::Error::malformed_input(format!(
                "Unknown reason code: {}",
                reason_code_u8
            )));
        }
    };

    // Parse source EID (array format)
    let source_eid_array = report_array[2]
        .as_array()
        .ok_or_else(|| crate::types::Error::malformed_input("Source EID not array"))?;

    if source_eid_array.len() != 2 {
        return Err(crate::types::Error::malformed_input(
            "Source EID wrong length",
        ));
    }

    let scheme_code = source_eid_array[0]
        .as_integer()
        .ok_or_else(|| crate::types::Error::malformed_input("EID scheme code not integer"))?;

    let source_eid = match Into::<i128>::into(scheme_code) {
        1 => {
            // dtn scheme
            let ssp = source_eid_array[1]
                .as_text()
                .ok_or_else(|| crate::types::Error::malformed_input("dtn SSP not text"))?;
            EndpointId::Dtn {
                ssp: ssp.to_string(),
            }
        }
        2 => {
            // ipn scheme
            let parts = source_eid_array[1]
                .as_array()
                .ok_or_else(|| crate::types::Error::malformed_input("ipn parts not array"))?;

            if parts.len() == 2 {
                let node: u64 = parts[0]
                    .as_integer()
                    .ok_or_else(|| crate::types::Error::malformed_input("ipn node not integer"))?
                    .try_into()
                    .map_err(|_| crate::types::Error::malformed_input("ipn node out of range"))?;
                let service: u64 = parts[1]
                    .as_integer()
                    .ok_or_else(|| crate::types::Error::malformed_input("ipn service not integer"))?
                    .try_into()
                    .map_err(|_| {
                        crate::types::Error::malformed_input("ipn service out of range")
                    })?;
                EndpointId::Ipn {
                    allocator: 0,
                    node,
                    service,
                }
            } else if parts.len() == 3 {
                let allocator: u64 = parts[0]
                    .as_integer()
                    .ok_or_else(|| {
                        crate::types::Error::malformed_input("ipn allocator not integer")
                    })?
                    .try_into()
                    .map_err(|_| {
                        crate::types::Error::malformed_input("ipn allocator out of range")
                    })?;
                let node: u64 = parts[1]
                    .as_integer()
                    .ok_or_else(|| crate::types::Error::malformed_input("ipn node not integer"))?
                    .try_into()
                    .map_err(|_| crate::types::Error::malformed_input("ipn node out of range"))?;
                let service: u64 = parts[2]
                    .as_integer()
                    .ok_or_else(|| crate::types::Error::malformed_input("ipn service not integer"))?
                    .try_into()
                    .map_err(|_| {
                        crate::types::Error::malformed_input("ipn service out of range")
                    })?;
                EndpointId::Ipn {
                    allocator,
                    node,
                    service,
                }
            } else {
                return Err(crate::types::Error::malformed_input(
                    "ipn wrong number of parts",
                ));
            }
        }
        _ => {
            return Err(crate::types::Error::malformed_input(format!(
                "Unknown EID scheme: {}",
                Into::<i128>::into(scheme_code)
            )));
        }
    };

    // Parse creation timestamp [time, seq]
    let timestamp_array = report_array[3]
        .as_array()
        .ok_or_else(|| crate::types::Error::malformed_input("Creation timestamp not array"))?;

    if timestamp_array.len() != 2 {
        return Err(crate::types::Error::malformed_input(
            "Creation timestamp wrong length",
        ));
    }

    let time_ms: u64 = timestamp_array[0]
        .as_integer()
        .ok_or_else(|| crate::types::Error::malformed_input("Timestamp time not integer"))?
        .try_into()
        .map_err(|_| crate::types::Error::malformed_input("Timestamp time out of range"))?;

    let seq: u64 = timestamp_array[1]
        .as_integer()
        .ok_or_else(|| crate::types::Error::malformed_input("Timestamp seq not integer"))?
        .try_into()
        .map_err(|_| crate::types::Error::malformed_input("Timestamp seq out of range"))?;

    let creation_timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(time_ms), seq);

    // Parse fragment fields if present
    let (fragment_offset, fragment_length) = if report_array.len() == 6 {
        let offset: u64 = report_array[4]
            .as_integer()
            .ok_or_else(|| crate::types::Error::malformed_input("Fragment offset not integer"))?
            .try_into()
            .map_err(|_| crate::types::Error::malformed_input("Fragment offset out of range"))?;

        let length: u64 = report_array[5]
            .as_integer()
            .ok_or_else(|| crate::types::Error::malformed_input("Fragment length not integer"))?
            .try_into()
            .map_err(|_| crate::types::Error::malformed_input("Fragment length out of range"))?;

        (Some(offset), Some(length))
    } else {
        (None, None)
    };

    Ok((
        StatusReport {
            received,
            forwarded,
            delivered,
            deleted,
            reason_code,
            source_eid,
            creation_timestamp,
            fragment_offset,
            fragment_length,
        },
        has_status_time,
    ))
}

/// Create an admin bundle containing a status report
///
/// Per RFC 9171 §6:
/// - Source EID is the reporting node
/// - Destination is the subject bundle's report-to EID
/// - Service number 0 (administrative endpoint)
pub fn create_status_report_bundle(
    report: StatusReport,
    reporting_node: &EndpointId,
    report_to: &EndpointId,
    current_time: SimInstant,
    creation_seq: u64,
    include_status_time: bool,
) -> crate::types::Result<Bundle> {
    use crate::bp::{BundleBuilder, CrcType};
    use crate::types::{CreationTimestamp, DtnTimeMs};

    // Encode status report to CBOR
    let payload = encode_status_report(&report, include_status_time);

    let timestamp = CreationTimestamp::new(
        DtnTimeMs::from_millis(current_time.as_nanos() / 1_000_000),
        creation_seq,
    );

    // Create administrative bundle with IS_ADMIN_RECORD flag set
    let mut bundle = BundleBuilder::new()
        .source(reporting_node.clone())
        .destination(report_to.clone())
        .creation_timestamp(timestamp)
        .lifetime(3_600_000) // 1 hour
        .crc_type(CrcType::Crc32)
        .payload(payload)
        .build()?;

    // Set the administrative record flag (Bit 1)
    bundle.primary.bundle_flags |= bundle_flags::IS_ADMIN_RECORD;

    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_flag_constants_match_rfc() {
        // RFC 9171 §4.2.3: "Bit 0 (0x000001): The bundle is a fragment."
        assert_eq!(bundle_flags::IS_FRAGMENT, 0x000001);

        // RFC 9171 §4.2.3: "Bit 1 (0x000002): ADU is an administrative record."
        assert_eq!(bundle_flags::IS_ADMIN_RECORD, 0x000002);

        // RFC 9171 §4.2.3: "Bit 2 (0x000004): Bundle must not be fragmented."
        assert_eq!(bundle_flags::MUST_NOT_FRAGMENT, 0x000004);

        // RFC 9171 §4.2.3: "Bit 5 (0x000020): Acknowledgement by application is requested."
        assert_eq!(bundle_flags::REQUEST_APP_ACK, 0x000020);

        // RFC 9171 §4.2.3: "Bit 6 (0x000040): Status time requested in reports."
        assert_eq!(bundle_flags::REQUEST_STATUS_TIME, 0x000040);

        // RFC 9171 §4.2.3: "Bit 14 (0x004000): Request reporting of bundle reception."
        assert_eq!(bundle_flags::REQUEST_REPORT_RECEPTION, 0x004000);

        // RFC 9171 §4.2.3: "Bit 16 (0x010000): Request reporting of bundle forwarding."
        assert_eq!(bundle_flags::REQUEST_REPORT_FORWARD, 0x010000);

        // RFC 9171 §4.2.3: "Bit 17 (0x020000): Request reporting of bundle delivery."
        assert_eq!(bundle_flags::REQUEST_REPORT_DELIVERY, 0x020000);

        // RFC 9171 §4.2.3: "Bit 18 (0x040000): Request reporting of bundle deletion."
        assert_eq!(bundle_flags::REQUEST_REPORT_DELETION, 0x040000);
    }

    #[test]
    fn test_status_report_roundtrip_without_time() {
        // Create a status report
        let report = StatusReport {
            received: StatusInfo::new(false),
            forwarded: StatusInfo::new(false),
            delivered: StatusInfo::new(false),
            deleted: StatusInfo::new(true),
            reason_code: ReasonCode::HopLimitExceeded,
            source_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 42),
            fragment_offset: None,
            fragment_length: None,
        };

        // Encode to CBOR
        let encoded = encode_status_report(&report, false);

        // Decode from CBOR
        let (decoded, has_time) = decode_status_report(&encoded).unwrap();

        // Verify round-trip
        assert!(!has_time);
        assert!(!decoded.received.asserted);
        assert!(!decoded.forwarded.asserted);
        assert!(!decoded.delivered.asserted);
        assert!(decoded.deleted.asserted);
        assert!(decoded.deleted.time.is_none());
        assert_eq!(
            decoded.reason_code as u8,
            ReasonCode::HopLimitExceeded as u8
        );

        if let EndpointId::Ipn {
            allocator,
            node,
            service,
        } = decoded.source_eid
        {
            assert_eq!(allocator, 0);
            assert_eq!(node, 1);
            assert_eq!(service, 0);
        } else {
            panic!("Expected IPN EID");
        }

        assert_eq!(decoded.creation_timestamp.time.as_millis(), 1000);
        assert_eq!(decoded.creation_timestamp.sequence, 42);
        assert!(decoded.fragment_offset.is_none());
        assert!(decoded.fragment_length.is_none());
    }

    #[test]
    fn test_status_report_roundtrip_with_time() {
        // Create a status report with status time
        let time = SimInstant::from_nanos(5_000_000_000); // 5s
        let report = StatusReport {
            received: StatusInfo::with_time(true, time),
            forwarded: StatusInfo::new(false),
            delivered: StatusInfo::new(false),
            deleted: StatusInfo::new(false),
            reason_code: ReasonCode::NoAdditionalInformation,
            source_eid: EndpointId::ipn(0, 2, 5).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(2000), 7),
            fragment_offset: None,
            fragment_length: None,
        };

        // Encode to CBOR
        let encoded = encode_status_report(&report, true);

        // Decode from CBOR
        let (decoded, has_time) = decode_status_report(&encoded).unwrap();

        // Verify round-trip
        assert!(has_time);
        assert!(decoded.received.asserted);
        assert!(decoded.received.time.is_some());
        assert_eq!(decoded.received.time.unwrap().as_nanos(), 5_000_000_000);
        assert!(!decoded.forwarded.asserted);
        assert!(!decoded.delivered.asserted);
        assert!(!decoded.deleted.asserted);
    }

    #[test]
    fn test_status_report_byte_level_encoding() {
        // Hand-crafted status report for byte-level verification
        let report = StatusReport {
            received: StatusInfo::new(false),
            forwarded: StatusInfo::new(true),
            delivered: StatusInfo::new(false),
            deleted: StatusInfo::new(false),
            reason_code: ReasonCode::NoAdditionalInformation,
            source_eid: EndpointId::ipn(0, 1, 2).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1),
            fragment_offset: None,
            fragment_length: None,
        };

        let encoded = encode_status_report(&report, false);

        // Verify CBOR structure manually
        // Expected structure:
        // [                             // Admin record array
        //   1,                          // Record type = 1 (status report)
        //   [                           // Status report array
        //     [                         // Status info array
        //       [false],                //   received
        //       [true],                 //   forwarded
        //       [false],                //   delivered
        //       [false]                 //   deleted
        //     ],
        //     0,                        // Reason code = 0
        //     [2, [1, 2]],              // Source EID: ipn:1.2
        //     [1000, 1]                 // Creation timestamp
        //   ]
        // ]

        // Decode and verify
        let (decoded, _) = decode_status_report(&encoded).unwrap();

        // Byte annotations (CBOR diagnostic notation):
        // 82           - Array(2) - Admin record
        //   01         - Unsigned(1) - Record type
        //   84         - Array(4) - Status report (no fragments)
        //     84       - Array(4) - Status info
        //       81 F4  - Array(1) [false] - received
        //       81 F5  - Array(1) [true] - forwarded
        //       81 F4  - Array(1) [false] - delivered
        //       81 F4  - Array(1) [false] - deleted
        //     00       - Unsigned(0) - reason code
        //     82       - Array(2) - Source EID
        //       02     - Unsigned(2) - ipn scheme
        //       82     - Array(2) - [node, service] (allocator 0)
        //         01   - Unsigned(1) - node
        //         02   - Unsigned(2) - service
        //     82       - Array(2) - Creation timestamp
        //       19 03E8 - Unsigned(1000) - time
        //       01      - Unsigned(1) - sequence

        assert!(!decoded.received.asserted);
        assert!(decoded.forwarded.asserted);
        assert!(!decoded.delivered.asserted);
        assert!(!decoded.deleted.asserted);
        assert_eq!(decoded.reason_code as u8, 0);

        // Verify the encoded bytes start with expected CBOR markers
        assert_eq!(encoded[0], 0x82); // Array(2) - admin record
        assert_eq!(encoded[1], 0x01); // Unsigned(1) - record type
        assert_eq!(encoded[2], 0x84); // Array(4) - status report
        assert_eq!(encoded[3], 0x84); // Array(4) - status info array
    }

    #[test]
    fn test_status_report_with_fragments() {
        let report = StatusReport {
            received: StatusInfo::new(true),
            forwarded: StatusInfo::new(false),
            delivered: StatusInfo::new(false),
            deleted: StatusInfo::new(false),
            reason_code: ReasonCode::NoAdditionalInformation,
            source_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1),
            fragment_offset: Some(1024),
            fragment_length: Some(512),
        };

        let encoded = encode_status_report(&report, false);
        let (decoded, _) = decode_status_report(&encoded).unwrap();

        assert_eq!(decoded.fragment_offset, Some(1024));
        assert_eq!(decoded.fragment_length, Some(512));
    }
}
