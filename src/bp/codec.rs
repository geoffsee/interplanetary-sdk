//! CBOR codec for Bundle Protocol per RFC 9171 §4

use super::{
    Bundle,
    blocks::{BlockType, CanonicalBlock, PrimaryBlock},
    crc::CrcType,
};
use crate::types::{Error, Result};
use ciborium::Value;
use std::io::Cursor;

/// Bundle encoding errors
#[derive(Debug)]
pub enum EncodeError {
    /// CBOR encoding failed
    CborError(String),
    /// Invalid bundle structure
    InvalidStructure(String),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CborError(msg) => write!(f, "CBOR encoding error: {}", msg),
            Self::InvalidStructure(msg) => write!(f, "Invalid bundle structure: {}", msg),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Bundle decoding errors
#[derive(Debug)]
pub enum DecodeError {
    /// CBOR decoding failed
    CborError(String),
    /// Malformed bundle
    MalformedBundle(String),
    /// CRC validation failed
    CrcMismatch,
    /// Unsupported version
    UnsupportedVersion(u8),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CborError(msg) => write!(f, "CBOR decoding error: {}", msg),
            Self::MalformedBundle(msg) => write!(f, "Malformed bundle: {}", msg),
            Self::CrcMismatch => write!(f, "CRC validation failed"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported BP version: {}", v),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Bundle codec for encoding and decoding
#[derive(Debug)]
pub struct BundleCodec;

impl BundleCodec {
    /// Encode bundle to wire format (CBOR bytes)
    pub fn encode(bundle: &Bundle) -> Result<Vec<u8>> {
        // Per RFC 9171 §4.1: Bundle is an indefinite-length CBOR array
        // containing primary block and canonical blocks

        let mut output = Vec::new();

        // Start indefinite array
        output.push(0x9F); // Array, indefinite length

        // Encode primary block
        let primary_bytes = Self::encode_primary(&bundle.primary)?;
        output.extend_from_slice(&primary_bytes);

        // Encode canonical blocks
        for block in &bundle.blocks {
            let block_bytes = Self::encode_canonical(block)?;
            output.extend_from_slice(&block_bytes);
        }

        // End indefinite array
        output.push(0xFF); // Break

        Ok(output)
    }

    /// Decode bundle from wire format with strict bounds checking
    pub fn decode(bytes: &[u8]) -> Result<Bundle> {
        if bytes.is_empty() {
            return Err(Error::malformed_input("Empty bundle"));
        }

        // Maximum bundle size to prevent resource exhaustion
        const MAX_BUNDLE_SIZE: usize = 100 * 1024 * 1024; // 100 MiB
        if bytes.len() > MAX_BUNDLE_SIZE {
            return Err(Error::malformed_input(format!(
                "Bundle too large: {} > {}",
                bytes.len(),
                MAX_BUNDLE_SIZE
            )));
        }

        // Check for indefinite array marker
        if bytes[0] != 0x9F {
            return Err(Error::malformed_input(
                "Bundle must start with indefinite array",
            ));
        }

        // Parse CBOR indefinite array
        let mut cursor = Cursor::new(&bytes[1..]); // Skip 0x9F marker
        let mut elements = Vec::new();
        let mut raw_blocks = Vec::new(); // Track raw byte spans for CRC validation

        // Read elements until break marker
        loop {
            let pos = cursor.position() as usize;
            if pos >= bytes.len() - 1 {
                return Err(Error::malformed_input("Missing break marker"));
            }

            // Check for break marker (0xFF)
            if bytes[1 + pos] == 0xFF {
                break;
            }

            let start_pos = 1 + pos; // Absolute position in bytes
            let element: Value = ciborium::from_reader(&mut cursor)
                .map_err(|e| Error::malformed_input(format!("Block parse error: {}", e)))?;
            let end_pos = 1 + cursor.position() as usize;

            // Store raw bytes for this block
            raw_blocks.push(&bytes[start_pos..end_pos]);
            elements.push(element);

            // Limit number of blocks
            if elements.len() > 1000 {
                return Err(Error::malformed_input("Too many blocks"));
            }
        }

        if elements.is_empty() {
            return Err(Error::malformed_input("Bundle has no primary block"));
        }

        // First element is primary block - validate CRC from raw bytes
        Self::validate_block_crc(raw_blocks[0], &elements[0], true)?;
        let primary = Self::decode_primary(&elements[0])?;

        // RFC 9171 §4.2.3 (RFC9171-4-018): If bundle's ADU is an administrative record,
        // then all status report request flag values MUST be zero
        const IS_ADMIN_RECORD: u64 = 0x000002;
        const STATUS_REPORT_FLAGS: u64 = 0x07C000; // Bits 14-18
        if (primary.bundle_flags & IS_ADMIN_RECORD) != 0
            && (primary.bundle_flags & STATUS_REPORT_FLAGS) != 0
        {
            return Err(Error::malformed_input(
                "RFC 9171 §4.2.3: Admin records MUST have zero status report flags",
            ));
        }

        // RFC 9171 §4.2.3: Validate bundle processing control flags constraints
        Self::validate_bundle_flags(&primary)?;

        // Remaining elements are canonical blocks
        let mut blocks = Vec::new();
        for (i, element) in elements[1..].iter().enumerate() {
            Self::validate_block_crc(raw_blocks[i + 1], element, false)?;
            blocks.push(Self::decode_canonical(element)?);
        }

        // RFC 9171 §4.2.4 (RFC9171-4-025): admin/null-source → block report flag MUST be 0
        Self::validate_admin_block_flags(&primary, &blocks)?;

        // RFC 9171 §4.4: Validate extension block uniqueness constraints
        Self::validate_extension_block_uniqueness(&blocks)?;

        // RFC 9171 §4.1: Bundle structure validation
        // "the bundle MUST have exactly one payload block"
        // "The last such block MUST be a payload block"
        Self::validate_bundle_structure(&blocks)?;

        // RFC 9171 §4.3.1: "The CRC type code for the primary block MAY be zero if
        // the bundle contains a BPSec Block Integrity Block [BPSEC] whose target is
        // the primary block; otherwise, the CRC type code for the primary block MUST
        // be non-zero."
        // Note: This is a generation rule (MUST for senders), not a validation rule.
        // We accept CRC type 0 on decode but enforce it on encode.

        Ok(Bundle::new(primary, blocks))
    }

    /// Validate CRC for a block from raw bytes per RFC 9171 §4.2.1
    ///
    /// Process: extract CRC value, zero it in a copy, recompute, compare.
    /// Primary block: CRC type at index 2. Canonical block: CRC type at index 3
    /// (after type, number, flags) — must not treat unrecognized block flags as CRC type.
    fn validate_block_crc(raw_bytes: &[u8], parsed: &Value, is_primary: bool) -> Result<()> {
        use super::crc::{Crc, CrcType};

        let arr = parsed
            .as_array()
            .ok_or_else(|| Error::malformed_input("Block must be array"))?;

        // Primary: [version, flags, crc_type, ...] — CRC type at index 2
        // Canonical: [type, number, flags, crc_type, data, crc?] — CRC type at index 3
        let crc_idx = if is_primary { 2 } else { 3 };
        if arr.len() <= crc_idx {
            return Ok(()); // No CRC field present
        }

        let crc_type_val = arr[crc_idx]
            .as_integer()
            .and_then(|i| i.try_into().ok())
            .ok_or_else(|| Error::malformed_input("Invalid CRC type"))?;
        let crc_type = CrcType::from_u64(crc_type_val)
            .ok_or_else(|| Error::malformed_input("Unknown CRC type"))?;

        if crc_type == CrcType::None {
            return Ok(()); // No validation needed, no CRC field present
        }

        // Extract CRC value (last element, only present if CRC type != None)
        // For canonical blocks: CRC field might be absent even if type != 0 (depends on encoding)
        // For primary blocks: CRC field always present
        let crc_bytes = match arr.last().and_then(|v| v.as_bytes()) {
            Some(bytes) if bytes.len() == crc_type.len() => bytes,
            Some(_bytes) => {
                // Last element is bytes but wrong length - might be data field, not CRC
                // This happens for canonical blocks with CRC type != 0 but only 5 elements
                // Skip validation for now (block decode will catch the inconsistency)
                return Ok(());
            }
            None => {
                // Last element is not bytes - skip validation
                return Ok(());
            }
        };

        // Find CRC value location in raw bytes
        // CRC is encoded as a byte string at the end
        // For CRC-16: 0x42 <byte1> <byte2>
        // For CRC-32C: 0x44 <byte1> <byte2> <byte3> <byte4>
        let crc_marker = match crc_type {
            CrcType::Crc16 => 0x42u8,
            CrcType::Crc32 => 0x44u8,
            CrcType::None => unreachable!(),
        };

        // Find the last occurrence of the CRC marker
        let crc_pos = raw_bytes
            .iter()
            .rposition(|&b| b == crc_marker)
            .ok_or_else(|| Error::malformed_input("CRC marker not found in raw bytes"))?;

        // Verify the CRC value follows the marker
        if crc_pos + 1 + crc_type.len() > raw_bytes.len() {
            return Err(Error::malformed_input("CRC value truncated"));
        }

        // Create a copy with zeroed CRC bytes
        let mut validation_bytes = raw_bytes.to_vec();
        for i in 0..crc_type.len() {
            validation_bytes[crc_pos + 1 + i] = 0x00;
        }

        // Compute CRC over the validation bytes
        let computed_crc = Crc::compute(crc_type, &validation_bytes);

        // Compare with extracted CRC
        if computed_crc.as_slice() != crc_bytes {
            return Err(Error::malformed_input("CRC validation failed"));
        }

        Ok(())
    }

    /// Validate bundle processing control flags per RFC 9171 §4.2.3
    fn validate_bundle_flags(primary: &PrimaryBlock) -> Result<()> {
        let flags = primary.bundle_flags;
        // Bit 1 (0x000002): ADU is an administrative record (RFC 9171 §4.2.3)
        let is_admin = (flags & 0x000002) != 0;
        let is_null_source = primary.source.is_null();
        let must_not_fragment = (flags & 0x000004) != 0; // Bit 2: must not be fragmented
        let status_flags = (flags >> 14) & 0x3F; // Bits 14-19: status report flags

        // RFC 9171 §4.2.3: "If the bundle processing control flags indicate that
        // the bundle's ADU is an administrative record, then all status report
        // request flag values MUST be zero."
        if is_admin && status_flags != 0 {
            return Err(Error::malformed_input(
                "RFC 9171 §4.2.3: Admin records MUST have zero status report flags",
            ));
        }

        // RFC 9171 §4.2.3: "If the bundle's source node is omitted (i.e., the
        // source node ID is the null endpoint ID), then the bundle MUST NOT be
        // fragmented (and therefore the 'Bundle must not be fragmented' flag
        // value MUST be 1) and all status report request flag values MUST be zero."
        if is_null_source {
            if !must_not_fragment {
                return Err(Error::malformed_input(
                    "RFC 9171 §4.2.3: Null source bundles MUST set 'must not be fragmented' flag",
                ));
            }
            if status_flags != 0 {
                return Err(Error::malformed_input(
                    "RFC 9171 §4.2.3: Null source bundles MUST have zero status report flags",
                ));
            }
        }

        Ok(())
    }

    /// RFC 9171 §4.2.4 / RFC9171-4-025: for admin-record or null-source bundles,
    /// "Transmit status report if block can't be processed" MUST be zero in every
    /// canonical block.
    fn validate_admin_block_flags(primary: &PrimaryBlock, blocks: &[CanonicalBlock]) -> Result<()> {
        let is_admin = (primary.bundle_flags & 0x000002) != 0;
        let is_null_source = primary.source.is_null();
        if !is_admin && !is_null_source {
            return Ok(());
        }
        const REPORT_ON_FAILURE: u64 = 0x02;
        for b in blocks {
            if (b.block_flags & REPORT_ON_FAILURE) != 0 {
                return Err(Error::malformed_input(
                    "RFC 9171 §4.2.4: Transmit-status-if-block-can't-be-processed MUST be zero for admin/null-source bundles",
                ));
            }
        }
        Ok(())
    }

    /// Validate extension block uniqueness per RFC 9171 §4.4
    fn validate_extension_block_uniqueness(blocks: &[super::CanonicalBlock]) -> Result<()> {
        use super::BlockType;
        use std::collections::HashSet;

        let mut seen_types = HashSet::new();

        for block in blocks {
            match block.block_type {
                BlockType::PreviousNode => {
                    // RFC 9171 §4.4.1: "the bundle SHOULD contain one (1) occurrence
                    // of this type of block and MUST NOT contain more than one."
                    if seen_types.contains(&BlockType::PreviousNode) {
                        return Err(Error::malformed_input(
                            "RFC 9171 §4.4.1: Bundle MUST NOT contain more than one Previous Node block",
                        ));
                    }
                    seen_types.insert(BlockType::PreviousNode);
                }
                BlockType::BundleAge => {
                    // RFC 9171 §4.4.2: "A bundle MUST NOT contain multiple occurrences
                    // of the Bundle Age Block, as this could result in processing anomalies."
                    if seen_types.contains(&BlockType::BundleAge) {
                        return Err(Error::malformed_input(
                            "RFC 9171 §4.4.2: Bundle MUST NOT contain multiple Bundle Age blocks",
                        ));
                    }
                    seen_types.insert(BlockType::BundleAge);
                }
                BlockType::HopCount => {
                    // RFC 9171 §4.4.3: By analogy with other extension blocks,
                    // at most one Hop Count block per bundle
                    if seen_types.contains(&BlockType::HopCount) {
                        return Err(Error::malformed_input(
                            "RFC 9171 §4.4.3: Bundle MUST NOT contain more than one Hop Count block",
                        ));
                    }
                    seen_types.insert(BlockType::HopCount);
                }
                _ => {
                    // Other block types may have multiple occurrences
                }
            }
        }

        Ok(())
    }

    /// Validate bundle structure per RFC 9171 §4.1
    ///
    /// - Bundle MUST have exactly one payload block
    /// - Last block MUST be a payload block
    fn validate_bundle_structure(blocks: &[super::CanonicalBlock]) -> Result<()> {
        // RFC 9171 §4.1: Bundle must have at least one block (the payload)
        if blocks.is_empty() {
            return Err(Error::malformed_input(
                "RFC 9171 §4.1: Bundle MUST have exactly one payload block (found 0 blocks)",
            ));
        }

        // Count payload blocks
        let payload_count = blocks.iter().filter(|b| b.block_type.is_payload()).count();

        // RFC 9171 §4.1: "the bundle MUST have exactly one payload block"
        if payload_count == 0 {
            return Err(Error::malformed_input(
                "RFC 9171 §4.1: Bundle MUST have exactly one payload block (found 0)",
            ));
        }

        if payload_count > 1 {
            return Err(Error::malformed_input(format!(
                "RFC 9171 §4.1: Bundle MUST have exactly one payload block (found {})",
                payload_count
            )));
        }

        // RFC 9171 §4.1: "The last such block MUST be a payload block"
        if let Some(last_block) = blocks.last()
            && !last_block.block_type.is_payload()
        {
            return Err(Error::malformed_input(
                "RFC 9171 §4.1: Last block MUST be a payload block",
            ));
        }

        Ok(())
    }

    /// Encode primary block to CBOR bytes per RFC 9171 §4.3.1
    ///
    /// Fields are encoded in the order specified by RFC 9171:
    /// version, bundle_flags, crc_type, destination, source, report_to,
    /// creation_timestamp, lifetime, fragment_offset (optional),
    /// total_app_data_length (optional), CRC (optional, computed last).
    pub fn encode_primary(primary: &PrimaryBlock) -> Result<Vec<u8>> {
        use super::cbor_encoding::*;
        use super::crc::{Crc, CrcType};

        let mut buffer = Vec::new();

        // RFC 9171 §4.3.1: "Each primary block SHALL be represented as a CBOR array;
        // the number of elements in the array SHALL be 8 (if the bundle is not a
        // fragment and the block has no CRC), 9 (if the block has a CRC and the bundle
        // is not a fragment), 10 (if the bundle is a fragment and the block has no CRC),
        // or 11 (if the bundle is a fragment and the block has a CRC)."
        //
        // Array structure: 8 base elements + optional fragment fields + optional CRC
        let base_count = 8;
        let frag_count = if primary.fragment_offset.is_some() {
            if primary.total_app_data_length.is_some() {
                2
            } else {
                1
            }
        } else {
            0
        };
        let crc_count = if primary.crc_type != CrcType::None {
            1
        } else {
            0
        };
        let elem_count = base_count + frag_count + crc_count;

        encode_array_header(elem_count, &mut buffer);
        encode_uint(primary.version as u64, &mut buffer);
        encode_uint(primary.bundle_flags, &mut buffer);
        encode_uint(primary.crc_type.to_u64(), &mut buffer);

        Self::encode_eid_cbor(&primary.destination, &mut buffer)?;
        Self::encode_eid_cbor(&primary.source, &mut buffer)?;
        Self::encode_eid_cbor(&primary.report_to, &mut buffer)?;

        encode_array_header(2, &mut buffer);
        encode_uint(primary.creation_timestamp.time.as_millis(), &mut buffer);
        encode_uint(primary.creation_timestamp.sequence, &mut buffer);
        encode_uint(primary.lifetime, &mut buffer);

        if let Some(offset) = primary.fragment_offset {
            encode_uint(offset, &mut buffer);
            if let Some(total) = primary.total_app_data_length {
                encode_uint(total, &mut buffer);
            }
        }

        // CRC computation per RFC 9171 §4.2.1:
        // CRC field only present if CRC type != 0 (not part of the 8/10 base elements)
        // Encode with zero-filled CRC byte string, compute CRC, overwrite zeros
        if primary.crc_type != CrcType::None {
            let crc_offset = buffer.len();
            match primary.crc_type {
                CrcType::None => unreachable!(),
                CrcType::Crc16 => {
                    // Encode as 2-byte zero-filled byte string (0x42 0x00 0x00)
                    encode_bytes(&[0x00, 0x00], &mut buffer);
                    // Compute CRC over entire block (including the zeros)
                    let crc = Crc::crc16(&buffer);
                    // Overwrite the zero bytes (skip the 0x42 length byte)
                    buffer[crc_offset + 1] = (crc >> 8) as u8;
                    buffer[crc_offset + 2] = (crc & 0xFF) as u8;
                }
                CrcType::Crc32 => {
                    // Encode as 4-byte zero-filled byte string (0x44 + 4 zeros)
                    encode_bytes(&[0x00, 0x00, 0x00, 0x00], &mut buffer);
                    // Compute CRC over entire block
                    let crc = Crc::crc32c(&buffer);
                    // Overwrite the zero bytes (skip the 0x44 length byte)
                    buffer[crc_offset + 1] = (crc >> 24) as u8;
                    buffer[crc_offset + 2] = ((crc >> 16) & 0xFF) as u8;
                    buffer[crc_offset + 3] = ((crc >> 8) & 0xFF) as u8;
                    buffer[crc_offset + 4] = (crc & 0xFF) as u8;
                }
            }
        }

        Ok(buffer)
    }

    fn encode_eid_cbor(eid: &crate::types::EndpointId, buffer: &mut Vec<u8>) -> Result<()> {
        use super::cbor_encoding::*;
        use crate::types::EndpointId;

        match eid {
            EndpointId::Ipn {
                allocator,
                node,
                service,
            } => {
                encode_array_header(2, buffer);
                encode_uint(2, buffer); // ipn scheme code

                // Per RFC 9758 §6.1:
                // - Default Allocator (0): use 2-element [FQNN, service] (RECOMMENDED)
                // - Non-zero allocator: use 3-element [allocator, node, service] (RECOMMENDED)
                if *allocator == 0 {
                    // Two-element encoding: FQNN = (allocator << 32) | node
                    encode_array_header(2, buffer);
                    let fqnn = (*allocator << 32) | *node;
                    encode_uint(fqnn, buffer);
                    encode_uint(*service, buffer);
                } else {
                    // Three-element encoding for non-default allocators
                    encode_array_header(3, buffer);
                    encode_uint(*allocator, buffer);
                    encode_uint(*node, buffer);
                    encode_uint(*service, buffer);
                }
            }
            EndpointId::Dtn { ssp } => {
                encode_array_header(2, buffer);
                encode_uint(1, buffer);
                encode_text(ssp, buffer);
            }
            EndpointId::Null => {
                // RFC 9171 §4.2.5.1.1: dtn:none SHALL be [1, 0]
                // where 1 = dtn scheme code, 0 = SSP as CBOR unsigned integer
                encode_array_header(2, buffer);
                encode_uint(1, buffer); // dtn scheme
                encode_uint(0, buffer); // SSP = 0 for "none"
            }
            EndpointId::Unknown { .. } => {
                return Err(Error::unsupported("Cannot encode unknown EID"));
            }
        }
        Ok(())
    }

    fn encode_canonical(block: &CanonicalBlock) -> Result<Vec<u8>> {
        use super::cbor_encoding::*;
        use super::crc::{Crc, CrcType};

        // Canonical block: [type, number, flags, crc_type, data, crc_value?]
        // CRC field only present if CRC type != None (different from primary block!)
        let mut buffer = Vec::new();

        let elem_count = if block.crc_type == CrcType::None {
            5
        } else {
            6
        };
        encode_array_header(elem_count, &mut buffer);
        encode_uint(block.block_type.to_u64(), &mut buffer);
        encode_uint(block.block_number, &mut buffer);
        encode_uint(block.block_flags, &mut buffer);
        encode_uint(block.crc_type.to_u64(), &mut buffer);
        encode_bytes(&block.data, &mut buffer);

        // CRC computation per RFC 9171 §4.2.1
        // CRC field only added as 6th element if CRC type != None
        if block.crc_type != CrcType::None {
            let crc_offset = buffer.len();
            match block.crc_type {
                CrcType::None => unreachable!(),
                CrcType::Crc16 => {
                    // Encode as 2-byte zero-filled byte string
                    encode_bytes(&[0x00, 0x00], &mut buffer);
                    let crc = Crc::crc16(&buffer);
                    buffer[crc_offset + 1] = (crc >> 8) as u8;
                    buffer[crc_offset + 2] = (crc & 0xFF) as u8;
                }
                CrcType::Crc32 => {
                    // Encode as 4-byte zero-filled byte string
                    encode_bytes(&[0x00, 0x00, 0x00, 0x00], &mut buffer);
                    let crc = Crc::crc32c(&buffer);
                    buffer[crc_offset + 1] = (crc >> 24) as u8;
                    buffer[crc_offset + 2] = ((crc >> 16) & 0xFF) as u8;
                    buffer[crc_offset + 3] = ((crc >> 8) & 0xFF) as u8;
                    buffer[crc_offset + 4] = (crc & 0xFF) as u8;
                }
            }
        }

        Ok(buffer)
    }

    fn decode_primary(value: &Value) -> Result<PrimaryBlock> {
        let arr = value
            .as_array()
            .ok_or_else(|| Error::malformed_input("Primary block must be array"))?;

        if arr.len() < 8 {
            return Err(Error::malformed_input("Primary block too short"));
        }

        // Version
        let version = Self::extract_u8(&arr[0], "version")?;
        if version != 7 {
            return Err(Error::malformed_input(format!(
                "Unsupported BP version: {}",
                version
            )));
        }

        // Flags
        let bundle_flags = Self::extract_u64(&arr[1], "bundle_flags")?;

        // CRC type
        let crc_type_val = Self::extract_u64(&arr[2], "crc_type")?;
        let crc_type = CrcType::from_u64(crc_type_val)
            .ok_or_else(|| Error::malformed_input(format!("Invalid CRC type: {}", crc_type_val)))?;

        // Destination EID
        let destination = Self::decode_eid(&arr[3])?;

        // Source EID
        let source = Self::decode_eid(&arr[4])?;

        // Report-to EID
        let report_to = Self::decode_eid(&arr[5])?;

        // Creation timestamp [time, sequence]
        let ts_arr = arr[6]
            .as_array()
            .ok_or_else(|| Error::malformed_input("Creation timestamp must be array"))?;
        if ts_arr.len() != 2 {
            return Err(Error::malformed_input(
                "Creation timestamp must have 2 elements",
            ));
        }
        let time_ms = Self::extract_u64(&ts_arr[0], "creation time")?;
        let sequence = Self::extract_u64(&ts_arr[1], "sequence")?;
        let creation_timestamp = crate::types::CreationTimestamp::new(
            crate::types::DtnTimeMs::from_millis(time_ms),
            sequence,
        );

        // Lifetime
        let lifetime = Self::extract_u64(&arr[7], "lifetime")?;

        // RFC 9171 §4.3.1: Array length validation
        // 8 elements: no fragment, no CRC
        // 9 elements: CRC OR fragment offset (but not both)
        // 10 elements: fragment offset + total length (no CRC) OR CRC + fragment offset
        // 11 elements: fragment + CRC
        let has_crc = crc_type != CrcType::None;

        // Validate array length
        let expected_min = 8;
        let expected_max = 11;
        if arr.len() < expected_min || arr.len() > expected_max {
            return Err(Error::malformed_input(format!(
                "Primary block array length must be 8-11, got {}",
                arr.len()
            )));
        }

        // Parse fragment fields (if present, they're at index 8 and optionally 9)
        let mut fragment_offset = None;
        let mut total_app_data_length = None;

        // Determine if we have fragment fields based on array length and CRC type
        // Array structures:
        // - 8: base only
        // - 9: base + (CRC | frag_offset)
        // - 10: base + (CRC + frag_offset | frag_offset + total)
        // - 11: base + frag_offset + total + CRC
        let fields_after_base = arr.len() - 8;
        let has_frag = fields_after_base > (if has_crc { 1 } else { 0 });

        if has_frag {
            fragment_offset = Some(Self::extract_u64(&arr[8], "fragment offset")?);
            // Check if we also have total length
            if fields_after_base >= (if has_crc { 3 } else { 2 }) {
                total_app_data_length = Some(Self::extract_u64(&arr[9], "total length")?);
            }
        }

        // Validate CRC field presence matches CRC type
        if has_crc && arr.len() < 9 {
            return Err(Error::malformed_input(
                "Primary block has non-zero CRC type but no CRC element",
            ));
        }
        if !has_crc
            && arr.last().and_then(|v| v.as_bytes()).is_some()
            && !arr.last().unwrap().as_bytes().unwrap().is_empty()
        {
            // Last element is non-empty bytes - might be a CRC when type is 0
            if arr.len() == 9 && fragment_offset.is_none() {
                return Err(Error::malformed_input(
                    "Primary block has CRC type 0 but contains a CRC element",
                ));
            }
        }

        Ok(PrimaryBlock {
            version,
            bundle_flags,
            crc_type,
            destination,
            source,
            report_to,
            creation_timestamp,
            lifetime,
            fragment_offset,
            total_app_data_length,
        })
    }

    fn decode_canonical(value: &Value) -> Result<CanonicalBlock> {
        let arr = value
            .as_array()
            .ok_or_else(|| Error::malformed_input("Block must be array"))?;

        // Per RFC 9171 §4.3.1: Canonical block has 5 or 6 elements
        // [type, number, flags, crc_type, data, crc_value?]
        // CRC field only present if CRC type != None (different from primary block!)
        if arr.len() < 5 || arr.len() > 6 {
            return Err(Error::malformed_input(format!(
                "Canonical block must have 5 or 6 elements, got {}",
                arr.len()
            )));
        }

        let block_type = BlockType::from_u64(Self::extract_u64(&arr[0], "block type")?);
        let block_number = Self::extract_u64(&arr[1], "block number")?;
        let block_flags = Self::extract_u64(&arr[2], "block flags")?;
        let crc_type_val = Self::extract_u64(&arr[3], "crc type")?;
        let crc_type = CrcType::from_u64(crc_type_val)
            .ok_or_else(|| Error::malformed_input(format!("Invalid CRC type: {}", crc_type_val)))?;

        let data = arr[4]
            .as_bytes()
            .ok_or_else(|| Error::malformed_input("Block data must be bytes"))?
            .to_vec();

        // Element 5 is the CRC value (only present if CRC type != None), already validated
        let expected_len = if crc_type == CrcType::None { 5 } else { 6 };
        if arr.len() != expected_len {
            return Err(Error::malformed_input(format!(
                "Canonical block with CRC type {:?} should have {} elements, got {}",
                crc_type,
                expected_len,
                arr.len()
            )));
        }

        Ok(CanonicalBlock {
            block_type,
            block_number,
            block_flags,
            crc_type,
            data,
        })
    }

    fn decode_eid(value: &Value) -> Result<crate::types::EndpointId> {
        use crate::types::EndpointId;

        let arr = value
            .as_array()
            .ok_or_else(|| Error::malformed_input("EID must be array"))?;

        if arr.is_empty() {
            return Err(Error::malformed_input("EID array empty"));
        }

        let scheme = Self::extract_u64(&arr[0], "EID scheme")?;

        match scheme {
            1 => {
                // dtn: scheme
                if arr.len() != 2 {
                    return Err(Error::malformed_input("dtn: EID must have 2 elements"));
                }

                // RFC 9171 §4.2.5.1.1: SSP SHALL be text string, UNLESS
                // SSP is "none", in which case it SHALL be unsigned integer 0
                match &arr[1] {
                    Value::Integer(_i) => {
                        let ssp_int = Self::extract_u64(&arr[1], "dtn: SSP integer")?;
                        if ssp_int == 0 {
                            Ok(EndpointId::Null) // dtn:none encoded as [1, 0]
                        } else {
                            Err(Error::malformed_input(
                                "dtn: SSP integer must be 0 (for 'none')",
                            ))
                        }
                    }
                    Value::Text(ssp) => {
                        // RFC 9171 §4.2.5.1.1: SSP "none" SHALL be integer 0, not text
                        // Strictly reject [1, "none"] encoding
                        if ssp == "none" {
                            Err(Error::malformed_input(
                                "dtn:none MUST be encoded as [1, 0], not [1, \"none\"]",
                            ))
                        } else {
                            EndpointId::dtn(ssp)
                        }
                    }
                    _ => Err(Error::malformed_input(
                        "dtn: SSP must be text string or integer 0",
                    )),
                }
            }
            2 => {
                // ipn: scheme
                if arr.len() != 2 {
                    return Err(Error::malformed_input("ipn: EID must have 2 elements"));
                }
                let ssp_arr = arr[1]
                    .as_array()
                    .ok_or_else(|| Error::malformed_input("ipn: SSP must be array"))?;

                match ssp_arr.len() {
                    2 => {
                        // RFC 9758 §6.2: Two-element [FQNN, service]
                        // Extract: allocator = FQNN >> 32, node = FQNN & 0xFFFFFFFF
                        let fqnn = Self::extract_u64(&ssp_arr[0], "ipn FQNN")?;
                        let service = Self::extract_u64(&ssp_arr[1], "ipn service")?;
                        let allocator = fqnn >> 32;
                        let node = fqnn & 0xFFFFFFFF;
                        EndpointId::ipn(allocator, node, service)
                    }
                    3 => {
                        // RFC 9758 §6.2: Three-element [allocator, node, service]
                        let allocator = Self::extract_u64(&ssp_arr[0], "ipn allocator")?;
                        let node = Self::extract_u64(&ssp_arr[1], "ipn node")?;
                        let service = Self::extract_u64(&ssp_arr[2], "ipn service")?;
                        EndpointId::ipn(allocator, node, service)
                    }
                    _ => Err(Error::malformed_input("ipn: SSP must have 2 or 3 elements")),
                }
            }
            _ => Err(Error::malformed_input(format!(
                "Unsupported EID scheme: {}",
                scheme
            ))),
        }
    }

    #[cfg(test)]
    fn encode_eid(eid: &crate::types::EndpointId) -> Result<Value> {
        use crate::types::EndpointId;

        // EID is encoded as [scheme_code, ssp_data]
        match eid {
            EndpointId::Dtn { ssp } => {
                // dtn: scheme = 1
                Ok(Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Text(ssp.clone()),
                ]))
            }
            EndpointId::Ipn {
                allocator,
                node,
                service,
            } => {
                // ipn: scheme = 2
                // Per RFC 9758 §6.1.1: Use 2-element [FQNN, service] when allocator=0
                // Per RFC 9758 §6.1.2: Use 3-element [allocator, node, service] otherwise
                if *allocator == 0 {
                    // Two-element encoding: FQNN = (allocator << 32) | node
                    let fqnn = (*allocator << 32) | *node;
                    Ok(Value::Array(vec![
                        Value::Integer(2i64.into()),
                        Value::Array(vec![
                            Value::Integer((fqnn as i64).into()),
                            Value::Integer((*service as i64).into()),
                        ]),
                    ]))
                } else {
                    // Three-element encoding for non-default allocators
                    Ok(Value::Array(vec![
                        Value::Integer(2i64.into()),
                        Value::Array(vec![
                            Value::Integer((*allocator as i64).into()),
                            Value::Integer((*node as i64).into()),
                            Value::Integer((*service as i64).into()),
                        ]),
                    ]))
                }
            }
            EndpointId::Null => {
                // dtn:none = scheme 1, SSP "none"
                Ok(Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Text("none".to_string()),
                ]))
            }
            EndpointId::Unknown { scheme, ssp } => {
                // Unknown scheme: encoded as text
                Ok(Value::Array(vec![Value::Text(format!(
                    "{}:{}",
                    scheme, ssp
                ))]))
            }
        }
    }

    fn extract_u64(value: &Value, field: &str) -> Result<u64> {
        value
            .as_integer()
            .and_then(|i| u64::try_from(i).ok())
            .ok_or_else(|| Error::malformed_input(format!("Invalid {}: not u64", field)))
    }

    fn extract_u8(value: &Value, field: &str) -> Result<u8> {
        value
            .as_integer()
            .and_then(|i| u8::try_from(i).ok())
            .ok_or_else(|| Error::malformed_input(format!("Invalid {}: not u8", field)))
    }
}

/// Convenience function: encode bundle to wire format
pub fn encode(bundle: &Bundle) -> Result<Vec<u8>> {
    BundleCodec::encode(bundle)
}

/// Convenience function: decode bundle from wire format
pub fn decode(bytes: &[u8]) -> Result<Bundle> {
    BundleCodec::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp::bundle::BundleBuilder;
    use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

    #[test]
    fn test_encode_simple_bundle() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let dest = EndpointId::ipn(0, 2, 0).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);

        let bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(60_000)
            .payload(b"Hello".to_vec())
            .build()
            .unwrap();

        let encoded = BundleCodec::encode(&bundle).unwrap();

        // Should start with indefinite array marker
        assert_eq!(encoded[0], 0x9F);

        // Should end with break marker
        assert_eq!(encoded[encoded.len() - 1], 0xFF);

        // Should be non-empty
        assert!(encoded.len() > 10);
    }

    #[test]
    fn test_encode_eid_dtn() {
        let eid = EndpointId::dtn("example/service").unwrap();
        let encoded = BundleCodec::encode_eid(&eid).unwrap();

        // Should be array with scheme=1 and SSP
        if let Value::Array(arr) = encoded {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], Value::Integer(1i64.into()));
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_encode_eid_ipn() {
        let eid = EndpointId::ipn(0, 42, 7).unwrap();
        let encoded = BundleCodec::encode_eid(&eid).unwrap();

        // Should be array with scheme=2 and SSP array
        if let Value::Array(arr) = encoded {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], Value::Integer(2i64.into()));
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let dest = EndpointId::ipn(0, 2, 0).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 42);

        let original = BundleBuilder::new()
            .source(source.clone())
            .destination(dest.clone())
            .creation_timestamp(timestamp)
            .lifetime(60_000)
            .payload(b"Test payload".to_vec())
            .build()
            .unwrap();

        let encoded = BundleCodec::encode(&original).unwrap();
        let decoded = BundleCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.primary.version, 7);
        assert_eq!(decoded.primary.source, source);
        assert_eq!(decoded.primary.destination, dest);
        assert_eq!(decoded.primary.creation_timestamp.time.as_millis(), 1000);
        assert_eq!(decoded.primary.creation_timestamp.sequence, 42);
        assert_eq!(decoded.primary.lifetime, 60_000);
        assert_eq!(decoded.blocks.len(), 1);
        assert_eq!(decoded.blocks[0].data, b"Test payload");
    }

    #[test]
    fn test_decode_rejects_empty() {
        assert!(BundleCodec::decode(&[]).is_err());
    }

    #[test]
    fn test_decode_rejects_wrong_version() {
        // Manually craft bundle with version 6
        let mut bytes = vec![0x9F]; // Indefinite array
        // Primary block with version 6
        let primary = Value::Array(vec![
            Value::Integer(6i64.into()), // Wrong version
            Value::Integer(0i64.into()),
            Value::Integer(0i64.into()),
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]),
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(2i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]),
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]),
            Value::Array(vec![
                Value::Integer(0i64.into()),
                Value::Integer(0i64.into()),
            ]),
            Value::Integer(60000i64.into()),
        ]);
        ciborium::into_writer(&primary, &mut bytes).unwrap();
        bytes.push(0xFF); // Break

        let result = BundleCodec::decode(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_decode_rejects_oversized() {
        let huge = vec![0u8; 200 * 1024 * 1024]; // 200 MiB
        assert!(BundleCodec::decode(&huge).is_err());
    }

    #[test]
    fn test_decode_rejects_malformed_primary() {
        let mut bytes = vec![0x9F]; // Indefinite array
        // Primary block with only 2 elements (need at least 8)
        let primary = Value::Array(vec![
            Value::Integer(7i64.into()),
            Value::Integer(0i64.into()),
        ]);
        ciborium::into_writer(&primary, &mut bytes).unwrap();
        bytes.push(0xFF);

        assert!(BundleCodec::decode(&bytes).is_err());
    }

    #[test]
    fn test_primary_block_crc16_roundtrip() {
        use crate::bp::crc::CrcType;
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0,
            crc_type: CrcType::Crc16,
            destination: EndpointId::ipn(0, 2, 0).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            lifetime: 86_400_000,
            fragment_offset: None,
            total_app_data_length: None,
        };

        // Encode with CRC-16
        let encoded = BundleCodec::encode_primary(&primary).unwrap();

        // Verify CRC bytes are present and non-zero
        assert!(encoded.len() > 2);
        let crc_offset = encoded.len() - 3; // 0x42 + 2 CRC bytes
        assert_eq!(encoded[crc_offset], 0x42); // Byte string marker for 2 bytes
        // CRC bytes should not be zero (unless by extreme coincidence)
        let has_nonzero = encoded[crc_offset + 1] != 0 || encoded[crc_offset + 2] != 0;
        assert!(has_nonzero, "CRC should be computed, not left as zeros");

        // Decode should succeed
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        BundleCodec::validate_block_crc(&encoded, &parsed, true).unwrap();
        let decoded = BundleCodec::decode_primary(&parsed).unwrap();

        assert_eq!(decoded.crc_type, CrcType::Crc16);
        assert_eq!(decoded.destination, primary.destination);
    }

    #[test]
    fn test_primary_block_crc32_roundtrip() {
        use crate::bp::crc::CrcType;
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0,
            crc_type: CrcType::Crc32,
            destination: EndpointId::ipn(0, 3, 1).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            lifetime: 86_400_000,
            fragment_offset: None,
            total_app_data_length: None,
        };

        // Encode with CRC-32C
        let encoded = BundleCodec::encode_primary(&primary).unwrap();

        // Verify CRC bytes are present
        let crc_offset = encoded.len() - 5; // 0x44 + 4 CRC bytes
        assert_eq!(encoded[crc_offset], 0x44); // Byte string marker for 4 bytes

        // Decode should succeed
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        BundleCodec::validate_block_crc(&encoded, &parsed, true).unwrap();
        let decoded = BundleCodec::decode_primary(&parsed).unwrap();

        assert_eq!(decoded.crc_type, CrcType::Crc32);
    }

    #[test]
    fn test_canonical_block_crc16_roundtrip() {
        use crate::bp::blocks::{BlockType, CanonicalBlock};
        use crate::bp::crc::CrcType;

        let block = CanonicalBlock {
            block_type: BlockType::Payload,
            block_number: 1,
            block_flags: 0,
            crc_type: CrcType::Crc16,
            data: b"test payload".to_vec(),
        };

        let encoded = BundleCodec::encode_canonical(&block).unwrap();
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        BundleCodec::validate_block_crc(&encoded, &parsed, false).unwrap();
        let decoded = BundleCodec::decode_canonical(&parsed).unwrap();

        assert_eq!(decoded.crc_type, CrcType::Crc16);
        assert_eq!(decoded.data, block.data);
    }

    #[test]
    fn test_canonical_block_crc32_roundtrip() {
        use crate::bp::blocks::{BlockType, CanonicalBlock};
        use crate::bp::crc::CrcType;

        let block = CanonicalBlock {
            block_type: BlockType::Payload,
            block_number: 1,
            block_flags: 0,
            crc_type: CrcType::Crc32,
            data: b"another test payload".to_vec(),
        };

        let encoded = BundleCodec::encode_canonical(&block).unwrap();
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        BundleCodec::validate_block_crc(&encoded, &parsed, false).unwrap();
        let decoded = BundleCodec::decode_canonical(&parsed).unwrap();

        assert_eq!(decoded.crc_type, CrcType::Crc32);
        assert_eq!(decoded.data, block.data);
    }

    #[test]
    fn test_crc_corruption_rejected() {
        use crate::bp::crc::CrcType;
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0,
            crc_type: CrcType::Crc16,
            destination: EndpointId::ipn(0, 2, 0).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            lifetime: 86_400_000,
            fragment_offset: None,
            total_app_data_length: None,
        };

        let mut encoded = BundleCodec::encode_primary(&primary).unwrap();

        // Corrupt a single bit in the encoded data (not in CRC itself)
        // Flip a bit in the lifetime field (somewhere in the middle)
        let middle = encoded.len() / 2;
        encoded[middle] ^= 0x01;

        // Validation should fail
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        let result = BundleCodec::validate_block_crc(&encoded, &parsed, true);
        assert!(result.is_err(), "Corrupted data should fail CRC validation");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("CRC validation failed")
        );
    }

    #[test]
    fn test_bundle_with_crc_roundtrip() {
        use crate::bp::BundleBuilder;
        use crate::bp::crc::CrcType;

        // Build bundle with CRC-16
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 1).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(86_400_000)
            .payload(b"Hello, CRC!".to_vec())
            .crc_type(CrcType::Crc16)
            .build()
            .unwrap();

        // Encode and decode
        let encoded = BundleCodec::encode(&bundle).unwrap();
        let decoded = BundleCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.primary.crc_type, CrcType::Crc16);
        assert_eq!(decoded.primary.destination, bundle.primary.destination);
        assert_eq!(decoded.blocks.len(), 1);
        assert_eq!(decoded.blocks[0].data, b"Hello, CRC!");
    }

    #[test]
    fn test_primary_block_array_length_no_frag_no_crc() {
        use crate::bp::crc::CrcType;
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0,
            crc_type: CrcType::None,
            destination: EndpointId::ipn(0, 2, 0).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            lifetime: 86_400_000,
            fragment_offset: None,
            total_app_data_length: None,
        };

        let encoded = BundleCodec::encode_primary(&primary).unwrap();
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        let arr = parsed.as_array().unwrap();

        // RFC 9171 §4.3.1: 8 elements if not fragment and no CRC
        assert_eq!(
            arr.len(),
            8,
            "Primary block without fragment or CRC must have 8 elements"
        );
    }

    #[test]
    fn test_primary_block_array_length_no_frag_with_crc() {
        use crate::bp::crc::CrcType;
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0,
            crc_type: CrcType::Crc16,
            destination: EndpointId::ipn(0, 2, 0).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            lifetime: 86_400_000,
            fragment_offset: None,
            total_app_data_length: None,
        };

        let encoded = BundleCodec::encode_primary(&primary).unwrap();
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        let arr = parsed.as_array().unwrap();

        // RFC 9171 §4.3.1: 9 elements if CRC and not fragment
        assert_eq!(
            arr.len(),
            9,
            "Primary block with CRC but no fragment must have 9 elements"
        );
    }

    #[test]
    fn test_primary_block_array_length_frag_no_crc() {
        use crate::bp::crc::CrcType;
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0x01, // Fragment flag
            crc_type: CrcType::None,
            destination: EndpointId::ipn(0, 2, 0).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            lifetime: 86_400_000,
            fragment_offset: Some(0),
            total_app_data_length: Some(1000),
        };

        let encoded = BundleCodec::encode_primary(&primary).unwrap();
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        let arr = parsed.as_array().unwrap();

        // RFC 9171 §4.3.1: 10 elements if fragment and no CRC
        assert_eq!(
            arr.len(),
            10,
            "Primary block with fragment but no CRC must have 10 elements"
        );
    }

    #[test]
    fn test_primary_block_array_length_frag_with_crc() {
        use crate::bp::crc::CrcType;
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0x01, // Fragment flag
            crc_type: CrcType::Crc32,
            destination: EndpointId::ipn(0, 2, 0).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            lifetime: 86_400_000,
            fragment_offset: Some(0),
            total_app_data_length: Some(1000),
        };

        let encoded = BundleCodec::encode_primary(&primary).unwrap();
        let parsed: Value = ciborium::from_reader(&encoded[..]).unwrap();
        let arr = parsed.as_array().unwrap();

        // RFC 9171 §4.3.1: 11 elements if fragment and CRC
        assert_eq!(
            arr.len(),
            11,
            "Primary block with fragment and CRC must have 11 elements"
        );
    }

    #[test]
    fn test_reject_primary_crc_type_0_with_crc_element() {
        // Manually craft a bundle with CRC type 0 but a trailing CRC element (invalid)
        let mut bytes = vec![0x9F]; // Indefinite array

        // 9-element primary block with CRC type 0 and a fake CRC element
        let primary = Value::Array(vec![
            Value::Integer(7i64.into()), // version
            Value::Integer(0i64.into()), // flags
            Value::Integer(0i64.into()), // CRC type 0
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // dest
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(2i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // source
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // report-to
            Value::Array(vec![
                Value::Integer(0i64.into()),
                Value::Integer(0i64.into()),
            ]), // timestamp
            Value::Integer(60000i64.into()), // lifetime
            Value::Bytes(vec![0x90, 0x6E]), // Invalid: CRC element when type is 0
        ]);
        ciborium::into_writer(&primary, &mut bytes).unwrap();
        bytes.push(0xFF); // Break

        let result = BundleCodec::decode(&bytes);
        assert!(
            result.is_err(),
            "Should reject primary block with CRC type 0 and CRC element"
        );
    }

    #[test]
    fn test_reject_primary_nonzero_crc_type_without_crc() {
        // Manually craft a bundle with CRC type 1 but no CRC element (invalid)
        let mut bytes = vec![0x9F]; // Indefinite array

        // 8-element primary block with CRC type 1 but missing CRC element
        let primary = Value::Array(vec![
            Value::Integer(7i64.into()), // version
            Value::Integer(0i64.into()), // flags
            Value::Integer(1i64.into()), // CRC type 1 (requires CRC element)
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // dest
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(2i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // source
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // report-to
            Value::Array(vec![
                Value::Integer(0i64.into()),
                Value::Integer(0i64.into()),
            ]), // timestamp
            Value::Integer(60000i64.into()), // lifetime
                                         // Missing CRC element despite type 1
        ]);
        ciborium::into_writer(&primary, &mut bytes).unwrap();
        bytes.push(0xFF); // Break

        let result = BundleCodec::decode(&bytes);
        assert!(
            result.is_err(),
            "Should reject primary block with non-zero CRC type and no CRC element"
        );
    }

    #[test]
    fn test_public_api_bundle_encode_validates_crc() {
        use crate::bp::{BundleBuilder, BundleCodec, CrcType};
        use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

        // Create a bundle using the public API with CRC-16
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(86_400_000)
            .payload(b"Public API test".to_vec())
            .crc_type(CrcType::Crc16)
            .build()
            .unwrap();

        // Encode using public API
        let encoded = BundleCodec::encode(&bundle).unwrap();

        // Decode and verify CRC is validated
        let decoded = BundleCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.primary.crc_type, CrcType::Crc16);

        // Corrupt a byte in the middle and verify rejection
        let mut corrupted = encoded.clone();
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0xFF;

        let result = BundleCodec::decode(&corrupted);
        assert!(
            result.is_err(),
            "Corrupted bundle should fail CRC validation"
        );
    }

    #[test]
    fn test_accept_primary_crc_type_0_for_compatibility() {
        // RFC 9171 §4.3.1 says CRC type 0 MUST not be used unless BIB targets primary,
        // but this is a generation rule, not a validation rule. We accept CRC type 0
        // on decode for compatibility with RFC 9173 test vectors.
        let mut bytes = vec![0x9F]; // Indefinite array

        // 8-element primary block with CRC type 0
        let primary = Value::Array(vec![
            Value::Integer(7i64.into()), // version
            Value::Integer(0i64.into()), // flags
            Value::Integer(0i64.into()), // CRC type 0
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // dest
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(2i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // source
            Value::Array(vec![
                Value::Integer(2i64.into()),
                Value::Array(vec![
                    Value::Integer(1i64.into()),
                    Value::Integer(0i64.into()),
                ]),
            ]), // report-to
            Value::Array(vec![
                Value::Integer(0i64.into()),
                Value::Integer(0i64.into()),
            ]), // timestamp
            Value::Integer(60000i64.into()), // lifetime
        ]);
        ciborium::into_writer(&primary, &mut bytes).unwrap();

        // Add a payload block (not a BIB)
        let payload_block = Value::Array(vec![
            Value::Integer(1i64.into()),    // block type (payload)
            Value::Integer(1i64.into()),    // block number
            Value::Integer(0i64.into()),    // flags
            Value::Integer(0i64.into()),    // CRC type
            Value::Bytes(b"test".to_vec()), // data
        ]);
        ciborium::into_writer(&payload_block, &mut bytes).unwrap();

        bytes.push(0xFF); // Break

        // Should decode successfully (generation rule, not validation rule)
        let result = BundleCodec::decode(&bytes);
        assert!(result.is_ok(), "Should accept CRC type 0 for compatibility");
        assert_eq!(result.unwrap().primary.crc_type, CrcType::None);
    }
}
