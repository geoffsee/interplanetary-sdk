//! Bundle block structures per RFC 9171 §4

use super::crc::CrcType;
use crate::types::{CreationTimestamp, EndpointId};

/// Block type codes per IANA Bundle Block Types registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum BlockType {
    /// Payload block (type 1)
    Payload = 1,
    /// Previous node (type 6)
    PreviousNode = 6,
    /// Bundle age (type 7)
    BundleAge = 7,
    /// Hop count (type 10)
    HopCount = 10,
    /// Block Integrity Block (type 11, BPSec)
    Bib = 11,
    /// Block Confidentiality Block (type 12, BPSec)
    Bcb = 12,
    /// Unknown/extension block
    Unknown(u64),
}

impl BlockType {
    /// Create from wire value
    pub fn from_u64(value: u64) -> Self {
        match value {
            1 => Self::Payload,
            6 => Self::PreviousNode,
            7 => Self::BundleAge,
            10 => Self::HopCount,
            11 => Self::Bib,
            12 => Self::Bcb,
            other => Self::Unknown(other),
        }
    }

    /// Convert to wire value
    pub fn to_u64(&self) -> u64 {
        match self {
            Self::Payload => 1,
            Self::PreviousNode => 6,
            Self::BundleAge => 7,
            Self::HopCount => 10,
            Self::Bib => 11,
            Self::Bcb => 12,
            Self::Unknown(val) => *val,
        }
    }

    /// Check if this is the payload block
    pub fn is_payload(&self) -> bool {
        matches!(self, Self::Payload)
    }

    /// Check if this is the bundle age block
    pub fn is_bundle_age(&self) -> bool {
        matches!(self, Self::BundleAge)
    }
}

/// Block processing control flags (RFC 9171 §4.2.4)
#[derive(Debug, Clone, Copy)]
pub struct BlockFlags(pub u64);

impl BlockFlags {
    /// Block must be replicated in every fragment
    pub const REPLICATE_IN_FRAGMENTS: u64 = 0x01;

    /// Report if block can't be processed
    pub const REPORT_ON_FAILURE: u64 = 0x02;

    /// Delete bundle if block can't be processed
    pub const DELETE_BUNDLE_ON_FAILURE: u64 = 0x04;

    /// Discard block if it can't be processed
    pub const DISCARD_BLOCK_ON_FAILURE: u64 = 0x10;

    /// Check if flag is set
    pub fn has(&self, flag: u64) -> bool {
        (self.0 & flag) != 0
    }

    /// Must delete bundle if block can't be processed?
    pub fn must_delete_bundle(&self) -> bool {
        self.has(Self::DELETE_BUNDLE_ON_FAILURE)
    }

    /// Should replicate in fragments?
    pub fn replicate_in_fragments(&self) -> bool {
        self.has(Self::REPLICATE_IN_FRAGMENTS)
    }
}

/// Primary bundle block (RFC 9171 §4.3.1)
///
/// The primary block is mandatory and must be first in the bundle.
/// It contains routing and identification information.
#[derive(Debug, Clone)]
pub struct PrimaryBlock {
    /// Bundle Protocol version (must be 7)
    pub version: u8,

    /// Bundle processing control flags
    pub bundle_flags: u64,

    /// CRC type for primary block
    pub crc_type: CrcType,

    /// Destination endpoint ID
    pub destination: EndpointId,

    /// Source endpoint ID
    pub source: EndpointId,

    /// Report-to endpoint ID
    pub report_to: EndpointId,

    /// Creation timestamp
    pub creation_timestamp: CreationTimestamp,

    /// Lifetime in milliseconds
    pub lifetime: u64,

    /// Fragment offset (if fragmented)
    pub fragment_offset: Option<u64>,

    /// Total application data length (if fragmented)
    pub total_app_data_length: Option<u64>,
}

impl PrimaryBlock {
    /// Check if bundle is a fragment
    pub fn is_fragment(&self) -> bool {
        self.fragment_offset.is_some()
    }

    /// Check if bundle has the "must not be fragmented" flag set (RFC 9171 §4.2.3 bit 2)
    pub fn must_not_fragment(&self) -> bool {
        (self.bundle_flags & 0x000004) != 0
    }

    /// Compute expiry time (creation time + lifetime)
    ///
    /// Returns None if creation time is unknown (0)
    pub fn expiry_time(&self) -> Option<crate::types::DtnTimeMs> {
        if self.creation_timestamp.is_unknown_clock() {
            None
        } else {
            self.creation_timestamp
                .time
                .checked_add_millis(self.lifetime)
        }
    }
}

/// Canonical block format (RFC 9171 §4.3.2)
///
/// Extension blocks, payload block, and security blocks use this format.
#[derive(Debug, Clone)]
pub struct CanonicalBlock {
    /// Block type code
    pub block_type: BlockType,

    /// Block number (unique within bundle)
    pub block_number: u64,

    /// Block processing control flags
    pub block_flags: u64,

    /// CRC type for this block
    pub crc_type: CrcType,

    /// Block-type-specific data
    pub data: Vec<u8>,
}

/// Convenience type alias
pub type Block = CanonicalBlock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_type_roundtrip() {
        assert_eq!(BlockType::from_u64(1), BlockType::Payload);
        assert_eq!(BlockType::Payload.to_u64(), 1);

        let unknown = BlockType::from_u64(99);
        assert_eq!(unknown.to_u64(), 99);
    }

    #[test]
    fn test_block_flags() {
        let flags = BlockFlags(BlockFlags::DELETE_BUNDLE_ON_FAILURE);
        assert!(flags.must_delete_bundle());
        assert!(!flags.replicate_in_fragments());

        let flags2 = BlockFlags(BlockFlags::REPLICATE_IN_FRAGMENTS | BlockFlags::REPORT_ON_FAILURE);
        assert!(flags2.replicate_in_fragments());
        assert!(!flags2.must_delete_bundle());
    }

    #[test]
    fn test_primary_block_expiry() {
        use crate::types::{CreationTimestamp, DtnTimeMs};

        let mut primary = PrimaryBlock {
            version: 7,
            bundle_flags: 0,
            crc_type: CrcType::None,
            destination: EndpointId::ipn(0, 2, 0).unwrap(),
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            report_to: EndpointId::ipn(0, 1, 0).unwrap(),
            creation_timestamp: CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0),
            lifetime: 60_000,
            fragment_offset: None,
            total_app_data_length: None,
        };

        let expiry = primary.expiry_time().unwrap();
        assert_eq!(expiry.as_millis(), 61_000);

        // Unknown clock
        primary.creation_timestamp.time = DtnTimeMs::UNKNOWN;
        assert!(primary.expiry_time().is_none());
    }
}
