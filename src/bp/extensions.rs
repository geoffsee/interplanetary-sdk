//! Built-in extension blocks per RFC 9171 §4.4

use super::blocks::{BlockType, CanonicalBlock};
use super::crc::CrcType;
use crate::types::{EndpointId, Error, Result};

/// Previous Node Block (type 6) per RFC 9171 §4.4.1
///
/// Identifies the node that forwarded this bundle to the local node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousNodeBlock {
    /// Block number
    pub block_number: u64,
    /// Block processing control flags
    pub block_flags: u64,
    /// CRC type
    pub crc_type: CrcType,
    /// Node ID of the forwarding node
    pub previous_node: EndpointId,
}

impl PreviousNodeBlock {
    /// Create a new Previous Node block
    pub fn new(block_number: u64, previous_node: EndpointId) -> Self {
        Self {
            block_number,
            block_flags: 0,
            crc_type: CrcType::None,
            previous_node,
        }
    }

    /// Encode to canonical block
    pub fn to_canonical(&self) -> Result<CanonicalBlock> {
        // Encode EID as CBOR
        let mut data = Vec::new();
        let eid_value = encode_eid(&self.previous_node)?;
        ciborium::into_writer(&eid_value, &mut data)
            .map_err(|e| Error::malformed_input(format!("Previous Node encoding: {}", e)))?;

        Ok(CanonicalBlock {
            block_type: BlockType::PreviousNode,
            block_number: self.block_number,
            block_flags: self.block_flags,
            crc_type: self.crc_type,
            data,
        })
    }

    /// Decode from canonical block
    pub fn from_canonical(block: &CanonicalBlock) -> Result<Self> {
        if block.block_type != BlockType::PreviousNode {
            return Err(Error::malformed_input("Not a Previous Node block"));
        }

        let eid_value: ciborium::Value = ciborium::from_reader(&block.data[..])
            .map_err(|e| Error::malformed_input(format!("Previous Node decode: {}", e)))?;
        let previous_node = decode_eid(&eid_value)?;

        Ok(Self {
            block_number: block.block_number,
            block_flags: block.block_flags,
            crc_type: block.crc_type,
            previous_node,
        })
    }
}

/// Bundle Age Block (type 7) per RFC 9171 §4.4.2
///
/// Contains milliseconds elapsed between creation and most recent forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleAgeBlock {
    /// Block number
    pub block_number: u64,
    /// Block processing control flags
    pub block_flags: u64,
    /// CRC type
    pub crc_type: CrcType,
    /// Age in milliseconds
    pub age_ms: u64,
}

impl BundleAgeBlock {
    /// Create a new Bundle Age block
    pub fn new(block_number: u64, age_ms: u64) -> Self {
        Self {
            block_number,
            block_flags: 0,
            crc_type: CrcType::None,
            age_ms,
        }
    }

    /// Encode to canonical block
    pub fn to_canonical(&self) -> Result<CanonicalBlock> {
        let mut data = Vec::new();
        ciborium::into_writer(&ciborium::Value::Integer(self.age_ms.into()), &mut data)
            .map_err(|e| Error::malformed_input(format!("Bundle Age encoding: {}", e)))?;

        Ok(CanonicalBlock {
            block_type: BlockType::BundleAge,
            block_number: self.block_number,
            block_flags: self.block_flags,
            crc_type: self.crc_type,
            data,
        })
    }

    /// Decode from canonical block
    pub fn from_canonical(block: &CanonicalBlock) -> Result<Self> {
        if block.block_type != BlockType::BundleAge {
            return Err(Error::malformed_input("Not a Bundle Age block"));
        }

        let value: ciborium::Value = ciborium::from_reader(&block.data[..])
            .map_err(|e| Error::malformed_input(format!("Bundle Age decode: {}", e)))?;

        let age_ms = value
            .as_integer()
            .and_then(|i| i.try_into().ok())
            .ok_or_else(|| Error::malformed_input("Bundle Age must be unsigned integer"))?;

        Ok(Self {
            block_number: block.block_number,
            block_flags: block.block_flags,
            crc_type: block.crc_type,
            age_ms,
        })
    }
}

/// Hop Count Block (type 10) per RFC 9171 §4.4.3
///
/// Contains hop limit and hop count to prevent forwarding loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopCountBlock {
    /// Block number
    pub block_number: u64,
    /// Block processing control flags
    pub block_flags: u64,
    /// CRC type
    pub crc_type: CrcType,
    /// Maximum hops allowed (1-255)
    pub hop_limit: u8,
    /// Current hop count
    pub hop_count: u64,
}

impl HopCountBlock {
    /// Create a new Hop Count block
    ///
    /// hop_limit must be in range 1-255 per RFC 9171 §4.4.3
    pub fn new(block_number: u64, hop_limit: u8, hop_count: u64) -> Result<Self> {
        if hop_limit == 0 {
            return Err(Error::invalid_config("Hop limit must be at least 1"));
        }

        Ok(Self {
            block_number,
            block_flags: 0,
            crc_type: CrcType::None,
            hop_limit,
            hop_count,
        })
    }

    /// Check if hop limit has been exceeded
    ///
    /// RFC 9171 §4.4.3: "When a bundle's hop count exceeds its hop limit"
    /// "exceeds" means strictly greater than (>), not greater than or equal
    pub fn is_exceeded(&self) -> bool {
        self.hop_count > self.hop_limit as u64
    }

    /// Increment hop count (called on forward)
    pub fn increment(&mut self) {
        self.hop_count = self.hop_count.saturating_add(1);
    }

    /// Encode to canonical block
    pub fn to_canonical(&self) -> Result<CanonicalBlock> {
        let mut data = Vec::new();
        let hop_array = ciborium::Value::Array(vec![
            ciborium::Value::Integer((self.hop_limit as u64).into()),
            ciborium::Value::Integer(self.hop_count.into()),
        ]);
        ciborium::into_writer(&hop_array, &mut data)
            .map_err(|e| Error::malformed_input(format!("Hop Count encoding: {}", e)))?;

        Ok(CanonicalBlock {
            block_type: BlockType::HopCount,
            block_number: self.block_number,
            block_flags: self.block_flags,
            crc_type: self.crc_type,
            data,
        })
    }

    /// Decode from canonical block
    pub fn from_canonical(block: &CanonicalBlock) -> Result<Self> {
        if block.block_type != BlockType::HopCount {
            return Err(Error::malformed_input("Not a Hop Count block"));
        }

        let value: ciborium::Value = ciborium::from_reader(&block.data[..])
            .map_err(|e| Error::malformed_input(format!("Hop Count decode: {}", e)))?;

        let arr = value
            .as_array()
            .ok_or_else(|| Error::malformed_input("Hop Count data must be array"))?;

        if arr.len() != 2 {
            return Err(Error::malformed_input(
                "Hop Count array must have 2 elements",
            ));
        }

        let hop_limit = arr[0]
            .as_integer()
            .and_then(|i| i.try_into().ok())
            .and_then(|n: u64| u8::try_from(n).ok())
            .ok_or_else(|| Error::malformed_input("Hop limit must be u8"))?;

        let hop_count = arr[1]
            .as_integer()
            .and_then(|i| i.try_into().ok())
            .ok_or_else(|| Error::malformed_input("Hop count must be unsigned integer"))?;

        if hop_limit == 0 {
            return Err(Error::malformed_input("Hop limit must be at least 1"));
        }

        Ok(Self {
            block_number: block.block_number,
            block_flags: block.block_flags,
            crc_type: block.crc_type,
            hop_limit,
            hop_count,
        })
    }
}

// Helper functions for EID encoding/decoding (matching codec.rs implementation)

fn encode_eid(eid: &EndpointId) -> Result<ciborium::Value> {
    use ciborium::Value;

    match eid {
        EndpointId::Ipn {
            allocator,
            node,
            service,
        } => {
            if *allocator == 0 {
                // Two-element encoding: FQNN = (allocator << 32) | node
                let fqnn = (*allocator << 32) | *node;
                Ok(Value::Array(vec![
                    Value::Integer(2i64.into()),
                    Value::Array(vec![
                        Value::Integer(fqnn.into()),
                        Value::Integer((*service).into()),
                    ]),
                ]))
            } else {
                // Three-element encoding for non-default allocators
                Ok(Value::Array(vec![
                    Value::Integer(2i64.into()),
                    Value::Array(vec![
                        Value::Integer((*allocator).into()),
                        Value::Integer((*node).into()),
                        Value::Integer((*service).into()),
                    ]),
                ]))
            }
        }
        EndpointId::Dtn { ssp } => Ok(Value::Array(vec![
            Value::Integer(1i64.into()),
            Value::Text(ssp.clone()),
        ])),
        EndpointId::Null => Ok(Value::Array(vec![
            Value::Integer(1i64.into()), // dtn scheme
            Value::Integer(0i64.into()), // SSP = 0 for "none"
        ])),
        EndpointId::Unknown { .. } => Err(Error::unsupported("Cannot encode unknown EID")),
    }
}

fn decode_eid(value: &ciborium::Value) -> Result<EndpointId> {
    let arr = value
        .as_array()
        .ok_or_else(|| Error::malformed_input("EID must be array"))?;

    if arr.is_empty() {
        return Err(Error::malformed_input("EID array must not be empty"));
    }

    let scheme = arr[0]
        .as_integer()
        .and_then(|i| i.try_into().ok())
        .ok_or_else(|| Error::malformed_input("EID scheme must be integer"))?;

    match scheme {
        0 => Ok(EndpointId::Null),
        1 => {
            // dtn: scheme
            if arr.len() != 2 {
                return Err(Error::malformed_input("dtn: EID must have 2 elements"));
            }
            // RFC 9171 §4.2.5.1.1: dtn:none is [1, 0], others are [1, text]
            if let Some(ssp_int) = arr[1].as_integer() {
                let val: i64 = ssp_int
                    .try_into()
                    .map_err(|_| Error::malformed_input("dtn: SSP integer out of range"))?;
                if val == 0 {
                    return Ok(EndpointId::Null); // dtn:none
                } else {
                    return Err(Error::malformed_input(
                        "dtn: SSP integer must be 0 (for 'none')",
                    ));
                }
            }
            let ssp = arr[1]
                .as_text()
                .ok_or_else(|| Error::malformed_input("dtn: SSP must be text or 0"))?;
            Ok(EndpointId::Dtn {
                ssp: ssp.to_string(),
            })
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
                    // Two-element: [FQNN, service]
                    let fqnn: u64 = ssp_arr[0]
                        .as_integer()
                        .and_then(|i| i.try_into().ok())
                        .ok_or_else(|| Error::malformed_input("ipn FQNN must be u64"))?;
                    let service: u64 = ssp_arr[1]
                        .as_integer()
                        .and_then(|i| i.try_into().ok())
                        .ok_or_else(|| Error::malformed_input("ipn service must be u64"))?;
                    let allocator = fqnn >> 32;
                    let node = fqnn & 0xFFFFFFFF;
                    EndpointId::ipn(allocator, node, service)
                }
                3 => {
                    // Three-element: [allocator, node, service]
                    let allocator: u64 = ssp_arr[0]
                        .as_integer()
                        .and_then(|i| i.try_into().ok())
                        .ok_or_else(|| Error::malformed_input("ipn allocator must be u64"))?;
                    let node: u64 = ssp_arr[1]
                        .as_integer()
                        .and_then(|i| i.try_into().ok())
                        .ok_or_else(|| Error::malformed_input("ipn node must be u64"))?;
                    let service: u64 = ssp_arr[2]
                        .as_integer()
                        .and_then(|i| i.try_into().ok())
                        .ok_or_else(|| Error::malformed_input("ipn service must be u64"))?;
                    EndpointId::ipn(allocator, node, service)
                }
                _ => Err(Error::malformed_input("ipn: SSP must have 2 or 3 elements")),
            }
        }
        _ => Err(Error::malformed_input(format!(
            "Unknown EID scheme: {}",
            scheme
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_previous_node_roundtrip() {
        let eid = EndpointId::ipn(0, 5, 0).unwrap();
        let block = PreviousNodeBlock::new(2, eid.clone());
        let canonical = block.to_canonical().unwrap();
        let decoded = PreviousNodeBlock::from_canonical(&canonical).unwrap();

        assert_eq!(decoded.previous_node, eid);
        assert_eq!(decoded.block_number, 2);
    }

    #[test]
    fn test_bundle_age_roundtrip() {
        let block = BundleAgeBlock::new(3, 12345);
        let canonical = block.to_canonical().unwrap();
        let decoded = BundleAgeBlock::from_canonical(&canonical).unwrap();

        assert_eq!(decoded.age_ms, 12345);
        assert_eq!(decoded.block_number, 3);
    }

    #[test]
    fn test_hop_count_roundtrip() {
        let block = HopCountBlock::new(4, 10, 3).unwrap();
        let canonical = block.to_canonical().unwrap();
        let decoded = HopCountBlock::from_canonical(&canonical).unwrap();

        assert_eq!(decoded.hop_limit, 10);
        assert_eq!(decoded.hop_count, 3);
        assert_eq!(decoded.block_number, 4);
        assert!(!decoded.is_exceeded());
    }

    #[test]
    fn test_hop_count_exceeded() {
        // RFC 9171 §4.4.3: "exceeds" means hop_count > hop_limit
        let mut block = HopCountBlock::new(4, 5, 6).unwrap();
        assert!(block.is_exceeded()); // 6 > 5

        block.hop_count = 5;
        assert!(!block.is_exceeded()); // 5 == 5, not exceeded

        block.hop_count = 4;
        assert!(!block.is_exceeded()); // 4 < 5

        block.increment(); // now 5
        assert!(!block.is_exceeded()); // 5 == 5, still not exceeded

        block.increment(); // now 6
        assert!(block.is_exceeded()); // 6 > 5, exceeded
    }

    #[test]
    fn test_hop_count_zero_limit_rejected() {
        let result = HopCountBlock::new(4, 0, 0);
        assert!(result.is_err());
    }
}
