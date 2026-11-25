//! Canonical form construction per RFC 9173 §3

use ciborium::{Value, value::Integer};
use interplanetary_bp::Bundle;
use interplanetary_types::Result;

/// Security target for BPSec operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Used by compute_hmac/verify_hmac which are conditionally compiled for tests
#[allow(dead_code)]
pub enum SecurityTarget {
    /// Primary block
    PrimaryBlock,
    /// Canonical block by number
    Block(u64),
}

/// Canonicalize bundle data for BPSec per RFC 9173 §3.8
///
/// Returns CBOR-encoded byte array of:
/// - Bundle CRC type (from primary block)
/// - For primary: primary block contents
/// - For extension block: [block type, block number, block flags, block data]
// Used by compute_hmac/verify_hmac in test/fixture contexts
#[allow(dead_code)]
pub fn canonicalize_for_bpsec(bundle: &Bundle, target: SecurityTarget) -> Result<Vec<u8>> {
    let mut output = Vec::new();

    match target {
        SecurityTarget::PrimaryBlock => {
            let crc_type = bundle.primary.crc_type as u64;

            let elements = vec![
                Value::Integer(Integer::from(bundle.primary.version)),
                Value::Integer(Integer::from(bundle.primary.bundle_flags)),
                Value::Integer(Integer::from(crc_type)),
                // Would encode full EIDs here, simplified for now
            ];

            ciborium::into_writer(&Value::Array(elements), &mut output).map_err(|e| {
                interplanetary_types::Error::malformed_input(format!(
                    "Canonicalization failed: {}",
                    e
                ))
            })?;
        }
        SecurityTarget::Block(block_num) => {
            let block = bundle
                .blocks
                .iter()
                .find(|b| b.block_number == block_num)
                .ok_or_else(|| interplanetary_types::Error::not_found("Target block not found"))?;

            let elements = vec![
                Value::Integer(Integer::from(block.block_type.to_u64())),
                Value::Integer(Integer::from(block.block_number)),
                Value::Integer(Integer::from(block.block_flags)),
                Value::Bytes(block.data.clone()),
            ];

            ciborium::into_writer(&Value::Array(elements), &mut output).map_err(|e| {
                interplanetary_types::Error::malformed_input(format!(
                    "Canonicalization failed: {}",
                    e
                ))
            })?;
        }
    }

    Ok(output)
}
