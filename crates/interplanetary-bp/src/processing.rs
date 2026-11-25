//! Bundle processing per RFC 9171 §5

use super::Bundle;
use super::blocks::BlockType;
use super::crc::CrcType;
use super::extensions::{BundleAgeBlock, HopCountBlock, PreviousNodeBlock};
use interplanetary_types::{EndpointId, Error, Result, SimDuration};

/// Status report reason codes per RFC 9171 §6.1.1 Table 1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeletionReason {
    /// No additional information
    NoInformation = 0,
    /// Lifetime expired
    LifetimeExpired = 1,
    /// Forwarded over unidirectional link
    ForwardedOverUnidirectionalLink = 2,
    /// Transmission canceled
    TransmissionCanceled = 3,
    /// Depleted storage
    DepletedStorage = 4,
    /// Destination endpoint ID unavailable
    DestinationEidUnavailable = 5,
    /// No known route to destination
    NoKnownRoute = 6,
    /// No timely contact with next node
    NoTimelyContact = 7,
    /// Block unintelligible
    BlockUnintelligible = 8,
    /// Hop limit exceeded (RFC 9171 §4.4.3)
    HopLimitExceeded = 9,
    /// Traffic pared
    TrafficPared = 10,
    /// Block unsupported
    BlockUnsupported = 11,
}

impl DeletionReason {
    /// Convert to wire value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Bundle reception result per RFC 9171 §5.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceptionResult {
    /// Bundle accepted and should continue processing
    Accepted,
    /// Bundle must be deleted with given reason
    DeleteBundle(DeletionReason),
    /// Generate status report with this reason  
    ReportFailure(DeletionReason),
}

/// Process bundle on reception per RFC 9171 §5.6
///
/// Processes block control flags for unknown/unsupported blocks.
/// Returns Ok(ReceptionResult) indicating how to proceed.
///
/// Per RFC 9171 §5.6:
/// - Step 1: Add "Dispatch pending" retention constraint (handled by caller)
/// - Step 2: Generate reception status report if requested (handled by caller)
/// - Step 3: Verify CRCs (handled during decode in codec.rs)
/// - Step 4: Process block control flags for unknown/unsupported blocks
///
/// Note: CRC verification per §5.6 Step 3 is performed during bundle decode
/// in codec.rs. If CRC verification fails, the bundle is rejected with reason
/// "Block unintelligible" before reaching this function.
pub fn process_on_reception(bundle: &mut Bundle) -> Result<ReceptionResult> {
    use super::blocks::BlockFlags;

    // Step 4: Process block control flags per RFC 9171 §5.6
    // Check for unsupported critical blocks
    let mut blocks_to_remove = Vec::new();

    for (idx, block) in bundle.blocks.iter().enumerate() {
        let flags = BlockFlags(block.block_flags);

        // Check if this is an unknown or unsupported block type
        let is_unsupported = matches!(block.block_type, BlockType::Unknown(_));

        if is_unsupported {
            // RFC 9171 §5.6: Handle block processing control flags

            // Bit 2 (0x04): Delete bundle if block can't be processed
            if flags.must_delete_bundle() {
                // RFC 9171 §5.6: "If the 'Delete bundle if block can't be processed'
                // flag (bit 2) is 1 in the block's block processing control flags,
                // then the BPA MUST delete the bundle for the reason 'Block unsupported'"
                return Ok(ReceptionResult::DeleteBundle(
                    DeletionReason::BlockUnsupported,
                ));
            }

            // Bit 1 (0x02): Report if block can't be processed
            if flags.has(BlockFlags::REPORT_ON_FAILURE) {
                // RFC 9171 §5.6: "If the 'Report if block can't be processed' flag (bit 1)
                // is 1 in the block's block processing control flags, then a bundle status
                // report with reason code 'Block unsupported' SHOULD be generated"
                return Ok(ReceptionResult::ReportFailure(
                    DeletionReason::BlockUnsupported,
                ));
            }

            // Bit 4 (0x10): Discard block if can't be processed
            if flags.has(BlockFlags::DISCARD_BLOCK_ON_FAILURE) {
                // RFC 9171 §5.6: "If the 'Discard block if it can't be processed' flag
                // (bit 4) is 1 in the block's block processing control flags, then the
                // BPA MUST remove this block from the bundle"
                blocks_to_remove.push(idx);
            }
        }
    }

    // Remove blocks that should be discarded (in reverse order to preserve indices)
    for idx in blocks_to_remove.into_iter().rev() {
        bundle.blocks.remove(idx);
    }

    Ok(ReceptionResult::Accepted)
}

/// Process bundle on forward per RFC 9171 §5.4
///
/// Updates Hop Count, Previous Node, and Bundle Age extension blocks.
/// Returns error if hop limit exceeded (bundle should be deleted).
pub fn process_on_forward(
    bundle: &mut Bundle,
    forwarding_node_eid: &EndpointId,
    residence_time: SimDuration,
) -> Result<()> {
    // RFC 9171 §4.4.3: Increment hop count and check limit
    if let Some(hop_block_idx) = find_hop_count_block(bundle) {
        let mut hop_block = HopCountBlock::from_canonical(&bundle.blocks[hop_block_idx])?;

        hop_block.increment();

        // Check if hop limit exceeded
        if hop_block.is_exceeded() {
            return Err(Error::protocol_violation(format!(
                "Hop limit exceeded: {} >= {}",
                hop_block.hop_count, hop_block.hop_limit
            )));
        }

        // Update the block in the bundle
        bundle.blocks[hop_block_idx] = hop_block.to_canonical()?;
    }

    // RFC 9171 §4.4.1: Insert or replace Previous Node block
    // "If the local node is the source of the bundle, then the bundle MUST NOT
    // contain any Previous Node Block. Otherwise, the bundle SHOULD contain one (1)
    // occurrence of this type of block"
    if bundle.primary.source != *forwarding_node_eid {
        let prev_node_block =
            PreviousNodeBlock::new(find_next_block_number(bundle), forwarding_node_eid.clone());

        // Remove existing Previous Node blocks (should be at most one per RFC)
        bundle
            .blocks
            .retain(|b| b.block_type != BlockType::PreviousNode);

        // Insert new Previous Node block
        bundle.blocks.insert(0, prev_node_block.to_canonical()?);
    }

    // RFC 9171 §4.4.2: Update Bundle Age by residence time
    if let Some(age_block_idx) = find_bundle_age_block(bundle) {
        let mut age_block = BundleAgeBlock::from_canonical(&bundle.blocks[age_block_idx])?;
        age_block.age_ms = age_block.age_ms.saturating_add(residence_time.as_millis());
        bundle.blocks[age_block_idx] = age_block.to_canonical()?;
    }

    Ok(())
}

/// Validate bundle at generation per RFC 9171 §5.2
pub fn validate_at_generation(bundle: &Bundle) -> Result<()> {
    // RFC 9171 §4.4.2: "If the bundle's creation time is zero, then the bundle
    // MUST contain exactly one (1) occurrence of this type of block"
    if bundle.primary.creation_timestamp.time.as_millis() == 0 {
        let age_blocks: Vec<_> = bundle
            .blocks
            .iter()
            .filter(|b| b.block_type == BlockType::BundleAge)
            .collect();

        if age_blocks.is_empty() {
            return Err(Error::protocol_violation(
                "Bundle Age block required when creation time is 0",
            ));
        }
        if age_blocks.len() > 1 {
            return Err(Error::protocol_violation(
                "Bundle must not contain multiple Bundle Age blocks",
            ));
        }
    }

    // RFC 9171 §4.3.1: "The CRC type code for the primary block MAY be zero if
    // the bundle contains a BPSec Block Integrity Block [BPSEC] whose target is
    // the primary block; otherwise, the CRC type code for the primary block MUST
    // be non-zero."
    if bundle.primary.crc_type == CrcType::None {
        let has_bib_targeting_primary = bundle
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::Bib && bib_targets_primary(&b.data));

        if !has_bib_targeting_primary {
            return Err(Error::protocol_violation(
                "Primary block CRC type must be non-zero unless BIB targets primary block",
            ));
        }
    }

    Ok(())
}

/// Find Hop Count block index
fn find_hop_count_block(bundle: &Bundle) -> Option<usize> {
    bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::HopCount)
}

/// Find Bundle Age block index
fn find_bundle_age_block(bundle: &Bundle) -> Option<usize> {
    bundle
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::BundleAge)
}

/// Find next available block number
fn find_next_block_number(bundle: &Bundle) -> u64 {
    bundle
        .blocks
        .iter()
        .map(|b| b.block_number)
        .max()
        .map(|n| n + 1)
        .unwrap_or(2) // Block 1 is typically payload
}

/// Check if BIB targets primary block (block number 0).
///
/// BIB block-type-specific data is a CBOR *sequence* whose first value is the
/// targets array (RFC 9172 ASB), not a single outer array.
/// Report whether a BIB's target list includes the primary block.
pub fn bib_targets_primary(bib_data: &[u8]) -> bool {
    if let Ok(ciborium::Value::Array(targets)) =
        ciborium::from_reader::<ciborium::Value, _>(bib_data)
    {
        return targets.iter().any(|t| {
            if let ciborium::Value::Integer(n) = t
                && let Ok(num) = TryInto::<u64>::try_into(*n)
            {
                return num == 0;
            }
            false
        });
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::{BlockFlags, CanonicalBlock};
    use crate::{BundleAgeBlock, BundleBuilder, HopCountBlock, PreviousNodeBlock};
    use interplanetary_types::{CreationTimestamp, DtnTimeMs, SimDuration};

    #[test]
    fn test_hop_count_increment_and_check() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        // Add hop count block with limit 2
        let hop_block = HopCountBlock::new(2, 2, 0).unwrap();
        bundle.blocks.push(hop_block.to_canonical().unwrap());

        let forwarder = EndpointId::ipn(0, 2, 0).unwrap();

        // First forward should succeed
        assert!(process_on_forward(&mut bundle, &forwarder, SimDuration::ZERO).is_ok());

        // Check hop count was incremented
        let hop_block = HopCountBlock::from_canonical(bundle.blocks.last().unwrap()).unwrap();
        assert_eq!(hop_block.hop_count, 1);

        // Second forward should succeed (count = 2, limit = 2, equals but not exceeded)
        assert!(process_on_forward(&mut bundle, &forwarder, SimDuration::ZERO).is_ok());
        let hop_block = HopCountBlock::from_canonical(bundle.blocks.last().unwrap()).unwrap();
        assert_eq!(hop_block.hop_count, 2);
        assert!(!hop_block.is_exceeded()); // 2 == 2, not exceeded

        // Third forward should fail (count = 3, exceeds limit of 2)
        let result = process_on_forward(&mut bundle, &forwarder, SimDuration::ZERO);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Hop limit exceeded")
        );
    }

    #[test]
    fn test_previous_node_inserted() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        let forwarder = EndpointId::ipn(0, 2, 0).unwrap();

        process_on_forward(&mut bundle, &forwarder, SimDuration::ZERO).unwrap();

        // Check Previous Node block was added
        let prev_node_blocks: Vec<_> = bundle
            .blocks
            .iter()
            .filter(|b| b.block_type == BlockType::PreviousNode)
            .collect();

        assert_eq!(prev_node_blocks.len(), 1);

        let prev_block = PreviousNodeBlock::from_canonical(prev_node_blocks[0]).unwrap();
        assert_eq!(prev_block.previous_node, forwarder);
    }

    #[test]
    fn test_previous_node_not_at_source() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let mut bundle = BundleBuilder::new()
            .source(source.clone())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        // Forward from source node (should NOT add Previous Node)
        process_on_forward(&mut bundle, &source, SimDuration::ZERO).unwrap();

        let prev_node_blocks: Vec<_> = bundle
            .blocks
            .iter()
            .filter(|b| b.block_type == BlockType::PreviousNode)
            .collect();

        assert_eq!(prev_node_blocks.len(), 0);
    }

    #[test]
    fn test_bundle_age_updated() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        // Add Bundle Age block
        let age_block = BundleAgeBlock::new(2, 100);
        bundle.blocks.push(age_block.to_canonical().unwrap());

        let forwarder = EndpointId::ipn(0, 2, 0).unwrap();
        let residence = SimDuration::from_millis(50);

        process_on_forward(&mut bundle, &forwarder, residence).unwrap();

        // Check age was incremented
        let age_block = BundleAgeBlock::from_canonical(
            bundle
                .blocks
                .iter()
                .find(|b| b.block_type == BlockType::BundleAge)
                .unwrap(),
        )
        .unwrap();

        assert_eq!(age_block.age_ms, 150);
    }

    #[test]
    fn test_bundle_age_required_when_creation_time_zero() {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        // Should fail: creation time is 0 but no Bundle Age block
        let result = validate_at_generation(&bundle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Bundle Age"));
    }

    #[test]
    fn test_primary_crc_type_zero_rejected_without_bib() {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 3, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .crc_type(CrcType::None)
            .build()
            .unwrap();

        // Should fail: CRC type 0 without BIB
        let result = validate_at_generation(&bundle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CRC type"));
    }

    #[test]
    fn test_reception_accepts_valid_bundle() {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        let mut bundle = bundle;
        let result = process_on_reception(&mut bundle).unwrap();
        assert_eq!(result, ReceptionResult::Accepted);
    }

    #[test]
    fn test_reception_deletes_on_unsupported_critical_block() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        // Add unsupported block with "delete bundle" flag (bit 2)
        let unsupported_block = CanonicalBlock {
            block_type: BlockType::Unknown(999),
            block_number: 10,
            block_flags: BlockFlags::DELETE_BUNDLE_ON_FAILURE,
            crc_type: CrcType::None,
            data: vec![1, 2, 3],
        };
        bundle.blocks.push(unsupported_block);

        let result = process_on_reception(&mut bundle).unwrap();
        assert_eq!(
            result,
            ReceptionResult::DeleteBundle(DeletionReason::BlockUnsupported)
        );
    }

    #[test]
    fn test_reception_reports_on_unsupported_reportable_block() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        // Add unsupported block with "report on failure" flag (bit 1)
        let unsupported_block = CanonicalBlock {
            block_type: BlockType::Unknown(999),
            block_number: 10,
            block_flags: BlockFlags::REPORT_ON_FAILURE,
            crc_type: CrcType::None,
            data: vec![1, 2, 3],
        };
        bundle.blocks.push(unsupported_block);

        let result = process_on_reception(&mut bundle).unwrap();
        assert_eq!(
            result,
            ReceptionResult::ReportFailure(DeletionReason::BlockUnsupported)
        );
    }

    #[test]
    fn test_reception_discards_unsupported_discardable_block() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        let initial_block_count = bundle.blocks.len();

        // Add unsupported block with "discard block" flag (bit 4)
        let unsupported_block = CanonicalBlock {
            block_type: BlockType::Unknown(999),
            block_number: 10,
            block_flags: BlockFlags::DISCARD_BLOCK_ON_FAILURE,
            crc_type: CrcType::None,
            data: vec![1, 2, 3],
        };
        bundle.blocks.push(unsupported_block);

        let result = process_on_reception(&mut bundle).unwrap();
        assert_eq!(result, ReceptionResult::Accepted);

        // Block should have been removed
        assert_eq!(bundle.blocks.len(), initial_block_count);

        // Verify the unsupported block was actually removed
        assert!(
            !bundle
                .blocks
                .iter()
                .any(|b| matches!(b.block_type, BlockType::Unknown(999)))
        );
    }

    #[test]
    fn test_reception_flag_priority_delete_over_report() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        // Add unsupported block with both "delete bundle" and "report" flags
        // Delete should take priority per RFC 9171 §5.6 step order
        let unsupported_block = CanonicalBlock {
            block_type: BlockType::Unknown(999),
            block_number: 10,
            block_flags: BlockFlags::DELETE_BUNDLE_ON_FAILURE | BlockFlags::REPORT_ON_FAILURE,
            crc_type: CrcType::None,
            data: vec![1, 2, 3],
        };
        bundle.blocks.push(unsupported_block);

        let result = process_on_reception(&mut bundle).unwrap();
        // DELETE_BUNDLE_ON_FAILURE is checked first in the implementation
        assert_eq!(
            result,
            ReceptionResult::DeleteBundle(DeletionReason::BlockUnsupported)
        );
    }

    #[test]
    fn test_reception_no_action_on_unsupported_non_critical_block() {
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
            .lifetime(86_400_000)
            .payload(b"test".to_vec())
            .build()
            .unwrap();

        let initial_block_count = bundle.blocks.len();

        // Add unsupported block with NO critical flags
        let unsupported_block = CanonicalBlock {
            block_type: BlockType::Unknown(999),
            block_number: 10,
            block_flags: 0, // No flags set
            crc_type: CrcType::None,
            data: vec![1, 2, 3],
        };
        bundle.blocks.push(unsupported_block);

        let result = process_on_reception(&mut bundle).unwrap();
        assert_eq!(result, ReceptionResult::Accepted);

        // Block should NOT have been removed (no discard flag)
        assert_eq!(bundle.blocks.len(), initial_block_count + 1);
    }
}
