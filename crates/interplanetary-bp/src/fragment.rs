//! Bundle fragmentation and reassembly per RFC 9171 §5.8

use crate::Bundle;
use interplanetary_types::{Bytes, Error, Result};
use std::collections::HashMap;

/// Fragment metadata
#[derive(Debug, Clone)]
pub struct FragmentInfo {
    /// Offset within original payload
    pub offset: u64,
    /// Total length of original payload
    pub total_length: u64,
}

/// Reassembly state for a fragmented bundle
#[derive(Debug)]
struct ReassemblyState {
    fragments: HashMap<u64, Vec<u8>>, // offset -> data
    total_length: u64,
    received_bytes: u64,
    expiry_time: u64, // Earliest expiry of any fragment
}

/// Fragment reassembly manager with bounded memory
#[derive(Debug)]
pub struct ReassemblyManager {
    states: HashMap<interplanetary_types::BundleId, ReassemblyState>,
    max_memory: Bytes,
    used_memory: Bytes,
    /// Bundle IDs quarantined due to fragment conflicts (RFC 9171 §5.7)
    quarantined: std::collections::HashSet<interplanetary_types::BundleId>,
}

impl ReassemblyManager {
    /// Create new reassembly manager
    pub fn new(max_memory: Bytes) -> Self {
        Self {
            states: HashMap::new(),
            max_memory,
            used_memory: Bytes::ZERO,
            quarantined: std::collections::HashSet::new(),
        }
    }

    /// Add fragment to reassembly
    pub fn add_fragment(
        &mut self,
        bundle_id: interplanetary_types::BundleId,
        bundle: &Bundle,
    ) -> Result<Option<Vec<u8>>> {
        // Check if bundle is quarantined due to previous conflict (RFC 9171 §5.7)
        if self.quarantined.contains(&bundle_id) {
            return Err(Error::protocol_violation(
                "Bundle quarantined due to fragment conflict",
            ));
        }

        // Check if this is a fragment
        let (offset, total_length) = match (
            &bundle.primary.fragment_offset,
            &bundle.primary.total_app_data_length,
        ) {
            (Some(off), Some(total)) => (*off, *total),
            _ => return Err(Error::invalid_config("Not a fragment")),
        };

        // Get or create reassembly state
        let state = self
            .states
            .entry(bundle_id.clone())
            .or_insert_with(|| ReassemblyState {
                fragments: HashMap::new(),
                total_length,
                received_bytes: 0,
                expiry_time: bundle.primary.lifetime,
            });

        // Verify total length matches
        if state.total_length != total_length {
            return Err(Error::protocol_violation("Fragment total length mismatch"));
        }

        // Get payload data
        let payload = bundle
            .blocks
            .first()
            .ok_or_else(|| Error::protocol_violation("Fragment has no payload block"))?;
        let fragment_len = payload.data.len() as u64;
        let fragment_end = offset + fragment_len;

        // RFC 9171 §5.7: Detect overlapping fragments with conflicting data
        for (existing_offset, existing_data) in &state.fragments {
            let existing_end = existing_offset + existing_data.len() as u64;

            // Check for overlap: ranges [offset, fragment_end) and [existing_offset, existing_end)
            let overlap_start = offset.max(*existing_offset);
            let overlap_end = fragment_end.min(existing_end);

            if overlap_start < overlap_end {
                // Overlapping byte range detected
                let overlap_len = (overlap_end - overlap_start) as usize;
                let new_overlap_start = (overlap_start - offset) as usize;
                let existing_overlap_start = (overlap_start - existing_offset) as usize;

                let new_slice = &payload.data[new_overlap_start..new_overlap_start + overlap_len];
                let existing_slice =
                    &existing_data[existing_overlap_start..existing_overlap_start + overlap_len];

                if new_slice != existing_slice {
                    // Conflict! Data differs in overlapping range
                    // Per RFC 9171 §5.7: "the bundle... MUST be abandoned"
                    self.quarantined.insert(bundle_id.clone());
                    self.states.remove(&bundle_id);
                    return Err(Error::protocol_violation(
                        "Fragment conflict: overlapping data mismatch",
                    ));
                }
                // Identical data in overlap is OK (redundant transmission)
            }
        }

        // Check memory limits
        let new_memory = Bytes(fragment_len);
        if self.used_memory.saturating_add(new_memory) > self.max_memory {
            return Err(Error::insufficient_storage(
                new_memory,
                self.max_memory.saturating_sub(self.used_memory),
            ));
        }

        // Store fragment (use entry API to avoid double lookup)
        use std::collections::hash_map::Entry;
        if let Entry::Vacant(e) = state.fragments.entry(offset) {
            e.insert(payload.data.clone());
            state.received_bytes += fragment_len;
            self.used_memory = self.used_memory.saturating_add(new_memory);

            // Update earliest expiry
            if bundle.primary.lifetime < state.expiry_time {
                state.expiry_time = bundle.primary.lifetime;
            }
        }

        // Check if complete
        if state.received_bytes >= state.total_length {
            // Reassemble
            let mut complete = Vec::new();
            let mut current_offset = 0u64;

            while current_offset < state.total_length {
                if let Some(data) = state.fragments.get(&current_offset) {
                    complete.extend_from_slice(data);
                    current_offset += data.len() as u64;
                } else {
                    // Gap in fragments
                    return Ok(None);
                }
            }

            // Clean up
            let state = self.states.remove(&bundle_id).unwrap();
            self.used_memory = self.used_memory.saturating_sub(Bytes(state.received_bytes));

            Ok(Some(complete))
        } else {
            Ok(None)
        }
    }

    /// Remove expired fragments
    pub fn remove_expired(&mut self, current_time: u64) -> Vec<interplanetary_types::BundleId> {
        let mut expired = Vec::new();

        self.states.retain(|id, state| {
            if state.expiry_time <= current_time {
                expired.push(id.clone());
                self.used_memory = self.used_memory.saturating_sub(Bytes(state.received_bytes));
                false
            } else {
                true
            }
        });

        expired
    }

    /// Get memory usage
    pub fn memory_usage(&self) -> Bytes {
        self.used_memory
    }
}

/// Create fragments from bundle (RFC 9171 §5.8)
pub fn fragment_bundle(bundle: &Bundle, max_fragment_size: Bytes) -> Result<Vec<Bundle>> {
    // RFC 9171 §5.8: Check if bundle must not be fragmented
    if bundle.primary.must_not_fragment() {
        return Err(Error::invalid_config(
            "Bundle has must-not-fragment flag set",
        ));
    }

    // Get payload
    let payload_block = bundle
        .blocks
        .iter()
        .find(|b| b.block_type == crate::BlockType::Payload)
        .ok_or_else(|| Error::invalid_config("Bundle has no payload to fragment"))?;

    let payload_data = &payload_block.data;
    let total_length = payload_data.len() as u64;

    if total_length <= max_fragment_size.0 {
        return Err(Error::invalid_config("Bundle doesn't need fragmentation"));
    }

    // Separate extension blocks by replication flag
    let mut replicate_blocks = Vec::new();
    let mut first_only_blocks = Vec::new();

    for block in &bundle.blocks {
        if block.block_type == crate::BlockType::Payload {
            continue; // Skip payload, we'll fragment it
        }
        // RFC 9171 §5.8: Block with bit 0 set must be replicated in every fragment
        if (block.block_flags & 0x01) != 0 {
            replicate_blocks.push(block.clone());
        } else {
            // RFC 9171 §5.8: Other extension blocks only in first fragment
            first_only_blocks.push(block.clone());
        }
    }

    let mut fragments = Vec::new();
    let mut offset = 0u64;

    while offset < total_length {
        let fragment_len = std::cmp::min(max_fragment_size.0, total_length - offset) as usize;

        let fragment_data =
            payload_data[offset as usize..(offset as usize + fragment_len)].to_vec();

        // Create fragment primary block (RFC 9171 §5.8)
        let mut fragment_primary = bundle.primary.clone();
        fragment_primary.fragment_offset = Some(offset);
        fragment_primary.total_app_data_length = Some(total_length);
        // RFC 9171 §5.8: Set is-fragment flag (bit 20)
        fragment_primary.bundle_flags |= 0x100000;

        // Build fragment blocks
        let mut fragment_blocks = Vec::new();

        // RFC 9171 §5.8: Add extension blocks with replicate flag to every fragment
        for block in &replicate_blocks {
            fragment_blocks.push(block.clone());
        }

        // RFC 9171 §5.8: Add all other extension blocks only to first fragment (offset 0)
        if offset == 0 {
            for block in &first_only_blocks {
                fragment_blocks.push(block.clone());
            }
        }

        // Create fragment payload
        let mut fragment_payload = payload_block.clone();
        fragment_payload.data = fragment_data;
        fragment_blocks.push(fragment_payload);

        fragments.push(Bundle::new(fragment_primary, fragment_blocks));

        offset += fragment_len as u64;
    }

    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BundleBuilder;
    use interplanetary_types::{CreationTimestamp, DtnTimeMs, EndpointId};

    #[test]
    fn test_fragment_and_reassemble() {
        let original = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(vec![0u8; 1000])
            .build()
            .unwrap();

        let fragments = fragment_bundle(&original, Bytes(300)).unwrap();

        // Should have 4 fragments (1000 / 300 = 3.33, rounded up)
        assert!(fragments.len() >= 3);

        // Each fragment should have offset and total length
        for frag in &fragments {
            assert!(frag.primary.fragment_offset.is_some());
            assert_eq!(frag.primary.total_app_data_length, Some(1000));
        }
    }

    #[test]
    fn test_reassembly_manager() {
        let mut manager = ReassemblyManager::new(Bytes::from_kib(10).unwrap());

        // Create fragmented bundle
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(vec![0xAA; 500])
            .build()
            .unwrap();

        let fragments = fragment_bundle(&bundle, Bytes(200)).unwrap();
        let bundle_id = bundle.id();

        // Add fragments
        for frag in &fragments[..fragments.len() - 1] {
            let result = manager.add_fragment(bundle_id.clone(), frag).unwrap();
            assert!(result.is_none(), "Should not be complete yet");
        }

        // Add final fragment
        let result = manager
            .add_fragment(bundle_id.clone(), fragments.last().unwrap())
            .unwrap();
        assert!(result.is_some(), "Should be complete");

        let reassembled = result.unwrap();
        assert_eq!(reassembled.len(), 500);
        assert_eq!(reassembled[0], 0xAA);
    }

    #[test]
    fn test_reassembly_memory_limit() {
        let mut manager = ReassemblyManager::new(Bytes(250)); // Enough for one fragment

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(vec![0u8; 500])
            .build()
            .unwrap();

        let fragments = fragment_bundle(&bundle, Bytes(200)).unwrap();
        let bundle_id = bundle.id();

        // First fragment should succeed (200 bytes)
        assert!(
            manager
                .add_fragment(bundle_id.clone(), &fragments[0])
                .is_ok()
        );

        // Second fragment should fail due to memory limit (200 + 200 > 250)
        let result = manager.add_fragment(bundle_id.clone(), &fragments[1]);
        assert!(
            result.is_err(),
            "Second fragment should fail due to memory limit"
        );
    }

    #[test]
    fn test_fragment_conflict_detection() {
        let mut manager = ReassemblyManager::new(Bytes::from_mib(1).unwrap());

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 42))
            .lifetime(86_400_000)
            .payload(vec![0xAA; 1000])
            .build()
            .unwrap();

        let bundle_id = bundle.id();
        let fragments = fragment_bundle(&bundle, Bytes(300)).unwrap();
        assert!(fragments.len() >= 3);

        // Add first fragment successfully
        assert!(
            manager
                .add_fragment(bundle_id.clone(), &fragments[0])
                .is_ok()
        );

        // Create conflicting fragment (same offset, different data)
        let mut conflicting = fragments[0].clone();
        if let Some(payload) = conflicting.blocks.first_mut() {
            payload.data[10] = 0xFF; // Change a byte
        }

        // Adding conflicting fragment should fail
        let result = manager.add_fragment(bundle_id.clone(), &conflicting);
        assert!(result.is_err());

        // Bundle should now be quarantined
        let result2 = manager.add_fragment(bundle_id.clone(), &fragments[1]);
        assert!(result2.is_err());
    }

    #[test]
    fn test_overlapping_identical_ok() {
        let mut manager = ReassemblyManager::new(Bytes::from_mib(1).unwrap());

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 99))
            .lifetime(86_400_000)
            .payload(vec![0xBB; 600])
            .build()
            .unwrap();

        let bundle_id = bundle.id();
        let fragments = fragment_bundle(&bundle, Bytes(300)).unwrap();

        // Add first fragment
        assert!(
            manager
                .add_fragment(bundle_id.clone(), &fragments[0])
                .is_ok()
        );

        // Re-add same fragment (identical data) - should not conflict
        let result = manager.add_fragment(bundle_id.clone(), &fragments[0]);
        assert!(result.is_ok());
    }
}
