//! Security block validation per RFC 9172

use crate::bp::{BlockType, Bundle};
use crate::types::{Error, Result};

/// Validate security blocks in bundle per RFC 9172 rules
pub fn validate_security_blocks(bundle: &Bundle) -> Result<()> {
    validate_security_blocks_ex(bundle, true)
}

/// Validate security blocks; `enforce_bib_after_bcb` controls RFC 9172 §3.9-056
/// (plaintext BIB on a BCB target). Disable when *adding* a BCB to a bundle that
/// already has a BIB (caller must then encrypt the BIB per §3.9).
pub fn validate_security_blocks_ex(bundle: &Bundle, enforce_bib_after_bcb: bool) -> Result<()> {
    // RFC 9172 §3.6: Validate CBOR structure of security blocks
    validate_asb_cbor_structure(bundle)?;

    // RFC 9172 §3.3: Security targets must not be security blocks
    validate_no_security_block_targets(bundle)?;

    // RFC 9172 §4.4: BCB must not target another BCB
    validate_bcb_not_targeting_bcb(bundle)?;

    // RFC 9172 §3.2: Only one BIB per target (uniqueness)
    validate_unique_bib_per_target(bundle)?;

    // RFC 9172 §3.2: Only one BCB per target (uniqueness)
    validate_unique_bcb_per_target(bundle)?;

    // RFC 9172 §3.9: BIB MUST NOT be added for a target that is already a BCB target
    if enforce_bib_after_bcb {
        validate_no_bib_on_bcb_target(bundle)?;
    }

    // RFC 9172 §3.8: BCB block flags validation
    validate_bcb_block_flags(bundle)?;

    Ok(())
}

/// RFC 9172 §3.9: A BIB MUST NOT be added for a security target that is already
/// the security target of a BCB (ambiguity in block processing order).
///
/// Valid exception: the BIB itself is encrypted by a BCB (BIB block number is a
/// BCB target). That is the §3.9 "encrypt the existing BIB" pattern.
fn validate_no_bib_on_bcb_target(bundle: &Bundle) -> Result<()> {
    use std::collections::HashSet;

    let mut bcb_targets: HashSet<u64> = HashSet::new();
    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb) {
            for t in extract_security_targets(&block.data)? {
                bcb_targets.insert(t);
            }
        }
    }

    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bib) {
            // Encrypted BIBs (themselves BCB targets) are the mandated §3.9 pattern
            if bcb_targets.contains(&block.block_number) {
                continue;
            }
            // Plaintext BIB — parse targets; ciphertext BIBs already skipped above
            let Ok(targets) = extract_security_targets(&block.data) else {
                continue;
            };
            for t in targets {
                if bcb_targets.contains(&t) {
                    return Err(Error::protocol_violation(format!(
                        "RFC 9172 §3.9: BIB {} MUST NOT target block {} which is already a BCB security target (BIB is not itself encrypted)",
                        block.block_number, t
                    )));
                }
            }
        }
    }

    Ok(())
}

/// RFC 9172 §3.6: Validate Abstract Security Block CBOR structure
fn validate_asb_cbor_structure(bundle: &Bundle) -> Result<()> {
    use ciborium::Value;
    use std::collections::HashSet;
    use std::io::Cursor;

    // Encrypted BIBs (BCB targets) hold ciphertext, not ASB CBOR — skip them.
    let mut bcb_targets: HashSet<u64> = HashSet::new();
    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb)
            && let Ok(ts) = extract_security_targets(&block.data)
        {
            bcb_targets.extend(ts);
        }
    }

    for block in &bundle.blocks {
        if !matches!(block.block_type, BlockType::Bib | BlockType::Bcb) {
            continue;
        }
        if matches!(block.block_type, BlockType::Bib) && bcb_targets.contains(&block.block_number) {
            continue;
        }

        let block_type_name = if matches!(block.block_type, BlockType::Bib) {
            "BIB"
        } else {
            "BCB"
        };

        let mut cursor = Cursor::new(&block.data);

        // Field 1: Security targets (RFC 9172 §3.6: CBOR array)
        let targets_value: Value = ciborium::from_reader(&mut cursor).map_err(|e| {
            Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} failed to parse targets field: {}",
                block_type_name, block.block_number, e
            ))
        })?;

        let targets = match targets_value {
            Value::Array(ref arr) => {
                // RFC 9172 §3.6: Targets MUST be CBOR array
                arr
            }
            _ => {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.6: {} {} targets field MUST be CBOR array, got {:?}",
                    block_type_name, block.block_number, targets_value
                )));
            }
        };

        // RFC 9172 §3.6: Array MUST have at least one entry
        if targets.is_empty() {
            return Err(Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} targets array MUST have at least one entry",
                block_type_name, block.block_number
            )));
        }

        // RFC 9172 §3.4/3.6: Each target MUST be represented as block number (integer)
        for (i, target) in targets.iter().enumerate() {
            match target {
                Value::Integer(_) => {}
                _ => {
                    return Err(Error::protocol_violation(format!(
                        "RFC 9172 §3.4/3.6: {} {} target[{}] MUST be block number (integer), got {:?}",
                        block_type_name, block.block_number, i, target
                    )));
                }
            }
        }

        // Field 2: Security context ID (RFC 9172 §3.6: CBOR unsigned integer)
        let context_id: Value = ciborium::from_reader(&mut cursor).map_err(|e| {
            Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} failed to parse context ID: {}",
                block_type_name, block.block_number, e
            ))
        })?;

        match context_id {
            Value::Integer(_) => {}
            _ => {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.6: {} {} context ID MUST be CBOR unsigned integer, got {:?}",
                    block_type_name, block.block_number, context_id
                )));
            }
        }

        // Field 3: Security context flags (RFC 9172 §3.6: CBOR unsigned integer)
        let flags: Value = ciborium::from_reader(&mut cursor).map_err(|e| {
            Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} failed to parse flags: {}",
                block_type_name, block.block_number, e
            ))
        })?;

        match flags {
            Value::Integer(_) => {}
            _ => {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.6: {} {} flags MUST be CBOR unsigned integer, got {:?}",
                    block_type_name, block.block_number, flags
                )));
            }
        }

        // Field 4: Security source (RFC 9172 §3.6: CBOR EID array per RFC 9171)
        let source: Value = ciborium::from_reader(&mut cursor).map_err(|e| {
            Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} failed to parse source: {}",
                block_type_name, block.block_number, e
            ))
        })?;

        match source {
            Value::Array(ref arr) if arr.len() >= 2 => {}
            _ => {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.6: {} {} source MUST be CBOR EID array [scheme, SSP, ...], got {:?}",
                    block_type_name, block.block_number, source
                )));
            }
        }

        // Field 5: Security parameters (RFC 9172 §3.6: CBOR array)
        let params: Value = ciborium::from_reader(&mut cursor).map_err(|e| {
            Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} failed to parse parameters: {}",
                block_type_name, block.block_number, e
            ))
        })?;

        match params {
            Value::Array(_) => {}
            _ => {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.6: {} {} parameters MUST be CBOR array, got {:?}",
                    block_type_name, block.block_number, params
                )));
            }
        }

        // Field 6: Security results (RFC 9172 §3.6: CBOR array)
        let results: Value = ciborium::from_reader(&mut cursor).map_err(|e| {
            Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} failed to parse results: {}",
                block_type_name, block.block_number, e
            ))
        })?;

        let results_arr = match results {
            Value::Array(ref arr) => arr,
            _ => {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.6: {} {} results MUST be CBOR array, got {:?}",
                    block_type_name, block.block_number, results
                )));
            }
        };

        // RFC 9172 §3.6: One result per target
        if results_arr.len() != targets.len() {
            return Err(Error::protocol_violation(format!(
                "RFC 9172 §3.6: {} {} MUST have one result per target. Got {} results for {} targets",
                block_type_name,
                block.block_number,
                results_arr.len(),
                targets.len()
            )));
        }
    }

    Ok(())
}

/// RFC 9172 §3.3 / §3.7 / §3.8: Security-target constraints
///
/// - A BIB MUST NOT target a BIB or BCB (§3.7).
/// - A BCB MUST NOT target another BCB or the primary block (§3.8).
/// - A BCB MAY target a BIB only when they share a security target (§3.8 / §3.9).
fn validate_no_security_block_targets(bundle: &Bundle) -> Result<()> {
    use std::collections::HashSet;

    // Precompute BCB targets so encrypted BIBs (ciphertext) can be skipped
    let mut all_bcb_targets: HashSet<u64> = HashSet::new();
    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb)
            && let Ok(ts) = extract_security_targets(&block.data)
        {
            all_bcb_targets.extend(ts);
        }
    }

    for block in &bundle.blocks {
        if !matches!(block.block_type, BlockType::Bib | BlockType::Bcb) {
            continue;
        }
        // Encrypted BIBs are ciphertext — not ASB
        if matches!(block.block_type, BlockType::Bib)
            && all_bcb_targets.contains(&block.block_number)
        {
            continue;
        }
        let targets = extract_security_targets(&block.data)?;
        let is_bcb = matches!(block.block_type, BlockType::Bcb);
        let bcb_target_set: HashSet<u64> = if is_bcb {
            targets.iter().copied().collect()
        } else {
            HashSet::new()
        };

        for target_num in &targets {
            let target_block = bundle.blocks.iter().find(|b| b.block_number == *target_num);

            if let Some(target) = target_block {
                match target.block_type {
                    BlockType::Bcb => {
                        return Err(Error::protocol_violation(format!(
                            "RFC 9172 §3.3/§3.8: Security block {} MUST NOT target BCB {}",
                            block.block_number, target_num
                        )));
                    }
                    BlockType::Bib => {
                        if matches!(block.block_type, BlockType::Bib) {
                            return Err(Error::protocol_violation(format!(
                                "RFC 9172 §3.7: BIB {} MUST NOT target BIB {}",
                                block.block_number, target_num
                            )));
                        }
                        // BCB → BIB: RFC 9172 §3.8. Encrypted BIBs hold ciphertext ASB —
                        // if targets cannot be parsed, treat as already-encrypted §3.9 BIB.
                        let Ok(bib_target_list) = extract_security_targets(&target.data) else {
                            continue;
                        };
                        let bib_targets: HashSet<u64> = bib_target_list.into_iter().collect();
                        let mut shared_ok = !bcb_target_set.is_disjoint(&bib_targets);
                        if !shared_ok {
                            for other in &bundle.blocks {
                                if other.block_number == block.block_number {
                                    continue;
                                }
                                if matches!(other.block_type, BlockType::Bcb) {
                                    let other_targets: HashSet<u64> =
                                        extract_security_targets(&other.data)?
                                            .into_iter()
                                            .collect();
                                    if !other_targets.is_disjoint(&bib_targets) {
                                        shared_ok = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if !shared_ok {
                            // In-progress §3.9 construction: BIB protects non-security content
                            for bt in &bib_targets {
                                if let Some(tb) =
                                    bundle.blocks.iter().find(|b| b.block_number == *bt)
                                {
                                    if !matches!(tb.block_type, BlockType::Bib | BlockType::Bcb) {
                                        shared_ok = true;
                                        break;
                                    }
                                } else if *bt == 1 || *bt == 0 {
                                    shared_ok = true;
                                    break;
                                }
                            }
                        }
                        if !shared_ok {
                            return Err(Error::protocol_violation(format!(
                                "RFC 9172 §3.8: BCB {} MUST NOT target BIB {} unless they share a security target",
                                block.block_number, target_num
                            )));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// RFC 9172 §4.4: BCB MUST NOT target another BCB
fn validate_bcb_not_targeting_bcb(bundle: &Bundle) -> Result<()> {
    // Find all BCBs
    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb) {
            let targets = extract_security_targets(&block.data)?;

            // Check no target is a BCB
            for target_num in targets {
                let target_block = bundle.blocks.iter().find(|b| b.block_number == target_num);

                if let Some(target) = target_block
                    && matches!(target.block_type, BlockType::Bcb)
                {
                    return Err(Error::protocol_violation(format!(
                        "RFC 9172 §4.4: BCB {} MUST NOT target another BCB (block {})",
                        block.block_number, target_num
                    )));
                }
            }
        }
    }

    Ok(())
}

/// RFC 9172 §3.2: Only one BIB integrity operation per target (uniqueness)
fn validate_unique_bib_per_target(bundle: &Bundle) -> Result<()> {
    use std::collections::{HashMap, HashSet};

    let mut bcb_targets: HashSet<u64> = HashSet::new();
    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb)
            && let Ok(ts) = extract_security_targets(&block.data)
        {
            bcb_targets.extend(ts);
        }
    }

    // Track which targets are protected by which BIBs
    let mut target_bib_map: HashMap<u64, u64> = HashMap::new();

    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bib) {
            // Skip encrypted BIBs (ciphertext is not ASB)
            if bcb_targets.contains(&block.block_number) {
                continue;
            }
            let targets = extract_security_targets(&block.data)?;

            for target_num in targets {
                if let Some(existing_bib) = target_bib_map.get(&target_num) {
                    return Err(Error::protocol_violation(format!(
                        "RFC 9172 §3.2: Security operations in a bundle MUST be unique. Target {} already protected by BIB {}. BIB {} also targets it (duplicate security operation)",
                        target_num, existing_bib, block.block_number
                    )));
                }
                target_bib_map.insert(target_num, block.block_number);
            }
        }
    }

    Ok(())
}

/// RFC 9172 §3.2: Only one BCB confidentiality operation per target (uniqueness)
fn validate_unique_bcb_per_target(bundle: &Bundle) -> Result<()> {
    use std::collections::HashMap;

    // Track which targets are protected by which BCBs
    let mut target_bcb_map: HashMap<u64, u64> = HashMap::new();

    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb) {
            let targets = extract_security_targets(&block.data)?;

            for target_num in targets {
                if let Some(existing_bcb) = target_bcb_map.get(&target_num) {
                    return Err(Error::protocol_violation(format!(
                        "RFC 9172 §3.2: Security operations in a bundle MUST be unique. Target {} already protected by BCB {}. BCB {} also targets it (duplicate security operation)",
                        target_num, existing_bcb, block.block_number
                    )));
                }
                target_bcb_map.insert(target_num, block.block_number);
            }
        }
    }

    Ok(())
}

/// RFC 9172 §3.8: BCB block flags validation
fn validate_bcb_block_flags(bundle: &Bundle) -> Result<()> {
    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb) {
            // RFC 9172 §3.8: BCBs MUST NOT have "remove if can't process" flag (bit 2)
            if block.block_flags & 0x04 != 0 {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.8: BCB {} MUST NOT have 'Block must be removed from bundle if it can't be processed' flag set (bit 2)",
                    block.block_number
                )));
            }

            // RFC 9172 §3.8: BCBs MUST have "replicate in every fragment" flag (bit 0) if target is payload
            let targets = extract_security_targets(&block.data)?;
            let targets_payload = targets.contains(&1); // Block 1 is payload

            if targets_payload && (block.block_flags & 0x01 == 0) {
                return Err(Error::protocol_violation(format!(
                    "RFC 9172 §3.8: BCB {} targeting payload MUST have 'Block must be replicated in every fragment' flag set (bit 0)",
                    block.block_number
                )));
            }
        }
    }

    Ok(())
}

/// Extract security targets array from security block data
/// Security block structure: targets || context_id || flags || source || params || results
fn extract_security_targets(block_data: &[u8]) -> Result<Vec<u64>> {
    use ciborium::Value;
    use std::io::Cursor;

    // Parse CBOR to get first item (targets array)
    let mut cursor = Cursor::new(block_data);
    let targets_value: Value = ciborium::from_reader(&mut cursor).map_err(|e| {
        Error::protocol_violation(format!("Failed to parse security targets: {}", e))
    })?;

    if let Value::Array(targets) = targets_value {
        let mut result = Vec::new();
        for target in targets {
            if let Value::Integer(num) = target {
                result.push(
                    num.try_into()
                        .map_err(|_| Error::protocol_violation("Invalid target block number"))?,
                );
            }
        }
        Ok(result)
    } else {
        Err(Error::protocol_violation(
            "Security targets must be a CBOR array",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp::{BundleBuilder, CanonicalBlock, CrcType, CreationTimestamp};
    use crate::types::{DtnTimeMs, EndpointId};

    #[test]
    fn test_rfc9172_039_bib_cannot_target_bcb() {
        // RFC 9172 §3.3: Security target MUST NOT be a security block

        let source = EndpointId::ipn(0, 2, 1).unwrap();
        let dest = EndpointId::ipn(0, 1, 2).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let mut bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Add a BCB (block 2) targeting payload (block 1)
        let bcb = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 2,
            block_flags: 1,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload)
                0x02, // context ID: 2
                0x01, // flags: 1
                0x82, 0x01, 0x00, // source: ipn:1.0
                0x80, // params: []
                0x81, 0x81, 0x81, 0x01, 0x40, // results: [[1, bytes]]
            ],
        };
        bundle.blocks.insert(0, bcb);

        // Add a BIB (block 3) targeting the BCB (block 2) - INVALID
        let bib = CanonicalBlock {
            block_type: BlockType::Bib,
            block_number: 3,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x02, // targets: [2] (BCB) - VIOLATES RFC 9172 §3.3
                0x01, // context ID: 1
                0x01, // flags: 1
                0x82, 0x01, 0x00, // source: ipn:1.0
                0x80, // params: []
                0x81, 0x81, 0x81, 0x01,
                0x40, // results: [[1, bytes]] (one result for one target)
            ],
        };
        bundle.blocks.insert(0, bib);

        // Validation MUST fail
        let result = validate_security_blocks(&bundle);
        assert!(
            result.is_err(),
            "BIB targeting BCB MUST be rejected per RFC 9172 §3.3"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("3.3") || err.contains("MUST NOT") || err.contains("security block"),
            "Error should reference RFC 9172 §3.3. Got: {}",
            err
        );
    }

    #[test]
    fn test_rfc9172_047_bcb_cannot_target_bcb() {
        // RFC 9172 §4.4: BCB MUST NOT target another BCB

        let source = EndpointId::ipn(0, 2, 1).unwrap();
        let dest = EndpointId::ipn(0, 1, 2).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let mut bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Add first BCB (block 2) targeting payload
        let bcb1 = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 2,
            block_flags: 1,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload)
                0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bcb1);

        // Add second BCB (block 3) targeting first BCB - INVALID
        let bcb2 = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 3,
            block_flags: 1,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x02, // targets: [2] (BCB) - VIOLATES RFC 9172 §4.4
                0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bcb2);

        // Validation MUST fail
        let result = validate_security_blocks(&bundle);
        assert!(
            result.is_err(),
            "BCB targeting BCB MUST be rejected per RFC 9172 §4.4"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("4.4") || err.contains("BCB") || err.contains("MUST NOT target"),
            "Error should reference RFC 9172 §4.4. Got: {}",
            err
        );
    }

    #[test]
    #[cfg(feature = "test-fixtures")]
    fn test_rfc9172_bcb_cannot_target_primary_block() {
        // RFC 9172 §4: BCB encrypts block-type-specific data,
        // which only exists for canonical blocks.
        // Primary block (block 0) cannot be a BCB target.

        use crate::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
        use crate::security::context2_aesgcm::AesGcmVariant;

        let source = EndpointId::ipn(0, 1, 1).unwrap();
        let dest = EndpointId::ipn(0, 2, 1).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let bundle = BundleBuilder::new()
            .source(source.clone())
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Try to create BCB targeting primary block (block 0)
        let bcb_config = BcbConfig {
            security_source: source,
            targets: BcbTargets {
                block_numbers: vec![0], // Target primary block - INVALID
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0xAA; 16],
            iv: vec![0x01; 12],
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: true,
        };

        // Generation MUST fail
        let result = generate_bcb(&bundle, &bcb_config, None);
        assert!(
            result.is_err(),
            "BCB targeting primary block MUST be rejected"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("primary block") || err.contains("block 0"),
            "Error should mention primary block. Got: {}",
            err
        );
    }

    #[test]
    fn test_rfc9172_042_multiple_bibs_per_target_rejected() {
        // RFC 9172 §3.3: Only one BIB per target (enforcing RECOMMENDED as MUST)

        let source = EndpointId::ipn(0, 2, 1).unwrap();
        let dest = EndpointId::ipn(0, 1, 2).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let mut bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Add first BIB (block 2) targeting payload
        let bib1 = CanonicalBlock {
            block_type: BlockType::Bib,
            block_number: 2,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload)
                0x01, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bib1);

        // Add second BIB (block 3) also targeting payload - INVALID
        let bib2 = CanonicalBlock {
            block_type: BlockType::Bib,
            block_number: 3,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload) - VIOLATES uniqueness
                0x01, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bib2);

        // Validation MUST fail
        let result = validate_security_blocks(&bundle);
        assert!(
            result.is_err(),
            "Multiple BIBs per target MUST be rejected per RFC 9172 §3.3"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("already protected") || err.contains("Multiple"),
            "Error should indicate duplicate BIB. Got: {}",
            err
        );
    }

    #[test]
    fn test_rfc9172_032_multiple_bcbs_per_target_rejected() {
        // RFC 9172 §3.2: Only one BCB per target (uniqueness)

        let source = EndpointId::ipn(0, 2, 1).unwrap();
        let dest = EndpointId::ipn(0, 1, 2).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let mut bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Add first BCB (block 2) targeting payload
        let bcb1 = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 2,
            block_flags: 1,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload)
                0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bcb1);

        // Add second BCB (block 3) also targeting payload - VIOLATES §3.2
        let bcb2 = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 3,
            block_flags: 1,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload) - duplicate operation
                0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bcb2);

        // Validation MUST fail
        let result = validate_security_blocks(&bundle);
        assert!(
            result.is_err(),
            "Multiple BCBs per target MUST be rejected per RFC 9172 §3.2"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("3.2") && err.contains("unique"),
            "Error should reference RFC 9172 §3.2 uniqueness. Got: {}",
            err
        );
    }

    #[test]
    fn test_rfc9172_046_bcb_cannot_have_remove_flag() {
        // RFC 9172 §3.8: BCBs MUST NOT have "Block must be removed from bundle if it can't be processed" flag

        let source = EndpointId::ipn(0, 2, 1).unwrap();
        let dest = EndpointId::ipn(0, 1, 2).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let mut bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Add BCB targeting payload with "remove" flag (bit 2) set - INVALID
        let bcb = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 2,
            block_flags: 0x05, // Bit 0 (replicate) + Bit 2 (remove) - VIOLATES §3.8
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload)
                0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bcb);

        // Validation MUST fail
        let result = validate_security_blocks(&bundle);
        assert!(
            result.is_err(),
            "BCB with 'remove' flag MUST be rejected per RFC 9172 §3.8"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("3.8") && err.contains("removed"),
            "Error should reference RFC 9172 §3.8 and 'removed' flag. Got: {}",
            err
        );
    }

    #[test]
    fn test_rfc9172_045_bcb_targeting_payload_must_have_replicate_flag() {
        // RFC 9172 §3.8: BCBs targeting payload MUST have "replicate in every fragment" flag

        let source = EndpointId::ipn(0, 2, 1).unwrap();
        let dest = EndpointId::ipn(0, 1, 2).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let mut bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Add BCB targeting payload WITHOUT replicate flag - INVALID
        let bcb = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 2,
            block_flags: 0x00, // No flags set - VIOLATES §3.8 for payload target
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload)
                0x02, 0x01, 0x82, 0x01, 0x00, 0x80, 0x81, 0x81, 0x81, 0x01, 0x40,
            ],
        };
        bundle.blocks.insert(0, bcb);

        // Validation MUST fail
        let result = validate_security_blocks(&bundle);
        assert!(
            result.is_err(),
            "BCB targeting payload without replicate flag MUST be rejected per RFC 9172 §3.8"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("3.8") && err.contains("replicate"),
            "Error should reference RFC 9172 §3.8 and replicate flag. Got: {}",
            err
        );
    }

    #[test]
    fn test_valid_security_configuration_accepted() {
        // Valid configuration: BIB targeting payload, BCB targeting different block

        let source = EndpointId::ipn(0, 2, 1).unwrap();
        let dest = EndpointId::ipn(0, 1, 2).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 1);

        let mut bundle = BundleBuilder::new()
            .source(source)
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(1000000)
            .payload(vec![0x42; 100])
            .build()
            .unwrap();

        // Add hop count block
        let hop_count = CanonicalBlock {
            block_type: BlockType::HopCount,
            block_number: 2,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![0x82, 0x1e, 0x00],
        };
        bundle.blocks.insert(0, hop_count);

        // Add BIB targeting payload (block 1)
        let bib = CanonicalBlock {
            block_type: BlockType::Bib,
            block_number: 3,
            block_flags: 0,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x01, // targets: [1] (payload)
                0x01, // context ID
                0x01, // flags
                0x82, 0x01, 0x00, // source: ipn:1.0
                0x80, // params: []
                0x81, 0x81, 0x81, 0x01,
                0x40, // results: [[1, bytes]] (one result for one target)
            ],
        };
        bundle.blocks.insert(0, bib);

        // Add BCB targeting hop count (block 2) - different target, OK
        let bcb = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 4,
            block_flags: 1,
            crc_type: CrcType::None,
            data: vec![
                0x81, 0x02, // targets: [2] (hop count)
                0x02, // context ID
                0x01, // flags
                0x82, 0x01, 0x00, // source: ipn:1.0
                0x80, // params: []
                0x81, 0x81, 0x81, 0x01,
                0x40, // results: [[1, bytes]] (one result for one target)
            ],
        };
        bundle.blocks.insert(0, bcb);

        // Validation MUST succeed
        let result = validate_security_blocks(&bundle);
        assert!(
            result.is_ok(),
            "Valid security configuration should be accepted. Got error: {:?}",
            result.err()
        );
    }
}
