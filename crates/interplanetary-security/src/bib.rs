//! Block Integrity Block (BIB) generation per RFC 9172/9173

use super::context1_hmac::{HmacSha256Context, HmacVariant};
use ciborium::Value;
use interplanetary_bp::{BlockType, Bundle, CanonicalBlock};
use interplanetary_types::{Error, Result};

/// BIB security targets
#[derive(Debug, Clone)]
pub struct BibTargets {
    /// Block numbers to protect
    pub block_numbers: Vec<u64>,
}

/// BIB configuration
#[derive(Debug, Clone)]
pub struct BibConfig {
    /// Security source endpoint
    pub security_source: interplanetary_types::EndpointId,
    /// Target blocks
    pub targets: BibTargets,
    /// HMAC SHA variant
    pub sha_variant: HmacVariant,
    /// HMAC key bytes
    pub key: Vec<u8>,
    /// Optional AES wrapped key per RFC 9173 §3.3.2 (parameter ID 2)
    pub wrapped_key: Option<Vec<u8>>,
    /// Scope flags per RFC 9172 §3.10
    pub scope_flags: u8,
    #[cfg(feature = "test-fixtures")]
    /// Skip security source validation (test-fixtures feature only, not for production)
    pub skip_source_validation: bool,
    #[cfg(feature = "test-fixtures")]
    /// HMAC key length policy (test-fixtures feature only)
    pub hmac_key_policy: Option<super::context1_hmac::HmacKeyLengthPolicy>,
}

/// Construct IPPT (Integrity Protected Plaintext) per RFC 9173 §3.8
///
/// IPPT = scope_flags || ? primary_block || ? target_header || ? security_header || target_data
///
/// When `scope_flags` bit 2 (0x04) is set, `security_header` must supply the BIB's
/// (block_number, block_flags) so type/number/flags can be appended (RFC9173-025).
pub fn construct_ippt(bundle: &Bundle, target_block_num: u64, scope_flags: u8) -> Result<Vec<u8>> {
    // Default: no security-header material (callers with bit 0x04 should use
    // construct_ippt_with_security_header). Kept for API compatibility when bit
    // 0x04 is unset.
    construct_ippt_with_security_header(bundle, target_block_num, scope_flags, None)
}

/// IPPT construction with optional BIB security-header fields (RFC 9173 §3.7 step 4).
pub fn construct_ippt_with_security_header(
    bundle: &Bundle,
    target_block_num: u64,
    scope_flags: u8,
    security_header: Option<(u64, u64)>,
) -> Result<Vec<u8>> {
    let mut ippt = Vec::new();

    // Scope flags byte
    ippt.push(scope_flags);

    // If scope includes primary (bit 0 set) AND target is not primary
    // Per RFC 9173 §3.7 step 2: skip if target is primary
    if scope_flags & 0x01 != 0 && target_block_num != 0 {
        // Encode primary block wrapped as CBOR bytes per RFC 9172 §4
        let primary_bytes = encode_primary_for_ippt(&bundle.primary)?;
        ciborium::into_writer(&Value::Bytes(primary_bytes), &mut ippt)
            .map_err(|e| Error::protocol_violation(format!("IPPT scope primary: {}", e)))?;
    }

    // Target block (RFC 9173 §3.7 step 5) — header first when bit 1 set
    if target_block_num == 0 {
        // Target is primary block - add wrapped as CBOR bytes per RFC 9172 §4
        // (primary/target-header steps skipped per RFC note)
        let primary_bytes = encode_primary_for_ippt(&bundle.primary)?;
        // Security header (BIB) before primary-as-target data when bit 2 set
        append_bib_security_header(&mut ippt, scope_flags, security_header)?;
        ciborium::into_writer(&Value::Bytes(primary_bytes), &mut ippt)
            .map_err(|e| Error::protocol_violation(format!("IPPT primary target: {}", e)))?;
    } else {
        // Target is a canonical block
        let block = bundle
            .blocks
            .iter()
            .find(|b| b.block_number == target_block_num)
            .ok_or_else(|| {
                Error::not_found(format!("Target block {} not found", target_block_num))
            })?;

        // If scope includes target header (bit 1 set)
        if scope_flags & 0x02 != 0 {
            // RFC 9172 §4.3.1 (RFC9172-074): reserved and unassigned block
            // processing control flags MUST be set to 0 in canonical form.
            // Defined bits are 0–2 (0x07); bit 3 is reserved, 4+ unassigned.
            const BLOCK_FLAGS_DEFINED: u64 = 0x07;
            let flags_canonical = block.block_flags & BLOCK_FLAGS_DEFINED;
            // Encode target header: [block_type, block_number, block_flags]
            let header = vec![
                Value::Integer(block.block_type.to_u64().into()),
                Value::Integer(block.block_number.into()),
                Value::Integer(flags_canonical.into()),
            ];
            ciborium::into_writer(&Value::Array(header), &mut ippt)
                .map_err(|e| Error::protocol_violation(format!("IPPT header encode: {}", e)))?;
        }

        // RFC 9173 §3.7 step 4 / RFC9173-025: security header flag → BIB type/number/flags
        append_bib_security_header(&mut ippt, scope_flags, security_header)?;

        // Target block data as CBOR bytes
        ciborium::into_writer(&Value::Bytes(block.data.clone()), &mut ippt)
            .map_err(|e| Error::protocol_violation(format!("IPPT data encode: {}", e)))?;
    }

    Ok(ippt)
}

fn append_bib_security_header(
    ippt: &mut Vec<u8>,
    scope_flags: u8,
    security_header: Option<(u64, u64)>,
) -> Result<()> {
    if scope_flags & 0x04 == 0 {
        return Ok(());
    }
    // RFC 9173 §3.7 step 4: [BIB block type, block number, block flags]
    // BIB block type code is 11 (RFC 9172).
    let (bib_num, bib_flags) = security_header.unwrap_or((0, 0));
    const BLOCK_FLAGS_DEFINED: u64 = 0x07;
    let flags_canonical = bib_flags & BLOCK_FLAGS_DEFINED;
    let header = vec![
        Value::Integer(11u64.into()),
        Value::Integer(bib_num.into()),
        Value::Integer(flags_canonical.into()),
    ];
    ciborium::into_writer(&Value::Array(header), ippt)
        .map_err(|e| Error::protocol_violation(format!("IPPT security header encode: {}", e)))?;
    Ok(())
}

pub(crate) fn encode_primary_for_ippt(
    primary: &interplanetary_bp::blocks::PrimaryBlock,
) -> Result<Vec<u8>> {
    // Per RFC 9171 §4.3.1: primary block is a CBOR array
    let mut elements = vec![
        Value::Integer(primary.version.into()),
        Value::Integer(primary.bundle_flags.into()),
        Value::Integer((primary.crc_type as u64).into()),
    ];

    // Encode EIDs as arrays per RFC 9171 §4.2.5
    elements.push(encode_eid(&primary.destination)?);
    elements.push(encode_eid(&primary.source)?);
    elements.push(encode_eid(&primary.report_to)?);

    // Creation timestamp: [time, sequence]
    elements.push(Value::Array(vec![
        Value::Integer(primary.creation_timestamp.time.as_millis().into()),
        Value::Integer(primary.creation_timestamp.sequence.into()),
    ]));

    // Lifetime
    elements.push(Value::Integer(primary.lifetime.into()));

    let mut output = Vec::new();
    ciborium::into_writer(&Value::Array(elements), &mut output)
        .map_err(|e| Error::protocol_violation(format!("Primary encode: {}", e)))?;
    Ok(output)
}

pub(crate) fn encode_eid(eid: &interplanetary_types::EndpointId) -> Result<Value> {
    use interplanetary_types::EndpointId;
    match eid {
        EndpointId::Ipn {
            allocator,
            node,
            service,
        } => {
            // Per RFC 9758 §6.1:
            // - Default Allocator (0): use 2-element [FQNN, service]
            // - Non-zero allocator: use 3-element [allocator, node, service]
            let ssp = if *allocator == 0 {
                // Two-element: FQNN = (allocator << 32) | node
                let fqnn = (*allocator << 32) | *node;
                Value::Array(vec![
                    Value::Integer(fqnn.into()),
                    Value::Integer((*service).into()),
                ])
            } else {
                // Three-element
                Value::Array(vec![
                    Value::Integer((*allocator).into()),
                    Value::Integer((*node).into()),
                    Value::Integer((*service).into()),
                ])
            };

            Ok(Value::Array(vec![
                Value::Integer(2.into()), // ipn scheme = 2
                ssp,
            ]))
        }
        EndpointId::Dtn { ssp } => {
            Ok(Value::Array(vec![
                Value::Integer(1.into()), // dtn scheme = 1
                Value::Text(ssp.clone()),
            ]))
        }
        EndpointId::Null => {
            Ok(Value::Array(vec![
                Value::Integer(0.into()), // null endpoint = 0
            ]))
        }
        EndpointId::Unknown { .. } => {
            Err(Error::unsupported("Cannot encode unknown endpoint scheme"))
        }
    }
}

/// RFC 9173 §3.8.1 / RFC9173-027/029: strip CRC from security targets before IPPT.
///
/// Sets target `crc_type` to `None` (no CRC present). Primary block (target 0)
/// is handled via `bundle.primary.crc_type`.
pub fn strip_crc_from_security_targets(bundle: &mut Bundle, targets: &[u64]) {
    for &t in targets {
        if t == 0 {
            bundle.primary.crc_type = interplanetary_bp::CrcType::None;
            continue;
        }
        if let Some(block) = bundle.blocks.iter_mut().find(|b| b.block_number == t) {
            block.crc_type = interplanetary_bp::CrcType::None;
        }
    }
}

/// Generate BIB block
pub fn generate_bib(bundle: &Bundle, config: &BibConfig) -> Result<CanonicalBlock> {
    // RFC 9172 §5.2: Security operations MUST NOT be performed on fragments
    if bundle.primary.is_fragment() {
        return Err(Error::protocol_violation(
            "RFC 9172 §5.2: Cannot add BIB to fragmented bundle",
        ));
    }

    // RFC 9758 §5.4-5.5: Validate security source
    #[cfg(feature = "test-fixtures")]
    let skip = config.skip_source_validation;
    #[cfg(not(feature = "test-fixtures"))]
    let skip = false;
    if !skip {
        config.security_source.validate_as_security_source()?;
    }

    #[cfg(feature = "test-fixtures")]
    let ctx = if let Some(policy) = config.hmac_key_policy {
        HmacSha256Context::with_key_policy(config.sha_variant, policy)
    } else {
        HmacSha256Context::new(config.sha_variant)
    };

    #[cfg(not(feature = "test-fixtures"))]
    let ctx = HmacSha256Context::new(config.sha_variant);

    // BIB block number/flags for IPPT security-header scope (RFC 9173 §3.7 step 4)
    let bib_num = bundle
        .blocks
        .iter()
        .map(|b| b.block_number)
        .max()
        .unwrap_or(0)
        + 1;
    // Match CanonicalBlock.block_flags below (RFC appendix vectors use 0)
    let bib_flags: u64 = 0;

    // Compute signatures for each target
    let mut results = Vec::new();

    for target_num in &config.targets.block_numbers {
        let ippt = construct_ippt_with_security_header(
            bundle,
            *target_num,
            config.scope_flags,
            Some((bib_num, bib_flags)),
        )?;
        let signature = ctx.sign(&ippt, &config.key)?;
        results.push((*target_num, signature));
    }

    // Construct BIB block-type-specific data per RFC 9172 §3.6-3.7
    let mut block_data = Vec::new();

    // Security targets array
    let targets: Vec<Value> = config
        .targets
        .block_numbers
        .iter()
        .map(|n| Value::Integer((*n).into()))
        .collect();
    ciborium::into_writer(&Value::Array(targets), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BIB targets: {}", e)))?;

    // Security context ID (BIB-HMAC-SHA2 = 1)
    ciborium::into_writer(&Value::Integer(1.into()), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BIB context ID: {}", e)))?;

    // Security context flags (0x01 = parameters present)
    ciborium::into_writer(&Value::Integer(1.into()), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BIB flags: {}", e)))?;

    // Security source (encoded as EID per RFC 9172 §3.6, RFC 9171/9758)
    let source_val = encode_eid(&config.security_source)?;
    ciborium::into_writer(&source_val, &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BIB source: {}", e)))?;

    // Security parameters (SHA variant, optional wrapped_key, scope flags)
    let mut params_array = vec![Value::Array(vec![
        Value::Integer(1.into()),
        Value::Integer((config.sha_variant as u64).into()),
    ])];

    // RFC 9173 §3.3.2: wrapped_key parameter (ID 2) if present
    if let Some(ref wrapped) = config.wrapped_key {
        params_array.push(Value::Array(vec![
            Value::Integer(2.into()),
            Value::Bytes(wrapped.clone()),
        ]));
    }

    // RFC 9173 §3.3.3: "Implementations MUST set reserved and unassigned bits in this
    // field to 0 when constructing these flags at a security source."
    // Only bits 0-2 are defined; mask out reserved bits 3-7
    let scope_flags_masked = config.scope_flags & 0x07;
    params_array.push(Value::Array(vec![
        Value::Integer(3.into()),
        Value::Integer((scope_flags_masked as u64).into()),
    ]));

    let params = Value::Array(params_array);
    ciborium::into_writer(&params, &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BIB params: {}", e)))?;

    // Security results (one per target)
    let results_array: Vec<Value> = results
        .iter()
        .map(|(_, sig)| {
            Value::Array(vec![Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(sig.clone()),
            ])])
        })
        .collect();
    ciborium::into_writer(&Value::Array(results_array), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BIB results: {}", e)))?;

    let bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 0, // Will be assigned by bundle builder
        block_flags: bib_flags,
        crc_type: interplanetary_bp::CrcType::None,
        data: block_data,
    };

    // RFC 9172 §3.3: Validate that adding this BIB doesn't violate security rules
    // Assign temporary block number for validation (actual number assigned by caller)
    let mut test_bib = bib.clone();
    test_bib.block_number = 999; // Temporary high number to avoid conflicts
    let mut test_bundle = bundle.clone();
    test_bundle.blocks.push(test_bib);
    if let Err(e) = super::validation::validate_security_blocks(&test_bundle) {
        return Err(Error::protocol_violation(format!(
            "Generated BIB would violate security rules: {}",
            e
        )));
    }

    Ok(bib)
}

/// Read BIB security-target block numbers and integrity scope flags from ASB bytes.
fn bib_targets_and_scope(block: &CanonicalBlock) -> Result<(Vec<u64>, u8)> {
    use std::io::Cursor;
    let mut cursor = Cursor::new(&block.data);
    let targets_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB targets: {}", e)))?;
    let targets = match targets_val {
        Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                Value::Integer(n) => n
                    .try_into()
                    .map_err(|_| Error::protocol_violation("Invalid BIB target")),
                _ => Err(Error::protocol_violation("BIB target must be integer")),
            })
            .collect::<Result<Vec<u64>>>()?,
        _ => return Err(Error::protocol_violation("BIB targets must be array")),
    };
    // context id, flags, source — skip
    let _: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB context: {}", e)))?;
    let _: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB flags: {}", e)))?;
    let _: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB source: {}", e)))?;
    let params_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB params: {}", e)))?;
    let mut scope_flags = 0u8;
    if let Value::Array(params) = params_val {
        for p in params {
            if let Value::Array(kv) = p
                && kv.len() == 2
                && let (Value::Integer(id), Value::Integer(val)) = (&kv[0], &kv[1])
            {
                let id_u: u64 = (*id).try_into().unwrap_or(0);
                if id_u == 3 {
                    let v: u64 = (*val).try_into().unwrap_or(0);
                    scope_flags = (v & 0x07) as u8;
                }
            }
        }
    }
    Ok((targets, scope_flags))
}

/// RFC 9172 §3.9 / RFC9172-053/055/067: Prepare BIBs when adding a BCB.
///
/// - Partial overlap: split BIB (overlapping results → new BIB that MUST be encrypted).
/// - Full overlap (RFC9172-067): existing BIB covering only BCB targets MUST be encrypted.
///
/// Returns block numbers of BIBs the caller MUST encrypt.
pub fn split_bibs_for_partial_bcb_targets(
    bundle: &mut Bundle,
    bcb_targets: &[u64],
    hmac_key: &[u8],
    sha_variant: HmacVariant,
    security_source: &interplanetary_types::EndpointId,
) -> Result<Vec<u64>> {
    let bcb_set: std::collections::HashSet<u64> = bcb_targets.iter().copied().collect();

    let mut replacements: Vec<(u64, Vec<u64>, Vec<u64>, u8)> = Vec::new();
    let mut full_overlap_bibs: Vec<u64> = Vec::new();
    for block in &bundle.blocks {
        if !matches!(block.block_type, BlockType::Bib) {
            continue;
        }
        let (targets, scope_flags) = bib_targets_and_scope(block)?;
        let overlapping: Vec<u64> = targets
            .iter()
            .copied()
            .filter(|t| bcb_set.contains(t))
            .collect();
        let remaining: Vec<u64> = targets
            .iter()
            .copied()
            .filter(|t| !bcb_set.contains(t))
            .collect();
        if overlapping.is_empty() {
            continue;
        }
        // RFC9172-067: full overlap — encrypt the existing BIB as-is
        if remaining.is_empty() {
            full_overlap_bibs.push(block.block_number);
            continue;
        }
        // Partial overlap (RFC9172-053/055)
        replacements.push((block.block_number, remaining, overlapping, scope_flags));
    }

    let mut new_bib_nums = full_overlap_bibs;
    for (old_num, remaining, overlapping, scope_flags) in replacements {
        bundle.blocks.retain(|b| b.block_number != old_num);

        let mut remain_bib = generate_bib(
            bundle,
            &BibConfig {
                security_source: security_source.clone(),
                targets: BibTargets {
                    block_numbers: remaining,
                },
                sha_variant,
                key: hmac_key.to_vec(),
                wrapped_key: None,
                scope_flags,
                #[cfg(feature = "test-fixtures")]
                skip_source_validation: true,
                #[cfg(feature = "test-fixtures")]
                hmac_key_policy: None,
            },
        )?;
        let remain_num = bundle
            .blocks
            .iter()
            .map(|b| b.block_number)
            .max()
            .unwrap_or(0)
            + 1;
        remain_bib.block_number = remain_num;
        bundle.blocks.insert(0, remain_bib);

        let mut split_bib = generate_bib(
            bundle,
            &BibConfig {
                security_source: security_source.clone(),
                targets: BibTargets {
                    block_numbers: overlapping,
                },
                sha_variant,
                key: hmac_key.to_vec(),
                wrapped_key: None,
                scope_flags,
                #[cfg(feature = "test-fixtures")]
                skip_source_validation: true,
                #[cfg(feature = "test-fixtures")]
                hmac_key_policy: None,
            },
        )?;
        let split_num = bundle
            .blocks
            .iter()
            .map(|b| b.block_number)
            .max()
            .unwrap_or(0)
            + 1;
        split_bib.block_number = split_num;
        bundle.blocks.insert(0, split_bib);
        new_bib_nums.push(split_num);
    }

    Ok(new_bib_nums)
}
