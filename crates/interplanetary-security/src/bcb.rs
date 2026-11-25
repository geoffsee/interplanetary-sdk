//! Block Confidentiality Block (BCB) generation per RFC 9172/9173

use super::context2_aesgcm::{AesGcmContext, AesGcmVariant};
use ciborium::Value;
use interplanetary_bp::{BlockType, Bundle, CanonicalBlock};
use interplanetary_types::{Error, Result};

/// BCB security targets
#[derive(Debug, Clone)]
pub struct BcbTargets {
    /// Block numbers to encrypt
    pub block_numbers: Vec<u64>,
}

/// BCB configuration
#[derive(Debug, Clone)]
pub struct BcbConfig {
    /// Security source endpoint
    pub security_source: interplanetary_types::EndpointId,
    /// Target blocks
    pub targets: BcbTargets,
    /// AES-GCM variant
    pub aes_variant: AesGcmVariant,
    /// Encryption key bytes
    pub key: Vec<u8>,
    /// Initialization vector
    pub iv: Vec<u8>,
    /// Optional AES wrapped key per RFC 9173 §4.3.3
    pub wrapped_key: Option<Vec<u8>>,
    /// Scope flags per RFC 9172 §3.10
    pub scope_flags: u8,
    /// Optional key ID for nonce tracking (RFC 9173 §4.3.1)
    pub key_id: Option<Vec<u8>>,
    #[cfg(feature = "test-fixtures")]
    /// Skip security source validation (test-fixtures feature only, not for production)
    pub skip_source_validation: bool,
}

/// Construct AAD (Additional Authenticated Data) per RFC 9173 §3.9
///
/// AAD = scope_flags || ? primary_block || ? target_header || ? security_header
pub fn construct_aad(
    bundle: &Bundle,
    target_block_num: u64,
    security_block_num: u64,
    scope_flags: u8,
) -> Result<Vec<u8>> {
    let mut aad = Vec::new();

    // Scope flags byte
    aad.push(scope_flags);

    // If scope includes primary (bit 0 set)
    if scope_flags & 0x01 != 0 {
        let primary_bytes = super::bib::encode_primary_for_ippt(&bundle.primary)?;
        aad.extend_from_slice(&primary_bytes);
    }

    // If scope includes target header (bit 1 set)
    if scope_flags & 0x02 != 0 && target_block_num != 0 {
        let block = bundle
            .blocks
            .iter()
            .find(|b| b.block_number == target_block_num)
            .ok_or_else(|| {
                Error::not_found(format!("Target block {} not found", target_block_num))
            })?;

        let header = vec![
            Value::Integer(block.block_type.to_u64().into()),
            Value::Integer(block.block_number.into()),
            Value::Integer(block.block_flags.into()),
        ];
        ciborium::into_writer(&Value::Array(header), &mut aad)
            .map_err(|e| Error::protocol_violation(format!("AAD target header: {}", e)))?;
    }

    // If scope includes security header (bit 2 set)
    if scope_flags & 0x04 != 0 {
        // Find BCB block itself
        let bcb = bundle
            .blocks
            .iter()
            .find(|b| b.block_number == security_block_num)
            .ok_or_else(|| Error::not_found("BCB block not found for AAD"))?;

        let header = vec![
            Value::Integer(bcb.block_type.to_u64().into()),
            Value::Integer(bcb.block_number.into()),
            Value::Integer(bcb.block_flags.into()),
        ];
        ciborium::into_writer(&Value::Array(header), &mut aad)
            .map_err(|e| Error::protocol_violation(format!("AAD security header: {}", e)))?;
    }

    Ok(aad)
}

/// Construct AAD during BCB generation (before the BCB block exists)
///
/// When scope_flags includes the security header bit (0x04), constructs a placeholder
/// header with the anticipated block number and standard BCB properties.
fn construct_aad_for_generation(
    bundle: &Bundle,
    target_block_num: u64,
    security_block_num: u64,
    scope_flags: u8,
) -> Result<Vec<u8>> {
    let mut aad = Vec::new();

    // Scope flags byte
    aad.push(scope_flags);

    // If scope includes primary (bit 0 set)
    if scope_flags & 0x01 != 0 {
        let primary_bytes = super::bib::encode_primary_for_ippt(&bundle.primary)?;
        aad.extend_from_slice(&primary_bytes);
    }

    // If scope includes target header (bit 1 set)
    if scope_flags & 0x02 != 0 && target_block_num != 0 {
        let block = bundle
            .blocks
            .iter()
            .find(|b| b.block_number == target_block_num)
            .ok_or_else(|| {
                Error::not_found(format!("Target block {} not found", target_block_num))
            })?;

        let header = vec![
            Value::Integer(block.block_type.to_u64().into()),
            Value::Integer(block.block_number.into()),
            Value::Integer(block.block_flags.into()),
        ];
        ciborium::into_writer(&Value::Array(header), &mut aad)
            .map_err(|e| Error::protocol_violation(format!("AAD target header: {}", e)))?;
    }

    // If scope includes security header (bit 2 set)
    if scope_flags & 0x04 != 0 {
        // During generation, BCB doesn't exist yet. Construct placeholder header.
        // RFC 9172 §4.2.3: BCB block flags MUST be 0x01 (replicate in every fragment)
        let header = vec![
            Value::Integer(BlockType::Bcb.to_u64().into()),
            Value::Integer(security_block_num.into()),
            Value::Integer(0x01.into()), // RFC 9172 §4.2.3: replicate flag
        ];
        ciborium::into_writer(&Value::Array(header), &mut aad)
            .map_err(|e| Error::protocol_violation(format!("AAD security header: {}", e)))?;
    }

    Ok(aad)
}

/// Generate BCB block (single target per RFC 9173 erratum 7002)
///
/// Per erratum 7002, each BCB MUST encrypt exactly one target to ensure unique IV per operation.
/// If multiple targets are requested, returns an error. Caller must generate separate BCBs.
///
/// ## RFC 9173 §4.3.1: IV Uniqueness
///
/// If `config.key_id` and `nonce_registry` are provided, this function registers the (key_id, IV)
/// pair to enforce RFC 9173 §4.3.1: "a value MUST NOT be reused for multiple encryptions using
/// the same encryption key." Returns error if reuse is detected.
///
/// ## Security Block Number
///
/// When `config.scope_flags` includes the security header bit (0x04), the AAD must include
/// the BCB block's own header. Since the block doesn't exist yet during generation, we construct
/// a placeholder header with the next available block number. This ensures RFC 9173 §3.9 compliance.
pub fn generate_bcb(
    bundle: &Bundle,
    config: &BcbConfig,
    nonce_registry: Option<&mut super::nonce::NonceRegistry>,
) -> Result<(CanonicalBlock, Vec<Vec<u8>>)> {
    // RFC 9173 erratum 7002: enforce one target per BCB (IV/nonce uniqueness)
    if config.targets.block_numbers.len() != 1 {
        return Err(Error::protocol_violation(format!(
            "BCB must have exactly one target per RFC 9173 erratum 7002 (IV uniqueness). Got {} targets",
            config.targets.block_numbers.len()
        )));
    }

    // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
    // encoding, MUST be between 8-16 bytes."
    if config.iv.len() < 8 || config.iv.len() > 16 {
        return Err(Error::invalid_config(format!(
            "RFC 9173 §4.3.1: IV must be between 8-16 bytes, got {} bytes",
            config.iv.len()
        )));
    }

    // RFC 9172 §5.2: Security operations MUST NOT be performed on fragments
    if bundle.primary.is_fragment() {
        return Err(Error::protocol_violation(
            "RFC 9172 §5.2: Cannot add BCB to fragmented bundle",
        ));
    }

    // RFC 9173 §4.3.1: Register IV to prevent reuse with same key
    if let (Some(key_id), Some(registry)) = (&config.key_id, nonce_registry) {
        registry.register(key_id, &config.iv).map_err(|e| {
            Error::security_failure(format!("RFC 9173 §4.3.1 IV reuse detected: {}", e))
        })?;
    }

    let target_num = config.targets.block_numbers[0];

    // RFC 9172 §4: BCB encrypts block-type-specific data, which only exists for canonical blocks
    // Primary block (block 0) cannot be encrypted by BCB
    if target_num == 0 {
        return Err(Error::protocol_violation(
            "RFC 9172 §4: BCB cannot target primary block (block 0)",
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

    // Get target block plaintext
    let target = bundle
        .blocks
        .iter()
        .find(|b| b.block_number == target_num)
        .ok_or_else(|| Error::not_found(format!("Target block {} not found", target_num)))?;

    let plaintext = &target.data;

    // RFC 9173 §4.7.2: Construct AAD per verbatim specification
    // If scope_flags includes security header bit (0x04), we need the BCB block number
    // Since the block doesn't exist yet, compute what it will be: next available block number
    let security_block_num = if config.scope_flags & 0x04 != 0 {
        // Find highest existing block number and add 1
        let max_block_num = bundle
            .blocks
            .iter()
            .map(|b| b.block_number)
            .max()
            .unwrap_or(0);
        max_block_num + 1
    } else {
        // Security header not included in AAD, placeholder is fine
        0
    };

    let aad =
        construct_aad_for_generation(bundle, target_num, security_block_num, config.scope_flags)?;

    // Encrypt with AES-GCM
    let ctx = AesGcmContext::new(config.aes_variant);
    let (ciphertext, tag) = ctx.encrypt(plaintext, &aad, &config.key, &config.iv)?;

    // Construct BCB block-type-specific data per RFC 9172 §3.6-3.7
    let mut block_data = Vec::new();

    // Security targets array
    let targets: Vec<Value> = config
        .targets
        .block_numbers
        .iter()
        .map(|n| Value::Integer((*n).into()))
        .collect();
    ciborium::into_writer(&Value::Array(targets), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BCB targets: {}", e)))?;

    // Security context ID (BCB-AES-GCM = 2)
    ciborium::into_writer(&Value::Integer(2.into()), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BCB context ID: {}", e)))?;

    // Security context flags (0x01 = parameters present)
    ciborium::into_writer(&Value::Integer(1.into()), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BCB flags: {}", e)))?;

    // Security source (encoded as EID per RFC 9172 §3.6, RFC 9171/9758)
    let source_val = super::bib::encode_eid(&config.security_source)?;
    ciborium::into_writer(&source_val, &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BCB source: {}", e)))?;

    // Security parameters (IV, AES variant, wrapped key (optional), scope flags)
    let aes_variant_num = match config.aes_variant {
        AesGcmVariant::Aes128 => 1,
        AesGcmVariant::Aes256 => 3,
    };

    let mut params_vec = vec![
        Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(config.iv.clone()),
        ]),
        Value::Array(vec![
            Value::Integer(2.into()),
            Value::Integer(aes_variant_num.into()),
        ]),
    ];

    // Add wrapped key parameter if present (parameter ID 3)
    if let Some(ref wrapped_key) = config.wrapped_key {
        params_vec.push(Value::Array(vec![
            Value::Integer(3.into()),
            Value::Bytes(wrapped_key.clone()),
        ]));
    }

    // RFC 9173 §3.3.3/§4.3.4: "Implementations MUST set reserved and unassigned bits in this
    // field to 0 when constructing these flags at a security source."
    // Only bits 0-2 are defined; mask out reserved bits 3-7
    let scope_flags_masked = config.scope_flags & 0x07;
    params_vec.push(Value::Array(vec![
        Value::Integer(4.into()),
        Value::Integer((scope_flags_masked as u64).into()),
    ]));

    let params = Value::Array(params_vec);
    ciborium::into_writer(&params, &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BCB params: {}", e)))?;

    // Security results (authentication tag)
    let results_array = vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(tag.clone()),
    ])])];
    ciborium::into_writer(&Value::Array(results_array), &mut block_data)
        .map_err(|e| Error::protocol_violation(format!("BCB results: {}", e)))?;

    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 0, // Will be assigned
        block_flags: 1,  // Block must be replicated in every fragment (per RFC 9171 §4.2.3)
        crc_type: interplanetary_bp::CrcType::None,
        data: block_data,
    };

    // RFC 9172 §3.3-3.4: Validate that adding this BCB doesn't violate security rules
    // Assign temporary block number for validation (actual number assigned by caller)
    let mut test_bcb = bcb.clone();
    test_bcb.block_number = 998; // Temporary high number to avoid conflicts
    let mut test_bundle = bundle.clone();
    test_bundle.blocks.push(test_bcb);
    // enforce_bib_after_bcb=false: adding a BCB beside an existing BIB is the
    // start of the §3.9 pattern (caller must encrypt the BIB next / as well).
    if let Err(e) = super::validation::validate_security_blocks_ex(&test_bundle, false) {
        return Err(Error::protocol_violation(format!(
            "Generated BCB would violate security rules: {}",
            e
        )));
    }

    // Return BCB and ciphertexts to replace target blocks
    Ok((bcb, vec![ciphertext]))
}
