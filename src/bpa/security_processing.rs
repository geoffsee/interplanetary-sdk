//! BPA Security Processing per RFC 9172
//!
//! This module implements node-level security operations:
//! - BIB verification at verifiers and acceptors
//! - BCB decryption at acceptors
//! - Security block removal after processing
//! - Failure handling per block processing control flags

use crate::bp::{BlockType, Bundle, CanonicalBlock};
use crate::security::context1_hmac::{HmacSha256Context, HmacVariant};
use crate::security::context2_aesgcm::{AesGcmContext, AesGcmVariant};
use crate::security::{bcb, bib};
use crate::types::{EndpointId, Error, Result};
use ciborium::Value;
use std::io::Cursor;
use zeroize::Zeroizing;

/// Security processing result
#[derive(Debug, Clone)]
pub enum SecurityProcessingResult {
    /// Processing succeeded, security blocks removed
    Success,
    /// BIB verification failed
    BibVerificationFailed {
        /// BIB block number that failed verification
        bib_block_num: u64,
        /// Target block number that failed verification
        target_block_num: u64,
    },
    /// BCB decryption failed
    BcbDecryptionFailed {
        /// BCB block number that failed decryption
        bcb_block_num: u64,
        /// Target block number that failed decryption
        target_block_num: u64,
    },
}

/// Security failure policy per RFC 9172 §5.1.1
///
/// "If processing a security operation fails, the target SHALL be processed
/// according to the security policy."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityFailurePolicy {
    /// Delete bundle when security processing fails (default, most secure)
    #[default]
    DeleteBundle,
    /// Strip security block and continue processing (less secure)
    StripSecurityBlock,
}

/// Local policy for BPSec *generation* failures (RFC 9173 §3.8.1 / §4.8.1).
///
/// "Problems encountered in the keyed hash generation / encryption MUST be
/// processed in accordance with local BPSec security policy."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityGenerationPolicy {
    /// Fail closed: return Err and do not admit/send the bundle (default)
    #[default]
    FailClosed,
    /// Omit the failed security operation and continue with the unprotected bundle
    OmitSecurityOperation,
}

/// BIB-HMAC-SHA2 security context identifier (RFC 9173 §3.2).
pub const BIB_HMAC_SHA2_CONTEXT_ID: u64 = 1;
/// BCB-AES-GCM security context identifier (RFC 9173 §4.2).
pub const BCB_AES_GCM_CONTEXT_ID: u64 = 2;

/// Tracks KEK usage to enforce RFC 9173 §6.2 cross-algorithm / cross-context bans.
#[derive(Debug, Clone, Default)]
pub struct KekUsageRegistry {
    /// kek bytes → security context ID first registered for that KEK
    by_kek: std::collections::HashMap<Vec<u8>, u64>,
}

impl KekUsageRegistry {
    /// Register a KEK for a security context. Returns Err if the same KEK was
    /// previously used for a different context (RFC9173-133) or if the caller
    /// attempts to bind it to an incompatible algorithm family (RFC9173-132).
    pub fn register(&mut self, kek: &[u8], context_id: u64) -> Result<()> {
        if context_id != BIB_HMAC_SHA2_CONTEXT_ID && context_id != BCB_AES_GCM_CONTEXT_ID {
            return Err(Error::protocol_violation(format!(
                "RFC9173-132/133: unsupported security context id {}",
                context_id
            )));
        }
        match self.by_kek.get(kek) {
            Some(existing) if *existing != context_id => Err(Error::protocol_violation(
                "RFC9173-133: A KEK MUST NOT be used to encrypt keys for different security contexts",
            )),
            Some(_) => Ok(()),
            None => {
                self.by_kek.insert(kek.to_vec(), context_id);
                Ok(())
            }
        }
    }

    /// Refuse using the same key material across different algorithms (RFC9173-132).
    /// BIB-HMAC-SHA2 and BCB-AES-GCM are different algorithm families.
    pub fn assert_same_key_not_cross_algorithm(
        key: &[u8],
        other_keys: &[(u64, &[u8])],
    ) -> Result<()> {
        for (ctx, other) in other_keys {
            if *other == key {
                return Err(Error::protocol_violation(format!(
                    "RFC9173-132: same key MUST NOT be used for different algorithms (also bound to context {})",
                    ctx
                )));
            }
        }
        Ok(())
    }
}

/// Security processing context (holds keys for verification/decryption)
///
/// RFC9173-128: keys live in [`Zeroizing`] buffers (zeroed on drop) and `Debug`
/// redacts key material so keys are not leaked when the context is logged.
#[derive(Clone)]
pub struct SecurityContext {
    /// HMAC keys by endpoint (for BIB verification) — zeroized on drop
    pub hmac_keys: std::collections::HashMap<EndpointId, Zeroizing<Vec<u8>>>,
    /// AES keys by endpoint (for BCB decryption) — zeroized on drop
    pub aes_keys: std::collections::HashMap<EndpointId, Zeroizing<Vec<u8>>>,
    /// Key encryption keys (KEKs) by endpoint for unwrapping AES keys (RFC 9173 §4.3.3)
    pub keks: std::collections::HashMap<EndpointId, Zeroizing<Vec<u8>>>,
    /// Policy for handling BIB verification failures (RFC 9172 §5.1.1)
    pub bib_failure_policy: SecurityFailurePolicy,
    /// Policy for handling BCB decryption failures (RFC 9172 §5.1.1)
    pub bcb_failure_policy: SecurityFailurePolicy,
    /// Local policy for keyed-hash / encryption generation failures (RFC9173-040/111).
    pub generation_failure_policy: SecurityGenerationPolicy,
    /// When true, this node is a BIB security acceptor even if not the bundle
    /// destination (removes BIBs after successful verification).
    pub bib_acceptor: bool,
    /// CRC type restored onto targets when an acceptor ≠ destination removes
    /// the last integrity/confidentiality service (RFC9173-050 / RFC9173-126).
    pub restore_crc_type: crate::bp::CrcType,
    /// KEK usage registry enforcing RFC9173-132/133
    pub kek_registry: KekUsageRegistry,
    /// RFC9173-080: max unsuccessful BCB decrypt attempts per key (security source).
    /// `None` = unlimited; default `Some(32)`.
    pub max_failed_bcb_verifies_per_key: Option<u64>,
    /// Running count of failed BCB decrypts per security-source key.
    pub failed_bcb_verifies: std::collections::HashMap<EndpointId, u64>,
    /// RFC9173-081: received (key_id, IV) pairs for decrypt-side replay detection.
    pub received_iv_registry: crate::security::NonceRegistry,
    /// RFC9173-129/130/131: security sources whose keys are considered compromised.
    /// Ops using those sources MUST NOT be treated as providing integrity/confidentiality.
    pub compromised_sources: std::collections::HashSet<EndpointId>,
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SecurityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityContext")
            .field(
                "hmac_keys",
                &format_args!("[{} redacted]", self.hmac_keys.len()),
            )
            .field(
                "aes_keys",
                &format_args!("[{} redacted]", self.aes_keys.len()),
            )
            .field("keks", &format_args!("[{} redacted]", self.keks.len()))
            .field("bib_failure_policy", &self.bib_failure_policy)
            .field("bcb_failure_policy", &self.bcb_failure_policy)
            .field("generation_failure_policy", &self.generation_failure_policy)
            .field("bib_acceptor", &self.bib_acceptor)
            .field("restore_crc_type", &self.restore_crc_type)
            .field("kek_registry", &self.kek_registry)
            .field(
                "max_failed_bcb_verifies_per_key",
                &self.max_failed_bcb_verifies_per_key,
            )
            .field("failed_bcb_verifies", &self.failed_bcb_verifies)
            .field("received_iv_registry", &self.received_iv_registry)
            .field("compromised_sources", &self.compromised_sources)
            .finish()
    }
}

/// Node-level BCB processing (for use by BundleAgent)
///
/// This wraps the low-level `process_bcbs` function and applies security policy on failure.
#[allow(dead_code)]
pub fn process_bcbs_at_node(
    _agent: &mut crate::bpa::BundleAgent,
    _bundle_id: &crate::types::BundleId,
    _ctx: &SecurityContext,
) -> Result<SecurityProcessingResult> {
    // Placeholder for node-level integration
    // Real implementation would:
    // 1. Get bundle from agent storage
    // 2. Call process_bcbs
    // 3. Apply security policy on failure (delete bundle or strip block)
    // 4. Update agent state
    unimplemented!("process_bcbs_at_node not yet integrated with BundleAgent")
}

/// Node-level BIB processing (for use by BundleAgent)
///
/// This wraps the low-level `process_bibs` function and applies security policy on failure.
#[allow(dead_code)]
pub fn process_bibs_at_node(
    _agent: &mut crate::bpa::BundleAgent,
    _bundle_id: &crate::types::BundleId,
    _ctx: &SecurityContext,
    _is_destination: bool,
) -> Result<SecurityProcessingResult> {
    // Placeholder for node-level integration
    // Real implementation would:
    // 1. Get bundle from agent storage
    // 2. Call process_bibs
    // 3. Apply security policy on failure (delete bundle or strip block)
    // 4. Update agent state
    unimplemented!("process_bibs_at_node not yet integrated with BundleAgent")
}

impl SecurityContext {
    /// Create new empty security context
    pub fn new() -> Self {
        Self {
            hmac_keys: std::collections::HashMap::new(),
            aes_keys: std::collections::HashMap::new(),
            keks: std::collections::HashMap::new(),
            bib_failure_policy: SecurityFailurePolicy::default(),
            bcb_failure_policy: SecurityFailurePolicy::default(),
            generation_failure_policy: SecurityGenerationPolicy::default(),
            bib_acceptor: false,
            restore_crc_type: crate::bp::CrcType::Crc16,
            kek_registry: KekUsageRegistry::default(),
            max_failed_bcb_verifies_per_key: Some(32),
            failed_bcb_verifies: std::collections::HashMap::new(),
            received_iv_registry: crate::security::NonceRegistry::new(),
            compromised_sources: std::collections::HashSet::new(),
        }
    }

    /// RFC9173-080: configure per-key failed BCB decrypt limit (`None` = unlimited).
    pub fn set_max_failed_bcb_verifies_per_key(&mut self, limit: Option<u64>) {
        self.max_failed_bcb_verifies_per_key = limit;
    }

    /// RFC9173-129/130/131: mark a security-source key as compromised.
    pub fn mark_key_compromised(&mut self, endpoint: &EndpointId) {
        self.compromised_sources.insert(endpoint.clone());
    }

    /// Add HMAC key for an endpoint (stored in a zeroizing buffer).
    pub fn add_hmac_key(&mut self, endpoint: EndpointId, key: Vec<u8>) {
        self.hmac_keys.insert(endpoint, Zeroizing::new(key));
    }

    /// Add AES key for an endpoint (stored in a zeroizing buffer).
    pub fn add_aes_key(&mut self, endpoint: EndpointId, key: Vec<u8>) {
        self.aes_keys.insert(endpoint, Zeroizing::new(key));
    }

    /// Add key encryption key (KEK) for an endpoint (for unwrapping wrapped AES keys).
    /// `context_id` is the BPSec context the KEK wraps keys for (1=BIB, 2=BCB).
    pub fn add_kek(&mut self, endpoint: EndpointId, kek: Vec<u8>) {
        // Backward-compatible: default to BCB context when unspecified
        let _ = self.add_kek_for_context(endpoint, kek, BCB_AES_GCM_CONTEXT_ID);
    }

    /// Register a KEK bound to a specific security context (RFC9173-133).
    pub fn add_kek_for_context(
        &mut self,
        endpoint: EndpointId,
        kek: Vec<u8>,
        context_id: u64,
    ) -> Result<()> {
        self.kek_registry.register(&kek, context_id)?;
        self.keks.insert(endpoint, Zeroizing::new(kek));
        Ok(())
    }

    /// Mark this node as a BIB security acceptor (may be a waypoint).
    pub fn set_bib_acceptor(&mut self, accept: bool) {
        self.bib_acceptor = accept;
    }

    /// Set CRC type restored when acceptor ≠ destination (RFC9173-050/126).
    pub fn set_restore_crc_type(&mut self, crc: crate::bp::CrcType) {
        self.restore_crc_type = crc;
    }

    /// Set BIB failure policy (RFC 9172 §5.1.1)
    pub fn set_bib_failure_policy(&mut self, policy: SecurityFailurePolicy) {
        self.bib_failure_policy = policy;
    }

    /// Set BCB failure policy (RFC 9172 §5.1.1)
    pub fn set_bcb_failure_policy(&mut self, policy: SecurityFailurePolicy) {
        self.bcb_failure_policy = policy;
    }

    /// Set local policy for generation failures (RFC9173-040/111).
    pub fn set_generation_failure_policy(&mut self, policy: SecurityGenerationPolicy) {
        self.generation_failure_policy = policy;
    }
}

/// Parse BIB block data
#[derive(Debug)]
pub struct ParsedBib {
    /// Target block numbers protected by this BIB
    pub targets: Vec<u64>,
    /// Security context ID
    pub context_id: u64,
    _flags: u64,
    security_source: EndpointId,
    sha_variant: HmacVariant,
    wrapped_key: Option<Vec<u8>>,
    scope_flags: u8,
    results: Vec<Vec<u8>>,
}

/// Parse BCB block data
#[derive(Debug)]
pub struct ParsedBcb {
    /// Target block numbers protected by this BCB
    pub targets: Vec<u64>,
    /// Security context ID
    pub context_id: u64,
    _flags: u64,
    security_source: EndpointId,
    aes_variant: AesGcmVariant,
    iv: Vec<u8>,
    wrapped_key: Option<Vec<u8>>,
    scope_flags: u8,
    /// Authentication tag from BCB security results; `None` when the tag is
    /// carried in the target ciphertext (RFC 9173 §4.4 / RFC9173-070/071).
    auth_tag: Option<Vec<u8>>,
}

/// Parse BIB block data per RFC 9172 §3.6
pub fn parse_bib_block(block: &CanonicalBlock) -> Result<ParsedBib> {
    let mut cursor = Cursor::new(&block.data);

    // Parse targets array
    let targets_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB targets parse: {}", e)))?;
    let targets = match targets_val {
        Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                Value::Integer(n) => n
                    .try_into()
                    .map_err(|_| Error::protocol_violation("Invalid target number")),
                _ => Err(Error::protocol_violation("Target must be integer")),
            })
            .collect::<Result<Vec<u64>>>()?,
        _ => return Err(Error::protocol_violation("Targets must be array")),
    };

    // Parse context ID
    let context_id: u64 = match ciborium::from_reader(&mut cursor) {
        Ok(Value::Integer(n)) => n
            .try_into()
            .map_err(|_| Error::protocol_violation("Invalid context ID"))?,
        _ => return Err(Error::protocol_violation("Context ID must be integer")),
    };

    // Parse flags
    let flags: u64 = match ciborium::from_reader(&mut cursor) {
        Ok(Value::Integer(n)) => n
            .try_into()
            .map_err(|_| Error::protocol_violation("Invalid flags"))?,
        _ => return Err(Error::protocol_violation("Flags must be integer")),
    };

    // Parse security source
    let source_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB source parse: {}", e)))?;
    let security_source = parse_eid_from_cbor(&source_val)?;

    // Parse parameters (SHA variant, wrapped key (optional), and scope flags)
    let params_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB params parse: {}", e)))?;
    let (sha_variant, wrapped_key, scope_flags) = parse_bib_params(&params_val)?;

    // Parse results
    let results_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BIB results parse: {}", e)))?;
    let results = parse_bib_results(&results_val)?;

    if results.len() != targets.len() {
        return Err(Error::protocol_violation(
            "BIB results count must match targets count",
        ));
    }

    Ok(ParsedBib {
        targets,
        context_id,
        _flags: flags,
        security_source,
        sha_variant,
        wrapped_key,
        scope_flags,
        results,
    })
}

/// Parse BCB block data per RFC 9172 §4.4
pub fn parse_bcb_block(block: &CanonicalBlock) -> Result<ParsedBcb> {
    let mut cursor = Cursor::new(&block.data);

    // Parse targets array
    let targets_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BCB targets parse: {}", e)))?;
    let targets = match targets_val {
        Value::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                Value::Integer(n) => n
                    .try_into()
                    .map_err(|_| Error::protocol_violation("Invalid target number")),
                _ => Err(Error::protocol_violation("Target must be integer")),
            })
            .collect::<Result<Vec<u64>>>()?,
        _ => return Err(Error::protocol_violation("Targets must be array")),
    };

    // Parse context ID
    let context_id: u64 = match ciborium::from_reader(&mut cursor) {
        Ok(Value::Integer(n)) => n
            .try_into()
            .map_err(|_| Error::protocol_violation("Invalid context ID"))?,
        _ => return Err(Error::protocol_violation("Context ID must be integer")),
    };

    // Parse flags
    let flags: u64 = match ciborium::from_reader(&mut cursor) {
        Ok(Value::Integer(n)) => n
            .try_into()
            .map_err(|_| Error::protocol_violation("Invalid flags"))?,
        _ => return Err(Error::protocol_violation("Flags must be integer")),
    };

    // Parse security source
    let source_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BCB source parse: {}", e)))?;
    let security_source = parse_eid_from_cbor(&source_val)?;

    // Parse parameters (AES variant, IV, wrapped key, scope flags)
    let params_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BCB params parse: {}", e)))?;
    let (aes_variant, iv, wrapped_key, scope_flags) = parse_bcb_params(&params_val)?;

    // Parse results (authentication tag)
    let results_val: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| Error::protocol_violation(format!("BCB results parse: {}", e)))?;
    let auth_tag = parse_bcb_results(&results_val)?;

    Ok(ParsedBcb {
        targets,
        context_id,
        _flags: flags,
        security_source,
        aes_variant,
        iv,
        wrapped_key,
        scope_flags,
        auth_tag,
    })
}

/// Parse EID from CBOR value
fn parse_eid_from_cbor(val: &Value) -> Result<EndpointId> {
    match val {
        Value::Array(arr) if arr.len() == 2 || arr.len() == 3 => {
            // IPN EID [scheme, node, service?]
            let scheme = match &arr[0] {
                Value::Integer(n) => {
                    let scheme_num: i128 = (*n).into();
                    if scheme_num != 2 {
                        return Err(Error::protocol_violation(format!(
                            "Unsupported EID scheme: {}",
                            scheme_num
                        )));
                    }
                    scheme_num
                }
                _ => return Err(Error::protocol_violation("EID scheme must be integer")),
            };

            if scheme == 2 {
                // IPN scheme - RFC 9758 encoding
                // [2, N] = ipn:0.N.0 (allocator=0, node=N, service=0)
                // [2, N, S] = ipn:0.N.S (allocator=0, node=N, service=S)
                match arr.len() {
                    2 => {
                        // [2, node_num] = ipn:0.node_num.0 (compressed form)
                        // OR [2, Array([node, service])] for non-zero service
                        match &arr[1] {
                            Value::Integer(n) => {
                                // Simple form: [2, node] = ipn:0.node.0
                                let combined: i128 = (*n).into();
                                let node: u64 = combined
                                    .try_into()
                                    .map_err(|_| Error::protocol_violation("Invalid IPN node"))?;
                                EndpointId::ipn(0, node, 0).map_err(|e| {
                                    Error::protocol_violation(format!("Invalid IPN EID: {}", e))
                                })
                            }
                            Value::Array(ssp_arr) if ssp_arr.len() == 2 => {
                                // Array form: [2, [node, service]]
                                let node: u64 = match &ssp_arr[0] {
                                    Value::Integer(n) => {
                                        let val: i128 = (*n).into();
                                        val.try_into().map_err(|_| {
                                            Error::protocol_violation("Invalid IPN node")
                                        })?
                                    }
                                    _ => {
                                        return Err(Error::protocol_violation(
                                            "IPN node must be integer",
                                        ));
                                    }
                                };
                                let service: u64 = match &ssp_arr[1] {
                                    Value::Integer(n) => {
                                        let val: i128 = (*n).into();
                                        val.try_into().map_err(|_| {
                                            Error::protocol_violation("Invalid IPN service")
                                        })?
                                    }
                                    _ => {
                                        return Err(Error::protocol_violation(
                                            "IPN service must be integer",
                                        ));
                                    }
                                };
                                EndpointId::ipn(0, node, service).map_err(|e| {
                                    Error::protocol_violation(format!("Invalid IPN EID: {}", e))
                                })
                            }
                            _ => Err(Error::protocol_violation("Invalid IPN SSP format")),
                        }
                    }
                    3 => {
                        // [2, node, service]
                        let node: u64 = match &arr[1] {
                            Value::Integer(n) => {
                                let val: i128 = (*n).into();
                                val.try_into()
                                    .map_err(|_| Error::protocol_violation("Invalid IPN node"))?
                            }
                            _ => return Err(Error::protocol_violation("IPN node must be integer")),
                        };
                        let service: u64 = match &arr[2] {
                            Value::Integer(n) => {
                                let val: i128 = (*n).into();
                                val.try_into()
                                    .map_err(|_| Error::protocol_violation("Invalid IPN service"))?
                            }
                            _ => {
                                return Err(Error::protocol_violation(
                                    "IPN service must be integer",
                                ));
                            }
                        };
                        EndpointId::ipn(0, node, service).map_err(|e| {
                            Error::protocol_violation(format!("Invalid IPN EID: {}", e))
                        })
                    }
                    _ => Err(Error::protocol_violation("Invalid IPN EID array length")),
                }
            } else {
                Err(Error::protocol_violation("Unsupported EID scheme"))
            }
        }
        _ => Err(Error::protocol_violation("EID must be array")),
    }
}

/// Parse BIB parameters: (sha_variant, wrapped_key, scope_flags)
/// RFC 9173 §3.3.2: wrapped key (parameter ID 2) is optional
fn parse_bib_params(params: &Value) -> Result<(HmacVariant, Option<Vec<u8>>, u8)> {
    let arr = match params {
        Value::Array(a) => a,
        _ => return Err(Error::protocol_violation("BIB params must be array")),
    };

    let mut sha_variant = None;
    let mut wrapped_key = None;
    let mut scope_flags = None;

    for param in arr {
        let param_arr = match param {
            Value::Array(a) if a.len() == 2 => a,
            _ => continue,
        };

        let param_id: u64 = match &param_arr[0] {
            Value::Integer(n) => (*n)
                .try_into()
                .map_err(|_| Error::protocol_violation("Invalid param ID"))?,
            _ => continue,
        };

        match param_id {
            1 => {
                // SHA variant (parameter ID 1)
                let variant_num: u64 = match &param_arr[1] {
                    Value::Integer(n) => (*n)
                        .try_into()
                        .map_err(|_| Error::protocol_violation("Invalid SHA variant"))?,
                    _ => return Err(Error::protocol_violation("SHA variant must be integer")),
                };
                sha_variant = Some(match variant_num {
                    5 => HmacVariant::Sha256,
                    6 => HmacVariant::Sha384,
                    7 => HmacVariant::Sha512,
                    _ => {
                        return Err(Error::protocol_violation(format!(
                            "Unknown SHA variant: {}",
                            variant_num
                        )));
                    }
                });
            }
            2 => {
                // Wrapped key (parameter ID 2) - RFC 9173 §3.3.2
                let key_bytes = match &param_arr[1] {
                    Value::Bytes(b) => b.clone(),
                    _ => return Err(Error::protocol_violation("Wrapped key must be bytes")),
                };
                wrapped_key = Some(key_bytes);
            }
            3 => {
                // Scope flags (parameter ID 3)
                let flags: u8 = match &param_arr[1] {
                    Value::Integer(n) => (*n)
                        .try_into()
                        .map_err(|_| Error::protocol_violation("Invalid scope flags"))?,
                    _ => return Err(Error::protocol_violation("Scope flags must be integer")),
                };
                scope_flags = Some(flags);
            }
            _ => {}
        }
    }

    // RFC 9173 §3.3.1 Table 1: When SHA variant not provided, default to 6 (HMAC 384/384)
    // RFC 9173 §3.3.3 / RFC9173-016: When integrity scope flags not provided, default to 7
    Ok((
        sha_variant.unwrap_or(HmacVariant::Sha384),
        wrapped_key,
        scope_flags.unwrap_or(0x07),
    ))
}

/// Parsed BCB parameters: (aes_variant, iv, wrapped_key, scope_flags)
type BcbParams = (AesGcmVariant, Vec<u8>, Option<Vec<u8>>, u8);

/// Parse BCB parameters
fn parse_bcb_params(params: &Value) -> Result<BcbParams> {
    let arr = match params {
        Value::Array(a) => a,
        _ => return Err(Error::protocol_violation("BCB params must be array")),
    };

    let mut aes_variant = None;
    let mut iv = None;
    let mut wrapped_key = None;
    let mut scope_flags = None;

    for param in arr {
        let param_arr = match param {
            Value::Array(a) if a.len() == 2 => a,
            _ => continue,
        };

        let param_id: u64 = match &param_arr[0] {
            Value::Integer(n) => (*n)
                .try_into()
                .map_err(|_| Error::protocol_violation("Invalid param ID"))?,
            _ => continue,
        };

        match param_id {
            1 => {
                // IV (initialization vector) - parameter ID 1
                let iv_bytes = match &param_arr[1] {
                    Value::Bytes(b) => b.clone(),
                    _ => return Err(Error::protocol_violation("IV must be bytes")),
                };
                // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
                // encoding, MUST be between 8-16 bytes."
                if iv_bytes.len() < 8 || iv_bytes.len() > 16 {
                    return Err(Error::protocol_violation(format!(
                        "RFC 9173 §4.3.1: IV must be between 8-16 bytes, got {} bytes",
                        iv_bytes.len()
                    )));
                }
                iv = Some(iv_bytes);
            }
            2 => {
                // AES variant - parameter ID 2
                let variant_num: u64 = match &param_arr[1] {
                    Value::Integer(n) => {
                        let val: i128 = (*n).into();
                        val.try_into()
                            .map_err(|_| Error::protocol_violation("Invalid AES variant"))?
                    }
                    _ => return Err(Error::protocol_violation("AES variant must be integer")),
                };
                aes_variant = Some(match variant_num {
                    1 => AesGcmVariant::Aes128,
                    3 => AesGcmVariant::Aes256,
                    _ => {
                        return Err(Error::protocol_violation(format!(
                            "Unknown AES variant: {}",
                            variant_num
                        )));
                    }
                });
            }
            3 => {
                // Wrapped key (RFC 9173 §4.3.3) - parameter ID 3
                let key_bytes = match &param_arr[1] {
                    Value::Bytes(b) => b.clone(),
                    _ => return Err(Error::protocol_violation("Wrapped key must be bytes")),
                };
                wrapped_key = Some(key_bytes);
            }
            4 => {
                // Scope flags - parameter ID 4
                let flags: u8 = match &param_arr[1] {
                    Value::Integer(n) => {
                        let val: i128 = (*n).into();
                        val.try_into()
                            .map_err(|_| Error::protocol_violation("Invalid scope flags"))?
                    }
                    _ => return Err(Error::protocol_violation("Scope flags must be integer")),
                };
                scope_flags = Some(flags);
            }
            _ => {}
        }
    }

    // RFC 9173 §4.3.1 Table 4: When AES variant not provided, default to 3 (A256GCM)
    Ok((
        aes_variant.unwrap_or(AesGcmVariant::Aes256),
        iv.ok_or_else(|| Error::protocol_violation("BCB missing IV"))?,
        wrapped_key,
        scope_flags.unwrap_or(0),
    ))
}

/// Parse BIB results (array of signature arrays)
fn parse_bib_results(results: &Value) -> Result<Vec<Vec<u8>>> {
    let results_arr = match results {
        Value::Array(a) => a,
        _ => return Err(Error::protocol_violation("BIB results must be array")),
    };

    let mut signatures = Vec::new();
    for result_set in results_arr {
        let result_arr = match result_set {
            Value::Array(a) => a,
            _ => return Err(Error::protocol_violation("Result set must be array")),
        };

        for result in result_arr {
            let result_pair = match result {
                Value::Array(a) if a.len() == 2 => a,
                _ => continue,
            };

            let result_id: u64 = match &result_pair[0] {
                Value::Integer(n) => (*n)
                    .try_into()
                    .map_err(|_| Error::protocol_violation("Invalid result ID"))?,
                _ => continue,
            };

            if result_id == 1 {
                // Signature result
                let sig = match &result_pair[1] {
                    Value::Bytes(b) => b.clone(),
                    _ => return Err(Error::protocol_violation("Signature must be bytes")),
                };
                signatures.push(sig);
            }
        }
    }

    Ok(signatures)
}

/// Parse BCB results (authentication tag). Returns `None` when the tag is
/// carried with the ciphertext in the security target (RFC9173-070/071).
fn parse_bcb_results(results: &Value) -> Result<Option<Vec<u8>>> {
    let results_arr = match results {
        Value::Array(a) => a,
        _ => return Err(Error::protocol_violation("BCB results must be array")),
    };

    // Empty results array: tag-in-ciphertext mode (RFC 9173 §4.4.1)
    if results_arr.is_empty() {
        return Ok(None);
    }

    let result_set = match &results_arr[0] {
        Value::Array(a) => a,
        _ => return Err(Error::protocol_violation("BCB result set must be array")),
    };

    // Empty result set also means tag-in-ciphertext
    if result_set.is_empty() {
        return Ok(None);
    }

    for result in result_set {
        let result_pair = match result {
            Value::Array(a) if a.len() == 2 => a,
            _ => continue,
        };

        let result_id: u64 = match &result_pair[0] {
            Value::Integer(n) => (*n)
                .try_into()
                .map_err(|_| Error::protocol_violation("Invalid result ID"))?,
            _ => continue,
        };

        if result_id == 1 {
            // Authentication tag
            return match &result_pair[1] {
                Value::Bytes(b) => Ok(Some(b.clone())),
                _ => Err(Error::protocol_violation("Auth tag must be bytes")),
            };
        }
    }

    // No type-1 result: treat as tag-in-ciphertext
    Ok(None)
}

/// RFC 9172 §4.3: Process BIBs at verifier or acceptor
///
/// Verifies HMAC signatures and removes verified BIB operations.
/// Returns Ok if all verifications succeeded, Err if any failed.
pub fn process_bibs(
    bundle: &mut Bundle,
    ctx: &SecurityContext,
    is_destination: bool,
) -> Result<SecurityProcessingResult> {
    // RFC 9172 §4.3.3: BIB MUST NOT be processed if security target is also target of BCB
    let bcb_targets = get_bcb_targets(bundle);

    // Find all BIBs
    let bib_indices: Vec<usize> = bundle
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| matches!(b.block_type, BlockType::Bib))
        .map(|(i, _)| i)
        .collect();

    for bib_idx in bib_indices {
        let bib_block = &bundle.blocks[bib_idx];
        let bib_block_num = bib_block.block_number;

        // RFC 9172 §3.9 / §4.3.3: BIB integrity MUST NOT be checked if the BIB
        // itself is the security target of an existing BCB (BIB data is ciphertext).
        if bcb_targets.contains(&bib_block_num) {
            continue;
        }

        let parsed = parse_bib_block(bib_block)?;

        // RFC9173-129/130/131: compromised key → do not treat BIB as providing integrity
        if ctx.compromised_sources.contains(&parsed.security_source) {
            let t = parsed.targets.first().copied().unwrap_or(0);
            return Ok(SecurityProcessingResult::BibVerificationFailed {
                bib_block_num,
                target_block_num: t,
            });
        }

        // RFC 9173 §3.8.2: "The HMAC key MUST be derived using the wrapped key security
        // context parameter if such a parameter is included in the security context parameters"
        let working_key: Vec<u8>;
        let key = if let Some(ref wrapped_key) = parsed.wrapped_key {
            // Wrapped key present - must unwrap it
            let kek = match ctx.keks.get(&parsed.security_source) {
                Some(k) => k,
                None => {
                    // No KEK available to unwrap - skip this BIB
                    continue;
                }
            };
            // Unwrap the HMAC key using AES-KW per RFC 9173 §3.3.2
            working_key = super::super::security::keywrap::unwrap_key(kek, wrapped_key)?;
            &working_key
        } else {
            // No wrapped key - use direct HMAC key
            match ctx.hmac_keys.get(&parsed.security_source) {
                Some(k) => k,
                None => {
                    // No key available - skip this BIB (RFC 9172 §4.3.3: MAY verify)
                    continue;
                }
            }
        };

        // Verify each target
        for (target_idx, target_num) in parsed.targets.iter().enumerate() {
            // RFC 9172 §4.3.3: Skip if target is also BCB target
            if bcb_targets.contains(target_num) {
                continue;
            }

            let expected_mac = &parsed.results[target_idx];

            // Reconstruct IPPT per RFC 9173 §3.8 (include BIB security header when bit 2 set)
            let bib_flags = bundle.blocks[bib_idx].block_flags;
            let ippt = bib::construct_ippt_with_security_header(
                bundle,
                *target_num,
                parsed.scope_flags,
                Some((bib_block_num, bib_flags)),
            )?;

            // Compute HMAC on IPPT
            let hmac_ctx = HmacSha256Context::new(parsed.sha_variant);
            let computed_mac = hmac_ctx.sign(&ippt, key)?;

            // RFC9173-020: production constant-time tag compare
            let valid = crate::security::constant_time_eq(&computed_mac, expected_mac);

            if !valid {
                // RFC 9172 §4.3.4: If verification fails, process per security policy
                // For now, fail the bundle per strict policy
                return Ok(SecurityProcessingResult::BibVerificationFailed {
                    bib_block_num,
                    target_block_num: *target_num,
                });
            }
        }

        // RFC 9172 §4.3.4: If at destination and verification succeeds,
        // remove BIB (or specific operation)
        // For simplicity, we remove entire BIB after all targets verified
    }

    // RFC 9172 §5.1.2: security acceptor removes BIBs after processing.
    // Destination is always an acceptor; waypoints opt in via bib_acceptor.
    let remove_bibs = is_destination || ctx.bib_acceptor;
    if remove_bibs {
        // Capture targets of BIBs being removed for CRC restore (RFC9173-050)
        let mut targets_needing_crc: Vec<u64> = Vec::new();
        if !is_destination {
            for block in &bundle.blocks {
                if matches!(block.block_type, BlockType::Bib)
                    && let Ok(parsed) = parse_bib_block(block)
                {
                    targets_needing_crc.extend(parsed.targets);
                }
            }
        }

        bundle
            .blocks
            .retain(|b| !matches!(b.block_type, BlockType::Bib));

        // RFC9173-050: acceptor ≠ destination → restore CRC when no other integrity remains
        if !is_destination && ctx.restore_crc_type != crate::bp::CrcType::None {
            restore_crc_if_unprotected(bundle, &targets_needing_crc, ctx.restore_crc_type);
        }
    }

    Ok(SecurityProcessingResult::Success)
}

/// RFC9173-050/126: after acceptor removes the last integrity/confidentiality
/// service for a target and the node is not the destination, attach a CRC.
fn restore_crc_if_unprotected(bundle: &mut Bundle, targets: &[u64], crc_type: crate::bp::CrcType) {
    let remaining_protected = {
        let mut set = std::collections::HashSet::new();
        for block in &bundle.blocks {
            match block.block_type {
                BlockType::Bib => {
                    if let Ok(p) = parse_bib_block(block) {
                        set.extend(p.targets);
                    }
                }
                BlockType::Bcb => {
                    if let Ok(p) = parse_bcb_block(block) {
                        set.extend(p.targets);
                    }
                }
                _ => {}
            }
        }
        set
    };

    for &t in targets {
        if remaining_protected.contains(&t) {
            continue;
        }
        if let Some(block) = bundle.blocks.iter_mut().find(|b| b.block_number == t)
            && block.crc_type == crate::bp::CrcType::None
        {
            block.crc_type = crc_type;
        }
    }
}

/// RFC 9172 §5.1.1: Discard a non-payload security target and every security
/// block associated with that target (BIB/BCB whose target list includes it).
fn discard_target_and_associated_security_blocks(bundle: &mut Bundle, target_num: u64) {
    // Identify security blocks associated with this target before mutating.
    let mut security_block_nums = Vec::new();
    for block in &bundle.blocks {
        match block.block_type {
            BlockType::Bib => {
                if let Ok(parsed) = parse_bib_block(block)
                    && parsed.targets.contains(&target_num)
                {
                    security_block_nums.push(block.block_number);
                }
            }
            BlockType::Bcb => {
                if let Ok(parsed) = parse_bcb_block(block)
                    && parsed.targets.contains(&target_num)
                {
                    security_block_nums.push(block.block_number);
                }
            }
            _ => {}
        }
    }

    bundle
        .blocks
        .retain(|b| b.block_number != target_num && !security_block_nums.contains(&b.block_number));
}

fn is_payload_block(bundle: &Bundle, block_num: u64) -> bool {
    bundle
        .blocks
        .iter()
        .any(|b| b.block_number == block_num && matches!(b.block_type, BlockType::Payload))
}

/// RFC 9172 §4.4 / §5.1.1: Process BCBs at acceptor
///
/// Decrypts encrypted targets and removes BCBs on success.
/// If a non-payload target cannot be decrypted, that target and all security
/// blocks associated with it are discarded and processing continues (RFC9172-088).
/// Payload decryption failure returns [`SecurityProcessingResult::BcbDecryptionFailed`].
///
/// When `is_destination` is false, successful acceptance restores a CRC on
/// targets that no longer have integrity/confidentiality (RFC9173-126).
pub fn process_bcbs(
    bundle: &mut Bundle,
    ctx: &mut SecurityContext,
) -> Result<SecurityProcessingResult> {
    process_bcbs_ex(bundle, ctx, true)
}

/// Like [`process_bcbs`] with explicit destination flag for CRC restore.
pub fn process_bcbs_ex(
    bundle: &mut Bundle,
    ctx: &mut SecurityContext,
    is_destination: bool,
) -> Result<SecurityProcessingResult> {
    let mut restored_targets: Vec<u64> = Vec::new();
    // Process one BCB at a time so discard mutations stay consistent.
    loop {
        let bcb_idx = match bundle
            .blocks
            .iter()
            .position(|b| matches!(b.block_type, BlockType::Bcb))
        {
            Some(i) => i,
            None => {
                if !is_destination
                    && ctx.restore_crc_type != crate::bp::CrcType::None
                    && !restored_targets.is_empty()
                {
                    restore_crc_if_unprotected(bundle, &restored_targets, ctx.restore_crc_type);
                }
                return Ok(SecurityProcessingResult::Success);
            }
        };

        let bcb_block_num = bundle.blocks[bcb_idx].block_number;
        let parsed = parse_bcb_block(&bundle.blocks[bcb_idx])?;

        // RFC9173-129/130/131: compromised key → do not treat BCB as providing confidentiality
        if ctx.compromised_sources.contains(&parsed.security_source) {
            let t = parsed.targets.first().copied().unwrap_or(0);
            return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                bcb_block_num,
                target_block_num: t,
            });
        }

        // RFC9173-080: refuse further decrypts once per-key failure limit hit
        if let Some(limit) = ctx.max_failed_bcb_verifies_per_key {
            let fails = ctx
                .failed_bcb_verifies
                .get(&parsed.security_source)
                .copied()
                .unwrap_or(0);
            if fails >= limit {
                let t = parsed.targets[0];
                return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                    bcb_block_num,
                    target_block_num: t,
                });
            }
        }

        // RFC9173-081: reject replayed (security_source, IV) on decrypt path
        let iv_key_id = format!("{:?}", parsed.security_source).into_bytes();
        if !ctx.received_iv_registry.is_unused(&iv_key_id, &parsed.iv) {
            let t = parsed.targets[0];
            return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                bcb_block_num,
                target_block_num: t,
            });
        }

        // RFC 9173 §5.3: Determine decryption key
        let key: Vec<u8> = if let Some(wrapped_key) = &parsed.wrapped_key {
            let kek = match ctx.keks.get(&parsed.security_source) {
                Some(k) => k,
                None => {
                    let t = parsed.targets[0];
                    if is_payload_block(bundle, t) {
                        return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                            bcb_block_num,
                            target_block_num: t,
                        });
                    }
                    discard_target_and_associated_security_blocks(bundle, t);
                    continue;
                }
            };

            match crate::security::keywrap::unwrap_key(kek, wrapped_key) {
                Ok(unwrapped) => unwrapped,
                Err(_) => {
                    let t = parsed.targets[0];
                    if is_payload_block(bundle, t) {
                        return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                            bcb_block_num,
                            target_block_num: t,
                        });
                    }
                    discard_target_and_associated_security_blocks(bundle, t);
                    continue;
                }
            }
        } else {
            match ctx.aes_keys.get(&parsed.security_source) {
                Some(k) => k.to_vec(),
                None => {
                    let t = parsed.targets[0];
                    if is_payload_block(bundle, t) {
                        return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                            bcb_block_num,
                            target_block_num: t,
                        });
                    }
                    discard_target_and_associated_security_blocks(bundle, t);
                    continue;
                }
            }
        };

        let mut discard_target: Option<u64> = None;
        let mut decrypt_failed = false;
        for target_num in &parsed.targets {
            let target_block_idx = bundle
                .blocks
                .iter()
                .position(|b| b.block_number == *target_num)
                .ok_or_else(|| {
                    Error::protocol_violation(format!("BCB target {} not found", target_num))
                })?;

            let mut ciphertext = bundle.blocks[target_block_idx].data.clone();
            let aad = bcb::construct_aad(bundle, *target_num, bcb_block_num, parsed.scope_flags)?;

            // RFC9173-070/071: tag may be in BCB result OR trailing 16 bytes of ciphertext
            let (ct_body, auth_tag) = match &parsed.auth_tag {
                Some(tag) => (ciphertext, tag.clone()),
                None => {
                    if ciphertext.len() < 16 {
                        decrypt_failed = true;
                        if is_payload_block(bundle, *target_num) {
                            *ctx.failed_bcb_verifies
                                .entry(parsed.security_source.clone())
                                .or_insert(0) += 1;
                            return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                                bcb_block_num,
                                target_block_num: *target_num,
                            });
                        }
                        discard_target = Some(*target_num);
                        break;
                    }
                    let tag = ciphertext.split_off(ciphertext.len() - 16);
                    (ciphertext, tag)
                }
            };

            match AesGcmContext::decrypt(
                &key,
                &parsed.iv,
                &ct_body,
                &auth_tag,
                &aad,
                parsed.aes_variant,
            ) {
                Ok(pt) => {
                    bundle.blocks[target_block_idx].data = pt;
                }
                Err(_) => {
                    decrypt_failed = true;
                    *ctx.failed_bcb_verifies
                        .entry(parsed.security_source.clone())
                        .or_insert(0) += 1;
                    if is_payload_block(bundle, *target_num) {
                        return Ok(SecurityProcessingResult::BcbDecryptionFailed {
                            bcb_block_num,
                            target_block_num: *target_num,
                        });
                    }
                    // RFC9172-088: discard non-payload target + associated security blocks
                    discard_target = Some(*target_num);
                    break;
                }
            }
        }
        let _ = decrypt_failed;

        if let Some(t) = discard_target {
            discard_target_and_associated_security_blocks(bundle, t);
            continue;
        }

        // Record IV only after successful decrypt (RFC9173-081)
        let _ = ctx.received_iv_registry.register(&iv_key_id, &parsed.iv);

        // Successful decrypt of this BCB: remove it (RFC 9172 §5.1.1)
        restored_targets.extend(parsed.targets.iter().copied());
        bundle.blocks.retain(|b| b.block_number != bcb_block_num);
    }
}

/// Get all block numbers that are targets of BCBs
fn get_bcb_targets(bundle: &Bundle) -> std::collections::HashSet<u64> {
    let mut targets = std::collections::HashSet::new();

    for block in &bundle.blocks {
        if matches!(block.block_type, BlockType::Bcb)
            && let Ok(parsed) = parse_bcb_block(block)
        {
            targets.extend(parsed.targets);
        }
    }

    targets
}

// Unit tests are in tests/rfc9172_node_processing.rs
