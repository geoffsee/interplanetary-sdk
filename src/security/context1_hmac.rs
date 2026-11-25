//! BPSec Context 1: HMAC Integrity (BIB) per RFC 9173 §4

use crate::bp::Bundle;
use crate::security::canonical::{SecurityTarget, canonicalize_for_bpsec};
use crate::types::Result;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

/// HMAC variant per RFC 9173 §3.3.1 Table 1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HmacVariant {
    /// HMAC 256/256 (RFC 8152 Table 7)
    Sha256 = 5,
    /// HMAC 384/384 (RFC 8152 Table 7) - default per RFC 9173
    Sha384 = 6,
    /// HMAC 512/512 (RFC 8152 Table 7)
    Sha512 = 7,
}

impl HmacVariant {
    /// Get HMAC output length in bytes
    pub fn output_len(&self) -> usize {
        match self {
            HmacVariant::Sha256 => 32,
            HmacVariant::Sha384 => 48,
            HmacVariant::Sha512 => 64,
        }
    }
}

/// HMAC key length validation policy
///
/// RFC 9173 §3.5 requires: "HMAC keys...MUST have a key length equal to the output of the HMAC."
/// However, RFC 9173 Appendix A informative examples use 16-byte keys for all variants,
/// conflicting with this normative requirement.
#[cfg(feature = "test-fixtures")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmacKeyLengthPolicy {
    /// Strict RFC 9173 §3.5 compliance (default for production)
    ///
    /// Keys must equal output length: 32 bytes (SHA-256), 48 bytes (SHA-384), 64 bytes (SHA-512)
    #[default]
    Strict,

    /// Allow RFC 9173 Appendix A test vector keys (non-conformant)
    ///
    /// Permits 16-byte keys to reproduce RFC's informative examples (A.1, A.3, A.4),
    /// which violate the normative §3.5 requirement. Available ONLY under test-fixtures feature.
    ///
    /// **WARNING:** This mode permits keys that violate RFC 9173 §3.5. Use only for
    /// reproducing the RFC's own test vectors. Never use in production.
    Rfc9173AppendixAVectors,
}

/// HMAC-SHA2 integrity context (Context 1)
pub(crate) struct HmacSha256Context {
    variant: HmacVariant,
    #[cfg(feature = "test-fixtures")]
    key_policy: HmacKeyLengthPolicy,
}

impl HmacSha256Context {
    pub(crate) fn new(variant: HmacVariant) -> Self {
        Self {
            variant,
            #[cfg(feature = "test-fixtures")]
            key_policy: HmacKeyLengthPolicy::Strict,
        }
    }

    #[cfg(feature = "test-fixtures")]
    pub(crate) fn with_key_policy(variant: HmacVariant, policy: HmacKeyLengthPolicy) -> Self {
        Self {
            variant,
            key_policy: policy,
        }
    }

    /// Validate key length per RFC 9173 §3.5 and configured policy
    fn validate_key_length(&self, key: &[u8]) -> Result<()> {
        #[cfg(feature = "test-fixtures")]
        if self.key_policy == HmacKeyLengthPolicy::Rfc9173AppendixAVectors {
            // Allow any key length for Appendix A vectors
            return Ok(());
        }

        // Strict mode: enforce §3.5
        let required_len = self.variant.output_len();
        if key.len() != required_len {
            return Err(crate::types::Error::security_failure(format!(
                "RFC 9173 §3.5: HMAC key must be {} bytes for {:?}, got {}",
                required_len,
                self.variant,
                key.len()
            )));
        }
        Ok(())
    }

    /// Sign data with HMAC (internal use only)
    pub(crate) fn sign(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        self.validate_key_length(key)?;

        let mac = match self.variant {
            HmacVariant::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            HmacVariant::Sha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            HmacVariant::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        };
        Ok(mac)
    }

    /// Compute HMAC per RFC 9173 §4.3
    // Used in test fixtures and may be needed for future verification modes
    #[allow(dead_code)]
    pub(crate) fn compute_hmac(
        key: &[u8],
        bundle: &Bundle,
        target: SecurityTarget,
        variant: HmacVariant,
    ) -> Result<Vec<u8>> {
        let ctx = Self::new(variant);
        ctx.validate_key_length(key)?;

        // Canonicalize target
        let canonical = canonicalize_for_bpsec(bundle, target)?;

        // Compute HMAC
        let mac = match variant {
            HmacVariant::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(&canonical);
                mac.finalize().into_bytes().to_vec()
            }
            HmacVariant::Sha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(&canonical);
                mac.finalize().into_bytes().to_vec()
            }
            HmacVariant::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(&canonical);
                mac.finalize().into_bytes().to_vec()
            }
        };

        Ok(mac)
    }

    /// Compute HMAC with explicit key policy (test-fixtures only)
    #[cfg(feature = "test-fixtures")]
    #[allow(dead_code)]
    pub(crate) fn compute_hmac_with_policy(
        key: &[u8],
        bundle: &Bundle,
        target: SecurityTarget,
        variant: HmacVariant,
        policy: HmacKeyLengthPolicy,
    ) -> Result<Vec<u8>> {
        let ctx = Self::with_key_policy(variant, policy);
        ctx.validate_key_length(key)?;

        // Canonicalize target
        let canonical = canonicalize_for_bpsec(bundle, target)?;

        // Compute HMAC
        let mac = match variant {
            HmacVariant::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(&canonical);
                mac.finalize().into_bytes().to_vec()
            }
            HmacVariant::Sha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(&canonical);
                mac.finalize().into_bytes().to_vec()
            }
            HmacVariant::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key length"))?;
                mac.update(&canonical);
                mac.finalize().into_bytes().to_vec()
            }
        };

        Ok(mac)
    }

    /// Verify HMAC
    // Used in test fixtures and may be needed for alternative verification paths
    #[allow(dead_code)]
    pub(crate) fn verify_hmac(
        key: &[u8],
        bundle: &Bundle,
        target: SecurityTarget,
        expected_mac: &[u8],
        variant: HmacVariant,
    ) -> Result<bool> {
        // RFC 9173 §3.5: Key length validation is enforced in compute_hmac
        let computed = Self::compute_hmac(key, bundle, target, variant)?;

        // RFC9173-020: single production constant-time compare
        Ok(super::constant_time_eq(&computed, expected_mac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp::BundleBuilder;
    use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

    #[test]
    fn test_hmac_sha256_compute() {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .build()
            .unwrap();

        let key = &[0x42u8; 32]; // Exactly 32 bytes for SHA-256
        let mac = HmacSha256Context::compute_hmac(
            key,
            &bundle,
            SecurityTarget::Block(1),
            HmacVariant::Sha256,
        )
        .unwrap();

        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_verify() {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .build()
            .unwrap();

        let key = &[0x42u8; 32]; // Exactly 32 bytes for SHA-256
        let mac = HmacSha256Context::compute_hmac(
            key,
            &bundle,
            SecurityTarget::Block(1),
            HmacVariant::Sha256,
        )
        .unwrap();

        let valid = HmacSha256Context::verify_hmac(
            key,
            &bundle,
            SecurityTarget::Block(1),
            &mac,
            HmacVariant::Sha256,
        )
        .unwrap();

        assert!(valid);
    }
}
