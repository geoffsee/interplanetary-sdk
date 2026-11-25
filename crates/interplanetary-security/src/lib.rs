//! BPSec default security contexts (RFC 9172 / 9173, erratum 7002).
//!
//! Enable with `bpsec-default`. BPA lifecycle policy for when to require or apply
//! security is separate: see [`interplanetary_bpa::SecurityPolicy`] under the same feature.
//!
//! ## Public API
//!
//! - [`SecurityPolicy`], [`BibRule`], [`BcbRule`] — rule tables for BIB/BCB application
//! - [`KeyProvider`] / [`StaticKeyProvider`] — operational key lookup
//! - [`NonceRegistry`] — AES-GCM nonce uniqueness tracking
//!
//! ## Internal Implementation
//!
//! Low-level cryptographic contexts, canonical form construction, and BIB/BCB
//! generation are `pub(crate)` unless `test-fixtures` is enabled. Direct access
//! bypasses policy checks and is not supported for operational use.
//!
//! ## Test Fixtures (`test-fixtures`)
//!
//! [`FixtureKeyProvider`] provides deterministic, RFC-reproducible nonces
//! suitable **only** for test vectors — never for operational traffic.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

// Public API: Policy and key management
pub mod policy;
pub use policy::{ApplicableRules, BcbRule, BibRule, PolicyCondition, SecurityPolicy};

pub use ct_eq::constant_time_eq;
pub use keys::{KeyProvider, StaticKeyProvider};
pub use nonce::NonceRegistry;

mod ct_eq;

// Test-only exports (deterministic nonces unsafe for operational use)
#[cfg(any(test, feature = "test-fixtures"))]
pub use fixtures::FixtureKeyProvider;

#[cfg(feature = "test-fixtures")]
pub use context1_hmac::HmacKeyLengthPolicy;

// Public for OutboundBcbConfig / policy APIs (bpsec-default)
pub use context1_hmac::HmacVariant;
pub use context2_aesgcm::AesGcmVariant;

// Test-only access to IPPT/AAD construction (for RFC testing)
#[cfg(any(test, feature = "test-fixtures"))]
pub use bcb::construct_aad;
#[cfg(any(test, feature = "test-fixtures"))]
pub use bib::{construct_ippt, construct_ippt_with_security_header};

// Internal implementation modules
pub mod canonical;
// Re-exported for use in security_processing module (feature-gated)
#[allow(unused_imports)]
pub use canonical::SecurityTarget;
#[allow(missing_docs, missing_debug_implementations)]
pub mod context1_hmac;
#[allow(missing_docs, missing_debug_implementations)]
pub mod context2_aesgcm;

// Generation functions: public under test-fixtures; crate-visible for BundleAgent otherwise
pub mod bib;

pub mod bcb;

pub(crate) mod fixtures;

// Re-export keys module internals for internal use only
mod keys;
mod nonce;

// Export keywrap for tests
pub mod keywrap;

pub mod validation;

/// AES key size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeySize {
    /// 128-bit AES key
    Aes128,
    /// 256-bit AES key
    Aes256,
}
