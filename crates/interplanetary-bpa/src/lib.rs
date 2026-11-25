//! Bundle Protocol Agent (BPA) — RFC 9171 §5 lifecycle.
//!
//! Implements transmission, forwarding, delivery, deletion, retention constraints,
//! and administrative records (status reports). Pair with [`interplanetary_sdk_sync::Scenario`]
//! for multi-node inject → route → CLA → deliver loops.
//!
//! Wire codec lives in [`crate::bp`]; cryptographic contexts live in [`crate::security`].
//! Under `bpsec-default`, this module also exposes BPA-facing security policy types
//! ([`SecurityPolicy`]) that are distinct from [`interplanetary_security::SecurityPolicy`]
//! (rule tables for BIB/BCB application).
//!
//! Enable with `sim-basic` (default). BPSec fields on [`BundleAgent`] / [`BpaConfig`]
//! require `bpsec-default`.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

pub mod actions;
pub mod admin;
pub mod agent;
pub mod policy;

pub use actions::{BpaAction, ForwardDecision};
pub use admin::{AdminRecord, ReasonCode, StatusReport, bundle_flags};
#[cfg(feature = "bpsec-default")]
pub use agent::OutboundBcbConfig;
pub use agent::{BpaConfig, BundleAgent, BundleState, StateTransition};
pub use policy::StatusReportPolicy;
pub mod retention;
pub use retention::{RetentionConstraint, RetentionConstraintSet};
#[cfg(feature = "bpsec-default")]
pub mod security_policy;
#[cfg(feature = "bpsec-default")]
pub use security_policy::{
    SecurityAction, SecurityFailureReason, SecurityOperation, SecurityPolicy, SecurityPolicyRule,
    SecurityRole,
};
#[cfg(feature = "bpsec-default")]
pub mod security_processing;
#[cfg(feature = "bpsec-default")]
pub use security_processing::{
    BCB_AES_GCM_CONTEXT_ID, BIB_HMAC_SHA2_CONTEXT_ID, KekUsageRegistry, SecurityContext,
    SecurityFailurePolicy, SecurityGenerationPolicy, SecurityProcessingResult,
};
