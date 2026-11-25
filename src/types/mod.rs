//! Foundational domain types shared by every module.
//!
//! - Identity: [`EndpointId`], [`NodeId`], [`BundleId`] (RFC 9171 / 9758)
//! - Time: [`SimInstant`], [`SimDuration`] (ns ticks), [`DtnTimeMs`] (2000-01-01 epoch)
//! - Units: [`Bytes`], [`BitsPerSecond`]
//! - Errors: [`Error`], [`ErrorKind`], [`Result`]
//!
//! ## Invariants
//!
//! - Constructors validate inputs; malformed or oversized values return [`Error`]
//! - Time and unit arithmetic is checked / saturating where overflow would be silent
//! - [`EndpointId`] `Display` is the URI form; use canonical bytes for security AAD/IPPT
//! - `Debug` / `Display` must not leak key material (keys live under [`crate::security`])
mod error;
mod ids;
mod time;
mod units;

pub use error::{Error, ErrorKind, Result};
pub use ids::{BundleId, CreationTimestamp, EndpointId, FragmentInfo, NodeId};
pub use time::{DtnTimeMs, EpochMapping, SimDuration, SimInstant};
pub use units::{BitsPerSecond, Bytes};

// Re-export common types for internal use
