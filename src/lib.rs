//! Pure-Rust library for delay-tolerant networking (DTN) modeling and simulation.
//!
//! Implements Bundle Protocol version 7 (BPv7) and related specs
//! (RFC 9171 / 9172 / 9173 / 9174 / 9758), plus experimental TIPTOP IP/QUIC profiles.
//!
//! The protocol kernel is synchronous and deterministic: each step is
//! `(state, event, clock) → (state′, effects)` with no sockets, TLS, or executor
//! inside that path. I/O and async runtimes belong in adapters around the kernel.
//!
//! # Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `bpv7` | yes | Bundle Protocol v7 wire codec and processing |
//! | `sim-basic` | yes | Discrete-event simulation engine, BPA, routing, CLA stubs |
//! | `bpsec-default` | no | BPSec HMAC / AES-GCM default contexts |
//! | `tcpclv4-model` | no | TCPCLv4 state machine over virtual streams |
//! | `tiptop-experimental` | no | Experimental IP/QUIC modeling (unstable) |
//! | `test-fixtures` | no | Deterministic test-vector helpers (not for production) |
//! | `stable-full` | meta | `bpv7` + `bpsec-default` + `sim-basic` + `tcpclv4-model` |
//! | `full` | meta | `stable-full` + `tiptop-experimental` |
//!
//! MSRV is the `rust-version` in `Cargo.toml` (currently nightly-pinned for local builds).
//!
//! # Architecture
//!
//! Modules are feature-gated; the public surface today is concrete types (not a
//! high-level `NetworkBuilder` facade):
//!
//! - [`types`] — identity, time, units, errors
//! - [`bp`] — BPv7 codec, blocks, CRC, fragmentation (`bpv7`)
//! - [`bpa`] — Bundle Protocol Agent lifecycle per RFC 9171 §5 (`sim-basic`)
//! - [`security`] — BPSec policy and key/nonce providers (`bpsec-default`)
//! - [`sim`] — discrete-event engine; [`sim::Scenario`] is the integrated runner
//! - [`routing`] — contact-graph and static routing (`sim-basic`)
//! - [`cla`] — CLA placeholders; real TCPCL modeling lives in [`tcpcl`]
//! - [`tcpcl`] — TCPCLv4 virtual-stream model (`tcpclv4-model`)
//! - [`tiptop`] — experimental IP/QUIC (`tiptop-experimental`)
//!
//! # Examples
//!
//! Parse an EID and compute a contact-graph route (doctests: `--features stable-full`):
//!
//! ```
//! use interplanetary_sdk::{
//!     routing::{CgrConfig, CgrRouter},
//!     sim::{Contact, ContactId, ContactPlan},
//!     types::*,
//! };
//!
//! # fn main() -> Result<()> {
//! let eid = EndpointId::ipn(0, 1, 1)?;
//! assert_eq!(eid.scheme(), "ipn");
//!
//! let mut plan = ContactPlan::new();
//! plan.add_contact(Contact {
//!     id: ContactId(1),
//!     from_node: NodeId::ipn(0, 1),
//!     to_node: NodeId::ipn(0, 2),
//!     start: SimInstant::ZERO,
//!     end: SimInstant::from_nanos(10_000_000_000),
//!     rate: BitsPerSecond::from_kbps(8)?,
//!     delay: SimDuration::from_secs(4),
//!     resource_group: None,
//! });
//!
//! let route = CgrRouter::new(CgrConfig::default()).compute_route(
//!     &NodeId::ipn(0, 1),
//!     &NodeId::ipn(0, 2),
//!     Bytes(1000),
//!     SimInstant::ZERO,
//!     &plan,
//! )?;
//! assert_eq!(route.next_hop, NodeId::ipn(0, 2));
//! # Ok(())
//! # }
//! ```
//!
//! End-to-end inject → deliver: see [`sim::Scenario`]. Longer contact plans live
//! under `examples/` (`three_node.rs`, `three_node_integrated.rs`, `expiry_demo.rs`).

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod types;

#[cfg(feature = "bpv7")]
#[cfg_attr(docsrs, doc(cfg(feature = "bpv7")))]
pub mod bp;

#[cfg(feature = "bpsec-default")]
#[cfg_attr(docsrs, doc(cfg(feature = "bpsec-default")))]
pub mod security;

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod sim;

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod bpa;

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod routing;

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod cla;

#[cfg(feature = "tcpclv4-model")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcpclv4-model")))]
pub mod tcpcl;

#[cfg(feature = "tiptop-experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "tiptop-experimental")))]
pub mod tiptop;

// Re-export commonly used types
pub use types::{
    BitsPerSecond, BundleId, Bytes, CreationTimestamp, DtnTimeMs, EndpointId, Error, NodeId,
    Result, SimDuration, SimInstant,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capabilities report: which Cargo features are enabled in this build.
///
/// Use [`Capabilities::current`] to inspect the active profile at runtime.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// BPv7 protocol support (`bpv7`)
    pub bpv7: bool,
    /// BPSec default contexts (`bpsec-default`)
    pub bpsec: bool,
    /// Discrete-event simulation (`sim-basic`)
    pub simulation: bool,
    /// TCPCLv4 model (`tcpclv4-model`)
    pub tcpclv4: bool,
    /// TIPTOP experimental (`tiptop-experimental`)
    pub tiptop_experimental: bool,
    /// Reserved: async adapter facade is not shipped yet (always `false`)
    pub async_adapter: bool,
}

impl Capabilities {
    /// Report which features are compiled into this binary
    pub fn current() -> Self {
        Self {
            bpv7: cfg!(feature = "bpv7"),
            bpsec: cfg!(feature = "bpsec-default"),
            simulation: cfg!(feature = "sim-basic"),
            tcpclv4: cfg!(feature = "tcpclv4-model"),
            tiptop_experimental: cfg!(feature = "tiptop-experimental"),
            async_adapter: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_reporting() {
        let caps = Capabilities::current();
        #[cfg(feature = "bpv7")]
        assert!(caps.bpv7);
        #[cfg(feature = "sim-basic")]
        assert!(caps.simulation);
    }
}
