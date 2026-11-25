//! Pure-Rust library for delay-tolerant networking (DTN) modeling and simulation.
//!
//! Implements Bundle Protocol version 7 (BPv7) and related specs
//! (RFC 9171 / 9172 / 9173 / 9174 / 9758), plus experimental TIPTOP IP/QUIC profiles.
//!
//! The protocol kernel is synchronous and deterministic: each step is
//! `(state, event, clock) → (state′, effects)` with no sockets, TLS, or executor
//! inside that path. Domain crates own that kernel. [`sim`] is the synchronous
//! runner. [`async_adapter`] drives the same kernel from Tokio.
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
//! | `async-adapter` | no | Tokio driver over the synchronous kernel |
//! | `stable-full` | meta | `bpv7` + `bpsec-default` + `sim-basic` + `tcpclv4-model` |
//! | `full` | meta | `stable-full` + `tiptop-experimental` + `async-adapter` |
//!
//! MSRV is the `rust-version` in `Cargo.toml` (currently nightly-pinned for local builds).
//!
//! # Architecture
//!
//! Modules are feature-gated re-exports of domain crates. The public surface is
//! concrete types (not a high-level `NetworkBuilder` facade):
//!
//! - [`types`] — identity, time, units, errors
//! - [`bp`] — BPv7 codec, blocks, CRC, fragmentation (`bpv7`)
//! - [`bpa`] — Bundle Protocol Agent lifecycle per RFC 9171 §5 (`sim-basic`)
//! - [`security`] — BPSec policy and key/nonce providers (`bpsec-default`)
//! - [`sim`] — discrete-event engine; [`sim::Scenario`] is the integrated runner
//! - [`routing`] — contact-graph and static routing (`sim-basic`)
//! - [`cla`] — CLA port and placeholders; TCPCL modeling lives in [`tcpcl`]
//! - [`tcpcl`] — TCPCLv4 virtual-stream model (`tcpclv4-model`)
//! - [`tiptop`] — experimental IP/QUIC (`tiptop-experimental`)
//! - [`async_adapter`] — Tokio driver (`async-adapter`)
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

pub mod types {
    //! Identity, time, units, and errors.
    pub use interplanetary_types::*;
}

#[cfg(feature = "bpv7")]
#[cfg_attr(docsrs, doc(cfg(feature = "bpv7")))]
pub mod bp {
    //! Bundle Protocol v7 codec and block processing.
    pub use interplanetary_bp::*;
    pub use interplanetary_bp::{
        blocks, bundle, cbor_encoding, codec, crc, extensions, fragment, processing,
    };
}

#[cfg(feature = "bpsec-default")]
#[cfg_attr(docsrs, doc(cfg(feature = "bpsec-default")))]
pub mod security {
    //! BPSec default contexts.
    #[cfg(feature = "test-fixtures")]
    pub use interplanetary_security::HmacKeyLengthPolicy;
    pub use interplanetary_security::{
        AesGcmVariant, AesKeySize, ApplicableRules, BcbRule, BibRule, HmacVariant, KeyProvider,
        NonceRegistry, PolicyCondition, SecurityPolicy, StaticKeyProvider, constant_time_eq,
        policy, validation,
    };
    #[cfg(any(test, feature = "test-fixtures"))]
    pub use interplanetary_security::{
        FixtureKeyProvider, bcb, bib, construct_aad, construct_ippt,
        construct_ippt_with_security_header, keywrap,
    };
}

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod sim {
    //! Discrete-event engine, contact plan, bundle store, and the sync scenario runner.
    pub use interplanetary_contacts::{Contact, ContactId, ContactPlan, PlanVersion};
    pub use interplanetary_sdk_sync::{Scenario, SimulationResult};
    pub use interplanetary_sim::*;
    pub use interplanetary_sim::{engine, event, ion_parser};
    pub use interplanetary_store::{BundleStore, StorageManager, StorageUsage};
}

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod bpa {
    //! Bundle Protocol Agent.
    pub use interplanetary_bpa::*;
    pub use interplanetary_bpa::{actions, admin, agent, policy, retention};
    #[cfg(feature = "bpsec-default")]
    pub use interplanetary_bpa::{security_policy, security_processing};
}

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod routing {
    //! Contact-graph and static routing.
    pub use interplanetary_routing::*;
    pub use interplanetary_routing::{cgr, multilabel, oracle, static_route, volume};
}

#[cfg(feature = "sim-basic")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim-basic")))]
pub mod cla {
    //! Convergence-layer port and name stubs.
    #[cfg(feature = "tcpclv4-model")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tcpclv4-model")))]
    pub use interplanetary_cla::TcpclV4;
    pub use interplanetary_cla::{BasicCla, PeerConnectScheduler};
}

#[cfg(feature = "tcpclv4-model")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcpclv4-model")))]
pub mod tcpcl {
    //! TCPCLv4 virtual-stream model.
    pub use interplanetary_tcpcl::*;
    pub use interplanetary_tcpcl::{clock, messages, session, session_fsm, stream};
}

#[cfg(feature = "tiptop-experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "tiptop-experimental")))]
pub mod tiptop {
    //! Experimental TIPTOP IP/QUIC models.
    pub use interplanetary_tiptop::*;
}

#[cfg(feature = "async-adapter")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-adapter")))]
pub mod async_adapter {
    //! Tokio driver over the synchronous kernel.
    pub use interplanetary_sdk_async::*;
}

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
    /// Tokio driver (`async-adapter`)
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
            async_adapter: cfg!(feature = "async-adapter"),
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
        #[cfg(feature = "async-adapter")]
        assert!(caps.async_adapter);
    }
}
