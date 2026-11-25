//! Convergence Layer Adapter (CLA) placeholders.
//!
//! This module does **not** implement a `ConvergenceLayer` trait or live I/O.
//! Operational TCPCLv4 modeling (virtual streams, session FSM, transfers) lives
//! in [`crate::tcpcl`] under the `tcpclv4-model` feature.
//!
//! The types here exist as named stubs for future CLA trait work and for
//! feature-gated API surface consistency with `sim-basic`.

/// Stub marker for a minimal transfer model (no behavior yet).
#[derive(Debug)]
pub struct BasicCla;

/// Stub marker; use [`crate::tcpcl`] for the TCPCLv4 state machine.
#[cfg(feature = "tcpclv4-model")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcpclv4-model")))]
#[derive(Debug)]
pub struct TcpclV4;
