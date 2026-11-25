//! Convergence-layer port shared by the protocol kernel and both runtimes.
//!
//! [`ConnectionManager`] is the synchronous scheduler the bundle agent uses for
//! RFC 9174 reconnect backoff. [`PeerConnectScheduler`] is the seam an async
//! runtime can implement without depending on the TCPCL session.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

mod conn_manager;
mod reconnect;

pub use conn_manager::{ConnectionManager, ConnectionResult, ConnectionState};
pub use reconnect::{ReconnectConfig, ReconnectScheduler, TimeMs};

/// Stub marker for a minimal transfer model (no behavior yet).
#[derive(Debug)]
pub struct BasicCla;

/// Stub marker for the TCPCLv4 model. The session state machine lives in `interplanetary-tcpcl`.
#[cfg(feature = "tcpclv4-model")]
#[derive(Debug)]
pub struct TcpclV4;

/// Peer connect and retry decisions, independent of the byte transport.
///
/// Method names differ from [`ConnectionManager`] so the sync scheduler can
/// implement this trait by forwarding, and an async runtime can implement it
/// without a TCPCL session type.
pub trait PeerConnectScheduler {
    /// Whether a connection attempt is allowed at `now_ms`.
    fn allow_attempt(&mut self, peer: &str, now_ms: TimeMs) -> ConnectionResult;

    /// Reset backoff after a session comes up.
    fn note_success(&mut self, peer: &str);

    /// Remember a failed attempt.
    fn note_failure(&mut self, peer: &str);
}

impl PeerConnectScheduler for ConnectionManager {
    fn allow_attempt(&mut self, peer: &str, now_ms: TimeMs) -> ConnectionResult {
        self.attempt_connect(peer, now_ms)
    }

    fn note_success(&mut self, peer: &str) {
        self.record_success(peer);
    }

    fn note_failure(&mut self, peer: &str) {
        self.record_failure(peer);
    }
}
