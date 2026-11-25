//! TCPCLv4 convergence layer model per RFC 9174.
//!
//! Virtual ordered byte-stream model — **not** real TCP sockets, TLS stacks, or
//! cryptography. Enable with `tcpclv4-model`. The [`crate::cla`] module only holds
//! name stubs; this module is the implementation to use from BPA / scenarios.
//!
//! ## RFC 9174 Coverage
//!
//! - §3: Contact initialization
//! - §4: Session lifecycle and state machine
//! - §5: Message types (all 7 types)
//! - §6: Transfer mechanism with segmentation
//!
//! ## Simulated vs Real
//!
//! - [`VirtualStream`] / [`StreamPair`] instead of TCP sockets
//! - TLS appears as explicit simulated outcomes only
//! - No actual cryptography or OS networking

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

pub mod clock;
pub mod messages;
pub mod session;
pub mod session_fsm;
pub mod stream;

pub use clock::{Clock, ManualClock, TimeMs};
pub use interplanetary_cla::{ConnectionManager, ConnectionResult, ConnectionState};
pub use interplanetary_cla::{ReconnectConfig, ReconnectScheduler};
pub use messages::{
    ContactHeader, ExtensionItem, Message, refuse_reason, reject_reason, term_reason,
    transfer_flags,
};
pub use session::{SessionConfig, SessionError, SessionState, TcpclSession};
pub use session_fsm::Role;
pub use stream::{CloseKind, StreamPair, VirtualStream};
