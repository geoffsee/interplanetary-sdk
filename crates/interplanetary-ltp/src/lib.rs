//! Licklider Transmission Protocol, red-part subset of RFC 5326.
//!
//! This engine builds and accepts LTP segments. It does not open sockets.
//! A live node sends one segment per UDP datagram.
//!
//! In scope: red data, end-of-red-part, end-of-block, checkpoints, report
//! segments, report acknowledgments, and retransmission of reported gaps.
//! Out of scope: green data, session cancellation, security extensions, and
//! cookies. Client service id 1 is the Bundle Protocol service number.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

mod engine;
mod sdnv;
mod segment;

pub use engine::{HandleOut, LtpEngine};
pub use segment::{BUNDLE_SERVICE_ID, Segment, SessionId};
