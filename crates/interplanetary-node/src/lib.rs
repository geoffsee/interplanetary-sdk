//! Live bundle node.
//!
//! The protocol kernel stays synchronous. This crate owns sockets and the wall
//! clock, and calls the kernel with explicit inputs.
//!
//! * TCP carries TCPCLv4 (RFC 9174), with mutual TLS after the contact header.
//! * UDP carries one BPv7 bundle per datagram.
//! * LTP carries a bundle as a red-part block (RFC 5326) over UDP.
//!
//! The bundle store is in memory. A restart drops stored bundles. Scheduled
//! contacts and foreign-stack interoperability are not claimed here.
//! Behavior and limits: `dev/docs/internal/live-node.md` in the repository.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

mod node;
mod tcp;
mod tls;

pub use node::{DeliveredBundle, Node, NodeConfig, Peer, TlsMode, Transport};
