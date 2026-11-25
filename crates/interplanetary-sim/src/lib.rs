//! Deterministic discrete-event simulation engine.
//!
//! Virtual time advances only by scheduled events. The event key is ordered by
//! `(time, microstep, phase, sequence)` so equal-time events stay reproducible.
//! Storage and queues are capacity-bounded via [`StorageManager`] / [`BundleStore`].
//!
//! [`Scenario`] is the integrated multi-node runner: contact plan + per-node
//! [`interplanetary_bpa::BundleAgent`] + [`interplanetary_routing::CgrRouter`]. Lower-level pieces
//! ([`SimEngine`], [`ContactPlan`], [`EventQueue`]) are available for custom harnesses.
//!
//! Enable with `sim-basic` (default). Cross-links: [`crate::routing`], [`crate::bpa`],
//! [`crate::tcpcl`] (with `tcpclv4-model`).

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

pub mod engine;
pub mod event;
pub mod ion_parser;

pub use engine::{QuiescentReason, SimConfig, SimEngine};
pub use event::{Event, EventKey, EventQueue, Phase, ScheduledEvent};
pub use interplanetary_contacts::{Contact, ContactId, ContactPlan, PlanVersion};
