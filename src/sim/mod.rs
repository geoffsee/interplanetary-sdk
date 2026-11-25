//! Deterministic discrete-event simulation engine.
//!
//! Virtual time advances only by scheduled events. The event key is ordered by
//! `(time, microstep, phase, sequence)` so equal-time events stay reproducible.
//! Storage and queues are capacity-bounded via [`StorageManager`] / [`BundleStore`].
//!
//! [`Scenario`] is the integrated multi-node runner: contact plan + per-node
//! [`crate::bpa::BundleAgent`] + [`crate::routing::CgrRouter`]. Lower-level pieces
//! ([`SimEngine`], [`ContactPlan`], [`EventQueue`]) are available for custom harnesses.
//!
//! Enable with `sim-basic` (default). Cross-links: [`crate::routing`], [`crate::bpa`],
//! [`crate::tcpcl`] (with `tcpclv4-model`).

pub mod contact;
pub mod engine;
pub mod event;
pub mod ion_parser;
pub mod scenario;
pub mod storage;

pub use contact::{Contact, ContactId, ContactPlan, PlanVersion};
pub use engine::{QuiescentReason, SimConfig, SimEngine};
pub use event::{Event, EventKey, EventQueue, Phase, ScheduledEvent};
pub use scenario::{Scenario, SimulationResult};
pub use storage::{BundleStore, StorageManager, StorageUsage};
