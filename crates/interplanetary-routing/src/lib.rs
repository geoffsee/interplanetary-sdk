//! Contact-aware routing and forwarding decisions.
//!
//! Concrete routers (no shared `Router` trait yet):
//!
//! - [`CgrRouter`] — earliest-arrival contact-graph approximation (not full ION CGR)
//! - [`MultiLabelSolver`] — Pareto multi-objective search over route labels
//! - [`StaticRouter`] — fixed destination → next-hop table
//! - [`PathOracle`] — enumerated-path verification helper
//! - [`VolumeTracker`] — contact volume / reservation accounting
//!
//! Enable with `sim-basic` (default). Used by [`interplanetary_sdk_sync::Scenario`] for
//! forward-path selection against a [`interplanetary_contacts::ContactPlan`].

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

pub mod cgr;
pub mod multilabel;
pub mod oracle;
pub mod static_route;
pub mod volume;

pub use cgr::{CgrConfig, CgrRouter, RouteInfo};
pub use multilabel::{MultiLabelSolver, ParetoRoute, ParetoSearchResult, RouteLabel};
pub use oracle::{EnumeratedPath, PathOracle, VerificationResult};
pub use static_route::StaticRouter;
pub use volume::{VolumeReservation, VolumeTracker};
