//! Tokio driver for the synchronous DTN kernel.
//!
//! [`AsyncSimulation`] runs [`interplanetary_sdk_sync::Scenario`] on blocking
//! threads. Encoding, BPA transitions, and contact-graph routing stay in the
//! domain crates. This crate does not open sockets.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

use std::sync::{Arc, Mutex};

use interplanetary_bp::Bundle;
use interplanetary_contacts::ContactPlan;
use interplanetary_sdk_sync::{Scenario, SimulationResult};
use interplanetary_types::{BundleId, Bytes, NodeId, Result};
use tokio::task::spawn_blocking;

/// Async handle for one synchronous [`Scenario`].
///
/// Methods wait on a blocking worker so the kernel never needs an executor.
/// Clone shares the same scenario. Calls run one at a time.
#[derive(Clone, Debug)]
pub struct AsyncSimulation {
    inner: Arc<Mutex<Scenario>>,
}

impl AsyncSimulation {
    /// Create a scenario from a contact plan.
    ///
    /// `storage_per_node` is accepted for parity with [`Scenario::new`]. Node
    /// capacity is set again in [`Self::add_node`].
    pub fn new(plan: ContactPlan, storage_per_node: Bytes) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Scenario::new(plan, storage_per_node))),
        }
    }

    /// Add a node with its own bundle store.
    pub async fn add_node(&self, node_id: NodeId, storage_capacity: Bytes) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking(move || {
            inner
                .lock()
                .expect("simulation lock")
                .add_node(node_id, storage_capacity)
        })
        .await
        .expect("blocking simulation task")
    }

    /// Admit `bundle` at `node_id` and schedule its forwarding.
    pub async fn inject_bundle(&self, node_id: NodeId, bundle: Bundle) -> Result<BundleId> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking(move || {
            inner
                .lock()
                .expect("simulation lock")
                .inject_bundle(&node_id, bundle)
        })
        .await
        .expect("blocking simulation task")
    }

    /// Drive the kernel until the event queue is empty or the budget is spent.
    pub async fn run(&self) -> Result<SimulationResult> {
        let inner = Arc::clone(&self.inner);
        spawn_blocking(move || inner.lock().expect("simulation lock").run())
            .await
            .expect("blocking simulation task")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use interplanetary_bp::{BundleAgeBlock, BundleBuilder, CrcType};
    use interplanetary_contacts::{Contact, ContactId};
    use interplanetary_types::{
        BitsPerSecond, CreationTimestamp, DtnTimeMs, EndpointId, SimDuration, SimInstant,
    };

    #[tokio::test]
    async fn two_node_hop_awaits_the_sync_kernel() {
        let mut plan = ContactPlan::new();
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(60_000_000_000),
            rate: BitsPerSecond::from_kbps(8).unwrap(),
            delay: SimDuration::from_secs(1),
            resource_group: None,
        });

        let sim = AsyncSimulation::new(plan, Bytes::from_mib(1).unwrap());
        sim.add_node(NodeId::ipn(0, 1), Bytes::from_mib(1).unwrap())
            .await
            .unwrap();
        sim.add_node(NodeId::ipn(0, 2), Bytes::from_mib(1).unwrap())
            .await
            .unwrap();

        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"hello mars".to_vec())
            .crc_type(CrcType::Crc16)
            .build()
            .unwrap();
        bundle
            .blocks
            .push(BundleAgeBlock::new(2, 0).to_canonical().unwrap());

        let id = sim.inject_bundle(NodeId::ipn(0, 1), bundle).await.unwrap();
        let result = sim.run().await.unwrap();
        assert!(result.events_processed > 0);
        let delivered = {
            let guard = sim.inner.lock().expect("simulation lock");
            guard
                .get_agent(&NodeId::ipn(0, 2))
                .unwrap()
                .get_bundle(&id)
                .is_some()
        };
        assert!(delivered);
    }
}
