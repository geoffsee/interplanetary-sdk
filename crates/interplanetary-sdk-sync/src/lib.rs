//! Integrated multi-node simulation scenario runner.
//!
//! [`Scenario`] is the primary facade for end-to-end DTN modeling: a contact plan,
//! per-node [`BundleAgent`]s, and a [`CgrRouter`] driven by the discrete-event
//! [`interplanetary_sim::SimEngine`]. Typical flow: `new` → `add_node` → `inject_bundle` → `run`.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

use interplanetary_bp::Bundle;
use interplanetary_bpa::{BpaConfig, BundleAgent};
use interplanetary_contacts::ContactPlan;
use interplanetary_routing::{CgrConfig, CgrRouter};
use interplanetary_sim::Event;
use interplanetary_sim::Phase;
use interplanetary_sim::QuiescentReason;
use interplanetary_sim::SimConfig;
use interplanetary_sim::SimEngine;
use interplanetary_store::BundleStore;
use interplanetary_store::StorageManager;
use interplanetary_types::{BundleId, Bytes, NodeId, Result, SimDuration, SimInstant};
use std::collections::HashMap;

/// Multi-node simulation: contact plan + agents + CGR routing.
///
/// Drives inject → admit → route → forward/CLA → deliver/delete until the event
/// queue is empty or the event budget is exhausted.
///
/// # Examples
///
/// Two-node hop with a single contact (requires `stable-full` for BPA + TCPCL):
///
/// ```
/// use interplanetary_bp::{BundleAgeBlock, BundleBuilder, CrcType};
/// use interplanetary_contacts::{Contact, ContactId, ContactPlan};
/// use interplanetary_sdk_sync::Scenario;
/// use interplanetary_types::*;
///
/// # fn main() -> Result<()> {
/// let mut plan = ContactPlan::new();
/// plan.add_contact(Contact {
///     id: ContactId(1),
///     from_node: NodeId::ipn(0, 1),
///     to_node: NodeId::ipn(0, 2),
///     start: SimInstant::ZERO,
///     end: SimInstant::from_nanos(60_000_000_000),
///     rate: BitsPerSecond::from_kbps(8)?,
///     delay: SimDuration::from_secs(1),
///     resource_group: None,
/// });
///
/// let mut scenario = Scenario::new(plan, Bytes::from_mib(1).unwrap());
/// scenario.add_node(NodeId::ipn(0, 1), Bytes::from_mib(1).unwrap())?;
/// scenario.add_node(NodeId::ipn(0, 2), Bytes::from_mib(1).unwrap())?;
///
/// // creation time 0 requires a Bundle Age block (RFC 9171 §4.4.2)
/// let mut bundle = BundleBuilder::new()
///     .source(EndpointId::ipn(0, 1, 0)?)
///     .destination(EndpointId::ipn(0, 2, 0)?)
///     .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
///     .lifetime(60_000)
///     .payload(b"hello mars".to_vec())
///     .crc_type(CrcType::Crc16)
///     .build()?;
/// bundle.blocks.push(BundleAgeBlock::new(2, 0).to_canonical()?);
///
/// let id = scenario.inject_bundle(&NodeId::ipn(0, 1), bundle)?;
/// let result = scenario.run()?;
/// assert!(result.events_processed > 0);
/// assert!(scenario.get_agent(&NodeId::ipn(0, 2)).unwrap().get_bundle(&id).is_some());
/// # Ok(())
/// # }
/// ```
///
/// Longer Earth → Relay → Mars contact plans: `examples/three_node.rs` and
/// `examples/three_node_integrated.rs`.
#[derive(Debug)]
pub struct Scenario {
    engine: SimEngine,
    agents: HashMap<NodeId, BundleAgent>,
    router: CgrRouter,
    /// Sequence number counter per node for status report bundle creation
    sequence_counters: HashMap<NodeId, u64>,
}

impl Scenario {
    /// Create new scenario with contact plan
    pub fn new(plan: ContactPlan, _storage_per_node: Bytes) -> Self {
        let mut engine = SimEngine::new(SimConfig::default());
        *engine.contact_plan_mut() = plan;

        Self {
            engine,
            agents: HashMap::new(),
            router: CgrRouter::new(CgrConfig::default()),
            sequence_counters: HashMap::new(),
        }
    }

    /// Add node to scenario
    pub fn add_node(&mut self, node_id: NodeId, storage_capacity: Bytes) -> Result<()> {
        let config = BpaConfig {
            local_node: node_id.clone(),
            local_eid: node_id.to_endpoint_id()?,
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: interplanetary_bpa::StatusReportPolicy::none(),
            cla_mtu: None,
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: true, // RFC 9758 §5.5 default
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: interplanetary_bpa::policy::ForwardingFailedPolicy::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        };
        let storage = StorageManager::new(storage_capacity);
        let agent = BundleAgent::new(config, storage);

        self.agents.insert(node_id.clone(), agent);
        self.sequence_counters.insert(node_id, 0);
        Ok(())
    }

    /// Add node with custom policy
    pub fn add_node_with_policy(
        &mut self,
        node_id: NodeId,
        storage_capacity: Bytes,
        policy: interplanetary_bpa::StatusReportPolicy,
    ) -> Result<()> {
        let config = BpaConfig {
            local_node: node_id.clone(),
            local_eid: node_id.to_endpoint_id()?,
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: policy,
            cla_mtu: None,
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: true, // RFC 9758 §5.5 default
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: interplanetary_bpa::policy::ForwardingFailedPolicy::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        };
        let storage = StorageManager::new(storage_capacity);
        let agent = BundleAgent::new(config, storage);

        self.agents.insert(node_id.clone(), agent);
        self.sequence_counters.insert(node_id, 0);
        Ok(())
    }

    /// Schedule expiry check for all nodes
    pub fn schedule_expiry_checks(&mut self, check_time: SimInstant) -> Result<()> {
        for node_id in self.agents.keys().cloned().collect::<Vec<_>>() {
            let agent = self.agents.get(&node_id).unwrap();
            let expired = agent.find_expired_bundles(check_time);

            for bundle_id in expired {
                self.engine.schedule_event(
                    check_time,
                    Phase::Policy,
                    Event::BundleExpired {
                        bundle_id,
                        node: node_id.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    /// Inject bundle at node
    pub fn inject_bundle(&mut self, node_id: &NodeId, bundle: Bundle) -> Result<BundleId> {
        // RFC 9171 §5.2: Validate bundle at generation
        interplanetary_bp::validate_at_generation(&bundle)?;

        let agent = self
            .agents
            .get_mut(node_id)
            .ok_or_else(|| interplanetary_types::Error::not_found("Node not found"))?;

        let bundle_id = agent.admit_bundle(bundle, self.engine.current_time())?;

        // Schedule admission event
        self.engine.schedule_event(
            self.engine.current_time(),
            Phase::Admission,
            Event::BundleAdmitted {
                bundle_id: bundle_id.clone(),
                node: node_id.clone(),
            },
        )?;

        Ok(bundle_id)
    }

    /// Run simulation until quiescent
    pub fn run(&mut self) -> Result<SimulationResult> {
        let mut events_processed = Vec::new();

        loop {
            match self.engine.step()? {
                Some(event) => {
                    let current_time = self.engine.current_time();
                    self.process_event(&event, current_time)?;
                    events_processed.push((current_time, event));
                }
                None => {
                    let reason = QuiescentReason::QueueEmpty;
                    return Ok(SimulationResult {
                        final_time: self.engine.current_time(),
                        events_processed: events_processed.len(),
                        quiescent_reason: reason,
                        event_log: events_processed,
                    });
                }
            }

            // Check event budget
            if self.engine.total_events_processed() >= 100_000 {
                return Ok(SimulationResult {
                    final_time: self.engine.current_time(),
                    events_processed: events_processed.len(),
                    quiescent_reason: QuiescentReason::EventBudgetExhausted { limit: 100_000 },
                    event_log: events_processed,
                });
            }
        }
    }

    /// Process single event
    fn process_event(&mut self, event: &Event, current_time: SimInstant) -> Result<()> {
        match event {
            Event::BundleAdmitted { bundle_id, node } => {
                self.process_admission(bundle_id, node, current_time)?;
            }
            Event::TransmissionCompleted {
                bundle_id,
                contact_id,
            } => {
                // Schedule reception after propagation delay
                let contact = self
                    .engine
                    .contact_plan()
                    .get_contact(*contact_id)
                    .ok_or_else(|| interplanetary_types::Error::not_found("Contact not found"))?;

                let arrival_time = current_time
                    .checked_add(contact.delay)
                    .ok_or_else(interplanetary_types::Error::time_overflow)?;

                self.engine.schedule_event(
                    arrival_time,
                    Phase::Completion,
                    Event::ReceptionCompleted {
                        bundle_id: bundle_id.clone(),
                        from_node: contact.from_node.clone(),
                        to_node: contact.to_node.clone(),
                    },
                )?;
            }
            Event::ReceptionCompleted {
                bundle_id,
                from_node,
                to_node,
            } => {
                self.process_reception(bundle_id, from_node, to_node, current_time)?;
            }
            Event::BundleDelivered { bundle_id, node } => {
                // Generate delivery status report if requested (before marking as delivered)
                if let Some(agent) = self.agents.get(node)
                    && let Some(bundle) = agent.storage().get(bundle_id)
                    && interplanetary_bpa::admin::requests_delivery_report(bundle)
                    && !interplanetary_bpa::admin::is_admin_record(bundle)
                {
                    let report_to = bundle.primary.report_to.clone();
                    let source = bundle.primary.source.clone();
                    let timestamp = bundle.primary.creation_timestamp;
                    let requests_time = interplanetary_bpa::admin::requests_status_time(bundle);

                    let time_opt = if requests_time {
                        Some(current_time)
                    } else {
                        None
                    };
                    let report = interplanetary_bpa::admin::StatusReport::delivery(
                        source, timestamp, time_opt,
                    );

                    if let Ok(reporting_node_eid) = node.to_endpoint_id() {
                        let seq = self.next_sequence(node);
                        if let Ok(report_bundle) =
                            interplanetary_bpa::admin::create_status_report_bundle(
                                report,
                                &reporting_node_eid,
                                &report_to,
                                current_time,
                                seq,
                                requests_time,
                            )
                        {
                            let _ = self.inject_bundle(node, report_bundle);
                        }
                    }
                }

                // Mark as delivered
                if let Some(agent) = self.agents.get_mut(node) {
                    agent.deliver_bundle(bundle_id, current_time)?;
                }
            }
            Event::BundleExpired { bundle_id, node } => {
                if let Some(agent) = self.agents.get_mut(node) {
                    agent.delete_bundle(
                        bundle_id,
                        interplanetary_bpa::admin::ReasonCode::LifetimeExpired,
                    )?;
                }
            }
            Event::BundleDeleted {
                bundle_id,
                node,
                reason,
            } => {
                if let Some(agent) = self.agents.get_mut(node) {
                    // Check if we need to generate a deletion status report
                    let should_report = if let Some(bundle) = agent.storage().get(bundle_id) {
                        interplanetary_bpa::admin::requests_deletion_report(bundle)
                            && !interplanetary_bpa::admin::is_admin_record(bundle)
                    } else {
                        false
                    };

                    // Get bundle info before deletion
                    let report_info = if should_report {
                        agent.storage().get(bundle_id).map(|b| {
                            let requests_time = interplanetary_bpa::admin::requests_status_time(b);
                            (
                                b.primary.source.clone(),
                                b.primary.creation_timestamp,
                                b.primary.report_to.clone(),
                                requests_time,
                            )
                        })
                    } else {
                        None
                    };

                    // Delete the bundle
                    agent.delete_bundle(bundle_id, *reason)?;

                    // Generate status report if requested
                    if let Some((source, timestamp, report_to, requests_time)) = report_info {
                        let time_opt = if requests_time {
                            Some(current_time)
                        } else {
                            None
                        };
                        let report = interplanetary_bpa::admin::StatusReport::deletion(
                            source, timestamp, *reason, time_opt,
                        );

                        // Create and inject status report bundle
                        if let Ok(reporting_node_eid) = node.to_endpoint_id() {
                            let seq = self.next_sequence(node);
                            if let Ok(report_bundle) =
                                interplanetary_bpa::admin::create_status_report_bundle(
                                    report,
                                    &reporting_node_eid,
                                    &report_to,
                                    current_time,
                                    seq,
                                    requests_time,
                                )
                            {
                                // Inject the status report (don't generate reports about reports!)
                                let _ = self.inject_bundle(node, report_bundle);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Process bundle admission (routing + transmission)
    fn process_admission(
        &mut self,
        bundle_id: &BundleId,
        node: &NodeId,
        current_time: SimInstant,
    ) -> Result<()> {
        let agent = self
            .agents
            .get(node)
            .ok_or_else(|| interplanetary_types::Error::not_found("Node not found"))?;

        let bundle = agent
            .get_bundle(bundle_id)
            .ok_or_else(|| interplanetary_types::Error::not_found("Bundle not found"))?;

        // Check if local delivery
        if agent.is_local_destination(&bundle.primary.destination) {
            self.engine.schedule_event(
                current_time,
                Phase::Observation,
                Event::BundleDelivered {
                    bundle_id: bundle_id.clone(),
                    node: node.clone(),
                },
            )?;
            return Ok(());
        }

        // RFC 9171 §5.4: Bundle Forwarding - process on forward before transmitting
        // This is an intermediate node that will forward the bundle
        let mut bundle_to_forward = bundle.clone();
        let node_eid = agent.config().local_eid.clone();

        // Compute residence time at this node (simplified: use zero for now)
        let residence_time = SimDuration::ZERO;

        // Process bundle on forward - this may fail if hop limit exceeded
        match interplanetary_bp::process_on_forward(
            &mut bundle_to_forward,
            &node_eid,
            residence_time,
        ) {
            Ok(()) => {
                // Success - update bundle in storage by removing old and admitting new
                // This ensures the updated bundle (with incremented hop count, updated age, etc.) is transmitted
                let agent_mut = self
                    .agents
                    .get_mut(node)
                    .ok_or_else(|| interplanetary_types::Error::not_found("Node not found"))?;
                agent_mut.storage_mut().remove(bundle_id)?;
                agent_mut.admit_bundle(bundle_to_forward.clone(), current_time)?;

                // Generate forwarding status report if requested
                if interplanetary_bpa::admin::requests_forward_report(&bundle_to_forward)
                    && !interplanetary_bpa::admin::is_admin_record(&bundle_to_forward)
                {
                    let report_to = bundle_to_forward.primary.report_to.clone();
                    let source = bundle_to_forward.primary.source.clone();
                    let timestamp = bundle_to_forward.primary.creation_timestamp;
                    let requests_time =
                        interplanetary_bpa::admin::requests_status_time(&bundle_to_forward);

                    let time_opt = if requests_time {
                        Some(current_time)
                    } else {
                        None
                    };
                    let report = interplanetary_bpa::admin::StatusReport::forwarding(
                        source, timestamp, time_opt,
                    );

                    let reporting_node_eid = node_eid.clone();
                    let seq = self.next_sequence(node);
                    if let Ok(report_bundle) =
                        interplanetary_bpa::admin::create_status_report_bundle(
                            report,
                            &reporting_node_eid,
                            &report_to,
                            current_time,
                            seq,
                            requests_time,
                        )
                    {
                        let _ = self.inject_bundle(node, report_bundle);
                    }
                }
            }
            Err(e) if e.to_string().contains("Hop limit exceeded") => {
                // RFC 9171 §4.4.3: Delete bundle when hop limit exceeded
                // Deletion reason code 9 per RFC 9171 §6.1.1 Table 1
                self.engine.schedule_event(
                    current_time,
                    Phase::Policy,
                    Event::BundleDeleted {
                        bundle_id: bundle_id.clone(),
                        node: node.clone(),
                        reason: interplanetary_bpa::admin::ReasonCode::HopLimitExceeded,
                    },
                )?;
                return Ok(()); // Don't forward
            }
            Err(e) => return Err(e),
        }

        // Compute route
        let dest_node = NodeId::from_endpoint(&bundle_to_forward.primary.destination)?;
        let bundle_size = Bytes(bundle_to_forward.estimated_size() as u64);

        let route = self.router.compute_route(
            node,
            &dest_node,
            bundle_size,
            current_time,
            self.engine.contact_plan(),
        )?;

        // Schedule transmission, respecting contact start time
        let contact = self
            .engine
            .contact_plan()
            .get_contact(route.via_contact)
            .ok_or_else(|| interplanetary_types::Error::not_found("Contact not found"))?;

        let tx_time = contact.serialization_time(bundle_size)?;

        // Find when we can actually transmit (respects contact start time)
        let (_tx_start, tx_end) = contact
            .find_available_interval(current_time, tx_time)
            .ok_or_else(|| {
                interplanetary_types::Error::no_route("Contact not available for bundle")
            })?;

        self.engine.schedule_event(
            tx_end,
            Phase::Completion,
            Event::TransmissionCompleted {
                bundle_id: bundle_id.clone(),
                contact_id: route.via_contact,
            },
        )?;

        Ok(())
    }

    /// Process bundle reception at node (from_node added to signature)
    fn process_reception(
        &mut self,
        bundle_id: &BundleId,
        from_node: &NodeId,
        to_node: &NodeId,
        current_time: SimInstant,
    ) -> Result<()> {
        // Get bundle from the specific sending node
        let bundle = {
            let from_agent = self
                .agents
                .get(from_node)
                .ok_or_else(|| interplanetary_types::Error::not_found("Sending node not found"))?;
            from_agent
                .get_bundle(bundle_id)
                .ok_or_else(|| {
                    interplanetary_types::Error::not_found("Bundle not in sender's storage")
                })?
                .clone()
        };

        // Admit to receiving node
        let dest_agent = self
            .agents
            .get_mut(to_node)
            .ok_or_else(|| interplanetary_types::Error::not_found("Destination node not found"))?;

        dest_agent.admit_bundle(bundle.clone(), current_time)?;

        // Generate reception status report if requested
        if interplanetary_bpa::admin::requests_reception_report(&bundle)
            && !interplanetary_bpa::admin::is_admin_record(&bundle)
        {
            let report_to = bundle.primary.report_to.clone();
            let source = bundle.primary.source.clone();
            let timestamp = bundle.primary.creation_timestamp;
            let requests_time = interplanetary_bpa::admin::requests_status_time(&bundle);

            let time_opt = if requests_time {
                Some(current_time)
            } else {
                None
            };
            let report =
                interplanetary_bpa::admin::StatusReport::reception(source, timestamp, time_opt);

            if let Ok(reporting_node_eid) = to_node.to_endpoint_id() {
                let seq = self.next_sequence(to_node);
                if let Ok(report_bundle) = interplanetary_bpa::admin::create_status_report_bundle(
                    report,
                    &reporting_node_eid,
                    &report_to,
                    current_time,
                    seq,
                    requests_time,
                ) {
                    let _ = self.inject_bundle(to_node, report_bundle);
                }
            }
        }

        // Schedule admission processing for forwarding/delivery
        self.engine.schedule_event(
            current_time,
            Phase::Admission,
            Event::BundleAdmitted {
                bundle_id: bundle_id.clone(),
                node: to_node.clone(),
            },
        )?;

        Ok(())
    }

    /// Get agent for node
    pub fn get_agent(&self, node: &NodeId) -> Option<&BundleAgent> {
        self.agents.get(node)
    }

    /// Get and increment sequence number for node
    fn next_sequence(&mut self, node: &NodeId) -> u64 {
        let counter = self.sequence_counters.entry(node.clone()).or_insert(0);
        let seq = *counter;
        *counter = counter.saturating_add(1);
        seq
    }

    /// Get current simulation time
    pub fn current_time(&self) -> SimInstant {
        self.engine.current_time()
    }
}

/// Simulation result
#[derive(Debug)]
pub struct SimulationResult {
    /// Final simulation time
    pub final_time: SimInstant,
    /// Number of events processed
    pub events_processed: usize,
    /// Reason simulation stopped
    pub quiescent_reason: QuiescentReason,
    /// Complete event trace
    pub event_log: Vec<(SimInstant, Event)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use interplanetary_bp::BundleBuilder;
    use interplanetary_contacts::Contact;
    use interplanetary_contacts::ContactId;
    use interplanetary_types::{BitsPerSecond, CreationTimestamp, DtnTimeMs, EndpointId};

    #[test]
    fn test_scenario_two_node_direct() {
        let mut plan = ContactPlan::new();

        // Direct contact: Node 1 → Node 2
        plan.add_contact(Contact {
            id: ContactId(1),
            from_node: NodeId::ipn(0, 1),
            to_node: NodeId::ipn(0, 2),
            start: SimInstant::ZERO,
            end: SimInstant::from_nanos(10_000_000_000),
            rate: BitsPerSecond::from_kbps(8).unwrap(),
            delay: SimDuration::from_secs(1),
            resource_group: None,
        });

        let mut scenario = Scenario::new(plan, Bytes::from_mib(1).unwrap());
        scenario
            .add_node(NodeId::ipn(0, 1), Bytes::from_mib(1).unwrap())
            .unwrap();
        scenario
            .add_node(NodeId::ipn(0, 2), Bytes::from_mib(1).unwrap())
            .unwrap();

        // Create and inject bundle
        // RFC 9171 §4.4.2: When creation time is 0, Bundle Age block is required
        // RFC 9171 §4.3.1: Primary CRC type must be non-zero unless BIB targets primary
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .crc_type(interplanetary_bp::CrcType::Crc16)
            .build()
            .unwrap();

        // Add Bundle Age block (required for creation time = 0)
        use interplanetary_bp::BundleAgeBlock;
        let age_block = BundleAgeBlock::new(2, 0);
        bundle.blocks.push(age_block.to_canonical().unwrap());

        let bundle_id = scenario.inject_bundle(&NodeId::ipn(0, 1), bundle).unwrap();

        // Run simulation
        let result = scenario.run().unwrap();

        // Should have delivered the bundle
        assert!(result.events_processed > 0);

        // Check bundle reached destination
        let dest_agent = scenario.get_agent(&NodeId::ipn(0, 2)).unwrap();
        assert!(dest_agent.get_bundle(&bundle_id).is_some());
    }
}
