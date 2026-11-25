//! Event scheduling with deterministic ordering per charter §8

use interplanetary_types::{BundleId, NodeId, SimInstant};
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

/// Event key for deterministic ordering: (time, microstep, phase, sequence)
///
/// Events are processed in strict order:
/// 1. SimInstant (virtual time)
/// 2. Microstep (iterations at same time)
/// 3. Phase (policy/expiry → completion → admission → observation)
/// 4. Sequence (stable ID for same phase)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventKey {
    /// Virtual simulation time for this event
    pub time: SimInstant,
    /// Microstep counter for events at same time
    pub microstep: u32,
    /// Processing phase (policy/completion/admission/observation)
    pub phase: Phase,
    /// Unique sequence number for deterministic ordering
    pub sequence: u64,
}

/// Event processing phases at a given time/microstep
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Policy and expiry checks (first)
    Policy = 0,
    /// Transfer/reception completions (second)
    Completion = 1,
    /// Routing and admission (third)
    Admission = 2,
    /// Observations (last)
    Observation = 3,
}

impl Ord for EventKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Natural ordering: earlier events come first
        self.time
            .cmp(&other.time)
            .then_with(|| self.microstep.cmp(&other.microstep))
            .then_with(|| self.phase.cmp(&other.phase))
            .then_with(|| self.sequence.cmp(&other.sequence))
    }
}

impl PartialOrd for EventKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Simulation events
#[derive(Debug, Clone)]
pub enum Event {
    /// Bundle admitted to storage
    BundleAdmitted {
        /// Bundle identifier
        bundle_id: BundleId,
        /// Node that admitted the bundle
        node: NodeId,
    },

    /// Bundle transmission started
    TransmissionStarted {
        /// Bundle being transmitted
        bundle_id: BundleId,
        /// Contact used for transmission
        contact_id: interplanetary_contacts::ContactId,
    },

    /// Bundle transmission completed (emission done)
    TransmissionCompleted {
        /// Bundle that finished transmission
        bundle_id: BundleId,
        /// Contact used
        contact_id: interplanetary_contacts::ContactId,
    },

    /// Bundle reception completed (arrival after propagation)
    ReceptionCompleted {
        /// Bundle that was received
        bundle_id: BundleId,
        /// Source node
        from_node: NodeId,
        /// Destination node
        to_node: NodeId,
    },

    /// Bundle expired
    BundleExpired {
        /// Expired bundle
        bundle_id: BundleId,
        /// Node where bundle expired
        node: NodeId,
    },

    /// Bundle delivered to application
    BundleDelivered {
        /// Delivered bundle
        bundle_id: BundleId,
        /// Node that delivered
        node: NodeId,
    },

    /// Bundle deleted
    BundleDeleted {
        /// Deleted bundle
        bundle_id: BundleId,
        /// Node that deleted
        node: NodeId,
        /// Deletion reason per RFC 9171 §6.1.1
        reason: interplanetary_bpa::admin::ReasonCode,
    },

    /// Bundle forwarded
    BundleForwarded {
        /// Forwarded bundle
        bundle_id: BundleId,
        /// Source node
        from_node: NodeId,
        /// Next hop node
        to_node: NodeId,
    },

    /// Contact opened
    ContactOpened {
        /// Contact that opened
        contact_id: interplanetary_contacts::ContactId,
    },

    /// Contact closed
    ContactClosed {
        /// Contact that closed
        contact_id: interplanetary_contacts::ContactId,
    },

    /// Route computed
    RouteComputed {
        /// Bundle for which route was computed
        bundle_id: BundleId,
        /// Sequence of contacts in route
        via_contacts: Vec<interplanetary_contacts::ContactId>,
    },

    /// Storage full (admission rejected)
    StorageFull {
        /// Bundle that could not be admitted
        bundle_id: BundleId,
        /// Requested capacity
        requested: interplanetary_types::Bytes,
        /// Available capacity
        available: interplanetary_types::Bytes,
    },
}

/// Scheduled event with key and payload
#[derive(Debug, Clone)]
pub struct ScheduledEvent {
    /// Ordering key (time, microstep, phase, sequence)
    pub key: EventKey,
    /// Event payload
    pub event: Event,
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ScheduledEvent {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for ScheduledEvent {}

/// Event queue with deterministic ordering
/// Uses BinaryHeap with Reverse to get min-heap behavior
#[derive(Debug)]
pub struct EventQueue {
    /// Min-heap of events ordered by EventKey
    heap: BinaryHeap<Reverse<ScheduledEvent>>,
    /// Next sequence number to assign
    next_sequence: u64,
    /// Maximum queue capacity
    max_size: usize,
}

impl EventQueue {
    /// Create new event queue
    pub fn new(max_size: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_sequence: 0,
            max_size,
        }
    }

    /// Schedule event at given time/microstep/phase
    pub fn schedule(
        &mut self,
        time: SimInstant,
        microstep: u32,
        phase: Phase,
        event: Event,
    ) -> interplanetary_types::Result<()> {
        if self.heap.len() >= self.max_size {
            return Err(interplanetary_types::Error::event_budget_exhausted(
                self.max_size as u64,
            ));
        }

        let key = EventKey {
            time,
            microstep,
            phase,
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;

        self.heap.push(Reverse(ScheduledEvent { key, event }));
        Ok(())
    }

    /// Pop next event (earliest)
    pub fn pop(&mut self) -> Option<ScheduledEvent> {
        self.heap.pop().map(|Reverse(e)| e)
    }

    /// Peek at next event without removing
    pub fn peek(&self) -> Option<&ScheduledEvent> {
        self.heap.peek().map(|Reverse(e)| e)
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Get queue size
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Clear all events
    pub fn clear(&mut self) {
        self.heap.clear();
        self.next_sequence = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use interplanetary_types::{CreationTimestamp, DtnTimeMs, EndpointId, SimDuration};

    #[test]
    fn test_event_key_ordering() {
        let k1 = EventKey {
            time: SimInstant::ZERO,
            microstep: 0,
            phase: Phase::Policy,
            sequence: 0,
        };

        let k2 = EventKey {
            time: SimInstant::ZERO,
            microstep: 0,
            phase: Phase::Completion,
            sequence: 0,
        };

        // Policy phase (0) should be processed before Completion phase (1)
        assert!(k1 < k2);

        let k3 = EventKey {
            time: SimInstant::ZERO
                .checked_add(SimDuration::from_secs(1))
                .unwrap(),
            microstep: 0,
            phase: Phase::Policy,
            sequence: 0,
        };

        // Earlier time comes first
        assert!(k1 < k3);
    }

    #[test]
    fn test_event_queue_fifo_at_same_time() {
        let mut queue = EventQueue::new(100);
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let ts = CreationTimestamp::new(DtnTimeMs::from_millis(0), 0);
        let node = NodeId::ipn(0, 1);

        // Schedule multiple events at same time/phase
        for _i in 0..3 {
            let bundle_id = BundleId::new(source.clone(), ts);
            queue
                .schedule(
                    SimInstant::ZERO,
                    0,
                    Phase::Policy,
                    Event::BundleAdmitted {
                        bundle_id,
                        node: node.clone(),
                    },
                )
                .unwrap();
        }

        // Should pop in sequence order (FIFO)
        let e1 = queue.pop().unwrap();
        let e2 = queue.pop().unwrap();
        let e3 = queue.pop().unwrap();

        assert!(e1.key.sequence < e2.key.sequence);
        assert!(e2.key.sequence < e3.key.sequence);
    }

    #[test]
    fn test_event_queue_respects_phases() {
        let mut queue = EventQueue::new(100);
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let ts = CreationTimestamp::new(DtnTimeMs::from_millis(0), 0);
        let node = NodeId::ipn(0, 1);
        let bundle_id = BundleId::new(source, ts);

        // Schedule in reverse phase order
        queue
            .schedule(
                SimInstant::ZERO,
                0,
                Phase::Observation,
                Event::BundleDelivered {
                    bundle_id: bundle_id.clone(),
                    node: node.clone(),
                },
            )
            .unwrap();

        queue
            .schedule(
                SimInstant::ZERO,
                0,
                Phase::Policy,
                Event::BundleExpired {
                    bundle_id: bundle_id.clone(),
                    node: node.clone(),
                },
            )
            .unwrap();

        // Should pop in phase order (Policy before Observation)
        let e1 = queue.pop().unwrap();
        assert!(matches!(e1.event, Event::BundleExpired { .. }));

        let e2 = queue.pop().unwrap();
        assert!(matches!(e2.event, Event::BundleDelivered { .. }));
    }

    #[test]
    fn test_event_queue_size_limit() {
        let mut queue = EventQueue::new(2);
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let ts = CreationTimestamp::new(DtnTimeMs::from_millis(0), 0);
        let node = NodeId::ipn(0, 1);
        let bundle_id = BundleId::new(source, ts);

        queue
            .schedule(
                SimInstant::ZERO,
                0,
                Phase::Policy,
                Event::BundleAdmitted {
                    bundle_id: bundle_id.clone(),
                    node: node.clone(),
                },
            )
            .unwrap();

        queue
            .schedule(
                SimInstant::ZERO,
                0,
                Phase::Policy,
                Event::BundleAdmitted {
                    bundle_id: bundle_id.clone(),
                    node: node.clone(),
                },
            )
            .unwrap();

        // Third should fail
        let result = queue.schedule(
            SimInstant::ZERO,
            0,
            Phase::Policy,
            Event::BundleAdmitted { bundle_id, node },
        );
        assert!(result.is_err());
    }
}
