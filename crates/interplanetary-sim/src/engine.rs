//! Simulation engine coordinating event processing

use super::{ContactPlan, Event, EventQueue, Phase};
use interplanetary_types::{Error, Result, SimDuration, SimInstant};

/// Reason why simulation reached quiescence
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuiescentReason {
    /// All bundles delivered or deleted
    AllDelivered,
    /// Event queue empty
    QueueEmpty,
    /// Waiting beyond known horizon
    WaitingBeyondHorizon(SimInstant),
    /// Blocked with no future events
    Blocked {
        /// Reason for blocking
        reason: String,
    },
    /// Event budget exhausted
    EventBudgetExhausted {
        /// Event limit
        limit: u64,
    },
    /// Microstep budget exhausted
    MicrostepBudgetExhausted {
        /// Microstep limit
        limit: u32,
    },
}

/// Simulation engine configuration
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Maximum events before halting
    pub max_events: usize,
    /// Maximum microsteps per instant
    pub microstep_budget: u32,
    /// Maximum simulation time horizon
    pub max_horizon: SimDuration,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            max_events: 100_000,
            microstep_budget: 1000,
            max_horizon: SimDuration::from_secs(365 * 24 * 3600), // 1 year
        }
    }
}

/// Main simulation engine
#[derive(Debug)]
pub struct SimEngine {
    event_queue: EventQueue,
    contact_plan: ContactPlan,
    current_time: SimInstant,
    current_microstep: u32,
    config: SimConfig,
    total_events_processed: u64,
}

impl SimEngine {
    /// Create new simulation engine
    pub fn new(config: SimConfig) -> Self {
        Self {
            event_queue: EventQueue::new(config.max_events),
            contact_plan: ContactPlan::new(),
            current_time: SimInstant::ZERO,
            current_microstep: 0,
            config,
            total_events_processed: 0,
        }
    }

    /// Get current simulation time
    pub fn current_time(&self) -> SimInstant {
        self.current_time
    }

    /// Get contact plan
    pub fn contact_plan(&self) -> &ContactPlan {
        &self.contact_plan
    }

    /// Get mutable contact plan
    pub fn contact_plan_mut(&mut self) -> &mut ContactPlan {
        &mut self.contact_plan
    }

    /// Schedule event
    pub fn schedule_event(&mut self, time: SimInstant, phase: Phase, event: Event) -> Result<()> {
        self.event_queue
            .schedule(time, self.current_microstep, phase, event)
    }

    /// Step one event (process next event from queue)
    pub fn step(&mut self) -> Result<Option<Event>> {
        let scheduled = match self.event_queue.pop() {
            Some(s) => s,
            None => return Ok(None),
        };

        // Update time/microstep
        if scheduled.key.time > self.current_time {
            self.current_time = scheduled.key.time;
            self.current_microstep = 0;
        } else if scheduled.key.microstep != self.current_microstep {
            self.current_microstep = scheduled.key.microstep;
        }

        // Check microstep budget
        if self.current_microstep >= self.config.microstep_budget {
            return Err(Error::new(
                interplanetary_types::ErrorKind::EventBudgetExhausted,
                format!(
                    "Microstep budget exhausted: {}",
                    self.config.microstep_budget
                ),
            ));
        }

        self.total_events_processed += 1;
        Ok(Some(scheduled.event))
    }

    /// Run until queue empty or condition met
    pub fn run_until_quiescent(&mut self) -> Result<QuiescentReason> {
        loop {
            match self.step()? {
                Some(_event) => {
                    // Process event (actual processing happens in higher layer)
                    // This is just the event loop driver
                }
                None => {
                    return Ok(QuiescentReason::QueueEmpty);
                }
            }

            // Check if we've exceeded event budget
            if self.total_events_processed >= self.config.max_events as u64 {
                return Ok(QuiescentReason::EventBudgetExhausted {
                    limit: self.config.max_events as u64,
                });
            }
        }
    }

    /// Get total events processed
    pub fn total_events_processed(&self) -> u64 {
        self.total_events_processed
    }

    /// Check if queue is empty
    pub fn is_quiescent(&self) -> bool {
        self.event_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use interplanetary_types::{BundleId, CreationTimestamp, DtnTimeMs, EndpointId, NodeId};

    #[test]
    fn test_engine_time_progression() {
        let mut engine = SimEngine::new(SimConfig::default());

        assert_eq!(engine.current_time(), SimInstant::ZERO);

        let node = NodeId::ipn(0, 1);
        let bundle_id = BundleId::new(
            EndpointId::ipn(0, 1, 0).unwrap(),
            CreationTimestamp::new(DtnTimeMs::ZERO, 0),
        );

        engine
            .schedule_event(
                SimInstant::from_nanos(1000),
                Phase::Policy,
                Event::BundleAdmitted { bundle_id, node },
            )
            .unwrap();

        engine.step().unwrap();
        assert_eq!(engine.current_time(), SimInstant::from_nanos(1000));
    }

    #[test]
    fn test_engine_event_ordering() {
        let mut engine = SimEngine::new(SimConfig::default());
        let node = NodeId::ipn(0, 1);
        let bundle_id = BundleId::new(
            EndpointId::ipn(0, 1, 0).unwrap(),
            CreationTimestamp::new(DtnTimeMs::ZERO, 0),
        );

        // Schedule events in reverse time order
        engine
            .schedule_event(
                SimInstant::from_nanos(2000),
                Phase::Policy,
                Event::BundleDelivered {
                    bundle_id: bundle_id.clone(),
                    node: node.clone(),
                },
            )
            .unwrap();

        engine
            .schedule_event(
                SimInstant::from_nanos(1000),
                Phase::Policy,
                Event::BundleAdmitted { bundle_id, node },
            )
            .unwrap();

        // Should process in time order
        let e1 = engine.step().unwrap();
        assert!(matches!(e1, Some(Event::BundleAdmitted { .. })));
        assert_eq!(engine.current_time(), SimInstant::from_nanos(1000));

        let e2 = engine.step().unwrap();
        assert!(matches!(e2, Some(Event::BundleDelivered { .. })));
        assert_eq!(engine.current_time(), SimInstant::from_nanos(2000));
    }

    #[test]
    fn test_engine_quiescence() {
        let mut engine = SimEngine::new(SimConfig::default());

        assert!(engine.is_quiescent());

        let reason = engine.run_until_quiescent().unwrap();
        assert_eq!(reason, QuiescentReason::QueueEmpty);
    }
}
