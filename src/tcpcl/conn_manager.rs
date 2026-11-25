//! CLA Connection Manager with RFC 9174 §4.1 compliant retry logic

use super::clock::TimeMs;
use super::reconnect::{ReconnectConfig, ReconnectScheduler};
use std::collections::HashMap;

/// Connection state for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connection attempt in progress
    Connecting,
    /// Successfully connected
    Connected,
}

/// Connection attempt result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionResult {
    /// Connection succeeded
    Success,
    /// Connection failed
    Failure,
    /// Connection attempt not allowed yet (backoff)
    Backoff {
        /// The earliest time when next attempt is allowed
        next_attempt_time: TimeMs,
    },
}

/// A connection manager that enforces RFC 9174 §4.1 reconnection rules
#[derive(Debug)]
pub struct ConnectionManager {
    /// Reconnect schedulers per peer
    schedulers: HashMap<String, ReconnectScheduler>,
    /// Current connection states per peer
    states: HashMap<String, ConnectionState>,
    /// Configuration for new schedulers
    config: ReconnectConfig,
    /// Connection attempts log for testing
    attempt_log: Vec<(TimeMs, String)>,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(config: ReconnectConfig) -> Self {
        Self {
            schedulers: HashMap::new(),
            states: HashMap::new(),
            config,
            attempt_log: Vec::new(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ReconnectConfig::default())
    }

    /// Attempt to connect to a peer at the given time
    ///
    /// RFC 9174 §4.1: "MUST NOT overwhelm its target with repeated connection attempts"
    /// RFC 9174 §4.1: "MUST NOT retry the connection setup earlier than some delay time"
    ///
    /// Returns whether the attempt is allowed and records it if so.
    pub fn attempt_connect(&mut self, peer: &str, now: TimeMs) -> ConnectionResult {
        let scheduler = self
            .schedulers
            .entry(peer.to_string())
            .or_insert_with(|| ReconnectScheduler::new(self.config.clone()));

        // RFC 9174 §4.1: Check if attempt is allowed by backoff scheduler
        if !scheduler.can_attempt(now)
            && let Some(next_time) = scheduler.next_attempt_time()
        {
            return ConnectionResult::Backoff {
                next_attempt_time: next_time,
            };
        }

        // Record the attempt
        scheduler.record_attempt(now);
        self.attempt_log.push((now, peer.to_string()));
        self.states
            .insert(peer.to_string(), ConnectionState::Connecting);

        ConnectionResult::Success
    }

    /// Record a successful connection
    pub fn record_success(&mut self, peer: &str) {
        if let Some(scheduler) = self.schedulers.get_mut(peer) {
            scheduler.record_success();
        }
        self.states
            .insert(peer.to_string(), ConnectionState::Connected);
    }

    /// Record a connection failure
    pub fn record_failure(&mut self, peer: &str) {
        self.states
            .insert(peer.to_string(), ConnectionState::Disconnected);
    }

    /// Get connection state for a peer
    pub fn connection_state(&self, peer: &str) -> ConnectionState {
        self.states
            .get(peer)
            .copied()
            .unwrap_or(ConnectionState::Disconnected)
    }

    /// Get the next allowed attempt time for a peer
    pub fn next_attempt_time(&self, peer: &str) -> Option<TimeMs> {
        self.schedulers.get(peer)?.next_attempt_time()
    }

    /// Get the attempt log (for testing)
    pub fn attempt_log(&self) -> &[(TimeMs, String)] {
        &self.attempt_log
    }

    /// Get consecutive failure count for a peer
    pub fn consecutive_failures(&self, peer: &str) -> u32 {
        self.schedulers
            .get(peer)
            .map(|s| s.consecutive_failures())
            .unwrap_or(0)
    }
}
