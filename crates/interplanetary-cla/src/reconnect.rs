//! Deterministic reconnect scheduler per RFC 9174 §4.1
//!
//! Implements connection retry with exponential backoff.

/// Milliseconds, matching [`interplanetary_tcpcl::clock::TimeMs`] when both are in use.
pub type TimeMs = u64;

/// Reconnect scheduler configuration per RFC 9174 §4.1
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Minimum delay between retry attempts in milliseconds
    /// RFC 9174 §4.1: "MUST NOT retry the connection setup earlier than some delay time"
    pub min_retry_delay_ms: u64,

    /// Maximum backoff delay in milliseconds
    /// RFC 9174 §4.1: "SHOULD be no longer than one minute (60 seconds)"
    pub max_backoff_ms: u64,

    /// Whether to use exponential backoff
    /// RFC 9174 §4.1: "SHOULD use a (binary) exponential backoff mechanism"
    pub use_exponential_backoff: bool,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            min_retry_delay_ms: 1000, // 1 second minimum
            max_backoff_ms: 60_000,   // 60 seconds max per RFC 9174 §4.1
            use_exponential_backoff: true,
        }
    }
}

/// Connection attempt scheduler with exponential backoff
#[derive(Debug)]
pub struct ReconnectScheduler {
    config: ReconnectConfig,
    consecutive_failures: u32,
    last_attempt_time_ms: Option<TimeMs>,
}

impl ReconnectScheduler {
    /// Create a new reconnect scheduler
    pub fn new(config: ReconnectConfig) -> Self {
        Self {
            config,
            consecutive_failures: 0,
            last_attempt_time_ms: None,
        }
    }

    /// Record a connection attempt at the given time
    pub fn record_attempt(&mut self, now_ms: TimeMs) {
        self.last_attempt_time_ms = Some(now_ms);
        self.consecutive_failures += 1;
    }

    /// Record a successful connection (resets failure count)
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_attempt_time_ms = None;
    }

    /// Get the earliest time a retry attempt is allowed
    /// RFC 9174 §4.1: "MUST NOT retry the connection setup earlier than some delay time"
    pub fn next_attempt_time(&self) -> Option<TimeMs> {
        let last_attempt = self.last_attempt_time_ms?;

        let delay_ms = if self.config.use_exponential_backoff && self.consecutive_failures > 0 {
            // Binary exponential backoff: delay = min_delay * 2^(failures - 1)
            let exponent = (self.consecutive_failures - 1).min(10); // Cap exponent to prevent overflow
            let backoff = self
                .config
                .min_retry_delay_ms
                .saturating_mul(1u64 << exponent);
            backoff.min(self.config.max_backoff_ms)
        } else {
            self.config.min_retry_delay_ms
        };

        Some(last_attempt.saturating_add(delay_ms))
    }

    /// Check if a retry attempt is allowed at the given time
    /// RFC 9174 §4.1: "MUST NOT retry the connection setup earlier than some delay time"
    pub fn can_attempt(&self, now_ms: TimeMs) -> bool {
        match self.next_attempt_time() {
            None => true, // No previous attempt, can try
            Some(next_time) => now_ms >= next_time,
        }
    }

    /// Get the number of consecutive failures
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_attempt_allowed() {
        let scheduler = ReconnectScheduler::new(ReconnectConfig::default());
        assert!(scheduler.can_attempt(0));
        assert!(scheduler.can_attempt(1000));
    }

    #[test]
    fn test_minimum_delay_enforced() {
        let mut scheduler = ReconnectScheduler::new(ReconnectConfig {
            min_retry_delay_ms: 5000,
            max_backoff_ms: 60_000,
            use_exponential_backoff: false,
        });

        // First attempt at t=0
        scheduler.record_attempt(0);
        assert_eq!(scheduler.next_attempt_time(), Some(5000));

        // Cannot retry before 5000ms
        assert!(!scheduler.can_attempt(0));
        assert!(!scheduler.can_attempt(4999));

        // Can retry at exactly 5000ms
        assert!(scheduler.can_attempt(5000));
        assert!(scheduler.can_attempt(5001));
    }

    #[test]
    fn test_exponential_backoff() {
        let mut scheduler = ReconnectScheduler::new(ReconnectConfig {
            min_retry_delay_ms: 1000,
            max_backoff_ms: 60_000,
            use_exponential_backoff: true,
        });

        // First failure: delay = 1000ms * 2^0 = 1000ms
        scheduler.record_attempt(0);
        assert_eq!(scheduler.next_attempt_time(), Some(1000));

        // Second failure: delay = 1000ms * 2^1 = 2000ms
        scheduler.record_attempt(1000);
        assert_eq!(scheduler.next_attempt_time(), Some(3000));

        // Third failure: delay = 1000ms * 2^2 = 4000ms
        scheduler.record_attempt(3000);
        assert_eq!(scheduler.next_attempt_time(), Some(7000));

        // Fourth failure: delay = 1000ms * 2^3 = 8000ms
        scheduler.record_attempt(7000);
        assert_eq!(scheduler.next_attempt_time(), Some(15000));
    }

    #[test]
    fn test_exponential_backoff_capped() {
        let mut scheduler = ReconnectScheduler::new(ReconnectConfig {
            min_retry_delay_ms: 1000,
            max_backoff_ms: 10_000,
            use_exponential_backoff: true,
        });

        // Keep failing until backoff exceeds max
        scheduler.record_attempt(0); // delay = 1000
        scheduler.record_attempt(1000); // delay = 2000
        scheduler.record_attempt(3000); // delay = 4000
        scheduler.record_attempt(7000); // delay = 8000
        scheduler.record_attempt(15000); // delay = 16000, but capped to 10000

        assert_eq!(scheduler.next_attempt_time(), Some(25000)); // 15000 + 10000
    }

    #[test]
    fn test_success_resets_backoff() {
        let mut scheduler = ReconnectScheduler::new(ReconnectConfig {
            min_retry_delay_ms: 1000,
            max_backoff_ms: 60_000,
            use_exponential_backoff: true,
        });

        // Build up some failures
        scheduler.record_attempt(0);
        scheduler.record_attempt(1000);
        scheduler.record_attempt(3000);
        assert_eq!(scheduler.consecutive_failures(), 3);

        // Success resets everything
        scheduler.record_success();
        assert_eq!(scheduler.consecutive_failures(), 0);
        assert!(scheduler.can_attempt(3000)); // Can immediately attempt again
    }

    #[test]
    fn test_rfc9174_4_1_max_backoff_60s() {
        let config = ReconnectConfig::default();
        assert_eq!(config.max_backoff_ms, 60_000);
    }
}
