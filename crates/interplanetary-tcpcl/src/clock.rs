//! Deterministic time abstraction for TCPCLv4 timing behavior
//!
//! Provides explicit time input without wall clock or async dependencies.

/// Time in milliseconds since an arbitrary epoch
pub type TimeMs = u64;

/// Clock trait for deterministic testing and synchronous timing
pub trait Clock {
    /// Get current time in milliseconds
    fn now_ms(&self) -> TimeMs;
}

/// Manual clock for testing - time advances only when set
#[derive(Debug, Clone)]
pub struct ManualClock {
    now_ms: TimeMs,
}

impl ManualClock {
    /// Create a new manual clock starting at time 0
    pub fn new() -> Self {
        Self { now_ms: 0 }
    }

    /// Create a manual clock with a specific start time
    pub fn with_time(now_ms: TimeMs) -> Self {
        Self { now_ms }
    }

    /// Advance the clock by the given duration
    pub fn advance(&mut self, delta_ms: u64) {
        self.now_ms = self.now_ms.saturating_add(delta_ms);
    }

    /// Set the clock to a specific time
    pub fn set(&mut self, now_ms: TimeMs) {
        self.now_ms = now_ms;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> TimeMs {
        self.now_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_clock_new() {
        let clock = ManualClock::new();
        assert_eq!(clock.now_ms(), 0);
    }

    #[test]
    fn test_manual_clock_advance() {
        let mut clock = ManualClock::new();
        clock.advance(1000);
        assert_eq!(clock.now_ms(), 1000);
        clock.advance(500);
        assert_eq!(clock.now_ms(), 1500);
    }

    #[test]
    fn test_manual_clock_set() {
        let mut clock = ManualClock::new();
        clock.set(5000);
        assert_eq!(clock.now_ms(), 5000);
    }

    #[test]
    fn test_manual_clock_with_time() {
        let clock = ManualClock::with_time(12345);
        assert_eq!(clock.now_ms(), 12345);
    }
}
