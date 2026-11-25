use super::{Error, Result};
use std::fmt;
use std::ops::{Add, Sub};

/// Simulation time instant: integer nanoseconds since simulation start
///
/// Uses integer ticks to ensure deterministic event ordering without floating-point issues.
/// Maximum representable time is ~584 years of simulated time.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SimInstant(u64);

impl SimInstant {
    /// Simulation start time
    pub const ZERO: Self = SimInstant(0);

    /// Maximum simulation horizon (~584 years)
    pub const MAX: Self = SimInstant(u64::MAX);

    /// Create from raw nanoseconds (use with caution)
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Get raw nanoseconds value
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }

    /// Checked addition with duration
    pub fn checked_add(self, dur: SimDuration) -> Option<Self> {
        self.0.checked_add(dur.0).map(Self)
    }

    /// Checked subtraction with duration
    pub fn checked_sub(self, dur: SimDuration) -> Option<Self> {
        self.0.checked_sub(dur.0).map(Self)
    }

    /// Saturating addition
    pub fn saturating_add(self, dur: SimDuration) -> Self {
        Self(self.0.saturating_add(dur.0))
    }

    /// Saturating subtraction
    pub fn saturating_sub(self, dur: SimDuration) -> Self {
        Self(self.0.saturating_sub(dur.0))
    }

    /// Duration since earlier instant
    pub fn duration_since(self, earlier: Self) -> Option<SimDuration> {
        if self >= earlier {
            Some(SimDuration(self.0 - earlier.0))
        } else {
            None
        }
    }
}

impl fmt::Debug for SimInstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SimInstant({}ns)", self.0)
    }
}

impl fmt::Display for SimInstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0 / 1_000_000_000;
        let subsec_ms = (self.0 % 1_000_000_000) / 1_000_000;
        write!(f, "{}.{:03}s", secs, subsec_ms)
    }
}

/// Simulation time duration: integer nanoseconds
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SimDuration(u64);

impl SimDuration {
    /// Zero duration
    pub const ZERO: Self = SimDuration(0);

    /// One nanosecond
    pub const NANOSECOND: Self = SimDuration(1);

    /// One microsecond
    pub const MICROSECOND: Self = SimDuration(1_000);

    /// One millisecond
    pub const MILLISECOND: Self = SimDuration(1_000_000);

    /// One second
    pub const SECOND: Self = SimDuration(1_000_000_000);

    /// One minute
    pub const MINUTE: Self = SimDuration(60 * 1_000_000_000);

    /// One hour
    pub const HOUR: Self = SimDuration(3600 * 1_000_000_000);

    /// Create from seconds
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs * 1_000_000_000)
    }

    /// Create from milliseconds
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis * 1_000_000)
    }

    /// Create from microseconds
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros * 1_000)
    }

    /// Create from nanoseconds
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Get duration in seconds (truncated)
    pub const fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Get duration in milliseconds (truncated)
    pub const fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }

    /// Get duration in microseconds (truncated)
    pub const fn as_micros(&self) -> u64 {
        self.0 / 1_000
    }

    /// Get duration in nanoseconds
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }

    /// Checked addition
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Checked subtraction
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Checked multiplication by scalar
    pub fn checked_mul(self, scalar: u64) -> Option<Self> {
        self.0.checked_mul(scalar).map(Self)
    }

    /// Checked division by scalar
    pub fn checked_div(self, scalar: u64) -> Option<Self> {
        self.0.checked_div(scalar).map(Self)
    }
}

impl fmt::Debug for SimDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SimDuration({}ns)", self.0)
    }
}

impl fmt::Display for SimDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0 / 1_000_000_000;
        if secs > 0 {
            let subsec_ms = (self.0 % 1_000_000_000) / 1_000_000;
            write!(f, "{}.{:03}s", secs, subsec_ms)
        } else {
            let millis = self.0 / 1_000_000;
            if millis > 0 {
                write!(f, "{}ms", millis)
            } else {
                let micros = self.0 / 1_000;
                if micros > 0 {
                    write!(f, "{}μs", micros)
                } else {
                    write!(f, "{}ns", self.0)
                }
            }
        }
    }
}

impl Add for SimDuration {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl Sub for SimDuration {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

/// DTN protocol time: milliseconds since 2000-01-01 00:00:00 UTC
///
/// Per RFC 9171 §4.2.6, DTN time uses epoch 2000-01-01 00:00:00 UTC.
/// A value of 0 explicitly represents unknown clock (§4.2.7).
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DtnTimeMs(u64);

impl DtnTimeMs {
    /// DTN epoch: 2000-01-01 00:00:00 UTC
    pub const EPOCH: Self = DtnTimeMs(0);

    /// Zero time (same as EPOCH)
    pub const ZERO: Self = DtnTimeMs(0);

    /// Explicitly unknown clock (creation timestamp = 0 per §4.2.7)
    pub const UNKNOWN: Self = DtnTimeMs(0);

    /// Unix epoch (1970-01-01) as seconds offset from DTN epoch
    /// DTN epoch is 2000-01-01, Unix epoch is 1970-01-01
    /// Difference: 30 years (including 8 leap years) = 946684800 seconds
    const UNIX_EPOCH_OFFSET_SECS: i64 = 946684800;

    /// Create from milliseconds since DTN epoch
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Get milliseconds since DTN epoch
    pub const fn as_millis(&self) -> u64 {
        self.0
    }

    /// Milliseconds since the DTN epoch for a wall-clock instant.
    ///
    /// This converts a value the caller already read. It does not read the clock.
    /// Instants before 2000-01-01 UTC are rejected. `0` is the DTN epoch itself
    /// (and the protocol's unknown-time sentinel).
    pub fn from_system_time(time: std::time::SystemTime) -> Result<Self> {
        let unix = time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::invalid_config("System time before Unix epoch"))?;
        let unix_millis = u64::try_from(unix.as_millis()).map_err(|_| Error::time_overflow())?;
        let offset_ms = (Self::UNIX_EPOCH_OFFSET_SECS as u64)
            .checked_mul(1_000)
            .ok_or_else(Error::time_overflow)?;
        if unix_millis < offset_ms {
            return Err(Error::invalid_config("System time before DTN epoch"));
        }
        Ok(Self(unix_millis - offset_ms))
    }

    /// Create from Unix timestamp (seconds since 1970-01-01)
    pub fn from_unix_timestamp(unix_secs: i64) -> Result<Self> {
        let dtn_secs = unix_secs
            .checked_sub(Self::UNIX_EPOCH_OFFSET_SECS)
            .ok_or_else(|| Error::invalid_config("Unix timestamp before DTN epoch"))?;

        if dtn_secs < 0 {
            return Err(Error::invalid_config("Unix timestamp before DTN epoch"));
        }

        let dtn_millis = (dtn_secs as u64)
            .checked_mul(1000)
            .ok_or_else(Error::time_overflow)?;

        Ok(Self(dtn_millis))
    }

    /// Convert to Unix timestamp (seconds since 1970-01-01)
    pub fn to_unix_timestamp(&self) -> i64 {
        let dtn_secs = (self.0 / 1000) as i64;
        dtn_secs + Self::UNIX_EPOCH_OFFSET_SECS
    }

    /// Check if this represents unknown clock
    pub const fn is_unknown(&self) -> bool {
        self.0 == 0
    }

    /// Checked addition with milliseconds
    pub fn checked_add_millis(self, ms: u64) -> Option<Self> {
        self.0.checked_add(ms).map(Self)
    }

    /// Checked subtraction with milliseconds
    pub fn checked_sub_millis(self, ms: u64) -> Option<Self> {
        self.0.checked_sub(ms).map(Self)
    }
}

impl fmt::Debug for DtnTimeMs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unknown() {
            write!(f, "DtnTimeMs(UNKNOWN)")
        } else {
            write!(f, "DtnTimeMs({}ms)", self.0)
        }
    }
}

impl fmt::Display for DtnTimeMs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unknown() {
            write!(f, "UNKNOWN")
        } else {
            write!(f, "{}ms", self.0)
        }
    }
}

/// Mapping between simulation time and DTN protocol time
///
/// This is configuration, not an implicit cast. Simulation time is deterministic
/// virtual time; DTN time is protocol time that may be communicated to peers.
#[derive(Debug, Clone, Copy)]
pub struct EpochMapping {
    /// Simulation instant corresponding to DTN epoch
    pub sim_zero: SimInstant,
    /// DTN time at simulation start
    pub dtn_zero: DtnTimeMs,
}

impl EpochMapping {
    /// Create a new epoch mapping
    pub const fn new(sim_zero: SimInstant, dtn_zero: DtnTimeMs) -> Self {
        Self { sim_zero, dtn_zero }
    }

    /// Default: simulation start (SimInstant::ZERO) maps to DTN epoch
    pub const fn default_mapping() -> Self {
        Self {
            sim_zero: SimInstant::ZERO,
            dtn_zero: DtnTimeMs::EPOCH,
        }
    }

    /// Convert simulation instant to DTN time
    pub fn sim_to_dtn(&self, instant: SimInstant) -> Result<DtnTimeMs> {
        let elapsed_ms = instant
            .duration_since(self.sim_zero)
            .ok_or_else(|| Error::invalid_config("Instant before simulation epoch"))?
            .as_millis();

        self.dtn_zero
            .checked_add_millis(elapsed_ms)
            .ok_or_else(Error::time_overflow)
    }

    /// Convert DTN time to simulation instant
    pub fn dtn_to_sim(&self, dtn_time: DtnTimeMs) -> Result<SimInstant> {
        if dtn_time < self.dtn_zero {
            return Err(Error::invalid_config("DTN time before mapped epoch"));
        }

        let elapsed_ms = dtn_time.as_millis() - self.dtn_zero.as_millis();
        self.sim_zero
            .checked_add(SimDuration::from_millis(elapsed_ms))
            .ok_or_else(Error::time_overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sim_instant_ordering() {
        let t0 = SimInstant::ZERO;
        let t1 = SimInstant::from_nanos(1000);
        let t2 = SimInstant::from_nanos(2000);

        assert!(t0 < t1);
        assert!(t1 < t2);
        assert_eq!(t1.duration_since(t0), Some(SimDuration::from_nanos(1000)));
    }

    #[test]
    fn test_sim_duration_arithmetic() {
        let d1 = SimDuration::from_secs(10);
        let d2 = SimDuration::from_secs(5);

        assert_eq!(d1.checked_add(d2), Some(SimDuration::from_secs(15)));
        assert_eq!(d1.checked_sub(d2), Some(SimDuration::from_secs(5)));
        assert_eq!(d2.checked_mul(3), Some(SimDuration::from_secs(15)));
    }

    #[test]
    fn test_dtn_time_unix_conversion() {
        // 2024-01-01 00:00:00 UTC = 1704067200 Unix seconds
        let unix_ts = 1704067200i64;
        let dtn = DtnTimeMs::from_unix_timestamp(unix_ts).unwrap();

        // 2024 - 2000 = 24 years = 757382400 seconds (with leap years)
        // But we need exact calc: (2024-2000)*365*24*3600 + leap days
        assert_eq!(dtn.to_unix_timestamp(), unix_ts);
    }

    #[test]
    fn test_dtn_time_from_system_time() {
        use std::time::{Duration, UNIX_EPOCH};

        let epoch = UNIX_EPOCH + Duration::from_secs(946_684_800);
        assert_eq!(DtnTimeMs::from_system_time(epoch).unwrap().as_millis(), 0);

        let after = epoch + Duration::from_millis(1_500);
        assert_eq!(
            DtnTimeMs::from_system_time(after).unwrap().as_millis(),
            1_500
        );

        let before = UNIX_EPOCH + Duration::from_secs(1);
        assert!(matches!(
            DtnTimeMs::from_system_time(before).unwrap_err().kind(),
            crate::ErrorKind::InvalidConfig
        ));

        if let Some(far) = UNIX_EPOCH.checked_add(Duration::from_secs(u64::MAX / 500)) {
            assert!(matches!(
                DtnTimeMs::from_system_time(far).unwrap_err().kind(),
                crate::ErrorKind::TimeOverflow
            ));
        }
    }

    #[test]
    fn test_dtn_time_unknown() {
        assert!(DtnTimeMs::UNKNOWN.is_unknown());
        assert!(DtnTimeMs::from_millis(0).is_unknown());
        assert!(!DtnTimeMs::from_millis(1).is_unknown());
    }

    #[test]
    fn test_epoch_mapping() {
        let mapping = EpochMapping::default_mapping();
        let t0 = SimInstant::ZERO;
        let t1 = t0.checked_add(SimDuration::from_secs(60)).unwrap();

        let dtn0 = mapping.sim_to_dtn(t0).unwrap();
        let dtn1 = mapping.sim_to_dtn(t1).unwrap();

        assert_eq!(dtn0, DtnTimeMs::EPOCH);
        assert_eq!(dtn1.as_millis(), 60_000);

        // Round-trip
        assert_eq!(mapping.dtn_to_sim(dtn1).unwrap(), t1);
    }

    #[test]
    fn test_display_formatting() {
        assert_eq!(SimDuration::from_secs(120).to_string(), "120.000s");
        assert_eq!(SimDuration::from_millis(500).to_string(), "500ms");
        assert_eq!(SimDuration::from_micros(123).to_string(), "123μs");
        assert_eq!(SimDuration::from_nanos(456).to_string(), "456ns");
    }
}
