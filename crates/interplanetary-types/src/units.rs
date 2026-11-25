use super::{Error, Result, SimDuration};
use std::fmt;

/// Typed byte count to avoid confusion with other integers
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Bytes(pub u64);

impl Bytes {
    /// Zero bytes
    pub const ZERO: Self = Bytes(0);

    /// Maximum representable bytes
    pub const MAX: Self = Bytes(u64::MAX);

    /// One kilobyte (1024 bytes)
    pub const KIB: Self = Bytes(1024);

    /// One megabyte (1024² bytes)
    pub const MIB: Self = Bytes(1024 * 1024);

    /// One gigabyte (1024³ bytes)
    pub const GIB: Self = Bytes(1024 * 1024 * 1024);

    /// Create from raw byte count
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Create from kilobytes (KiB)
    pub fn from_kib(kib: u64) -> Option<Self> {
        kib.checked_mul(1024).map(Self)
    }

    /// Create from megabytes (MiB)
    pub fn from_mib(mib: u64) -> Option<Self> {
        mib.checked_mul(1024 * 1024).map(Self)
    }

    /// Create from gigabytes (GiB)
    pub fn from_gib(gib: u64) -> Option<Self> {
        gib.checked_mul(1024 * 1024 * 1024).map(Self)
    }

    /// Get raw byte count
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Get as kilobytes (truncated)
    pub const fn as_kib(&self) -> u64 {
        self.0 / 1024
    }

    /// Get as megabytes (truncated)
    pub const fn as_mib(&self) -> u64 {
        self.0 / (1024 * 1024)
    }

    /// Get as gigabytes (truncated)
    pub const fn as_gib(&self) -> u64 {
        self.0 / (1024 * 1024 * 1024)
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

    /// Saturating addition
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Calculate serialization time at given bit rate
    pub fn serialization_time(&self, rate: BitsPerSecond) -> Result<SimDuration> {
        let bits = self
            .0
            .checked_mul(8)
            .ok_or_else(|| Error::protocol_violation("Bytes to bits overflow"))?;
        let nanos = bits
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_div(rate.0))
            .ok_or_else(|| Error::protocol_violation("Serialization time overflow"))?;
        Ok(SimDuration::from_nanos(nanos))
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({})", self.0)
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const GIB: u64 = 1024 * 1024 * 1024;
        const MIB: u64 = 1024 * 1024;
        const KIB: u64 = 1024;

        if self.0 >= GIB {
            write!(f, "{:.2} GiB", self.0 as f64 / GIB as f64)
        } else if self.0 >= MIB {
            write!(f, "{:.2} MiB", self.0 as f64 / MIB as f64)
        } else if self.0 >= KIB {
            write!(f, "{:.2} KiB", self.0 as f64 / KIB as f64)
        } else {
            write!(f, "{} B", self.0)
        }
    }
}

/// Typed bit rate to avoid confusion with bytes
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BitsPerSecond(pub u64);

impl BitsPerSecond {
    /// Zero bit rate
    pub const ZERO: Self = BitsPerSecond(0);

    /// Maximum representable bit rate
    pub const MAX: Self = BitsPerSecond(u64::MAX);

    /// Create from raw bits per second
    pub const fn from_bps(bps: u64) -> Self {
        Self(bps)
    }

    /// Create from kilobits per second (1000 bps)
    pub fn from_kbps(kbps: u64) -> Result<Self> {
        kbps.checked_mul(1000)
            .map(Self)
            .ok_or_else(Error::time_overflow)
    }

    /// Create from megabits per second (1_000_000 bps)
    pub fn from_mbps(mbps: u64) -> Result<Self> {
        mbps.checked_mul(1_000_000)
            .map(Self)
            .ok_or_else(Error::time_overflow)
    }

    /// Create from gigabits per second (1_000_000_000 bps)
    pub fn from_gbps(gbps: u64) -> Result<Self> {
        gbps.checked_mul(1_000_000_000)
            .map(Self)
            .ok_or_else(Error::time_overflow)
    }

    /// Get raw bits per second
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Compute serialization time for given byte count
    ///
    /// Returns the time required to transmit `bytes` at this bit rate.
    /// Formula: ceil(8 * bytes * ticks_per_sec / bit_rate)
    ///
    /// Uses checked u128 arithmetic to avoid overflow.
    pub fn serialization_time(&self, bytes: Bytes) -> Result<SimDuration> {
        if self.0 == 0 {
            return Err(Error::invalid_config("Zero bit rate"));
        }

        // Convert to u128 to avoid overflow
        let bits = (bytes.0 as u128) * 8;
        let nanos_per_sec = 1_000_000_000u128;
        let rate = self.0 as u128;

        // Compute nanos = ceil(bits * nanos_per_sec / rate)
        let nanos = (bits * nanos_per_sec).div_ceil(rate);

        if nanos > u64::MAX as u128 {
            return Err(Error::time_overflow());
        }

        Ok(SimDuration::from_nanos(nanos as u64))
    }

    /// Compute how many bytes can be sent in the given duration
    pub fn bytes_in_duration(&self, duration: SimDuration) -> Bytes {
        let bits = ((duration.as_nanos() as u128) * (self.0 as u128)) / 1_000_000_000u128;
        let bytes = bits / 8;
        Bytes(bytes.min(u64::MAX as u128) as u64)
    }
}

impl fmt::Debug for BitsPerSecond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitsPerSecond({})", self.0)
    }
}

impl fmt::Display for BitsPerSecond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const GBPS: u64 = 1_000_000_000;
        const MBPS: u64 = 1_000_000;
        const KBPS: u64 = 1_000;

        if self.0 >= GBPS {
            write!(f, "{:.2} Gbps", self.0 as f64 / GBPS as f64)
        } else if self.0 >= MBPS {
            write!(f, "{:.2} Mbps", self.0 as f64 / MBPS as f64)
        } else if self.0 >= KBPS {
            write!(f, "{:.2} Kbps", self.0 as f64 / KBPS as f64)
        } else {
            write!(f, "{} bps", self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_creation() {
        assert_eq!(Bytes::from_kib(1), Some(Bytes(1024)));
        assert_eq!(Bytes::from_mib(1), Some(Bytes(1024 * 1024)));
        assert_eq!(Bytes::from_gib(1), Some(Bytes(1024 * 1024 * 1024)));
    }

    #[test]
    fn test_bytes_arithmetic() {
        let b1 = Bytes(1000);
        let b2 = Bytes(500);

        assert_eq!(b1.checked_add(b2), Some(Bytes(1500)));
        assert_eq!(b1.checked_sub(b2), Some(Bytes(500)));
        assert_eq!(b2.checked_mul(3), Some(Bytes(1500)));
    }

    #[test]
    fn test_bytes_display() {
        assert_eq!(Bytes(512).to_string(), "512 B");
        assert_eq!(Bytes::from_kib(2).unwrap().to_string(), "2.00 KiB");
        assert_eq!(Bytes::from_mib(5).unwrap().to_string(), "5.00 MiB");
    }

    #[test]
    fn test_bit_rate_creation() {
        assert_eq!(BitsPerSecond::from_kbps(1).unwrap().as_u64(), 1_000);
        assert_eq!(BitsPerSecond::from_mbps(1).unwrap().as_u64(), 1_000_000);
        assert_eq!(BitsPerSecond::from_gbps(1).unwrap().as_u64(), 1_000_000_000);
    }

    #[test]
    fn test_serialization_time() {
        // 1 Mbps rate, 1000 bytes (1 KB)
        // = 8000 bits / 1_000_000 bps = 0.008 seconds = 8 milliseconds
        let rate = BitsPerSecond::from_mbps(1).unwrap();
        let bytes = Bytes(1000);
        let time = rate.serialization_time(bytes).unwrap();

        assert_eq!(time.as_millis(), 8);
    }

    #[test]
    fn test_bytes_in_duration() {
        // 1 Mbps for 1 second should give 125,000 bytes (1 Mb = 125 KB)
        let rate = BitsPerSecond::from_mbps(1).unwrap();
        let duration = SimDuration::from_secs(1);
        let bytes = rate.bytes_in_duration(duration);

        assert_eq!(bytes.as_u64(), 125_000);
    }

    #[test]
    fn test_serialization_time_exact_fit() {
        // Test exact boundary: at what time does serialization complete?
        // For 100 bytes at 800 bps (100 bytes/sec):
        // = 800 bits / 800 bps = 1.0 second exactly
        let rate = BitsPerSecond::from_bps(800);
        let bytes = Bytes(100);
        let time = rate.serialization_time(bytes).unwrap();

        assert_eq!(time.as_secs(), 1);
    }

    #[test]
    fn test_bit_rate_display() {
        assert_eq!(BitsPerSecond::from_bps(500).to_string(), "500 bps");
        assert_eq!(
            BitsPerSecond::from_kbps(1).unwrap().to_string(),
            "1.00 Kbps"
        );
        assert_eq!(
            BitsPerSecond::from_mbps(10).unwrap().to_string(),
            "10.00 Mbps"
        );
    }
}
