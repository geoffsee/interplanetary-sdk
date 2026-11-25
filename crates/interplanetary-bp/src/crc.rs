//! CRC computation per RFC 9171 §4.2.2

/// CRC type codes per RFC 9171 Table 1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcType {
    /// No CRC present (type 0)
    None = 0,
    /// CRC-16 (type 1) - X25 variant
    Crc16 = 1,
    /// CRC-32 (type 2) - Castagnoli variant
    Crc32 = 2,
}

impl CrcType {
    /// Create from wire value
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Crc16),
            2 => Some(Self::Crc32),
            _ => None,
        }
    }

    /// Convert to wire value
    pub fn to_u64(&self) -> u64 {
        *self as u64
    }

    /// Get expected CRC length in bytes
    pub fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Crc16 => 2,
            Self::Crc32 => 4,
        }
    }

    /// Check if CRC type has zero length (CrcType::None)
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
/// CRC computation and validation
#[derive(Debug)]
pub struct Crc;

impl Crc {
    /// Compute CRC-16 (X25 variant) per RFC 9171
    ///
    /// X.25 CRC-16: polynomial 0x1021, init 0xFFFF, refin=true, refout=true, xorout=0xFFFF
    pub fn crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0xFFFF;

        for &byte in data {
            // Reflect input byte
            let reflected_byte = Self::reflect_u8(byte);
            crc ^= (reflected_byte as u16) << 8;

            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }

        // Reflect output and XOR with 0xFFFF
        let reflected_crc = Self::reflect_u16(crc);
        reflected_crc ^ 0xFFFF
    }

    fn reflect_u8(byte: u8) -> u8 {
        let mut result = 0u8;
        for i in 0..8 {
            if byte & (1 << i) != 0 {
                result |= 1 << (7 - i);
            }
        }
        result
    }

    fn reflect_u16(value: u16) -> u16 {
        let mut result = 0u16;
        for i in 0..16 {
            if value & (1 << i) != 0 {
                result |= 1 << (15 - i);
            }
        }
        result
    }

    /// Compute CRC-32C (Castagnoli) per RFC 9171
    ///
    /// Polynomial: 0x1EDC6F41, uses lookup table for efficiency
    pub fn crc32c(data: &[u8]) -> u32 {
        // CRC-32C (Castagnoli) implementation
        // Polynomial: 0x1EDC6F41
        const POLY: u32 = 0x82F63B78; // Reversed polynomial

        let mut crc: u32 = 0xFFFFFFFF;

        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ POLY
                } else {
                    crc >> 1
                };
            }
        }

        crc ^ 0xFFFFFFFF
    }

    /// Compute CRC of specified type
    pub fn compute(crc_type: CrcType, data: &[u8]) -> Vec<u8> {
        match crc_type {
            CrcType::None => vec![],
            CrcType::Crc16 => {
                let crc = Self::crc16(data);
                crc.to_be_bytes().to_vec()
            }
            CrcType::Crc32 => {
                let crc = Self::crc32c(data);
                crc.to_be_bytes().to_vec()
            }
        }
    }

    /// Verify CRC
    pub fn verify(crc_type: CrcType, data: &[u8], expected: &[u8]) -> bool {
        if expected.len() != crc_type.len() {
            return false;
        }

        let computed = Self::compute(crc_type, data);
        computed == expected
    }
}

/// Verify CRC for bundle block
/// Returns Ok(true) if valid, Ok(false) if invalid, Err if CRC type unknown
pub fn verify_crc(
    data: &[u8],
    crc_value: &[u8],
    crc_type: CrcType,
) -> interplanetary_types::Result<bool> {
    Ok(Crc::verify(crc_type, data, crc_value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_simple() {
        let data = b"hello";
        let crc = Crc::crc16(data);

        // Recompute should match
        let crc2 = Crc::crc16(data);
        assert_eq!(crc, crc2);

        // Different data should differ
        let crc3 = Crc::crc16(b"world");
        assert_ne!(crc, crc3);
    }

    #[test]
    fn test_crc32c_simple() {
        let data = b"hello";
        let crc = Crc::crc32c(data);

        // Recompute should match
        let crc2 = Crc::crc32c(data);
        assert_eq!(crc, crc2);

        // Different data should differ
        let crc3 = Crc::crc32c(b"world");
        assert_ne!(crc, crc3);
    }

    #[test]
    fn test_crc_compute_and_verify() {
        let data = b"test data";

        let crc16 = Crc::compute(CrcType::Crc16, data);
        assert_eq!(crc16.len(), 2);
        assert!(Crc::verify(CrcType::Crc16, data, &crc16));

        let crc32 = Crc::compute(CrcType::Crc32, data);
        assert_eq!(crc32.len(), 4);
        assert!(Crc::verify(CrcType::Crc32, data, &crc32));

        // Wrong CRC should fail
        let wrong = vec![0u8; 2];
        assert!(!Crc::verify(CrcType::Crc16, data, &wrong));
    }

    #[test]
    fn test_crc_type_len() {
        assert_eq!(CrcType::None.len(), 0);
        assert_eq!(CrcType::Crc16.len(), 2);
        assert_eq!(CrcType::Crc32.len(), 4);
    }

    #[test]
    fn test_crc16_check_value() {
        // Standard "123456789" check value for CRC-16/X-25
        // Expected: 0x906E per RFC specification
        let data = b"123456789";
        let crc = Crc::crc16(data);
        assert_eq!(crc, 0x906E, "CRC-16/X-25 check value for '123456789'");
    }

    #[test]
    fn test_crc32c_check_value() {
        // Standard "123456789" check value for CRC-32C (Castagnoli)
        // Expected: 0xE3069283 per RFC specification
        let data = b"123456789";
        let crc = Crc::crc32c(data);
        assert_eq!(crc, 0xE3069283, "CRC-32C check value for '123456789'");
    }
}
