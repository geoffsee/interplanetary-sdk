//! Constant-time byte comparison for BPSec authentication tags (RFC 9173 §3.6).
//!
//! All BIB-HMAC-SHA2 / BCB-AES-GCM tag comparisons on the production path MUST
//! go through [`constant_time_eq`] so a single incorrect implementation is
//! detectable by tests (RFC9173-020).

use subtle::ConstantTimeEq;

/// Compare two byte slices in constant time.
///
/// Returns `true` iff lengths match and every byte is equal. A mismatch in any
/// position (including the last byte) returns `false`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc9173_020_constant_time_eq_match_and_last_byte_mismatch() {
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut b = a;
        assert!(
            constant_time_eq(&a, &b),
            "RFC9173-020: identical tags MUST compare equal"
        );
        b[15] ^= 0x01;
        assert!(
            !constant_time_eq(&a, &b),
            "RFC9173-020: last-byte mismatch MUST be rejected"
        );
        assert!(
            !constant_time_eq(&a, &a[..15]),
            "RFC9173-020: length mismatch MUST be rejected"
        );
    }
}
