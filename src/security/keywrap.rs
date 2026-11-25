//! AES Key Wrap (AES-KW) per RFC 3394 and RFC 9173 §3.3.2, §4.3.3
//!
//! Wraps content encryption keys with key encryption keys for secure distribution.

use crate::types::{Error, Result};
use aes_kw::{KekAes128, KekAes192, KekAes256};

/// Wrap a content encryption key (CEK) with a key encryption key (KEK) using AES-KW
///
/// RFC 9173 §3.3.2 (BIB): "This optional parameter contains the output of the AES key wrap
/// function as defined in \[RFC3394\]. Specifically, this parameter holds the output of the
/// AES-KW key wrap function (KW) as defined in Section 2.2.1 of \[RFC3394\]."
///
/// RFC 9173 §4.3.3 (BCB): "This optional parameter contains the output of the AES key wrap
/// function as defined in \[RFC3394\]. Specifically, this parameter holds the output of the
/// AES-KW key wrap function (KW) as defined in Section 2.2.1 of \[RFC3394\]."
///
/// # Arguments
/// * `kek` - Key encryption key (16, 24, or 32 bytes for AES-128/192/256)
/// * `cek` - Content encryption key to wrap (must be multiple of 8 bytes)
///
/// # Returns
/// Wrapped key bytes (len = cek.len() + 8)
///
/// # Errors
/// Returns error if KEK length is invalid or wrapping fails
pub fn wrap_key(kek: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    // RFC 3394 §2: KEK must be 128, 192, or 256 bits
    match kek.len() {
        16 | 24 | 32 => {}
        _ => {
            return Err(Error::invalid_config(format!(
                "KEK must be 16, 24, or 32 bytes for AES-128/192/256, got {}",
                kek.len()
            )));
        }
    }

    // RFC 3394 §2.2.1: plaintext (CEK) must be multiple of 8 bytes (semiblocks)
    if cek.len() % 8 != 0 {
        return Err(Error::invalid_config(format!(
            "CEK must be multiple of 8 bytes for AES-KW, got {}",
            cek.len()
        )));
    }

    // Perform AES-KW wrapping based on KEK length
    // RFC 3394: wrapped output is input length + 8 bytes
    let mut wrapped = vec![0u8; cek.len() + 8];

    match kek.len() {
        16 => {
            let kek_obj = KekAes128::try_from(kek)
                .map_err(|_| Error::security_failure("Failed to create AES-128 KEK"))?;
            kek_obj
                .wrap(cek, &mut wrapped)
                .map_err(|_| Error::security_failure("AES-KW key wrapping failed"))?;
        }
        24 => {
            let kek_obj = KekAes192::try_from(kek)
                .map_err(|_| Error::security_failure("Failed to create AES-192 KEK"))?;
            kek_obj
                .wrap(cek, &mut wrapped)
                .map_err(|_| Error::security_failure("AES-KW key wrapping failed"))?;
        }
        32 => {
            let kek_obj = KekAes256::try_from(kek)
                .map_err(|_| Error::security_failure("Failed to create AES-256 KEK"))?;
            kek_obj
                .wrap(cek, &mut wrapped)
                .map_err(|_| Error::security_failure("AES-KW key wrapping failed"))?;
        }
        _ => {
            return Err(Error::invalid_config(format!(
                "KEK length {} is invalid",
                kek.len()
            )));
        }
    }

    Ok(wrapped)
}

/// Unwrap a wrapped key using AES-KW
///
/// RFC 9173 §3.7 (BIB): "The HMAC key MUST be derived using the wrapped key security
/// context parameter if such a parameter is included in the security context parameters
/// of the BIB."
///
/// RFC 9173 §5.3 (BCB): "The decryption key MUST be derived using the wrapped key security
/// context parameter if such a parameter is included in the security context parameters
/// of the BCB."
///
/// # Arguments
/// * `kek` - Key encryption key (16, 24, or 32 bytes for AES-128/192/256)
/// * `wrapped_key` - Wrapped key bytes from security parameters
///
/// # Returns
/// Unwrapped content encryption key
///
/// # Errors
/// Returns error if KEK is invalid, wrapped key is invalid, or unwrapping fails
pub fn unwrap_key(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>> {
    // RFC 3394 §2: KEK must be 128, 192, or 256 bits
    match kek.len() {
        16 | 24 | 32 => {}
        _ => {
            return Err(Error::invalid_config(format!(
                "KEK must be 16, 24, or 32 bytes for AES-128/192/256, got {}",
                kek.len()
            )));
        }
    }

    // RFC 3394 §2.2.2: wrapped key must be at least 24 bytes (n >= 2 semiblocks + ICV)
    if wrapped_key.len() < 24 {
        return Err(Error::security_failure(format!(
            "Wrapped key too short: {} bytes (minimum 24)",
            wrapped_key.len()
        )));
    }

    // Perform AES-KW unwrapping based on KEK length
    // RFC 3394: unwrapped output is input length - 8 bytes
    let mut unwrapped = vec![0u8; wrapped_key.len() - 8];

    match kek.len() {
        16 => {
            let kek_obj = KekAes128::try_from(kek)
                .map_err(|_| Error::security_failure("Failed to create AES-128 KEK"))?;
            kek_obj.unwrap(wrapped_key, &mut unwrapped).map_err(|_| {
                Error::security_failure(
                    "AES-KW key unwrapping failed (wrong KEK or corrupted wrapped key)",
                )
            })?;
        }
        24 => {
            let kek_obj = KekAes192::try_from(kek)
                .map_err(|_| Error::security_failure("Failed to create AES-192 KEK"))?;
            kek_obj.unwrap(wrapped_key, &mut unwrapped).map_err(|_| {
                Error::security_failure(
                    "AES-KW key unwrapping failed (wrong KEK or corrupted wrapped key)",
                )
            })?;
        }
        32 => {
            let kek_obj = KekAes256::try_from(kek)
                .map_err(|_| Error::security_failure("Failed to create AES-256 KEK"))?;
            kek_obj.unwrap(wrapped_key, &mut unwrapped).map_err(|_| {
                Error::security_failure(
                    "AES-KW key unwrapping failed (wrong KEK or corrupted wrapped key)",
                )
            })?;
        }
        _ => {
            return Err(Error::invalid_config(format!(
                "KEK length {} is invalid",
                kek.len()
            )));
        }
    }

    Ok(unwrapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc9173_a2_wrapped_key_exact_bytes() {
        // RFC 9173 Appendix A.2: AES-KW test vector
        // "Content Encryption Key: h'71776572747975696f70617364666768'"
        // "Key Encryption Key: h'6162636465666768696a6b6c6d6e6f70'"
        // "AES Wrapped Key: h'69c411276fecddc4780df42c8a2af89296fabf34d7fae700'"

        let cek = hex::decode("71776572747975696f70617364666768").unwrap();
        let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
        let expected_wrapped =
            hex::decode("69c411276fecddc4780df42c8a2af89296fabf34d7fae700").unwrap();

        let wrapped = wrap_key(&kek, &cek).expect("wrapping should succeed");
        assert_eq!(
            wrapped, expected_wrapped,
            "RFC 9173 A.2 wrapped key mismatch.\nExpected: {:02x?}\nGot:      {:02x?}",
            expected_wrapped, wrapped
        );
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap(); // 16 bytes
        let cek = hex::decode("71776572747975696f70617364666768").unwrap(); // 16 bytes

        let wrapped = wrap_key(&kek, &cek).expect("wrap should succeed");
        assert_eq!(
            wrapped.len(),
            cek.len() + 8,
            "wrapped key should be 8 bytes longer"
        );

        let unwrapped = unwrap_key(&kek, &wrapped).expect("unwrap should succeed");
        assert_eq!(unwrapped, cek, "roundtrip should recover original CEK");
    }

    #[test]
    fn test_unwrap_wrong_kek_fails() {
        let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
        let cek = hex::decode("71776572747975696f70617364666768").unwrap();
        let wrapped = wrap_key(&kek, &cek).expect("wrap should succeed");

        // Wrong KEK
        let wrong_kek = hex::decode("ffffffffffffffffffffffffffffffff").unwrap();
        let result = unwrap_key(&wrong_kek, &wrapped);
        assert!(result.is_err(), "unwrapping with wrong KEK should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unwrapping failed"),
            "error should indicate unwrapping failure"
        );
    }

    #[test]
    fn test_cek_not_multiple_of_8_fails() {
        let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
        let cek = vec![0u8; 15]; // Not multiple of 8

        let result = wrap_key(&kek, &cek);
        assert!(
            result.is_err(),
            "wrapping non-8-byte-multiple CEK should fail"
        );
        assert!(
            result.unwrap_err().to_string().contains("multiple of 8"),
            "error should mention 8-byte requirement"
        );
    }

    #[test]
    fn test_invalid_kek_length_fails() {
        let invalid_kek = vec![0u8; 17]; // Not 16, 24, or 32
        let cek = vec![0u8; 16];

        let result = wrap_key(&invalid_kek, &cek);
        assert!(result.is_err(), "invalid KEK length should fail");
        assert!(
            result.unwrap_err().to_string().contains("KEK must be"),
            "error should mention KEK length requirement"
        );
    }

    #[test]
    fn test_wrapped_key_too_short_fails() {
        let kek = hex::decode("6162636465666768696a6b6c6d6e6f70").unwrap();
        let short_wrapped = vec![0u8; 16]; // Less than 24 bytes

        let result = unwrap_key(&kek, &short_wrapped);
        assert!(result.is_err(), "wrapped key too short should fail");
        assert!(
            result.unwrap_err().to_string().contains("too short"),
            "error should indicate wrapped key is too short"
        );
    }
}
