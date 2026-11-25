//! BPSec Context 2: AES-GCM Confidentiality (BCB) per RFC 9173 §5
//!
//! Resolves RFC 9173 erratum 7002: one target per BCB block, unique IV per operation.

#[cfg(test)]
use crate::bp::Bundle;
#[cfg(test)]
use crate::security::canonical::{SecurityTarget, canonicalize_for_bpsec};
use crate::types::Result;
use aes_gcm::{
    AesGcm,
    aead::{Aead, KeyInit, Payload},
    aes::{Aes128, Aes256},
};
use typenum::{U8, U9, U10, U11, U12, U13, U14, U15, U16};

/// AES-GCM variant per RFC 9173 §4.3.2 Table 4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AesGcmVariant {
    /// A128GCM (RFC 8152 Table 9)
    Aes128 = 1,
    /// A256GCM (RFC 8152 Table 9) - default per RFC 9173
    Aes256 = 3,
}

impl AesGcmVariant {
    /// Get AES key length in bytes
    pub fn key_len(&self) -> usize {
        match self {
            AesGcmVariant::Aes128 => 16,
            AesGcmVariant::Aes256 => 32,
        }
    }
}

/// AES-GCM confidentiality context (Context 2)
pub(crate) struct AesGcmContext {
    variant: AesGcmVariant,
}

impl AesGcmContext {
    pub(crate) fn new(variant: AesGcmVariant) -> Self {
        Self { variant }
    }

    /// Encrypt plaintext with AES-GCM (internal use only)
    ///
    /// Returns (ciphertext, authentication_tag)
    /// IV/nonce MUST be unique per key per erratum 7002.
    pub(crate) fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes. A value of 12 bytes SHOULD be used
        // unless local security policy requires a different length."
        if iv.len() < 8 || iv.len() > 16 {
            return Err(crate::types::Error::invalid_config(
                "RFC 9173 §4.3.1: IV must be between 8-16 bytes",
            ));
        }

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        // Dispatch based on IV length using typenum-generic AesGcm
        // RFC 9173 §4.3.1: IV must be 8-16 bytes; 12 is recommended
        let ciphertext = match (self.variant, iv.len()) {
            (AesGcmVariant::Aes128, 8) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U8>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U8>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 9) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U9>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U9>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 10) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U10>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U10>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 11) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U11>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U11>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 12) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U12>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U12>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 13) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U13>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U13>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 14) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U14>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U14>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 15) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U15>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U15>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes128, 16) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U16>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 8) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U8>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U8>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 9) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U9>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U9>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 10) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U10>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U10>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 11) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U11>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U11>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 12) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U12>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U12>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 13) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U13>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U13>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 14) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U14>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U14>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 15) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U15>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U15>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            (AesGcmVariant::Aes256, 16) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U16>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| crate::types::Error::security_failure("Encryption failed"))?
            }
            _ => {
                // This should be unreachable due to the length check at the start,
                // but we keep it for safety
                return Err(crate::types::Error::invalid_config(
                    "RFC 9173 §4.3.1: IV must be between 8-16 bytes",
                ));
            }
        };

        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        Ok((ct.to_vec(), tag.to_vec()))
    }

    /// Encrypt target per RFC 9173 §5.3 (bundle-based)
    ///
    /// Returns (ciphertext, authentication_tag)
    /// IV/nonce MUST be unique per key per erratum 7002.
    #[cfg(test)]
    pub(crate) fn encrypt_bundle(
        key: &[u8],
        iv: &[u8], // 8-16 bytes per RFC 9173 §4.3.1; 12 is recommended
        bundle: &Bundle,
        target: SecurityTarget,
        aad: &[u8], // Additional authenticated data
        variant: AesGcmVariant,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes. A value of 12 bytes SHOULD be used
        // unless local security policy requires a different length."
        if iv.len() < 8 || iv.len() > 16 {
            return Err(crate::types::Error::invalid_config(
                "RFC 9173 §4.3.1: IV must be between 8-16 bytes",
            ));
        }

        // Canonicalize target (this becomes the plaintext)
        let plaintext = canonicalize_for_bpsec(bundle, target)?;

        // Use the instance encrypt method
        let ctx = AesGcmContext::new(variant);
        ctx.encrypt(&plaintext, aad, key, iv)
    }

    /// Decrypt target
    pub(crate) fn decrypt(
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
        variant: AesGcmVariant,
    ) -> Result<Vec<u8>> {
        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes. A value of 12 bytes SHOULD be used
        // unless local security policy requires a different length."
        if iv.len() < 8 || iv.len() > 16 {
            return Err(crate::types::Error::protocol_violation(
                "RFC 9173 §4.3.1: IV must be between 8-16 bytes",
            ));
        }

        if tag.len() != 16 {
            return Err(crate::types::Error::invalid_config("Tag must be 16 bytes"));
        }

        // Reconstruct ciphertext with tag
        let mut ct_with_tag = ciphertext.to_vec();
        ct_with_tag.extend_from_slice(tag);

        let payload = Payload {
            msg: &ct_with_tag,
            aad,
        };

        // Dispatch based on IV length using typenum-generic AesGcm
        let plaintext = match (variant, iv.len()) {
            (AesGcmVariant::Aes128, 8) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U8>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U8>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 9) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U9>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U9>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 10) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U10>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U10>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 11) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U11>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U11>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 12) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U12>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U12>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 13) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U13>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U13>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 14) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U14>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U14>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 15) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U15>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U15>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes128, 16) => {
                if key.len() != 16 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-128 requires 16-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes128, U16>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 8) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U8>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U8>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 9) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U9>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U9>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 10) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U10>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U10>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 11) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U11>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U11>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 12) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U12>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U12>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 13) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U13>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U13>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 14) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U14>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U14>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 15) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U15>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U15>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            (AesGcmVariant::Aes256, 16) => {
                if key.len() != 32 {
                    return Err(crate::types::Error::invalid_config(
                        "AES-256 requires 32-byte key",
                    ));
                }
                let cipher = AesGcm::<Aes256, U16>::new_from_slice(key)
                    .map_err(|_| crate::types::Error::security_failure("Invalid key"))?;
                let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);
                cipher.decrypt(nonce, payload).map_err(|_| {
                    crate::types::Error::security_failure("Decryption/authentication failed")
                })?
            }
            _ => {
                // This should be unreachable due to the length check at the start,
                // but we keep it for safety
                return Err(crate::types::Error::protocol_violation(
                    "RFC 9173 §4.3.1: IV must be between 8-16 bytes",
                ));
            }
        };

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp::BundleBuilder;
    use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

    #[test]
    fn test_aesgcm_encrypt_decrypt_128() {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"Secret message".to_vec())
            .build()
            .unwrap();

        let key = b"sixteen-byte-key"; // 16 bytes for AES-128
        let iv = b"unique-nonce"; // 12 bytes
        let aad = b"additional-authenticated-data";

        let (ciphertext, tag) = AesGcmContext::encrypt_bundle(
            key,
            iv,
            &bundle,
            SecurityTarget::Block(1),
            aad,
            AesGcmVariant::Aes128,
        )
        .unwrap();

        assert!(!ciphertext.is_empty());
        assert_eq!(tag.len(), 16);

        let plaintext =
            AesGcmContext::decrypt(key, iv, &ciphertext, &tag, aad, AesGcmVariant::Aes128).unwrap();

        // Should recover original canonical form
        let original = canonicalize_for_bpsec(&bundle, SecurityTarget::Block(1)).unwrap();
        assert_eq!(plaintext, original);
    }

    #[test]
    fn test_aesgcm_wrong_key_fails() {
        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"Secret".to_vec())
            .build()
            .unwrap();

        let key1 = b"sixteen-byte-key";
        let key2 = b"different-key!!!";
        let iv = b"unique-nonce";
        let aad = b"aad";

        let (ct, tag) = AesGcmContext::encrypt_bundle(
            key1,
            iv,
            &bundle,
            SecurityTarget::Block(1),
            aad,
            AesGcmVariant::Aes128,
        )
        .unwrap();

        // Decryption with wrong key should fail
        let result = AesGcmContext::decrypt(key2, iv, &ct, &tag, aad, AesGcmVariant::Aes128);

        assert!(result.is_err());
    }
}
