//! Key and nonce providers for BPSec contexts

use interplanetary_types::Result;
use std::collections::HashMap;

/// Key material provider trait
pub trait KeyProvider {
    /// Get key by key ID
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Get nonce for operation (must be unique per key)
    fn get_nonce(&mut self, key_id: &str) -> Result<Vec<u8>>;
}

/// In-memory [`KeyProvider`] for demos and unit tests (not HSM-backed).
///
/// # Examples
///
/// ```
/// use interplanetary_security::{KeyProvider, StaticKeyProvider};
///
/// # fn main() -> interplanetary_types::Result<()> {
/// let mut keys = StaticKeyProvider::new();
/// keys.add_key("hmac-1", vec![0x11; 32]);
///
/// assert_eq!(keys.get_key("hmac-1")?.len(), 32);
/// let n1 = keys.get_nonce("hmac-1")?;
/// let n2 = keys.get_nonce("hmac-1")?;
/// assert_ne!(n1, n2); // counter-based uniqueness
/// assert_eq!(n1.len(), 12);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct StaticKeyProvider {
    keys: HashMap<String, Vec<u8>>,
    nonce_counter: HashMap<String, u64>,
}

impl StaticKeyProvider {
    /// Create new provider
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            nonce_counter: HashMap::new(),
        }
    }

    /// Register key material under `key_id`
    pub fn add_key(&mut self, key_id: impl Into<String>, key: Vec<u8>) {
        self.keys.insert(key_id.into(), key);
    }
}

impl Default for StaticKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for StaticKeyProvider {
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>> {
        self.keys.get(key_id).cloned().ok_or_else(|| {
            interplanetary_types::Error::not_found(format!("Key {} not found", key_id))
        })
    }

    fn get_nonce(&mut self, key_id: &str) -> Result<Vec<u8>> {
        // Simple counter-based nonce (sufficient for testing)
        let counter = self.nonce_counter.entry(key_id.to_string()).or_insert(0);
        *counter += 1;

        // 12-byte nonce for AES-GCM (96 bits)
        let mut nonce = vec![0u8; 12];
        let counter_bytes = counter.to_be_bytes();
        nonce[4..12].copy_from_slice(&counter_bytes);

        Ok(nonce)
    }
}
