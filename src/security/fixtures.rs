//! Deterministic key and nonce providers for RFC test fixtures

use super::keys::KeyProvider;
use crate::types::Result;
use std::collections::HashMap;

/// Deterministic nonce provider for test fixtures
/// Always returns the same nonce for a given key (for RFC vector reproduction)
#[derive(Debug)]
pub struct FixtureNonceProvider {
    fixed_nonces: HashMap<String, Vec<u8>>,
}

impl FixtureNonceProvider {
    pub fn new() -> Self {
        Self {
            fixed_nonces: HashMap::new(),
        }
    }

    /// Set a fixed nonce for a key
    pub fn set_nonce(&mut self, key_id: impl Into<String>, nonce: Vec<u8>) {
        self.fixed_nonces.insert(key_id.into(), nonce);
    }
}

/// Fixture key provider with deterministic nonces
#[derive(Debug)]
pub struct FixtureKeyProvider {
    keys: HashMap<String, Vec<u8>>,
    nonces: FixtureNonceProvider,
}

impl Default for FixtureKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureKeyProvider {
    /// Create new fixture key provider
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            nonces: FixtureNonceProvider::new(),
        }
    }

    /// Add key for testing
    pub fn add_key(&mut self, key_id: impl Into<String>, key: Vec<u8>) {
        self.keys.insert(key_id.into(), key);
    }

    /// Set deterministic nonce for testing
    pub fn set_nonce(&mut self, key_id: impl Into<String>, nonce: Vec<u8>) {
        self.nonces.set_nonce(key_id, nonce);
    }
}

impl KeyProvider for FixtureKeyProvider {
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>> {
        self.keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| crate::types::Error::not_found(format!("Key {} not found", key_id)))
    }

    fn get_nonce(&mut self, key_id: &str) -> Result<Vec<u8>> {
        self.nonces
            .fixed_nonces
            .get(key_id)
            .cloned()
            .ok_or_else(|| crate::types::Error::not_found(format!("Nonce for {} not set", key_id)))
    }
}
