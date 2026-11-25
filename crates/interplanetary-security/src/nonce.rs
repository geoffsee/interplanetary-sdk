//! Nonce safety for AES-GCM encryption
//!
//! AES-GCM security requires that (key, nonce) pairs are NEVER reused.
//! This module provides nonce tracking to prevent catastrophic failures
//! from nonce reuse, especially across simulation snapshots/clones.

use interplanetary_types::{Error, Result};
use std::collections::HashSet;

/// Registry tracking used (key_id, nonce) pairs to prevent reuse
///
/// ## Security Critical
///
/// AES-GCM is catastrophically broken if the same nonce is ever used twice
/// with the same key. This registry detects and prevents such reuse.
///
/// ## Usage Patterns
///
/// 1. **Normal operation**: Check before each BCB generation
/// 2. **Snapshot/clone**: Clone registry with simulation state
/// 3. **Testing**: Use deterministic nonces only in test fixtures
///
/// ## Thread Safety
///
/// This implementation is NOT thread-safe. For multi-threaded scenarios,
/// wrap in `Arc<Mutex<NonceRegistry>>`.
#[derive(Debug, Clone)]
pub struct NonceRegistry {
    /// Set of (key_id, nonce) pairs that have been used
    /// Stored as concatenated bytes for simplicity
    used: HashSet<Vec<u8>>,
}

impl NonceRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            used: HashSet::new(),
        }
    }

    /// Check if a (key_id, nonce) pair has been used before
    ///
    /// Returns `true` if the pair is new (safe to use).
    /// Returns `false` if the pair has been used (UNSAFE).
    pub fn is_unused(&self, key_id: &[u8], nonce: &[u8]) -> bool {
        let pair = Self::make_pair(key_id, nonce);
        !self.used.contains(&pair)
    }

    /// Register a (key_id, nonce) pair as used
    ///
    /// ## Errors
    ///
    /// Returns error if the pair was already registered (nonce reuse detected).
    pub fn register(&mut self, key_id: &[u8], nonce: &[u8]) -> Result<()> {
        let pair = Self::make_pair(key_id, nonce);

        if self.used.contains(&pair) {
            return Err(Error::security_failure(
                "Nonce reuse detected: same (key, nonce) pair used twice",
            ));
        }

        self.used.insert(pair);
        Ok(())
    }

    /// Check and register in one atomic operation
    ///
    /// This is the recommended method for BCB generation.
    ///
    /// ## Errors
    ///
    /// Returns error if nonce reuse is detected.
    pub fn check_and_register(&mut self, key_id: &[u8], nonce: &[u8]) -> Result<()> {
        self.register(key_id, nonce)
    }

    /// Clear all registered pairs (use with caution!)
    ///
    /// This should only be used in testing or when starting a completely
    /// new simulation context where key material has been rotated.
    pub fn clear(&mut self) {
        self.used.clear();
    }

    /// Get count of registered pairs
    pub fn len(&self) -> usize {
        self.used.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }

    /// Merge another registry into this one
    ///
    /// This is useful when combining state from multiple sources.
    ///
    /// ## Errors
    ///
    /// Returns error if any overlapping pairs are detected (would indicate
    /// nonce reuse across registries).
    pub fn merge(&mut self, other: &NonceRegistry) -> Result<()> {
        for pair in &other.used {
            if self.used.contains(pair) {
                return Err(Error::security_failure(
                    "Nonce collision detected when merging registries",
                ));
            }
            self.used.insert(pair.clone());
        }
        Ok(())
    }

    // Helper: combine key_id and nonce into single Vec for hashing
    fn make_pair(key_id: &[u8], nonce: &[u8]) -> Vec<u8> {
        let mut pair = Vec::with_capacity(key_id.len() + 1 + nonce.len());
        pair.extend_from_slice(key_id);
        pair.push(0xff); // Delimiter to prevent ambiguity
        pair.extend_from_slice(nonce);
        pair
    }
}

impl Default for NonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_registry_basic() {
        let mut registry = NonceRegistry::new();

        let key1 = b"key1";
        let nonce1 = b"nonce1";
        let nonce2 = b"nonce2";

        // First use should succeed
        assert!(registry.register(key1, nonce1).is_ok());

        // Reuse should fail
        assert!(registry.register(key1, nonce1).is_err());

        // Different nonce should succeed
        assert!(registry.register(key1, nonce2).is_ok());

        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_nonce_registry_different_keys() {
        let mut registry = NonceRegistry::new();

        let key1 = b"key1";
        let key2 = b"key2";
        let nonce = b"same_nonce";

        // Same nonce with different keys is OK
        assert!(registry.register(key1, nonce).is_ok());
        assert!(registry.register(key2, nonce).is_ok());

        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_nonce_registry_check_before_register() {
        let mut registry = NonceRegistry::new();

        let key = b"key";
        let nonce = b"nonce";

        assert!(registry.is_unused(key, nonce));

        registry.register(key, nonce).unwrap();

        assert!(!registry.is_unused(key, nonce));
    }

    #[test]
    fn test_nonce_registry_clone() {
        let mut registry1 = NonceRegistry::new();
        registry1.register(b"key1", b"nonce1").unwrap();

        // Clone creates independent copy
        let mut registry2 = registry1.clone();

        // Both see the same history
        assert!(registry1.register(b"key1", b"nonce1").is_err());
        assert!(registry2.register(b"key1", b"nonce1").is_err());

        // But can diverge
        registry2.register(b"key2", b"nonce2").unwrap();
        assert!(registry1.is_unused(b"key2", b"nonce2"));
    }

    #[test]
    fn test_nonce_registry_merge() {
        let mut registry1 = NonceRegistry::new();
        registry1.register(b"key1", b"nonce1").unwrap();

        let mut registry2 = NonceRegistry::new();
        registry2.register(b"key2", b"nonce2").unwrap();

        // Non-overlapping merge should succeed
        assert!(registry1.merge(&registry2).is_ok());
        assert_eq!(registry1.len(), 2);

        // Overlapping merge should fail
        let mut registry3 = NonceRegistry::new();
        registry3.register(b"key1", b"nonce1").unwrap();
        assert!(registry1.merge(&registry3).is_err());
    }

    #[test]
    fn test_nonce_registry_clear() {
        let mut registry = NonceRegistry::new();
        registry.register(b"key", b"nonce").unwrap();

        assert_eq!(registry.len(), 1);

        registry.clear();

        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());

        // Can reuse after clear
        assert!(registry.register(b"key", b"nonce").is_ok());
    }
}
