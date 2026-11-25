//! RFC 9173-056 Nonce Uniqueness Tests
//!
//! RFC 9173 §4.3.1: "The initialization vector can have any value, with the caveat
//! that a value MUST NOT be reused for multiple encryptions using the same encryption key."
#![cfg(feature = "bpsec-default")]

use interplanetary_sdk::security::{KeyProvider, NonceRegistry, StaticKeyProvider};

#[test]
fn test_rfc9173_056_static_provider_ensures_unique_nonces() {
    // RFC 9173 §4.3.1: IV MUST NOT be reused for same key
    // StaticKeyProvider uses a counter to ensure uniqueness

    let mut provider = StaticKeyProvider::new();
    provider.add_key("test-key", vec![0xAA; 16]);

    // Generate multiple nonces for the same key
    let nonce1 = provider.get_nonce("test-key").unwrap();
    let nonce2 = provider.get_nonce("test-key").unwrap();
    let nonce3 = provider.get_nonce("test-key").unwrap();

    // All nonces MUST be different
    assert_ne!(nonce1, nonce2, "Nonces must be unique per RFC 9173 §4.3.1");
    assert_ne!(nonce2, nonce3, "Nonces must be unique per RFC 9173 §4.3.1");
    assert_ne!(nonce1, nonce3, "Nonces must be unique per RFC 9173 §4.3.1");

    // Nonces should be 12 bytes for AES-GCM
    assert_eq!(nonce1.len(), 12);
    assert_eq!(nonce2.len(), 12);
    assert_eq!(nonce3.len(), 12);
}

#[test]
fn test_rfc9173_056_nonce_registry_detects_reuse() {
    // RFC 9173 §4.3.1: Nonce reuse MUST NOT occur
    // NonceRegistry provides runtime detection of violations

    let mut registry = NonceRegistry::new();

    let key = b"test-key";
    let nonce = b"test-nonce-12";

    // First use should succeed
    assert!(
        registry.register(key, nonce).is_ok(),
        "First nonce use must succeed"
    );

    // Reuse should fail (would violate RFC 9173 §4.3.1)
    let result = registry.register(key, nonce);
    assert!(
        result.is_err(),
        "Nonce reuse must be detected and rejected per RFC 9173 §4.3.1"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Nonce reuse") || err_msg.contains("used twice"),
        "Error should indicate nonce reuse, got: {}",
        err_msg
    );
}

#[test]
fn test_rfc9173_056_same_nonce_different_keys_allowed() {
    // RFC 9173 §4.3.1: Reuse constraint is per-key
    // Same nonce can be used with different keys

    let mut registry = NonceRegistry::new();

    let key1 = b"key1";
    let key2 = b"key2";
    let nonce = b"same-nonce-12";

    // Using same nonce with different keys is allowed
    assert!(
        registry.register(key1, nonce).is_ok(),
        "Nonce use with key1 must succeed"
    );
    assert!(
        registry.register(key2, nonce).is_ok(),
        "Same nonce with different key (key2) is allowed"
    );

    // But reuse with same key is still forbidden
    assert!(
        registry.register(key1, nonce).is_err(),
        "Reuse with same key must be rejected"
    );
}

#[test]
fn test_rfc9173_056_provider_generates_many_unique_nonces() {
    // RFC 9173 §4.3.1: Verify provider can generate many unique nonces
    // This ensures the counter-based approach is robust

    let mut provider = StaticKeyProvider::new();
    provider.add_key("test-key", vec![0xAA; 16]);

    let mut nonces = Vec::new();
    for _ in 0..1000 {
        let nonce = provider.get_nonce("test-key").unwrap();
        assert_eq!(nonce.len(), 12, "Nonce must be 12 bytes");

        // Check uniqueness against all previous nonces
        for prev in &nonces {
            assert_ne!(
                &nonce, prev,
                "Generated nonce must be unique per RFC 9173 §4.3.1"
            );
        }

        nonces.push(nonce);
    }

    assert_eq!(nonces.len(), 1000, "Should generate 1000 unique nonces");
}
