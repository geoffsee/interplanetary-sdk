//! RFC 9173 Appendix A Known-Answer Tests
//!
//! Test vectors extracted from spec/sources/rfc9173.txt (SHA-256: 60fe3d47...)
//! Tests crypto primitives and bundle structures against RFC examples.
//!
//! Per charter and work order: A.1-A.3 verify generation and verification paths.
//! A.4 is a historical fixture only (erratum 7002 - multi-target IV reuse).
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::BundleCodec;
use std::fs;

#[test]
fn test_a1_simple_integrity_hmac() {
    // RFC 9173 A.1.3.1 (lines 1728-1778): BIB with HMAC-SHA2
    // Test HMAC-SHA-512 signature computation against known answer

    let vectors: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("spec/rfc9173_test_vectors.json").unwrap())
            .unwrap();

    let a1 = &vectors["vectors"][0];
    assert_eq!(a1["section"], "A.1.3.1");

    let key_hex = a1["key"].as_str().unwrap();
    let ippt_hex = a1["ippt"].as_str().unwrap();
    let expected_sig_hex = a1["signature"].as_str().unwrap();

    let key = hex::decode(key_hex).unwrap();
    let ippt = hex::decode(ippt_hex).unwrap();
    let expected_sig = hex::decode(expected_sig_hex).unwrap();

    // Compute HMAC-SHA-512/512 directly over IPPT
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let mut mac = Hmac::<Sha512>::new_from_slice(&key).unwrap();
    mac.update(&ippt);
    let computed_sig = mac.finalize().into_bytes();

    assert_eq!(
        computed_sig.as_slice(),
        expected_sig.as_slice(),
        "HMAC-SHA-512 signature must match RFC 9173 A.1.3.1"
    );
}

#[test]
fn test_a2_simple_confidentiality_aesgcm() {
    // RFC 9173 A.2.3.1 (lines 1897-1947): BCB with AES-GCM

    let vectors: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("spec/rfc9173_test_vectors.json").unwrap())
            .unwrap();

    let a2 = &vectors["vectors"][1];
    assert_eq!(a2["section"], "A.2.3.1");

    let cek_hex = a2["content_encryption_key"].as_str().unwrap();
    let iv_hex = a2["iv"].as_str().unwrap();
    let payload_hex = a2["payload_data"].as_str().unwrap();
    let aad_hex = a2["aad"].as_str().unwrap();
    let expected_ciphertext_hex = a2["payload_ciphertext"].as_str().unwrap();
    let expected_tag_hex = a2["authentication_tag"].as_str().unwrap();

    let cek = hex::decode(cek_hex).unwrap();
    let iv = hex::decode(iv_hex).unwrap();
    let plaintext = hex::decode(payload_hex).unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let expected_ciphertext = hex::decode(expected_ciphertext_hex).unwrap();
    let expected_tag = hex::decode(expected_tag_hex).unwrap();

    assert_eq!(
        iv.len(),
        12,
        "IV must be 12 bytes per RFC 9173 erratum 7002"
    );

    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };

    let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
    let nonce = Nonce::from_slice(&iv);

    let payload_struct = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let ciphertext_with_tag = cipher.encrypt(nonce, payload_struct).unwrap();
    let (computed_ciphertext, computed_tag) =
        ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    assert_eq!(
        computed_ciphertext,
        expected_ciphertext.as_slice(),
        "AES-GCM ciphertext must match RFC 9173 A.2.3.1"
    );

    assert_eq!(
        computed_tag,
        expected_tag.as_slice(),
        "AES-GCM tag must match RFC 9173 A.2.3.1"
    );

    // Verify final bundle structure
    let final_bundle_hex = a2["final_bundle"].as_str().unwrap();
    let final_bundle_bytes = hex::decode(final_bundle_hex).unwrap();

    let bundle = BundleCodec::decode(&final_bundle_bytes)
        .expect("A.2 final bundle must decode successfully");

    // Verify bundle has blocks: primary + BCB + payload
    assert!(
        bundle.blocks.len() >= 2,
        "A.2 bundle should have BCB and payload blocks"
    );

    // Find BCB (block type 12)
    use interplanetary_sdk::bp::blocks::BlockType;
    let bcb = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .expect("A.2 bundle must contain BCB");

    assert_eq!(bcb.block_number, 2, "BCB should be block number 2");
}

#[test]
fn test_a3_multi_source_security() {
    // RFC 9173 A.3 (lines 1990-2290): BIB + BCB from multiple sources

    let vectors: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("spec/rfc9173_test_vectors.json").unwrap())
            .unwrap();

    let a3 = &vectors["vectors"][2];
    assert_eq!(a3["section"], "A.3");
    assert!(
        a3["description"]
            .as_str()
            .unwrap()
            .contains("Multiple Sources")
    );

    // Verify BIB HMAC-256 signatures
    let bib_primary_ippt = hex::decode(a3["bib_primary_ippt"].as_str().unwrap()).unwrap();
    let bib_age_ippt = hex::decode(a3["bib_bundle_age_ippt"].as_str().unwrap()).unwrap();
    let expected_primary_sig = hex::decode(a3["bib_primary_signature"].as_str().unwrap()).unwrap();
    let expected_age_sig = hex::decode(a3["bib_bundle_age_signature"].as_str().unwrap()).unwrap();
    let key = hex::decode(a3["bib_key"].as_str().unwrap()).unwrap();

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac_primary = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac_primary.update(&bib_primary_ippt);
    let computed_primary_sig = mac_primary.finalize().into_bytes();

    assert_eq!(
        computed_primary_sig.as_slice(),
        expected_primary_sig.as_slice(),
        "A.3 primary block signature must match"
    );

    let mut mac_age = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac_age.update(&bib_age_ippt);
    let computed_age_sig = mac_age.finalize().into_bytes();

    assert_eq!(
        computed_age_sig.as_slice(),
        expected_age_sig.as_slice(),
        "A.3 bundle age block signature must match"
    );

    // Verify final bundle structure
    let final_bundle_hex = a3["final_bundle"].as_str().unwrap();
    let final_bundle_bytes = hex::decode(final_bundle_hex).unwrap();

    let bundle = BundleCodec::decode(&final_bundle_bytes)
        .expect("A.3 final bundle must decode successfully");

    // Should have primary + BIB + BCB + bundle age + payload (encrypted)
    assert!(
        bundle.blocks.len() >= 4,
        "A.3 bundle should have BIB, BCB, bundle age, and payload"
    );

    // Find BIB (block type 11)
    use interplanetary_sdk::bp::blocks::BlockType;
    let bib = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bib))
        .expect("A.3 bundle must contain BIB");

    assert_eq!(bib.block_number, 3, "BIB should be block number 3");

    // Find BCB (block type 12)
    let bcb = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .expect("A.3 bundle must contain BCB");

    assert_eq!(bcb.block_number, 4, "BCB should be block number 4");
}

#[test]
fn test_a4_full_scope_historical() {
    // RFC 9173 A.4 (lines 2294-2594): Full scope security
    // HISTORICAL FIXTURE ONLY - Erratum 7002: multi-target BCB shares IV
    // This test verifies we can decode the example but documents it's not a generation template

    let vectors: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("spec/rfc9173_test_vectors.json").unwrap())
            .unwrap();

    let a4 = &vectors["vectors"][3];
    assert_eq!(a4["section"], "A.4");
    assert!(a4["description"].as_str().unwrap().contains("HISTORICAL"));

    // Verify warning is present
    let warning = a4["warning"]
        .as_str()
        .expect("A.4 must have erratum 7002 warning");
    assert!(
        warning.contains("7002"),
        "Warning must mention erratum 7002"
    );
    assert!(
        warning.contains("never use as generation"),
        "Warning must prohibit generation use"
    );

    // Decode final bundle to verify structure
    let final_bundle_hex = a4["final_bundle"].as_str().unwrap();
    let final_bundle_bytes = hex::decode(final_bundle_hex).unwrap();

    let bundle = BundleCodec::decode(&final_bundle_bytes)
        .expect("A.4 bundle must decode for historical verification");

    // Should have primary + BIB (encrypted) + BCB + payload (encrypted)
    assert!(
        bundle.blocks.len() >= 3,
        "A.4 bundle should have BIB, BCB, and payload"
    );

    // Find BIB (block type 11)
    use interplanetary_sdk::bp::blocks::BlockType;
    let bib = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bib))
        .expect("A.4 bundle must contain BIB");

    assert_eq!(bib.block_number, 3, "BIB should be block number 3");

    // Find BCB (block type 12)
    let bcb = bundle
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Bcb))
        .expect("A.4 bundle must contain BCB");

    assert_eq!(bcb.block_number, 2, "BCB should be block number 2");

    // Verify scope flags indicate full scope (0x07)
    let scope_flags = a4["bcb_scope_flags"].as_str().unwrap();
    assert_eq!(scope_flags, "0x07", "A.4 BCB must have full scope flags");
}
