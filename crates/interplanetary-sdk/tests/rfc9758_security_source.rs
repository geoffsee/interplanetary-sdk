//! RFC 9758 §5.4-5.5: Security source validation tests
//!
//! Per RFC 9758:
//! - §5.4: LocalNode ipn EID MUST NOT be used as a BPSec security source
//! - §5.5: Private Use ipn EID MUST NOT be used as a BPSec security source
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::BundleBuilder;
use interplanetary_sdk::security::HmacVariant;
use interplanetary_sdk::security::bib::{self, BibConfig, BibTargets};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// RFC 9758 §5.4: LocalNode ipn EID MUST NOT be used as BPSec security source (BIB)
#[test]
fn test_rfc9758_5_4_localnode_rejected_as_bib_source() {
    // LocalNode is ipn:4294967295.X in default allocator (allocator 0)
    let local_node_eid = EndpointId::ipn(0, 4294967295, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 16777216, 0).unwrap())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(86_400_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let config = BibConfig {
        targets: BibTargets {
            block_numbers: vec![1],
        },
        security_source: local_node_eid,
        sha_variant: HmacVariant::Sha256,
        key: vec![0u8; 32],
        scope_flags: 0,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    // Per RFC 9758 §5.4: "LocalNode ipn EID MUST NOT be used as a Bundle Protocol
    // Security (BPSec) [RFC9172] security source for a bundle transmitted from the
    // local bundle node"
    let result = bib::generate_bib(&bundle, &config);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("LocalNode ipn EID MUST NOT be used")
    );
}

/// RFC 9758 §5.5: Private Use ipn EID MUST NOT be used as BPSec security source (BIB)
#[test]
fn test_rfc9758_5_5_private_use_rejected_as_bib_source() {
    // Private Use range in default allocator: 1..16777215 (0x000001..0xFFFFFF)
    let private_use_eid = EndpointId::ipn(0, 100, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 16777216, 0).unwrap())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(86_400_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let config = BibConfig {
        targets: BibTargets {
            block_numbers: vec![1],
        },
        security_source: private_use_eid,
        sha_variant: HmacVariant::Sha256,
        key: vec![0u8; 32],
        scope_flags: 0,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    // Per RFC 9758 §5.5: "Private Use ipn EID MUST NOT be used as a BPSec
    // [RFC9172] security source for a bundle when the bundle is destined for
    // a different administrative domain."
    let result = bib::generate_bib(&bundle, &config);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Private Use ipn EID MUST NOT be used")
    );
}

/// Verify that valid security sources are accepted
#[test]
fn test_valid_security_source_accepted() {
    // Non-private, non-LocalNode EID (node >= 0x1000000 in default allocator)
    let valid_eid = EndpointId::ipn(0, 0x1000000, 0).unwrap();

    let bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 16777216, 0).unwrap())
        .destination(EndpointId::ipn(0, 16777217, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
        .lifetime(86_400_000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    let config = BibConfig {
        targets: BibTargets {
            block_numbers: vec![1],
        },
        security_source: valid_eid,
        sha_variant: HmacVariant::Sha256,
        key: vec![0u8; 32],
        scope_flags: 0,
        wrapped_key: None,
        skip_source_validation: false,
        hmac_key_policy: None,
    };

    // Should succeed with valid security source
    let result = bib::generate_bib(&bundle, &config);
    assert!(result.is_ok());
}
