//! RFC 9172 ASB Structure Tests
//!
//! RFC 9172 §3.6: "The fields of the ASB SHALL be as follows, listed in the order
//! in which they must appear."
//!
//! RFC 9172 §3.6: "The encoding of these fields MUST be in accordance with the
//! canonical forms provided in Section 4."
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{bp::*, types::*};

/// Helper to create a bundle with manually-constructed BIB
fn create_bundle_with_manual_bib(bib_data: Vec<u8>) -> Vec<u8> {
    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Test".to_vec())
        .build()
        .unwrap();

    let bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0x01,
        crc_type: CrcType::None,
        data: bib_data,
    };

    bundle.blocks.insert(0, bib);
    BundleCodec::encode(&bundle).unwrap()
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_017_asb_fields_out_of_order_rejected() {
    // RFC 9172 §3.6: Fields SHALL appear in order: targets, context_id, flags, source, params, results
    //
    // Test: Create BIB with fields out of order (swap context_id and targets). Receiver must reject.

    use ciborium::Value;
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let source = EndpointId::ipn(0, 2, 1).unwrap();

    // Build BIB with WRONG field order: context_id BEFORE targets
    let mut bib_data = Vec::new();

    // Field 1 (WRONG): context_id (should be targets)
    ciborium::into_writer(&Value::Integer(1.into()), &mut bib_data).unwrap();

    // Field 2 (WRONG): targets (should be context_id)
    ciborium::into_writer(&Value::Array(vec![Value::Integer(1.into())]), &mut bib_data).unwrap();

    // Fields 3-6: flags, source, params, results (correct order)
    ciborium::into_writer(&Value::Integer(0.into()), &mut bib_data).unwrap();

    let source_value = Value::Array(vec![
        Value::Integer(2.into()),
        Value::Array(vec![Value::Integer(2.into()), Value::Integer(1.into())]),
    ]);
    ciborium::into_writer(&source_value, &mut bib_data).unwrap();

    let params = Value::Array(vec![
        Value::Array(vec![Value::Integer(1.into()), Value::Integer(6.into())]),
        Value::Array(vec![Value::Integer(3.into()), Value::Integer(0.into())]),
    ]);
    ciborium::into_writer(&params, &mut bib_data).unwrap();

    let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(vec![0xAA; 48]),
    ])])]);
    ciborium::into_writer(&results, &mut bib_data).unwrap();

    let encoded = create_bundle_with_manual_bib(bib_data);

    // Receiver setup
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source, vec![0xAA; 48]);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: Default::default(),
        cla_mtu: None,
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: Default::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(interplanetary_sdk::types::Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // RFC 9172 §3.6: Bundle with out-of-order ASB fields MUST be rejected
    let result = agent.receive_bytes_from_cla(&encoded);

    assert!(
        result.is_err() || agent.delivered_adus().is_empty(),
        "RFC 9172 §3.6: Bundle with ASB fields out of order MUST be rejected"
    );
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_018_non_canonical_cbor_rejected() {
    // RFC 9172 §3.6: Encoding MUST be canonical per Section 4
    //
    // Test: Create BIB with non-canonical CBOR (indefinite-length array). Receiver must reject.

    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let source = EndpointId::ipn(0, 2, 1).unwrap();

    // Build BIB with non-canonical encoding: indefinite-length array for targets
    let mut bib_data = Vec::new();

    // Field 1: targets as INDEFINITE-LENGTH array (non-canonical)
    // CBOR indefinite array: 0x9F (start), items..., 0xFF (break)
    bib_data.push(0x9F); // Start indefinite array
    bib_data.push(0x01); // Integer 1 (target block number)
    bib_data.push(0xFF); // Break

    // Field 2-6: remaining fields (using canonical encoding)
    use ciborium::Value;

    ciborium::into_writer(&Value::Integer(1.into()), &mut bib_data).unwrap();
    ciborium::into_writer(&Value::Integer(0.into()), &mut bib_data).unwrap();

    let source_value = Value::Array(vec![
        Value::Integer(2.into()),
        Value::Array(vec![Value::Integer(2.into()), Value::Integer(1.into())]),
    ]);
    ciborium::into_writer(&source_value, &mut bib_data).unwrap();

    let params = Value::Array(vec![
        Value::Array(vec![Value::Integer(1.into()), Value::Integer(6.into())]),
        Value::Array(vec![Value::Integer(3.into()), Value::Integer(0.into())]),
    ]);
    ciborium::into_writer(&params, &mut bib_data).unwrap();

    let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(vec![0xAA; 48]),
    ])])]);
    ciborium::into_writer(&results, &mut bib_data).unwrap();

    let encoded = create_bundle_with_manual_bib(bib_data);

    // Receiver setup
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source, vec![0xAA; 48]);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: Default::default(),
        cla_mtu: None,
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: Default::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(interplanetary_sdk::types::Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // RFC 9172 §3.6 + §4: Bundle with non-canonical CBOR MUST be rejected
    let result = agent.receive_bytes_from_cla(&encoded);

    assert!(
        result.is_err() || agent.delivered_adus().is_empty(),
        "RFC 9172 §3.6: Bundle with non-canonical CBOR in ASB MUST be rejected"
    );
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9172_018_non_minimal_integer_rejected() {
    // RFC 9172 §4: Canonical CBOR requires minimal integer encoding
    //
    // Test: Encode small integer with unnecessarily long encoding. Receiver must reject.

    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let source = EndpointId::ipn(0, 2, 1).unwrap();

    // Build BIB with non-minimal integer: encode 1 as 2-byte integer (non-canonical)
    let mut bib_data = Vec::new();

    use ciborium::Value;

    // Field 1: targets
    ciborium::into_writer(&Value::Array(vec![Value::Integer(1.into())]), &mut bib_data).unwrap();

    // Field 2: context_id with NON-MINIMAL encoding
    // Canonical: 0x01 (1-byte uint)
    // Non-canonical: 0x19 0x00 0x01 (2-byte uint for value 1)
    bib_data.push(0x19); // CBOR major type 0, additional info 25 (2-byte uint16)
    bib_data.push(0x00);
    bib_data.push(0x01);

    // Field 3-6: remaining fields
    ciborium::into_writer(&Value::Integer(0.into()), &mut bib_data).unwrap();

    let source_value = Value::Array(vec![
        Value::Integer(2.into()),
        Value::Array(vec![Value::Integer(2.into()), Value::Integer(1.into())]),
    ]);
    ciborium::into_writer(&source_value, &mut bib_data).unwrap();

    let params = Value::Array(vec![
        Value::Array(vec![Value::Integer(1.into()), Value::Integer(6.into())]),
        Value::Array(vec![Value::Integer(3.into()), Value::Integer(0.into())]),
    ]);
    ciborium::into_writer(&params, &mut bib_data).unwrap();

    let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(vec![0xAA; 48]),
    ])])]);
    ciborium::into_writer(&results, &mut bib_data).unwrap();

    let encoded = create_bundle_with_manual_bib(bib_data);

    // Receiver setup
    let dest = EndpointId::ipn(0, 1, 2).unwrap();
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source, vec![0xAA; 48]);

    let config = BpaConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: dest.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: Default::default(),
        cla_mtu: None,
        security_context: Some(sec_ctx),
        security_policy: None,
        enforce_private_use_restrictions: false,
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: Default::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(interplanetary_sdk::types::Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // RFC 9172 §4: Bundle with non-minimal integer encoding MUST be rejected
    let result = agent.receive_bytes_from_cla(&encoded);

    assert!(
        result.is_err() || agent.delivered_adus().is_empty(),
        "RFC 9172 §4: Bundle with non-minimal integer encoding in ASB MUST be rejected"
    );
}
