//! RFC 9173 Parameter Default Value Tests
//!
//! Tests that security context parameters use correct defaults when omitted.
//! - RFC 9173 §3.3.1 Table 1: SHA variant defaults to 6 (HMAC 384/384)
//! - RFC 9173 §4.3.1 Table 4: AES variant defaults to 3 (A256GCM)
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::{bp::*, types::*};

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_010_bib_parser_defaults_sha_variant_to_6() {
    // RFC 9173 §3.3.1 Table 1: "When not provided, implementations SHOULD assume a value
    // of 6 (indicating use of HMAC 384/384)"

    use interplanetary_sdk::SimInstant;
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    // Create a simple bundle
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Test data".to_vec())
        .build()
        .unwrap();

    // Compute HMAC-384 signature (the default) for payload block
    let key = vec![0xAA; 48]; // 48 bytes for HMAC-384
    use hmac::{Hmac, Mac};
    use sha2::Sha384;

    let ippt = interplanetary_sdk::security::construct_ippt(&bundle, 1, 0x00).unwrap();
    let mut mac = Hmac::<Sha384>::new_from_slice(&key).unwrap();
    mac.update(&ippt);
    let signature = mac.finalize().into_bytes().to_vec();

    // Manually construct BIB block WITHOUT SHA variant parameter (omit parameter ID 1)
    use ciborium::Value;
    let targets = Value::Array(vec![Value::Integer(1.into())]);
    let context_id = Value::Integer(1.into());
    let context_flags = Value::Integer(0.into());

    // Encode source EID properly - RFC 9758 §6.1 for IPN scheme
    let source_value = {
        // IPN EID encoding: [2, [allocator, node, service]] or [2, [fqnn, service]] for allocator 0
        use ciborium::Value;
        // For ipn:2.1 with allocator 0, use 2-element form [fqnn, service]
        // fqnn = (allocator << 32) | node = (0 << 32) | 2 = 2
        Value::Array(vec![
            Value::Integer(2.into()), // Scheme code 2 = ipn
            Value::Array(vec![
                Value::Integer(2.into()), // FQNN = 2
                Value::Integer(1.into()), // Service = 1
            ]),
        ])
    };

    // Parameters: OMIT parameter ID 1 (SHA variant) to test default
    // Only include parameter ID 3 (scope flags) = 0
    let params = Value::Array(vec![Value::Array(vec![
        Value::Integer(3.into()), // Parameter ID 3 = scope flags
        Value::Integer(0.into()), // Value = 0x00
    ])]);

    // Security results (array of result sets, one per target)
    // Each result set is an array of [result_id, value] pairs
    // Result ID 1 = signature per RFC 9173 §3.3.2
    let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()), // Result ID 1 = HMAC output
        Value::Bytes(signature),
    ])])]);

    // Encode all BIB fields
    let mut bib_data = Vec::new();
    ciborium::into_writer(&targets, &mut bib_data).unwrap();
    ciborium::into_writer(&context_id, &mut bib_data).unwrap();
    ciborium::into_writer(&context_flags, &mut bib_data).unwrap();
    ciborium::into_writer(&source_value, &mut bib_data).unwrap();
    ciborium::into_writer(&params, &mut bib_data).unwrap();
    ciborium::into_writer(&results, &mut bib_data).unwrap();

    let bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0x01, // Replicate in every fragment (RFC 9172 §3.8)
        crc_type: CrcType::None,
        data: bib_data,
    };

    bundle.blocks.insert(0, bib);
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Set up receiver with key
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), key);

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

    // Receive bundle - parser should default to SHA variant 6 (HMAC 384/384)
    agent.receive_bytes_from_cla(&encoded).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify bundle was accepted and delivered
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "RFC 9173 §3.3.1 Table 1: Bundle with omitted SHA variant parameter MUST be accepted with default 6 (HMAC 384/384)"
    );
    // Extract payload from delivered bundle
    let payload = &delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("Bundle must have payload")
        .data;
    assert_eq!(payload.as_slice(), b"Test data");
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_010_explicit_sha_variant_overrides_default() {
    // Test that explicit SHA variant parameter overrides the default
    // This proves the default is used only when parameter is omitted

    use interplanetary_sdk::SimInstant;
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(b"Test data".to_vec())
        .build()
        .unwrap();

    // Compute HMAC-256 signature (non-default)
    let key = vec![0xAA; 32]; // 32 bytes for HMAC-256
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let ippt = interplanetary_sdk::security::construct_ippt(&bundle, 1, 0x00).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(&ippt);
    let signature = mac.finalize().into_bytes().to_vec();

    // Create BIB WITH explicit SHA variant parameter = 5 (SHA-256)
    use ciborium::Value;
    let targets = Value::Array(vec![Value::Integer(1.into())]);
    let context_id = Value::Integer(1.into());
    let context_flags = Value::Integer(0.into());
    let source_value = {
        use ciborium::Value;
        Value::Array(vec![
            Value::Integer(2.into()), // Scheme code 2 = ipn
            Value::Array(vec![
                Value::Integer(2.into()), // FQNN = 2
                Value::Integer(1.into()), // Service = 1
            ]),
        ])
    };

    // Include parameter ID 1 (SHA variant) = 5 (SHA-256)
    let params = Value::Array(vec![
        Value::Array(vec![
            Value::Integer(1.into()), // Parameter ID 1 = SHA variant
            Value::Integer(5.into()), // Value = 5 (SHA-256)
        ]),
        Value::Array(vec![
            Value::Integer(3.into()), // Parameter ID 3 = scope flags
            Value::Integer(0.into()),
        ]),
    ]);
    let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()), // Result ID 1 = HMAC output
        Value::Bytes(signature),
    ])])]);

    let mut bib_data = Vec::new();
    ciborium::into_writer(&targets, &mut bib_data).unwrap();
    ciborium::into_writer(&context_id, &mut bib_data).unwrap();
    ciborium::into_writer(&context_flags, &mut bib_data).unwrap();
    ciborium::into_writer(&source_value, &mut bib_data).unwrap();
    ciborium::into_writer(&params, &mut bib_data).unwrap();
    ciborium::into_writer(&results, &mut bib_data).unwrap();

    let bib = CanonicalBlock {
        block_type: BlockType::Bib,
        block_number: 2,
        block_flags: 0x01, // Replicate in every fragment (RFC 9172 §3.8)
        crc_type: CrcType::None,
        data: bib_data,
    };
    bundle.blocks.insert(0, bib);

    let encoded = BundleCodec::encode(&bundle).unwrap();

    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_hmac_key(source.clone(), key);

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

    agent.receive_bytes_from_cla(&encoded).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify bundle was accepted with explicit SHA-256 (not default)
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "Bundle with explicit SHA variant parameter MUST be accepted"
    );
    // Extract payload from delivered bundle
    let payload = &delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("Bundle must have payload")
        .data;
    assert_eq!(payload.as_slice(), b"Test data");
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_059_bcb_parser_defaults_aes_variant_to_3() {
    // RFC 9173 §4.3.1 Table 4: "When not provided, implementations SHOULD assume a value
    // of 3 (indicating use of A256GCM)"

    use interplanetary_sdk::SimInstant;
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let plaintext = b"Test data";
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(plaintext.to_vec())
        .build()
        .unwrap();

    // Encrypt with AES-256-GCM (the default)
    let key = vec![0xBB; 32]; // 32 bytes for A256GCM
    let iv = vec![0xCC; 12]; // 12-byte IV

    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&iv);

    // Construct AAD
    let aad = interplanetary_sdk::security::construct_aad(&bundle, 1, 2, 0x00).unwrap();

    let payload_struct = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext_with_tag = cipher.encrypt(nonce, payload_struct).unwrap();
    let (ciphertext, auth_tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    // Replace payload with ciphertext
    bundle.blocks[0].data = ciphertext.to_vec();

    // Manually construct BCB WITHOUT AES variant parameter (omit parameter ID 2)
    use ciborium::Value;
    let targets = Value::Array(vec![Value::Integer(1.into())]);
    let context_id = Value::Integer(2.into()); // BCB context ID
    let context_flags = Value::Integer(0.into());
    let source_value = {
        Value::Array(vec![
            Value::Integer(2.into()), // Scheme code 2 = ipn
            Value::Array(vec![
                Value::Integer(2.into()), // FQNN = 2
                Value::Integer(1.into()), // Service = 1
            ]),
        ])
    };

    // Parameters: OMIT parameter ID 2 (AES variant) to test default
    // Only include parameter ID 1 (IV) and parameter ID 4 (scope flags)
    let params = Value::Array(vec![
        Value::Array(vec![
            Value::Integer(1.into()), // Parameter ID 1 = IV
            Value::Bytes(iv),
        ]),
        Value::Array(vec![
            Value::Integer(4.into()), // Parameter ID 4 = AAD scope flags
            Value::Integer(0.into()), // Value = 0x00
        ]),
    ]);

    // Security results - same structure as BIB
    // Result ID 1 = authentication tag per RFC 9173 §4.3.3
    let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()), // Result ID 1 = authentication tag
        Value::Bytes(auth_tag.to_vec()),
    ])])]);

    let mut bcb_data = Vec::new();
    ciborium::into_writer(&targets, &mut bcb_data).unwrap();
    ciborium::into_writer(&context_id, &mut bcb_data).unwrap();
    ciborium::into_writer(&context_flags, &mut bcb_data).unwrap();
    ciborium::into_writer(&source_value, &mut bcb_data).unwrap();
    ciborium::into_writer(&params, &mut bcb_data).unwrap();
    ciborium::into_writer(&results, &mut bcb_data).unwrap();

    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 0x01, // Replicate in every fragment (RFC 9172 §3.8)
        crc_type: CrcType::None,
        data: bcb_data,
    };

    bundle.blocks.insert(0, bcb);
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Set up receiver with key
    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(source.clone(), key);

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

    // Receive bundle - parser should default to AES variant 3 (A256GCM)
    agent.receive_bytes_from_cla(&encoded).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify bundle was decrypted and delivered
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "RFC 9173 §4.3.1 Table 4: Bundle with omitted AES variant parameter MUST be accepted with default 3 (A256GCM)"
    );
    // Extract payload from delivered bundle
    let payload = &delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("Bundle must have payload")
        .data;
    assert_eq!(payload.as_slice(), plaintext);
}

#[test]
#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
fn test_rfc9173_059_explicit_aes_variant_overrides_default() {
    // Test that explicit AES variant parameter overrides the default

    use interplanetary_sdk::SimInstant;
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
    use interplanetary_sdk::sim::StorageManager;

    let source = EndpointId::ipn(0, 2, 1).unwrap();
    let dest = EndpointId::ipn(0, 1, 2).unwrap();

    let plaintext = b"Test data";
    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest.clone())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 1))
        .lifetime(60_000)
        .payload(plaintext.to_vec())
        .build()
        .unwrap();

    // Encrypt with AES-128-GCM (non-default)
    let key = vec![0xBB; 16]; // 16 bytes for A128GCM
    let iv = vec![0xCC; 12];

    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };

    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&iv);

    let aad = interplanetary_sdk::security::construct_aad(&bundle, 1, 2, 0x00).unwrap();
    let payload_struct = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext_with_tag = cipher.encrypt(nonce, payload_struct).unwrap();
    let (ciphertext, auth_tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    bundle.blocks[0].data = ciphertext.to_vec();

    // Create BCB WITH explicit AES variant parameter = 1 (A128GCM)
    use ciborium::Value;
    let targets = Value::Array(vec![Value::Integer(1.into())]);
    let context_id = Value::Integer(2.into());
    let context_flags = Value::Integer(0.into());
    let source_value = {
        Value::Array(vec![
            Value::Integer(2.into()), // Scheme code 2 = ipn
            Value::Array(vec![
                Value::Integer(2.into()), // FQNN = 2
                Value::Integer(1.into()), // Service = 1
            ]),
        ])
    };

    // Include parameter ID 2 (AES variant) = 1 (A128GCM)
    let params = Value::Array(vec![
        Value::Array(vec![
            Value::Integer(1.into()), // Parameter ID 1 = IV
            Value::Bytes(iv),
        ]),
        Value::Array(vec![
            Value::Integer(2.into()), // Parameter ID 2 = AES variant
            Value::Integer(1.into()), // Value = 1 (A128GCM)
        ]),
        Value::Array(vec![
            Value::Integer(4.into()), // Parameter ID 4 = scope flags
            Value::Integer(0.into()),
        ]),
    ]);
    // Security results - same structure as BIB
    // Result ID 1 = authentication tag per RFC 9173 §4.3.3
    let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
        Value::Integer(1.into()), // Result ID 1 = authentication tag
        Value::Bytes(auth_tag.to_vec()),
    ])])]);

    let mut bcb_data = Vec::new();
    ciborium::into_writer(&targets, &mut bcb_data).unwrap();
    ciborium::into_writer(&context_id, &mut bcb_data).unwrap();
    ciborium::into_writer(&context_flags, &mut bcb_data).unwrap();
    ciborium::into_writer(&source_value, &mut bcb_data).unwrap();
    ciborium::into_writer(&params, &mut bcb_data).unwrap();
    ciborium::into_writer(&results, &mut bcb_data).unwrap();

    let bcb = CanonicalBlock {
        block_type: BlockType::Bcb,
        block_number: 2,
        block_flags: 0x01, // Replicate in every fragment (RFC 9172 §3.8)
        crc_type: CrcType::None,
        data: bcb_data,
    };
    bundle.blocks.insert(0, bcb);

    let encoded = BundleCodec::encode(&bundle).unwrap();

    let mut sec_ctx = SecurityContext::new();
    sec_ctx.add_aes_key(source.clone(), key);

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

    agent.receive_bytes_from_cla(&encoded).unwrap();
    agent.poll(SimInstant::from_nanos(100_000_000));

    // Verify bundle was accepted with explicit A128GCM (not default)
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "Bundle with explicit AES variant parameter MUST be accepted"
    );
    // Extract payload from delivered bundle
    let payload = &delivered[0]
        .blocks
        .iter()
        .find(|b| matches!(b.block_type, BlockType::Payload))
        .expect("Bundle must have payload")
        .data;
    assert_eq!(payload.as_slice(), plaintext);
}
