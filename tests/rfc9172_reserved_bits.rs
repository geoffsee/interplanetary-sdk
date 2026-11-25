//! RFC 9172 §3.6: Reserved bits in security context flags
//!
//! RFC9172-026: "Implementations MUST set reserved bits to 0 when writing this
//! field and MUST ignore the values of reserved bits when reading this field."

#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

use interplanetary_sdk::bp::*;
use interplanetary_sdk::bpa::policy::ForwardingFailedPolicy;
use interplanetary_sdk::bpa::security_processing::SecurityContext;
use interplanetary_sdk::bpa::{BpaConfig, BundleAgent, StatusReportPolicy};
use interplanetary_sdk::security::HmacVariant;
use interplanetary_sdk::security::bib::{BibConfig, BibTargets, generate_bib};
use interplanetary_sdk::sim::StorageManager;
use interplanetary_sdk::types::*;

/// RFC9172-026 (generator): Reserved bits (>0) MUST be 0 when writing security context flags
///
/// Generate a BIB block using generate_bib (on production path), encode to bytes,
/// and verify that reserved bits in the security context flags field are 0.
#[test]
fn test_rfc9172_026_generator_reserved_bits_zero() {
    let source = EndpointId::ipn(1, 1, 1).unwrap();
    let dest = EndpointId::ipn(2, 1, 0).unwrap();

    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 0);

    let mut bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(dest)
        .creation_timestamp(timestamp)
        .lifetime(3_600_000)
        .crc_type(CrcType::Crc32)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    // Add BIB targeting the payload block using production generate_bib
    let bib_config = BibConfig {
        security_source: source.clone(),
        targets: BibTargets {
            block_numbers: vec![1], // payload
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0x42; 32],
        wrapped_key: None,
        scope_flags: 0x00,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: false,
        #[cfg(feature = "test-fixtures")]
        hmac_key_policy: None,
    };

    let bib_block = generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Encode the bundle - this exercises the production encoding path
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // Decode to access the BIB block data in the emitted bytes
    let decoded = BundleCodec::decode(&encoded).unwrap();

    // Find the BIB block
    let bib = decoded
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::Bib)
        .expect("BIB block must be present");

    // Parse the BIB block-type-specific data
    // Per RFC 9172 §3.6: [targets, context_id, flags, source, ?params, results]
    let mut reader = std::io::Cursor::new(&bib.data);

    // Skip targets array
    let _targets: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();

    // Skip context ID
    let _context_id: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();

    // Read security context flags
    let flags_val: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();
    let flags = flags_val.as_integer().unwrap();
    let flags_u8 = u8::try_from(flags).unwrap();

    // RFC9172-026: Reserved bits (bits >0) MUST be 0
    // Bit 0 (0x01) is "parameters present" flag - allowed to be 1
    // Bits 1-7 (0xFE) are reserved and MUST be 0
    let reserved_mask = 0xFE;
    assert_eq!(
        flags_u8 & reserved_mask,
        0,
        "Reserved bits (>0) in security context flags must be 0 (got flags=0x{:02x})",
        flags_u8
    );
}

/// RFC9172-026 (receiver): Reserved bits MUST be ignored when reading security context flags
///
/// Feed BundleAgent.receive_bytes_from_cla a bundle with security context flags that have
/// reserved bits set, and verify that the reserved bits are ignored (bundle is processed
/// normally: BIB verified, bundle delivered).
#[test]
fn test_rfc9172_026_receiver_ignores_reserved_bits() {
    let receiver_node = NodeId::ipn(0, 2);
    let receiver_eid = EndpointId::ipn(0, 2, 0).unwrap();
    let source_eid = EndpointId::ipn(0, 1, 0).unwrap();

    // Create security context with the same key
    let mut security_context = SecurityContext::new();
    security_context.add_hmac_key(source_eid.clone(), vec![0x42; 32]);

    let config = BpaConfig {
        local_node: receiver_node.clone(),
        local_eid: receiver_eid.clone(),
        enable_forwarding: false,
        enable_delivery: true,
        status_report_policy: StatusReportPolicy::none(),
        cla_mtu: None,
        security_context: Some(security_context),
        security_policy: None,
        enforce_private_use_restrictions: false, // Disable for test to focus on reserved bits
        administrative_domain: None,
        static_routes: None,
        forwarding_failed_policy: ForwardingFailedPolicy::default(),
        #[cfg(feature = "bpsec-default")]
        outbound_bcb: None,
    };

    let storage = StorageManager::new(Bytes::from_mib(10).unwrap());
    let mut agent = BundleAgent::new(config, storage);

    // Create a bundle with BIB
    let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(0), 0);

    let mut bundle = BundleBuilder::new()
        .source(source_eid.clone())
        .destination(receiver_eid.clone())
        .creation_timestamp(timestamp)
        .lifetime(3_600_000)
        .crc_type(CrcType::Crc32)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let bib_config = BibConfig {
        security_source: source_eid.clone(),
        targets: BibTargets {
            block_numbers: vec![1],
        },
        sha_variant: HmacVariant::Sha256,
        key: vec![0x42; 32],
        wrapped_key: None,
        scope_flags: 0x00,
        #[cfg(feature = "test-fixtures")]
        skip_source_validation: true, // Allow private use EID for this test
        #[cfg(feature = "test-fixtures")]
        hmac_key_policy: None,
    };

    let bib_block = generate_bib(&bundle, &bib_config).unwrap();
    bundle.blocks.insert(0, bib_block);

    // Encode the bundle
    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    // Find BIB block
    let bib_idx = decoded
        .blocks
        .iter()
        .position(|b| b.block_type == BlockType::Bib)
        .unwrap();

    // Parse original BIB data
    let orig_bib = &decoded.blocks[bib_idx];
    let mut reader = std::io::Cursor::new(&orig_bib.data);

    let targets_val: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();
    let context_id_val: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();
    let _flags_val: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();
    let source_val: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();
    let params_val: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();
    let results_val: ciborium::Value = ciborium::from_reader(&mut reader).unwrap();

    // Reconstruct BIB data with reserved bits set in flags
    // Set flags to 0x03 (bit 0 = parameters present, bit 1 = reserved bit set)
    let mut modified_bib_data = Vec::new();
    ciborium::into_writer(&targets_val, &mut modified_bib_data).unwrap();
    ciborium::into_writer(&context_id_val, &mut modified_bib_data).unwrap();
    ciborium::into_writer(
        &ciborium::Value::Integer(0x03.into()),
        &mut modified_bib_data,
    )
    .unwrap(); // Reserved bit 1 set
    ciborium::into_writer(&source_val, &mut modified_bib_data).unwrap();
    ciborium::into_writer(&params_val, &mut modified_bib_data).unwrap();
    ciborium::into_writer(&results_val, &mut modified_bib_data).unwrap();

    // Create modified bundle with reserved bits in security context flags
    let mut modified_bundle = decoded.clone();
    modified_bundle.blocks[bib_idx].data = modified_bib_data;

    // Encode the modified bundle with reserved bits
    let encoded_with_reserved = BundleCodec::encode(&modified_bundle).unwrap();

    // Feed to BundleAgent via receive_bytes_from_cla (production path)
    let result = agent.receive_bytes_from_cla(&encoded_with_reserved);

    // RFC9172-026: Reserved bits MUST be ignored - bundle should be accepted
    assert!(
        result.is_ok(),
        "Bundle with reserved bits in security context flags should be accepted (reserved bits ignored), got: {:?}",
        result
    );

    // Poll the agent to process the bundle
    agent.poll(SimInstant::from_nanos(1_000_000_000));

    // Verify the bundle was delivered (since receiver_eid is the destination)
    // This proves the reserved bits were ignored - BIB was verified and bundle processed normally
    let delivered = agent.delivered_adus();
    assert_eq!(
        delivered.len(),
        1,
        "Bundle should be delivered despite reserved bits in BIB (proving they were ignored)"
    );

    // Extract payload from delivered bundle
    let payload_block = delivered[0]
        .payload_block()
        .expect("Payload block must be present");
    assert_eq!(payload_block.data, b"test payload");
}
