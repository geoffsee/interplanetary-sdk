#![cfg(feature = "bpv7")]

//! RFC 9171 §4.4: Extension block insertion and removal

use interplanetary_sdk::bp::*;
use interplanetary_sdk::types::*;

#[test]
fn test_rfc9171_4_076_may_insert_extension_blocks() {
    // RFC 9171 §4.4: "any BPA MAY insert or remove any extension block in any bundle"

    // Create a minimal bundle
    let mut bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Initial state: should have only payload block
    let initial_count = bundle.blocks.len();

    // SDK MUST allow inserting extension blocks
    // Insert a Bundle Age block
    let age_block = CanonicalBlock {
        block_type: BlockType::BundleAge,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x00], // Age = 0
    };

    bundle.blocks.insert(0, age_block);
    assert_eq!(
        bundle.blocks.len(),
        initial_count + 1,
        "SDK MAY insert extension blocks"
    );

    // Verify bundle is still valid
    let encoded = BundleCodec::encode(&bundle);
    assert!(encoded.is_ok(), "Bundle with inserted block must be valid");
}

#[test]
fn test_rfc9171_4_076_may_remove_extension_blocks() {
    // RFC 9171 §4.4: "any BPA MAY insert or remove any extension block in any bundle"

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Insert an extension block
    let age_block = CanonicalBlock {
        block_type: BlockType::BundleAge,
        block_number: 2,
        block_flags: 0,
        crc_type: CrcType::None,
        data: vec![0x00],
    };
    bundle.blocks.insert(0, age_block);

    let count_with_ext = bundle.blocks.len();

    // SDK MUST allow removing extension blocks (but not payload)
    bundle.blocks.retain(|b| b.block_type == BlockType::Payload);

    assert!(
        bundle.blocks.len() < count_with_ext,
        "SDK MAY remove extension blocks"
    );
    assert_eq!(bundle.blocks.len(), 1, "Payload block remains");

    // Verify bundle is still valid
    let encoded = BundleCodec::encode(&bundle);
    assert!(
        encoded.is_ok(),
        "Bundle after removing extension must be valid"
    );
}
