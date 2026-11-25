//! RFC 9171 §4.3 Canonical Bundle Block CBOR Encoding Tests
//!
//! Tests that verify the SDK encodes canonical blocks according to RFC 9171 §4.3.2

use ciborium::Value;
use interplanetary_sdk::bp::{
    BundleBuilder, CrcType,
    blocks::BlockType,
    codec::BundleCodec,
    extensions::{HopCountBlock, PreviousNodeBlock},
};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};
use std::io::Cursor;

#[test]
fn test_rfc9171_4_3_2_042_canonical_block_array_structure() {
    // RFC 9171 §4.3.2: "With the exception of the primary block, every
    // block of a bundle SHALL be represented as a CBOR array."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    // Skip primary block (index 0), check canonical blocks
    for (i, block) in blocks.iter().skip(1).enumerate() {
        let Value::Array(_) = block else {
            panic!(
                "Canonical block {} SHALL be CBOR array (RFC 9171 §4.3.2)",
                i + 1
            );
        };
    }
}

#[test]
fn test_rfc9171_4_3_2_043_block_type_code_unsigned() {
    // RFC 9171 §4.3.2: "The block type code SHALL be represented as a
    // CBOR unsigned integer."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    // Check payload block (last block)
    let Value::Array(payload_block) = &blocks[blocks.len() - 1] else {
        panic!("Payload block must be CBOR array");
    };

    let Value::Integer(block_type_code) = &payload_block[0] else {
        panic!("Block type code SHALL be CBOR unsigned integer");
    };

    // Payload block type is 1
    assert_eq!(
        (*block_type_code).try_into().ok(),
        Some(1u64),
        "Payload block type code should be 1"
    );
}

#[test]
fn test_rfc9171_4_3_2_044_block_number_unsigned() {
    // RFC 9171 §4.3.2: "The block number SHALL be represented as a CBOR
    // unsigned integer."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let Value::Array(payload_block) = &blocks[blocks.len() - 1] else {
        panic!("Payload block must be CBOR array");
    };

    let Value::Integer(_block_number) = &payload_block[1] else {
        panic!("Block number SHALL be CBOR unsigned integer");
    };
}

#[test]
fn test_rfc9171_4_3_2_045_block_processing_control_flags_unsigned() {
    // RFC 9171 §4.3.2: "The block processing control flags SHALL be
    // represented as a CBOR unsigned integer."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let Value::Array(payload_block) = &blocks[blocks.len() - 1] else {
        panic!("Payload block must be CBOR array");
    };

    let Value::Integer(_block_flags) = &payload_block[2] else {
        panic!("Block processing control flags SHALL be CBOR unsigned integer");
    };
}

#[test]
fn test_rfc9171_4_3_2_046_crc_type_unsigned() {
    // RFC 9171 §4.3.2: "The CRC type code SHALL be represented as a CBOR
    // unsigned integer."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let Value::Array(payload_block) = &blocks[blocks.len() - 1] else {
        panic!("Payload block must be CBOR array");
    };

    let Value::Integer(_crc_type) = &payload_block[3] else {
        panic!("CRC type code SHALL be CBOR unsigned integer");
    };
}

#[test]
fn test_rfc9171_4_3_2_047_block_type_specific_data_byte_string() {
    // RFC 9171 §4.3.2: "The block-type-specific data's value SHALL be
    // represented as a CBOR byte string."

    let bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test payload".to_vec())
        .build()
        .unwrap();

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let Value::Array(payload_block) = &blocks[blocks.len() - 1] else {
        panic!("Payload block must be CBOR array");
    };

    let Value::Bytes(_block_data) = &payload_block[4] else {
        panic!("Block-type-specific data SHALL be CBOR byte string");
    };
}

#[test]
fn test_rfc9171_4_3_2_crc_present_when_crc_type_nonzero() {
    // RFC 9171 §4.3.2: "If and only if the CRC type code is not zero,
    // any CRC computed for this block SHALL be represented... as a CBOR
    // byte string"

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::dtn("//source").unwrap())
        .destination(EndpointId::dtn("//dest").unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Force CRC on payload block
    for block in bundle.blocks.iter_mut() {
        if block.block_type == BlockType::Payload {
            block.crc_type = CrcType::Crc16;
        }
    }

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let Value::Array(payload_block) = &blocks[blocks.len() - 1] else {
        panic!("Payload block must be CBOR array");
    };

    let Value::Integer(crc_type) = &payload_block[3] else {
        panic!("CRC type must be unsigned integer");
    };

    let crc_type_value: u64 = (*crc_type).try_into().unwrap();

    if crc_type_value != 0 {
        assert!(
            payload_block.len() >= 6,
            "CRC field must be present when CRC type is nonzero"
        );
        let Value::Bytes(_crc_bytes) = &payload_block[5] else {
            panic!("CRC SHALL be CBOR byte string when CRC type is nonzero");
        };
    }
}

#[test]
fn test_rfc9171_4_3_2_multiple_blocks_unique_block_numbers() {
    // RFC 9171 §4.3.2: Block numbers are unique within a bundle,
    // implied by "identifying the block" and used for XREF_BLOCK

    let mut bundle = BundleBuilder::new()
        .source(EndpointId::ipn(0, 1, 0).unwrap())
        .destination(EndpointId::ipn(0, 2, 0).unwrap())
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(100), 0))
        .lifetime(3600000)
        .payload(b"test".to_vec())
        .build()
        .unwrap();

    // Add multiple extension blocks
    let hop_count = HopCountBlock::new(2, 10, 0).unwrap();
    let prev_node = PreviousNodeBlock::new(3, EndpointId::ipn(0, 3, 0).unwrap());

    bundle.blocks.insert(0, hop_count.to_canonical().unwrap());
    bundle.blocks.insert(1, prev_node.to_canonical().unwrap());

    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded: Value = ciborium::from_reader(Cursor::new(&encoded)).unwrap();

    let Value::Array(blocks) = decoded else {
        panic!("Bundle must be CBOR array");
    };

    let mut block_numbers = vec![];

    for block in blocks.iter().skip(1) {
        // Skip primary block
        let Value::Array(block_array) = block else {
            panic!("Block must be CBOR array");
        };
        let Value::Integer(block_number) = &block_array[1] else {
            panic!("Block number must be unsigned integer");
        };
        let num: u64 = (*block_number).try_into().unwrap();
        assert!(
            !block_numbers.contains(&num),
            "Block numbers must be unique within bundle"
        );
        block_numbers.push(num);
    }
}
