//! RFC 9171 §4.4 Extension Block Structural Rules and Constraints

mod common;

use common::simple_bundle;
use interplanetary_sdk::bp::extensions::{BundleAgeBlock, HopCountBlock, PreviousNodeBlock};
use interplanetary_sdk::bp::{BlockType, BundleCodec};
use interplanetary_sdk::types::EndpointId;

#[test]
fn test_rfc9171_4_075_implementation_must_parse_extension_blocks() {
    // RFC 9171 §4.4: "All implementations of the Bundle Protocol specification
    // (the present document) MUST include procedures for recognizing, parsing,
    // and acting on, but not necessarily producing, these types of extension
    // blocks."
    //
    // This test verifies the SDK can decode bundles with all standard extension blocks.

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Insert Previous Node block
    let prev_node = PreviousNodeBlock::new(2, EndpointId::ipn(0, 10, 0).unwrap());
    bundle.blocks.insert(0, prev_node.to_canonical().unwrap());

    // Insert Bundle Age block
    let age_block = BundleAgeBlock::new(3, 5000);
    bundle.blocks.insert(1, age_block.to_canonical().unwrap());

    // Insert Hop Count block
    let hop_block = HopCountBlock::new(4, 20, 3).unwrap();
    bundle.blocks.insert(2, hop_block.to_canonical().unwrap());

    // SDK MUST be able to encode and decode bundle with extension blocks
    let encoded = BundleCodec::encode(&bundle).unwrap();
    let decoded = BundleCodec::decode(&encoded).unwrap();

    // Verify all blocks were recognized and parsed
    assert!(
        decoded
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::PreviousNode),
        "Implementation MUST recognize Previous Node blocks"
    );
    assert!(
        decoded
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::BundleAge),
        "Implementation MUST recognize Bundle Age blocks"
    );
    assert!(
        decoded
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::HopCount),
        "Implementation MUST recognize Hop Count blocks"
    );

    // Verify blocks can be parsed back to their typed structures
    let prev_parsed = decoded
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::PreviousNode)
        .and_then(|b| PreviousNodeBlock::from_canonical(b).ok())
        .expect("MUST parse Previous Node block");
    assert_eq!(
        prev_parsed.previous_node,
        EndpointId::ipn(0, 10, 0).unwrap()
    );

    let age_parsed = decoded
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::BundleAge)
        .and_then(|b| BundleAgeBlock::from_canonical(b).ok())
        .expect("MUST parse Bundle Age block");
    assert_eq!(age_parsed.age_ms, 5000);

    let hop_parsed = decoded
        .blocks
        .iter()
        .find(|b| b.block_type == BlockType::HopCount)
        .and_then(|b| HopCountBlock::from_canonical(b).ok())
        .expect("MUST parse Hop Count block");
    assert_eq!(hop_parsed.hop_limit, 20);
    assert_eq!(hop_parsed.hop_count, 3);
}

#[test]
fn test_rfc9171_4_080_at_most_one_previous_node_block() {
    // RFC 9171 §4.4.1: "Otherwise, the bundle SHOULD contain one (1)
    // occurrence of this type of block and MUST NOT contain more than one."
    //
    // SDK decoder rejects bundles with multiple Previous Node blocks.

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Insert two Previous Node blocks (violation)
    let prev1 = PreviousNodeBlock::new(2, EndpointId::ipn(0, 10, 0).unwrap());
    let prev2 = PreviousNodeBlock::new(3, EndpointId::ipn(0, 11, 0).unwrap());
    bundle.blocks.push(prev1.to_canonical().unwrap());
    bundle.blocks.push(prev2.to_canonical().unwrap());

    // Encode the malformed bundle
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // SDK MUST reject on decode
    let result = BundleCodec::decode(&encoded);

    assert!(
        result.is_err(),
        "Decoder MUST reject bundle with multiple Previous Node blocks"
    );

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("§4.4.1") && error.contains("more than one Previous Node"),
        "Error must cite RFC 9171 §4.4.1: {}",
        error
    );
}

#[test]
fn test_rfc9171_4_083_at_most_one_bundle_age_block() {
    // RFC 9171 §4.4.2: "A bundle MUST NOT contain multiple occurrences of
    // the Bundle Age Block, as this could result in processing anomalies."
    //
    // SDK decoder rejects bundles with multiple Bundle Age blocks.

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Insert two Bundle Age blocks (violation)
    let age1 = BundleAgeBlock::new(2, 1000);
    let age2 = BundleAgeBlock::new(3, 2000);
    bundle.blocks.push(age1.to_canonical().unwrap());
    bundle.blocks.push(age2.to_canonical().unwrap());

    // Encode the malformed bundle
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // SDK MUST reject on decode
    let result = BundleCodec::decode(&encoded);

    assert!(
        result.is_err(),
        "Decoder MUST reject bundle with multiple Bundle Age blocks"
    );

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("§4.4.2") && error.contains("multiple Bundle Age"),
        "Error must cite RFC 9171 §4.4.2: {}",
        error
    );
}

#[test]
fn test_rfc9171_4_084_hop_limit_range_1_to_255() {
    // RFC 9171 §4.4.3: "The hop limit MUST be in the range 1 through 255."

    // Test valid range
    for limit in [1, 10, 128, 255] {
        let result = HopCountBlock::new(2, limit, 0);
        assert!(
            result.is_ok(),
            "Hop limit {} MUST be valid (range 1-255)",
            limit
        );
    }

    // Test invalid: hop limit = 0
    let result = HopCountBlock::new(2, 0, 0);
    assert!(
        result.is_err(),
        "Hop limit 0 MUST be rejected (range 1-255)"
    );
}

#[test]
fn test_rfc9171_4_087_hop_count_cbor_array_two_items() {
    // RFC 9171 §4.4.3: "The block-type-specific data in a Hop Count Block
    // SHALL be represented as a CBOR array comprising two items."

    let hop_block = HopCountBlock::new(2, 10, 3).unwrap();
    let canonical = hop_block.to_canonical().unwrap();

    // Decode the block-type-specific data as CBOR
    use ciborium::Value;
    let cbor_value: Value = ciborium::de::from_reader(&canonical.data[..]).unwrap();

    // Verify it's a CBOR array
    let arr = cbor_value
        .as_array()
        .expect("Hop Count data SHALL be a CBOR array");

    // Verify it has exactly 2 items
    assert_eq!(
        arr.len(),
        2,
        "Hop Count CBOR array SHALL comprise two items"
    );

    // Verify items are unsigned integers (hop limit and hop count)
    assert!(
        arr[0].as_integer().is_some(),
        "First item SHALL be hop limit (unsigned integer)"
    );
    assert!(
        arr[1].as_integer().is_some(),
        "Second item SHALL be hop count (unsigned integer)"
    );
}

#[test]
fn test_rfc9171_4_088_hop_limit_first_item_cbor_unsigned() {
    // RFC 9171 §4.4.3: "The first item of this array SHALL be the bundle's
    // hop limit, represented as a CBOR unsigned integer."

    let hop_limit = 15u8;
    let hop_count = 7u64;
    let hop_block = HopCountBlock::new(2, hop_limit, hop_count).unwrap();
    let canonical = hop_block.to_canonical().unwrap();

    // Decode the CBOR array
    use ciborium::Value;
    let cbor_value: Value = ciborium::de::from_reader(&canonical.data[..]).unwrap();
    let arr = cbor_value.as_array().unwrap();

    // Verify first item is hop limit as unsigned integer
    let first_item_value = arr[0]
        .as_integer()
        .and_then(|i| TryInto::<u64>::try_into(i).ok())
        .expect("First item SHALL be unsigned integer");

    assert_eq!(
        first_item_value, hop_limit as u64,
        "First item SHALL be the hop limit"
    );
}

#[test]
fn test_rfc9171_4_090_at_most_one_hop_count_block() {
    // RFC 9171 §4.4.3 (inferred from context - similar to other extension blocks):
    // "A bundle MAY contain one occurrence of this type of block but MUST NOT
    // contain more than one."
    //
    // SDK decoder rejects bundles with multiple Hop Count blocks.

    let mut bundle = simple_bundle(
        EndpointId::ipn(0, 1, 0).unwrap(),
        EndpointId::ipn(0, 2, 0).unwrap(),
    );

    // Insert two Hop Count blocks (violation)
    let hop1 = HopCountBlock::new(2, 10, 0).unwrap();
    let hop2 = HopCountBlock::new(3, 20, 0).unwrap();
    bundle.blocks.push(hop1.to_canonical().unwrap());
    bundle.blocks.push(hop2.to_canonical().unwrap());

    // Encode the malformed bundle
    let encoded = BundleCodec::encode(&bundle).unwrap();

    // SDK MUST reject on decode
    let result = BundleCodec::decode(&encoded);

    assert!(
        result.is_err(),
        "Decoder MUST reject bundle with multiple Hop Count blocks"
    );

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("§4.4.3") && error.contains("more than one Hop Count"),
        "Error must cite RFC 9171 §4.4.3: {}",
        error
    );
}

#[test]
fn test_rfc9171_4_077_previous_node_eid_conforms_to_section_4() {
    // RFC 9171 §4.4.1: "...its block-type-specific data is the node ID of
    // that forwarder node. That node ID SHALL conform to Section 4."
    //
    // Section 4 covers endpoint ID structure (scheme + SSP).

    // Valid EIDs conforming to §4
    let valid_eids = vec![
        EndpointId::ipn(0, 10, 5).unwrap(),         // IPN scheme
        EndpointId::dtn("//node/service").unwrap(), // DTN scheme
        EndpointId::null(),                         // Null endpoint
    ];

    for eid in valid_eids {
        let prev_node = PreviousNodeBlock::new(2, eid.clone());
        let canonical = prev_node.to_canonical().unwrap();

        // Decode and verify EID round-trips correctly
        let decoded = PreviousNodeBlock::from_canonical(&canonical).unwrap();
        assert_eq!(
            decoded.previous_node, eid,
            "Previous Node EID SHALL conform to §4 (valid scheme + SSP)"
        );
    }
}

#[test]
fn test_rfc9171_4_084_hop_count_initially_zero_increments_by_one() {
    // RFC 9171 §4.4.3: "...the hop count value SHOULD initially be zero and
    // SHOULD be increased by 1 on each hop."

    // Test initial value = 0
    let hop_block_initial = HopCountBlock::new(2, 10, 0).unwrap();
    assert_eq!(
        hop_block_initial.hop_count, 0,
        "Hop count SHOULD initially be zero"
    );

    // Test increment by 1
    let mut hop_block = HopCountBlock::new(2, 10, 5).unwrap();
    let before = hop_block.hop_count;

    hop_block.increment();

    assert_eq!(
        hop_block.hop_count,
        before + 1,
        "Hop count SHOULD be increased by 1 on each hop"
    );
}
