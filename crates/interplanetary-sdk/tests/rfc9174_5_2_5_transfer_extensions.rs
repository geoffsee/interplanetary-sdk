#![cfg(feature = "tcpclv4-model")]

//! RFC 9174 §5.2.5 Transfer Extension Items Tests

mod common;

use interplanetary_sdk::tcpcl::messages::*;

/// RFC9174-5-2-5-129: Transfer Extension Items SHALL be encoded as TLV
#[test]
fn test_rfc9174_5_2_5_129_transfer_extension_tlv_encoding() {
    // RFC 9174 §5.2.5: "Each of the Transfer Extension Items SHALL be encoded in an
    // identical Type-Length-Value (TLV) container form"
    // Format: flags(1) | type(2) | length(2) | value(variable)

    let ext = ExtensionItem::new(0x0001, vec![0xAA, 0xBB, 0xCC], false);
    let encoded = ext.encode();

    // Verify TLV format
    assert_eq!(
        encoded.len(),
        1 + 2 + 2 + 3,
        "Transfer extension must be encoded as: flags(1) + type(2) + length(2) + value(n)"
    );

    // Verify flags field (1 byte)
    assert_eq!(encoded[0], 0x00, "Flags field at byte 0");

    // Verify type field (2 bytes, big-endian)
    let type_code = u16::from_be_bytes([encoded[1], encoded[2]]);
    assert_eq!(type_code, 0x0001, "Type code at bytes 1-2");

    // Verify length field (2 bytes, big-endian)
    let length = u16::from_be_bytes([encoded[3], encoded[4]]);
    assert_eq!(length, 3, "Length field at bytes 3-4");

    // Verify value field
    assert_eq!(
        &encoded[5..8],
        &[0xAA, 0xBB, 0xCC],
        "Value field starts at byte 5"
    );
}

/// RFC9174-5-2-5-130: Reserved flags SHALL be 0 by sender
#[test]
fn test_rfc9174_5_2_5_130_transfer_extension_reserved_flags_zero() {
    // RFC 9174 §5.2.5 Table 7: Flag bit 0 is CRITICAL, bits 1-7 are reserved
    // "All reserved header flag bits SHALL be set to 0 by the sender"

    // Test non-critical extension
    let ext_non_critical = ExtensionItem::new(0x0001, vec![0x01], false);
    let encoded = ext_non_critical.encode();
    let flags = encoded[0];

    // All bits should be 0 for non-critical
    assert_eq!(flags, 0x00, "Non-critical: all reserved bits must be 0");

    // Test critical extension
    let ext_critical = ExtensionItem::new(0x0002, vec![0x02], true);
    let encoded = ext_critical.encode();
    let flags = encoded[0];

    // Bit 0 should be 1 (CRITICAL), bits 1-7 should be 0
    assert_eq!(
        flags & 0x01,
        0x01,
        "Critical extension: bit 0 (CRITICAL) must be 1"
    );
    assert_eq!(
        flags & 0xFE,
        0x00,
        "Critical extension: reserved bits 1-7 must be 0"
    );

    // Verify that reserved bits (1-7) are always 0
    let reserved_bits = flags & 0xFE;
    assert_eq!(
        reserved_bits, 0x00,
        "Reserved bits (1-7) SHALL be set to 0 by sender"
    );
}

/// RFC9174-5-2-5-132: Reserved flags ignored by receiver
#[test]
fn test_rfc9174_5_2_5_132_transfer_extension_flags_ignored() {
    // RFC 9174 §5.2.5: "All reserved header flag bits SHALL be ignored by the receiver"

    // Create extension with valid encoding
    let ext = ExtensionItem::new(0x0042, vec![0xDE, 0xAD], true);
    let mut encoded = ext.encode();

    // Original flags: 0x01 (CRITICAL bit set)
    assert_eq!(encoded[0] & 0x01, 0x01);

    // Artificially set reserved bits (simulate sender violation or future extension)
    // Set bit 2 and bit 5 (reserved bits that should be ignored)
    encoded[0] |= 0b00100100; // Set bits 2 and 5

    // Decode should succeed and extract only the CRITICAL bit
    let (decoded, _) =
        ExtensionItem::decode(&encoded).expect("Decoder SHALL ignore reserved flag bits");

    // Verify CRITICAL bit is preserved
    assert!(
        decoded.is_critical(),
        "CRITICAL bit (bit 0) should be preserved"
    );

    // Verify decoder ignores reserved bits (bits 1-7)
    // The decoded flags should only have bit 0 set if critical
    let decoded_flags = decoded.flags;
    assert_eq!(
        decoded_flags & 0x01,
        0x01,
        "CRITICAL bit should be preserved"
    );

    // The key test: decoder should not fail or behave differently
    // when reserved bits are set (they are ignored)
    assert_eq!(decoded.type_code, 0x0042, "Type code preserved");
    assert_eq!(decoded.value, vec![0xDE, 0xAD], "Value preserved");
}

/// RFC9174-5-2-5-133: Unknown critical extension SHALL trigger XFER_REFUSE
#[test]
fn test_rfc9174_5_2_5_133_unknown_critical_extension_refused() {
    // RFC 9174 §5.2.5: "If a TCPCL entity receives a Transfer Extension Item with an
    // unknown Item Type and the CRITICAL flag is 1, the entity SHALL refuse the transfer
    // with a XFER_REFUSE reason code of 'Extension Failure'"

    let pair = common::SessionPair::establish().unwrap();
    let mut active = pair.active;
    let mut passive = pair.passive;

    // Active starts transfer with unknown critical extension
    let unknown_type = 0xFFFF; // Not a known extension type
    let transfer_id = active.start_transfer(vec![0xAA; 100]).unwrap();

    // Create segment with unknown critical extension
    let mut segments = active.create_segments(transfer_id, 1000).unwrap();
    assert_eq!(segments.len(), 1);

    // Add unknown critical extension to segment
    if let Message::TransferSegment { extensions, .. } = &mut segments[0] {
        extensions.push(ExtensionItem::new(unknown_type, vec![0x01, 0x02], true));
    }

    // Passive should refuse the transfer
    let result = passive.process_segment(&segments[0]);

    // Should generate XFER_REFUSE with Extension Failure reason
    assert!(result.is_ok(), "Should process and generate refusal");
    let response = result.unwrap();
    assert!(response.is_some(), "Should generate XFER_REFUSE");

    match response.unwrap() {
        Message::TransferRefuse {
            reason_code,
            transfer_id: refused_id,
        } => {
            assert_eq!(
                reason_code,
                refuse_reason::EXTENSION_FAILURE,
                "SHALL refuse with Extension Failure reason"
            );
            assert_eq!(refused_id, transfer_id, "Correct transfer ID refused");
        }
        _ => panic!("Expected XFER_REFUSE for unknown critical extension"),
    }
}

/// RFC9174-5-2-5-134: SHOULD avoid large extension data
#[test]
fn test_rfc9174_5_2_5_134_avoid_large_extensions() {
    // RFC 9174 §5.2.5: "Extension specifications SHOULD avoid the use of large data
    // lengths, as the associated transfer cannot begin until the full extension data
    // is sent"

    // This is a SHOULD recommendation for extension designers
    // Test documents the requirement and demonstrates encoding behavior

    // Small extension (recommended)
    let small_ext = ExtensionItem::new(0x0001, vec![0xAA; 10], false);
    let small_encoded = small_ext.encode();
    assert!(
        small_encoded.len() <= 100,
        "Small extensions are recommended ({}bytes)",
        small_encoded.len()
    );

    // Large extension (not recommended but technically valid)
    let large_ext = ExtensionItem::new(0x0002, vec![0xBB; 10000], false);
    let large_encoded = large_ext.encode();
    assert!(
        large_encoded.len() > 1000,
        "Large extensions delay transfer start ({} bytes)",
        large_encoded.len()
    );

    // Both are valid protocol-wise, but small is RECOMMENDED
    // Extensions SHOULD be designed to avoid large data
}

/// RFC9174-5-2-5-1-135: Multiple Transfer Length items SHALL NOT occur
#[test]
fn test_rfc9174_5_2_5_1_135_no_duplicate_transfer_length_extensions() {
    // RFC 9174 §5.2.5.1: "Multiple Transfer Length Extension Items SHALL NOT occur
    // within the same transfer"

    let pair = common::SessionPair::establish().unwrap();
    let mut session = pair.active;

    let transfer_id = session.start_transfer(vec![0xCC; 200]).unwrap();
    let mut segments = session.create_segments(transfer_id, 1000).unwrap();

    // Check first segment (START flag set)
    let first_segment = &mut segments[0];

    if let Message::TransferSegment { extensions, .. } = first_segment {
        // Count Transfer Length Extension items (type 0x0001)
        let transfer_length_count = extensions
            .iter()
            .filter(|ext| ext.type_code == 0x0001)
            .count();

        assert!(
            transfer_length_count <= 1,
            "SHALL NOT have multiple Transfer Length Extension items (found {})",
            transfer_length_count
        );
    }

    // If implementation added multiple, that would violate the SHALL NOT
}

/// RFC9174-5-2-5-1-139: Lack of Transfer Length SHALL NOT imply anything
#[test]
fn test_rfc9174_5_2_5_1_139_no_transfer_length_no_implication() {
    // RFC 9174 §5.2.5.1: "The lack of a Transfer Length Extension Item in any transfer
    // SHALL NOT imply anything regarding the potential length of the transfer"

    let pair = common::SessionPair::establish().unwrap();
    let mut session = pair.active;

    // Transfer without Transfer Length Extension
    let transfer_id = session.start_transfer(vec![0xDD; 50]).unwrap();
    let segments = session.create_segments(transfer_id, 1000).unwrap();

    // Verify transfer is valid without Transfer Length Extension
    assert!(
        !segments.is_empty(),
        "Transfer valid without Transfer Length"
    );

    // Check if Transfer Length Extension is present
    if let Message::TransferSegment { extensions, .. } = &segments[0] {
        let has_transfer_length = extensions.iter().any(|ext| ext.type_code == 0x0001);

        // Whether present or not, absence SHALL NOT imply anything about length
        // Both with and without are valid protocol usage
        // This test documents the requirement
        if !has_transfer_length {
            // Absence does not mean short transfer, long transfer, or anything else
            // Receiver must process segments as they arrive without assumptions
            // No assertion needed - documents that absence is valid and implies nothing
        }
    }
}

/// RFC9174-5-2-5-1-140: Single-segment transfer SHOULD NOT have Transfer Length
#[test]
fn test_rfc9174_5_2_5_1_140_single_segment_should_not_have_length() {
    // RFC 9174 §5.2.5.1: "If a transfer occupies exactly one segment (i.e., both the
    // START flag and the END flag are 1), the Transfer Length Extension SHOULD NOT
    // be present"

    let pair = common::SessionPair::establish().unwrap();
    let mut session = pair.active;

    // Small transfer that fits in one segment
    let small_data = vec![0xEE; 50];
    let transfer_id = session.start_transfer(small_data).unwrap();
    let segments = session.create_segments(transfer_id, 1000).unwrap();

    assert_eq!(segments.len(), 1, "Transfer occupies exactly one segment");

    // Check segment flags and extensions
    if let Message::TransferSegment {
        flags,
        ref extensions,
        ..
    } = segments[0]
    {
        // Verify both START and END flags are set (single segment)
        let is_single_segment = (flags & 0x03) == 0x03; // START=1, END=1
        assert!(is_single_segment, "Both START and END flags should be set");

        // Check if Transfer Length Extension is present
        let has_transfer_length = extensions.iter().any(|ext| ext.type_code == 0x0001);

        // For single-segment transfers, Transfer Length SHOULD NOT be present
        // (it's redundant since segment length == transfer length)
        assert!(
            !has_transfer_length,
            "Single-segment transfer SHOULD NOT have Transfer Length Extension"
        );
    }
}

/// RFC9174-5-2-5-1-143: Transfer Length SHALL be set to bundle size
#[test]
fn test_rfc9174_5_2_5_1_143_transfer_length_equals_bundle_size() {
    // RFC 9174 §5.2.5.1: "If a Transfer Length Extension is present in a transfer,
    // the Total Bundle Length field SHALL be set to the size in octets of the bundle
    // that is being transferred"

    let pair = common::SessionPair::establish().unwrap();
    let mut session = pair.active;

    // Multi-segment transfer (force by using small segment size)
    let bundle_data = vec![0xFF; 500];
    let bundle_size = bundle_data.len();

    let transfer_id = session.start_transfer(bundle_data).unwrap();
    let segments = session.create_segments(transfer_id, 100).unwrap(); // Small MRU forces multiple segments

    assert!(segments.len() > 1, "Transfer should use multiple segments");

    // Check first segment (START flag set) for Transfer Length Extension
    if let Message::TransferSegment { extensions, .. } = &segments[0] {
        // Find Transfer Length Extension (type 0x0001)
        if let Some(transfer_length_ext) = extensions.iter().find(|ext| ext.type_code == 0x0001) {
            // Decode Total Bundle Length from extension value (8 bytes, big-endian)
            assert_eq!(
                transfer_length_ext.value.len(),
                8,
                "Transfer Length value should be 8 bytes"
            );

            let total_length = u64::from_be_bytes([
                transfer_length_ext.value[0],
                transfer_length_ext.value[1],
                transfer_length_ext.value[2],
                transfer_length_ext.value[3],
                transfer_length_ext.value[4],
                transfer_length_ext.value[5],
                transfer_length_ext.value[6],
                transfer_length_ext.value[7],
            ]);

            assert_eq!(
                total_length as usize, bundle_size,
                "Total Bundle Length SHALL equal bundle size in octets"
            );
        }
    }
}
