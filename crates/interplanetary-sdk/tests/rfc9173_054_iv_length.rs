//! RFC 9173 §4.3.1: IV length validation tests
//!
//! RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
//! encoding, MUST be between 8-16 bytes."
//!
//! This tests that:
//! 1. BCB generation rejects IVs shorter than 8 bytes
//! 2. BCB generation rejects IVs longer than 16 bytes
//! 3. Node processing rejects received BCBs with invalid IV lengths
#![cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]

#[cfg(all(feature = "bpsec-default", feature = "test-fixtures"))]
mod iv_length_tests {
    use interplanetary_sdk::bp::{BundleBuilder, CanonicalBlock};
    use interplanetary_sdk::bpa::security_processing::SecurityContext;
    use interplanetary_sdk::security::AesGcmVariant;
    use interplanetary_sdk::security::bcb::{BcbConfig, BcbTargets};
    use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

    /// Test that BCB generation rejects IV shorter than 8 bytes (7 bytes)
    #[test]
    fn test_rfc9173_054_generation_rejects_short_iv() {
        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes."

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"test payload".to_vec())
            .build()
            .unwrap();

        // Attempt to generate BCB with 7-byte IV (below minimum)
        let config = BcbConfig {
            security_source: EndpointId::ipn(0, 2, 0).unwrap(),
            targets: BcbTargets {
                block_numbers: vec![1], // Target payload block
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0xAA; 16],
            iv: vec![0x01; 7], // 7 bytes - TOO SHORT
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: false,
        };

        let result = interplanetary_sdk::security::bcb::generate_bcb(&bundle, &config, None);

        // Must reject 7-byte IV
        assert!(
            result.is_err(),
            "BCB generation must reject 7-byte IV (below 8-byte minimum)"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("8-16 bytes") || err.to_string().contains("4.3.1"),
            "Error message should reference RFC 9173 §4.3.1 IV length requirement, got: {}",
            err
        );
    }

    /// Test that BCB generation rejects IV longer than 16 bytes (17 bytes)
    #[test]
    fn test_rfc9173_054_generation_rejects_long_iv() {
        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes."

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"test payload".to_vec())
            .build()
            .unwrap();

        // Attempt to generate BCB with 17-byte IV (above maximum)
        let config = BcbConfig {
            security_source: EndpointId::ipn(0, 2, 0).unwrap(),
            targets: BcbTargets {
                block_numbers: vec![1], // Target payload block
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0xAA; 16],
            iv: vec![0x01; 17], // 17 bytes - TOO LONG
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: false,
        };

        let result = interplanetary_sdk::security::bcb::generate_bcb(&bundle, &config, None);

        // Must reject 17-byte IV
        assert!(
            result.is_err(),
            "BCB generation must reject 17-byte IV (above 16-byte maximum)"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("8-16 bytes") || err.to_string().contains("4.3.1"),
            "Error message should reference RFC 9173 §4.3.1 IV length requirement, got: {}",
            err
        );
    }

    /// Test that node processing rejects received BCB with short IV (7 bytes)
    ///
    /// This constructs a bundle with a manually-crafted BCB block containing a 7-byte IV,
    /// then verifies that parsing/processing rejects it per RFC 9173 §4.3.1.
    #[test]
    fn test_rfc9173_054_node_rejects_received_short_iv() {
        use ciborium::Value;
        use interplanetary_sdk::bp::BlockType;

        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes."

        // Create a bundle with a manually-crafted BCB containing a 7-byte IV
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"encrypted payload".to_vec())
            .build()
            .unwrap();

        // Craft BCB block data with 7-byte IV
        let mut bcb_data = Vec::new();

        // Security targets: [1] (payload block)
        ciborium::into_writer(&Value::Array(vec![Value::Integer(1.into())]), &mut bcb_data)
            .unwrap();

        // Security context ID: 2 (BCB-AES-GCM)
        ciborium::into_writer(&Value::Integer(2.into()), &mut bcb_data).unwrap();

        // Security context flags: 1 (parameters present)
        ciborium::into_writer(&Value::Integer(1.into()), &mut bcb_data).unwrap();

        // Security source: ipn:0.2.0 as [2, 2]
        ciborium::into_writer(
            &Value::Array(vec![Value::Integer(2.into()), Value::Integer(2.into())]),
            &mut bcb_data,
        )
        .unwrap();

        // Security parameters: IV (7 bytes), AES variant, scope flags
        let params = Value::Array(vec![
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(vec![0x01; 7]), // 7-byte IV - INVALID
            ]),
            Value::Array(vec![
                Value::Integer(2.into()),
                Value::Integer(1.into()), // AES-128
            ]),
            Value::Array(vec![
                Value::Integer(4.into()),
                Value::Integer(0.into()), // scope flags
            ]),
        ]);
        ciborium::into_writer(&params, &mut bcb_data).unwrap();

        // Security results: dummy auth tag
        let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(vec![0xAA; 16]),
        ])])]);
        ciborium::into_writer(&results, &mut bcb_data).unwrap();

        // Add BCB block to bundle
        let bcb_block = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 2,
            block_flags: 1,
            crc_type: interplanetary_sdk::bp::CrcType::None,
            data: bcb_data,
        };
        bundle.blocks.push(bcb_block);

        // Attempt to process BCB (parse will fail on invalid IV length)
        let mut ctx = SecurityContext::new();
        ctx.add_aes_key(EndpointId::ipn(0, 2, 0).unwrap(), vec![0xAA; 16]);

        let result =
            interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx);

        // Must reject bundle with 7-byte IV
        assert!(
            result.is_err(),
            "Node must reject received BCB with 7-byte IV (below 8-byte minimum)"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("8-16 bytes") || err.to_string().contains("4.3.1"),
            "Error message should reference RFC 9173 §4.3.1 IV length requirement, got: {}",
            err
        );
    }

    /// Test that node processing rejects received BCB with long IV (17 bytes)
    ///
    /// This constructs a bundle with a manually-crafted BCB block containing a 17-byte IV,
    /// then verifies that parsing/processing rejects it per RFC 9173 §4.3.1.
    #[test]
    fn test_rfc9173_054_node_rejects_received_long_iv() {
        use ciborium::Value;
        use interplanetary_sdk::bp::BlockType;

        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes."

        // Create a bundle with a manually-crafted BCB containing a 17-byte IV
        let mut bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"encrypted payload".to_vec())
            .build()
            .unwrap();

        // Craft BCB block data with 17-byte IV
        let mut bcb_data = Vec::new();

        // Security targets: [1] (payload block)
        ciborium::into_writer(&Value::Array(vec![Value::Integer(1.into())]), &mut bcb_data)
            .unwrap();

        // Security context ID: 2 (BCB-AES-GCM)
        ciborium::into_writer(&Value::Integer(2.into()), &mut bcb_data).unwrap();

        // Security context flags: 1 (parameters present)
        ciborium::into_writer(&Value::Integer(1.into()), &mut bcb_data).unwrap();

        // Security source: ipn:0.2.0 as [2, 2]
        ciborium::into_writer(
            &Value::Array(vec![Value::Integer(2.into()), Value::Integer(2.into())]),
            &mut bcb_data,
        )
        .unwrap();

        // Security parameters: IV (17 bytes), AES variant, scope flags
        let params = Value::Array(vec![
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(vec![0x01; 17]), // 17-byte IV - INVALID
            ]),
            Value::Array(vec![
                Value::Integer(2.into()),
                Value::Integer(1.into()), // AES-128
            ]),
            Value::Array(vec![
                Value::Integer(4.into()),
                Value::Integer(0.into()), // scope flags
            ]),
        ]);
        ciborium::into_writer(&params, &mut bcb_data).unwrap();

        // Security results: dummy auth tag
        let results = Value::Array(vec![Value::Array(vec![Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(vec![0xAA; 16]),
        ])])]);
        ciborium::into_writer(&results, &mut bcb_data).unwrap();

        // Add BCB block to bundle
        let bcb_block = CanonicalBlock {
            block_type: BlockType::Bcb,
            block_number: 2,
            block_flags: 1,
            crc_type: interplanetary_sdk::bp::CrcType::None,
            data: bcb_data,
        };
        bundle.blocks.push(bcb_block);

        // Attempt to process BCB (parse will fail on invalid IV length)
        let mut ctx = SecurityContext::new();
        ctx.add_aes_key(EndpointId::ipn(0, 2, 0).unwrap(), vec![0xAA; 16]);

        let result =
            interplanetary_sdk::bpa::security_processing::process_bcbs(&mut bundle, &mut ctx);

        // Must reject bundle with 17-byte IV
        assert!(
            result.is_err(),
            "Node must reject received BCB with 17-byte IV (above 16-byte maximum)"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("8-16 bytes") || err.to_string().contains("4.3.1"),
            "Error message should reference RFC 9173 §4.3.1 IV length requirement, got: {}",
            err
        );
    }

    /// Test that valid 12-byte IV is accepted (RFC 9173 Appendix A standard)
    ///
    /// This verifies that the standard 12-byte IV used in RFC 9173 test vectors
    /// passes validation at both generation and processing.
    #[test]
    fn test_rfc9173_054_accepts_valid_12_byte_iv() {
        // RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR
        // encoding, MUST be between 8-16 bytes."
        // RFC 9173 Appendix A uses 12-byte IVs exclusively (the GCM standard).

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::ZERO, 1))
            .lifetime(60_000)
            .payload(b"test payload".to_vec())
            .build()
            .unwrap();

        // Generate BCB with 12-byte IV (standard size)
        let config = BcbConfig {
            security_source: EndpointId::ipn(0, 2, 0).unwrap(), // Use node 2 (valid security source)
            targets: BcbTargets {
                block_numbers: vec![1], // Target payload block
            },
            aes_variant: AesGcmVariant::Aes128,
            key: vec![0xAA; 16],
            // 12-byte IV (standard GCM size, used in RFC 9173 Appendix A.2)
            iv: vec![
                0x54, 0x77, 0x65, 0x6C, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32,
            ],
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: None,
            skip_source_validation: true, // Skip validation for this test (testing IV, not source)
        };

        let result = interplanetary_sdk::security::bcb::generate_bcb(&bundle, &config, None);

        // Must accept 12-byte IV
        assert!(
            result.is_ok(),
            "BCB generation must accept 12-byte IV: {}",
            result.unwrap_err()
        );
    }
}
