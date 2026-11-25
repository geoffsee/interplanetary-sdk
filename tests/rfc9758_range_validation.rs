use interplanetary_sdk::types::EndpointId;

/// RFC9758-007: SDK MUST reject node numbers > u32::MAX in text parse
#[test]
fn test_rfc9758_007_text_parse_rejects_node_exceeds_u32_max() {
    // RFC 9758 §4: "The IPN numeric code shall be in the range of 0 to 4294967295"
    // Test node number > u32::MAX (4294967296)
    let result = EndpointId::parse("ipn:4294967296.1");
    assert!(
        result.is_err(),
        "Parse MUST reject ipn node number > u32::MAX per RFC 9758 §4"
    );
}

/// RFC9758-007: SDK MUST reject service numbers > u32::MAX in text parse
#[test]
fn test_rfc9758_007_text_parse_rejects_service_exceeds_u32_max() {
    // RFC 9758 §4: "The IPN numeric code shall be in the range of 0 to 4294967295"
    // Test service number > u32::MAX (4294967296)
    let result = EndpointId::parse("ipn:1.4294967296");
    assert!(
        result.is_err(),
        "Parse MUST reject ipn service number > u32::MAX per RFC 9758 §4"
    );
}

/// RFC9758-007: SDK MUST reject allocator+node > u32::MAX in text parse
#[test]
fn test_rfc9758_007_text_parse_rejects_three_element_node_exceeds_u32_max() {
    // RFC 9758 §4: "The IPN numeric code shall be in the range of 0 to 4294967295"
    // Test three-element format with node > u32::MAX
    let result = EndpointId::parse("ipn:1.4294967296.1");
    assert!(
        result.is_err(),
        "Parse MUST reject ipn node number > u32::MAX in 3-element format per RFC 9758 §4"
    );
}

/// RFC9758-007: SDK MUST reject node numbers > u32::MAX in CBOR decode
#[test]
fn test_rfc9758_007_cbor_decode_rejects_node_exceeds_u32_max() {
    use interplanetary_sdk::bp::{BundleBuilder, BundleCodec};
    use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs};

    // Create a valid bundle to get structure
    let bundle = BundleBuilder::new()
        .source(EndpointId::parse("dtn://src").unwrap())
        .destination(EndpointId::parse("dtn://dest").unwrap())
        .creation_timestamp(CreationTimestamp {
            time: DtnTimeMs::from_millis(1000),
            sequence: 0,
        })
        .lifetime(3600000)
        .payload(vec![0x01, 0x02])
        .build()
        .unwrap();

    // Hand-craft CBOR with ipn destination having node > u32::MAX
    // Bundle: indefinite array [primary, blocks...]
    // Primary: [version, flags, crc, dest, src, report, timestamp, lifetime]
    // Dest ipn: [2, [fqnn, service]] where fqnn = (allocator << 32) | node

    // Manually construct an ipn EID with invalid node number in CBOR
    // ipn scheme=2, [allocator=0, node=4294967296, service=1] (3-element form)
    use ciborium::Value;
    let invalid_ipn = Value::Array(vec![
        Value::Integer(2i64.into()), // ipn scheme
        Value::Array(vec![
            Value::Integer(0i64.into()),          // allocator
            Value::Integer(4294967296i64.into()), // node > u32::MAX
            Value::Integer(1i64.into()),          // service
        ]),
    ]);

    // Construct primary block with invalid destination
    let invalid_primary = Value::Array(vec![
        Value::Integer(7i64.into()),                       // version
        Value::Integer(0i64.into()),                       // flags
        Value::Integer(0i64.into()),                       // crc_type
        invalid_ipn,                                       // destination (invalid!)
        bundle.primary.source.to_cbor_value().unwrap(),    // source
        bundle.primary.report_to.to_cbor_value().unwrap(), // report_to
        Value::Array(vec![
            Value::Integer(1000i64.into()),
            Value::Integer(0i64.into()),
        ]), // timestamp
        Value::Integer(3600000i64.into()),                 // lifetime
    ]);

    // Encode invalid bundle
    let mut invalid_bundle = Vec::new();
    invalid_bundle.push(0x9F); // Indefinite array
    ciborium::into_writer(&invalid_primary, &mut invalid_bundle).unwrap();

    // Add a valid payload block
    let payload_block = Value::Array(vec![
        Value::Integer(1i64.into()),    // block type (payload)
        Value::Integer(1i64.into()),    // block number
        Value::Integer(0i64.into()),    // flags
        Value::Integer(0i64.into()),    // crc_type
        Value::Bytes(vec![0x01, 0x02]), // data
    ]);
    ciborium::into_writer(&payload_block, &mut invalid_bundle).unwrap();
    invalid_bundle.push(0xFF); // Break

    // Decoder should reject bundle with ipn node > u32::MAX
    let result = BundleCodec::decode(&invalid_bundle);
    assert!(
        result.is_err(),
        "CBOR decoder MUST reject ipn node number > u32::MAX per RFC 9758 §4"
    );
}

// Helper trait for EndpointId to convert to CBOR Value (for testing)
trait ToCborValue {
    fn to_cbor_value(&self) -> Result<ciborium::Value, String>;
}

impl ToCborValue for EndpointId {
    fn to_cbor_value(&self) -> Result<ciborium::Value, String> {
        use ciborium::Value;
        match self {
            EndpointId::Dtn { ssp } => Ok(Value::Array(vec![
                Value::Integer(1i64.into()),
                Value::Text(ssp.clone()),
            ])),
            EndpointId::Ipn {
                allocator,
                node,
                service,
            } => {
                if *allocator == 0 {
                    let fqnn = (*allocator << 32) | *node;
                    Ok(Value::Array(vec![
                        Value::Integer(2i64.into()),
                        Value::Array(vec![
                            Value::Integer((fqnn as i64).into()),
                            Value::Integer((*service as i64).into()),
                        ]),
                    ]))
                } else {
                    Ok(Value::Array(vec![
                        Value::Integer(2i64.into()),
                        Value::Array(vec![
                            Value::Integer((*allocator as i64).into()),
                            Value::Integer((*node as i64).into()),
                            Value::Integer((*service as i64).into()),
                        ]),
                    ]))
                }
            }
            EndpointId::Null => Ok(Value::Array(vec![
                Value::Integer(1i64.into()),
                Value::Integer(0i64.into()),
            ])),
            EndpointId::Unknown { scheme, ssp } => Ok(Value::Text(format!("{}:{}", scheme, ssp))),
        }
    }
}
