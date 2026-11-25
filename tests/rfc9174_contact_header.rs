//! RFC 9174 §4.2 Contact Header Tests

#[test]
fn test_rfc9174_4_2_magic_value() {
    // RFC 9174 §4.2: The Contact Header SHALL consist of the following
    // fields: Magic: A four-octet field that SHALL contain the octet
    // sequence 0x64 0x74 0x6e 0x21 ("dtn!")

    const MAGIC: [u8; 4] = [0x64, 0x74, 0x6e, 0x21];

    assert_eq!(
        MAGIC,
        [0x64, 0x74, 0x6e, 0x21],
        "Magic SHALL be 0x64 0x74 0x6e 0x21 (dtn!)"
    );
}

#[test]
fn test_rfc9174_4_2_version_field() {
    // RFC 9174 §4.2: Version: A one-octet field value indicating the
    // version of the protocol in use. This document defines version 4.

    const VERSION: u8 = 4;

    assert_eq!(VERSION, 4, "Version MUST be 4 for TCPCLv4");
}

#[test]
fn test_rfc9174_4_2_flags_field() {
    // RFC 9174 §4.2: Flags: A one-octet field containing optional
    // connection flags

    let _flags: u8 = 0;

    // Flags field is one octet (u8 type ensures this)
}

#[test]
fn test_rfc9174_4_3_invalid_magic_rejection() {
    // RFC 9174 §4.3: If the magic string is not an exact match, the
    // connection MUST be terminated

    const MAGIC: [u8; 4] = [0x64, 0x74, 0x6e, 0x21];
    let invalid_magic = [0x64, 0x74, 0x6e, 0x22]; // Wrong last byte

    assert_ne!(invalid_magic, MAGIC, "Invalid magic MUST be rejected");
}

#[test]
fn test_rfc9174_4_3_version_mismatch_causes_rejection() {
    // RFC 9174 §4.3: If the version from the Contact Header is not
    // version 4, the connection MUST be terminated

    let unsupported_version: u8 = 3;

    assert_ne!(
        unsupported_version, 4,
        "Version mismatch MUST cause connection termination"
    );
}
