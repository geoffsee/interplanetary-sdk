//! Shortest-form CBOR encoding per RFC 8949 §4.2.1 and RFC 9171 §4.1

/// Encode unsigned integer in shortest CBOR form per RFC 8949 §4.2.1
///
/// Preferred encoding (must use for generation):
/// - 0-23: direct in type byte (major type 0, additional info 0-23)
/// - 24-255: uint8 (type byte 0x18, 1 byte follows)
/// - 256-65535: uint16 (type byte 0x19, 2 bytes follow)
/// - 65536-4294967295: uint32 (type byte 0x1a, 4 bytes follow)
/// - >4294967295: uint64 (type byte 0x1b, 8 bytes follow)
pub fn encode_uint(value: u64, output: &mut Vec<u8>) {
    if value <= 23 {
        output.push(value as u8);
    } else if value <= 255 {
        output.push(0x18);
        output.push(value as u8);
    } else if value <= 65535 {
        output.push(0x19);
        output.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFFFFFF {
        output.push(0x1a);
        output.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        output.push(0x1b);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

/// Encode byte string in shortest CBOR form
pub fn encode_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    encode_major_type(2, bytes.len() as u64, output);
    output.extend_from_slice(bytes);
}

/// Encode text string in shortest CBOR form
pub fn encode_text(text: &str, output: &mut Vec<u8>) {
    encode_major_type(3, text.len() as u64, output);
    output.extend_from_slice(text.as_bytes());
}

/// Encode array header in shortest CBOR form
pub fn encode_array_header(len: u64, output: &mut Vec<u8>) {
    encode_major_type(4, len, output);
}

/// Encode major type with argument in shortest form
fn encode_major_type(major: u8, argument: u64, output: &mut Vec<u8>) {
    let type_byte = major << 5;
    if argument <= 23 {
        output.push(type_byte | (argument as u8));
    } else if argument <= 255 {
        output.push(type_byte | 24);
        output.push(argument as u8);
    } else if argument <= 65535 {
        output.push(type_byte | 25);
        output.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= 0xFFFFFFFF {
        output.push(type_byte | 26);
        output.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        output.push(type_byte | 27);
        output.extend_from_slice(&argument.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_uint_boundary_0_23() {
        let mut buf = Vec::new();
        encode_uint(0, &mut buf);
        assert_eq!(buf, vec![0x00], "0 encodes as direct byte");

        buf.clear();
        encode_uint(23, &mut buf);
        assert_eq!(buf, vec![0x17], "23 encodes as direct byte");
    }

    #[test]
    fn test_encode_uint_boundary_24() {
        let mut buf = Vec::new();
        encode_uint(24, &mut buf);
        assert_eq!(buf, vec![0x18, 0x18], "24 requires uint8 form");

        buf.clear();
        encode_uint(255, &mut buf);
        assert_eq!(buf, vec![0x18, 0xFF], "255 is largest uint8");
    }

    #[test]
    fn test_encode_uint_boundary_256() {
        let mut buf = Vec::new();
        encode_uint(256, &mut buf);
        assert_eq!(buf, vec![0x19, 0x01, 0x00], "256 requires uint16 form");

        buf.clear();
        encode_uint(65535, &mut buf);
        assert_eq!(buf, vec![0x19, 0xFF, 0xFF], "65535 is largest uint16");
    }

    #[test]
    fn test_encode_uint_boundary_65536() {
        let mut buf = Vec::new();
        encode_uint(65536, &mut buf);
        assert_eq!(
            buf,
            vec![0x1a, 0x00, 0x01, 0x00, 0x00],
            "65536 requires uint32 form"
        );

        buf.clear();
        encode_uint(0xFFFFFFFF, &mut buf);
        assert_eq!(
            buf,
            vec![0x1a, 0xFF, 0xFF, 0xFF, 0xFF],
            "2^32-1 is largest uint32"
        );
    }

    #[test]
    fn test_encode_uint_boundary_2_32() {
        let mut buf = Vec::new();
        encode_uint(0x100000000, &mut buf);
        assert_eq!(
            buf,
            vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            "2^32 requires uint64 form"
        );
    }

    #[test]
    fn test_encode_array_shortest() {
        let mut buf = Vec::new();
        encode_array_header(5, &mut buf);
        assert_eq!(buf, vec![0x85], "Array of 5 uses direct encoding");

        buf.clear();
        encode_array_header(24, &mut buf);
        assert_eq!(buf, vec![0x98, 0x18], "Array of 24 uses uint8");
    }

    #[test]
    fn test_encode_bytes_shortest() {
        let mut buf = Vec::new();
        encode_bytes(&[0x01, 0x02, 0x03], &mut buf);
        assert_eq!(
            buf,
            vec![0x43, 0x01, 0x02, 0x03],
            "3-byte string uses direct length"
        );
    }
}
