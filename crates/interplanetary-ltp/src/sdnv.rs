//! Self-delimiting numeric values (RFC 6256).

use interplanetary_types::{Error, Result};

pub(crate) fn encode(mut value: u64, out: &mut Vec<u8>) {
    let mut buf = [0u8; 10];
    let mut i = 9;
    buf[i] = (value & 0x7f) as u8;
    value >>= 7;
    while value > 0 {
        i -= 1;
        buf[i] = ((value & 0x7f) as u8) | 0x80;
        value >>= 7;
    }
    out.extend_from_slice(&buf[i..]);
}

pub(crate) fn decode(bytes: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, byte) in bytes.iter().enumerate().take(10) {
        if value > (u64::MAX >> 7) {
            return Err(Error::malformed_input("SDNV overflow"));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(Error::malformed_input("truncated SDNV"))
}
