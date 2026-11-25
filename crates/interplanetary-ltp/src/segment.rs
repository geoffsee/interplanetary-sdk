//! LTP segment codec (RFC 5326 §3).

use super::sdnv;
use interplanetary_types::{Error, Result};

/// IANA / CCSDS client service number for the Bundle Protocol.
pub const BUNDLE_SERVICE_ID: u64 = 1;

/// Session identifier: engine number plus session number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    /// Engine that originated the session.
    pub engine: u64,
    /// Session number at that engine.
    pub session: u64,
}

/// One LTP segment. Header and trailer extension counts are zero on encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// Red-part data. `checkpoint` is set on type codes 1, 2, and 3.
    Red {
        /// Session this data belongs to.
        session: SessionId,
        /// Offset of `data` within the block.
        offset: u64,
        /// Client service bytes.
        data: Vec<u8>,
        /// Checkpoint serial and report serial, when this segment is a checkpoint.
        checkpoint: Option<(u64, u64)>,
        /// End of red part.
        end_of_red: bool,
        /// End of block.
        end_of_block: bool,
    },
    /// Report of reception claims for a checkpoint.
    Report {
        /// Session being reported.
        session: SessionId,
        /// Report serial number.
        report_serial: u64,
        /// Checkpoint serial this report answers.
        checkpoint_serial: u64,
        /// Exclusive end of the reported range.
        upper: u64,
        /// Inclusive start of the reported range.
        lower: u64,
        /// `(offset, length)` claims inside the range.
        claims: Vec<(u64, u64)>,
    },
    /// Acknowledgement of a report segment.
    ReportAck {
        /// Session whose report is acknowledged.
        session: SessionId,
        /// Report serial number.
        report_serial: u64,
    },
}

impl Segment {
    /// Encode one segment.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let (type_code, session) = match self {
            Segment::Red {
                session,
                checkpoint,
                end_of_red,
                end_of_block,
                ..
            } => {
                let code = match (checkpoint.is_some(), *end_of_red, *end_of_block) {
                    (false, false, false) => 0,
                    (true, false, false) => 1,
                    (true, true, false) => 2,
                    (true, true, true) => 3,
                    _ => 0,
                };
                (code, *session)
            }
            Segment::Report { session, .. } => (8, *session),
            Segment::ReportAck { session, .. } => (9, *session),
        };
        out.push(type_code);
        sdnv::encode(session.engine, &mut out);
        sdnv::encode(session.session, &mut out);
        sdnv::encode(0, &mut out);
        sdnv::encode(0, &mut out);
        match self {
            Segment::Red {
                offset,
                data,
                checkpoint,
                ..
            } => {
                sdnv::encode(BUNDLE_SERVICE_ID, &mut out);
                sdnv::encode(*offset, &mut out);
                sdnv::encode(data.len() as u64, &mut out);
                if let Some((cp, rs)) = checkpoint {
                    sdnv::encode(*cp, &mut out);
                    sdnv::encode(*rs, &mut out);
                }
                out.extend_from_slice(data);
            }
            Segment::Report {
                report_serial,
                checkpoint_serial,
                upper,
                lower,
                claims,
                ..
            } => {
                sdnv::encode(*report_serial, &mut out);
                sdnv::encode(*checkpoint_serial, &mut out);
                sdnv::encode(*upper, &mut out);
                sdnv::encode(*lower, &mut out);
                sdnv::encode(claims.len() as u64, &mut out);
                for (off, len) in claims {
                    sdnv::encode(*off, &mut out);
                    sdnv::encode(*len, &mut out);
                }
            }
            Segment::ReportAck { report_serial, .. } => {
                sdnv::encode(*report_serial, &mut out);
            }
        }
        out
    }

    /// Decode one datagram. Trailing bytes are an error.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::malformed_input("empty LTP segment"));
        }
        let type_code = bytes[0] & 0x0f;
        let version = bytes[0] >> 4;
        if version != 0 {
            return Err(Error::unsupported(format!("LTP version {version}")));
        }
        let mut offset = 1;
        let (engine, n) = sdnv::decode(&bytes[offset..])?;
        offset += n;
        let (session_num, n) = sdnv::decode(&bytes[offset..])?;
        offset += n;
        let session = SessionId {
            engine,
            session: session_num,
        };
        let (header_ext, n) = sdnv::decode(&bytes[offset..])?;
        offset += n;
        offset = skip_extensions(bytes, offset, header_ext)?;
        let (trailer_ext, n) = sdnv::decode(&bytes[offset..])?;
        offset += n;
        offset = skip_extensions(bytes, offset, trailer_ext)?;
        let segment = match type_code {
            0..=3 => decode_red(bytes, &mut offset, session, type_code)?,
            8 => decode_report(bytes, &mut offset, session)?,
            9 => {
                let (report_serial, n) = sdnv::decode(&bytes[offset..])?;
                offset += n;
                Segment::ReportAck {
                    session,
                    report_serial,
                }
            }
            other => {
                return Err(Error::unsupported(format!(
                    "unsupported LTP segment type {other}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(Error::malformed_input("trailing bytes after LTP segment"));
        }
        Ok(segment)
    }
}

fn skip_extensions(bytes: &[u8], mut offset: usize, count: u64) -> Result<usize> {
    for _ in 0..count {
        let (_tag, n) = sdnv::decode(&bytes[offset..])?;
        offset += n;
        let (len, n) = sdnv::decode(&bytes[offset..])?;
        offset += n;
        let len = usize::try_from(len).map_err(|_| Error::malformed_input("extension length"))?;
        if bytes.len() < offset + len {
            return Err(Error::malformed_input("truncated LTP extension"));
        }
        offset += len;
    }
    Ok(offset)
}

fn decode_red(
    bytes: &[u8],
    offset: &mut usize,
    session: SessionId,
    type_code: u8,
) -> Result<Segment> {
    let (_service, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let (data_off, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let (len, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let checkpoint = if type_code == 0 {
        None
    } else {
        let (cp, n) = sdnv::decode(&bytes[*offset..])?;
        *offset += n;
        let (rs, n) = sdnv::decode(&bytes[*offset..])?;
        *offset += n;
        Some((cp, rs))
    };
    let len = usize::try_from(len).map_err(|_| Error::malformed_input("data length"))?;
    if bytes.len() < *offset + len {
        return Err(Error::malformed_input("truncated LTP data"));
    }
    let data = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(Segment::Red {
        session,
        offset: data_off,
        data,
        checkpoint,
        end_of_red: matches!(type_code, 2 | 3),
        end_of_block: type_code == 3,
    })
}

fn decode_report(bytes: &[u8], offset: &mut usize, session: SessionId) -> Result<Segment> {
    let (report_serial, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let (checkpoint_serial, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let (upper, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let (lower, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let (count, n) = sdnv::decode(&bytes[*offset..])?;
    *offset += n;
    let mut claims = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for _ in 0..count {
        let (off, n) = sdnv::decode(&bytes[*offset..])?;
        *offset += n;
        let (len, n) = sdnv::decode(&bytes[*offset..])?;
        *offset += n;
        claims.push((off, len));
    }
    Ok(Segment::Report {
        session,
        report_serial,
        checkpoint_serial,
        upper,
        lower,
        claims,
    })
}
