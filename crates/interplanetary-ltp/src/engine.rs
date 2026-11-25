//! Red-part session engine.

use super::segment::{Segment, SessionId};
use std::collections::HashMap;

/// Segments to send and blocks ready for the client service.
#[derive(Debug, Default)]
pub struct HandleOut {
    /// Segments produced by this call.
    pub responses: Vec<Segment>,
    /// Completed client-service blocks, in arrival order.
    pub blocks: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct Outbound {
    data: Vec<u8>,
    next_checkpoint: u64,
    next_report_echo: u64,
}

#[derive(Debug)]
struct Inbound {
    pieces: Vec<(u64, Vec<u8>)>,
    length: Option<u64>,
    next_report: u64,
}

/// One LTP engine. Session numbers increase from 1.
#[derive(Debug)]
pub struct LtpEngine {
    engine_id: u64,
    next_session: u64,
    segment_payload: usize,
    outbound: HashMap<u64, Outbound>,
    inbound: HashMap<SessionId, Inbound>,
}

impl LtpEngine {
    /// `segment_payload` is the maximum client-service bytes in one data segment.
    pub fn new(engine_id: u64, segment_payload: usize) -> Self {
        Self {
            engine_id,
            next_session: 1,
            segment_payload: segment_payload.max(1),
            outbound: HashMap::new(),
            inbound: HashMap::new(),
        }
    }

    /// Queue a red block and return the segments that carry it.
    ///
    /// The last segment is a checkpoint, end of red part, and end of block.
    pub fn send_block(&mut self, data: Vec<u8>) -> Vec<Segment> {
        let session = self.next_session;
        self.next_session = self.next_session.saturating_add(1);
        let segments = segments_for(
            SessionId {
                engine: self.engine_id,
                session,
            },
            &data,
            &[(0, data.len() as u64)],
            self.segment_payload,
            1,
            0,
        );
        self.outbound.insert(
            session,
            Outbound {
                data,
                next_checkpoint: 2,
                next_report_echo: 1,
            },
        );
        segments
    }

    /// Accept one segment from the peer.
    pub fn handle(&mut self, segment: Segment) -> HandleOut {
        match segment {
            Segment::Red {
                session,
                offset,
                data,
                checkpoint,
                end_of_block,
                ..
            } => self.on_red(session, offset, data, checkpoint, end_of_block),
            Segment::Report {
                session,
                report_serial,
                upper,
                lower,
                claims,
                ..
            } => self.on_report(session, report_serial, lower, upper, claims),
            Segment::ReportAck { session, .. } => {
                self.inbound.remove(&session);
                HandleOut::default()
            }
        }
    }

    fn on_red(
        &mut self,
        session: SessionId,
        offset: u64,
        data: Vec<u8>,
        checkpoint: Option<(u64, u64)>,
        end_of_block: bool,
    ) -> HandleOut {
        let block = self.inbound.entry(session).or_insert_with(|| Inbound {
            pieces: Vec::new(),
            length: None,
            next_report: 1,
        });
        let end = offset + data.len() as u64;
        if end_of_block {
            block.length = Some(end);
        }
        block.pieces.push((offset, data));
        let mut out = HandleOut::default();
        if let Some(total) = block.length
            && let Some(joined) = assemble(&block.pieces, total)
        {
            out.blocks.push(joined);
        }
        if let Some((checkpoint_serial, _report_serial)) = checkpoint {
            let upper = block.length.unwrap_or(end);
            let claims = claims_for(&block.pieces, upper);
            let report_serial = block.next_report;
            block.next_report = block.next_report.saturating_add(1);
            out.responses.push(Segment::Report {
                session,
                report_serial,
                checkpoint_serial,
                upper,
                lower: 0,
                claims,
            });
        }
        out
    }

    fn on_report(
        &mut self,
        session: SessionId,
        report_serial: u64,
        lower: u64,
        upper: u64,
        claims: Vec<(u64, u64)>,
    ) -> HandleOut {
        let mut out = HandleOut::default();
        if session.engine != self.engine_id {
            return out;
        }
        out.responses.push(Segment::ReportAck {
            session,
            report_serial,
        });
        let Some(state) = self.outbound.get_mut(&session.session) else {
            return out;
        };
        let covered = lower == 0
            && upper >= state.data.len() as u64
            && covers(&claims, state.data.len() as u64);
        if covered {
            self.outbound.remove(&session.session);
            return out;
        }
        let gaps = gaps(&claims, state.data.len() as u64);
        let cp = state.next_checkpoint;
        let rs = state.next_report_echo;
        state.next_checkpoint = state.next_checkpoint.saturating_add(1);
        let data = state.data.clone();
        let payload = self.segment_payload;
        out.responses
            .extend(segments_for(session, &data, &gaps, payload, cp, rs));
        out
    }
}

fn claims_for(pieces: &[(u64, Vec<u8>)], upper: u64) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = pieces
        .iter()
        .map(|(off, data)| (*off, data.len() as u64))
        .filter(|(_, len)| *len > 0)
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (off, len) in spans {
        let end = off + len;
        if let Some((_, merged_end)) = merged.last_mut()
            && off <= *merged_end
        {
            *merged_end = (*merged_end).max(end);
            continue;
        }
        merged.push((off, end));
    }
    merged
        .into_iter()
        .filter_map(|(start, end)| {
            let end = end.min(upper);
            (end > start).then_some((start, end - start))
        })
        .collect()
}

fn covers(claims: &[(u64, u64)], len: u64) -> bool {
    let mut cursor = 0u64;
    let mut spans: Vec<(u64, u64)> = claims.iter().copied().filter(|(_, n)| *n > 0).collect();
    spans.sort_unstable();
    for (off, n) in spans {
        if off > cursor {
            return false;
        }
        cursor = cursor.max(off + n);
        if cursor >= len {
            return true;
        }
    }
    cursor >= len
}

fn gaps(claims: &[(u64, u64)], len: u64) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = claims.iter().copied().filter(|(_, n)| *n > 0).collect();
    spans.sort_unstable();
    let mut gaps = Vec::new();
    let mut cursor = 0u64;
    for (off, n) in spans {
        if off > cursor && cursor < len {
            gaps.push((cursor, off.min(len) - cursor));
        }
        cursor = cursor.max(off.saturating_add(n));
    }
    if cursor < len {
        gaps.push((cursor, len - cursor));
    }
    gaps
}

fn segments_for(
    session: SessionId,
    data: &[u8],
    ranges: &[(u64, u64)],
    segment_payload: usize,
    checkpoint_serial: u64,
    report_serial: u64,
) -> Vec<Segment> {
    let mut pieces = Vec::new();
    for &(start, len) in ranges {
        let mut off = start;
        let end = start.saturating_add(len).min(data.len() as u64);
        while off < end {
            let n = ((end - off) as usize).min(segment_payload);
            let slice = data[off as usize..(off as usize + n)].to_vec();
            pieces.push((off, slice));
            off += n as u64;
        }
    }
    let last = pieces.len().saturating_sub(1);
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, (offset, bytes))| {
            let end = i == last;
            let at_block_end = offset + bytes.len() as u64 == data.len() as u64;
            Segment::Red {
                session,
                offset,
                data: bytes,
                checkpoint: end.then_some((checkpoint_serial, report_serial)),
                end_of_red: end && at_block_end,
                end_of_block: end && at_block_end,
            }
        })
        .collect()
}

fn assemble(pieces: &[(u64, Vec<u8>)], len: u64) -> Option<Vec<u8>> {
    let len = usize::try_from(len).ok()?;
    let mut buf = vec![0u8; len];
    let mut filled = vec![false; len];
    for (off, data) in pieces {
        let start = usize::try_from(*off).ok()?;
        if start + data.len() > len {
            return None;
        }
        buf[start..start + data.len()].copy_from_slice(data);
        for slot in &mut filled[start..start + data.len()] {
            *slot = true;
        }
    }
    filled.iter().all(|bit| *bit).then_some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn red_block_round_trip_and_gap_fill() {
        let mut sender = LtpEngine::new(9, 10);
        let mut receiver = LtpEngine::new(4, 10);
        let payload = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        let mut segs = sender.send_block(payload.clone());
        assert!(segs.len() > 1);
        segs.remove(1);
        let mut report = None;
        for seg in segs {
            let out = receiver.handle(seg);
            report = out.responses.into_iter().next().or(report);
        }
        let report = report.expect("checkpoint report");
        let again = sender.handle(report);
        assert!(
            again
                .responses
                .iter()
                .any(|seg| matches!(seg, Segment::ReportAck { .. }))
        );
        let mut delivered = Vec::new();
        for seg in again.responses {
            if matches!(seg, Segment::ReportAck { .. }) {
                continue;
            }
            let wire = seg.encode();
            let decoded = Segment::decode(&wire).unwrap();
            let out = receiver.handle(decoded);
            delivered.extend(out.blocks);
        }
        assert_eq!(delivered, vec![payload]);
    }
}
