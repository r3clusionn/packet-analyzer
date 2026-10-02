//! TCP stream reassembly: turns the segments of one connection into the byte streams the two
//! sides sent, as "Follow TCP Stream" does.
//!
//! * Sequence numbers are unwrapped into 64-bit stream offsets, so a stream may cross the 2^32
//!   wrap more than once.
//! * Out-of-order segments wait until the bytes before them arrive; a retransmission adds
//!   nothing.
//! * When segments overlap with different content (a retransmission with other data, or an
//!   evasion attempt), the bytes that came first win and the conflict is counted.
//! * Data that never arrives is reported as a gap of known size.

use std::collections::BTreeMap;

use crate::flow::Direction;

#[derive(Clone, Debug, PartialEq)]
pub struct Chunk {
    pub dir: Direction,
    pub ts: f64,
    pub data: Vec<u8>,
    /// Bytes missing immediately before this chunk (0 when the stream is contiguous here).
    pub gap: u64,
}

#[derive(Default)]
struct Side {
    /// (sequence number, stream offset) of the last segment, to unwrap the next sequence number.
    anchor: Option<(u32, i64)>,
    /// The offset of the next byte expected.
    next: i64,
    /// Everything delivered so far, to compare retransmissions against.
    delivered: Vec<u8>,
    /// Offset of `delivered[0]` in the stream.
    origin: i64,
    pending: BTreeMap<i64, Vec<u8>>,
}

pub struct Reassembler {
    sides: [Side; 2],
    pub chunks: Vec<Chunk>,
    pub retransmitted_bytes: u64,
    pub conflicting_bytes: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Reassembler {
        Reassembler {
            sides: [Side::default(), Side::default()],
            chunks: Vec::new(),
            retransmitted_bytes: 0,
            conflicting_bytes: 0,
        }
    }

    /// Adds one TCP segment. `syn` segments consume a sequence number before their data.
    pub fn add(&mut self, dir: Direction, seq: u32, syn: bool, payload: &[u8], ts: f64) {
        let side = &mut self.sides[dir as usize];
        let seq = if syn { seq.wrapping_add(1) } else { seq };
        let start = match side.anchor {
            None => {
                side.next = 0;
                0
            }
            Some((aseq, aoff)) => aoff + seq.wrapping_sub(aseq) as i32 as i64,
        };
        side.anchor = Some((seq, start));
        if payload.is_empty() {
            return;
        }
        let delivered_before = side.delivered.len();
        Self::offer(side, start, payload.to_vec(), &mut self.retransmitted_bytes, &mut self.conflicting_bytes);
        Self::drain(
            side,
            &mut self.retransmitted_bytes,
            &mut self.conflicting_bytes,
            dir,
            ts,
            &mut self.chunks,
            delivered_before,
        );
    }

    /// Places data that starts at `start`: delivers what is new now, parks what is ahead of a gap.
    fn offer(side: &mut Side, start: i64, data: Vec<u8>, retrans: &mut u64, conflict: &mut u64) {
        let end = start + data.len() as i64;
        if end <= side.next {
            // Entirely old: a retransmission. Compare it with what was delivered.
            *retrans += data.len() as u64;
            Self::compare(side, start, &data, conflict);
        } else if start <= side.next {
            let overlap = (side.next - start) as usize;
            if overlap > 0 {
                *retrans += overlap as u64;
                Self::compare(side, start, &data[..overlap], conflict);
            }
            side.delivered.extend_from_slice(&data[overlap..]);
            side.next = end;
        } else {
            // Ahead of a gap. If the same offset is parked already, keep the first and count a conflict if they differ.
            match side.pending.get(&start) {
                Some(old) => {
                    let n = old.len().min(data.len());
                    if old[..n] != data[..n] {
                        *conflict += n as u64;
                    }
                    if data.len() > old.len() {
                        side.pending.insert(start, data);
                    }
                }
                None => {
                    side.pending.insert(start, data);
                }
            }
        }
    }

    fn compare(side: &Side, start: i64, data: &[u8], conflict: &mut u64) {
        for (i, b) in data.iter().enumerate() {
            let off = start + i as i64 - side.origin;
            if off >= 0 {
                if let Some(old) = side.delivered.get(off as usize) {
                    if old != b {
                        *conflict += 1;
                    }
                }
            }
        }
    }

    /// Moves parked data that has become contiguous, and records one chunk for everything newly delivered.
    fn drain(
        side: &mut Side,
        retrans: &mut u64,
        conflict: &mut u64,
        dir: Direction,
        ts: f64,
        chunks: &mut Vec<Chunk>,
        delivered_before: usize,
    ) {
        while let Some((&k, _)) = side.pending.iter().next() {
            if k > side.next {
                break;
            }
            let data = side.pending.remove(&k).unwrap();
            Self::offer(side, k, data, retrans, conflict);
        }
        if side.delivered.len() > delivered_before {
            chunks.push(Chunk { dir, ts, data: side.delivered[delivered_before..].to_vec(), gap: 0 });
        }
    }

    /// Ends the capture: data parked behind a gap is delivered with the size of the gap in front of it.
    pub fn finish(&mut self, ts: f64) {
        for (i, dir) in [Direction::ClientToServer, Direction::ServerToClient].into_iter().enumerate() {
            let side = &mut self.sides[i];
            while let Some((&k, _)) = side.pending.iter().next() {
                let data = side.pending.remove(&k).unwrap();
                let gap = (k - side.next).max(0) as u64;
                let delivered_before = side.delivered.len();
                if gap > 0 {
                    side.next = k;
                }
                Self::offer(side, k, data, &mut self.retransmitted_bytes, &mut self.conflicting_bytes);
                if side.delivered.len() > delivered_before {
                    self.chunks.push(Chunk { dir, ts, data: side.delivered[delivered_before..].to_vec(), gap });
                }
            }
        }
    }

    /// Everything one side sent, in order, with gaps left out.
    pub fn stream(&self, dir: Direction) -> Vec<u8> {
        self.chunks.iter().filter(|c| c.dir == dir).flat_map(|c| c.data.iter().copied()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Direction::{ClientToServer as C, ServerToClient as S};

    fn text(r: &Reassembler, d: Direction) -> String {
        String::from_utf8_lossy(&r.stream(d)).into_owned()
    }

    #[test]
    fn in_order_segments_and_interleaved_directions() {
        let mut r = Reassembler::new();
        r.add(C, 99, true, b"", 0.0);
        r.add(S, 499, true, b"", 0.1);
        r.add(C, 100, false, b"GET / ", 0.2);
        r.add(C, 106, false, b"HTTP/1.1\r\n\r\n", 0.3);
        r.add(S, 500, false, b"HTTP/1.1 200 OK\r\n", 0.4);
        r.add(S, 517, false, b"\r\nhello", 0.5);
        assert_eq!(text(&r, C), "GET / HTTP/1.1\r\n\r\n");
        assert_eq!(text(&r, S), "HTTP/1.1 200 OK\r\n\r\nhello");
        let order: Vec<Direction> = r.chunks.iter().map(|c| c.dir).collect();
        assert_eq!(order, vec![C, C, S, S], "chunks keep the order in which data arrived");
        assert_eq!((r.retransmitted_bytes, r.conflicting_bytes), (0, 0));
    }

    #[test]
    fn out_of_order_segments_wait_for_the_missing_bytes() {
        let mut r = Reassembler::new();
        r.add(C, 1000, false, b"AAAA", 0.0);
        r.add(C, 1008, false, b"CCCC", 0.1);
        assert_eq!(text(&r, C), "AAAA", "CCCC waits behind a gap");
        r.add(C, 1012, false, b"DDDD", 0.2);
        r.add(C, 1004, false, b"BBBB", 0.3);
        assert_eq!(text(&r, C), "AAAABBBBCCCCDDDD");
        // The chunk that completed the stream carries everything it unlocked.
        assert_eq!(r.chunks.last().unwrap().data, b"BBBBCCCCDDDD");
        assert!(r.chunks.iter().all(|c| c.gap == 0));
    }

    #[test]
    fn retransmissions_add_nothing_and_are_counted() {
        let mut r = Reassembler::new();
        r.add(C, 10, false, b"hello ", 0.0);
        r.add(C, 10, false, b"hello ", 0.1);
        r.add(C, 16, false, b"world", 0.2);
        r.add(C, 13, false, b"lo wor", 0.3); // overlaps both
        assert_eq!(text(&r, C), "hello world");
        assert_eq!((r.retransmitted_bytes, r.conflicting_bytes), (6 + 6, 0));
    }

    #[test]
    fn a_partly_new_segment_delivers_only_its_new_part() {
        let mut r = Reassembler::new();
        r.add(C, 0, false, b"abcdef", 0.0);
        r.add(C, 4, false, b"efghij", 0.1);
        assert_eq!(text(&r, C), "abcdefghij");
        assert_eq!(r.chunks[1].data, b"ghij");
        assert_eq!(r.retransmitted_bytes, 2);
    }

    #[test]
    fn conflicting_overlaps_keep_the_first_bytes() {
        let mut r = Reassembler::new();
        r.add(C, 0, false, b"GET /ok", 0.0);
        r.add(C, 4, false, b"/EVIL", 0.1); // a rewrite of bytes already delivered, with two new ones
        assert_eq!(text(&r, C), "GET /okIL");
        assert!(r.conflicting_bytes > 0);
        // Conflicting copies parked behind a gap.
        let mut r = Reassembler::new();
        r.add(C, 0, false, b"AA", 0.0);
        r.add(C, 10, false, b"first", 0.1);
        r.add(C, 10, false, b"other", 0.2);
        r.finish(1.0);
        assert!(text(&r, C).ends_with("first"));
        assert_eq!(r.conflicting_bytes, 5);
    }

    #[test]
    fn gaps_are_reported_with_their_size() {
        let mut r = Reassembler::new();
        r.add(C, 0, false, b"head", 0.0);
        r.add(C, 20, false, b"tail", 0.1);
        r.finish(2.0);
        assert_eq!(r.chunks.len(), 2);
        assert_eq!((r.chunks[1].gap, r.chunks[1].data.as_slice()), (16, &b"tail"[..]));
        assert_eq!(r.chunks[0].gap, 0);
    }

    #[test]
    fn sequence_numbers_wrap_around() {
        let mut r = Reassembler::new();
        let start = u32::MAX - 5;
        r.add(C, start, false, b"before ", 0.0); // crosses the wrap: 6 bytes before, 1 after
        r.add(C, start.wrapping_add(7), false, b"after", 0.1);
        r.add(C, start.wrapping_add(12), false, b"!", 0.2);
        assert_eq!(text(&r, C), "before after!");
        // Out of order across the wrap.
        let mut r = Reassembler::new();
        r.add(C, u32::MAX - 1, false, b"ab", 0.0);
        r.add(C, 2, false, b"ef", 0.1);
        r.add(C, 0, false, b"cd", 0.2);
        assert_eq!(text(&r, C), "abcdef");
    }

    #[test]
    fn a_long_stream_crossing_the_wrap_more_than_once() {
        let mut r = Reassembler::new();
        let mut seq = 0u32;
        let block = vec![b'x'; 1_000_000_000];
        // 5 GB of sequence space in four-segment hops without storing the data: only offsets matter,
        // so use tiny payloads spaced by large gaps and let finish() report the gaps.
        let _ = block;
        let mut total_gap = 0u64;
        for i in 0..6 {
            r.add(C, seq, false, &[i as u8], 0.0);
            seq = seq.wrapping_add(1_000_000_000);
            total_gap += 999_999_999;
        }
        r.finish(1.0);
        let gaps: u64 = r.chunks.iter().map(|c| c.gap).sum();
        assert_eq!(gaps, total_gap - 999_999_999);
        assert_eq!(r.stream(C), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn syn_consumes_a_sequence_number() {
        let mut r = Reassembler::new();
        r.add(C, 100, true, b"", 0.0);
        r.add(C, 101, false, b"data", 0.1);
        assert_eq!(text(&r, C), "data");
        assert!(r.chunks.iter().all(|c| c.gap == 0));
    }

    #[test]
    fn data_before_the_first_seen_segment_is_not_a_gap() {
        // A capture that starts mid-stream: the first segment defines the start.
        let mut r = Reassembler::new();
        r.add(C, 123_456, false, b"mid", 0.0);
        r.add(C, 123_459, false, b"stream", 0.1);
        r.finish(1.0);
        assert_eq!(text(&r, C), "midstream");
    }

    #[test]
    fn random_segmentations_reassemble_exactly() {
        let mut seed = 21u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..500 {
            let len = 1 + next(300) as usize;
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + round) as u8).collect();
            let base = next(u32::MAX as u64) as u32;
            // Cut into random segments, add random retransmissions and overlaps, then shuffle.
            let mut segs: Vec<(usize, usize)> = Vec::new();
            let mut at = 0;
            while at < len {
                let n = (1 + next(40) as usize).min(len - at);
                segs.push((at, n));
                at += n;
            }
            for _ in 0..next(6) {
                let s = next(len as u64) as usize;
                let n = (1 + next(40) as usize).min(len - s);
                segs.push((s, n));
            }
            for i in (1..segs.len()).rev() {
                let j = next(i as u64 + 1) as usize;
                segs.swap(i, j);
            }
            let mut r = Reassembler::new();
            // The first segment seen defines the start, so make sure offset 0 is not behind it:
            // deliver a zero-length anchor segment first.
            r.add(C, base, false, b"", 0.0);
            for (s, n) in &segs {
                r.add(C, base.wrapping_add(*s as u32), false, &data[*s..*s + *n], 0.0);
            }
            r.finish(1.0);
            assert_eq!(r.stream(C), data, "round {round}");
            assert_eq!(r.conflicting_bytes, 0);
            assert!(r.chunks.iter().all(|c| c.gap == 0), "round {round}");
        }
    }
}
