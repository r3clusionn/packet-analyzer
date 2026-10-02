//! Reading and writing capture files: classic pcap (microsecond and nanosecond timestamps, both
//! byte orders) and pcapng (sections, interfaces with their own timestamp resolution, enhanced
//! and simple packet blocks).
//!
//! The reader never trusts a length from the file: block and record sizes are checked against the
//! file's own limits before anything is allocated, and a file that ends in the middle of a record
//! yields the packets before it and then one error, not a panic.

use std::io::{self, Read, Write};

/// Largest single record or block accepted (a jumbo frame is 9 KiB; this leaves room for anything real).
const MAX_RECORD: u32 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum PcapError {
    Io(io::Error),
    /// The file is not a capture file, or is damaged.
    Format(String),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapError::Io(e) => write!(f, "{e}"),
            PcapError::Format(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for PcapError {}

impl From<io::Error> for PcapError {
    fn from(e: io::Error) -> Self {
        PcapError::Io(e)
    }
}

fn bad<T>(m: impl Into<String>) -> Result<T, PcapError> {
    Err(PcapError::Format(m.into()))
}

/// One captured packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// 1-based position in the file.
    pub number: u64,
    pub ts_sec: u64,
    pub ts_nsec: u32,
    /// The data link type (`1` is Ethernet).
    pub link: u32,
    /// Length of the packet on the wire; `data` may be shorter if the capture was truncated.
    pub orig_len: u32,
    pub data: Vec<u8>,
    /// Interface number within the section (pcapng); 0 for classic pcap.
    pub iface: u32,
}

impl Packet {
    /// Seconds since the epoch as a float, for display and arithmetic.
    pub fn time(&self) -> f64 {
        self.ts_sec as f64 + self.ts_nsec as f64 / 1e9
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Order {
    Little,
    Big,
}

impl Order {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        match self {
            Order::Little => u16::from_le_bytes(a),
            Order::Big => u16::from_be_bytes(a),
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        match self {
            Order::Little => u32::from_le_bytes(a),
            Order::Big => u32::from_be_bytes(a),
        }
    }
}

#[derive(Clone, Debug)]
struct Interface {
    link: u32,
    /// Timestamp units per second.
    units_per_sec: u64,
    name: Option<String>,
}

/// What a capture file says about one of its interfaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub link: u32,
    pub name: Option<String>,
}

enum Format {
    Classic { order: Order, nano: bool, link: u32 },
    Ng { order: Order, ifaces: Vec<Interface> },
}

/// A streaming reader over any `Read`.
pub struct Reader<R: Read> {
    r: R,
    fmt: Format,
    number: u64,
    /// Set after an error so that the iterator ends.
    done: bool,
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, PcapError> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => {
                return if got == 0 { Ok(false) } else { bad("the file ends in the middle of a record") };
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

fn read_n<R: Read>(r: &mut R, n: usize) -> Result<Vec<u8>, PcapError> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            PcapError::Format("the file ends in the middle of a record".into())
        } else {
            e.into()
        }
    })?;
    Ok(v)
}

impl<R: Read> Reader<R> {
    pub fn new(mut r: R) -> Result<Reader<R>, PcapError> {
        let mut magic = [0u8; 4];
        if !read_exact_or_eof(&mut r, &mut magic)? {
            return bad("the file is empty");
        }
        let fmt = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => Self::classic_header(&mut r, Order::Little, false)?,
            [0xa1, 0xb2, 0xc3, 0xd4] => Self::classic_header(&mut r, Order::Big, false)?,
            [0x4d, 0x3c, 0xb2, 0xa1] => Self::classic_header(&mut r, Order::Little, true)?,
            [0xa1, 0xb2, 0x3c, 0x4d] => Self::classic_header(&mut r, Order::Big, true)?,
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                let order = Self::section_header(&mut r)?;
                Format::Ng { order, ifaces: Vec::new() }
            }
            _ => return bad("not a pcap or pcapng file (unrecognised magic number)"),
        };
        Ok(Reader { r, fmt, number: 0, done: false })
    }

    fn classic_header(r: &mut R, order: Order, nano: bool) -> Result<Format, PcapError> {
        let rest = read_n(r, 20)?;
        let (major, link) = (order.u16(&rest[0..2]), order.u32(&rest[16..20]) & 0x0fff_ffff);
        if major != 2 {
            return bad(format!("unsupported pcap version {major}"));
        }
        Ok(Format::Classic { order, nano, link })
    }

    /// Reads the rest of a section header block (the block type has been consumed); returns its byte order.
    fn section_header(r: &mut R) -> Result<Order, PcapError> {
        let head = read_n(r, 8)?; // total length, byte-order magic
        let order = match &head[4..8] {
            [0x4d, 0x3c, 0x2b, 0x1a] => Order::Little,
            [0x1a, 0x2b, 0x3c, 0x4d] => Order::Big,
            _ => return bad("pcapng section header with a bad byte-order magic"),
        };
        let total = order.u32(&head[0..4]);
        if !(28..=MAX_RECORD).contains(&total) || total % 4 != 0 {
            return bad(format!("pcapng section header with an impossible length {total}"));
        }
        let body = read_n(r, total as usize - 12)?;
        if order.u32(&body[body.len() - 4..]) != total {
            return bad("pcapng section header whose two length fields differ");
        }
        let major = order.u16(&body[0..2]);
        if major != 1 {
            return bad(format!("unsupported pcapng version {major}"));
        }
        Ok(order)
    }

    /// The interfaces declared so far (pcapng; only those seen before the current position are known).
    pub fn interfaces(&self) -> Vec<InterfaceInfo> {
        match &self.fmt {
            Format::Classic { link, .. } => vec![InterfaceInfo { link: *link, name: None }],
            Format::Ng { ifaces, .. } => ifaces.iter().map(|i| InterfaceInfo { link: i.link, name: i.name.clone() }).collect(),
        }
    }

    /// The data link type of a classic pcap file (`None` for pcapng, where each interface has its own).
    pub fn link_type(&self) -> Option<u32> {
        match &self.fmt {
            Format::Classic { link, .. } => Some(*link),
            Format::Ng { .. } => None,
        }
    }

    fn next_classic(&mut self) -> Result<Option<Packet>, PcapError> {
        let Format::Classic { order, nano, link } = self.fmt else { unreachable!() };
        let mut h = [0u8; 16];
        if !read_exact_or_eof(&mut self.r, &mut h)? {
            return Ok(None);
        }
        let (sec, frac, incl, orig) = (order.u32(&h[0..4]), order.u32(&h[4..8]), order.u32(&h[8..12]), order.u32(&h[12..16]));
        if incl > MAX_RECORD {
            return bad(format!("record {} claims {incl} captured bytes", self.number + 1));
        }
        let data = read_n(&mut self.r, incl as usize)?;
        let nsec = if nano { frac } else { frac.saturating_mul(1000) };
        self.number += 1;
        Ok(Some(Packet {
            number: self.number,
            ts_sec: sec as u64,
            ts_nsec: nsec.min(999_999_999),
            link,
            orig_len: orig,
            data,
            iface: 0,
        }))
    }

    fn next_ng(&mut self) -> Result<Option<Packet>, PcapError> {
        loop {
            let Format::Ng { order, .. } = &self.fmt else { unreachable!() };
            let order = *order;
            let mut h = [0u8; 8];
            if !read_exact_or_eof(&mut self.r, &mut h)? {
                return Ok(None);
            }
            // A new section may use the other byte order, and it is recognised by its type bytes.
            if h[0..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
                // Re-read as a section header: we already consumed 8 of its bytes (type, length).
                let mut rest = vec![0u8; 4];
                self.r.read_exact(&mut rest)?;
                let new_order = match &rest[..] {
                    [0x4d, 0x3c, 0x2b, 0x1a] => Order::Little,
                    [0x1a, 0x2b, 0x3c, 0x4d] => Order::Big,
                    _ => return bad("pcapng section header with a bad byte-order magic"),
                };
                let total = new_order.u32(&h[4..8]);
                if !(28..=MAX_RECORD).contains(&total) || total % 4 != 0 {
                    return bad(format!("pcapng section header with an impossible length {total}"));
                }
                let body = read_n(&mut self.r, total as usize - 12)?;
                if new_order.u32(&body[body.len() - 4..]) != total {
                    return bad("pcapng section header whose two length fields differ");
                }
                self.fmt = Format::Ng { order: new_order, ifaces: Vec::new() };
                continue;
            }
            let (kind, total) = (order.u32(&h[0..4]), order.u32(&h[4..8]));
            if !(12..=MAX_RECORD).contains(&total) || total % 4 != 0 {
                return bad(format!("pcapng block of type {kind} with an impossible length {total}"));
            }
            let body = read_n(&mut self.r, total as usize - 8)?;
            if order.u32(&body[body.len() - 4..]) != total {
                return bad(format!("pcapng block of type {kind} whose two length fields differ"));
            }
            let body = &body[..body.len() - 4];
            match kind {
                1 => {
                    // Interface description block.
                    if body.len() < 8 {
                        return bad("pcapng interface block too short");
                    }
                    let link = order.u16(&body[0..2]) as u32;
                    let mut units = 1_000_000u64;
                    let mut name: Option<String> = None;
                    let mut at = 8;
                    while at + 4 <= body.len() {
                        let (code, len) = (order.u16(&body[at..at + 2]), order.u16(&body[at + 2..at + 4]) as usize);
                        if code == 0 {
                            break;
                        }
                        let val = body.get(at + 4..at + 4 + len);
                        if (code == 2 || (code == 3 && name.is_none())) && val.is_some() {
                            name = val.map(|v| String::from_utf8_lossy(v).trim_end_matches('\u{0}').to_string());
                        }
                        if code == 9 {
                            if let Some(v) = val.and_then(|v| v.first()) {
                                units = if v & 0x80 == 0 {
                                    10u64.checked_pow((*v & 0x7f) as u32).unwrap_or(0)
                                } else {
                                    1u64.checked_shl((*v & 0x7f) as u32).unwrap_or(0)
                                };
                                if units == 0 {
                                    return bad("pcapng interface with an unusable timestamp resolution");
                                }
                            }
                        }
                        at += 4 + len.div_ceil(4) * 4;
                    }
                    if let Format::Ng { ifaces, .. } = &mut self.fmt {
                        ifaces.push(Interface { link, units_per_sec: units, name });
                    }
                }
                6 => {
                    // Enhanced packet block.
                    if body.len() < 20 {
                        return bad("pcapng packet block too short");
                    }
                    let iface = order.u32(&body[0..4]);
                    let ts = ((order.u32(&body[4..8]) as u64) << 32) | order.u32(&body[8..12]) as u64;
                    let (cap, orig) = (order.u32(&body[12..16]) as usize, order.u32(&body[16..20]));
                    let data = body
                        .get(20..20 + cap)
                        .ok_or_else(|| PcapError::Format("pcapng packet longer than its block".into()))?
                        .to_vec();
                    let Format::Ng { ifaces, .. } = &self.fmt else { unreachable!() };
                    let ifc = ifaces
                        .get(iface as usize)
                        .ok_or_else(|| PcapError::Format(format!("packet for the undeclared interface {iface}")))?;
                    let (sec, nsec) = (
                        ts / ifc.units_per_sec,
                        ((ts % ifc.units_per_sec) as u128 * 1_000_000_000 / ifc.units_per_sec as u128) as u32,
                    );
                    self.number += 1;
                    return Ok(Some(Packet {
                        number: self.number,
                        ts_sec: sec,
                        ts_nsec: nsec,
                        link: ifc.link,
                        orig_len: orig,
                        data,
                        iface,
                    }));
                }
                3 => {
                    // Simple packet block: no timestamp, the first interface.
                    if body.len() < 4 {
                        return bad("pcapng simple packet block too short");
                    }
                    let orig = order.u32(&body[0..4]);
                    let cap = (orig as usize).min(body.len() - 4);
                    let Format::Ng { ifaces, .. } = &self.fmt else { unreachable!() };
                    let link = ifaces
                        .first()
                        .map(|i| i.link)
                        .ok_or_else(|| PcapError::Format("simple packet before any interface".into()))?;
                    self.number += 1;
                    return Ok(Some(Packet {
                        number: self.number,
                        ts_sec: 0,
                        ts_nsec: 0,
                        link,
                        orig_len: orig,
                        data: body[4..4 + cap].to_vec(),
                        iface: 0,
                    }));
                }
                // Name resolution, statistics, custom and obsolete blocks carry no packets.
                _ => {}
            }
        }
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Packet, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let r = match self.fmt {
            Format::Classic { .. } => self.next_classic(),
            Format::Ng { .. } => self.next_ng(),
        };
        match r {
            Ok(Some(p)) => Some(Ok(p)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Recognises the same packet recorded more than once, as `pktmon` does by capturing at every layer of
/// the network stack: identical bytes seen again within a millisecond. This is a heuristic: two
/// genuinely identical packets that close together are dropped as well.
pub struct Dedup {
    recent: std::collections::HashMap<u64, f64>,
    window: f64,
    pub dropped: u64,
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new()
    }
}

impl Dedup {
    pub fn new() -> Dedup {
        Dedup { recent: std::collections::HashMap::new(), window: 0.001, dropped: 0 }
    }

    /// True if `p` is a copy of a packet seen a moment ago.
    pub fn is_duplicate(&mut self, p: &Packet) -> bool {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        p.link.hash(&mut h);
        p.data.hash(&mut h);
        let key = h.finish();
        let t = p.time();
        let dup = matches!(self.recent.get(&key), Some(t0) if (t - t0).abs() <= self.window);
        self.recent.insert(key, t);
        if self.recent.len() > 100_000 {
            let cutoff = t - self.window * 4.0;
            self.recent.retain(|_, t0| *t0 >= cutoff);
        }
        if dup {
            self.dropped += 1;
        }
        dup
    }
}

/// Writes a classic pcap file with nanosecond timestamps.
pub struct Writer<W: Write> {
    w: W,
}

impl<W: Write> Writer<W> {
    pub fn new(mut w: W, link: u32, snaplen: u32) -> io::Result<Writer<W>> {
        w.write_all(&0xa1b2_3c4du32.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&snaplen.to_le_bytes())?;
        w.write_all(&link.to_le_bytes())?;
        Ok(Writer { w })
    }

    pub fn write(&mut self, ts_sec: u64, ts_nsec: u32, orig_len: u32, data: &[u8]) -> io::Result<()> {
        self.w.write_all(&(ts_sec as u32).to_le_bytes())?;
        self.w.write_all(&ts_nsec.to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(&orig_len.to_le_bytes())?;
        self.w.write_all(data)
    }

    pub fn into_inner(self) -> W {
        self.w
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classic(order: Order, nano: bool, link: u32, packets: &[(u32, u32, &[u8], u32)]) -> Vec<u8> {
        let p16 = |v: u16| if order == Order::Little { v.to_le_bytes() } else { v.to_be_bytes() };
        let p32 = |v: u32| if order == Order::Little { v.to_le_bytes() } else { v.to_be_bytes() };
        let magic: u32 = if nano { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
        let mut out = Vec::new();
        out.extend(if order == Order::Little { magic.to_le_bytes() } else { magic.to_be_bytes() });
        out.extend(p16(2));
        out.extend(p16(4));
        out.extend(p32(0));
        out.extend(p32(0));
        out.extend(p32(65535));
        out.extend(p32(link));
        for (s, f, data, orig) in packets {
            out.extend(p32(*s));
            out.extend(p32(*f));
            out.extend(p32(data.len() as u32));
            out.extend(p32(*orig));
            out.extend(*data);
        }
        out
    }

    fn all(bytes: &[u8]) -> (Vec<Packet>, Option<String>) {
        let mut r = Reader::new(bytes).unwrap();
        let mut out = Vec::new();
        let mut err = None;
        for p in &mut r {
            match p {
                Ok(p) => out.push(p),
                Err(e) => err = Some(e.to_string()),
            }
        }
        (out, err)
    }

    #[test]
    fn classic_files_in_all_four_flavours() {
        for order in [Order::Little, Order::Big] {
            for nano in [false, true] {
                let bytes = classic(order, nano, 1, &[(1_700_000_000, 123_456, b"abc", 3), (1_700_000_001, 7, b"", 60)]);
                let (p, err) = all(&bytes);
                assert!(err.is_none());
                assert_eq!(p.len(), 2, "{order:?} nano={nano}");
                assert_eq!((p[0].ts_sec, p[0].link, p[0].data.as_slice(), p[0].number), (1_700_000_000, 1, &b"abc"[..], 1));
                assert_eq!(p[0].ts_nsec, if nano { 123_456 } else { 123_456_000 });
                assert_eq!((p[1].orig_len, p[1].data.len(), p[1].number), (60, 0, 2));
            }
        }
    }

    #[test]
    fn a_truncated_last_record_gives_the_packets_before_it_then_an_error() {
        let bytes = classic(Order::Little, false, 1, &[(1, 0, b"first", 5), (2, 0, b"second packet", 13)]);
        for cut in 1..=6 {
            let (p, err) = all(&bytes[..bytes.len() - cut]);
            assert_eq!(p.len(), 1, "cut {cut}");
            assert!(err.unwrap().contains("ends in the middle"), "cut {cut}");
        }
        // Ending exactly on a record boundary is clean.
        let (p, err) = all(&bytes[..bytes.len() - 13]);
        assert_eq!(p.len(), 1);
        assert!(err.unwrap().contains("ends in the middle"), "a record header without its data is truncated too");
        let boundary = classic(Order::Little, false, 1, &[(1, 0, b"first", 5)]);
        assert!(all(&boundary).1.is_none());
    }

    #[test]
    fn rejects_what_is_not_a_capture_file() {
        for bad in [&b""[..], b"abc", b"hello world, this is not a pcap file", &[0u8; 100][..]] {
            assert!(Reader::new(bad).is_err());
        }
        // A huge claimed record is refused before anything is allocated.
        let mut bytes = classic(Order::Little, false, 1, &[]);
        bytes.extend([0u8; 8]);
        bytes.extend(0x7fff_ffffu32.to_le_bytes());
        bytes.extend(0x7fff_ffffu32.to_le_bytes());
        let (p, err) = all(&bytes);
        assert!(p.is_empty() && err.unwrap().contains("claims"));
        // An unsupported version.
        let mut v = classic(Order::Little, false, 1, &[]);
        v[4] = 9;
        assert!(Reader::new(&v[..]).is_err());
    }

    // --- pcapng

    struct Ng {
        order: Order,
        out: Vec<u8>,
    }

    impl Ng {
        fn new(order: Order) -> Ng {
            let mut n = Ng { order, out: Vec::new() };
            let mut body = Vec::new();
            body.extend(n.p32(0x1a2b_3c4d));
            body.extend(n.p16(1));
            body.extend(n.p16(0));
            body.extend((-1i64).to_le_bytes());
            n.block(0x0a0d_0d0a, &body);
            n
        }

        fn p16(&self, v: u16) -> [u8; 2] {
            if self.order == Order::Little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        }

        fn p32(&self, v: u32) -> [u8; 4] {
            if self.order == Order::Little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        }

        fn block(&mut self, kind: u32, body: &[u8]) {
            let padded = body.len().div_ceil(4) * 4;
            let total = (padded + 12) as u32;
            self.out.extend(self.p32(kind));
            self.out.extend(self.p32(total));
            self.out.extend(body);
            self.out.extend(std::iter::repeat_n(0u8, padded - body.len()));
            self.out.extend(self.p32(total));
        }

        fn iface(&mut self, link: u16, tsresol: Option<u8>) {
            let mut body = Vec::new();
            body.extend(self.p16(link));
            body.extend(self.p16(0));
            body.extend(self.p32(65535));
            if let Some(t) = tsresol {
                body.extend(self.p16(9));
                body.extend(self.p16(1));
                body.extend([t, 0, 0, 0]);
                body.extend(self.p16(0));
                body.extend(self.p16(0));
            }
            self.block(1, &body);
        }

        fn epb(&mut self, iface: u32, ts: u64, data: &[u8], orig: u32) {
            let mut body = Vec::new();
            body.extend(self.p32(iface));
            body.extend(self.p32((ts >> 32) as u32));
            body.extend(self.p32(ts as u32));
            body.extend(self.p32(data.len() as u32));
            body.extend(self.p32(orig));
            body.extend(data);
            body.extend(std::iter::repeat_n(0u8, data.len().div_ceil(4) * 4 - data.len()));
            // A comment option, which must be skipped.
            body.extend(self.p16(1));
            body.extend(self.p16(4));
            body.extend(b"note");
            body.extend(self.p16(0));
            body.extend(self.p16(0));
            self.block(6, &body);
        }
    }

    #[test]
    fn pcapng_with_both_byte_orders_and_padding() {
        for order in [Order::Little, Order::Big] {
            let mut n = Ng::new(order);
            n.iface(1, None);
            n.epb(0, 1_700_000_000_500_000, b"x", 1);
            n.epb(0, 1_700_000_001_000_001, b"abcde", 99);
            let (p, err) = all(&n.out);
            assert!(err.is_none(), "{err:?}");
            assert_eq!(p.len(), 2);
            assert_eq!((p[0].ts_sec, p[0].ts_nsec, p[0].data.as_slice()), (1_700_000_000, 500_000_000, &b"x"[..]));
            assert_eq!(
                (p[1].ts_sec, p[1].ts_nsec, p[1].orig_len, p[1].data.as_slice()),
                (1_700_000_001, 1000, 99, &b"abcde"[..])
            );
        }
    }

    #[test]
    fn pcapng_timestamp_resolutions_and_multiple_interfaces() {
        let mut n = Ng::new(Order::Little);
        n.iface(1, Some(9)); // nanoseconds
        n.iface(101, Some(3)); // milliseconds
        n.iface(1, Some(0x80 | 10)); // units of 2^-10 seconds
        n.epb(0, 1_700_000_000_123_456_789, b"a", 1);
        n.epb(1, 1_700_000_000_250, b"b", 1);
        n.epb(2, 1024 * 5 + 512, b"c", 1);
        let (p, err) = all(&n.out);
        assert!(err.is_none(), "{err:?}");
        assert_eq!((p[0].ts_sec, p[0].ts_nsec, p[0].link, p[0].iface), (1_700_000_000, 123_456_789, 1, 0));
        assert_eq!((p[1].ts_sec, p[1].ts_nsec, p[1].link, p[1].iface), (1_700_000_000, 250_000_000, 101, 1));
        assert_eq!((p[2].ts_sec, p[2].ts_nsec, p[2].iface), (5, 500_000_000, 2));
    }

    #[test]
    fn pcapng_skips_blocks_it_does_not_know_and_follows_new_sections() {
        let mut n = Ng::new(Order::Little);
        n.iface(1, None);
        n.block(0x0000_0004, b"\x01\x00\x04\x00\x7f\x00\x00\x01"); // name resolution
        n.block(0x0000_0005, &[0u8; 24]); // interface statistics
        n.block(0x4000_0bad, b"custom"); // custom
        n.epb(0, 1_000_000, b"one", 3);
        // A second section, in the other byte order, with its own interface numbering.
        let mut second = Ng::new(Order::Big);
        second.iface(101, Some(6));
        second.epb(0, 2_000_000, b"two", 3);
        n.out.extend(second.out);
        let (p, err) = all(&n.out);
        assert!(err.is_none(), "{err:?}");
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].link, p[0].ts_sec), (1, 1));
        assert_eq!((p[1].link, p[1].ts_sec, p[1].number), (101, 2, 2));
    }

    #[test]
    fn pcapng_simple_packet_blocks() {
        let mut n = Ng::new(Order::Little);
        n.iface(1, None);
        let mut body = Vec::new();
        body.extend(10u32.to_le_bytes());
        body.extend(b"0123456789");
        n.block(3, &body);
        let (p, _) = all(&n.out);
        assert_eq!((p[0].orig_len, p[0].data.as_slice(), p[0].ts_sec), (10, &b"0123456789"[..], 0));
    }

    #[test]
    fn pcapng_damage_is_reported() {
        let mut n = Ng::new(Order::Little);
        n.iface(1, None);
        n.epb(0, 1, b"abcd", 4);
        let good = n.out.clone();
        // Every truncation gives an error or a clean end, and never a panic.
        for cut in 4..good.len() {
            let _ = Reader::new(&good[..cut]).map(|r| r.count());
        }
        // A packet for an interface that was never declared.
        let mut m = Ng::new(Order::Little);
        m.iface(1, None);
        m.epb(5, 1, b"abcd", 4);
        assert!(all(&m.out).1.unwrap().contains("undeclared interface 5"));
        // Mismatched block lengths and impossible lengths.
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(all(&bad).1.is_some());
        let mut bad2 = good.clone();
        bad2[28 + 4] = 3; // interface block length not a multiple of 4
        assert!(all(&bad2).1.is_some());
        // A nonsense timestamp resolution.
        let mut o = Ng::new(Order::Little);
        o.iface(1, Some(0x7f));
        o.epb(0, 1, b"abcd", 4);
        assert!(all(&o.out).1.is_some());
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut seed = 99u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let seeds: Vec<Vec<u8>> = vec![classic(Order::Little, false, 1, &[(1, 2, b"hello", 5), (3, 4, b"world", 5)]), {
            let mut n = Ng::new(Order::Little);
            n.iface(1, Some(9));
            n.epb(0, 5, b"payload", 7);
            n.out
        }];
        for base in seeds {
            for _ in 0..4000 {
                let mut v = base.clone();
                for _ in 0..(1 + next() % 4) {
                    let i = (next() as usize) % v.len();
                    v[i] = next() as u8;
                }
                if let Ok(r) = Reader::new(&v[..]) {
                    let _ = r.count();
                }
            }
        }
    }

    #[test]
    fn dedup_drops_copies_within_a_millisecond_only() {
        let mk = |n: u64, ns: u32, data: &[u8]| Packet {
            number: n,
            ts_sec: 10,
            ts_nsec: ns,
            link: 1,
            orig_len: data.len() as u32,
            data: data.to_vec(),
            iface: 0,
        };
        let mut d = Dedup::new();
        assert!(!d.is_duplicate(&mk(1, 0, b"same")));
        assert!(d.is_duplicate(&mk(2, 2_000, b"same")), "2 microseconds later");
        assert!(d.is_duplicate(&mk(3, 900_000, b"same")), "within the millisecond window");
        assert!(!d.is_duplicate(&mk(4, 100_000_000, b"same")), "100 ms later is a real second packet");
        assert!(!d.is_duplicate(&mk(5, 100_001_000, b"different")));
        assert_eq!(d.dropped, 2);
        // The table does not grow without bound.
        let mut d = Dedup::new();
        for i in 0..250_000u64 {
            d.is_duplicate(&Packet {
                number: i,
                ts_sec: i / 1000,
                ts_nsec: ((i % 1000) * 1_000_000) as u32,
                link: 1,
                orig_len: 8,
                data: i.to_le_bytes().to_vec(),
                iface: 0,
            });
        }
        assert!(d.recent.len() < 150_000);
    }

    #[test]
    fn interface_names_are_read_from_pcapng_options() {
        let mut n = Ng::new(Order::Little);
        let mut body = Vec::new();
        body.extend(n.p16(1));
        body.extend(n.p16(0));
        body.extend(n.p32(65535));
        body.extend(n.p16(2)); // if_name
        body.extend(n.p16(5));
        body.extend(b"eth0\0\0\0\0");
        body.extend(n.p16(0));
        body.extend(n.p16(0));
        n.block(1, &body);
        let mut r = Reader::new(&n.out[..]).unwrap();
        let _ = r.by_ref().count();
        assert_eq!(r.interfaces(), vec![InterfaceInfo { link: 1, name: Some("eth0".into()) }]);
    }

    #[test]
    fn writer_round_trips() {
        let mut w = Writer::new(Vec::new(), 1, 65535).unwrap();
        w.write(1_700_000_000, 999_999_999, 100, b"abc").unwrap();
        w.write(1_700_000_001, 0, 4, b"wxyz").unwrap();
        let bytes = w.into_inner();
        let (p, err) = all(&bytes);
        assert!(err.is_none());
        assert_eq!((p[0].ts_sec, p[0].ts_nsec, p[0].orig_len), (1_700_000_000, 999_999_999, 100));
        assert_eq!(p[1].data, b"wxyz");
    }
}
