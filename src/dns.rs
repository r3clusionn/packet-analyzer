//! DNS messages (RFC 1035 and the common extensions): header, questions and resource records,
//! with name compression.
//!
//! A message can lie in many ways: a pointer to itself, a chain of pointers, a label that runs past
//! the end, counts far larger than the data. Every name read is bounded (at most 255 bytes of name
//! and 64 pointer jumps) and every read is checked against the message length.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(String),
    Cname(String),
    Ptr(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// EDNS(0) pseudo record: the requestor's UDP payload size is carried in the class field.
    Opt {
        udp_size: u16,
        ext_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        options_len: usize,
    },
    Other {
        len: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Dns {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

pub fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        47 => "NSEC".into(),
        48 => "DNSKEY".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        252 => "AXFR".into(),
        255 => "ANY".into(),
        257 => "CAA".into(),
        n => format!("TYPE{n}"),
    }
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "RCODE?",
    }
}

const MAX_NAME: usize = 255;
const MAX_JUMPS: usize = 64;

/// Reads a possibly compressed name at `pos`; returns it and the position after its first
/// encoding (after the first pointer, if there is one).
pub fn read_name(msg: &[u8], pos: usize) -> Result<(String, usize), String> {
    let mut name = String::new();
    let mut at = pos;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(at).ok_or("a name runs past the end of the message")? as usize;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    at += 1;
                    break;
                }
                let label = msg.get(at + 1..at + 1 + len).ok_or("a label runs past the end of the message")?;
                if name.len() + len + 1 > MAX_NAME {
                    return Err("a name is longer than 255 bytes".into());
                }
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    match b {
                        b'.' | b'\\' => {
                            name.push('\\');
                            name.push(b as char);
                        }
                        0x21..=0x7e => name.push(b as char),
                        _ => name.push_str(&format!("\\{b:03}")),
                    }
                }
                at += 1 + len;
            }
            0xc0 => {
                let second = *msg.get(at + 1).ok_or("a compression pointer is cut off")? as usize;
                let target = ((len & 0x3f) << 8) | second;
                if end.is_none() {
                    end = Some(at + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err("too many compression pointers (a loop?)".into());
                }
                if target >= msg.len() {
                    return Err("a compression pointer points outside the message".into());
                }
                at = target;
            }
            _ => return Err("a label with a reserved length prefix".into()),
        }
    }
    if name.is_empty() {
        name.push('.');
    }
    Ok((name, end.unwrap_or(at)))
}

struct Reader<'a> {
    msg: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.msg.get(self.at..self.at + 2).ok_or("the message ends inside a field")?;
        self.at += 2;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.msg.get(self.at..self.at + 4).ok_or("the message ends inside a field")?;
        self.at += 4;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn name(&mut self) -> Result<String, String> {
        let (n, next) = read_name(self.msg, self.at)?;
        self.at = next;
        Ok(n)
    }
}

fn rdata(msg: &[u8], start: usize, len: usize, rtype: u16, class: u16, ttl: u32) -> Result<RData, String> {
    let data = msg.get(start..start + len).ok_or("record data runs past the end of the message")?;
    let name = |at: usize| read_name(msg, at);
    Ok(match rtype {
        1 if len == 4 => RData::A(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
        28 if len == 16 => RData::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap())),
        2 => RData::Ns(name(start)?.0),
        5 => RData::Cname(name(start)?.0),
        12 => RData::Ptr(name(start)?.0),
        15 if len >= 3 => RData::Mx { preference: u16::from_be_bytes([data[0], data[1]]), exchange: name(start + 2)?.0 },
        16 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < data.len() {
                let l = data[i] as usize;
                let s = data.get(i + 1..i + 1 + l).ok_or("a TXT string runs past its record")?;
                parts.push(String::from_utf8_lossy(s).into_owned());
                i += 1 + l;
            }
            RData::Txt(parts)
        }
        6 => {
            let (mname, p) = name(start)?;
            let (rname, p) = name(p)?;
            let nums = msg.get(p..p + 20).ok_or("an SOA record is too short")?;
            let n = |i: usize| u32::from_be_bytes(nums[i..i + 4].try_into().unwrap());
            RData::Soa { mname, rname, serial: n(0), refresh: n(4), retry: n(8), expire: n(12), minimum: n(16) }
        }
        33 if len >= 7 => RData::Srv {
            priority: u16::from_be_bytes([data[0], data[1]]),
            weight: u16::from_be_bytes([data[2], data[3]]),
            port: u16::from_be_bytes([data[4], data[5]]),
            target: name(start + 6)?.0,
        },
        41 => RData::Opt {
            udp_size: class,
            ext_rcode: (ttl >> 24) as u8,
            version: (ttl >> 16) as u8,
            dnssec_ok: ttl & 0x8000 != 0,
            options_len: len,
        },
        _ => RData::Other { len },
    })
}

fn records(r: &mut Reader, count: u16, out: &mut Vec<Record>, section: &str, notes: &mut Vec<String>) -> bool {
    for _ in 0..count {
        let item = (|| -> Result<Record, String> {
            let name = r.name()?;
            let rtype = r.u16()?;
            let class = r.u16()?;
            let ttl = r.u32()?;
            let len = r.u16()? as usize;
            let data = rdata(r.msg, r.at, len, rtype, class, ttl)?;
            r.at += len;
            Ok(Record { name, rtype, class, ttl, data })
        })();
        match item {
            Ok(rec) => out.push(rec),
            Err(e) => {
                notes.push(format!("DNS {section} section: {e}"));
                return false;
            }
        }
    }
    true
}

/// Parses a DNS message. Problems after the header end parsing early and are returned as notes
/// along with what was read; only an unusable header is an error.
pub fn parse(msg: &[u8]) -> Result<(Dns, Vec<String>), String> {
    if msg.len() < 12 {
        return Err(format!("{} bytes is shorter than a DNS header", msg.len()));
    }
    let mut r = Reader { msg, at: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let (qd, an, ns, ar) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    // A real message needs at least 5 bytes per question and 11 per record.
    let min_needed = qd as usize * 5 + (an as usize + ns as usize + ar as usize) * 11;
    if min_needed > msg.len() * 4 + 64 {
        return Err(format!(
            "the header claims {} entries in a {}-byte message",
            qd as usize + an as usize + ns as usize + ar as usize,
            msg.len()
        ));
    }
    let mut dns = Dns {
        id,
        response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0xf) as u8,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        rcode: (flags & 0xf) as u8,
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let mut notes = Vec::new();
    for _ in 0..qd {
        let q = (|| -> Result<Question, String> { Ok(Question { name: r.name()?, qtype: r.u16()?, qclass: r.u16()? }) })();
        match q {
            Ok(q) => dns.questions.push(q),
            Err(e) => {
                notes.push(format!("DNS question section: {e}"));
                return Ok((dns, notes));
            }
        }
    }
    if records(&mut r, an, &mut dns.answers, "answer", &mut notes)
        && records(&mut r, ns, &mut dns.authorities, "authority", &mut notes)
        && records(&mut r, ar, &mut dns.additionals, "additional", &mut notes)
        && r.at < msg.len()
    {
        notes.push(format!("{} bytes follow the last DNS record", msg.len() - r.at));
    }
    if dns.truncated && !notes.is_empty() {
        notes.push("the TC (truncated) bit is set: the answer did not fit and the client should retry over TCP".into());
    }
    Ok((dns, notes))
}

/// The record data as a short text, for summaries.
pub fn rdata_text(d: &RData) -> String {
    match d {
        RData::A(a) => a.to_string(),
        RData::Aaaa(a) => a.to_string(),
        RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.clone(),
        RData::Mx { preference, exchange } => format!("{preference} {exchange}"),
        RData::Txt(t) => t.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(" "),
        RData::Soa { mname, rname, serial, .. } => format!("{mname} {rname} {serial}"),
        RData::Srv { priority, weight, port, target } => format!("{priority} {weight} {port} {target}"),
        RData::Opt { udp_size, .. } => format!("EDNS udp={udp_size}"),
        RData::Other { len } => format!("({len} bytes)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a name from labels.
    fn name(labels: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for l in labels {
            v.push(l.len() as u8);
            v.extend(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn header(id: u16, flags: u16, counts: [u16; 4]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(id.to_be_bytes());
        v.extend(flags.to_be_bytes());
        for c in counts {
            v.extend(c.to_be_bytes());
        }
        v
    }

    fn rr(name_bytes: &[u8], rtype: u16, class: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut v = name_bytes.to_vec();
        v.extend(rtype.to_be_bytes());
        v.extend(class.to_be_bytes());
        v.extend(ttl.to_be_bytes());
        v.extend((data.len() as u16).to_be_bytes());
        v.extend(data);
        v
    }

    #[test]
    fn a_query() {
        let mut m = header(0x1234, 0x0100, [1, 0, 0, 0]);
        m.extend(name(&["www", "example", "com"]));
        m.extend([0, 1, 0, 1]);
        let (d, notes) = parse(&m).unwrap();
        assert!(notes.is_empty());
        assert!(!d.response && d.recursion_desired && d.id == 0x1234);
        assert_eq!(d.questions, vec![Question { name: "www.example.com".into(), qtype: 1, qclass: 1 }]);
    }

    #[test]
    fn a_response_with_compression() {
        let mut m = header(7, 0x8180, [1, 3, 0, 0]);
        m.extend(name(&["example", "com"])); // at offset 12
        m.extend([0, 1, 0, 1]);
        m.extend(rr(&[0xc0, 12], 5, 1, 300, &{
            let mut v = vec![3];
            v.extend(b"www");
            v.extend([0xc0, 12]); // www + pointer to example.com
            v
        }));
        m.extend(rr(&[0xc0, 12], 1, 1, 60, &[93, 184, 216, 34]));
        m.extend(rr(&[0xc0, 12], 28, 1, 60, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        let (d, notes) = parse(&m).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert!(d.response && d.recursion_available && d.rcode == 0);
        assert_eq!(d.answers[0].data, RData::Cname("www.example.com".into()));
        assert_eq!(d.answers[1].data, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(rdata_text(&d.answers[2].data), "2001:db8::1");
        assert_eq!((d.answers[1].ttl, d.answers[1].name.as_str()), (60, "example.com"));
    }

    #[test]
    fn mx_txt_soa_srv_ptr_ns_and_opt() {
        let mut m = header(1, 0x8400, [0, 6, 0, 1]);
        let mx = {
            let mut v = vec![0, 10];
            v.extend(name(&["mail", "example", "org"]));
            v
        };
        m.extend(rr(&name(&["example", "org"]), 15, 1, 3600, &mx));
        m.extend(rr(&name(&["example", "org"]), 16, 1, 60, &[5, b'h', b'e', b'l', b'l', b'o', 3, b'a', b'b', b'c']));
        let soa = {
            let mut v = name(&["ns1", "example", "org"]);
            v.extend(name(&["admin", "example", "org"]));
            for n in [2024u32, 7200, 900, 1_209_600, 300] {
                v.extend(n.to_be_bytes());
            }
            v
        };
        m.extend(rr(&name(&["example", "org"]), 6, 1, 60, &soa));
        let srv = {
            let mut v = vec![0, 5, 0, 10, 0x1f, 0x90];
            v.extend(name(&["srv", "example", "org"]));
            v
        };
        m.extend(rr(&name(&["_http", "_tcp", "example", "org"]), 33, 1, 60, &srv));
        m.extend(rr(&name(&["1", "2", "0", "192", "in-addr", "arpa"]), 12, 1, 60, &name(&["host", "example", "org"])));
        m.extend(rr(&name(&["example", "org"]), 2, 1, 60, &name(&["ns1", "example", "org"])));
        m.extend(rr(&[0], 41, 4096, 0x0000_8000, &[]));
        let (d, notes) = parse(&m).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert!(d.authoritative);
        assert_eq!(d.answers[0].data, RData::Mx { preference: 10, exchange: "mail.example.org".into() });
        assert_eq!(d.answers[1].data, RData::Txt(vec!["hello".into(), "abc".into()]));
        let RData::Soa { serial, minimum, rname, .. } = &d.answers[2].data else { panic!() };
        assert_eq!((*serial, *minimum, rname.as_str()), (2024, 300, "admin.example.org"));
        assert_eq!(d.answers[3].data, RData::Srv { priority: 5, weight: 10, port: 8080, target: "srv.example.org".into() });
        assert_eq!(d.answers[4].name, "1.2.0.192.in-addr.arpa");
        assert_eq!(d.answers[4].data, RData::Ptr("host.example.org".into()));
        assert_eq!(d.answers[5].data, RData::Ns("ns1.example.org".into()));
        assert_eq!(
            d.additionals[0].data,
            RData::Opt { udp_size: 4096, ext_rcode: 0, version: 0, dnssec_ok: true, options_len: 0 }
        );
        assert_eq!(d.additionals[0].name, ".");
    }

    #[test]
    fn hostile_names_are_refused() {
        // A pointer to itself.
        let mut m = header(1, 0, [1, 0, 0, 0]);
        m.extend([0xc0, 12, 0, 1, 0, 1]);
        let (d, notes) = parse(&m).unwrap();
        assert!(d.questions.is_empty() && notes[0].contains("too many compression pointers"), "{notes:?}");
        // Two pointers pointing at each other.
        let mut m = header(1, 0, [1, 0, 0, 0]);
        m.extend([0xc0, 14, 0xc0, 12, 0, 1, 0, 1]);
        assert!(parse(&m).unwrap().1[0].contains("pointers"));
        // A pointer past the end.
        let mut m = header(1, 0, [1, 0, 0, 0]);
        m.extend([0xc3, 0xff, 0, 1, 0, 1]);
        assert!(parse(&m).unwrap().1[0].contains("outside the message"));
        // A label longer than the message.
        let mut m = header(1, 0, [1, 0, 0, 0]);
        m.extend([60, b'a', b'b']);
        assert!(parse(&m).unwrap().1[0].contains("label runs past"));
        // A name longer than 255 bytes, built from 63-byte labels.
        let mut m = header(1, 0, [1, 0, 0, 0]);
        for _ in 0..5 {
            m.push(63);
            m.extend([b'x'; 63]);
        }
        m.extend([0, 0, 1, 0, 1]);
        assert!(parse(&m).unwrap().1[0].contains("longer than 255"));
        // Reserved label prefixes (0x40 and 0x80).
        for p in [0x40u8, 0x80] {
            let mut m = header(1, 0, [1, 0, 0, 0]);
            m.extend([p, 1, 2, 3, 0, 0, 1, 0, 1]);
            assert!(parse(&m).unwrap().1[0].contains("reserved"), "{p:#x}");
        }
    }

    #[test]
    fn counts_larger_than_the_data_are_handled() {
        let m = header(1, 0, [60000, 60000, 60000, 60000]);
        assert!(parse(&m).is_err());
        let mut m = header(1, 0x8000, [0, 5, 0, 0]);
        m.extend(rr(&name(&["a"]), 1, 1, 1, &[1, 2, 3, 4]));
        let (d, notes) = parse(&m).unwrap();
        assert_eq!(d.answers.len(), 1);
        assert!(notes[0].contains("answer section"));
        assert!(parse(&[0u8; 11]).is_err());
    }

    #[test]
    fn labels_with_special_bytes_are_escaped() {
        let mut m = header(1, 0, [1, 0, 0, 0]);
        m.extend([4, b'a', b'.', b'b', 0x01, 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        let (d, _) = parse(&m).unwrap();
        assert_eq!(d.questions[0].name, "a\\.b\\001.com");
    }

    #[test]
    fn truncated_messages_keep_what_they_have() {
        let mut m = header(9, 0x8380, [1, 2, 0, 0]);
        m.extend(name(&["example", "com"]));
        m.extend([0, 1, 0, 1]);
        m.extend(rr(&[0xc0, 12], 1, 1, 60, &[1, 2, 3, 4]));
        m.extend(rr(&[0xc0, 12], 1, 1, 60, &[5, 6, 7, 8]));
        for cut in 0..m.len() {
            let r = parse(&m[..cut]);
            if cut >= 12 {
                assert!(r.is_ok(), "cut {cut}");
            }
        }
        let (d, notes) = parse(&m[..m.len() - 3]).unwrap();
        assert_eq!(d.answers.len(), 1);
        assert!(d.truncated && notes.iter().any(|n| n.contains("TC")), "{notes:?}");
    }

    #[test]
    fn random_messages_never_panic() {
        let mut seed = 5u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut base = header(1, 0x8180, [1, 2, 1, 1]);
        base.extend(name(&["example", "com"]));
        base.extend([0, 1, 0, 1]);
        base.extend(rr(&[0xc0, 12], 1, 1, 60, &[1, 2, 3, 4]));
        base.extend(rr(&[0xc0, 12], 15, 1, 60, &[0, 5, 0xc0, 12]));
        base.extend(rr(&[0xc0, 12], 16, 1, 60, &[3, b'a', b'b', b'c']));
        base.extend(rr(&[0], 41, 512, 0, &[]));
        for _ in 0..30_000 {
            let mut v = base.clone();
            for _ in 0..(1 + next() % 5) {
                let i = (next() as usize) % v.len();
                v[i] = next() as u8;
            }
            if next() % 4 == 0 {
                v.truncate((next() as usize) % v.len());
            }
            let _ = parse(&v);
        }
    }

    #[test]
    fn type_names() {
        assert_eq!(type_name(1), "A");
        assert_eq!(type_name(28), "AAAA");
        assert_eq!(type_name(65), "HTTPS");
        assert_eq!(type_name(999), "TYPE999");
        assert_eq!(rcode_name(3), "NXDOMAIN");
    }
}
