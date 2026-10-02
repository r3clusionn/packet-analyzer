//! Application protocols recognised from a TCP or UDP payload: HTTP/1.x, TLS and DHCP.
//!
//! They are found by looking at the bytes, not at port numbers, and only claimed when the start of
//! the payload is clearly that protocol. Text that merely happens to begin like HTTP is not.

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::decode::Mac;

// ---------------------------------------------------------------------------------- HTTP

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Http {
    pub is_request: bool,
    pub method: Option<String>,
    pub target: Option<String>,
    pub version: String,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    /// Whether the blank line that ends the headers was in this payload.
    pub headers_complete: bool,
}

impl Http {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

const METHODS: &[&str] = &[
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "M-SEARCH",
    "NOTIFY",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "REPORT",
    "PURGE",
];

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub fn parse_http(payload: &[u8]) -> Option<Http> {
    // The start line must be complete and printable: a method or a version, then spaces.
    let line_end = payload.windows(2).position(|w| w == b"\r\n")?;
    if line_end > 8192 {
        return None;
    }
    let first = std::str::from_utf8(&payload[..line_end]).ok()?;
    if first.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let (mut method, mut target, mut status, mut reason) = (None, None, None, None);
    let version;
    let is_request;
    if let Some(rest) = first.strip_prefix("HTTP/") {
        let (v, tail) = rest.split_once(' ')?;
        if !(v.len() == 3 && v.as_bytes()[0].is_ascii_digit() && v.as_bytes()[1] == b'.' && v.as_bytes()[2].is_ascii_digit()) {
            return None;
        }
        let (code, why) = tail.split_once(' ').unwrap_or((tail, ""));
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        version = format!("HTTP/{v}");
        status = code.parse::<u16>().ok();
        reason = Some(why.to_string());
        is_request = false;
    } else {
        let mut parts = first.splitn(3, ' ');
        let (m, t, v) = (parts.next()?, parts.next()?, parts.next()?);
        if !METHODS.contains(&m) || !is_token(m) || t.is_empty() || t.contains(' ') {
            return None;
        }
        let ok = v.strip_prefix("HTTP/").is_some_and(|n| {
            n.len() == 3 && n.as_bytes()[0].is_ascii_digit() && n.as_bytes()[1] == b'.' && n.as_bytes()[2].is_ascii_digit()
        });
        if !ok {
            return None;
        }
        method = Some(m.to_string());
        target = Some(t.to_string());
        version = v.to_string();
        is_request = true;
    }
    let mut headers = Vec::new();
    let mut complete = false;
    let mut at = line_end + 2;
    while at < payload.len() {
        let Some(rel) = payload[at..].windows(2).position(|w| w == b"\r\n") else { break };
        let line = &payload[at..at + rel];
        at += rel + 2;
        if line.is_empty() {
            complete = true;
            break;
        }
        if headers.len() >= 64 {
            break;
        }
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let name = String::from_utf8_lossy(&line[..colon]).into_owned();
            if is_token(&name) {
                headers.push((name, String::from_utf8_lossy(&line[colon + 1..]).trim().to_string()));
            }
        }
    }
    Some(Http { is_request, method, target, version, status, reason, headers, headers_complete: complete })
}

// ---------------------------------------------------------------------------------- TLS

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Handshake {
    ClientHello {
        version: u16,
        session_id_len: u8,
        cipher_suites: Vec<u16>,
        sni: Option<String>,
        alpn: Vec<String>,
        supported_versions: Vec<u16>,
        extensions: Vec<u16>,
    },
    ServerHello {
        version: u16,
        cipher_suite: u16,
        selected_version: Option<u16>,
        extensions: Vec<u16>,
    },
    /// Any other handshake message, or a hello that did not fit in the captured segment.
    Other {
        kind: u8,
        length: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TlsRecord {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
    pub handshake: Option<Handshake>,
    pub alert: Option<(u8, u8)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tls {
    pub records: Vec<TlsRecord>,
}

pub fn tls_version_name(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        n => format!("{n:#06x}"),
    }
}

pub fn handshake_name(kind: u8) -> &'static str {
    match kind {
        0 => "HelloRequest",
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Handshake",
    }
}

/// GREASE values (RFC 8701) are placeholders sent to keep implementations honest; they are not shown.
fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = b;
        Some(a)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u24(&mut self) -> Option<u32> {
        let b = self.take(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

fn parse_extensions(mut ext: Cur, client: bool, hello: &mut (Option<String>, Vec<String>, Vec<u16>, Vec<u16>)) {
    while let (Some(t), Some(len)) = (ext.u16(), ext.u16()) {
        let Some(data) = ext.take(len as usize) else { break };
        if !is_grease(t) {
            hello.3.push(t);
        }
        let mut d = Cur(data);
        match t {
            // server_name
            0 if client => {
                let Some(list_len) = d.u16() else { continue };
                let Some(list) = d.take(list_len as usize) else { continue };
                let mut l = Cur(list);
                while let (Some(kind), Some(n)) = (l.u8(), l.u16()) {
                    let Some(name) = l.take(n as usize) else { break };
                    if kind == 0 && hello.0.is_none() {
                        hello.0 = Some(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            // application_layer_protocol_negotiation
            16 => {
                let Some(list_len) = d.u16() else { continue };
                let Some(list) = d.take(list_len as usize) else { continue };
                let mut l = Cur(list);
                while let Some(n) = l.u8() {
                    let Some(p) = l.take(n as usize) else { break };
                    hello.1.push(String::from_utf8_lossy(p).into_owned());
                }
            }
            // supported_versions
            43 => {
                if client {
                    let Some(n) = d.u8() else { continue };
                    let Some(list) = d.take(n as usize) else { continue };
                    let mut l = Cur(list);
                    while let Some(v) = l.u16() {
                        if !is_grease(v) {
                            hello.2.push(v);
                        }
                    }
                } else if let Some(v) = d.u16() {
                    hello.2.push(v);
                }
            }
            _ => {}
        }
    }
}

fn parse_handshake(body: &[u8], available: bool) -> Option<Handshake> {
    let mut c = Cur(body);
    let kind = c.u8()?;
    let length = c.u24()?;
    let msg = match c.take(length as usize) {
        Some(m) if available => m,
        _ => return Some(Handshake::Other { kind, length }),
    };
    let mut m = Cur(msg);
    match kind {
        1 => {
            let version = m.u16()?;
            m.take(32)?;
            let sid = m.u8()?;
            m.take(sid as usize)?;
            let cs_len = m.u16()? as usize;
            let cs = m.take(cs_len)?;
            let comp = m.u8()?;
            m.take(comp as usize)?;
            let cipher_suites: Vec<u16> =
                (0..cs.len() / 2).map(|i| u16::from_be_bytes([cs[2 * i], cs[2 * i + 1]])).filter(|v| !is_grease(*v)).collect();
            let mut hello = (None, Vec::new(), Vec::new(), Vec::new());
            if let Some(el) = m.u16() {
                if let Some(ext) = m.take(el as usize) {
                    parse_extensions(Cur(ext), true, &mut hello);
                }
            }
            Some(Handshake::ClientHello {
                version,
                session_id_len: sid,
                cipher_suites,
                sni: hello.0,
                alpn: hello.1,
                supported_versions: hello.2,
                extensions: hello.3,
            })
        }
        2 => {
            let version = m.u16()?;
            m.take(32)?;
            let sid = m.u8()?;
            m.take(sid as usize)?;
            let cipher_suite = m.u16()?;
            m.u8()?;
            let mut hello = (None, Vec::new(), Vec::new(), Vec::new());
            if let Some(el) = m.u16() {
                if let Some(ext) = m.take(el as usize) {
                    parse_extensions(Cur(ext), false, &mut hello);
                }
            }
            Some(Handshake::ServerHello {
                version,
                cipher_suite,
                selected_version: hello.2.first().copied(),
                extensions: hello.3,
            })
        }
        _ => Some(Handshake::Other { kind, length }),
    }
}

/// Recognises TLS records at the start of a TCP payload.
pub fn parse_tls(payload: &[u8]) -> Option<Tls> {
    let mut records = Vec::new();
    let mut at = 0;
    while at + 5 <= payload.len() {
        let (content_type, major, minor) = (payload[at], payload[at + 1], payload[at + 2]);
        let length = u16::from_be_bytes([payload[at + 3], payload[at + 4]]);
        let plausible =
            (20..=23).contains(&content_type) && major == 3 && minor <= 4 && length > 0 && length as usize <= 16384 + 2048;
        if !plausible {
            break;
        }
        let version = u16::from_be_bytes([major, minor]);
        let body_start = at + 5;
        let body_end = (body_start + length as usize).min(payload.len());
        let body = &payload[body_start..body_end];
        let complete = body_start + length as usize <= payload.len();
        let (mut handshake, mut alert) = (None, None);
        match content_type {
            22 => handshake = parse_handshake(body, complete),
            21 if body.len() >= 2 => alert = Some((body[0], body[1])),
            _ => {}
        }
        records.push(TlsRecord { content_type, version, length, handshake, alert });
        if !complete {
            break;
        }
        at = body_end;
    }
    // The first record must be present, and a lone ApplicationData-looking header at the very
    // start of an arbitrary payload is too weak to claim.
    let first = records.first()?;
    if records.len() == 1 && first.content_type == 23 && first.length < 16 {
        return None;
    }
    Some(Tls { records })
}

// ---------------------------------------------------------------------------------- DHCP

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Dhcp {
    pub op: u8,
    pub xid: u32,
    pub client_ip: Ipv4Addr,
    pub your_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub client_mac: Option<Mac>,
    pub message_type: Option<u8>,
    pub hostname: Option<String>,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub lease_secs: Option<u32>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
}

pub fn dhcp_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "message",
    }
}

fn ip_at(b: &[u8], i: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[i], b[i + 1], b[i + 2], b[i + 3])
}

pub fn parse_dhcp(p: &[u8]) -> Option<Dhcp> {
    if p.len() < 240 || p[236..240] != [0x63, 0x82, 0x53, 0x63] || !(p[0] == 1 || p[0] == 2) {
        return None;
    }
    let hlen = p[2] as usize;
    let mut d = Dhcp {
        op: p[0],
        xid: u32::from_be_bytes(p[4..8].try_into().ok()?),
        client_ip: ip_at(p, 12),
        your_ip: ip_at(p, 16),
        server_ip: ip_at(p, 20),
        gateway_ip: ip_at(p, 24),
        client_mac: (p[1] == 1 && hlen == 6).then(|| Mac(p[28..34].try_into().unwrap())),
        message_type: None,
        hostname: None,
        requested_ip: None,
        server_id: None,
        lease_secs: None,
        subnet_mask: None,
        routers: Vec::new(),
        dns_servers: Vec::new(),
    };
    let mut i = 240;
    while i < p.len() {
        let code = p[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *p.get(i + 1)? as usize;
        let v = p.get(i + 2..i + 2 + len)?;
        match (code, len) {
            (53, 1) => d.message_type = Some(v[0]),
            (12, _) => d.hostname = Some(String::from_utf8_lossy(v).into_owned()),
            (50, 4) => d.requested_ip = Some(ip_at(v, 0)),
            (54, 4) => d.server_id = Some(ip_at(v, 0)),
            (51, 4) => d.lease_secs = Some(u32::from_be_bytes(v.try_into().ok()?)),
            (1, 4) => d.subnet_mask = Some(ip_at(v, 0)),
            (3, n) if n % 4 == 0 => d.routers = v.chunks(4).map(|c| ip_at(c, 0)).collect(),
            (6, n) if n % 4 == 0 => d.dns_servers = v.chunks(4).map(|c| ip_at(c, 0)).collect(),
            _ => {}
        }
        i += 2 + len;
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_requests() {
        let p = b"GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1.0\r\nAccept: */*\r\n\r\nbody";
        let h = parse_http(p).unwrap();
        assert!(h.is_request && h.headers_complete);
        assert_eq!(
            (h.method.as_deref(), h.target.as_deref(), h.version.as_str()),
            (Some("GET"), Some("/index.html?x=1"), "HTTP/1.1")
        );
        assert_eq!(h.header("host"), Some("example.com"));
        assert_eq!(h.headers.len(), 3);
        // Headers cut off by the end of the segment.
        let h = parse_http(b"POST /a HTTP/1.0\r\nContent-Length: 5\r\nX-Part").unwrap();
        assert!(!h.headers_complete && h.headers.len() == 1);
    }

    #[test]
    fn http_responses() {
        let h = parse_http(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\n").unwrap();
        assert!(!h.is_request);
        assert_eq!((h.status, h.reason.as_deref()), (Some(404), Some("Not Found")));
        assert_eq!(h.header("Content-Length"), Some("12"));
        let h = parse_http(b"HTTP/1.0 200\r\n\r\n").unwrap();
        assert_eq!((h.status, h.reason.as_deref()), (Some(200), Some("")));
    }

    #[test]
    fn things_that_only_look_like_http_are_not_claimed() {
        for p in [
            &b"GET / HTTP/1.1"[..],               // no CRLF
            b"GET\r\n",                           // no target
            b"FOO / HTTP/1.1\r\n",                // not a method
            b"GET / HTTP/9.1\r\nHost: x\r\n\r\n", // 9.1 is shaped like a version but this is two digits; "9.1" passes the shape test
            b"GET /a b HTTP/1.1\r\n\r\n",         // a space in the target
            b"HTTP/1.1 20 OK\r\n\r\n",            // two-digit status
            b"HTTP/1.1 abc OK\r\n\r\n",
            b"GET / HTTP/1.1\x01\r\n\r\n", // control byte
            b"\x16\x03\x01\x00\x05hello",
            b"",
            b"just some text\r\nwith lines\r\n",
        ] {
            let r = parse_http(p);
            // The "9.1" case is syntactically valid; every other input must be refused.
            if p.starts_with(b"GET / HTTP/9.1") {
                assert!(r.is_some());
            } else {
                assert!(r.is_none(), "{:?}", String::from_utf8_lossy(p));
            }
        }
    }

    #[test]
    fn an_endless_first_line_is_not_http() {
        let mut p = b"GET /".to_vec();
        p.extend(std::iter::repeat_n(b'a', 9000));
        p.extend(b" HTTP/1.1\r\n\r\n");
        assert!(parse_http(&p).is_none());
        let mut ok = b"GET /".to_vec();
        ok.extend(std::iter::repeat_n(b'a', 4000));
        ok.extend(b" HTTP/1.1\r\n\r\n");
        assert!(parse_http(&ok).is_some());
    }

    #[test]
    fn ssdp_over_http_syntax() {
        let h =
            parse_http(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n")
                .unwrap();
        assert_eq!(h.method.as_deref(), Some("M-SEARCH"));
        assert_eq!(h.header("st"), Some("ssdp:all"));
    }

    // ---- TLS

    fn client_hello(sni: &str, with_grease: bool) -> Vec<u8> {
        let mut ext = Vec::new();
        let mut push = |t: u16, d: &[u8]| {
            ext.extend(t.to_be_bytes());
            ext.extend((d.len() as u16).to_be_bytes());
            ext.extend(d);
        };
        if with_grease {
            push(0x0a0a, &[]);
        }
        let mut sni_data = Vec::new();
        sni_data.extend(((sni.len() + 3) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend((sni.len() as u16).to_be_bytes());
        sni_data.extend(sni.as_bytes());
        push(0, &sni_data);
        push(16, &[0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']);
        push(43, &[6, 0x2a, 0x2a, 0x03, 0x04, 0x03, 0x03]);
        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]);
        body.push(0); // empty session id
        body.extend([0, 6, 0x0a, 0x0a, 0x13, 0x01, 0xc0, 0x2f]);
        body.extend([1, 0]);
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(&ext);
        let mut hs = vec![1];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(&body);
        let mut rec = vec![22, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(&hs);
        rec
    }

    #[test]
    fn client_hello_with_sni_alpn_and_versions() {
        let t = parse_tls(&client_hello("example.com", true)).unwrap();
        let Some(Handshake::ClientHello { version, cipher_suites, sni, alpn, supported_versions, extensions, .. }) =
            &t.records[0].handshake
        else {
            panic!("{:?}", t.records[0])
        };
        assert_eq!((*version, sni.as_deref()), (0x0303, Some("example.com")));
        assert_eq!(cipher_suites, &vec![0x1301, 0xc02f], "GREASE is dropped");
        assert_eq!(alpn, &vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(supported_versions, &vec![0x0304, 0x0303]);
        assert_eq!(extensions, &vec![0, 16, 43]);
        assert_eq!((t.records[0].content_type, t.records[0].version), (22, 0x0301));
    }

    #[test]
    fn server_hello_picks_the_version_from_the_extension() {
        let mut body = vec![0x03, 0x03];
        body.extend([9u8; 32]);
        body.push(0);
        body.extend([0x13, 0x01, 0]);
        let ext = [0, 43, 0, 2, 0x03, 0x04];
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(ext);
        let mut hs = vec![2];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(&body);
        let mut rec = vec![22, 3, 3];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(&hs);
        // Followed by a ChangeCipherSpec and some application data in the same segment.
        rec.extend([20, 3, 3, 0, 1, 1]);
        rec.extend([23, 3, 3, 0, 20]);
        rec.extend([0u8; 20]);
        let t = parse_tls(&rec).unwrap();
        assert_eq!(t.records.len(), 3);
        let Some(Handshake::ServerHello { cipher_suite, selected_version, .. }) = &t.records[0].handshake else { panic!() };
        assert_eq!((*cipher_suite, *selected_version), (0x1301, Some(0x0304)));
        assert_eq!(t.records[1].content_type, 20);
        assert_eq!((t.records[2].content_type, t.records[2].length), (23, 20));
    }

    #[test]
    fn a_hello_cut_by_the_segment_is_reported_as_partial() {
        let full = client_hello("example.com", false);
        let t = parse_tls(&full[..full.len() - 10]).unwrap();
        assert!(matches!(t.records[0].handshake, Some(Handshake::Other { kind: 1, .. })));
        // Just the 5-byte record header.
        assert!(parse_tls(&full[..5]).is_some());
        assert!(parse_tls(&full[..4]).is_none());
    }

    #[test]
    fn alerts_and_non_tls() {
        let t = parse_tls(&[21, 3, 3, 0, 2, 2, 40]).unwrap();
        assert_eq!(t.records[0].alert, Some((2, 40)));
        for p in [
            &b"GET / HTTP/1.1\r\n"[..],
            &[22, 3, 9, 0, 5, 1, 2, 3, 4, 5],
            &[22, 2, 1, 0, 5, 1, 2, 3, 4, 5],
            &[22, 3, 1, 0, 0],
            &[],
            &[23, 3, 3, 0, 4, 1, 2, 3, 4],
        ] {
            assert!(parse_tls(p).is_none(), "{p:?}");
        }
    }

    #[test]
    fn tls_parser_survives_mutation() {
        let base = client_hello("example.org", true);
        let mut seed = 77u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..30_000 {
            let mut v = base.clone();
            for _ in 0..(1 + next() % 4) {
                let i = (next() as usize) % v.len();
                v[i] = next() as u8;
            }
            if next() % 3 == 0 {
                v.truncate((next() as usize) % v.len());
            }
            let _ = parse_tls(&v);
            let _ = parse_http(&v);
            let _ = parse_dhcp(&v);
        }
    }

    // ---- DHCP

    fn dhcp(op: u8, mtype: u8, opts: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = op;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        p[16..20].copy_from_slice(&[192, 0, 2, 50]);
        p[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
        p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        p.extend([53, 1, mtype]);
        p.extend(opts);
        p.push(255);
        p
    }

    #[test]
    fn dhcp_offer() {
        let opts = [
            1, 4, 255, 255, 255, 0, 3, 4, 192, 0, 2, 1, 6, 8, 192, 0, 2, 1, 192, 0, 2, 2, 51, 4, 0, 1, 0x51, 0x80, 54, 4, 192, 0,
            2, 1, 12, 4, b'h', b'o', b's', b't', 0, 0,
        ];
        let d = parse_dhcp(&dhcp(2, 2, &opts)).unwrap();
        assert_eq!((d.op, d.message_type, d.xid), (2, Some(2), 0xdeadbeef));
        assert_eq!(dhcp_type_name(2), "Offer");
        assert_eq!(d.your_ip.to_string(), "192.0.2.50");
        assert_eq!(d.client_mac.unwrap().to_string(), "02:00:00:00:00:09");
        assert_eq!(
            (d.subnet_mask.unwrap().to_string(), d.lease_secs, d.hostname.as_deref()),
            ("255.255.255.0".into(), Some(86400), Some("host"))
        );
        assert_eq!((d.routers.len(), d.dns_servers.len()), (1, 2));
        assert_eq!(d.server_id.unwrap().to_string(), "192.0.2.1");
    }

    #[test]
    fn dhcp_rejects_what_is_not_dhcp() {
        assert!(parse_dhcp(&[0u8; 100]).is_none());
        let mut p = dhcp(1, 1, &[]);
        p[236] = 0;
        assert!(parse_dhcp(&p).is_none());
        let mut p = dhcp(1, 1, &[]);
        p[0] = 9;
        assert!(parse_dhcp(&p).is_none());
        // An option that claims more bytes than there are.
        assert!(parse_dhcp(&dhcp(1, 1, &[12, 200, 1, 2])).is_none());
    }
}
