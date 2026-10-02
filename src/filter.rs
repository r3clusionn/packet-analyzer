//! A small filter language in the style of tcpdump:
//!
//! ```text
//! tcp and port 443          not arp          host 192.0.2.1 or net 10.0.0.0/8
//! udp and (dst port 53 or src port 53)        len > 1000        syn and not ack
//! dnsname example.com       sni example.com   contains "password"
//! ```
//!
//! Predicates: `ip ip6 tcp udp icmp icmp6 arp dns http tls dhcp frag iface N vlan [ID]`,
//! `[src|dst] host ADDR`, `[src|dst] net ADDR/BITS`, `[src|dst] port N`, `[src|dst] portrange A-B`,
//! `len OP N` (OP is `< <= = == != >= >`), the TCP flags `syn fin rst psh ack urg`, and the
//! content tests `dnsname TEXT`, `sni TEXT`, `httphost TEXT` and `contains TEXT` (all
//! case-insensitive substring tests). Combine with `and`/`&&`, `or`/`||`, `not`/`!` and parentheses;
//! `not` binds tighter than `and`, which binds tighter than `or`.

use std::net::IpAddr;

use crate::app::Handshake;
use crate::decode::{Decoded, Layer};
use crate::dns::RData;
use crate::pcap::Packet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    Any,
    Src,
    Dst,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    Lt,
    Le,
    Eq,
    Ne,
    Ge,
    Gt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Layer(&'static str),
    Host(Dir, IpAddr),
    Net(Dir, IpAddr, u8),
    Port(Dir, u16, u16),
    Len(Cmp, u64),
    Vlan(Option<u16>),
    Frag,
    Iface(u32),
    Flag(&'static str),
    DnsName(String),
    Sni(String),
    HttpHost(String),
    Contains(String),
    All,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    expr: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Quoted(String),
    LParen,
    RParen,
    And,
    Or,
    Not,
    Op(Cmp),
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            ' ' | '\t' | '\n' => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '&' if b.get(i + 1) == Some(&'&') => {
                out.push(Tok::And);
                i += 2;
            }
            '|' if b.get(i + 1) == Some(&'|') => {
                out.push(Tok::Or);
                i += 2;
            }
            '!' if b.get(i + 1) != Some(&'=') => {
                out.push(Tok::Not);
                i += 1;
            }
            '<' | '>' | '=' | '!' => {
                let two = b.get(i + 1) == Some(&'=');
                out.push(Tok::Op(match (c, two) {
                    ('<', false) => Cmp::Lt,
                    ('<', true) => Cmp::Le,
                    ('>', false) => Cmp::Gt,
                    ('>', true) => Cmp::Ge,
                    ('=', _) => Cmp::Eq,
                    ('!', _) => Cmp::Ne,
                    _ => unreachable!(),
                }));
                i += if two { 2 } else { 1 };
            }
            '"' | '\'' => {
                let end = b[i + 1..]
                    .iter()
                    .position(|x| *x == c)
                    .ok_or_else(|| format!("unterminated quote starting at character {}", i + 1))?;
                out.push(Tok::Quoted(b[i + 1..i + 1 + end].iter().collect()));
                i += end + 2;
            }
            _ => {
                let start = i;
                while i < b.len()
                    && !matches!(b[i], ' ' | '\t' | '\n' | '(' | ')' | '<' | '>' | '=' | '"' | '\'')
                    && !(b[i] == '&' && b.get(i + 1) == Some(&'&'))
                    && !(b[i] == '|' && b.get(i + 1) == Some(&'|'))
                {
                    i += 1;
                }
                let w: String = b[start..i].iter().collect();
                out.push(match w.to_ascii_lowercase().as_str() {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    _ => Tok::Word(w),
                });
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.at).cloned();
        self.at += 1;
        t
    }

    fn word(&mut self, what: &str) -> Result<String, String> {
        match self.next() {
            Some(Tok::Word(w)) | Some(Tok::Quoted(w)) => Ok(w),
            Some(t) => Err(format!("expected {what}, found {}", show(&t))),
            None => Err(format!("expected {what} at the end of the filter")),
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut l = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.at += 1;
            l = Expr::Or(Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut l = self.not()?;
        while self.peek() == Some(&Tok::And) {
            self.at += 1;
            l = Expr::And(Box::new(l), Box::new(self.not()?));
        }
        Ok(l)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.peek() == Some(&Tok::Not) {
            self.at += 1;
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::LParen) => {
                let e = self.or()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    _ => Err("missing )".to_string()),
                }
            }
            Some(Tok::Word(w)) => self.predicate(&w),
            Some(t) => Err(format!("unexpected {}", show(&t))),
            None => Err("the filter ends where a term is expected".to_string()),
        }
    }

    fn predicate(&mut self, w: &str) -> Result<Expr, String> {
        let lw = w.to_ascii_lowercase();
        Ok(match lw.as_str() {
            "ip" | "ip4" | "ipv4" => Expr::Layer("IPv4"),
            "ip6" | "ipv6" => Expr::Layer("IPv6"),
            "tcp" => Expr::Layer("TCP"),
            "udp" => Expr::Layer("UDP"),
            "icmp" => Expr::Layer("ICMP"),
            "icmp6" | "icmpv6" => Expr::Layer("ICMPv6"),
            "arp" => Expr::Layer("ARP"),
            "dns" => Expr::Layer("DNS"),
            "http" => Expr::Layer("HTTP"),
            "tls" | "ssl" => Expr::Layer("TLS"),
            "dhcp" => Expr::Layer("DHCP"),
            "frag" | "fragment" | "fragmented" => Expr::Frag,
            "iface" | "interface" => {
                let n = self.word("an interface number")?;
                Expr::Iface(n.parse().map_err(|_| format!("{n:?} is not an interface number"))?)
            }
            "syn" => Expr::Flag("syn"),
            "fin" => Expr::Flag("fin"),
            "rst" => Expr::Flag("rst"),
            "psh" => Expr::Flag("psh"),
            "ack" => Expr::Flag("ack"),
            "urg" => Expr::Flag("urg"),
            "vlan" => {
                let id = match self.peek() {
                    Some(Tok::Word(n)) if n.bytes().all(|b| b.is_ascii_digit()) => {
                        let n = n.parse::<u16>().map_err(|_| format!("{n} is not a VLAN id"))?;
                        self.at += 1;
                        Some(n)
                    }
                    _ => None,
                };
                Expr::Vlan(id)
            }
            "src" | "dst" => {
                let dir = if lw == "src" { Dir::Src } else { Dir::Dst };
                let what = self.word("host, net, port or portrange after src/dst")?;
                self.directed(dir, &what)?
            }
            "host" | "net" | "port" | "portrange" => self.directed(Dir::Any, &lw)?,
            "len" | "length" => {
                let op = match self.next() {
                    Some(Tok::Op(o)) => o,
                    _ => return Err("len needs a comparison: len > 100".to_string()),
                };
                let n = self.word("a number")?;
                Expr::Len(op, n.parse().map_err(|_| format!("{n:?} is not a number"))?)
            }
            "dnsname" => Expr::DnsName(self.word("a name")?.to_ascii_lowercase()),
            "sni" => Expr::Sni(self.word("a name")?.to_ascii_lowercase()),
            "httphost" => Expr::HttpHost(self.word("a host name")?.to_ascii_lowercase()),
            "contains" => Expr::Contains(self.word("the text to look for")?.to_ascii_lowercase()),
            "all" | "any" | "true" => Expr::All,
            _ => return Err(format!("unknown term {w:?}")),
        })
    }

    fn directed(&mut self, dir: Dir, what: &str) -> Result<Expr, String> {
        match what.to_ascii_lowercase().as_str() {
            "host" => {
                let a = self.word("an IP address")?;
                Ok(Expr::Host(dir, a.parse().map_err(|_| format!("{a:?} is not an IP address (names are not resolved)"))?))
            }
            "net" => {
                let a = self.word("an address with a prefix length, like 10.0.0.0/8")?;
                let (addr, bits) = a.split_once('/').ok_or_else(|| format!("{a:?} needs a prefix length: {a}/24"))?;
                let ip: IpAddr = addr.parse().map_err(|_| format!("{addr:?} is not an IP address"))?;
                let bits: u8 = bits.parse().map_err(|_| format!("{bits:?} is not a prefix length"))?;
                if bits > if ip.is_ipv4() { 32 } else { 128 } {
                    return Err(format!("a prefix of {bits} bits is too long for {ip}"));
                }
                Ok(Expr::Net(dir, ip, bits))
            }
            "port" => {
                let n = self.word("a port number")?;
                let p = n.parse::<u16>().map_err(|_| format!("{n:?} is not a port number"))?;
                Ok(Expr::Port(dir, p, p))
            }
            "portrange" => {
                let n = self.word("a port range like 1000-2000")?;
                let (a, b) = n.split_once('-').ok_or_else(|| format!("{n:?} needs the form 1000-2000"))?;
                let (a, b): (u16, u16) = (
                    a.parse().map_err(|_| format!("{a:?} is not a port"))?,
                    b.parse().map_err(|_| format!("{b:?} is not a port"))?,
                );
                if a > b {
                    return Err(format!("the port range {a}-{b} is backwards"));
                }
                Ok(Expr::Port(dir, a, b))
            }
            other => Err(format!("expected host, net, port or portrange after src/dst, found {other:?}")),
        }
    }
}

fn show(t: &Tok) -> String {
    match t {
        Tok::Word(w) => format!("{w:?}"),
        Tok::Quoted(w) => format!("\"{w}\""),
        Tok::LParen => "(".into(),
        Tok::RParen => ")".into(),
        Tok::And => "and".into(),
        Tok::Or => "or".into(),
        Tok::Not => "not".into(),
        Tok::Op(_) => "a comparison operator".into(),
    }
}

fn in_net(addr: &IpAddr, net: &IpAddr, bits: u8) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits as u32) };
            u32::from(*a) & mask == u32::from(*n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits as u32) };
            u128::from(*a) & mask == u128::from(*n) & mask
        }
        _ => false,
    }
}

/// The (source, destination) addresses of the packet's network layer; for ARP the sender and target.
fn addresses(d: &Decoded) -> Option<(IpAddr, IpAddr)> {
    d.layers.iter().find_map(|l| match l {
        Layer::Ipv4 { src, dst, .. } => Some(((*src).into(), (*dst).into())),
        Layer::Ipv6 { src, dst, .. } => Some(((*src).into(), (*dst).into())),
        Layer::Arp { sender_ip, target_ip, .. } => Some(((*sender_ip).into(), (*target_ip).into())),
        _ => None,
    })
}

fn ports(d: &Decoded) -> Option<(u16, u16)> {
    d.layers.iter().find_map(|l| match l {
        Layer::Tcp { src_port, dst_port, .. } | Layer::Udp { src_port, dst_port, .. } => Some((*src_port, *dst_port)),
        _ => None,
    })
}

impl Expr {
    fn eval(&self, p: &Packet, d: &Decoded, data: &[u8]) -> bool {
        let text_has = |hay: &str, needle: &str| hay.to_ascii_lowercase().contains(needle);
        match self {
            Expr::All => true,
            Expr::Or(a, b) => a.eval(p, d, data) || b.eval(p, d, data),
            Expr::And(a, b) => a.eval(p, d, data) && b.eval(p, d, data),
            Expr::Not(a) => !a.eval(p, d, data),
            Expr::Layer(n) => d.has(n),
            Expr::Host(dir, ip) => addresses(d).is_some_and(|(s, t)| match dir {
                Dir::Any => s == *ip || t == *ip,
                Dir::Src => s == *ip,
                Dir::Dst => t == *ip,
            }),
            Expr::Net(dir, net, bits) => addresses(d).is_some_and(|(s, t)| match dir {
                Dir::Any => in_net(&s, net, *bits) || in_net(&t, net, *bits),
                Dir::Src => in_net(&s, net, *bits),
                Dir::Dst => in_net(&t, net, *bits),
            }),
            Expr::Port(dir, lo, hi) => ports(d).is_some_and(|(s, t)| {
                let inr = |x: u16| (*lo..=*hi).contains(&x);
                match dir {
                    Dir::Any => inr(s) || inr(t),
                    Dir::Src => inr(s),
                    Dir::Dst => inr(t),
                }
            }),
            Expr::Len(op, n) => {
                let l = p.orig_len as u64;
                match op {
                    Cmp::Lt => l < *n,
                    Cmp::Le => l <= *n,
                    Cmp::Eq => l == *n,
                    Cmp::Ne => l != *n,
                    Cmp::Ge => l >= *n,
                    Cmp::Gt => l > *n,
                }
            }
            Expr::Vlan(id) => d.layers.iter().any(|l| matches!(l, Layer::Vlan { id: v, .. } if id.is_none_or(|i| i == *v))),
            Expr::Iface(n) => p.iface == *n,
            Expr::Frag => d.layers.iter().any(|l| match l {
                Layer::Ipv4 { more_fragments, fragment_offset, .. } => *more_fragments || *fragment_offset != 0,
                Layer::Ipv6Fragment { .. } => true,
                _ => false,
            }),
            Expr::Flag(name) => d.tcp().is_some_and(|l| {
                let Layer::Tcp { flags, .. } = l else { return false };
                match *name {
                    "syn" => flags.syn,
                    "fin" => flags.fin,
                    "rst" => flags.rst,
                    "psh" => flags.psh,
                    "ack" => flags.ack,
                    _ => flags.urg,
                }
            }),
            Expr::DnsName(n) => d.dns().is_some_and(|dns| {
                dns.questions.iter().any(|q| text_has(&q.name, n))
                    || dns.answers.iter().chain(&dns.authorities).chain(&dns.additionals).any(|r| {
                        text_has(&r.name, n)
                            || matches!(&r.data, RData::Cname(c) | RData::Ptr(c) | RData::Ns(c) if text_has(c, n))
                    })
            }),
            Expr::Sni(n) => d.tls().is_some_and(|t| {
                t.records
                    .iter()
                    .any(|r| matches!(&r.handshake, Some(Handshake::ClientHello { sni: Some(s), .. }) if text_has(s, n)))
            }),
            Expr::HttpHost(n) => d.http().and_then(|h| h.header("host")).is_some_and(|h| text_has(h, n)),
            Expr::Contains(n) => {
                let payload = data.get(d.payload_offset..d.payload_offset.saturating_add(d.payload_len)).unwrap_or(&[]);
                let needle = n.as_bytes();
                !needle.is_empty() && payload.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
            }
        }
    }
}

impl Filter {
    /// Parses a filter. An empty (or all-blank) filter matches everything.
    pub fn parse(s: &str) -> Result<Filter, String> {
        let toks = tokenize(s)?;
        if toks.is_empty() {
            return Ok(Filter { expr: Expr::All });
        }
        let mut p = Parser { toks, at: 0 };
        let expr = p.or()?;
        if p.peek() == Some(&Tok::RParen) {
            return Err("unmatched )".to_string());
        }
        if let Some(t) = p.peek() {
            return Err(format!("unexpected {} after a complete expression (missing and/or?)", show(t)));
        }
        Ok(Filter { expr })
    }

    pub fn matches(&self, p: &Packet, d: &Decoded) -> bool {
        self.expr.eval(p, d, &p.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode, ETH_ARP, ETH_IPV4, PROTO_TCP, PROTO_UDP};
    use crate::testutil::*;

    const A: [u8; 4] = [192, 0, 2, 1];
    const B: [u8; 4] = [10, 1, 2, 3];

    fn packet(data: Vec<u8>) -> (Packet, Decoded) {
        let p = Packet { number: 1, ts_sec: 0, ts_nsec: 0, link: 1, orig_len: data.len() as u32, data, iface: 0 };
        let d = decode(1, &p.data);
        (p, d)
    }

    fn syn() -> (Packet, Decoded) {
        packet(eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, A, B, &tcp_segment(A, B, 51234, 443, 1, 0, 0x02, &[], b""))))
    }

    fn dns_query() -> (Packet, Decoded) {
        let mut m = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["www", "Example", "com"] {
            m.push(l.len() as u8);
            m.extend(l.as_bytes());
        }
        m.extend([0, 0, 1, 0, 1]);
        packet(eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, A, B, &udp_datagram(A, B, 40000, 53, &m))))
    }

    fn m(f: &str, pd: &(Packet, Decoded)) -> bool {
        Filter::parse(f).unwrap_or_else(|e| panic!("{f}: {e}")).matches(&pd.0, &pd.1)
    }

    #[test]
    fn protocol_terms() {
        let t = syn();
        for (f, want) in [
            ("tcp", true),
            ("udp", false),
            ("ip", true),
            ("ip6", false),
            ("icmp", false),
            ("arp", false),
            ("dns", false),
            ("TCP", true),
            ("all", true),
            ("", true),
            ("   ", true),
        ] {
            assert_eq!(m(f, &t), want, "{f:?}");
        }
        let q = dns_query();
        assert!(m("udp and dns", &q) && !m("tcp", &q));
    }

    #[test]
    fn addresses_and_ports() {
        let t = syn();
        for (f, want) in [
            ("host 192.0.2.1", true),
            ("host 10.1.2.3", true),
            ("host 10.1.2.4", false),
            ("src host 192.0.2.1", true),
            ("dst host 192.0.2.1", false),
            ("src 192.0.2.1", false), // a bare address after src is not a term; handled below
        ] {
            if f == "src 192.0.2.1" {
                assert!(Filter::parse(f).is_err());
                continue;
            }
            assert_eq!(m(f, &t), want, "{f}");
        }
        for (f, want) in [
            ("port 443", true),
            ("port 80", false),
            ("dst port 443", true),
            ("src port 443", false),
            ("src port 51234", true),
            ("portrange 400-500", true),
            ("src portrange 400-500", false),
            ("dst portrange 443-443", true),
            ("net 10.0.0.0/8", true),
            ("src net 10.0.0.0/8", false),
            ("dst net 10.0.0.0/8", true),
            ("net 192.0.2.0/24", true),
            ("net 192.0.3.0/24", false),
            ("net 0.0.0.0/0", true),
            ("net 192.0.2.1/32", true),
            ("net 2001:db8::/32", false),
        ] {
            assert_eq!(m(f, &t), want, "{f}");
        }
    }

    #[test]
    fn boolean_logic_and_precedence() {
        let t = syn();
        // not > and > or
        assert!(m("tcp and port 443 or udp", &t));
        assert!(m("udp or tcp and port 443", &t));
        assert!(!m("udp or tcp and port 80", &t));
        assert!(m("not udp", &t) && !m("not tcp", &t) && m("! udp", &t) && m("not not tcp", &t));
        assert!(m("(udp or tcp) and port 443", &t));
        assert!(!m("udp or (tcp and not port 443)", &t));
        assert!(m("tcp && port 443", &t) && m("udp || tcp", &t));
        assert!(m("TCP AND NOT UDP", &t));
    }

    #[test]
    fn tcp_flags_len_and_content() {
        let t = syn();
        assert!(m("syn", &t) && !m("ack", &t) && !m("fin", &t) && m("syn and not ack", &t));
        let l = t.0.orig_len as u64;
        assert!(
            m(&format!("len = {l}"), &t)
                && m(&format!("len == {l}"), &t)
                && m(&format!("len >= {l}"), &t)
                && m(&format!("len <= {l}"), &t)
        );
        assert!(
            m(&format!("len > {}", l - 1), &t)
                && !m(&format!("len > {l}"), &t)
                && m(&format!("len < {}", l + 1), &t)
                && m(&format!("len != {}", l + 1), &t)
        );
        let q = dns_query();
        assert!(m("dnsname example.com", &q) && m("dnsname WWW.EXAMPLE", &q) && !m("dnsname other.org", &q));
        assert!(m("contains \"www\"", &q) && m("contains EXAMPLE", &q) && !m("contains nothere", &q));
        assert!(!m("dnsname example", &t));
    }

    #[test]
    fn http_tls_arp_and_vlan() {
        let http = packet(eth_frame(
            ETH_IPV4,
            &ipv4_packet(
                PROTO_TCP,
                A,
                B,
                &tcp_segment(A, B, 1234, 80, 1, 1, 0x18, &[], b"GET / HTTP/1.1\r\nHost: Example.org\r\n\r\n"),
            ),
        ));
        assert!(m("http and httphost example.org", &http) && !m("httphost nothere", &http) && !m("tls", &http));
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1];
        arp.extend(A);
        arp.extend([0u8; 6]);
        arp.extend(B);
        let a = packet(eth_frame(ETH_ARP, &arp));
        assert!(m("arp and host 192.0.2.1 and host 10.1.2.3", &a) && m("src host 192.0.2.1", &a) && !m("ip", &a));
        let mut vlan = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x81, 0x00, 0x00, 0x2a, 0x08, 0x00];
        vlan.extend(ipv4_packet(PROTO_UDP, A, B, &udp_datagram(A, B, 1, 2, b"x")));
        let v = packet(vlan);
        assert!(m("vlan", &v) && m("vlan 42", &v) && !m("vlan 43", &v) && !m("vlan", &syn()));
    }

    #[test]
    fn fragments() {
        let f = packet(eth_frame(ETH_IPV4, &ipv4_packet_with(PROTO_UDP, A, B, &[0u8; 16], 0x2000, 0)));
        assert!(m("frag", &f) && !m("frag", &syn()));
    }

    #[test]
    fn errors_are_specific() {
        for (f, want) in [
            ("tcp and", "ends where a term is expected"),
            ("(tcp", "missing )"),
            ("tcp)", "unmatched )"),
            ("bogus", "unknown term"),
            ("host", "expected an IP address"),
            ("host example.com", "names are not resolved"),
            ("port abc", "not a port number"),
            ("port 70000", "not a port number"),
            ("portrange 5-1", "backwards"),
            ("portrange 5", "needs the form"),
            ("net 10.0.0.0", "needs a prefix length"),
            ("net 10.0.0.0/33", "too long"),
            ("net 10.0.0.0/x", "not a prefix length"),
            ("len 5", "needs a comparison"),
            ("len > x", "not a number"),
            ("tcp udp", "missing and/or"),
            ("src", "after src/dst"),
            ("src banana", "expected host, net, port"),
            ("contains", "the text to look for"),
            ("contains \"unterminated", "unterminated quote"),
        ] {
            let e = Filter::parse(f).expect_err(f);
            assert!(e.contains(want), "{f:?} gave {e:?}, wanted {want:?}");
        }
    }

    #[test]
    fn ipv6_hosts_and_nets() {
        let mut ip = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        ip.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip.extend([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        ip.extend([0, 1, 0, 2, 0, 8, 0, 0]);
        let p = packet(eth_frame(0x86dd, &ip));
        assert!(
            m("host 2001:db8::1", &p)
                && m("dst host 2001:db8:1::2", &p)
                && m("net 2001:db8::/32", &p)
                && !m("net 2001:db9::/32", &p)
                && m("ip6 and udp", &p)
        );
        assert!(!m("net 192.0.2.0/24", &p));
    }
}
