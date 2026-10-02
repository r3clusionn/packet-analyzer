//! Decoding a captured frame into layers: link, network, transport, and the application
//! protocols recognised from the payload (see [`crate::dns`] and [`crate::app`]).
//!
//! Every read is bounds-checked. When a header does not fit in the captured bytes the layers
//! decoded so far are kept, [`Decoded::truncated`] says which header was cut, and decoding stops;
//! nothing here can panic on any input (a fuzz test checks that).

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::app::{self, Dhcp, Http, Tls};
use crate::dns::{self, Dns};

pub const LINK_NULL: u32 = 0;
pub const LINK_ETHERNET: u32 = 1;
pub const LINK_RAW: u32 = 101;
pub const LINK_RAW_ALT: u32 = 12;
pub const LINK_LINUX_SLL: u32 = 113;
pub const LINK_LINUX_SLL2: u32 = 276;

pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_ARP: u16 = 0x0806;
pub const ETH_VLAN: u16 = 0x8100;
pub const ETH_QINQ: u16 = 0x88a8;
pub const ETH_IPV6: u16 = 0x86dd;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// A MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Serialize for Mac {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

impl TcpFlags {
    /// The flags the way tcpdump writes them: `[SYN, ACK]`.
    pub fn names(&self) -> String {
        let mut v = Vec::new();
        for (on, n) in [
            (self.syn, "SYN"),
            (self.fin, "FIN"),
            (self.rst, "RST"),
            (self.psh, "PSH"),
            (self.ack, "ACK"),
            (self.urg, "URG"),
            (self.ece, "ECE"),
            (self.cwr, "CWR"),
            (self.ns, "NS"),
        ] {
            if on {
                v.push(n);
            }
        }
        format!("[{}]", v.join(", "))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum TcpOption {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<(u32, u32)>),
    Timestamp { value: u32, echo: u32 },
    Nop,
    Unknown { kind: u8, len: u8 },
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "layer")]
pub enum Layer {
    Ethernet {
        dst: Mac,
        src: Mac,
        ethertype: u16,
    },
    Vlan {
        id: u16,
        priority: u8,
        dei: bool,
        ethertype: u16,
    },
    LinuxSll {
        packet_type: u16,
        addr_type: u16,
        addr: Vec<u8>,
        protocol: u16,
    },
    Loopback {
        family: u32,
    },
    Arp {
        op: u16,
        sender_mac: Mac,
        sender_ip: Ipv4Addr,
        target_mac: Mac,
        target_ip: Ipv4Addr,
    },
    Ipv4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        ttl: u8,
        id: u16,
        dscp: u8,
        ecn: u8,
        dont_fragment: bool,
        more_fragments: bool,
        fragment_offset: u16,
        header_len: u8,
        total_len: u16,
        checksum: u16,
        checksum_ok: bool,
        options_len: u8,
    },
    Ipv6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        hop_limit: u8,
        traffic_class: u8,
        flow_label: u32,
        payload_len: u16,
    },
    Ipv6Fragment {
        next_header: u8,
        offset: u16,
        more_fragments: bool,
        id: u32,
    },
    Ipv6Extension {
        kind: u8,
        len: usize,
    },
    Icmp {
        icmp_type: u8,
        code: u8,
        checksum_ok: bool,
        id: Option<u16>,
        seq: Option<u16>,
        info: String,
    },
    Icmpv6 {
        icmp_type: u8,
        code: u8,
        checksum_ok: bool,
        id: Option<u16>,
        seq: Option<u16>,
        info: String,
    },
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        checksum: u16,
        checksum_ok: Option<bool>,
        urgent: u16,
        header_len: u8,
        options: Vec<TcpOption>,
        payload_len: usize,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
        checksum: u16,
        checksum_ok: Option<bool>,
        payload_len: usize,
    },
    Dns(Dns),
    Http(Http),
    Tls(Tls),
    Dhcp(Dhcp),
}

impl Layer {
    pub fn name(&self) -> &'static str {
        match self {
            Layer::Ethernet { .. } => "Ethernet",
            Layer::Vlan { .. } => "VLAN",
            Layer::LinuxSll { .. } => "Linux cooked",
            Layer::Loopback { .. } => "Loopback",
            Layer::Arp { .. } => "ARP",
            Layer::Ipv4 { .. } => "IPv4",
            Layer::Ipv6 { .. } => "IPv6",
            Layer::Ipv6Fragment { .. } => "IPv6 fragment",
            Layer::Ipv6Extension { .. } => "IPv6 extension",
            Layer::Icmp { .. } => "ICMP",
            Layer::Icmpv6 { .. } => "ICMPv6",
            Layer::Tcp { .. } => "TCP",
            Layer::Udp { .. } => "UDP",
            Layer::Dns(_) => "DNS",
            Layer::Http(_) => "HTTP",
            Layer::Tls(_) => "TLS",
            Layer::Dhcp(_) => "DHCP",
        }
    }
}

/// The result of decoding one frame.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Decoded {
    pub layers: Vec<Layer>,
    /// The name of the header that did not fit in the captured bytes, if any.
    pub truncated: Option<String>,
    /// Things that are wrong or odd but did not stop decoding (a bad checksum, a bad length).
    pub notes: Vec<String>,
    /// Offset in the frame where the innermost decoded layer's payload starts.
    pub payload_offset: usize,
    pub payload_len: usize,
}

impl Decoded {
    pub fn ipv4(&self) -> Option<(&Ipv4Addr, &Ipv4Addr)> {
        self.layers.iter().find_map(|l| if let Layer::Ipv4 { src, dst, .. } = l { Some((src, dst)) } else { None })
    }

    pub fn tcp(&self) -> Option<&Layer> {
        self.layers.iter().find(|l| matches!(l, Layer::Tcp { .. }))
    }

    pub fn has(&self, name: &str) -> bool {
        self.layers.iter().any(|l| l.name() == name)
    }

    pub fn dns(&self) -> Option<&Dns> {
        self.layers.iter().find_map(|l| if let Layer::Dns(d) = l { Some(d) } else { None })
    }

    pub fn http(&self) -> Option<&Http> {
        self.layers.iter().find_map(|l| if let Layer::Http(h) = l { Some(h) } else { None })
    }

    pub fn tls(&self) -> Option<&Tls> {
        self.layers.iter().find_map(|l| if let Layer::Tls(t) = l { Some(t) } else { None })
    }
}

/// A cursor that never reads past the end.
struct Cur<'a> {
    d: &'a [u8],
    at: usize,
}

struct Short(&'static str);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Short> {
        let s = self.d.get(self.at..self.at + n).ok_or(Short(what))?;
        self.at += n;
        Ok(s)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, Short> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, Short> {
        Ok(u16::from_be_bytes(self.take(2, what)?.try_into().unwrap()))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, Short> {
        Ok(u32::from_be_bytes(self.take(4, what)?.try_into().unwrap()))
    }

    fn rest(&self) -> &'a [u8] {
        &self.d[self.at.min(self.d.len())..]
    }
}

/// The Internet checksum (RFC 1071) of some byte slices taken as one sequence.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry_byte: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match carry_byte.take() {
                Some(hi) => sum += u32::from(u16::from_be_bytes([hi, b])),
                None => carry_byte = Some(b),
            }
        }
    }
    if let Some(hi) = carry_byte {
        sum += u32::from(hi) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn pseudo_header(src: &[u8], dst: &[u8], proto: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(40);
    p.extend(src);
    p.extend(dst);
    if src.len() == 4 {
        p.push(0);
        p.push(proto);
        p.extend((len as u16).to_be_bytes());
    } else {
        p.extend((len as u32).to_be_bytes());
        p.extend([0, 0, 0, proto]);
    }
    p
}

/// The addresses of the enclosing IP header, for checksums and flow keys.
#[derive(Clone)]
struct IpCtx {
    src: Vec<u8>,
    dst: Vec<u8>,
}

/// Decodes a frame captured on a link of type `link`.
pub fn decode(link: u32, data: &[u8]) -> Decoded {
    let mut d = Decoded { payload_offset: 0, payload_len: data.len(), ..Default::default() };
    if let Err(Short(w)) = decode_link(link, data, &mut d) {
        d.truncated = Some(w.to_string());
    }
    d
}

fn decode_link(link: u32, data: &[u8], d: &mut Decoded) -> Result<(), Short> {
    let mut c = Cur { d: data, at: 0 };
    match link {
        LINK_ETHERNET => {
            let dst = Mac(c.take(6, "Ethernet header")?.try_into().unwrap());
            let src = Mac(c.take(6, "Ethernet header")?.try_into().unwrap());
            let mut ethertype = c.u16("Ethernet header")?;
            d.layers.push(Layer::Ethernet { dst, src, ethertype });
            let mut tags = 0;
            while matches!(ethertype, ETH_VLAN | ETH_QINQ | 0x9100) && tags < 4 {
                let tci = c.u16("VLAN tag")?;
                let inner = c.u16("VLAN tag")?;
                d.layers.push(Layer::Vlan {
                    id: tci & 0x0fff,
                    priority: (tci >> 13) as u8,
                    dei: tci & 0x1000 != 0,
                    ethertype: inner,
                });
                ethertype = inner;
                tags += 1;
            }
            d.payload_offset = c.at;
            d.payload_len = c.rest().len();
            network(ethertype, c.rest(), c.at, d)
        }
        LINK_NULL => {
            // The address family is in the capturing machine's byte order; accept either.
            let raw = c.take(4, "loopback header")?;
            let (le, be) = (u32::from_le_bytes(raw.try_into().unwrap()), u32::from_be_bytes(raw.try_into().unwrap()));
            let family = if le < 256 { le } else { be };
            d.layers.push(Layer::Loopback { family });
            let ethertype = match family {
                2 => ETH_IPV4,
                10 | 24 | 28 | 30 => ETH_IPV6,
                _ => 0,
            };
            d.payload_offset = c.at;
            d.payload_len = c.rest().len();
            network(ethertype, c.rest(), c.at, d)
        }
        LINK_RAW | LINK_RAW_ALT | 14 => {
            let first = *data.first().ok_or(Short("IP header"))?;
            let ethertype = match first >> 4 {
                4 => ETH_IPV4,
                6 => ETH_IPV6,
                _ => 0,
            };
            network(ethertype, data, 0, d)
        }
        LINK_LINUX_SLL => {
            let packet_type = c.u16("cooked header")?;
            let addr_type = c.u16("cooked header")?;
            let addr_len = c.u16("cooked header")? as usize;
            let raw = c.take(8, "cooked header")?;
            let protocol = c.u16("cooked header")?;
            d.layers.push(Layer::LinuxSll { packet_type, addr_type, addr: raw[..addr_len.min(8)].to_vec(), protocol });
            d.payload_offset = c.at;
            d.payload_len = c.rest().len();
            network(protocol, c.rest(), c.at, d)
        }
        LINK_LINUX_SLL2 => {
            let protocol = c.u16("cooked v2 header")?;
            c.take(2, "cooked v2 header")?; // reserved
            c.take(4, "cooked v2 header")?; // interface index
            let addr_type = c.u16("cooked v2 header")?;
            let packet_type = c.u8("cooked v2 header")? as u16;
            let addr_len = c.u8("cooked v2 header")? as usize;
            let raw = c.take(8, "cooked v2 header")?;
            d.layers.push(Layer::LinuxSll { packet_type, addr_type, addr: raw[..addr_len.min(8)].to_vec(), protocol });
            d.payload_offset = c.at;
            d.payload_len = c.rest().len();
            network(protocol, c.rest(), c.at, d)
        }
        other => {
            d.notes.push(format!("data link type {other} is not supported"));
            Ok(())
        }
    }
}

fn network(ethertype: u16, data: &[u8], base: usize, d: &mut Decoded) -> Result<(), Short> {
    match ethertype {
        ETH_IPV4 => ipv4(data, base, d),
        ETH_IPV6 => ipv6(data, base, d),
        ETH_ARP => arp(data, base, d),
        0 => Ok(()),
        t if t <= 1500 => {
            d.notes.push("an IEEE 802.3 frame (length field instead of a type), LLC is not decoded".into());
            Ok(())
        }
        t => {
            d.notes.push(format!("unrecognised EtherType {t:#06x}"));
            Ok(())
        }
    }
}

fn arp(data: &[u8], base: usize, d: &mut Decoded) -> Result<(), Short> {
    let mut c = Cur { d: data, at: 0 };
    let (hw, proto) = (c.u16("ARP")?, c.u16("ARP")?);
    let (hlen, plen) = (c.u8("ARP")?, c.u8("ARP")?);
    let op = c.u16("ARP")?;
    if hw != 1 || proto != ETH_IPV4 || hlen != 6 || plen != 4 {
        d.notes.push(format!("ARP for hardware type {hw}, protocol {proto:#06x} is not decoded"));
        return Ok(());
    }
    let sender_mac = Mac(c.take(6, "ARP")?.try_into().unwrap());
    let sender_ip = Ipv4Addr::from(<[u8; 4]>::try_from(c.take(4, "ARP")?).unwrap());
    let target_mac = Mac(c.take(6, "ARP")?.try_into().unwrap());
    let target_ip = Ipv4Addr::from(<[u8; 4]>::try_from(c.take(4, "ARP")?).unwrap());
    d.layers.push(Layer::Arp { op, sender_mac, sender_ip, target_mac, target_ip });
    d.payload_offset = base + c.at;
    d.payload_len = c.rest().len();
    Ok(())
}

fn ipv4(data: &[u8], base: usize, d: &mut Decoded) -> Result<(), Short> {
    let mut c = Cur { d: data, at: 0 };
    let vihl = c.u8("IPv4 header")?;
    let tos = c.u8("IPv4 header")?;
    let total_len = c.u16("IPv4 header")?;
    let id = c.u16("IPv4 header")?;
    let ff = c.u16("IPv4 header")?;
    let ttl = c.u8("IPv4 header")?;
    let protocol = c.u8("IPv4 header")?;
    let checksum_field = c.u16("IPv4 header")?;
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(c.take(4, "IPv4 header")?).unwrap());
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(c.take(4, "IPv4 header")?).unwrap());
    let ihl = (vihl & 0x0f) as usize * 4;
    if vihl >> 4 != 4 {
        d.notes.push(format!("IPv4 header with version {}", vihl >> 4));
        return Ok(());
    }
    if ihl < 20 {
        d.notes.push(format!("IPv4 header length {ihl} is below the minimum of 20"));
        return Ok(());
    }
    let header = data.get(..ihl).ok_or(Short("IPv4 options"))?;
    let checksum_ok = checksum(&[header]) == 0;
    let fragment_offset = (ff & 0x1fff) * 8;
    let more_fragments = ff & 0x2000 != 0;
    d.layers.push(Layer::Ipv4 {
        src,
        dst,
        protocol,
        ttl,
        id,
        dscp: tos >> 2,
        ecn: tos & 3,
        dont_fragment: ff & 0x4000 != 0,
        more_fragments,
        fragment_offset,
        header_len: ihl as u8,
        total_len,
        checksum: checksum_field,
        checksum_ok,
        options_len: (ihl - 20) as u8,
    });
    // The IP total length excludes link-layer padding (an Ethernet frame is at least 60 bytes).
    let end = if (total_len as usize) < ihl {
        d.notes.push(format!("IPv4 total length {total_len} is shorter than its header"));
        data.len()
    } else {
        (total_len as usize).min(data.len())
    };
    if (total_len as usize) > data.len() {
        d.notes.push(format!("IPv4 total length {total_len} but only {} bytes were captured", data.len()));
    }
    let payload = &data[ihl.min(end)..end];
    d.payload_offset = base + ihl;
    d.payload_len = payload.len();
    if fragment_offset != 0 {
        d.notes.push(format!("a fragment at offset {fragment_offset}: the transport header is in an earlier fragment"));
        return Ok(());
    }
    if more_fragments {
        d.notes.push("the first fragment of a fragmented datagram".into());
    }
    let ctx = IpCtx { src: src.octets().to_vec(), dst: dst.octets().to_vec() };
    transport(protocol, payload, base + ihl, &ctx, more_fragments, d)
}

fn ipv6(data: &[u8], base: usize, d: &mut Decoded) -> Result<(), Short> {
    let mut c = Cur { d: data, at: 0 };
    let w = c.u32("IPv6 header")?;
    let payload_len = c.u16("IPv6 header")?;
    let mut next_header = c.u8("IPv6 header")?;
    let hop_limit = c.u8("IPv6 header")?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(c.take(16, "IPv6 header")?).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(c.take(16, "IPv6 header")?).unwrap());
    if w >> 28 != 6 {
        d.notes.push(format!("IPv6 header with version {}", w >> 28));
        return Ok(());
    }
    d.layers.push(Layer::Ipv6 {
        src,
        dst,
        next_header,
        hop_limit,
        traffic_class: (w >> 20) as u8,
        flow_label: w & 0xf_ffff,
        payload_len,
    });
    let ctx = IpCtx { src: src.octets().to_vec(), dst: dst.octets().to_vec() };
    // A payload length of 0 means a jumbo payload or a capture offload: use what is there.
    let end = if payload_len == 0 { data.len() } else { (40 + payload_len as usize).min(data.len()) };
    if payload_len != 0 && 40 + payload_len as usize > data.len() {
        d.notes.push(format!("IPv6 payload length {payload_len} but only {} bytes were captured", data.len() - 40));
    }
    let body = &data[40..end.max(40)];
    let mut body_at = 40;
    let mut cur = Cur { d: body, at: 0 };
    // Walk the extension headers up to the upper-layer protocol.
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 | 51 => {
                let nh = cur.u8("IPv6 extension header")?;
                let len_field = cur.u8("IPv6 extension header")? as usize;
                // Authentication Header counts in 4-byte units minus two; the others in 8-byte units minus one.
                let len = if next_header == 51 { (len_field + 2) * 4 } else { (len_field + 1) * 8 };
                cur.take(len - 2, "IPv6 extension header")?;
                d.layers.push(Layer::Ipv6Extension { kind: next_header, len });
                next_header = nh;
                body_at = 40 + cur.at;
            }
            44 => {
                let nh = cur.u8("IPv6 fragment header")?;
                cur.u8("IPv6 fragment header")?;
                let off_flags = cur.u16("IPv6 fragment header")?;
                let id = cur.u32("IPv6 fragment header")?;
                let offset = (off_flags >> 3) * 8;
                let more = off_flags & 1 != 0;
                d.layers.push(Layer::Ipv6Fragment { next_header: nh, offset, more_fragments: more, id });
                next_header = nh;
                body_at = 40 + cur.at;
                if offset != 0 {
                    d.payload_offset = base + body_at;
                    d.payload_len = cur.rest().len();
                    d.notes.push(format!("a fragment at offset {offset}: the transport header is in an earlier fragment"));
                    return Ok(());
                }
                if more {
                    d.notes.push("the first fragment of a fragmented datagram".into());
                }
            }
            _ => break,
        }
    }
    d.payload_offset = base + body_at;
    d.payload_len = cur.rest().len();
    if next_header == 59 {
        return Ok(()); // no next header
    }
    transport(next_header, cur.rest(), base + body_at, &ctx, false, d)
}

fn transport(proto: u8, payload: &[u8], base: usize, ip: &IpCtx, fragmented: bool, d: &mut Decoded) -> Result<(), Short> {
    d.payload_offset = base;
    d.payload_len = payload.len();
    match proto {
        PROTO_ICMP => icmp(payload, base, false, ip, fragmented, d),
        PROTO_ICMPV6 => icmp(payload, base, true, ip, fragmented, d),
        PROTO_TCP => tcp(payload, base, ip, fragmented, d),
        PROTO_UDP => udp(payload, base, ip, fragmented, d),
        _ => Ok(()),
    }
}

fn icmp(data: &[u8], base: usize, v6: bool, ip: &IpCtx, fragmented: bool, d: &mut Decoded) -> Result<(), Short> {
    let mut c = Cur { d: data, at: 0 };
    let t = c.u8("ICMP header")?;
    let code = c.u8("ICMP header")?;
    c.u16("ICMP header")?;
    let rest = c.take(4, "ICMP header")?;
    let checksum_ok = if fragmented {
        true
    } else if v6 {
        let ph = pseudo_header(&ip.src, &ip.dst, PROTO_ICMPV6, data.len());
        checksum(&[&ph, data]) == 0
    } else {
        checksum(&[data]) == 0
    };
    let echo = if v6 { matches!(t, 128 | 129) } else { matches!(t, 0 | 8) };
    let (id, seq) = if echo {
        (Some(u16::from_be_bytes([rest[0], rest[1]])), Some(u16::from_be_bytes([rest[2], rest[3]])))
    } else {
        (None, None)
    };
    let info = if v6 { icmpv6_name(t, code) } else { icmpv4_name(t, code) };
    let layer = if v6 {
        Layer::Icmpv6 { icmp_type: t, code, checksum_ok, id, seq, info }
    } else {
        Layer::Icmp { icmp_type: t, code, checksum_ok, id, seq, info }
    };
    d.layers.push(layer);
    d.payload_offset = base + 8;
    d.payload_len = data.len() - 8;
    Ok(())
}

pub fn icmpv4_name(t: u8, code: u8) -> String {
    match (t, code) {
        (0, _) => "echo reply".into(),
        (3, 0) => "destination unreachable: network".into(),
        (3, 1) => "destination unreachable: host".into(),
        (3, 2) => "destination unreachable: protocol".into(),
        (3, 3) => "destination unreachable: port".into(),
        (3, 4) => "destination unreachable: fragmentation needed".into(),
        (3, _) => format!("destination unreachable (code {code})"),
        (4, _) => "source quench".into(),
        (5, _) => "redirect".into(),
        (8, _) => "echo request".into(),
        (9, _) => "router advertisement".into(),
        (10, _) => "router solicitation".into(),
        (11, 0) => "time exceeded: TTL in transit".into(),
        (11, 1) => "time exceeded: fragment reassembly".into(),
        (12, _) => "parameter problem".into(),
        (13, _) => "timestamp request".into(),
        (14, _) => "timestamp reply".into(),
        _ => format!("type {t} code {code}"),
    }
}

pub fn icmpv6_name(t: u8, code: u8) -> String {
    match t {
        1 => "destination unreachable".into(),
        2 => "packet too big".into(),
        3 => "time exceeded".into(),
        4 => "parameter problem".into(),
        128 => "echo request".into(),
        129 => "echo reply".into(),
        130 => "multicast listener query".into(),
        131 => "multicast listener report".into(),
        132 => "multicast listener done".into(),
        133 => "router solicitation".into(),
        134 => "router advertisement".into(),
        135 => "neighbor solicitation".into(),
        136 => "neighbor advertisement".into(),
        137 => "redirect".into(),
        143 => "multicast listener report v2".into(),
        _ => format!("type {t} code {code}"),
    }
}

fn tcp(data: &[u8], base: usize, ip: &IpCtx, fragmented: bool, d: &mut Decoded) -> Result<(), Short> {
    let mut c = Cur { d: data, at: 0 };
    let src_port = c.u16("TCP header")?;
    let dst_port = c.u16("TCP header")?;
    let seq = c.u32("TCP header")?;
    let ack = c.u32("TCP header")?;
    let off_flags = c.u16("TCP header")?;
    let window = c.u16("TCP header")?;
    let checksum_field = c.u16("TCP header")?;
    let urgent = c.u16("TCP header")?;
    let header_len = ((off_flags >> 12) as usize) * 4;
    if header_len < 20 {
        d.notes.push(format!("TCP header length {header_len} is below the minimum of 20"));
        return Ok(());
    }
    let opts = data.get(20..header_len).ok_or(Short("TCP options"))?;
    let flags = TcpFlags {
        fin: off_flags & 0x01 != 0,
        syn: off_flags & 0x02 != 0,
        rst: off_flags & 0x04 != 0,
        psh: off_flags & 0x08 != 0,
        ack: off_flags & 0x10 != 0,
        urg: off_flags & 0x20 != 0,
        ece: off_flags & 0x40 != 0,
        cwr: off_flags & 0x80 != 0,
        ns: off_flags & 0x100 != 0,
    };
    let (options, bad_opt) = parse_tcp_options(opts);
    if let Some(m) = bad_opt {
        d.notes.push(m);
    }
    let payload = &data[header_len..];
    let checksum_ok = if fragmented {
        None
    } else {
        let ph = pseudo_header(&ip.src, &ip.dst, PROTO_TCP, data.len());
        Some(checksum(&[&ph, data]) == 0)
    };
    d.layers.push(Layer::Tcp {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        checksum: checksum_field,
        checksum_ok,
        urgent,
        header_len: header_len as u8,
        options,
        payload_len: payload.len(),
    });
    d.payload_offset = base + header_len;
    d.payload_len = payload.len();
    application(true, src_port, dst_port, payload, d);
    Ok(())
}

fn parse_tcp_options(mut o: &[u8]) -> (Vec<TcpOption>, Option<String>) {
    let mut out = Vec::new();
    while let Some((&kind, rest)) = o.split_first() {
        match kind {
            0 => break,
            1 => {
                out.push(TcpOption::Nop);
                o = rest;
            }
            _ => {
                let Some(&len) = rest.first() else { return (out, Some(format!("TCP option {kind} is cut off"))) };
                let len = len as usize;
                if len < 2 || len > o.len() {
                    return (out, Some(format!("TCP option {kind} has the impossible length {len}")));
                }
                let body = &o[2..len];
                out.push(match (kind, body.len()) {
                    (2, 2) => TcpOption::Mss(u16::from_be_bytes([body[0], body[1]])),
                    (3, 1) => TcpOption::WindowScale(body[0]),
                    (4, 0) => TcpOption::SackPermitted,
                    (5, n) if n % 8 == 0 => TcpOption::Sack(
                        body.chunks(8)
                            .map(|b| {
                                (u32::from_be_bytes(b[0..4].try_into().unwrap()), u32::from_be_bytes(b[4..8].try_into().unwrap()))
                            })
                            .collect(),
                    ),
                    (8, 8) => TcpOption::Timestamp {
                        value: u32::from_be_bytes(body[0..4].try_into().unwrap()),
                        echo: u32::from_be_bytes(body[4..8].try_into().unwrap()),
                    },
                    _ => TcpOption::Unknown { kind, len: len as u8 },
                });
                o = &o[len..];
            }
        }
    }
    (out, None)
}

fn udp(data: &[u8], base: usize, ip: &IpCtx, fragmented: bool, d: &mut Decoded) -> Result<(), Short> {
    let mut c = Cur { d: data, at: 0 };
    let src_port = c.u16("UDP header")?;
    let dst_port = c.u16("UDP header")?;
    let length = c.u16("UDP header")?;
    let checksum_field = c.u16("UDP header")?;
    let end = if (length as usize) < 8 {
        d.notes.push(format!("UDP length {length} is below the minimum of 8"));
        data.len()
    } else {
        (length as usize).min(data.len())
    };
    if length as usize > data.len() {
        d.notes.push(format!("UDP length {length} but only {} bytes were captured", data.len()));
    }
    let payload = &data[8..end.max(8)];
    let checksum_ok = if fragmented || (checksum_field == 0 && ip.src.len() == 4) || length as usize > data.len() {
        None
    } else {
        let ph = pseudo_header(&ip.src, &ip.dst, PROTO_UDP, length as usize);
        Some(checksum(&[&ph, &data[..length as usize]]) == 0)
    };
    d.layers.push(Layer::Udp { src_port, dst_port, length, checksum: checksum_field, checksum_ok, payload_len: payload.len() });
    d.payload_offset = base + 8;
    d.payload_len = payload.len();
    application(false, src_port, dst_port, payload, d);
    Ok(())
}

/// Recognises the application protocol from the ports and the payload itself.
fn application(is_tcp: bool, src: u16, dst: u16, payload: &[u8], d: &mut Decoded) {
    if payload.is_empty() {
        return;
    }
    let ports = [src, dst];
    if ports.iter().any(|p| matches!(p, 53 | 5353 | 5355)) {
        // DNS over TCP carries a two-byte length in front of the message.
        let msg = if is_tcp {
            if payload.len() >= 2 && usize::from(u16::from_be_bytes([payload[0], payload[1]])) + 2 <= payload.len() {
                Some(&payload[2..])
            } else {
                None
            }
        } else {
            Some(payload)
        };
        if let Some(m) = msg {
            match dns::parse(m) {
                Ok((dns, notes)) => {
                    d.layers.push(Layer::Dns(dns));
                    d.notes.extend(notes);
                    return;
                }
                Err(e) => d.notes.push(format!("not decoded as DNS: {e}")),
            }
        }
    }
    if !is_tcp && ports.contains(&67) | ports.contains(&68) {
        if let Some(dh) = app::parse_dhcp(payload) {
            d.layers.push(Layer::Dhcp(dh));
            return;
        }
    }
    if let Some(h) = app::parse_http(payload) {
        d.layers.push(Layer::Http(h));
        return;
    }
    if is_tcp {
        if let Some(t) = app::parse_tls(payload) {
            d.layers.push(Layer::Tls(t));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    const A: [u8; 4] = [192, 0, 2, 1];
    const B: [u8; 4] = [192, 0, 2, 2];

    fn tcp_layer(d: &Decoded) -> &Layer {
        d.tcp().expect("a TCP layer")
    }

    #[test]
    fn checksum_known_values() {
        // RFC 1071's example.
        assert_eq!(checksum(&[&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]]), !0xddf2u16);
        // An odd number of bytes, and the same data split across slices.
        assert_eq!(checksum(&[&[1, 2, 3]]), checksum(&[&[1, 2], &[3]]));
        assert_eq!(checksum(&[&[1], &[2, 3]]), checksum(&[&[1, 2, 3]]));
        assert_eq!(checksum(&[]), 0xffff);
    }

    #[test]
    fn ethernet_ipv4_tcp_syn_with_options() {
        let opts = [2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7];
        let seg = tcp_segment(A, B, 51234, 443, 1000, 0, 0x02, &opts, b"");
        let frame = eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, A, B, &seg));
        let d = decode(LINK_ETHERNET, &frame);
        assert!(d.truncated.is_none() && d.notes.is_empty(), "{:?}", d.notes);
        let names: Vec<&str> = d.layers.iter().map(Layer::name).collect();
        assert_eq!(names, vec!["Ethernet", "IPv4", "TCP"]);
        let Layer::Tcp { src_port, dst_port, seq, flags, options, checksum_ok, header_len, .. } = tcp_layer(&d) else { panic!() };
        assert_eq!((*src_port, *dst_port, *seq, *header_len), (51234, 443, 1000, 40));
        assert!(flags.syn && !flags.ack);
        assert_eq!(flags.names(), "[SYN]");
        assert_eq!(*checksum_ok, Some(true));
        assert_eq!(
            options,
            &vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp { value: 1, echo: 0 },
                TcpOption::Nop,
                TcpOption::WindowScale(7)
            ]
        );
        let Layer::Ipv4 { checksum_ok, ttl, .. } = &d.layers[1] else { panic!() };
        assert!(*checksum_ok && *ttl == 64);
    }

    #[test]
    fn corrupted_checksums_are_reported_not_hidden() {
        let seg = tcp_segment(A, B, 1, 2, 0, 0, 0x10, &[], b"data");
        let mut ip = ipv4_packet(PROTO_TCP, A, B, &seg);
        ip[30] ^= 0xff; // a payload byte
        ip[10] ^= 0x01; // the IP checksum
        let d = decode(LINK_ETHERNET, &eth_frame(ETH_IPV4, &ip));
        let Layer::Ipv4 { checksum_ok, .. } = &d.layers[1] else { panic!() };
        assert!(!*checksum_ok);
        let Layer::Tcp { checksum_ok, .. } = tcp_layer(&d) else { panic!() };
        assert_eq!(*checksum_ok, Some(false));
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        let udp = udp_datagram(A, B, 1000, 2000, b"hi");
        let mut frame = eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, A, B, &udp));
        frame.extend([0u8; 18]); // pad to the 60-byte minimum
        let d = decode(LINK_ETHERNET, &frame);
        let Layer::Udp { payload_len, length, checksum_ok, .. } = d.layers.last().unwrap() else { panic!() };
        assert_eq!((*payload_len, *length, *checksum_ok), (2, 10, Some(true)));
        assert!(d.notes.is_empty());
    }

    #[test]
    fn tcp_has_no_length_field_so_ethernet_padding_must_come_from_the_ip_length() {
        // A bare ACK is 54 bytes; Ethernet pads the frame to 60. Those six bytes are not TCP data.
        let seg = tcp_segment(A, B, 1, 2, 5, 6, 0x10, &[], b"");
        let mut frame = eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, A, B, &seg));
        frame.extend([0u8; 6]);
        assert_eq!(frame.len(), 60);
        let d = decode(LINK_ETHERNET, &frame);
        let Layer::Tcp { payload_len, checksum_ok, .. } = tcp_layer(&d) else { panic!() };
        assert_eq!((*payload_len, *checksum_ok), (0, Some(true)));
        assert_eq!(d.payload_len, 0);
    }

    #[test]
    fn a_udp_datagram_shorter_than_its_ip_payload_ends_where_udp_says() {
        let mut udp = udp_datagram(A, B, 1, 2, b"abcd");
        udp.extend(b"trailing bytes that belong to nobody");
        let d = decode(LINK_ETHERNET, &eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, A, B, &udp)));
        let Layer::Udp { payload_len, length, .. } = d.layers.last().unwrap() else { panic!() };
        assert_eq!((*payload_len, *length), (4, 12));
    }

    #[test]
    fn ipv6_authentication_header_counts_in_four_byte_units() {
        let udp = udp_datagram([0; 4], [0; 4], 9, 10, b"x");
        // Next header UDP, length 4 means (4 + 2) * 4 = 24 bytes in all.
        let mut body = vec![PROTO_UDP, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2];
        body.extend([0u8; 12]);
        body.extend(&udp);
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend((body.len() as u16).to_be_bytes());
        ip.extend([51, 64]);
        ip.extend([0u8; 32]);
        ip.extend(&body);
        let d = decode(LINK_RAW, &ip);
        assert!(d.has("UDP"), "{:?} {:?}", d.layers, d.notes);
        let Layer::Ipv6Extension { kind, len } = &d.layers[1] else { panic!() };
        assert_eq!((*kind, *len), (51, 24));
    }

    #[test]
    fn vlan_stacks_and_ip_options() {
        let udp = udp_datagram(A, B, 5, 6, b"x");
        let ip = ipv4_packet_with(PROTO_UDP, A, B, &udp, 0x4000, 8);
        // Outer 802.1ad tag then an inner 802.1Q tag.
        let mut frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        frame.extend(ETH_QINQ.to_be_bytes());
        frame.extend((0x2000u16 | 100).to_be_bytes()); // priority 1, id 100
        frame.extend(ETH_VLAN.to_be_bytes());
        frame.extend(200u16.to_be_bytes());
        frame.extend(ETH_IPV4.to_be_bytes());
        frame.extend(ip);
        let d = decode(LINK_ETHERNET, &frame);
        let names: Vec<&str> = d.layers.iter().map(Layer::name).collect();
        assert_eq!(names, vec!["Ethernet", "VLAN", "VLAN", "IPv4", "UDP"]);
        let Layer::Vlan { id, priority, .. } = &d.layers[1] else { panic!() };
        assert_eq!((*id, *priority), (100, 1));
        let Layer::Ipv4 { options_len, dont_fragment, header_len, checksum_ok, .. } = &d.layers[3] else { panic!() };
        assert_eq!((*options_len, *dont_fragment, *header_len, *checksum_ok), (8, true, 28, true));
    }

    #[test]
    fn fragments_are_not_decoded_as_transport() {
        let udp = udp_datagram(A, B, 5, 6, &[7u8; 40]);
        // The first fragment (offset 0, more fragments) keeps its UDP header; the second does not.
        let first = ipv4_packet_with(PROTO_UDP, A, B, &udp[..24], 0x2000, 0);
        let second = ipv4_packet_with(PROTO_UDP, A, B, &udp[24..], 3, 0); // offset 3 * 8 = 24
        let d1 = decode(LINK_ETHERNET, &eth_frame(ETH_IPV4, &first));
        assert!(d1.has("UDP") && d1.notes.iter().any(|n| n.contains("first fragment")));
        let d2 = decode(LINK_ETHERNET, &eth_frame(ETH_IPV4, &second));
        assert!(!d2.has("UDP") && d2.notes.iter().any(|n| n.contains("offset 24")));
        let Layer::Ipv4 { fragment_offset, more_fragments, .. } = &d2.layers[1] else { panic!() };
        assert_eq!((*fragment_offset, *more_fragments), (24, false));
    }

    #[test]
    fn truncation_is_named_at_every_cut() {
        let seg = tcp_segment(A, B, 1, 2, 0, 0, 0x02, &[2, 4, 5, 0xb4], b"");
        let frame = eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, A, B, &seg));
        let mut seen = std::collections::BTreeSet::new();
        for cut in 0..frame.len() {
            let d = decode(LINK_ETHERNET, &frame[..cut]);
            if let Some(t) = &d.truncated {
                seen.insert(t.clone());
            }
            assert!(d.truncated.is_some() || cut >= 14, "cut {cut}");
        }
        for want in ["Ethernet header", "IPv4 header", "TCP header", "TCP options"] {
            assert!(seen.contains(want), "{want} not named in {seen:?}");
        }
        assert!(decode(LINK_ETHERNET, &frame).truncated.is_none());
    }

    #[test]
    fn ipv6_with_extension_headers() {
        let (s6, d6) = (
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        );
        let mut tcp = tcp_segment([0; 4], [0; 4], 1, 2, 7, 0, 0x02, &[], b"");
        // The TCP checksum covers an IPv6 pseudo header; recompute it.
        tcp[16..18].copy_from_slice(&[0, 0]);
        let ph = pseudo_header(&s6, &d6, PROTO_TCP, tcp.len());
        let c = checksum(&[&ph, &tcp]);
        tcp[16..18].copy_from_slice(&c.to_be_bytes());
        // hop-by-hop (8 bytes), destination options (16 bytes), then TCP
        let mut body = vec![60, 0, 1, 4, 0, 0, 0, 0]; // next=dest-options, len 0 -> 8 bytes
        body.extend([PROTO_TCP, 1, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // next=tcp, len 1 -> 16 bytes
        body.extend(&tcp);
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend((body.len() as u16).to_be_bytes());
        ip.extend([0, 64]); // next header: hop-by-hop
        ip.extend(s6);
        ip.extend(d6);
        ip.extend(body);
        let d = decode(LINK_ETHERNET, &eth_frame(ETH_IPV6, &ip));
        assert!(d.truncated.is_none() && d.notes.is_empty(), "{:?} {:?}", d.truncated, d.notes);
        let names: Vec<&str> = d.layers.iter().map(Layer::name).collect();
        assert_eq!(names, vec!["Ethernet", "IPv6", "IPv6 extension", "IPv6 extension", "TCP"]);
        let Layer::Tcp { seq, checksum_ok, .. } = tcp_layer(&d) else { panic!() };
        assert_eq!((*seq, *checksum_ok), (7, Some(true)));
        let Layer::Ipv6 { src, hop_limit, .. } = &d.layers[1] else { panic!() };
        assert_eq!((src.to_string(), *hop_limit), ("2001:db8::1".to_string(), 64));
    }

    #[test]
    fn ipv6_fragment_headers() {
        let mut body = vec![PROTO_UDP, 0, 0x00, 0x01, 0, 0, 0, 9]; // offset 0, more fragments, id 9
        body.extend(udp_datagram([0; 4], [0; 4], 1, 2, b"abcd"));
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend((body.len() as u16).to_be_bytes());
        ip.extend([44, 64]);
        ip.extend([0u8; 32]);
        ip.extend(&body);
        let d = decode(LINK_RAW, &ip);
        assert!(d.has("UDP"));
        let Layer::Ipv6Fragment { more_fragments, id, .. } = &d.layers[1] else { panic!() };
        assert!(*more_fragments && *id == 9);
        // A later fragment: no transport layer.
        let mut later = ip.clone();
        later[40 + 3] = 0x0b; // offset 1 (8 bytes), no more
        later[40 + 2] = 0;
        let d = decode(LINK_RAW, &later);
        assert!(!d.has("UDP") && d.notes.iter().any(|n| n.contains("offset 8")));
    }

    #[test]
    fn arp_request_and_reply() {
        let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
        a.extend([2, 0, 0, 0, 0, 1]);
        a.extend(A);
        a.extend([0u8; 6]);
        a.extend(B);
        let d = decode(LINK_ETHERNET, &eth_frame(ETH_ARP, &a));
        let Layer::Arp { op, sender_ip, target_ip, sender_mac, .. } = &d.layers[1] else { panic!() };
        assert_eq!(
            (*op, sender_ip.to_string(), target_ip.to_string(), sender_mac.to_string()),
            (1, "192.0.2.1".into(), "192.0.2.2".into(), "02:00:00:00:00:01".into())
        );
    }

    #[test]
    fn icmp_echo_and_checksum() {
        let mut m = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x07, b'p', b'i', b'n', b'g'];
        let c = checksum(&[&m]);
        m[2..4].copy_from_slice(&c.to_be_bytes());
        let d = decode(LINK_ETHERNET, &eth_frame(ETH_IPV4, &ipv4_packet(PROTO_ICMP, A, B, &m)));
        let Layer::Icmp { icmp_type, id, seq, checksum_ok, info, .. } = d.layers.last().unwrap() else { panic!() };
        assert_eq!((*icmp_type, *id, *seq, *checksum_ok, info.as_str()), (8, Some(0x1234), Some(7), true, "echo request"));
    }

    #[test]
    fn other_link_types() {
        let udp = udp_datagram(A, B, 1, 2, b"x");
        let ip = ipv4_packet(PROTO_UDP, A, B, &udp);
        // Raw IP.
        assert!(decode(LINK_RAW, &ip).has("UDP"));
        // BSD loopback, little-endian AF_INET.
        let mut lo = vec![2, 0, 0, 0];
        lo.extend(&ip);
        let d = decode(LINK_NULL, &lo);
        assert!(d.has("Loopback") && d.has("UDP"));
        // Linux cooked capture.
        let mut sll = vec![0, 0, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0, 0x08, 0x00];
        sll.extend(&ip);
        assert!(decode(LINK_LINUX_SLL, &sll).has("UDP"));
        // An unsupported link type is reported, not guessed at.
        let d = decode(147, &ip);
        assert!(d.layers.is_empty() && d.notes[0].contains("not supported"));
    }

    #[test]
    fn tcp_option_errors_are_notes() {
        // MSS claiming a length that runs past the options.
        let (opts, err) = parse_tcp_options(&[2, 9, 0, 0]);
        assert!(opts.is_empty() && err.unwrap().contains("impossible length"));
        let (_, err) = parse_tcp_options(&[2]);
        assert!(err.unwrap().contains("cut off"));
        let (opts, err) = parse_tcp_options(&[1, 1, 0, 9, 9]); // data after the end-of-options marker is ignored
        assert_eq!((opts.len(), err), (2, None));
        let (opts, _) = parse_tcp_options(&[99, 4, 1, 2]);
        assert_eq!(opts, vec![TcpOption::Unknown { kind: 99, len: 4 }]);
    }

    #[test]
    fn random_bytes_never_panic_on_any_link_type() {
        let mut seed = 0x1234_5678u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let seg = tcp_segment(A, B, 51234, 80, 1, 2, 0x18, &[2, 4, 5, 0xb4], b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        let templates = [
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, A, B, &seg)),
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, A, B, &udp_datagram(A, B, 5000, 53, &[0; 40]))),
        ];
        for t in &templates {
            for _ in 0..20_000 {
                let mut v = t.clone();
                for _ in 0..(1 + next() % 5) {
                    let i = (next() as usize) % v.len();
                    v[i] = next() as u8;
                }
                if next() % 3 == 0 {
                    v.truncate((next() as usize) % v.len());
                }
                for link in [LINK_ETHERNET, LINK_NULL, LINK_RAW, LINK_LINUX_SLL, LINK_LINUX_SLL2, 999] {
                    let _ = decode(link, &v);
                }
            }
        }
        for _ in 0..5000 {
            let n = (next() % 120) as usize;
            let v: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            let _ = decode(LINK_ETHERNET, &v);
            let _ = decode(LINK_RAW, &v);
        }
    }
}
