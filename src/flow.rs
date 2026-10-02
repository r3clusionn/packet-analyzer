//! Conversations (flows) and capture statistics.
//!
//! A flow is all the packets between two endpoints with one transport protocol, in both
//! directions. The endpoint that sent the first packet (the SYN of a TCP connection, when the
//! capture has it) is called the client.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use serde::Serialize;

use crate::decode::{Decoded, Layer};
use crate::dns::{self, RData};
use crate::pcap::Packet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(a) => write!(f, "{a}:{}", self.port),
            IpAddr::V6(a) => write!(f, "[{a}]:{}", self.port),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl Proto {
    pub fn name(self) -> String {
        match self {
            Proto::Tcp => "TCP".into(),
            Proto::Udp => "UDP".into(),
            Proto::Icmp => "ICMP".into(),
            Proto::Icmpv6 => "ICMPv6".into(),
            Proto::Other(n) => format!("proto {n}"),
        }
    }
}

/// The identity of a flow: the protocol and the two endpoints in a fixed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub proto: Proto,
    pub a: Endpoint,
    pub b: Endpoint,
}

/// Who sent a packet, from the point of view of the flow's first packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Debug, Serialize)]
pub struct Flow {
    pub id: usize,
    pub proto: Proto,
    pub client: Endpoint,
    pub server: Endpoint,
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    pub first_ts: f64,
    pub last_ts: f64,
    pub first_packet: u64,
    pub syn: bool,
    pub syn_ack: bool,
    pub fin: u32,
    pub rst: bool,
    /// TCP segments carrying data that had been seen before at the same sequence number.
    pub retransmissions: u64,
}

impl Flow {
    pub fn state(&self) -> &'static str {
        match self.proto {
            Proto::Tcp => {
                if self.rst {
                    "reset"
                } else if self.fin >= 2 {
                    "closed"
                } else if self.fin == 1 {
                    "closing"
                } else if self.syn && self.syn_ack {
                    "established"
                } else if self.syn {
                    "syn sent"
                } else {
                    "midstream"
                }
            }
            _ => "",
        }
    }

    pub fn total_packets(&self) -> u64 {
        self.packets[0] + self.packets[1]
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes[0] + self.bytes[1]
    }
}

/// What the flow table needs to know about a packet.
pub struct FlowInfo {
    pub key: FlowKey,
    pub from: Endpoint,
    pub seq_and_len: Option<(u32, usize)>,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

/// Extracts the flow identity of a decoded packet; `None` for packets without an IP layer.
pub fn flow_info(d: &Decoded) -> Option<FlowInfo> {
    let (src, dst) = d.layers.iter().find_map(|l| match l {
        Layer::Ipv4 { src, dst, .. } => Some((IpAddr::from(*src), IpAddr::from(*dst))),
        Layer::Ipv6 { src, dst, .. } => Some((IpAddr::from(*src), IpAddr::from(*dst))),
        _ => None,
    })?;
    let mut info = (Proto::Other(0), 0u16, 0u16, None, (false, false, false, false));
    let mut found = false;
    for l in &d.layers {
        match l {
            Layer::Tcp { src_port, dst_port, seq, flags, payload_len, .. } => {
                info =
                    (Proto::Tcp, *src_port, *dst_port, Some((*seq, *payload_len)), (flags.syn, flags.ack, flags.fin, flags.rst));
                found = true;
            }
            Layer::Udp { src_port, dst_port, .. } => {
                info = (Proto::Udp, *src_port, *dst_port, None, (false, false, false, false));
                found = true;
            }
            Layer::Icmp { .. } => {
                info.0 = Proto::Icmp;
                found = true;
            }
            Layer::Icmpv6 { .. } => {
                info.0 = Proto::Icmpv6;
                found = true;
            }
            _ => {}
        }
    }
    if !found {
        return None;
    }
    let (proto, sp, dp, seq_and_len, (syn, ack, fin, rst)) = info;
    let (from, to) = (Endpoint { ip: src, port: sp }, Endpoint { ip: dst, port: dp });
    let (a, b) = if from <= to { (from, to) } else { (to, from) };
    Some(FlowInfo { key: FlowKey { proto, a, b }, from, seq_and_len, syn, ack, fin, rst })
}

#[derive(Default)]
pub struct FlowTable {
    index: HashMap<FlowKey, usize>,
    flows: Vec<Flow>,
    /// Per flow and direction, the (sequence, length) of data segments already seen.
    seen: Vec<[HashSet<(u32, usize)>; 2]>,
}

impl FlowTable {
    pub fn new() -> FlowTable {
        FlowTable::default()
    }

    /// Adds a packet; returns the flow it belongs to and the direction it travels in.
    pub fn add(&mut self, p: &Packet, d: &Decoded) -> Option<(usize, Direction)> {
        let info = flow_info(d)?;
        let idx = *self.index.entry(info.key).or_insert_with(|| {
            let id = self.flows.len();
            // The first packet's sender is the client, unless this is a SYN-ACK (a capture that missed the SYN).
            let from_is_server = info.syn && info.ack;
            let other = if info.from == info.key.a { info.key.b } else { info.key.a };
            let (client, server) = if from_is_server { (other, info.from) } else { (info.from, other) };
            self.flows.push(Flow {
                id,
                proto: info.key.proto,
                client,
                server,
                packets: [0; 2],
                bytes: [0; 2],
                first_ts: p.time(),
                last_ts: p.time(),
                first_packet: p.number,
                syn: false,
                syn_ack: false,
                fin: 0,
                rst: false,
                retransmissions: 0,
            });
            self.seen.push([HashSet::new(), HashSet::new()]);
            id
        });
        let f = &mut self.flows[idx];
        let dir = if info.from == f.client { Direction::ClientToServer } else { Direction::ServerToClient };
        let di = dir as usize;
        f.packets[di] += 1;
        f.bytes[di] += p.orig_len as u64;
        f.last_ts = f.last_ts.max(p.time());
        if info.syn && !info.ack {
            f.syn = true;
        }
        if info.syn && info.ack {
            f.syn_ack = true;
        }
        if info.fin {
            f.fin += 1;
        }
        f.rst |= info.rst;
        if let Some((seq, len)) = info.seq_and_len {
            if len > 0 && !self.seen[idx][di].insert((seq, len)) {
                f.retransmissions += 1;
            }
        }
        Some((idx, dir))
    }

    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    pub fn get(&self, id: usize) -> Option<&Flow> {
        self.flows.get(id)
    }
}

/// Counts that summarise a whole capture.
#[derive(Default, Debug, Serialize)]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    pub first_ts: Option<f64>,
    pub last_ts: Option<f64>,
    pub min_len: Option<u32>,
    pub max_len: u32,
    /// Packets by the highest protocol decoded.
    pub protocols: BTreeMap<String, (u64, u64)>,
    /// Bytes sent and received per IP address.
    pub hosts: BTreeMap<IpAddr, (u64, u64)>,
    pub truncated_packets: u64,
    pub undecoded_packets: u64,
    pub dns_queries: BTreeMap<String, u64>,
    pub dns_nxdomain: u64,
    pub tls_sni: BTreeMap<String, u64>,
    pub http_hosts: BTreeMap<String, u64>,
    pub tcp_syn: u64,
    pub tcp_rst: u64,
    /// Packets per whole second since the first packet, for the busiest second.
    pub peak_pps: u64,
    #[serde(skip)]
    per_second: BTreeMap<u64, u64>,
}

/// The highest protocol layer that was decoded, as shown in the summary and the statistics.
pub fn top_protocol(d: &Decoded) -> String {
    for l in d.layers.iter().rev() {
        if !matches!(l, Layer::Ipv6Extension { .. } | Layer::Ipv6Fragment { .. }) {
            return l.name().to_string();
        }
    }
    "unknown".to_string()
}

impl Stats {
    pub fn add(&mut self, p: &Packet, d: &Decoded) {
        self.packets += 1;
        self.bytes += p.orig_len as u64;
        let t = p.time();
        let first = *self.first_ts.get_or_insert(t);
        self.last_ts = Some(self.last_ts.map_or(t, |l| l.max(t)));
        self.min_len = Some(self.min_len.map_or(p.orig_len, |m| m.min(p.orig_len)));
        self.max_len = self.max_len.max(p.orig_len);
        let e = self.protocols.entry(top_protocol(d)).or_default();
        e.0 += 1;
        e.1 += p.orig_len as u64;
        if d.truncated.is_some() {
            self.truncated_packets += 1;
        }
        if d.layers.is_empty() {
            self.undecoded_packets += 1;
        }
        if let Some(info) = flow_info(d) {
            let to = if info.from == info.key.a { info.key.b } else { info.key.a };
            self.hosts.entry(info.from.ip).or_default().0 += p.orig_len as u64;
            self.hosts.entry(to.ip).or_default().1 += p.orig_len as u64;
        }
        if let Some(Layer::Tcp { flags, .. }) = d.tcp() {
            if flags.syn && !flags.ack {
                self.tcp_syn += 1;
            }
            if flags.rst {
                self.tcp_rst += 1;
            }
        }
        if let Some(dns) = d.dns() {
            if !dns.response {
                for q in &dns.questions {
                    *self.dns_queries.entry(q.name.to_ascii_lowercase()).or_default() += 1;
                }
            } else if dns.rcode == 3 {
                self.dns_nxdomain += 1;
            }
        }
        if let Some(tls) = d.tls() {
            for r in &tls.records {
                if let Some(crate::app::Handshake::ClientHello { sni: Some(s), .. }) = &r.handshake {
                    *self.tls_sni.entry(s.to_ascii_lowercase()).or_default() += 1;
                }
            }
        }
        if let Some(h) = d.http() {
            if h.is_request {
                if let Some(host) = h.header("host") {
                    *self.http_hosts.entry(host.to_ascii_lowercase()).or_default() += 1;
                }
            }
        }
        let sec = (t - first).max(0.0) as u64;
        let c = self.per_second.entry(sec).or_default();
        *c += 1;
        self.peak_pps = self.peak_pps.max(*c);
    }

    pub fn duration(&self) -> f64 {
        match (self.first_ts, self.last_ts) {
            (Some(a), Some(b)) => (b - a).max(0.0),
            _ => 0.0,
        }
    }
}

/// One DNS exchange: a query and, if one was captured, its response.
#[derive(Debug, Clone, Serialize)]
pub struct DnsExchange {
    pub query_packet: u64,
    pub time: f64,
    pub client: Endpoint,
    pub server: Endpoint,
    pub id: u16,
    pub name: String,
    pub qtype: String,
    pub response_packet: Option<u64>,
    pub latency_ms: Option<f64>,
    pub rcode: Option<String>,
    pub answers: Vec<String>,
}

/// Pairs DNS queries with their responses (same client, server, port and transaction id).
#[derive(Default)]
pub struct DnsTracker {
    pending: HashMap<(Endpoint, Endpoint, u16), usize>,
    pub exchanges: Vec<DnsExchange>,
}

impl DnsTracker {
    pub fn new() -> DnsTracker {
        DnsTracker::default()
    }

    pub fn add(&mut self, p: &Packet, d: &Decoded) {
        let (Some(dns), Some(info)) = (d.dns(), flow_info(d)) else { return };
        let to = if info.from == info.key.a { info.key.b } else { info.key.a };
        if !dns.response {
            let q = dns.questions.first();
            let idx = self.exchanges.len();
            self.exchanges.push(DnsExchange {
                query_packet: p.number,
                time: p.time(),
                client: info.from,
                server: to,
                id: dns.id,
                name: q.map(|q| q.name.clone()).unwrap_or_default(),
                qtype: q.map(|q| dns::type_name(q.qtype)).unwrap_or_default(),
                response_packet: None,
                latency_ms: None,
                rcode: None,
                answers: Vec::new(),
            });
            self.pending.insert((info.from, to, dns.id), idx);
        } else if let Some(idx) = self.pending.remove(&(to, info.from, dns.id)) {
            let ex = &mut self.exchanges[idx];
            ex.response_packet = Some(p.number);
            ex.latency_ms = Some((p.time() - ex.time) * 1000.0);
            ex.rcode = Some(dns::rcode_name(dns.rcode).to_string());
            ex.answers = dns
                .answers
                .iter()
                .filter(|r| !matches!(r.data, RData::Opt { .. }))
                .map(|r| format!("{} {}", dns::type_name(r.rtype), dns::rdata_text(&r.data)))
                .collect();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode, ETH_IPV4, PROTO_TCP, PROTO_UDP};
    use crate::testutil::*;

    const C: [u8; 4] = [192, 0, 2, 1];
    const S: [u8; 4] = [198, 51, 100, 7];

    fn pkt(n: u64, t: f64, data: Vec<u8>) -> (Packet, Decoded) {
        let p = Packet {
            number: n,
            ts_sec: t as u64,
            ts_nsec: ((t.fract()) * 1e9) as u32,
            link: 1,
            orig_len: data.len() as u32,
            data,
            iface: 0,
        };
        let d = decode(1, &p.data);
        (p, d)
    }

    fn tcp(n: u64, t: f64, from_client: bool, seq: u32, flags: u8, payload: &[u8]) -> (Packet, Decoded) {
        let (src, dst, sp, dp) = if from_client { (C, S, 50000, 443) } else { (S, C, 443, 50000) };
        pkt(
            n,
            t,
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, src, dst, &tcp_segment(src, dst, sp, dp, seq, 0, flags, &[], payload))),
        )
    }

    #[test]
    fn a_tcp_connection_is_one_flow_with_a_client_and_a_server() {
        let mut t = FlowTable::new();
        for (p, d) in [
            tcp(1, 0.0, true, 100, 0x02, b""),
            tcp(2, 0.1, false, 900, 0x12, b""),
            tcp(3, 0.2, true, 101, 0x10, b""),
            tcp(4, 0.3, true, 101, 0x18, b"hello"),
            tcp(5, 0.4, true, 101, 0x18, b"hello"),
            tcp(6, 0.5, false, 901, 0x11, b""),
            tcp(7, 0.6, true, 106, 0x11, b""),
        ] {
            t.add(&p, &d).unwrap();
        }
        assert_eq!(t.flows().len(), 1);
        let f = &t.flows()[0];
        assert_eq!((f.client.to_string(), f.server.to_string()), ("192.0.2.1:50000".into(), "198.51.100.7:443".into()));
        assert_eq!((f.packets, f.retransmissions, f.fin), ([5, 2], 1, 2));
        assert!(f.syn && f.syn_ack);
        assert_eq!(f.state(), "closed");
        assert!((f.last_ts - f.first_ts - 0.6).abs() < 1e-6);
    }

    #[test]
    fn a_capture_that_starts_with_a_syn_ack_knows_who_the_server_is() {
        let mut t = FlowTable::new();
        let (p, d) = tcp(1, 0.0, false, 900, 0x12, b"");
        t.add(&p, &d);
        let f = &t.flows()[0];
        assert_eq!((f.client.port, f.server.port), (50000, 443));
        let (p, d) = tcp(2, 0.1, true, 100, 0x10, b"");
        assert_eq!(t.add(&p, &d).unwrap().1, Direction::ClientToServer);
    }

    #[test]
    fn midstream_resets_and_separate_connections() {
        let mut t = FlowTable::new();
        let (p, d) = tcp(1, 0.0, true, 5, 0x10, b"x");
        t.add(&p, &d);
        assert_eq!(t.flows()[0].state(), "midstream");
        let (p, d) = tcp(2, 0.1, false, 5, 0x04, b"");
        t.add(&p, &d);
        assert_eq!(t.flows()[0].state(), "reset");
        // The same addresses on other ports is another flow.
        let other =
            pkt(3, 0.2, eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, C, S, &tcp_segment(C, S, 50001, 443, 1, 0, 0x02, &[], b""))));
        t.add(&other.0, &other.1);
        assert_eq!(t.flows().len(), 2);
        assert_eq!(t.get(1).unwrap().id, 1);
    }

    #[test]
    fn non_ip_packets_have_no_flow() {
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1];
        arp.extend(C);
        arp.extend([0u8; 6]);
        arp.extend(S);
        let (p, d) = pkt(1, 0.0, eth_frame(0x0806, &arp));
        let mut t = FlowTable::new();
        assert!(t.add(&p, &d).is_none());
        assert!(t.flows().is_empty());
    }

    fn dns_msg(id: u16, response: bool, name: &str, answer: Option<[u8; 4]>, rcode: u8) -> Vec<u8> {
        let flags: u16 = if response { 0x8180 | rcode as u16 } else { 0x0100 };
        let mut m = Vec::new();
        m.extend(id.to_be_bytes());
        m.extend(flags.to_be_bytes());
        m.extend([0, 1, 0, answer.is_some() as u8, 0, 0, 0, 0]);
        for l in name.split('.') {
            m.push(l.len() as u8);
            m.extend(l.as_bytes());
        }
        m.extend([0, 0, 1, 0, 1]);
        if let Some(a) = answer {
            m.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            m.extend(a);
        }
        m
    }

    fn udp_pkt(n: u64, t: f64, from_client: bool, payload: &[u8]) -> (Packet, Decoded) {
        let (src, dst, sp, dp) = if from_client { (C, S, 40000, 53) } else { (S, C, 53, 40000) };
        pkt(n, t, eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, src, dst, &udp_datagram(src, dst, sp, dp, payload))))
    }

    #[test]
    fn dns_exchanges_are_paired_with_latency() {
        let mut tr = DnsTracker::new();
        for (p, d) in [
            udp_pkt(1, 1.000, true, &dns_msg(7, false, "a.example.com", None, 0)),
            udp_pkt(2, 1.002, true, &dns_msg(8, false, "missing.example.com", None, 0)),
            udp_pkt(3, 1.0125, false, &dns_msg(7, true, "a.example.com", Some([93, 184, 216, 34]), 0)),
            udp_pkt(4, 1.0300, false, &dns_msg(8, true, "missing.example.com", None, 3)),
            udp_pkt(5, 2.000, true, &dns_msg(9, false, "unanswered.example.com", None, 0)),
        ] {
            tr.add(&p, &d);
        }
        let e = &tr.exchanges;
        assert_eq!(e.len(), 3);
        assert_eq!((e[0].name.as_str(), e[0].qtype.as_str(), e[0].response_packet), ("a.example.com", "A", Some(3)));
        assert!((e[0].latency_ms.unwrap() - 12.5).abs() < 0.01);
        assert_eq!((e[0].rcode.as_deref(), e[0].answers.as_slice()), (Some("NOERROR"), &["A 93.184.216.34".to_string()][..]));
        assert_eq!(e[1].rcode.as_deref(), Some("NXDOMAIN"));
        assert!(e[2].response_packet.is_none() && e[2].latency_ms.is_none());
    }

    #[test]
    fn a_response_with_the_wrong_id_or_server_is_not_paired() {
        let mut tr = DnsTracker::new();
        let (p, d) = udp_pkt(1, 0.0, true, &dns_msg(7, false, "x.example.com", None, 0));
        tr.add(&p, &d);
        let (p, d) = udp_pkt(2, 0.1, false, &dns_msg(8, true, "x.example.com", Some([1, 1, 1, 1]), 0));
        tr.add(&p, &d);
        assert!(tr.exchanges[0].response_packet.is_none());
    }

    #[test]
    fn statistics() {
        let mut s = Stats::default();
        let mut table = FlowTable::new();
        let q = dns_msg(1, false, "Example.COM", None, 0);
        let nx = dns_msg(1, true, "example.com", None, 3);
        let list = [
            tcp(1, 0.0, true, 1, 0x02, b""),
            tcp(2, 0.5, false, 1, 0x14, b""),
            udp_pkt(3, 0.7, true, &q),
            udp_pkt(4, 0.8, false, &nx),
            tcp(5, 2.5, true, 2, 0x10, b"data"),
        ];
        for (p, d) in &list {
            s.add(p, d);
            table.add(p, d);
        }
        assert_eq!((s.packets, s.tcp_syn, s.tcp_rst, s.dns_nxdomain), (5, 1, 1, 1));
        assert_eq!(s.dns_queries.get("example.com"), Some(&1));
        assert!((s.duration() - 2.5).abs() < 1e-6);
        assert_eq!(s.protocols.get("TCP").map(|v| v.0), Some(3));
        assert_eq!(s.protocols.get("DNS").map(|v| v.0), Some(2));
        assert_eq!(s.peak_pps, 4, "four packets fall in the first two seconds' first bucket");
        let c = s.hosts.get(&IpAddr::from(C)).unwrap();
        let sv = s.hosts.get(&IpAddr::from(S)).unwrap();
        assert!(c.0 > 0 && c.1 > 0 && sv.0 > 0 && sv.1 > 0);
        assert_eq!(s.undecoded_packets, 0);
        assert_eq!(table.flows().len(), 2);
    }
}
