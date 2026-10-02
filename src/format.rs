//! Turning decoded packets into text: one-line summaries, verbose layer dumps, hex dumps and JSON.

use std::fmt::Write;

use serde::Serialize;

use crate::app::{dhcp_type_name, handshake_name, tls_version_name, Handshake};
use crate::decode::{Decoded, Layer, TcpOption};
use crate::dns::{self, RData};
use crate::flow::top_protocol;
use crate::pcap::Packet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeMode {
    /// Seconds since the first packet.
    Relative,
    /// Seconds since the previous packet.
    Delta,
    /// Time of day, UTC.
    Absolute,
    /// Seconds since 1970.
    Epoch,
}

pub struct Style {
    pub time: TimeMode,
    /// Also say when a checksum is wrong (captures taken on the sending machine often have checksums
    /// that the network card has not filled in yet).
    pub checksums: bool,
}

pub fn format_time(p: &Packet, first: f64, prev: f64, mode: TimeMode) -> String {
    let t = p.time();
    match mode {
        TimeMode::Relative => format!("{:.6}", t - first),
        TimeMode::Delta => format!("{:.6}", (t - prev).max(0.0)),
        TimeMode::Epoch => format!("{t:.6}"),
        TimeMode::Absolute => {
            let s = p.ts_sec % 86_400;
            format!("{:02}:{:02}:{:02}.{:06}", s / 3600, s % 3600 / 60, s % 60, p.ts_nsec / 1000)
        }
    }
}

fn endpoint(ip: &std::net::IpAddr, port: Option<u16>) -> String {
    match (ip, port) {
        (std::net::IpAddr::V6(a), Some(p)) => format!("[{a}]:{p}"),
        (a, Some(p)) => format!("{a}:{p}"),
        (a, None) => a.to_string(),
    }
}

/// The (source, destination) shown in the summary line.
fn endpoints(d: &Decoded) -> (String, String) {
    let ports = d.layers.iter().find_map(|l| match l {
        Layer::Tcp { src_port, dst_port, .. } | Layer::Udp { src_port, dst_port, .. } => Some((*src_port, *dst_port)),
        _ => None,
    });
    for l in &d.layers {
        match l {
            Layer::Ipv4 { src, dst, .. } => {
                return (endpoint(&(*src).into(), ports.map(|p| p.0)), endpoint(&(*dst).into(), ports.map(|p| p.1)))
            }
            Layer::Ipv6 { src, dst, .. } => {
                return (endpoint(&(*src).into(), ports.map(|p| p.0)), endpoint(&(*dst).into(), ports.map(|p| p.1)))
            }
            Layer::Arp { sender_ip, target_ip, .. } => return (sender_ip.to_string(), target_ip.to_string()),
            _ => {}
        }
    }
    for l in &d.layers {
        if let Layer::Ethernet { src, dst, .. } = l {
            return (src.to_string(), dst.to_string());
        }
    }
    ("-".into(), "-".into())
}

fn tcp_info(l: &Layer) -> String {
    let Layer::Tcp { src_port, dst_port, seq, ack, flags, window, options, payload_len, .. } = l else { return String::new() };
    let mut s = format!("{src_port} > {dst_port} {} Seq={seq}", flags.names());
    if flags.ack {
        let _ = write!(s, " Ack={ack}");
    }
    let _ = write!(s, " Win={window} Len={payload_len}");
    for o in options {
        match o {
            TcpOption::Mss(m) => {
                let _ = write!(s, " MSS={m}");
            }
            TcpOption::WindowScale(w) => {
                let _ = write!(s, " WS={}", 1u32 << (*w).min(14));
            }
            TcpOption::SackPermitted => s.push_str(" SACK_PERM"),
            TcpOption::Sack(b) => {
                let _ = write!(s, " SACK={}", b.iter().map(|(l, r)| format!("{l}-{r}")).collect::<Vec<_>>().join(","));
            }
            TcpOption::Timestamp { value, echo } => {
                let _ = write!(s, " TSval={value} TSecr={echo}");
            }
            _ => {}
        }
    }
    s
}

fn dns_info(d: &dns::Dns) -> String {
    let q = d.questions.first().map(|q| format!("{} {}", dns::type_name(q.qtype), q.name)).unwrap_or_default();
    if !d.response {
        return format!("query id={:#06x} {q}", d.id);
    }
    let answers: Vec<String> =
        d.answers.iter().filter(|r| !matches!(r.data, RData::Opt { .. })).map(|r| dns::rdata_text(&r.data)).collect();
    let tail = if answers.is_empty() { String::new() } else { format!(" -> {}", answers.join(", ")) };
    format!("response id={:#06x} {q}{tail} ({})", d.id, dns::rcode_name(d.rcode))
}

fn http_info(h: &crate::app::Http) -> String {
    if h.is_request {
        let mut s = format!("{} {} {}", h.method.as_deref().unwrap_or(""), h.target.as_deref().unwrap_or(""), h.version);
        if let Some(host) = h.header("host") {
            let _ = write!(s, " Host: {host}");
        }
        s
    } else {
        let mut s = format!("{} {} {}", h.version, h.status.unwrap_or(0), h.reason.as_deref().unwrap_or(""));
        let s2 = s.trim_end().to_string();
        s = s2;
        let mut extra = Vec::new();
        if let Some(t) = h.header("content-type") {
            extra.push(t.split(';').next().unwrap_or(t).trim().to_string());
        }
        if let Some(l) = h.header("content-length") {
            extra.push(format!("{l} bytes"));
        }
        if !extra.is_empty() {
            let _ = write!(s, " ({})", extra.join(", "));
        }
        s
    }
}

fn tls_info(t: &crate::app::Tls) -> String {
    let parts: Vec<String> = t
        .records
        .iter()
        .map(|r| match (&r.handshake, r.alert, r.content_type) {
            (Some(Handshake::ClientHello { sni, alpn, supported_versions, version, .. }), _, _) => {
                let mut s = "ClientHello".to_string();
                if let Some(n) = sni {
                    let _ = write!(s, " sni={n}");
                }
                if !alpn.is_empty() {
                    let _ = write!(s, " alpn={}", alpn.join(","));
                }
                let versions: Vec<String> = if supported_versions.is_empty() {
                    vec![tls_version_name(*version)]
                } else {
                    supported_versions.iter().map(|v| tls_version_name(*v)).collect()
                };
                let _ = write!(s, " versions={}", versions.join(","));
                s
            }
            (Some(Handshake::ServerHello { version, cipher_suite, selected_version, .. }), _, _) => {
                format!("ServerHello {} cipher={cipher_suite:#06x}", tls_version_name(selected_version.unwrap_or(*version)))
            }
            (Some(Handshake::Other { kind, .. }), _, _) => handshake_name(*kind).to_string(),
            (None, Some((level, desc)), 21) => format!("Alert level={level} description={desc}"),
            (_, _, 20) => "ChangeCipherSpec".to_string(),
            (_, _, 23) => format!("Application Data ({} bytes)", r.length),
            (_, _, c) => format!("record type {c}"),
        })
        .collect();
    parts.join(" | ")
}

/// The part of the summary line after the protocol and length.
pub fn info(d: &Decoded) -> String {
    let mut parts: Vec<String> = Vec::new();
    for l in d.layers.iter().rev() {
        match l {
            Layer::Dns(x) => {
                parts.push(dns_info(x));
                break;
            }
            Layer::Http(x) => {
                parts.push(http_info(x));
                break;
            }
            Layer::Tls(x) => {
                parts.push(tls_info(x));
                break;
            }
            Layer::Dhcp(x) => {
                let mut s = format!("{} xid={:#x}", x.message_type.map(dhcp_type_name).unwrap_or("message"), x.xid);
                if !x.your_ip.is_unspecified() {
                    let _ = write!(s, " your={}", x.your_ip);
                }
                if let Some(h) = &x.hostname {
                    let _ = write!(s, " host={h}");
                }
                parts.push(s);
                break;
            }
            Layer::Tcp { .. } => {
                parts.push(tcp_info(l));
                break;
            }
            Layer::Udp { src_port, dst_port, payload_len, .. } => {
                parts.push(format!("{src_port} > {dst_port} Len={payload_len}"));
                break;
            }
            Layer::Icmp { info, id, seq, .. } | Layer::Icmpv6 { info, id, seq, .. } => {
                let mut s = info.clone();
                if let (Some(i), Some(q)) = (id, seq) {
                    let _ = write!(s, " id={i:#06x} seq={q}");
                }
                parts.push(s);
                break;
            }
            Layer::Arp { op, sender_mac, sender_ip, target_ip, .. } => {
                parts.push(match op {
                    1 => format!("who-has {target_ip} tell {sender_ip}"),
                    2 => format!("{sender_ip} is-at {sender_mac}"),
                    o => format!("operation {o}"),
                });
                break;
            }
            Layer::Ipv4 { protocol, fragment_offset, more_fragments, .. } if *fragment_offset != 0 || *more_fragments => {
                parts.push(format!(
                    "fragment of protocol {protocol}, offset {fragment_offset}{}",
                    if *more_fragments { ", more to follow" } else { "" }
                ));
                break;
            }
            Layer::Ipv4 { protocol, .. } => {
                parts.push(format!("protocol {protocol}"));
                break;
            }
            Layer::Ipv6 { next_header, .. } => {
                parts.push(format!("next header {next_header}"));
                break;
            }
            Layer::Ethernet { ethertype, .. } => {
                parts.push(format!("EtherType {ethertype:#06x}"));
                break;
            }
            _ => {}
        }
    }
    let mut s = parts.join(" ");
    if let Some(t) = &d.truncated {
        let _ = write!(s, " [truncated: {t}]");
    }
    s
}

/// One summary line for a packet.
pub fn summary(p: &Packet, d: &Decoded, first: f64, prev: f64, style: &Style) -> String {
    let (src, dst) = endpoints(d);
    let mut line = format!(
        "{:>6} {:>11} {src} > {dst} {} {} {}",
        p.number,
        format_time(p, first, prev, style.time),
        top_protocol(d),
        p.orig_len,
        info(d)
    );
    if style.checksums {
        let bad = d.layers.iter().any(|l| match l {
            Layer::Ipv4 { checksum_ok, .. } => !*checksum_ok,
            Layer::Icmp { checksum_ok, .. } | Layer::Icmpv6 { checksum_ok, .. } => !*checksum_ok,
            Layer::Tcp { checksum_ok, .. } | Layer::Udp { checksum_ok, .. } => *checksum_ok == Some(false),
            _ => false,
        });
        if bad {
            line.push_str(" [bad checksum]");
        }
    }
    line.trim_end().to_string()
}

fn describe(l: &Layer) -> Vec<String> {
    match l {
        Layer::Ethernet { dst, src, ethertype } => {
            vec![format!("destination {dst}"), format!("source {src}"), format!("type {ethertype:#06x}")]
        }
        Layer::Vlan { id, priority, dei, ethertype } => {
            vec![format!("id {id}, priority {priority}, drop-eligible {dei}"), format!("type {ethertype:#06x}")]
        }
        Layer::LinuxSll { packet_type, protocol, .. } => {
            vec![format!("packet type {packet_type}"), format!("protocol {protocol:#06x}")]
        }
        Layer::Loopback { family } => vec![format!("address family {family}")],
        Layer::Arp { op, sender_mac, sender_ip, target_mac, target_ip } => vec![
            format!("operation {op}"),
            format!("sender {sender_mac} {sender_ip}"),
            format!("target {target_mac} {target_ip}"),
        ],
        Layer::Ipv4 {
            src,
            dst,
            protocol,
            ttl,
            id,
            dscp,
            ecn,
            dont_fragment,
            more_fragments,
            fragment_offset,
            header_len,
            total_len,
            checksum,
            checksum_ok,
            options_len,
        } => vec![
            format!("{src} > {dst}, protocol {protocol}, ttl {ttl}"),
            format!("header {header_len} bytes ({options_len} of options), total length {total_len}, id {id:#06x}"),
            format!("flags: DF={dont_fragment} MF={more_fragments}, fragment offset {fragment_offset}, dscp {dscp}, ecn {ecn}"),
            format!("checksum {checksum:#06x} ({})", if *checksum_ok { "correct" } else { "wrong" }),
        ],
        Layer::Ipv6 { src, dst, next_header, hop_limit, traffic_class, flow_label, payload_len } => vec![
            format!("{src} > {dst}, next header {next_header}, hop limit {hop_limit}"),
            format!("payload {payload_len} bytes, traffic class {traffic_class}, flow label {flow_label:#07x}"),
        ],
        Layer::Ipv6Fragment { next_header, offset, more_fragments, id } => {
            vec![format!("next header {next_header}, offset {offset}, more fragments {more_fragments}, id {id:#x}")]
        }
        Layer::Ipv6Extension { kind, len } => vec![format!("type {kind}, {len} bytes")],
        Layer::Icmp { icmp_type, code, checksum_ok, info, .. } | Layer::Icmpv6 { icmp_type, code, checksum_ok, info, .. } => {
            vec![
                format!("type {icmp_type} code {code}: {info}"),
                format!("checksum {}", if *checksum_ok { "correct" } else { "wrong" }),
            ]
        }
        Layer::Tcp {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            checksum,
            checksum_ok,
            urgent,
            header_len,
            options,
            payload_len,
        } => {
            let mut v = vec![
                format!("{src_port} > {dst_port} {}", flags.names()),
                format!("seq {seq}, ack {ack}, window {window}, urgent {urgent}"),
                format!("header {header_len} bytes, payload {payload_len} bytes"),
                format!(
                    "checksum {checksum:#06x} ({})",
                    match checksum_ok {
                        Some(true) => "correct",
                        Some(false) => "wrong",
                        None => "not checked, fragmented",
                    }
                ),
            ];
            if !options.is_empty() {
                v.push(format!("options {options:?}"));
            }
            v
        }
        Layer::Udp { src_port, dst_port, length, checksum, checksum_ok, payload_len } => vec![
            format!("{src_port} > {dst_port}, length {length}, payload {payload_len} bytes"),
            format!(
                "checksum {checksum:#06x} ({})",
                match checksum_ok {
                    Some(true) => "correct",
                    Some(false) => "wrong",
                    None => "not used or not checked",
                }
            ),
        ],
        Layer::Dns(x) => {
            let mut v = vec![format!(
                "id {:#06x}, {}, opcode {}, rcode {}",
                x.id,
                if x.response { "response" } else { "query" },
                x.opcode,
                dns::rcode_name(x.rcode)
            )];
            v.push(format!(
                "flags: AA={} TC={} RD={} RA={}",
                x.authoritative, x.truncated, x.recursion_desired, x.recursion_available
            ));
            for q in &x.questions {
                v.push(format!("question {} {}", dns::type_name(q.qtype), q.name));
            }
            for (label, list) in [("answer", &x.answers), ("authority", &x.authorities), ("additional", &x.additionals)] {
                for r in list {
                    v.push(format!("{label} {} {} ttl {} {}", r.name, dns::type_name(r.rtype), r.ttl, dns::rdata_text(&r.data)));
                }
            }
            v
        }
        Layer::Http(h) => {
            let mut v = vec![http_info(h)];
            v.extend(h.headers.iter().map(|(n, val)| format!("{n}: {val}")));
            if !h.headers_complete {
                v.push("(the headers continue in the next segment)".into());
            }
            v
        }
        Layer::Tls(t) => t
            .records
            .iter()
            .map(|r| {
                format!(
                    "record type {} {} length {}: {}",
                    r.content_type,
                    tls_version_name(r.version),
                    r.length,
                    tls_info(&crate::app::Tls { records: vec![r.clone()] })
                )
            })
            .collect(),
        Layer::Dhcp(x) => vec![
            format!("{} xid {:#x}", x.message_type.map(dhcp_type_name).unwrap_or("message"), x.xid),
            format!("client {} your {} server {}", x.client_ip, x.your_ip, x.server_ip),
            format!("hostname {:?}, lease {:?}, routers {:?}, dns {:?}", x.hostname, x.lease_secs, x.routers, x.dns_servers),
        ],
    }
}

/// A multi-line description: one block per layer, plus notes.
pub fn verbose(p: &Packet, d: &Decoded) -> String {
    let mut out =
        format!("Packet {}: {} bytes on the wire, {} captured, link type {}\n", p.number, p.orig_len, p.data.len(), p.link);
    for l in &d.layers {
        let _ = writeln!(out, "  {}", l.name());
        for line in describe(l) {
            let _ = writeln!(out, "    {line}");
        }
    }
    if let Some(t) = &d.truncated {
        let _ = writeln!(out, "  [the capture ends inside the {t}]");
    }
    for n in &d.notes {
        let _ = writeln!(out, "  note: {n}");
    }
    out
}

/// A classic hex dump: offset, 16 bytes in hex, and the printable characters.
pub fn hexdump(data: &[u8], indent: &str) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let (a, b) = hex.split_at(hex.len().min(8));
        let text: String = chunk.iter().map(|b| if (0x20..0x7f).contains(b) { *b as char } else { '.' }).collect();
        let _ = writeln!(out, "{indent}{:08x}  {:<23}  {:<23}  |{text}|", i * 16, a.join(" "), b.join(" "));
    }
    out
}

#[derive(Serialize)]
struct Json<'a> {
    number: u64,
    time: f64,
    length: u32,
    captured: usize,
    link_type: u32,
    #[serde(flatten)]
    decoded: &'a Decoded,
}

/// One JSON object per packet (for line-oriented tools such as `jq`).
pub fn json(p: &Packet, d: &Decoded) -> String {
    serde_json::to_string(&Json {
        number: p.number,
        time: p.time(),
        length: p.orig_len,
        captured: p.data.len(),
        link_type: p.link,
        decoded: d,
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode, ETH_ARP, ETH_IPV4, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
    use crate::testutil::*;

    const A: [u8; 4] = [192, 0, 2, 1];
    const B: [u8; 4] = [198, 51, 100, 7];

    fn pkt(n: u64, t: f64, data: Vec<u8>) -> (Packet, Decoded) {
        let p = Packet {
            number: n,
            ts_sec: 1_700_000_000 + t as u64,
            ts_nsec: (t.fract() * 1e9) as u32,
            link: 1,
            orig_len: data.len() as u32,
            data,
            iface: 0,
        };
        let d = decode(1, &p.data);
        (p, d)
    }

    fn line(pd: &(Packet, Decoded)) -> String {
        summary(&pd.0, &pd.1, 1_700_000_000.0, 1_700_000_000.0, &Style { time: TimeMode::Relative, checksums: false })
    }

    #[test]
    fn tcp_summary_lines() {
        let syn = pkt(
            1,
            0.0,
            eth_frame(
                ETH_IPV4,
                &ipv4_packet(
                    PROTO_TCP,
                    A,
                    B,
                    &tcp_segment(A, B, 51234, 443, 1000, 0, 0x02, &[2, 4, 5, 0xb4, 1, 3, 3, 7, 4, 2, 1, 1], b""),
                ),
            ),
        );
        assert_eq!(line(&syn), "     1    0.000000 192.0.2.1:51234 > 198.51.100.7:443 TCP 66 51234 > 443 [SYN] Seq=1000 Win=65535 Len=0 MSS=1460 WS=128 SACK_PERM");
        let data = pkt(
            2,
            0.25,
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, B, A, &tcp_segment(B, A, 443, 51234, 5, 1001, 0x18, &[], b"hello"))),
        );
        assert_eq!(
            line(&data),
            "     2    0.250000 198.51.100.7:443 > 192.0.2.1:51234 TCP 59 443 > 51234 [PSH, ACK] Seq=5 Ack=1001 Win=65535 Len=5"
        );
    }

    #[test]
    fn dns_http_tls_arp_icmp_summaries() {
        let mut q = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["www", "example", "com"] {
            q.push(l.len() as u8);
            q.extend(l.as_bytes());
        }
        q.extend([0, 0, 1, 0, 1]);
        let dns = pkt(1, 0.0, eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, A, B, &udp_datagram(A, B, 40000, 53, &q))));
        assert!(line(&dns).ends_with("DNS 75 query id=0xabcd A www.example.com"), "{}", line(&dns));
        let http = pkt(
            2,
            0.0,
            eth_frame(
                ETH_IPV4,
                &ipv4_packet(
                    PROTO_TCP,
                    A,
                    B,
                    &tcp_segment(A, B, 1234, 80, 1, 1, 0x18, &[], b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                ),
            ),
        );
        assert!(
            line(&http).contains(" HTTP ") && line(&http).ends_with("GET /index.html HTTP/1.1 Host: example.com"),
            "{}",
            line(&http)
        );
        let resp = pkt(
            3,
            0.0,
            eth_frame(
                ETH_IPV4,
                &ipv4_packet(
                    PROTO_TCP,
                    B,
                    A,
                    &tcp_segment(
                        B,
                        A,
                        80,
                        1234,
                        1,
                        1,
                        0x18,
                        &[],
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 12\r\n\r\n",
                    ),
                ),
            ),
        );
        assert!(line(&resp).ends_with("HTTP/1.1 200 OK (text/html, 12 bytes)"), "{}", line(&resp));
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1];
        arp.extend(A);
        arp.extend([0u8; 6]);
        arp.extend(B);
        let a = pkt(4, 0.0, eth_frame(ETH_ARP, &arp));
        assert!(line(&a).ends_with("ARP 42 who-has 198.51.100.7 tell 192.0.2.1"), "{}", line(&a));
        let mut ping = vec![8, 0, 0, 0, 0, 1, 0, 9];
        let c = crate::decode::checksum(&[&ping]);
        ping[2..4].copy_from_slice(&c.to_be_bytes());
        let i = pkt(5, 0.0, eth_frame(ETH_IPV4, &ipv4_packet(PROTO_ICMP, A, B, &ping)));
        assert!(line(&i).ends_with("ICMP 42 echo request id=0x0001 seq=9"), "{}", line(&i));
    }

    #[test]
    fn truncated_packets_say_where() {
        let seg = tcp_segment(A, B, 1, 2, 0, 0, 0x02, &[], b"");
        let full = eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, A, B, &seg));
        let mut p = pkt(1, 0.0, full[..40].to_vec());
        p.0.orig_len = full.len() as u32;
        assert!(line(&p).ends_with("[truncated: TCP header]"), "{}", line(&p));
    }

    #[test]
    fn checksum_marker_is_opt_in() {
        let mut ip = ipv4_packet(PROTO_TCP, A, B, &tcp_segment(A, B, 1, 2, 0, 0, 0x02, &[], b""));
        ip[10] ^= 1;
        let p = pkt(1, 0.0, eth_frame(ETH_IPV4, &ip));
        assert!(!line(&p).contains("bad checksum"));
        let s = summary(&p.0, &p.1, 0.0, 0.0, &Style { time: TimeMode::Relative, checksums: true });
        assert!(s.ends_with("[bad checksum]"), "{s}");
    }

    #[test]
    fn time_modes() {
        let p = pkt(1, 3.5, eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, A, B, &udp_datagram(A, B, 1, 2, b"x")))).0;
        assert_eq!(format_time(&p, 1_700_000_000.0, 1_700_000_002.0, TimeMode::Relative), "3.500000");
        assert_eq!(format_time(&p, 1_700_000_000.0, 1_700_000_002.0, TimeMode::Delta), "1.500000");
        assert_eq!(format_time(&p, 0.0, 0.0, TimeMode::Absolute), "22:13:23.500000");
        assert_eq!(format_time(&p, 0.0, 0.0, TimeMode::Epoch), "1700000003.500000");
    }

    #[test]
    fn hexdump_layout() {
        let h = hexdump(b"Hello, world! 0123456789", "");
        assert_eq!(h, "00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 20 30 31  |Hello, world! 01|\n00000010  32 33 34 35 36 37 38 39                           |23456789|\n");
        assert_eq!(hexdump(b"", ""), "");
        assert_eq!(hexdump(&[0, 255, 10], ">> "), ">> 00000000  00 ff 0a                                          |...|\n");
    }

    #[test]
    fn verbose_and_json_describe_every_layer() {
        let pd = pkt(
            7,
            0.5,
            eth_frame(
                ETH_IPV4,
                &ipv4_packet(
                    PROTO_TCP,
                    A,
                    B,
                    &tcp_segment(A, B, 1234, 80, 1, 1, 0x18, &[], b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
                ),
            ),
        );
        let v = verbose(&pd.0, &pd.1);
        for want in [
            "Packet 7:",
            "  Ethernet",
            "  IPv4",
            "192.0.2.1 > 198.51.100.7",
            "  TCP",
            "[PSH, ACK]",
            "  HTTP",
            "Host: x",
            "checksum",
        ] {
            assert!(v.contains(want), "missing {want:?} in\n{v}");
        }
        let j: serde_json::Value = serde_json::from_str(&json(&pd.0, &pd.1)).unwrap();
        assert_eq!(j["number"], 7);
        assert_eq!(j["layers"][0]["layer"], "Ethernet");
        assert_eq!(j["layers"][1]["src"], "192.0.2.1");
        assert_eq!(j["layers"][2]["dst_port"], 80);
        assert_eq!(j["layers"][3]["layer"], "Http");
    }
}
