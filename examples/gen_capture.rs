//! Writes a large, deterministic pcap for benchmarking: `gen_capture OUT.pcap [PACKETS]`.
//!
//! The mix is meant to look like ordinary traffic: mostly TCP segments (a quarter of them with HTTP
//! text), DNS queries and responses, UDP, ICMP echo and ARP, spread over a few thousand flows.

use std::fs::File;
use std::io::BufWriter;

use pktscope::decode::{ETH_ARP, ETH_IPV4, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use pktscope::pcap::Writer;
use pktscope::testutil::{eth_frame, ipv4_packet, tcp_segment, udp_datagram};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = args.first().expect("usage: gen_capture OUT.pcap [PACKETS]");
    let n: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(1_000_000);
    let mut w = Writer::new(BufWriter::new(File::create(out).unwrap()), 1, 65535).unwrap();
    let mut seed = 0x1234_5678_9abc_def1u64;
    let mut next = move |m: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % m
    };
    let http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench/1.0\r\nAccept: */*\r\n\r\n";
    // Sequence numbers per flow and direction, so the data has no accidental retransmissions.
    let mut seqs = vec![[1000u32; 2]; 4096];
    let mut dns_ids = 0u16;
    for i in 0..n {
        let flow = next(4096) as usize;
        let client = [10, 0, (flow >> 8) as u8, flow as u8];
        let server = [198, 51, 100, (flow % 200) as u8 + 1];
        let sport = 10_000 + (flow as u16);
        let kind = next(100);
        let frame = if kind < 55 {
            // TCP data or ACK, client to server or back.
            let payload_len = [0usize, 0, 64, 512, 1200, 1460][next(6) as usize];
            let mut payload = vec![0u8; payload_len];
            for b in payload.iter_mut().take(16) {
                *b = next(256) as u8;
            }
            let dir = next(2) as usize;
            let (src, dst, sp, dp) = if dir == 0 { (client, server, sport, 443) } else { (server, client, 443, sport) };
            let seq = seqs[flow][dir];
            seqs[flow][dir] = seq.wrapping_add(payload_len as u32);
            let seg = tcp_segment(src, dst, sp, dp, seq, 77, if payload_len > 0 { 0x18 } else { 0x10 }, &[], &payload);
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, src, dst, &seg))
        } else if kind < 65 {
            let seq = seqs[flow][0];
            seqs[flow][0] = seq.wrapping_add(http.len() as u32);
            let seg = tcp_segment(client, server, sport, 80, seq, 77, 0x18, &[], http);
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_TCP, client, server, &seg))
        } else if kind < 85 {
            // DNS query or response.
            dns_ids = dns_ids.wrapping_add(1);
            let name = format!("host{}.example.com", flow % 500);
            let mut m = Vec::new();
            m.extend(dns_ids.to_be_bytes());
            let response = next(2) == 0;
            m.extend(if response { [0x81, 0x80] } else { [0x01, 0x00] });
            m.extend([0, 1, 0, response as u8, 0, 0, 0, 0]);
            for l in name.split('.') {
                m.push(l.len() as u8);
                m.extend(l.as_bytes());
            }
            m.extend([0, 0, 1, 0, 1]);
            if response {
                m.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, (flow % 250) as u8]);
            }
            let (src, dst, sp, dp) = if response { (server, client, 53, sport) } else { (client, server, sport, 53) };
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, src, dst, &udp_datagram(src, dst, sp, dp, &m)))
        } else if kind < 93 {
            let payload = vec![next(256) as u8; 100 + next(900) as usize];
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_UDP, client, server, &udp_datagram(client, server, sport, 5000, &payload)))
        } else if kind < 97 {
            let mut m = vec![8, 0, 0, 0, 0, 1, 0, (i % 256) as u8];
            m.extend([0x61u8; 32]);
            let c = pktscope::decode::checksum(&[&m]);
            m[2..4].copy_from_slice(&c.to_be_bytes());
            eth_frame(ETH_IPV4, &ipv4_packet(PROTO_ICMP, client, server, &m))
        } else {
            let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1];
            a.extend(client);
            a.extend([0u8; 6]);
            a.extend(server);
            eth_frame(ETH_ARP, &a)
        };
        let t = 1_700_000_000 + i / 20_000;
        w.write(t, ((i % 20_000) * 50_000) as u32, frame.len() as u32, &frame).unwrap();
    }
    use std::io::Write;
    w.into_inner().flush().unwrap();
}
