//! Builders for hand-made packets, used by the tests (and by the benchmark generator). Hidden from
//! the documentation: they are not part of the analyzer.
#![doc(hidden)]

use crate::decode::{checksum, pseudo_header, PROTO_TCP, PROTO_UDP};

pub fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02];
    v.extend(ethertype.to_be_bytes());
    v.extend(payload);
    v
}

pub fn ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    ipv4_packet_with(proto, src, dst, payload, 0, 0)
}

pub fn ipv4_packet_with(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8], frag_flags: u16, options: usize) -> Vec<u8> {
    let ihl = 20 + options;
    let mut h = vec![0x40 | (ihl / 4) as u8, 0];
    h.extend(((ihl + payload.len()) as u16).to_be_bytes());
    h.extend([0x12, 0x34]);
    h.extend(frag_flags.to_be_bytes());
    h.extend([64, proto, 0, 0]);
    h.extend(src);
    h.extend(dst);
    h.extend(std::iter::repeat_n(1u8, options)); // NOP options
    let c = checksum(&[&h]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend(payload);
    h
}

#[allow(clippy::too_many_arguments)]
pub fn tcp_segment(
    src: [u8; 4],
    dst: [u8; 4],
    sp: u16,
    dp: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    opts: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let hl = 20 + opts.len();
    assert_eq!(hl % 4, 0);
    let mut t = Vec::new();
    t.extend(sp.to_be_bytes());
    t.extend(dp.to_be_bytes());
    t.extend(seq.to_be_bytes());
    t.extend(ack.to_be_bytes());
    t.extend((((hl / 4) as u16) << 12 | flags as u16).to_be_bytes());
    t.extend(65535u16.to_be_bytes());
    t.extend([0, 0, 0, 0]);
    t.extend(opts);
    t.extend(payload);
    let ph = pseudo_header(&src, &dst, PROTO_TCP, t.len());
    let c = checksum(&[&ph, &t]);
    t[16..18].copy_from_slice(&c.to_be_bytes());
    t
}

pub fn udp_datagram(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend(sp.to_be_bytes());
    u.extend(dp.to_be_bytes());
    u.extend(((8 + payload.len()) as u16).to_be_bytes());
    u.extend([0, 0]);
    u.extend(payload);
    let ph = pseudo_header(&src, &dst, PROTO_UDP, u.len());
    let mut c = checksum(&[&ph, &u]);
    if c == 0 {
        c = 0xffff;
    }
    u[6..8].copy_from_slice(&c.to_be_bytes());
    u
}
