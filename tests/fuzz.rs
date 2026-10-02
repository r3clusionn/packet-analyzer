//! Mutated capture files, pushed through everything that handles a packet: the reader, the decoder,
//! the filter, the formatters, the flow table, statistics, DNS pairing and the TCP reassembler.
//! None of it may panic, whatever the bytes say.

use std::path::PathBuf;

use pktscope::decode::{decode, Layer};
use pktscope::filter::Filter;
use pktscope::flow::{Direction, DnsTracker, FlowTable, Stats};
use pktscope::format::{hexdump, json, summary, verbose, Style, TimeMode};
use pktscope::pcap::Reader;
use pktscope::stream::Reassembler;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)).unwrap()
}

fn rng(seed: u64) -> impl FnMut(u64) -> u64 {
    let mut s = seed | 1;
    move |n| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s % n
    }
}

fn exercise(bytes: &[u8], filters: &[Filter]) -> usize {
    let Ok(reader) = Reader::new(bytes) else { return 0 };
    let style = Style { time: TimeMode::Absolute, checksums: true };
    let (mut flows, mut stats, mut dns, mut re) = (FlowTable::new(), Stats::default(), DnsTracker::new(), Reassembler::new());
    let mut n = 0;
    for p in reader {
        let Ok(p) = p else { break };
        n += 1;
        let d = decode(p.link, &p.data);
        let _ = summary(&p, &d, 0.0, 0.0, &style);
        let _ = verbose(&p, &d);
        let _ = json(&p, &d);
        let _ = hexdump(&p.data, "  ");
        for f in filters {
            let _ = f.matches(&p, &d);
        }
        stats.add(&p, &d);
        dns.add(&p, &d);
        if let Some((_, dir)) = flows.add(&p, &d) {
            if let Some(Layer::Tcp { seq, flags, .. }) = d.tcp() {
                // The same slice the `follow` command takes.
                let payload = p.data.get(d.payload_offset..d.payload_offset.saturating_add(d.payload_len)).unwrap_or(&[]);
                re.add(dir, *seq, flags.syn, payload, p.time());
            }
        }
    }
    re.finish(0.0);
    let _ = re.stream(Direction::ClientToServer);
    n
}

#[test]
fn mutated_capture_files_never_panic() {
    let filters: Vec<Filter> = [
        "tcp and port 443",
        "dnsname example",
        "sni fixture",
        "contains abc",
        "net 10.0.0.0/8 or host ::1",
        "len > 100 and not udp",
        "httphost x",
        "vlan",
        "frag",
    ]
    .iter()
    .map(|f| Filter::parse(f).unwrap())
    .collect();
    let mut total = 0usize;
    for (name, rounds) in [("net.pcap", 3000), ("tls13.pcap", 1500), ("tls12.pcap", 1500), ("http.pcap", 1500)] {
        let base = fixture(name);
        let mut r = rng(0x5eed + name.len() as u64);
        for _ in 0..rounds {
            let mut v = base.clone();
            // Mutations anywhere, including the file header and the record headers.
            for _ in 0..(1 + r(6)) {
                let i = r(v.len() as u64) as usize;
                match r(4) {
                    0 => v[i] = r(256) as u8,
                    1 => v[i] ^= 1 << r(8),
                    2 => {
                        let end = (i + 1 + r(16) as usize).min(v.len());
                        v.drain(i..end);
                        if v.is_empty() {
                            v.push(0);
                        }
                    }
                    _ => {
                        let byte = r(256) as u8;
                        v.insert(i, byte);
                    }
                }
            }
            if r(5) == 0 {
                let cut = r(v.len() as u64) as usize;
                v.truncate(cut);
            }
            total += exercise(&v, &filters);
        }
    }
    assert!(total > 50_000, "the fuzz run decoded {total} packets, expected far more");
}

#[test]
fn the_unmutated_fixtures_run_through_the_same_path() {
    let filters = vec![Filter::parse("tcp").unwrap()];
    assert_eq!(exercise(&fixture("net.pcap"), &filters), 43);
    assert_eq!(exercise(&fixture("tls13.pcap"), &filters), 13);
    assert_eq!(exercise(&fixture("tls12.pcap"), &filters), 12);
    assert_eq!(exercise(&fixture("http.pcap"), &filters), 8);
}
