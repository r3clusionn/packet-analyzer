//! Checks the decoder against facts reported by other implementations (see scripts/make_fixtures.py):
//!
//! * `net.pcap`: 43 frames built with scapy; the expected values are what scapy reports when it
//!   parses the finished bytes again.
//! * `tls12.pcap`, `tls13.pcap`: real handshakes between two OpenSSL endpoints; the expected values
//!   come from the ssl objects (version, cipher, server name, ALPN).
//! * `http.pcap`: an exchange produced by Python's http.server and http.client.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use pktscope::app::Handshake;
use pktscope::decode::{decode, Layer};
use pktscope::flow::{Direction, FlowTable};
use pktscope::pcap::{Packet, Reader};
use pktscope::stream::Reassembler;
use serde_json::{json, Map, Value};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
}

fn packets(name: &str) -> Vec<Packet> {
    let r = Reader::new(BufReader::new(File::open(fixture(name)).unwrap())).unwrap();
    r.map(|p| p.unwrap()).collect()
}

fn expected(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixture(name)).unwrap()).unwrap()
}

/// The same fields scapy reports, taken from this program's decoder.
fn our_facts(p: &Packet) -> Map<String, Value> {
    let d = decode(p.link, &p.data);
    let v = serde_json::to_value(&d).unwrap();
    let layers = v["layers"].as_array().unwrap();
    let mut f = Map::new();
    let mut vlans = Vec::new();
    let mut ext = 0;
    for l in layers {
        match l["layer"].as_str().unwrap() {
            "Ethernet" => {
                f.insert("eth_src".into(), l["src"].clone());
                f.insert("eth_dst".into(), l["dst"].clone());
            }
            "Vlan" => vlans.push(l["id"].clone()),
            "Ipv4" => {
                f.insert("l3".into(), json!("ipv4"));
                for (k, from) in [
                    ("src", "src"),
                    ("dst", "dst"),
                    ("ttl", "ttl"),
                    ("ip_id", "id"),
                    ("ip_proto", "protocol"),
                    ("frag_offset", "fragment_offset"),
                    ("mf", "more_fragments"),
                    ("df", "dont_fragment"),
                    ("ihl", "header_len"),
                ] {
                    f.insert(k.into(), l[from].clone());
                }
            }
            "Ipv6" => {
                f.insert("l3".into(), json!("ipv6"));
                for (k, from) in [
                    ("src", "src"),
                    ("dst", "dst"),
                    ("hop_limit", "hop_limit"),
                    ("traffic_class", "traffic_class"),
                    ("flow_label", "flow_label"),
                ] {
                    f.insert(k.into(), l[from].clone());
                }
            }
            "Ipv6Fragment" => {
                f.insert("v6_frag_offset".into(), l["offset"].clone());
                f.insert("v6_frag_more".into(), l["more_fragments"].clone());
                f.insert("v6_frag_id".into(), l["id"].clone());
            }
            "Ipv6Extension" => ext += 1,
            "Arp" => {
                f.insert("l3".into(), json!("arp"));
                f.insert("arp_op".into(), l["op"].clone());
                f.insert("arp_psrc".into(), l["sender_ip"].clone());
                f.insert("arp_pdst".into(), l["target_ip"].clone());
                f.insert("arp_hwsrc".into(), l["sender_mac"].clone());
            }
            "Tcp" => {
                let fl = &l["flags"];
                let flags: String = [
                    ("F", "fin"),
                    ("S", "syn"),
                    ("R", "rst"),
                    ("P", "psh"),
                    ("A", "ack"),
                    ("U", "urg"),
                    ("E", "ece"),
                    ("C", "cwr"),
                ]
                .iter()
                .filter(|(_, k)| fl[*k] == json!(true))
                .map(|(c, _)| *c)
                .collect();
                let mut t = json!({"sport": l["src_port"], "dport": l["dst_port"], "seq": l["seq"], "ack": l["ack"], "flags": flags, "window": l["window"], "payload": l["payload_len"]});
                for o in l["options"].as_array().unwrap() {
                    if let Some(m) = o.get("Mss") {
                        t["mss"] = m.clone();
                    } else if let Some(w) = o.get("WindowScale") {
                        t["wscale"] = w.clone();
                    } else if o == &json!("SackPermitted") {
                        t["sack_permitted"] = json!(true);
                    } else if let Some(ts) = o.get("Timestamp") {
                        t["ts_val"] = ts["value"].clone();
                        t["ts_ecr"] = ts["echo"].clone();
                    }
                }
                f.insert("tcp".into(), t);
            }
            "Udp" => {
                f.insert(
                    "udp".into(),
                    json!({"sport": l["src_port"], "dport": l["dst_port"], "length": l["length"], "payload": l["payload_len"]}),
                );
            }
            "Icmp" => {
                let mut i = json!({"type": l["icmp_type"], "code": l["code"]});
                if !l["id"].is_null() {
                    i["id"] = l["id"].clone();
                    i["seq"] = l["seq"].clone();
                }
                f.insert("icmp".into(), i);
            }
            "Icmpv6" => {
                let mut i = json!({"type": l["icmp_type"], "code": l["code"]});
                if !l["id"].is_null() {
                    i["id"] = l["id"].clone();
                    i["seq"] = l["seq"].clone();
                }
                f.insert("icmpv6".into(), i);
            }
            "Dns" => {
                // Serialised without a tag of its own: the fields sit beside "layer".
                let qs = l["questions"].as_array().unwrap();
                let mut dns = json!({"id": l["id"], "response": l["response"], "rcode": l["rcode"], "qdcount": qs.len(), "ancount": l["answers"].as_array().unwrap().len()});
                if let Some(q) = qs.first() {
                    dns["qname"] = q["name"].clone();
                    dns["qtype"] = q["qtype"].clone();
                }
                let answers: Vec<Value> = l["answers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| {
                        let ty = r["rtype"].as_u64().unwrap();
                        let name = r["name"].as_str().unwrap();
                        let data = &r["data"];
                        let text = match ty {
                            1 => format!("{ty}:{name}:{}", data["A"].as_str().unwrap()),
                            28 => format!("{ty}:{name}:{}", data["Aaaa"].as_str().unwrap()),
                            5 => format!("{ty}:{name}:{}", data["Cname"].as_str().unwrap()),
                            2 => format!("{ty}:{name}:{}", data["Ns"].as_str().unwrap()),
                            12 => format!("{ty}:{name}:{}", data["Ptr"].as_str().unwrap()),
                            _ => format!("{ty}:{name}"),
                        };
                        json!(text)
                    })
                    .collect();
                dns["answers"] = json!(answers);
                f.insert("dns".into(), dns);
            }
            "Dhcp" => {
                let mut dh = json!({"op": l["op"], "xid": l["xid"], "yiaddr": l["your_ip"], "message_type": l["message_type"]});
                if !l["hostname"].is_null() {
                    dh["hostname"] = l["hostname"].clone();
                }
                f.insert("dhcp".into(), dh);
            }
            _ => {}
        }
    }
    if !vlans.is_empty() {
        f.insert("vlans".into(), Value::Array(vlans));
    }
    if f.get("l3") == Some(&json!("ipv6")) {
        f.insert("v6_ext_headers".into(), json!(ext));
    }
    f
}

#[test]
fn every_scapy_frame_decodes_to_the_same_facts() {
    let pkts = packets("net.pcap");
    let facts = expected("net.facts.json");
    let facts = facts.as_array().unwrap();
    assert_eq!(pkts.len(), facts.len());
    assert!(pkts.len() >= 40);
    let mut problems = Vec::new();
    for (p, want) in pkts.iter().zip(facts) {
        let case = want["case"].as_str().unwrap();
        let mut want = want.as_object().unwrap().clone();
        let frame_len = want.remove("frame_len").unwrap().as_u64().unwrap();
        want.remove("case");
        want.remove("number");
        let got = our_facts(p);
        assert_eq!(p.orig_len as u64, frame_len, "{case}: frame length");
        // scapy leaves out DNS answers it cannot name and the DHCP fields of other messages; compare only what it reports.
        let mut mine = got.clone();
        // scapy reports v6_ext_headers only for IPv6.
        if !want.contains_key("v6_ext_headers") {
            mine.remove("v6_ext_headers");
        }
        // The DNS layer carries qdcount/ancount in scapy; ours derive them from what was parsed, which is the same when the message is whole.
        if want != mine {
            let diff: Vec<String> = want
                .iter()
                .filter(|(k, v)| mine.get(*k) != Some(v))
                .map(|(k, v)| {
                    format!(
                        "{k}: scapy {v}, pktscope {}",
                        mine.get(k).map(|x| x.to_string()).unwrap_or_else(|| "(missing)".into())
                    )
                })
                .chain(mine.keys().filter(|k| !want.contains_key(*k)).map(|k| format!("{k}: only pktscope reports {}", mine[k])))
                .collect();
            problems.push(format!("{case}:\n    {}", diff.join("\n    ")));
        }
    }
    assert!(problems.is_empty(), "{} of {} frames disagree with scapy:\n{}", problems.len(), facts.len(), problems.join("\n"));
}

#[test]
fn no_scapy_frame_has_a_note_or_truncation_it_should_not() {
    // Fragments and the ethernet padding case legitimately produce notes; nothing is truncated.
    for p in packets("net.pcap") {
        let d = decode(p.link, &p.data);
        assert!(d.truncated.is_none(), "packet {} truncated at {:?}", p.number, d.truncated);
        for n in &d.notes {
            assert!(n.contains("fragment") || n.contains("bytes were captured"), "packet {}: unexpected note {n}", p.number);
        }
    }
}

#[test]
fn checksums_of_every_scapy_frame_verify() {
    for p in packets("net.pcap") {
        let d = decode(p.link, &p.data);
        for l in &d.layers {
            match l {
                Layer::Ipv4 { checksum_ok, .. } => assert!(*checksum_ok, "packet {}: IPv4 checksum", p.number),
                Layer::Tcp { checksum_ok, .. } | Layer::Udp { checksum_ok, .. } => {
                    assert_ne!(*checksum_ok, Some(false), "packet {}: transport checksum", p.number)
                }
                Layer::Icmp { checksum_ok, .. } | Layer::Icmpv6 { checksum_ok, .. } => {
                    assert!(*checksum_ok, "packet {}: ICMP checksum", p.number)
                }
                _ => {}
            }
        }
    }
}

fn client_server_streams(name: &str) -> (Reassembler, Vec<(Direction, Packet)>) {
    let mut table = FlowTable::new();
    let mut re = Reassembler::new();
    let mut seen = Vec::new();
    let mut last = 0.0;
    for p in packets(name) {
        let d = decode(p.link, &p.data);
        let (_, dir) = table.add(&p, &d).expect("every fixture packet is IP");
        if let Some(Layer::Tcp { seq, flags, .. }) = d.tcp() {
            let payload = &p.data[d.payload_offset..d.payload_offset + d.payload_len];
            re.add(dir, *seq, flags.syn, payload, p.time());
            last = p.time();
        }
        seen.push((dir, p));
    }
    re.finish(last);
    assert_eq!(table.flows().len(), 1, "one TCP connection");
    (re, seen)
}

fn cipher_code(name: &str) -> u16 {
    match name {
        "ECDHE-RSA-AES256-GCM-SHA384" => 0xc030,
        "TLS_AES_256_GCM_SHA384" => 0x1302,
        other => panic!("cipher {other} is not in the test's table"),
    }
}

#[test]
fn real_tls_handshakes_are_read_correctly() {
    let facts = expected("tls.facts.json");
    for (name, wire_version) in [("tls12", 0x0303u16), ("tls13", 0x0304u16)] {
        let want = &facts[name];
        let (re, seen) = client_server_streams(&format!("{name}.pcap"));
        // Every record of every packet that carries a TLS layer, in order.
        let mut hello = None;
        let mut server_hello = None;
        let mut record_types: Vec<(Direction, u8)> = Vec::new();
        for (dir, p) in &seen {
            let d = decode(p.link, &p.data);
            if let Some(t) = d.tls() {
                for r in &t.records {
                    record_types.push((*dir, r.content_type));
                    match &r.handshake {
                        Some(Handshake::ClientHello { .. }) => hello = r.handshake.clone(),
                        Some(Handshake::ServerHello { .. }) => server_hello = r.handshake.clone(),
                        _ => {}
                    }
                }
            }
        }
        let Some(Handshake::ClientHello { sni, alpn, supported_versions, cipher_suites, session_id_len, .. }) = hello else {
            panic!("{name}: no ClientHello found")
        };
        assert_eq!(sni.as_deref(), want["sni"].as_str(), "{name}: SNI");
        assert_eq!(alpn, vec!["h2".to_string(), "http/1.1".to_string()], "{name}: client ALPN offer");
        assert!(
            cipher_suites.contains(&cipher_code(want["cipher"].as_str().unwrap())),
            "{name}: the negotiated cipher was offered"
        );
        assert!(supported_versions.contains(&0x0304) || name == "tls12" || supported_versions.is_empty());
        if name == "tls13" {
            assert!(supported_versions.contains(&0x0304), "{name}: TLS 1.3 is offered through the supported_versions extension");
        }
        let _ = session_id_len;
        let Some(Handshake::ServerHello { cipher_suite, selected_version, version, .. }) = server_hello else {
            panic!("{name}: no ServerHello found")
        };
        assert_eq!(cipher_suite, cipher_code(want["cipher"].as_str().unwrap()), "{name}: the server's cipher");
        let negotiated = selected_version.unwrap_or(version);
        assert_eq!(negotiated, wire_version, "{name}: negotiated version");
        assert_eq!(want["version"].as_str().unwrap(), if name == "tls12" { "TLSv1.2" } else { "TLSv1.3" });

        // The reassembled streams are exactly the flights the endpoints produced.
        let flights = want["flights"].as_array().unwrap();
        for (side, dir) in [("c", Direction::ClientToServer), ("s", Direction::ServerToClient)] {
            let expected_len: u64 = flights.iter().filter(|f| f["from"] == side).map(|f| f["bytes"].as_u64().unwrap()).sum();
            assert_eq!(re.stream(dir).len() as u64, expected_len, "{name}: {side} stream length");
        }
        assert!(re.chunks.iter().all(|c| c.gap == 0) && re.retransmitted_bytes == 0);
        // The record types seen include handshake (22) from the client and server and application data (23).
        for dir in [Direction::ClientToServer, Direction::ServerToClient] {
            assert!(record_types.iter().any(|(d, t)| *d == dir && *t == 22), "{name}: {dir:?} handshake record");
            assert!(record_types.iter().any(|(d, t)| *d == dir && *t == 23), "{name}: {dir:?} application data record");
        }
    }
}

#[test]
fn an_http_exchange_from_pythons_own_server_is_read_correctly() {
    let want = expected("http.facts.json");
    let (re, _) = client_server_streams("http.pcap");
    let c = re.stream(Direction::ClientToServer);
    let s = re.stream(Direction::ServerToClient);
    assert_eq!(c.len() as u64, want["request_bytes"].as_u64().unwrap());
    assert_eq!(s.len() as u64, want["response_bytes"].as_u64().unwrap());
    let req = pktscope::app::parse_http(&c).expect("a request");
    assert!(req.is_request && req.headers_complete);
    assert_eq!(req.target.as_deref(), want["path"].as_str());
    assert_eq!(req.header("host"), want["host"].as_str());
    let rsp = pktscope::app::parse_http(&s).expect("a response");
    assert_eq!(rsp.status, want["status"].as_u64().map(|v| v as u16));
    assert_eq!(rsp.header("content-type"), want["content_type"].as_str());
    assert_eq!(rsp.header("content-length").map(|v| v.parse::<u64>().unwrap()), want["content_length"].as_u64());
    // The body is exactly what follows the blank line.
    let split = s.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(String::from_utf8_lossy(&s[split..]), want["body"].as_str().unwrap());
}

#[test]
fn the_same_stream_survives_reordering_and_duplication_of_its_packets() {
    // Shuffle the TLS 1.3 data packets and add duplicates: the reassembled streams must not change.
    let (reference, _) = client_server_streams("tls13.pcap");
    let mut pkts = packets("tls13.pcap");
    let mut seed = 5u64;
    let mut next = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for _ in 0..50 {
        let mut order: Vec<usize> = (0..pkts.len()).collect();
        for i in (1..order.len()).rev() {
            let j = next(i as u64 + 1) as usize;
            order.swap(i, j);
        }
        // Keep the handshake first (SYN, SYN-ACK and ACK anchor both streams), shuffle the rest and duplicate a few packets.
        let mut shuffled: Vec<Packet> = pkts[..3].to_vec();
        shuffled.extend(order.iter().filter(|i| **i >= 3).map(|i| pkts[*i].clone()));
        for _ in 0..4 {
            let i = next(pkts.len() as u64) as usize;
            shuffled.push(pkts[i].clone());
        }
        let mut table = FlowTable::new();
        let mut re = Reassembler::new();
        let mut by_dir: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
        for p in &shuffled {
            let d = decode(p.link, &p.data);
            let (_, dir) = table.add(p, &d).unwrap();
            if let Some(Layer::Tcp { seq, flags, .. }) = d.tcp() {
                re.add(dir, *seq, flags.syn, &p.data[d.payload_offset..d.payload_offset + d.payload_len], p.time());
            }
        }
        re.finish(0.0);
        for dir in [Direction::ClientToServer, Direction::ServerToClient] {
            by_dir.insert(dir as u8, re.stream(dir));
            assert!(re.stream(dir) == reference.stream(dir), "shuffled capture, {dir:?}: the reassembled stream differs");
        }
    }
    pkts.clear();
}
