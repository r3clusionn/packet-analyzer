//! Runs the `pks` binary on the fixtures.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name).to_string_lossy().into_owned()
}

fn pks(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pks")).args(args).output().expect("run pks")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn show_lists_every_packet_with_a_readable_summary() {
    let o = pks(&["show", &fixture("net.pcap")]);
    assert!(o.status.success());
    let text = out(&o);
    assert_eq!(text.lines().count(), 43);
    for want in [
        "192.0.2.10:51234 > 198.51.100.20:443 TCP 74 51234 > 443 [SYN] Seq=1000 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=111 TSecr=0 WS=128",
        "DNS ",
        "query id=0x1234 A www.example.com",
        "response id=0x1234 A www.example.com -> 93.184.216.34, 93.184.216.35 (NOERROR)",
        "response id=0x1236 A nothing.example.net (NXDOMAIN)",
        "who-has 198.51.100.20 tell 192.0.2.10",
        "02:00:00:00:00:14 is-at".replace("02:00:00:00:00:14 is-at", "198.51.100.20 is-at 02:00:00:00:00:14").as_str(),
        "echo request id=0x1234 seq=7",
        "GET /index.html?q=1 HTTP/1.1 Host: example.com",
        "HTTP/1.1 200 OK (text/html, 13 bytes)",
        "DHCP 297 Discover xid=0xcafebabe host=demo-host",
        "DHCP 310 Offer xid=0xcafebabe your=192.0.2.77",
        "neighbor solicitation",
        "fragment of protocol 17, offset 1000, more to follow",
    ] {
        assert!(text.contains(want), "missing {want:?} in:\n{text}");
    }
}

#[test]
fn filters_select_packets() {
    let f = fixture("net.pcap");
    let count = |filter: &[&str]| {
        let mut args = vec!["show", f.as_str()];
        args.extend(filter);
        let o = pks(&args);
        assert!(o.status.success(), "{filter:?}: {}", err(&o));
        out(&o).lines().count()
    };
    assert_eq!(count(&["arp"]), 2);
    assert_eq!(count(&["dns"]), 7);
    assert_eq!(count(&["udp", "and", "port", "53"]), 5);
    assert_eq!(count(&["tcp", "and", "not", "port", "443"]), count(&["tcp"]) - 3);
    assert_eq!(count(&["vlan"]), 2);
    assert_eq!(count(&["vlan", "200"]), 1);
    assert_eq!(count(&["frag"]), 6, "four IPv4 fragments and two IPv6 ones");
    assert_eq!(count(&["host", "198.51.100.20", "and", "icmp"]), 3);
    assert_eq!(count(&["net", "2001:db8::/32"]), 7);
    assert_eq!(count(&["len", ">", "1000"]), 3, "the three 1,034-byte IPv4 fragments");
    assert_eq!(count(&["syn", "and", "not", "ack"]), 3);
    assert_eq!(count(&["dnsname", "example.com"]), 4);
    assert_eq!(count(&["httphost", "example.com"]), 1);
    assert_eq!(count(&["contains", "\"hello over tcp\""]), 1, "quotes keep a phrase together");
    // A quoted filter given as one argument works the same.
    assert_eq!(count(&["tcp and port 8080"]), 3);
}

#[test]
fn bad_filters_and_files_are_clear_errors() {
    let o = pks(&["show", &fixture("net.pcap"), "tcp", "and"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("ends where a term is expected"), "{}", err(&o));
    let o = pks(&["show", "no-such-file.pcap"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("no-such-file.pcap"), "{}", err(&o));
    let o = pks(&["show", &fixture("net.facts.json")]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("not a pcap or pcapng file"), "{}", err(&o));
}

#[test]
fn count_verbose_hex_and_json() {
    let f = fixture("net.pcap");
    assert_eq!(out(&pks(&["show", &f, "-c", "5"])).lines().count(), 5);
    let v = out(&pks(&["show", &f, "-c", "1", "-v", "-x"]));
    for want in ["Packet 1:", "  Ethernet", "  IPv4", "  TCP", "options", "00000000  "] {
        assert!(v.contains(want), "missing {want:?} in:\n{v}");
    }
    let j = out(&pks(&["show", &f, "--json"]));
    let lines: Vec<&str> = j.lines().collect();
    assert_eq!(lines.len(), 43);
    for l in &lines {
        let v: serde_json::Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"));
        assert!(v["number"].as_u64().is_some() && v["layers"].is_array());
    }
    // Times: relative by default, epoch and absolute on request.
    let rel = out(&pks(&["show", &f, "-c", "2"]));
    assert!(rel.lines().nth(1).unwrap().contains("0.000250"), "{rel}");
    assert!(out(&pks(&["show", &f, "-c", "1", "-t", "epoch"])).contains("1700000000.000000"));
    assert!(out(&pks(&["show", &f, "-c", "1", "-t", "abs"])).contains("22:13:20.000000"));
    assert!(out(&pks(&["show", &f, "-c", "2", "-t", "delta"])).lines().nth(1).unwrap().contains("0.000250"));
}

#[test]
fn stats_flows_and_dns() {
    let s = out(&pks(&["stats", &fixture("net.pcap")]));
    for want in ["43 packets", "Protocols", "DNS", "ARP", "ICMPv6", "www.example.com", "SYN"] {
        assert!(s.contains(want), "missing {want:?} in:\n{s}");
    }
    let j: serde_json::Value = serde_json::from_str(&out(&pks(&["stats", &fixture("net.pcap"), "--json"]))).unwrap();
    assert_eq!(j["packets"], 43);
    assert_eq!(j["dns_nxdomain"], 1);

    let f = out(&pks(&["flows", &fixture("tls13.pcap")]));
    assert!(f.contains("192.0.2.10:44444") && f.contains("198.51.100.20:443") && f.contains("closed"), "{f}");
    let fj: serde_json::Value = serde_json::from_str(&out(&pks(&["flows", &fixture("tls13.pcap"), "--json"]))).unwrap();
    assert_eq!(fj.as_array().unwrap().len(), 1);
    assert_eq!(fj[0]["syn"], true);

    let d = out(&pks(&["dns", &fixture("net.pcap")]));
    assert!(d.contains("www.example.com") && d.contains("queries"), "{d}");
}

#[test]
fn follow_prints_the_reassembled_conversation() {
    let f = fixture("http.pcap");
    let text = out(&pks(&["follow", &f, "0"]));
    assert!(text.contains("client -> server") && text.contains("GET /fixture/page.html?x=1 HTTP/1.1"), "{text}");
    assert!(text.contains("server -> client") && text.contains("hello from the fixture server"), "{text}");
    // One direction, raw: exactly the bytes the server sent.
    let o = pks(&["follow", &f, "0", "--direction", "s2c", "--raw"]);
    assert!(o.status.success());
    assert!(o.stdout.starts_with(b"HTTP/1.1 200 OK\r\n") && o.stdout.ends_with(b"</html>"));
    let hex = out(&pks(&["follow", &f, "0", "--hex", "--direction", "c2s"]));
    assert!(hex.contains("00000000  47 45 54 20") && !hex.contains("HTTP/1.1 200"), "{hex}");
    // Errors.
    let o = pks(&["follow", &f, "9"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("there is no conversation 9"), "{}", err(&o));
    assert_eq!(pks(&["follow", &f, "0", "--raw"]).status.code(), Some(2));
    let o = pks(&["follow", &fixture("net.pcap"), "3"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
}

#[test]
fn extract_writes_a_new_capture_with_only_the_matching_packets() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("dns.pcap");
    let o = pks(&["extract", &fixture("net.pcap"), out_path.to_str().unwrap(), "dns"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(err(&o).contains("wrote 7 of 43 packets"), "{}", err(&o));
    // The new file reads back, with the same packets and times.
    let back = out(&pks(&["show", out_path.to_str().unwrap()]));
    assert_eq!(back.lines().count(), 7);
    assert!(back.contains("response id=0x1234"));
    let a = out(&pks(&["show", &fixture("net.pcap"), "-t", "epoch", "dns"]));
    let b = out(&pks(&["show", out_path.to_str().unwrap(), "-t", "epoch"]));
    let times = |s: &str| -> Vec<String> { s.lines().map(|l| l.split_whitespace().nth(1).unwrap().to_string()).collect() };
    assert_eq!(times(&a), times(&b));
    // Nothing matching still produces a valid, empty capture.
    let empty = dir.path().join("none.pcap");
    assert!(pks(&["extract", &fixture("net.pcap"), empty.to_str().unwrap(), "port", "9"]).status.success());
    assert_eq!(out(&pks(&["show", empty.to_str().unwrap()])), "");
}

#[test]
fn a_damaged_file_gives_the_packets_it_has_and_a_nonzero_exit() {
    let bytes = std::fs::read(fixture("net.pcap")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("cut.pcap");
    std::fs::write(&p, &bytes[..bytes.len() - 20]).unwrap();
    let o = pks(&["show", p.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(out(&o).lines().count(), 42);
    assert!(err(&o).contains("ends early or is damaged"), "{}", err(&o));
}

#[test]
fn capture_arguments_are_checked_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let o = pks(&["capture", dir.path().join("x.pcapng").to_str().unwrap(), "--seconds", "1", "--proto", "gre"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("unknown protocol"), "{}", err(&o));
    let o = pks(&["capture", dir.path().join("x.pcapng").to_str().unwrap(), "--seconds", "1", "--ip", "nonsense"]);
    assert!(err(&o).contains("not an IP address"), "{}", err(&o));
}
