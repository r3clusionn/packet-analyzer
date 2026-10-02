use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::{Parser, Subcommand, ValueEnum};
use pktscope::capture::{self, CaptureOptions};
use pktscope::decode::{decode, Decoded};
use pktscope::filter::Filter;
use pktscope::flow::{Direction, DnsTracker, FlowTable, Stats};
use pktscope::format::{self, Style, TimeMode};
use pktscope::pcap::{Dedup, InterfaceInfo, Packet, PcapError, Reader, Writer};
use pktscope::stream::Reassembler;

/// A packet analyzer for pcap and pcapng files.
#[derive(Parser)]
#[command(name = "pks", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum TimeArg {
    /// Seconds since the first packet
    Rel,
    /// Seconds since the previous packet
    Delta,
    /// Time of day (UTC)
    Abs,
    /// Seconds since 1970
    Epoch,
}

#[derive(Clone, Copy, ValueEnum)]
enum DirArg {
    /// Client to server
    C2s,
    /// Server to client
    S2c,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the packets of a capture, one line each
    Show {
        file: PathBuf,
        /// Skip copies of a packet recorded on several interfaces (pktmon records every layer of the stack)
        #[arg(long)]
        dedup: bool,
        /// Stop after this many matching packets
        #[arg(short = 'c', long)]
        count: Option<u64>,
        /// Describe every layer of every packet
        #[arg(short, long)]
        verbose: bool,
        /// Also print a hex dump of each packet
        #[arg(short = 'x', long)]
        hex: bool,
        /// One JSON object per packet
        #[arg(long)]
        json: bool,
        #[arg(short, long, value_enum, default_value = "rel")]
        time: TimeArg,
        /// Mark packets with a wrong checksum (offloaded captures have many)
        #[arg(long)]
        checksums: bool,
        /// Filter expression, e.g. tcp and port 443
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        filter: Vec<String>,
    },
    /// Summarise a capture: protocols, hosts, DNS names, TLS server names
    Stats {
        file: PathBuf,
        #[arg(long)]
        dedup: bool,
        #[arg(long)]
        json: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        filter: Vec<String>,
    },
    /// List the conversations (TCP connections, UDP and ICMP exchanges)
    Flows {
        file: PathBuf,
        #[arg(long)]
        dedup: bool,
        #[arg(long)]
        json: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        filter: Vec<String>,
    },
    /// Print the reassembled data of one TCP connection (numbers come from `flows`)
    Follow {
        file: PathBuf,
        flow: usize,
        #[arg(long)]
        dedup: bool,
        /// Hex dump instead of text
        #[arg(long)]
        hex: bool,
        /// Only this direction
        #[arg(long, value_enum)]
        direction: Option<DirArg>,
        /// Write the chosen direction's bytes to stdout unchanged (needs --direction)
        #[arg(long)]
        raw: bool,
    },
    /// List DNS queries with their answers and response times
    Dns {
        file: PathBuf,
        #[arg(long)]
        dedup: bool,
        #[arg(long)]
        json: bool,
    },
    /// Write the packets that match a filter to a new pcap file
    Extract {
        file: PathBuf,
        out: PathBuf,
        #[arg(long)]
        dedup: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        filter: Vec<String>,
    },
    /// Record packets on Windows with pktmon (needs an elevated terminal)
    Capture {
        /// The pcapng file to write
        out: PathBuf,
        /// Stop after this many seconds (default: press Enter or Ctrl+C)
        #[arg(short, long)]
        seconds: Option<u64>,
        /// Only this port (repeatable)
        #[arg(long)]
        port: Vec<u16>,
        /// Only this IP address (repeatable)
        #[arg(long)]
        ip: Vec<String>,
        /// Only tcp, udp, icmp or arp
        #[arg(long)]
        proto: Option<String>,
        /// Bytes kept per packet (0 for all)
        #[arg(long, default_value_t = 0)]
        snaplen: u32,
        /// Capture on the physical adapters only (a packet is otherwise recorded at every layer of the stack)
        #[arg(long)]
        nics_only: bool,
        /// Keep the intermediate .etl file
        #[arg(long)]
        keep_etl: bool,
    },
}

fn parse_filter(words: &[String]) -> Result<Filter, String> {
    Filter::parse(&words.join(" "))
}

fn open_capture(path: &PathBuf) -> Result<Reader<Box<dyn Read>>, String> {
    let r: Box<dyn Read> = if path.as_os_str() == "-" {
        Box::new(BufReader::with_capacity(1 << 20, io::stdin()))
    } else {
        Box::new(BufReader::with_capacity(1 << 20, File::open(path).map_err(|e| format!("{}: {e}", path.display()))?))
    };
    Reader::new(r).map_err(|e| format!("{}: {e}", path.display()))
}

/// What reading a capture file left behind besides the packets.
struct Scan {
    /// The error that ended the file early, if any.
    err: Option<PcapError>,
    interfaces: Vec<InterfaceInfo>,
    /// Copies of the same packet recorded on several interfaces that were skipped (`--dedup`).
    duplicates: u64,
}

/// Calls `f` for every packet that matches `filter` (after dropping duplicates when asked).
fn each_packet(
    path: &PathBuf,
    filter: &Filter,
    dedup: bool,
    mut f: impl FnMut(&Packet, &Decoded) -> bool,
) -> Result<Scan, String> {
    let mut reader = open_capture(path)?;
    let mut dd = Dedup::new();
    let mut err = None;
    for p in reader.by_ref() {
        match p {
            Ok(p) => {
                if dedup && dd.is_duplicate(&p) {
                    continue;
                }
                let d = decode(p.link, &p.data);
                if filter.matches(&p, &d) && !f(&p, &d) {
                    break;
                }
            }
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    Ok(Scan { err, interfaces: reader.interfaces(), duplicates: dd.dropped })
}

fn finish(e: Option<PcapError>) -> ExitCode {
    match e {
        Some(e) => {
            eprintln!("pks: the capture file ends early or is damaged: {e}");
            ExitCode::from(1)
        }
        None => ExitCode::SUCCESS,
    }
}

fn human_bytes(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2} GB", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.1} MB", n as f64 / 1e6)
    } else if n >= 1000 {
        format!("{:.1} kB", n as f64 / 1e3)
    } else {
        format!("{n} B")
    }
}

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn top<K: Clone + std::fmt::Display>(map: &std::collections::BTreeMap<K, u64>, n: usize) -> Vec<(K, u64)> {
    let mut v: Vec<(K, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.to_string().cmp(&b.0.to_string())));
    v.truncate(n);
    v
}

fn printable(data: &[u8]) -> String {
    data.iter().map(|b| if matches!(b, b'\n' | b'\r' | b'\t') || (0x20..0x7f).contains(b) { *b as char } else { '.' }).collect()
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pks: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Cmd::Show { file, dedup, count, verbose, hex, json, time, checksums, filter } => {
            let filter = parse_filter(&filter)?;
            let style = Style {
                time: match time {
                    TimeArg::Rel => TimeMode::Relative,
                    TimeArg::Delta => TimeMode::Delta,
                    TimeArg::Abs => TimeMode::Absolute,
                    TimeArg::Epoch => TimeMode::Epoch,
                },
                checksums,
            };
            let mut out = BufWriter::new(io::stdout().lock());
            let (mut first, mut prev, mut shown) = (None::<f64>, 0.0f64, 0u64);
            // Relative and delta times refer to the first and previous packet of the capture, matching or not.
            let reader = open_capture(&file)?;
            let mut dd = Dedup::new();
            for p in reader {
                let p = match p {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = out.flush();
                        return Ok(finish(Some(e)));
                    }
                };
                if dedup && dd.is_duplicate(&p) {
                    continue;
                }
                let t = p.time();
                let f0 = *first.get_or_insert(t);
                let prev_t = if prev == 0.0 { t } else { prev };
                prev = t;
                let d = decode(p.link, &p.data);
                if !filter.matches(&p, &d) {
                    continue;
                }
                let res = if json {
                    writeln!(out, "{}", format::json(&p, &d))
                } else if verbose {
                    write!(out, "{}\n{}", format::summary(&p, &d, f0, prev_t, &style), format::verbose(&p, &d))
                        .and_then(|_| if hex { write!(out, "{}", format::hexdump(&p.data, "    ")) } else { Ok(()) })
                        .and_then(|_| writeln!(out))
                } else {
                    writeln!(out, "{}", format::summary(&p, &d, f0, prev_t, &style)).and_then(|_| {
                        if hex {
                            write!(out, "{}", format::hexdump(&p.data, "    "))
                        } else {
                            Ok(())
                        }
                    })
                };
                if res.is_err() {
                    // The reader of the output went away (head, a closed pipe).
                    return Ok(ExitCode::SUCCESS);
                }
                shown += 1;
                if count.is_some_and(|c| shown >= c) {
                    break;
                }
            }
            let _ = out.flush();
        }
        Cmd::Stats { file, dedup, json, filter } => {
            let filter = parse_filter(&filter)?;
            let mut stats = Stats::default();
            let mut flows = FlowTable::new();
            let scan = each_packet(&file, &filter, dedup, |p, d| {
                stats.add(p, d);
                flows.add(p, d);
                true
            })?;
            let err = scan.err;
            if json {
                println!("{}", serde_json::to_string_pretty(&stats).map_err(|e| e.to_string())?);
                return Ok(finish(err));
            }
            let dur = stats.duration();
            println!("{} packets, {} on the wire, {:.2} s", thousands(stats.packets), human_bytes(stats.bytes), dur);
            if scan.interfaces.len() > 1 {
                let names: Vec<String> = scan
                    .interfaces
                    .iter()
                    .enumerate()
                    .map(|(i, f)| format!("{i}={}", f.name.as_deref().unwrap_or("unnamed")))
                    .collect();
                println!("{} interfaces: {}", scan.interfaces.len(), names.join(", "));
                if !dedup {
                    println!("(a packet seen on several interfaces is counted once per interface; --dedup counts it once)");
                }
            }
            if scan.duplicates > 0 {
                println!("{} duplicate copies skipped", thousands(scan.duplicates));
            }
            if dur > 0.0 {
                println!(
                    "{:.0} packets/s on average, {} /s, busiest second {} packets",
                    stats.packets as f64 / dur,
                    human_bytes((stats.bytes as f64 / dur) as u64),
                    stats.peak_pps
                );
            }
            if let Some(average) = stats.bytes.checked_div(stats.packets) {
                println!("frame sizes: min {}, average {average}, max {}", stats.min_len.unwrap_or(0), stats.max_len);
            }
            println!("\nProtocols (by the highest layer decoded)");
            let mut protos: Vec<_> = stats.protocols.iter().collect();
            protos.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then(a.0.cmp(b.0)));
            for (name, (n, bytes)) in protos {
                println!(
                    "  {name:<16} {:>9} packets {:>10}  {:>5.1}%",
                    thousands(*n),
                    human_bytes(*bytes),
                    *bytes as f64 * 100.0 / stats.bytes.max(1) as f64
                );
            }
            let mut hosts: Vec<_> = stats.hosts.iter().collect();
            hosts.sort_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)).then(a.0.cmp(b.0)));
            if !hosts.is_empty() {
                println!("\nBusiest hosts (bytes sent / received)");
                for (ip, (sent, recv)) in hosts.iter().take(8) {
                    println!("  {:<40} {:>10} / {:<10}", ip.to_string(), human_bytes(*sent), human_bytes(*recv));
                }
            }
            let list = |title: &str, map: &std::collections::BTreeMap<String, u64>| {
                if !map.is_empty() {
                    println!("\n{title}");
                    for (k, c) in top(map, 8) {
                        println!("  {c:>6}  {k}");
                    }
                }
            };
            list(
                &format!(
                    "DNS names asked ({} queries, {} answered NXDOMAIN)",
                    stats.dns_queries.values().sum::<u64>(),
                    stats.dns_nxdomain
                ),
                &stats.dns_queries,
            );
            list("TLS server names (SNI)", &stats.tls_sni);
            list("HTTP hosts", &stats.http_hosts);
            let retrans: u64 = flows.flows().iter().map(|f| f.retransmissions).sum();
            let tcp_flows = flows.flows().iter().filter(|f| f.proto == pktscope::flow::Proto::Tcp).count();
            println!(
                "\n{} conversations ({} TCP); {} SYN, {} RST, {} retransmitted segments",
                flows.flows().len(),
                tcp_flows,
                stats.tcp_syn,
                stats.tcp_rst,
                retrans
            );
            if stats.truncated_packets > 0 || stats.undecoded_packets > 0 {
                println!(
                    "{} packets were cut short by the capture, {} could not be decoded",
                    stats.truncated_packets, stats.undecoded_packets
                );
            }
            return Ok(finish(err));
        }
        Cmd::Flows { file, dedup, json, filter } => {
            let filter = parse_filter(&filter)?;
            let mut flows = FlowTable::new();
            let err = each_packet(&file, &filter, dedup, |p, d| {
                flows.add(p, d);
                true
            })?
            .err;
            if json {
                println!("{}", serde_json::to_string_pretty(&flows.flows()).map_err(|e| e.to_string())?);
            } else {
                println!(
                    "{:>4}  {:<6} {:<28} {:<28} {:>7} {:>10} {:>9}  {:<11} retrans",
                    "id", "proto", "client", "server", "packets", "bytes", "duration", "state"
                );
                for f in flows.flows() {
                    println!(
                        "{:>4}  {:<6} {:<28} {:<28} {:>7} {:>10} {:>8.3}s  {:<11} {}",
                        f.id,
                        f.proto.name(),
                        f.client.to_string(),
                        f.server.to_string(),
                        thousands(f.total_packets()),
                        human_bytes(f.total_bytes()),
                        f.last_ts - f.first_ts,
                        f.state(),
                        if f.retransmissions > 0 { f.retransmissions.to_string() } else { String::new() }
                    );
                }
            }
            return Ok(finish(err));
        }
        Cmd::Follow { file, flow, dedup, hex, direction, raw } => {
            if raw && direction.is_none() {
                return Err("--raw needs --direction c2s or s2c".to_string());
            }
            // Pass one finds the flow, pass two feeds its segments to the reassembler.
            let all = Filter::parse("").map_err(|e| e.to_string())?;
            let mut table = FlowTable::new();
            each_packet(&file, &all, dedup, |p, d| {
                table.add(p, d);
                true
            })?;
            let f = table
                .get(flow)
                .ok_or_else(|| {
                    format!("there is no conversation {flow} (the capture has {}; see `pks flows`)", table.flows().len())
                })?
                .clone();
            if f.proto != pktscope::flow::Proto::Tcp {
                return Err(format!("conversation {flow} is {}, only TCP can be followed", f.proto.name()));
            }
            let mut table = FlowTable::new();
            let mut re = Reassembler::new();
            let mut last_ts = 0.0;
            let err = each_packet(&file, &all, dedup, |p, d| {
                if let Some((id, dir)) = table.add(p, d) {
                    if id == flow {
                        if let Some(pktscope::decode::Layer::Tcp { seq, flags, .. }) = d.tcp() {
                            let payload = p.data.get(d.payload_offset..d.payload_offset + d.payload_len).unwrap_or(&[]);
                            re.add(dir, *seq, flags.syn, payload, p.time());
                            last_ts = p.time();
                        }
                    }
                }
                true
            })?
            .err;
            re.finish(last_ts);
            let want = |d: Direction| match direction {
                None => true,
                Some(DirArg::C2s) => d == Direction::ClientToServer,
                Some(DirArg::S2c) => d == Direction::ServerToClient,
            };
            let mut out = BufWriter::new(io::stdout().lock());
            if raw {
                for c in re.chunks.iter().filter(|c| want(c.dir)) {
                    out.write_all(&c.data).map_err(|e| e.to_string())?;
                }
                out.flush().map_err(|e| e.to_string())?;
                return Ok(finish(err));
            }
            let _ = writeln!(out, "Conversation {flow}: client {} -> server {}", f.client, f.server);
            for c in re.chunks.iter().filter(|c| want(c.dir)) {
                if c.gap > 0 {
                    let _ = writeln!(out, "--- {} bytes missing from the capture ---", c.gap);
                }
                let arrow = if c.dir == Direction::ClientToServer { "client -> server" } else { "server -> client" };
                let _ = writeln!(out, "--- {arrow}, {} bytes ---", c.data.len());
                if hex {
                    let _ = write!(out, "{}", format::hexdump(&c.data, ""));
                } else {
                    let _ = writeln!(out, "{}", printable(&c.data));
                }
            }
            if re.retransmitted_bytes > 0 || re.conflicting_bytes > 0 {
                let _ = writeln!(
                    out,
                    "--- {} bytes were retransmitted; {} of them differed from the first copy (the first copy is shown) ---",
                    re.retransmitted_bytes, re.conflicting_bytes
                );
            }
            let _ = out.flush();
            return Ok(finish(err));
        }
        Cmd::Dns { file, dedup, json } => {
            let all = Filter::parse("").map_err(|e| e.to_string())?;
            let mut tr = DnsTracker::new();
            let first = std::cell::Cell::new(None::<f64>);
            let err = each_packet(&file, &all, dedup, |p, d| {
                first.set(Some(first.get().unwrap_or(p.time())));
                tr.add(p, d);
                true
            })?
            .err;
            if json {
                println!("{}", serde_json::to_string_pretty(&tr.exchanges).map_err(|e| e.to_string())?);
                return Ok(finish(err));
            }
            let t0 = first.get().unwrap_or(0.0);
            println!("{:>10}  {:<22} {:<6} {:<40} {:<9} {:>9}  answers", "time", "client", "type", "name", "result", "latency");
            for e in &tr.exchanges {
                println!(
                    "{:>10.6}  {:<22} {:<6} {:<40} {:<9} {:>9}  {}",
                    e.time - t0,
                    e.client.to_string(),
                    e.qtype,
                    e.name,
                    e.rcode.as_deref().unwrap_or("no answer"),
                    e.latency_ms.map(|l| format!("{l:.2} ms")).unwrap_or_default(),
                    e.answers.join(", ")
                );
            }
            let unanswered = tr.exchanges.iter().filter(|e| e.response_packet.is_none()).count();
            println!("\n{} queries, {} without a response in the capture", tr.exchanges.len(), unanswered);
            return Ok(finish(err));
        }
        Cmd::Extract { file, out, dedup, filter } => {
            let filter = parse_filter(&filter)?;
            let reader = open_capture(&file)?;
            let mut writer: Option<Writer<BufWriter<File>>> = None;
            let mut link = reader.link_type();
            let (mut kept, mut seen) = (0u64, 0u64);
            let mut dd = Dedup::new();
            for p in reader {
                let p = match p {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("pks: stopping at packet {}: {e}", seen + 1);
                        break;
                    }
                };
                seen += 1;
                if dedup && dd.is_duplicate(&p) {
                    continue;
                }
                link.get_or_insert(p.link);
                let d = decode(p.link, &p.data);
                if !filter.matches(&p, &d) {
                    continue;
                }
                if link != Some(p.link) {
                    return Err(
                        "the capture has packets of different link types; a pcap file holds one (filter by interface first)"
                            .to_string(),
                    );
                }
                if writer.is_none() {
                    let f = File::create(&out).map_err(|e| format!("{}: {e}", out.display()))?;
                    writer = Some(Writer::new(BufWriter::new(f), p.link, 262_144).map_err(|e| e.to_string())?);
                }
                writer.as_mut().unwrap().write(p.ts_sec, p.ts_nsec, p.orig_len, &p.data).map_err(|e| e.to_string())?;
                kept += 1;
            }
            if let Some(w) = writer {
                w.into_inner().flush().map_err(|e| e.to_string())?;
            } else {
                // An empty result is still a valid capture file.
                let f = File::create(&out).map_err(|e| format!("{}: {e}", out.display()))?;
                Writer::new(BufWriter::new(f), link.unwrap_or(1), 262_144)
                    .map_err(|e| e.to_string())?
                    .into_inner()
                    .flush()
                    .map_err(|e| e.to_string())?;
            }
            eprintln!("wrote {kept} of {seen} packets to {}", out.display());
        }
        Cmd::Capture { out, seconds, port, ip, proto, snaplen, nics_only, keep_etl } => {
            let opts = CaptureOptions { ports: port, ips: ip, protocol: proto, snaplen, nics_only };
            #[cfg(windows)]
            install_ctrl_c();
            if seconds.is_none() {
                eprintln!("capturing; press Enter or Ctrl+C to stop");
                std::thread::spawn(|| {
                    let mut s = String::new();
                    let _ = io::stdin().read_line(&mut s);
                    INTERRUPTED.store(true, Ordering::SeqCst);
                });
            }
            let path = capture::record(&opts, &out, seconds, &|| INTERRUPTED.load(Ordering::SeqCst), keep_etl)?;
            eprintln!("wrote {}", path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(windows)]
fn install_ctrl_c() {
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }
    unsafe extern "system" fn handler(_: u32) -> i32 {
        INTERRUPTED.store(true, Ordering::SeqCst);
        1
    }
    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}
