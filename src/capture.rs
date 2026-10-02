//! Live capture on Windows without installing a capture driver: `pktmon`, which ships with
//! Windows 10 and later, records packets to an ETL file and converts them to pcapng.
//!
//! This only builds the command lines and runs them; the analysis is the same as for any file.
//! The command builders are plain functions so they can be tested without administrator rights.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct CaptureOptions {
    /// Keep only packets with this port (either direction); at most a few filters are useful.
    pub ports: Vec<u16>,
    /// Keep only packets to or from these addresses.
    pub ips: Vec<String>,
    /// `tcp`, `udp`, `icmp`, `arp`, or empty for everything.
    pub protocol: Option<String>,
    /// Packet bytes to keep (0 for the whole packet).
    pub snaplen: u32,
    /// Capture at the physical network adapters only, instead of every component in the stack
    /// (which records the same packet several times).
    pub nics_only: bool,
}

/// Argument lists for each `pktmon` step. Nothing here touches the system.
pub fn filter_args(o: &CaptureOptions) -> Result<Vec<Vec<String>>, String> {
    let mut out = Vec::new();
    let proto = match o.protocol.as_deref() {
        None | Some("") | Some("any") => None,
        Some(p) => match p.to_ascii_lowercase().as_str() {
            "tcp" => Some("TCP"),
            "udp" => Some("UDP"),
            "icmp" => Some("ICMP"),
            "arp" => Some("ARP"),
            other => return Err(format!("unknown protocol {other:?} (use tcp, udp, icmp or arp)")),
        },
    };
    for ip in &o.ips {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("{ip:?} is not an IP address"));
        }
    }
    let ports: Vec<String> = o.ports.iter().map(|p| p.to_string()).collect();
    // pktmon combines one filter's options with AND; separate filters are ORed.
    let mut base: Vec<String> = vec!["filter".into(), "add".into()];
    if let Some(p) = proto {
        base.push("-t".into());
        base.push(p.into());
    }
    let mut any = false;
    for p in &ports {
        let mut f = base.clone();
        f.extend(["-p".into(), p.clone()]);
        out.push(f);
        any = true;
    }
    for ip in &o.ips {
        let mut f = base.clone();
        f.extend(["-i".into(), ip.clone()]);
        out.push(f);
        any = true;
    }
    if !any && proto.is_some() {
        out.push(base);
    }
    Ok(out)
}

pub fn start_args(o: &CaptureOptions, etl: &Path) -> Vec<String> {
    let mut a: Vec<String> = vec!["start".into(), "--capture".into(), "--pkt-size".into(), o.snaplen.to_string()];
    if o.nics_only {
        a.extend(["--comp".into(), "nics".into()]);
    }
    a.extend(["-f".into(), etl.to_string_lossy().into_owned()]);
    a
}

pub fn convert_args(etl: &Path, out: &Path) -> Vec<String> {
    vec!["etl2pcap".into(), etl.to_string_lossy().into_owned(), "-o".into(), out.to_string_lossy().into_owned()]
}

fn pktmon(args: &[String]) -> Result<(bool, String), String> {
    let o = Command::new("pktmon")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run pktmon (it is part of Windows 10 and later): {e}"))?;
    let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&o.stderr));
    Ok((o.status.success(), text.trim().to_string()))
}

/// Whether a `pktmon status` text says a capture is running: when it is not, the text is just
/// "Packet Monitor is not running."; when it is, it lists the logger parameters.
pub fn is_running(status: &str) -> bool {
    !status.to_ascii_lowercase().contains("is not running") && status.contains("Logger name")
}

/// Records for `seconds` (or until `stop` returns true), converts to pcapng and returns its path.
pub fn record(
    o: &CaptureOptions,
    out: &Path,
    seconds: Option<u64>,
    stop: &dyn Fn() -> bool,
    keep_etl: bool,
) -> Result<PathBuf, String> {
    let filters = filter_args(o)?;
    let etl = out.with_extension("etl");
    let strs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    let (_, status) = pktmon(&strs(&["status"]))?;
    if is_running(&status) {
        return Err(
            "a pktmon capture is already running (another tool or an earlier run); stop it with `pktmon stop`".to_string()
        );
    }
    pktmon(&strs(&["filter", "remove"]))?;
    for f in &filters {
        let (ok, text) = pktmon(f)?;
        if !ok {
            return Err(format!("pktmon rejected a filter: {text}"));
        }
    }
    let (ok, text) = pktmon(&start_args(o, &etl))?;
    if !ok {
        let admin = text.to_ascii_lowercase().contains("access") || text.contains("elevat") || text.contains("administrator");
        return Err(if admin {
            "capturing needs an elevated terminal (run as administrator)".to_string()
        } else {
            format!("pktmon could not start: {text}")
        });
    }
    let start = Instant::now();
    loop {
        if stop() || seconds.is_some_and(|s| start.elapsed() >= Duration::from_secs(s)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (_, stop_text) = pktmon(&strs(&["stop"]))?;
    let _ = pktmon(&strs(&["filter", "remove"]));
    if !etl.is_file() {
        return Err(format!("pktmon did not write {}: {stop_text}", etl.display()));
    }
    let (ok, text) = pktmon(&convert_args(&etl, out))?;
    if !ok || !out.is_file() {
        return Err(format!("pktmon could not convert the capture: {text}"));
    }
    if !keep_etl {
        let _ = std::fs::remove_file(&etl);
    }
    Ok(out.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> CaptureOptions {
        CaptureOptions::default()
    }

    #[test]
    fn no_filters_means_no_filter_commands() {
        assert!(filter_args(&opts()).unwrap().is_empty());
        assert_eq!(start_args(&opts(), Path::new("c.etl")), ["start", "--capture", "--pkt-size", "0", "-f", "c.etl"]);
        assert_eq!(convert_args(Path::new("c.etl"), Path::new("c.pcapng")), ["etl2pcap", "c.etl", "-o", "c.pcapng"]);
    }

    #[test]
    fn filters_per_port_and_address_with_a_protocol() {
        let o = CaptureOptions { ports: vec![53, 443], ips: vec!["192.0.2.1".into()], protocol: Some("UDP".into()), ..opts() };
        let f = filter_args(&o).unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0], ["filter", "add", "-t", "UDP", "-p", "53"]);
        assert_eq!(f[2], ["filter", "add", "-t", "UDP", "-i", "192.0.2.1"]);
        // A protocol alone is a filter of its own.
        let only = filter_args(&CaptureOptions { protocol: Some("tcp".into()), ..opts() }).unwrap();
        assert_eq!(only, vec![vec!["filter".to_string(), "add".into(), "-t".into(), "TCP".into()]]);
    }

    #[test]
    fn bad_input_is_refused_before_anything_runs() {
        assert!(filter_args(&CaptureOptions { protocol: Some("gre".into()), ..opts() })
            .unwrap_err()
            .contains("unknown protocol"));
        assert!(filter_args(&CaptureOptions { ips: vec!["not-an-ip".into()], ..opts() })
            .unwrap_err()
            .contains("not an IP address"));
    }

    #[test]
    fn snaplen_and_nics_only() {
        let a = start_args(&CaptureOptions { snaplen: 128, nics_only: true, ..opts() }, Path::new("x.etl"));
        assert_eq!(a, ["start", "--capture", "--pkt-size", "128", "--comp", "nics", "-f", "x.etl"]);
    }

    #[test]
    fn status_detection() {
        assert!(is_running(
            "Collected Data:\n    Packet counters, packet capture\n\nLogger Parameters:\n    Logger name:        PktMon\n"
        ));
        assert!(!is_running("Packet Monitor is not running."));
        assert!(!is_running(""));
    }
}
