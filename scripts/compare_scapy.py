"""Compares pks with scapy on any capture file, packet by packet.

    python scripts/compare_scapy.py CAPTURE [--pks PATH_TO_PKS]

For every packet it asks scapy for the facts make_fixtures.facts() reports, takes the same facts from
`pks show --json`, and prints the packets where they differ. Exit status 1 if any differ. Use it on
captures of your own traffic to look for decoding mistakes the fixtures do not cover.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging  # noqa: E402

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from make_fixtures import facts  # noqa: E402
from scapy.all import rdpcap  # noqa: E402


def pks_facts(obj):
    """The same fields facts() reports, from one `pks show --json` object."""
    f = {}
    vlans, ext = [], 0
    for l in obj["layers"]:
        kind = l["layer"]
        if kind == "Ethernet":
            f["eth_src"], f["eth_dst"] = l["src"], l["dst"]
        elif kind == "Vlan":
            vlans.append(l["id"])
        elif kind == "Ipv4":
            f.update(l3="ipv4", src=l["src"], dst=l["dst"], ttl=l["ttl"], ip_id=l["id"], ip_proto=l["protocol"], frag_offset=l["fragment_offset"],
                     mf=l["more_fragments"], df=l["dont_fragment"], ihl=l["header_len"])
        elif kind == "Ipv6":
            f.update(l3="ipv6", src=l["src"], dst=l["dst"], hop_limit=l["hop_limit"], traffic_class=l["traffic_class"], flow_label=l["flow_label"])
        elif kind == "Ipv6Fragment":
            f.update(v6_frag_offset=l["offset"], v6_frag_more=l["more_fragments"], v6_frag_id=l["id"])
        elif kind == "Ipv6Extension":
            ext += 1
        elif kind == "Arp":
            f.update(l3="arp", arp_op=l["op"], arp_psrc=l["sender_ip"], arp_pdst=l["target_ip"], arp_hwsrc=l["sender_mac"])
        elif kind == "Tcp":
            fl = l["flags"]
            flags = "".join(c for c, k in zip("FSRPAUEC", ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr")) if fl[k])
            t = dict(sport=l["src_port"], dport=l["dst_port"], seq=l["seq"], ack=l["ack"], flags=flags, window=l["window"], payload=l["payload_len"])
            for o in l["options"]:
                if isinstance(o, dict) and "Mss" in o:
                    t["mss"] = o["Mss"]
                elif isinstance(o, dict) and "WindowScale" in o:
                    t["wscale"] = o["WindowScale"]
                elif o == "SackPermitted":
                    t["sack_permitted"] = True
                elif isinstance(o, dict) and "Timestamp" in o:
                    t["ts_val"], t["ts_ecr"] = o["Timestamp"]["value"], o["Timestamp"]["echo"]
            f["tcp"] = t
        elif kind == "Udp":
            f["udp"] = dict(sport=l["src_port"], dport=l["dst_port"], length=l["length"], payload=l["payload_len"])
        elif kind == "Icmp":
            f["icmp"] = dict(type=l["icmp_type"], code=l["code"])
            if l["id"] is not None:
                f["icmp"].update(id=l["id"], seq=l["seq"])
        elif kind == "Icmpv6":
            f["icmpv6"] = dict(type=l["icmp_type"], code=l["code"])
            if l["id"] is not None:
                f["icmpv6"].update(id=l["id"], seq=l["seq"])
        elif kind == "Dns":
            d = dict(id=l["id"], response=l["response"], rcode=l["rcode"], qdcount=len(l["questions"]), ancount=len(l["answers"]))
            if l["questions"]:
                d["qname"], d["qtype"] = l["questions"][0]["name"], l["questions"][0]["qtype"]
            answers = []
            for r in l["answers"]:
                t, n, data = r["rtype"], r["name"], r["data"]
                if t == 1:
                    answers.append(f"{t}:{n}:{data['A']}")
                elif t == 28:
                    answers.append(f"{t}:{n}:{data['Aaaa']}")
                elif t in (5, 2, 12):
                    key = {5: "Cname", 2: "Ns", 12: "Ptr"}[t]
                    answers.append(f"{t}:{n}:{data[key]}")
                else:
                    answers.append(f"{t}:{n}")
            d["answers"] = answers
            f["dns"] = d
        elif kind == "Dhcp":
            d = dict(op=l["op"], xid=l["xid"], yiaddr=l["your_ip"], message_type=l["message_type"])
            if l["hostname"] is not None:
                d["hostname"] = l["hostname"]
            f["dhcp"] = d
    if vlans:
        f["vlans"] = vlans
    if f.get("l3") == "ipv6":
        f["v6_ext_headers"] = ext
    return f


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    capture = args[0]
    pks = args[args.index("--pks") + 1] if "--pks" in args else os.path.join(os.path.dirname(__file__), "..", "target", "release", "pks.exe" if os.name == "nt" else "pks")
    out = subprocess.run([pks, "show", capture, "--json"], capture_output=True, text=True, check=True).stdout
    ours = [json.loads(l) for l in out.splitlines()]
    scapy_packets = rdpcap(capture)
    if len(ours) != len(scapy_packets):
        sys.exit(f"pks reports {len(ours)} packets, scapy {len(scapy_packets)}")
    bad = 0
    for i, (o, sp) in enumerate(zip(ours, scapy_packets), 1):
        raw = bytes(sp.original)
        want, got = facts(raw), pks_facts(o)
        want.pop("v6_ext_headers", None) if "v6_ext_headers" not in want else None
        # facts() only reports DNS answers scapy names; compare the keys both report.
        if want != got:
            bad += 1
            if bad <= 20:
                diff = [f"  {k}: scapy {want.get(k)!r}  pks {got.get(k)!r}" for k in sorted(set(want) | set(got)) if want.get(k) != got.get(k)]
                print(f"packet {i}:\n" + "\n".join(diff))
    print(f"{len(ours)} packets compared, {bad} differ")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
