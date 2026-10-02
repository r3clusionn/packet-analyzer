"""Builds the capture fixtures and the facts that independent implementations report about them.

    python scripts/make_fixtures.py        (needs scapy:  pip install scapy; and the openssl command)

Writes into tests/fixtures/:

    net.pcap, net.facts.json     many protocol cases built with scapy. The facts are what scapy reports
                                 when it parses the finished bytes again, so they come from a second
                                 implementation and not from the code that built the packets.
    tls12.pcap, tls13.pcap,      real TLS handshakes between two OpenSSL endpoints (Python's ssl module)
    tls.facts.json               carried over TCP. The facts come from the ssl objects: negotiated version,
                                 cipher, server name and ALPN.
    http.pcap, http.facts.json   an HTTP exchange produced by Python's own http.server and http.client.

Addresses are from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32). The files
are deterministic apart from the TLS captures, whose keys and random values are new on every run (so
the fixtures are generated once and committed).
"""
import json
import os
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (  # noqa: E402
    ARP, BOOTP, DHCP, DNS, Padding, DNSQR, DNSRR, Dot1AD, Dot1Q, Ether, ICMP, ICMPv6EchoReply, ICMPv6EchoRequest,
    ICMPv6ND_NA, ICMPv6ND_NS, IP, IPOption_NOP, IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop, Raw, TCP, UDP, conf, fragment,
)

conf.verb = 0
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures")
os.makedirs(OUT, exist_ok=True)

C4, S4, R4 = "192.0.2.10", "198.51.100.20", "203.0.113.1"
C6, S6 = "2001:db8::10", "2001:db8:1::20"
MAC_C, MAC_S = "02:00:00:00:00:0a", "02:00:00:00:00:14"


def write_pcap(path, packets, base=1_700_000_000, step_us=250):
    """Classic pcap, microsecond timestamps, Ethernet."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for i, data in enumerate(packets):
            us = i * step_us
            f.write(struct.pack("<IIII", base + us // 1_000_000, us % 1_000_000, len(data), len(data)))
            f.write(data)


def eth(l3, c2s=True):
    src, dst = (MAC_C, MAC_S) if c2s else (MAC_S, MAC_C)
    return Ether(src=src, dst=dst) / l3


# ---------------------------------------------------------------------------------------------- scapy facts

TCP_FLAG_ORDER = "FSRPAUEC"


def tcp_flags_string(flags):
    names = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}
    v = int(flags)
    return "".join(c for c in TCP_FLAG_ORDER if v & names[c])


def norm_name(n):
    n = n.decode() if isinstance(n, bytes) else str(n)
    return n[:-1] if n.endswith(".") else n


def facts(raw):
    """What scapy sees in finished frame bytes."""
    p = Ether(raw)
    f = {}
    # Ethernet pads short frames; scapy keeps the padding as a layer of its own after the payload.
    pad = len(p[Padding].load) if Padding in p else 0
    f["eth_src"], f["eth_dst"] = p.src, p.dst
    vlans, layer = [], p
    while True:
        layer = layer.payload
        if layer.__class__.__name__ in ("Dot1Q", "Dot1AD"):
            vlans.append(layer.vlan)
        else:
            break
    if vlans:
        f["vlans"] = vlans
    if IP in p:
        ip = p[IP]
        f.update(l3="ipv4", src=ip.src, dst=ip.dst, ttl=ip.ttl, ip_id=ip.id, ip_proto=ip.proto, frag_offset=ip.frag * 8,
                 mf=bool(ip.flags.MF), df=bool(ip.flags.DF), ihl=ip.ihl * 4)
    elif IPv6 in p:
        ip = p[IPv6]
        f.update(l3="ipv6", src=ip.src, dst=ip.dst, hop_limit=ip.hlim, traffic_class=ip.tc, flow_label=ip.fl)
        if IPv6ExtHdrFragment in p:
            fh = p[IPv6ExtHdrFragment]
            f.update(v6_frag_offset=fh.offset * 8, v6_frag_more=bool(fh.m), v6_frag_id=fh.id)
        f["v6_ext_headers"] = sum(1 for n in ("IPv6ExtHdrHopByHop", "IPv6ExtHdrDestOpt", "IPv6ExtHdrRouting") if n in [c.__name__ for c in p.layers()])
    elif ARP in p:
        a = p[ARP]
        f.update(l3="arp", arp_op=a.op, arp_psrc=a.psrc, arp_pdst=a.pdst, arp_hwsrc=a.hwsrc)
    if TCP in p and (IP in p and p[IP].frag == 0 or IPv6 in p):
        t = p[TCP]
        opts = dict((k, v) for k, v in t.options if k != "NOP")
        f["tcp"] = dict(sport=t.sport, dport=t.dport, seq=t.seq, ack=t.ack, flags=tcp_flags_string(t.flags), window=t.window,
                        payload=len(bytes(t.payload)) - pad)
        if "MSS" in opts:
            f["tcp"]["mss"] = opts["MSS"]
        if "WScale" in opts:
            f["tcp"]["wscale"] = opts["WScale"]
        if "SAckOK" in opts:
            f["tcp"]["sack_permitted"] = True
        if "Timestamp" in opts:
            f["tcp"]["ts_val"], f["tcp"]["ts_ecr"] = opts["Timestamp"]
    if UDP in p and (IP in p and p[IP].frag == 0 or IPv6 in p) and UDP in p:
        u = p[UDP]
        f["udp"] = dict(sport=u.sport, dport=u.dport, length=u.len, payload=len(bytes(u.payload)) - pad)
    if ICMP in p:
        i = p[ICMP]
        f["icmp"] = dict(type=i.type, code=i.code)
        if i.type in (0, 8):
            f["icmp"].update(id=i.id, seq=i.seq)
    for lay in p.layers():
        if lay.__name__.startswith("ICMPv6") and hasattr(p.getlayer(lay), "type") and hasattr(p.getlayer(lay), "code"):
            i = p.getlayer(lay)
            f["icmpv6"] = dict(type=i.type, code=i.code)
            if i.type in (128, 129):
                f["icmpv6"].update(id=i.id, seq=i.seq)
            break
    if DNS in p and (UDP in p or TCP in p):
        d = p[DNS]
        f["dns"] = dict(id=d.id, response=bool(d.qr), rcode=d.rcode, qdcount=d.qdcount, ancount=d.ancount)
        if d.qdcount:
            f["dns"]["qname"] = norm_name(d.qd.qname)
            f["dns"]["qtype"] = d.qd.qtype
        answers = []
        for rr in list(d.an):
            if rr.type in (1, 28):
                answers.append(f"{rr.type}:{norm_name(rr.rrname)}:{rr.rdata}")
            elif rr.type in (5, 2, 12):
                answers.append(f"{rr.type}:{norm_name(rr.rrname)}:{norm_name(rr.rdata)}")
            else:
                answers.append(f"{rr.type}:{norm_name(rr.rrname)}")
        f["dns"]["answers"] = answers
    if BOOTP in p and DHCP in p:
        opts = dict((o[0], o[1]) for o in p[DHCP].options if isinstance(o, tuple))
        f["dhcp"] = dict(op=p[BOOTP].op, xid=p[BOOTP].xid, yiaddr=p[BOOTP].yiaddr, message_type=opts.get("message-type"))
        if "hostname" in opts:
            h = opts["hostname"]
            f["dhcp"]["hostname"] = h.decode() if isinstance(h, bytes) else h
    return f


def net_cases():
    cases = []

    def add(name, pkt):
        cases.append((name, bytes(pkt) if not isinstance(pkt, bytes) else pkt))

    opts = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (111, 0)), ("NOP", None), ("WScale", 7)]
    add("tcp_syn_options", eth(IP(src=C4, dst=S4, id=0x1234, ttl=64) / TCP(sport=51234, dport=443, seq=1000, flags="S", window=64240, options=opts)))
    add("tcp_synack", eth(IP(src=S4, dst=C4, id=7) / TCP(sport=443, dport=51234, seq=5000, ack=1001, flags="SA", options=[("MSS", 1380), ("NOP", None), ("WScale", 9), ("SAckOK", b"")]), False))
    add("tcp_data", eth(IP(src=C4, dst=S4) / TCP(sport=51234, dport=8080, seq=1001, ack=5001, flags="PA") / Raw(b"hello over tcp\r\n")))
    add("tcp_fin_ack", eth(IP(src=C4, dst=S4) / TCP(sport=51234, dport=8080, seq=1017, ack=5001, flags="FA")))
    add("tcp_rst", eth(IP(src=S4, dst=C4) / TCP(sport=8080, dport=51234, seq=5001, flags="R"), False))
    add("tcp_all_flags", eth(IP(src=C4, dst=S4) / TCP(sport=1, dport=2, flags="FSRPAUEC")))
    add("tcp_sack_blocks", eth(IP(src=C4, dst=S4) / TCP(sport=1, dport=2, flags="A", options=[("SAck", (100, 200, 300, 400)), ("NOP", None), ("NOP", None)])))
    add("ipv4_options", eth(IP(src=C4, dst=S4, options=[IPOption_NOP(), IPOption_NOP(), IPOption_NOP(), IPOption_NOP()]) / UDP(sport=5000, dport=6000) / Raw(b"x")))
    add("udp_basic", eth(IP(src=C4, dst=S4, flags="DF") / UDP(sport=40000, dport=9999) / Raw(b"datagram payload")))
    add("udp_empty", eth(IP(src=C4, dst=S4) / UDP(sport=40000, dport=9999)))
    big = IP(src=C4, dst=S4, id=0x4242) / UDP(sport=1000, dport=2000) / Raw(bytes(range(256)) * 12)
    for i, frag in enumerate(fragment(big, fragsize=1000)):
        add(f"ipv4_fragment_{i}", eth(frag))
    add("icmp_echo_request", eth(IP(src=C4, dst=S4) / ICMP(type=8, id=0x1234, seq=7) / Raw(b"abcdefgh")))
    add("icmp_echo_reply", eth(IP(src=S4, dst=C4) / ICMP(type=0, id=0x1234, seq=7) / Raw(b"abcdefgh"), False))
    add("icmp_port_unreachable", eth(IP(src=S4, dst=C4) / ICMP(type=3, code=3) / IP(src=C4, dst=S4) / UDP(sport=40000, dport=9) / Raw(b"orig"), False))
    add("icmp_time_exceeded", eth(IP(src=R4, dst=C4) / ICMP(type=11, code=0) / IP(src=C4, dst=S4, ttl=1) / UDP(sport=1, dport=2), False))
    add("arp_who_has", Ether(src=MAC_C, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_C, psrc=C4, hwdst="00:00:00:00:00:00", pdst=S4))
    add("arp_is_at", Ether(src=MAC_S, dst=MAC_C) / ARP(op=2, hwsrc=MAC_S, psrc=S4, hwdst=MAC_C, pdst=C4))
    add("vlan_single", Ether(src=MAC_C, dst=MAC_S) / Dot1Q(vlan=42, prio=3) / IP(src=C4, dst=S4) / UDP(sport=1, dport=2) / Raw(b"v"))
    add("vlan_qinq", Ether(src=MAC_C, dst=MAC_S) / Dot1AD(vlan=100) / Dot1Q(vlan=200) / IP(src=C4, dst=S4) / TCP(sport=3, dport=4, flags="S"))
    add("ipv6_tcp", eth(IPv6(src=C6, dst=S6, hlim=55, tc=10, fl=0x12345) / TCP(sport=40000, dport=443, seq=77, flags="S", options=[("MSS", 1440)])))
    add("ipv6_udp", eth(IPv6(src=C6, dst=S6) / UDP(sport=5000, dport=6000) / Raw(b"six")))
    add("ipv6_ext_headers", eth(IPv6(src=C6, dst=S6) / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt() / UDP(sport=7, dport=8) / Raw(b"ext")))
    add("ipv6_fragment_first", eth(IPv6(src=C6, dst=S6) / IPv6ExtHdrFragment(offset=0, m=1, id=9, nh=17) / UDP(sport=11, dport=12, len=40) / Raw(b"a" * 16)))
    add("ipv6_fragment_later", eth(IPv6(src=C6, dst=S6) / IPv6ExtHdrFragment(offset=3, m=0, id=9, nh=17) / Raw(b"b" * 16)))
    add("icmpv6_echo_request", eth(IPv6(src=C6, dst=S6) / ICMPv6EchoRequest(id=0x77, seq=3, data=b"ping")))
    add("icmpv6_echo_reply", eth(IPv6(src=S6, dst=C6) / ICMPv6EchoReply(id=0x77, seq=3, data=b"ping"), False))
    add("icmpv6_neighbor_solicit", eth(IPv6(src="fe80::1", dst="ff02::1:ff00:2", hlim=255) / ICMPv6ND_NS(tgt="fe80::2")))
    add("icmpv6_neighbor_advert", eth(IPv6(src="fe80::2", dst="fe80::1", hlim=255) / ICMPv6ND_NA(tgt="fe80::2", R=0, S=1, O=1), False))
    # DNS
    add("dns_query_a", eth(IP(src=C4, dst=S4) / UDP(sport=53123, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))))
    add("dns_query_aaaa", eth(IP(src=C4, dst=S4) / UDP(sport=53124, dport=53) / DNS(id=0x1235, rd=1, qd=DNSQR(qname="example.org", qtype="AAAA"))))
    add("dns_response_a", eth(IP(src=S4, dst=C4) / UDP(sport=53, dport=53123) / DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.com", qtype="A"),
                                                                                 an=[DNSRR(rrname="www.example.com", type="A", ttl=300, rdata="93.184.216.34"), DNSRR(rrname="www.example.com", type="A", ttl=300, rdata="93.184.216.35")]), False))
    add("dns_nxdomain", eth(IP(src=S4, dst=C4) / UDP(sport=53, dport=53123) / DNS(id=0x1236, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname="nothing.example.net", qtype="A")), False))
    # A response with real name compression: CNAME then A, both pointing at the question name.
    q = b"\x03www\x07example\x03com\x00"
    msg = struct.pack(">HHHHHH", 0x2222, 0x8180, 1, 3, 0, 0) + q + struct.pack(">HH", 1, 1)
    msg += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, 6) + b"\x03web\xc0\x10"  # CNAME web.example.com (pointer to example.com)
    msg += b"\xc0\x2d" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 9])  # A for web.example.com (pointer into the CNAME data)
    msg += b"\xc0\x2d" + struct.pack(">HHIH", 28, 1, 60, 16) + bytes.fromhex("20010db8000000000000000000000001")
    add("dns_response_compressed", eth(IP(src=S4, dst=C4) / UDP(sport=53, dport=53125) / Raw(msg), False))
    dq = bytes(DNS(id=0x3333, rd=1, qd=DNSQR(qname="tcp.example.com", qtype="A")))
    add("dns_over_tcp", eth(IP(src=C4, dst=S4) / TCP(sport=40001, dport=53, flags="PA", seq=1, ack=1) / Raw(struct.pack(">H", len(dq)) + dq)))
    add("mdns_query", Ether(src=MAC_C, dst="01:00:5e:00:00:fb") / IP(src=C4, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(id=0, rd=0, qd=DNSQR(qname="_http._tcp.local", qtype="PTR")))
    # DHCP
    add("dhcp_discover", Ether(src=MAC_C, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex("02000000000a") + b"\x00" * 10, xid=0xCAFEBABE) / DHCP(options=[("message-type", "discover"), ("hostname", "demo-host"), "end"]))
    add("dhcp_offer", Ether(src=MAC_S, dst=MAC_C) / IP(src=S4, dst="255.255.255.255") / UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr="192.0.2.77", siaddr=S4, chaddr=bytes.fromhex("02000000000a") + b"\x00" * 10, xid=0xCAFEBABE) /
        DHCP(options=[("message-type", "offer"), ("server_id", S4), ("lease_time", 3600), ("subnet_mask", "255.255.255.0"), ("router", "192.0.2.1"), "end"]))
    # Application data over TCP (checked by hand-written expectations in the Rust test, not by scapy).
    add("http_request", eth(IP(src=C4, dst=S4) / TCP(sport=50000, dport=80, flags="PA", seq=1, ack=1) / Raw(b"GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fixture/1.0\r\nAccept: */*\r\n\r\n")))
    add("http_response", eth(IP(src=S4, dst=C4) / TCP(sport=80, dport=50000, flags="PA", seq=1, ack=100) / Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 13\r\n\r\nHello, world!"), False))
    # Ethernet padding: a short frame padded with zeros to 60 bytes.
    short = bytes(eth(IP(src=C4, dst=S4) / UDP(sport=1, dport=2) / Raw(b"p")))
    add("ethernet_padding", short + b"\x00" * (60 - len(short)))
    return cases


def build_net():
    cases = net_cases()
    write_pcap(os.path.join(OUT, "net.pcap"), [c[1] for c in cases])
    out = []
    for i, (name, raw) in enumerate(cases):
        f = facts(raw)
        f["case"], f["number"], f["frame_len"] = name, i + 1, len(raw)
        out.append(f)
    json.dump(out, open(os.path.join(OUT, "net.facts.json"), "w"), indent=1, sort_keys=True)
    print(f"net.pcap: {len(cases)} packets")


# ---------------------------------------------------------------------------------------------- TCP wrapper

class Wire:
    """Wraps byte flights in TCP segments with correct sequence numbers."""

    def __init__(self, client=(C4, 44444), server=(S4, 443)):
        self.client, self.server = client, server
        self.seq = {"c": 1_000_000, "s": 9_000_000}
        self.frames = []

    def _tcp(self, src, flags, payload=b"", ack_from=None):
        s, d = (self.client, self.server) if src == "c" else (self.server, self.client)
        other = "s" if src == "c" else "c"
        pkt = IP(src=s[0], dst=d[0]) / TCP(sport=s[1], dport=d[1], seq=self.seq[src], ack=self.seq[other] if flags != "S" else 0, flags=flags, window=65535)
        if payload:
            pkt = pkt / Raw(payload)
        self.frames.append(bytes(eth(pkt, src == "c")))
        self.seq[src] += len(payload) + (1 if "S" in flags or "F" in flags else 0)

    def handshake(self):
        self._tcp("c", "S")
        self._tcp("s", "SA")
        self._tcp("c", "A")

    def send(self, src, data, mss=1400):
        for i in range(0, len(data), mss):
            self._tcp(src, "PA", data[i:i + mss])

    def close(self):
        self._tcp("c", "FA")
        self._tcp("s", "FA")
        self._tcp("c", "A")


# ---------------------------------------------------------------------------------------------- TLS fixtures

def make_cert(tmp):
    key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "3650",
                    "-subj", "/CN=fixture.example.test", "-addext", "subjectAltName=DNS:fixture.example.test"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return key, crt


def tls_exchange(version_name, tmp, key, crt):
    """Runs a full handshake and a little application data between two in-memory endpoints; returns the
    byte flights in order and the facts the ssl objects report."""
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(crt, key)
    sctx.set_alpn_protocols(["h2", "http/1.1"])
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.load_verify_locations(crt)
    cctx.set_alpn_protocols(["h2", "http/1.1"])
    if version_name == "tls12":
        sctx.maximum_version = cctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        sctx.minimum_version = cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client = cctx.wrap_bio(c_in, c_out, server_hostname="fixture.example.test")
    server = sctx.wrap_bio(s_in, s_out, server_side=True)
    flights = []
    done_c = done_s = False
    for _ in range(20):
        if not done_c:
            try:
                client.do_handshake()
                done_c = True
            except ssl.SSLWantReadError:
                pass
        data = c_out.read()
        if data:
            flights.append(("c", data))
            s_in.write(data)
        if not done_s:
            try:
                server.do_handshake()
                done_s = True
            except ssl.SSLWantReadError:
                pass
        data = s_out.read()
        if data:
            flights.append(("s", data))
            c_in.write(data)
        if done_c and done_s:
            break
    # Flush anything the finished handshake still owes (TLS 1.3 session tickets, the client Finished).
    for _ in range(3):
        data = c_out.read()
        if data:
            flights.append(("c", data))
            s_in.write(data)
        data = s_out.read()
        if data:
            flights.append(("s", data))
            c_in.write(data)
    client.write(b"ping from the client")
    data = c_out.read()
    flights.append(("c", data))
    s_in.write(data)
    server.read(100)
    server.write(b"pong")
    data = s_out.read()
    flights.append(("s", data))
    c_in.write(data)
    facts = dict(version=client.version(), cipher=client.cipher()[0], sni="fixture.example.test", alpn=client.selected_alpn_protocol())
    return flights, facts


def build_tls():
    tmp = tempfile.mkdtemp()
    key, crt = make_cert(tmp)
    allfacts = {}
    for name in ("tls12", "tls13"):
        flights, f = tls_exchange(name, tmp, key, crt)
        w = Wire()
        w.handshake()
        for side, data in flights:
            w.send(side, data)
        w.close()
        write_pcap(os.path.join(OUT, f"{name}.pcap"), w.frames)
        f["packets"] = len(w.frames)
        # The record layer sees the flights, so record the content types of each flight's first record.
        f["flights"] = [{"from": s, "bytes": len(d), "first_record_type": d[0]} for s, d in flights]
        allfacts[name] = f
        print(f"{name}.pcap: {len(w.frames)} packets, {f['version']}, {f['cipher']}, alpn={f['alpn']}")
    json.dump(allfacts, open(os.path.join(OUT, "tls.facts.json"), "w"), indent=1, sort_keys=True)


# ---------------------------------------------------------------------------------------------- HTTP fixture

def build_http():
    import http.client
    import http.server
    import socketserver

    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"<html>hello from the fixture server</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "fixture")
            self.end_headers()
            self.wfile.write(body)
            seen["path"], seen["host"] = self.path, self.headers["Host"]

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    conn.request("GET", "/fixture/page.html?x=1", headers={"Host": "fixture.example.test", "User-Agent": "fixture-client/1.0"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()  # the single-threaded server is blocked serving this keep-alive connection
    srv.shutdown()
    # Reconstruct the two byte streams exactly as http.client / http.server wrote them.
    req = b"GET /fixture/page.html?x=1 HTTP/1.1\r\nHost: fixture.example.test\r\nUser-Agent: fixture-client/1.0\r\nAccept-Encoding: identity\r\n\r\n"
    rsp = (b"HTTP/1.1 200 OK\r\nServer: fixture\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n\r\n" % len(body)) + body
    w = Wire(server=(S4, 80))
    w.handshake()
    w.send("c", req)
    w.send("s", rsp)
    w.close()
    write_pcap(os.path.join(OUT, "http.pcap"), w.frames)
    json.dump(dict(status=resp.status, host=seen["host"], path=seen["path"], content_type=resp.getheader("Content-Type"),
                   content_length=int(resp.getheader("Content-Length")), request_bytes=len(req), response_bytes=len(rsp), body=body.decode()),
              open(os.path.join(OUT, "http.facts.json"), "w"), indent=1, sort_keys=True)
    print(f"http.pcap: {len(w.frames)} packets")


if __name__ == "__main__":
    build_net()
    build_tls()
    build_http()
