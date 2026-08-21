#!/usr/bin/env python3
"""Deterministic synthetic PCAP fixture corpus generator for PcapRaven Phase 17."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

FIXTURES_DIR = Path("tests/fixtures/pcaps")
BENIGN_DIR = FIXTURES_DIR / "benign"
SUSPICIOUS_DIR = FIXTURES_DIR / "suspicious"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
EDGE_DIR = FIXTURES_DIR / "edge_cases"

# Ethernet constants
ETH_TYPE_IPV4 = 0x0800
MAC_A = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
MAC_B = bytes([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB])

# Documentation IP addresses (RFC 5737)
IP_CLIENT = bytes([192, 0, 2, 10])     # 192.0.2.10
IP_SERVER = bytes([198, 51, 100, 20])  # 198.51.100.20
IP_DNS = bytes([203, 0, 113, 53])      # 203.0.113.53


def ip_checksum(data: bytes) -> int:
    """Calculate standard IP 16-bit one's complement checksum."""
    if len(data) % 2 == 1:
        data += b"\x00"
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def make_ethernet_frame(dst_mac: bytes, src_mac: bytes, eth_type: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


def make_ipv4_packet(src_ip: bytes, dst_ip: bytes, protocol: int, payload: bytes) -> bytes:
    ihl_version = 0x45
    dscp_ecn = 0
    total_len = 20 + len(payload)
    ident = 0x1234
    flags_frag = 0
    ttl = 64
    header_without_cs = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_version,
        dscp_ecn,
        total_len,
        ident,
        flags_frag,
        ttl,
        protocol,
        0,
        src_ip,
        dst_ip,
    )
    cs = ip_checksum(header_without_cs)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_version,
        dscp_ecn,
        total_len,
        ident,
        flags_frag,
        ttl,
        protocol,
        cs,
        src_ip,
        dst_ip,
    )
    return header + payload


def make_udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return header + payload


def make_tcp_packet(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 64240,
) -> bytes:
    data_offset = (5 << 4)  # 20 bytes header
    urgent_ptr = 0
    checksum = 0
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window,
        checksum,
        urgent_ptr,
    )
    return header + payload


def encode_dns_name(name: str) -> bytes:
    parts = name.strip(".").split(".")
    out = bytearray()
    for part in parts:
        b = part.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def make_dns_query(tx_id: int, qname: str, qtype: int = 1) -> bytes:
    flags = 0x0100  # standard query, RD=1
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)
    question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)  # class IN=1
    return header + question


def make_dns_response(tx_id: int, qname: str, answer_ip: bytes = bytes([198, 51, 100, 1])) -> bytes:
    flags = 0x8180  # standard response, QR=1, RD=1, RA=1, NOERROR
    qdcount = 1
    ancount = 1
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)
    question = encode_dns_name(qname) + struct.pack("!HH", 1, 1)
    # Answer: pointer to question qname (0xc00c), type A=1, class IN=1, TTL 300, len 4, IP
    answer = struct.pack("!HHHIH4s", 0xC00C, 1, 1, 300, 4, answer_ip)
    return header + question + answer


class PcapBuilder:
    def __init__(self) -> None:
        self.packets: list[tuple[int, int, bytes]] = []

    def add_packet(self, sec: int, usec: int, frame: bytes) -> None:
        self.packets.append((sec, usec, frame))

    def to_bytes(self) -> bytes:
        # PCAP Global Header: magic 0xa1b2c3d4, v2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        out = bytearray(hdr)
        for sec, usec, pkt in self.packets:
            pkt_hdr = struct.pack("<IIII", sec, usec, len(pkt), len(pkt))
            out.extend(pkt_hdr)
            out.extend(pkt)
        return bytes(out)


def build_clean_dns() -> bytes:
    p = PcapBuilder()
    # Packet 1: DNS Query for example.com
    dns_req = make_dns_query(0x1001, "example.com")
    udp_req = make_udp_packet(53000, 53, dns_req)
    ip_req = make_ipv4_packet(IP_CLIENT, IP_DNS, 17, udp_req)
    p.add_packet(1700000000, 100000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, ip_req))

    # Packet 2: DNS Response for example.com
    dns_resp = make_dns_response(0x1001, "example.com", bytes([198, 51, 100, 1]))
    udp_resp = make_udp_packet(53, 53000, dns_resp)
    ip_resp = make_ipv4_packet(IP_DNS, IP_CLIENT, 17, udp_resp)
    p.add_packet(1700000000, 120000, make_ethernet_frame(MAC_A, MAC_B, ETH_TYPE_IPV4, ip_resp))
    return p.to_bytes()


def build_clean_http() -> bytes:
    p = PcapBuilder()
    # TCP 3-way handshake on port 80
    syn = make_tcp_packet(49152, 80, 1000, 0, 0x02)  # SYN
    p.add_packet(1700000000, 0, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, syn)))

    syn_ack = make_tcp_packet(80, 49152, 2000, 1001, 0x12)  # SYN-ACK
    p.add_packet(1700000000, 10000, make_ethernet_frame(MAC_A, MAC_B, ETH_TYPE_IPV4, make_ipv4_packet(IP_SERVER, IP_CLIENT, 6, syn_ack)))

    ack = make_tcp_packet(49152, 80, 1001, 2001, 0x10)  # ACK
    p.add_packet(1700000000, 20000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, ack)))

    # HTTP Request
    http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: PcapRavenTest\r\n\r\n"
    req_pkt = make_tcp_packet(49152, 80, 1001, 2001, 0x18, http_req)
    p.add_packet(1700000000, 30000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, req_pkt)))

    # HTTP Response
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, world!"
    resp_pkt = make_tcp_packet(80, 49152, 2001, 1001 + len(http_req), 0x18, http_resp)
    p.add_packet(1700000000, 50000, make_ethernet_frame(MAC_A, MAC_B, ETH_TYPE_IPV4, make_ipv4_packet(IP_SERVER, IP_CLIENT, 6, resp_pkt)))

    # Teardown FIN
    fin = make_tcp_packet(49152, 80, 1001 + len(http_req), 2001 + len(http_resp), 0x11)
    p.add_packet(1700000000, 60000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, fin)))
    return p.to_bytes()


def build_clean_tls() -> bytes:
    p = PcapBuilder()
    # ClientHello with SNI secure.example.com and SupportedVersions TLS 1.3
    sni_hostname = b"secure.example.com"
    sni_ext_data = struct.pack("!HHB", len(sni_hostname) + 3, 0, len(sni_hostname)) + sni_hostname
    sni_ext = struct.pack("!HH", 0, len(sni_ext_data)) + sni_ext_data

    # supported_versions in ClientHello: ext_type=43, ext_len=3, list_len=2, version=0x0304 (TLS 1.3)
    supp_vers_ext = struct.pack("!HHB", 43, 3, 2) + bytes([0x03, 0x04])

    exts = sni_ext + supp_vers_ext
    ciphers = bytes([0x13, 0x01, 0x13, 0x02])  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    random_bytes = b"\x01" * 32
    session_id = b""

    ch_body = (
        struct.pack("!H", 0x0303)  # TLS 1.2 legacy version in ClientHello
        + random_bytes
        + struct.pack("!B", len(session_id))
        + session_id
        + struct.pack("!H", len(ciphers))
        + ciphers
        + struct.pack("!BB", 1, 0)  # compression null
        + struct.pack("!H", len(exts))
        + exts
    )

    handshake_msg = struct.pack("!B", 1) + struct.pack("!I", len(ch_body))[1:] + ch_body
    record = struct.pack("!BHH", 22, 0x0303, len(handshake_msg)) + handshake_msg

    # Send TLS record over TCP 443
    syn = make_tcp_packet(50000, 443, 100, 0, 0x02)
    p.add_packet(1700000000, 0, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, syn)))

    tls_pkt = make_tcp_packet(50000, 443, 101, 1, 0x18, record)
    p.add_packet(1700000000, 20000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, tls_pkt)))
    return p.to_bytes()


def build_clean_tcp_flows() -> bytes:
    p = PcapBuilder()
    # Flow 1: Client -> Server on port 8080
    syn1 = make_tcp_packet(40001, 8080, 10, 0, 0x02)
    p.add_packet(1700000000, 1000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, syn1)))
    fin1 = make_tcp_packet(40001, 8080, 11, 1, 0x11)
    p.add_packet(1700000000, 2000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, fin1)))

    # Flow 2: Client -> Server on port 9090
    syn2 = make_tcp_packet(40002, 9090, 20, 0, 0x02)
    p.add_packet(1700000000, 3000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, syn2)))
    fin2 = make_tcp_packet(40002, 9090, 21, 1, 0x11)
    p.add_packet(1700000000, 4000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, fin2)))
    return p.to_bytes()


def build_clean_udp_flows() -> bytes:
    p = PcapBuilder()
    udp1 = make_udp_packet(30001, 7000, b"ping")
    p.add_packet(1700000000, 10000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 17, udp1)))
    udp2 = make_udp_packet(30002, 7001, b"pong")
    p.add_packet(1700000000, 20000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 17, udp2)))
    return p.to_bytes()


def build_periodic_beaconing() -> bytes:
    """10 packets at exact 5.0-second intervals matching behavior.periodic_beaconing."""
    p = PcapBuilder()
    for i in range(10):
        sec = 1700000000 + i * 5
        usec = 0
        pkt = make_tcp_packet(45000, 8080, 100 + i * 10, 1, 0x18, b"beacon")
        p.add_packet(sec, usec, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, pkt)))
    return p.to_bytes()


def build_dns_long_query() -> bytes:
    """A DNS query with a label > 40 chars, qname > 120 chars, diversity > 0.33."""
    p = PcapBuilder()
    lbl1 = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"  # 48 chars, 36 distinct
    lbl2 = "subdomainpart2abcdefghijklmnopqrstuvwxyz012345"   # 46 chars
    lbl3 = "subdomainpart3abcdefghijklmnopqrstuvwxyz012345"   # 46 chars
    qname = f"{lbl1}.{lbl2}.{lbl3}.example.org"  # total wire length ~ 156 bytes
    req = make_dns_query(0x2001, qname)
    udp = make_udp_packet(54000, 53, req)
    p.add_packet(1700000000, 1000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_DNS, 17, udp)))
    return p.to_bytes()


def build_dns_tunneling() -> bytes:
    """10 queries with long diverse labels to the same domain matching dns.possible_tunneling."""
    p = PcapBuilder()
    for i in range(10):
        h1 = hashlib.sha256(f"chunk1-{i}".encode("ascii")).hexdigest()[:48]
        h2 = hashlib.sha256(f"chunk2-{i}".encode("ascii")).hexdigest()[:48]
        h3 = hashlib.sha256(f"chunk3-{i}".encode("ascii")).hexdigest()[:48]
        qname = f"{h1}.{h2}.{h3}.tunnel.example.org"  # wire length > 150 bytes
        req = make_dns_query(0x3000 + i, qname)
        udp = make_udp_packet(55000, 53, req)
        p.add_packet(1700000000 + i, 10000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_DNS, 17, udp)))
    return p.to_bytes()


def build_repeated_low_volume() -> bytes:
    """8 separate short TCP flows between 192.0.2.10 and 198.51.100.20 with <= 2 packets and <= 200 bytes."""
    p = PcapBuilder()
    for i in range(8):
        port = 46000 + i
        sec = 1700000000 + i * 20
        syn = make_tcp_packet(port, 9000, 100, 0, 0x02)
        p.add_packet(sec, 0, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, syn)))
        rst = make_tcp_packet(port, 9000, 101, 0, 0x04)
        p.add_packet(sec, 100000, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, rst)))
    return p.to_bytes()


def build_c2_multi_signal() -> bytes:
    """A flow exhibiting both periodic beaconing and DNS tunneling queries."""
    p = PcapBuilder()
    for i in range(10):
        sec = 1700000000 + i * 5
        h1 = hashlib.sha256(f"c2-data1-{i}".encode("ascii")).hexdigest()[:48]
        h2 = hashlib.sha256(f"c2-data2-{i}".encode("ascii")).hexdigest()[:48]
        h3 = hashlib.sha256(f"c2-data3-{i}".encode("ascii")).hexdigest()[:48]
        qname = f"{h1}.{h2}.{h3}.c2.example.org"
        req = make_dns_query(0x4000 + i, qname)
        udp = make_udp_packet(56000, 53, req)
        p.add_packet(sec, 0, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_DNS, 17, udp)))
    return p.to_bytes()


def build_truncated_header() -> bytes:
    """Truncated 12-byte PCAP header."""
    full = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return full[:12]


def build_corrupt_packet() -> bytes:
    """Valid PCAP header + packet record header claiming 100 bytes but only 10 bytes present."""
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt_hdr = struct.pack("<IIII", 1700000000, 0, 100, 100)
    return hdr + pkt_hdr + b"\x00" * 10


def build_zero_length() -> bytes:
    return b""


def build_non_monotonic_timestamps() -> bytes:
    """Packets with decreasing timestamps."""
    p = PcapBuilder()
    pkt1 = make_tcp_packet(47001, 80, 1, 0, 0x02)
    p.add_packet(1700000100, 0, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, pkt1)))
    pkt2 = make_tcp_packet(47001, 80, 2, 1, 0x10)
    p.add_packet(1700000050, 0, make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, pkt2)))
    return p.to_bytes()


def main() -> None:
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)
    SUSPICIOUS_DIR.mkdir(parents=True, exist_ok=True)
    MALFORMED_DIR.mkdir(parents=True, exist_ok=True)
    EDGE_DIR.mkdir(parents=True, exist_ok=True)

    fixtures: dict[Path, bytes] = {
        BENIGN_DIR / "clean_dns.pcap": build_clean_dns(),
        BENIGN_DIR / "clean_http.pcap": build_clean_http(),
        BENIGN_DIR / "clean_tls.pcap": build_clean_tls(),
        BENIGN_DIR / "clean_tcp_flows.pcap": build_clean_tcp_flows(),
        BENIGN_DIR / "clean_udp_flows.pcap": build_clean_udp_flows(),
        SUSPICIOUS_DIR / "periodic_beaconing.pcap": build_periodic_beaconing(),
        SUSPICIOUS_DIR / "dns_long_query.pcap": build_dns_long_query(),
        SUSPICIOUS_DIR / "dns_tunneling.pcap": build_dns_tunneling(),
        SUSPICIOUS_DIR / "repeated_low_volume.pcap": build_repeated_low_volume(),
        SUSPICIOUS_DIR / "c2_multi_signal.pcap": build_c2_multi_signal(),
        MALFORMED_DIR / "truncated_header.pcap": build_truncated_header(),
        MALFORMED_DIR / "corrupt_packet.pcap": build_corrupt_packet(),
        MALFORMED_DIR / "zero_length.pcap": build_zero_length(),
        EDGE_DIR / "non_monotonic_timestamps.pcap": build_non_monotonic_timestamps(),
    }

    checksum_lines: list[str] = []
    for path, data in sorted(fixtures.items(), key=lambda x: str(x[0])):
        path.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        rel_path = path.relative_to(FIXTURES_DIR)
        checksum_lines.append(f"{sha}  {rel_path}")
        print(f"Wrote {path} ({len(data)} bytes, sha256={sha[:8]}...)")

    checksum_file = FIXTURES_DIR / "checksums.sha256"
    checksum_file.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    print(f"Generated {len(fixtures)} fixtures and updated {checksum_file}")


if __name__ == "__main__":
    main()
