#!/usr/bin/env python3
"""Deterministically write or read-only verify the synthetic Phase 17 corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from verification_support import (
    BoundedDiagnostics,
    FileSizeLimitExceeded,
    discover_files,
    read_file_bounded,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES_RELATIVE_ROOT = Path("tests/fixtures/pcaps")
FIXTURES_DIR = ROOT / FIXTURES_RELATIVE_ROOT
BENIGN_DIR = FIXTURES_DIR / "benign"
SUSPICIOUS_DIR = FIXTURES_DIR / "suspicious"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
EDGE_DIR = FIXTURES_DIR / "edge_cases"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"
CHECKSUMS_PATH = FIXTURES_DIR / "checksums.sha256"
MAX_FIXTURE_BYTES = 256 * 1024
MAX_CORPUS_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_DISCOVERY_ENTRIES = 4096
MAX_DISCOVERED_CAPTURE_FILES = 1024
MAX_DISCOVERY_DEPTH = 8
MAX_REPORTED_ERRORS = 50
KNOWN_CATEGORIES = {"benign", "suspicious", "malformed", "edge_cases"}

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


def _ng_block(block_type: int, body: bytes) -> bytes:
    total_length = 12 + len(body)
    if total_length % 4:
        raise ValueError("PCAPNG block body must be 32-bit aligned")
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def _pcapng_shb() -> bytes:
    return _ng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))


def _pcapng_idb() -> bytes:
    end_option = struct.pack("<HH", 0, 0)
    return _ng_block(1, struct.pack("<HHI", 1, 0, 65535) + end_option)


def _padded(data: bytes) -> bytes:
    return data + bytes((-len(data)) % 4)


def _pcapng_epb(timestamp: int, packet: bytes) -> bytes:
    body = struct.pack(
        "<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), len(packet)
    )
    return _ng_block(6, body + _padded(packet) + struct.pack("<HH", 0, 0))


def _pcapng_spb(packet: bytes) -> bytes:
    return _ng_block(3, struct.pack("<I", len(packet)) + _padded(packet))


def build_multi_section_pcapng() -> bytes:
    first = make_ethernet_frame(
        MAC_B,
        MAC_A,
        ETH_TYPE_IPV4,
        make_ipv4_packet(IP_CLIENT, IP_DNS, 17, make_udp_packet(53000, 53, make_dns_query(0x5101, "first.example"))),
    )
    second = make_ethernet_frame(
        MAC_A,
        MAC_B,
        ETH_TYPE_IPV4,
        make_ipv4_packet(IP_SERVER, IP_CLIENT, 17, make_udp_packet(7000, 7001, b"section-two")),
    )
    return (
        _pcapng_shb()
        + _pcapng_idb()
        + _pcapng_epb(1_700_000_000_000_000, first)
        + _pcapng_shb()
        + _pcapng_idb()
        + _pcapng_spb(second)
    )


def build_useful_then_truncated_record() -> bytes:
    p = PcapBuilder()
    packet = make_ethernet_frame(
        MAC_B,
        MAC_A,
        ETH_TYPE_IPV4,
        make_ipv4_packet(IP_CLIENT, IP_DNS, 17, make_udp_packet(53000, 53, make_dns_query(0x5201, "useful.example"))),
    )
    p.add_packet(1700000000, 0, packet)
    return p.to_bytes() + struct.pack("<IIII", 1700000001, 0, 128, 128) + b"truncated"


def build_flow_close_out_of_creation_order() -> bytes:
    p = PcapBuilder()
    flow0 = (48000, 8080)
    flow1 = (48001, 8081)
    for usec, ports, flags in [
        (0, flow0, 0x02),
        (1000, flow1, 0x02),
        (2000, flow1, 0x04),
        (3000, flow0, 0x04),
    ]:
        tcp = make_tcp_packet(ports[0], ports[1], 1, 0, flags)
        frame = make_ethernet_frame(
            MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, tcp)
        )
        p.add_packet(1700000000, usec, frame)
    return p.to_bytes()


def build_local_http_partial_with_dns_detection() -> bytes:
    p = PcapBuilder()
    partial_http = b"GET / HTTP/1.1\r\nHost: example.com\r\nBroken"
    tcp = make_tcp_packet(49000, 80, 1, 1, 0x18, partial_http)
    p.add_packet(
        1700000000,
        0,
        make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_SERVER, 6, tcp)),
    )
    for i in range(10):
        labels = [hashlib.sha256(f"local-{part}-{i}".encode()).hexdigest()[:48] for part in range(3)]
        query = make_dns_query(0x5300 + i, ".".join(labels) + ".partial.example")
        udp = make_udp_packet(57000, 53, query)
        p.add_packet(
            1700000001 + i,
            0,
            make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(IP_CLIENT, IP_DNS, 17, udp)),
        )
    return p.to_bytes()


def build_csv_formula_sentinels() -> bytes:
    p = PcapBuilder()
    request = (
        b"GET /formula HTTP/1.1\r\n"
        b"Host: =host.example\r\n"
        b"Content-Type: +phase17/type\r\n"
        b"User-Agent: @phase17-agent\r\n\r\n"
    )
    response = b"HTTP/1.1 200 OK\r\nServer: -phase17-server\r\nContent-Length: 0\r\n\r\n"
    for usec, src, dst, src_port, dst_port, payload in [
        (0, IP_CLIENT, IP_SERVER, 49100, 80, request),
        (1000, IP_SERVER, IP_CLIENT, 80, 49100, response),
    ]:
        tcp = make_tcp_packet(src_port, dst_port, 1, 1, 0x18, payload)
        p.add_packet(
            1700000000,
            usec,
            make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(src, dst, 6, tcp)),
        )
    return p.to_bytes()


def build_http_privacy_sentinels() -> bytes:
    p = PcapBuilder()
    request = (
        b"GET /privacy HTTP/1.1\r\nHost: privacy.example\r\n"
        b"Authorization: PHASE18_AUTH_SECRET\r\n"
        b"Proxy-Authorization: PHASE18_PROXY_AUTH_SECRET\r\n"
        b"Cookie: PHASE18_COOKIE_SECRET\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
        b"Set-Cookie: PHASE18_SET_COOKIE_SECRET\r\n\r\n"
    )
    for usec, src, dst, src_port, dst_port, payload in [
        (0, IP_CLIENT, IP_SERVER, 49200, 80, request),
        (1000, IP_SERVER, IP_CLIENT, 80, 49200, response),
    ]:
        tcp = make_tcp_packet(src_port, dst_port, 1, 1, 0x18, payload)
        p.add_packet(
            1700000000,
            usec,
            make_ethernet_frame(MAC_B, MAC_A, ETH_TYPE_IPV4, make_ipv4_packet(src, dst, 6, tcp)),
        )
    return p.to_bytes()


def fixture_definitions() -> dict[str, tuple[bytes, str, str, str]]:
    """Return path -> (bytes, purpose, expected behavior, container format)."""
    return {
        "benign/clean_dns.pcap": (build_clean_dns(), "Clean DNS query and response.", "Complete analysis with no findings.", "pcap"),
        "benign/clean_http.pcap": (build_clean_http(), "Clean HTTP/1.1 request and response.", "Complete HTTP observations with no findings.", "pcap"),
        "benign/clean_tcp_flows.pcap": (build_clean_tcp_flows(), "Two clean TCP flows.", "Canonical complete flow output.", "pcap"),
        "benign/clean_tls.pcap": (build_clean_tls(), "Clean TLS ClientHello metadata.", "Complete visible TLS observation.", "pcap"),
        "benign/clean_udp_flows.pcap": (build_clean_udp_flows(), "Two clean UDP flows.", "Complete bounded flow output.", "pcap"),
        "edge_cases/csv_formula_sentinels.pcap": (build_csv_formula_sentinels(), "Retained HTTP text beginning with CSV formula triggers.", "CSV prefixes dangerous cells while JSON and NDJSON preserve factual text.", "pcap"),
        "edge_cases/flow_close_out_of_creation_order.pcap": (build_flow_close_out_of_creation_order(), "Flows close in reverse creation order.", "Final flow order remains flow:0 then flow:1.", "pcap"),
        "edge_cases/http_privacy_sentinels.pcap": (build_http_privacy_sentinels(), "Sensitive HTTP header non-retention sentinels.", "Presence flags are retained and secret values never appear in output.", "pcap"),
        "edge_cases/local_http_partial_with_dns_detection.pcap": (build_local_http_partial_with_dns_detection(), "Partial HTTP beside independent suspicious DNS behavior.", "Analysis is partial and the DNS detector still emits its finding.", "pcap"),
        "edge_cases/multi_section.pcapng": (build_multi_section_pcapng(), "Two supported PCAPNG sections with section-local interfaces.", "Both section records validate and analyze deterministically.", "pcapng"),
        "edge_cases/non_monotonic_timestamps.pcap": (build_non_monotonic_timestamps(), "Decreasing packet timestamps.", "Temporal degradation is represented without negative duration.", "pcap"),
        "malformed/corrupt_packet.pcap": (build_corrupt_packet(), "Truncated first packet record.", "No useful record; every command exits 1.", "pcap"),
        "malformed/truncated_header.pcap": (build_truncated_header(), "Truncated PCAP global header.", "Fails before useful records with exit 1.", "pcap"),
        "malformed/useful_then_truncated_record.pcap": (build_useful_then_truncated_record(), "Useful packet followed by a truncated record.", "Produces a useful partial result with capture_truncated and exit 3.", "pcap"),
        "malformed/zero_length.pcap": (build_zero_length(), "Empty capture input.", "Fails before useful records with exit 1.", "pcap"),
        "suspicious/c2_multi_signal.pcap": (build_c2_multi_signal(), "Synthetic correlated DNS timing signals.", "Emits periodic, DNS tunneling, and correlated findings.", "pcap"),
        "suspicious/dns_long_query.pcap": (build_dns_long_query(), "Single long diverse DNS query.", "Emits dns.long_query_name.", "pcap"),
        "suspicious/dns_tunneling.pcap": (build_dns_tunneling(), "Repeated long diverse DNS queries.", "Emits dns.possible_tunneling.", "pcap"),
        "suspicious/periodic_beaconing.pcap": (build_periodic_beaconing(), "Regular directional packet timing.", "Emits behavior.periodic_beaconing.", "pcap"),
        "suspicious/repeated_low_volume.pcap": (build_repeated_low_volume(), "Repeated short low-volume flows.", "Emits behavior.repeated_low_volume_flows.", "pcap"),
    }


def expected_metadata(fixtures: dict[str, tuple[bytes, str, str, str]]) -> tuple[bytes, bytes]:
    entries = []
    checksum_lines = []
    for rel_path in sorted(fixtures):
        data, purpose, expected_behavior, container_format = fixtures[rel_path]
        category = rel_path.split("/", 1)[0]
        digest = hashlib.sha256(data).hexdigest()
        entries.append({
            "id": rel_path.rsplit(".", 1)[0].replace("/", "."),
            "path": rel_path,
            "category": category,
            "container_format": container_format,
            "sha256": digest,
            "synthetic": True,
            "license": "MIT",
            "purpose": purpose,
            "expected_behavior": expected_behavior,
        })
        checksum_lines.append(f"{digest}  {rel_path}")
    manifest = {"schema_version": 1, "generator_version": 1, "fixtures": entries}
    return (
        (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("utf-8"),
        ("\n".join(checksum_lines) + "\n").encode("utf-8"),
    )


def validate_definitions(fixtures: dict[str, tuple[bytes, str, str, str]]) -> list[str]:
    errors = []
    aggregate = 0
    for rel_path, (data, purpose, expected_behavior, container_format) in fixtures.items():
        category = rel_path.split("/", 1)[0]
        if category not in KNOWN_CATEGORIES:
            errors.append(f"unknown category for {rel_path}: {category}")
        if container_format not in {"pcap", "pcapng"} or not rel_path.endswith(f".{container_format}"):
            errors.append(f"container metadata mismatch for {rel_path}")
        if not purpose or not expected_behavior:
            errors.append(f"missing descriptive metadata for {rel_path}")
        if len(data) > MAX_FIXTURE_BYTES:
            errors.append(f"fixture exceeds {MAX_FIXTURE_BYTES} bytes: {rel_path}")
        aggregate += len(data)
    if aggregate > MAX_CORPUS_BYTES:
        errors.append(f"aggregate corpus exceeds {MAX_CORPUS_BYTES} bytes")
    return errors


def check(fixtures: dict[str, tuple[bytes, str, str, str]]) -> int:
    errors = BoundedDiagnostics(MAX_REPORTED_ERRORS)
    errors.extend(validate_definitions(fixtures))
    expected_paths = set(fixtures)
    discovery = discover_files(
        ROOT,
        FIXTURES_RELATIVE_ROOT,
        lambda path: path.suffix.lower() in {".pcap", ".pcapng"},
        errors,
        maximum_entries=MAX_DISCOVERY_ENTRIES,
        maximum_files=MAX_DISCOVERED_CAPTURE_FILES,
        maximum_depth=MAX_DISCOVERY_DEPTH,
        label="fixture",
    )
    actual_paths = set(discovery.paths)
    for missing in sorted(expected_paths):
        if missing not in actual_paths:
            errors.add(f"missing or non-regular fixture: {missing}")
    for unexpected in sorted(actual_paths - expected_paths):
        errors.add(f"unexpected fixture: {unexpected}")
    if not discovery.complete or errors.has_errors:
        errors.emit()
        return 1

    actual_aggregate = 0
    for rel_path in sorted(expected_paths):
        try:
            actual = read_file_bounded(
                ROOT, FIXTURES_RELATIVE_ROOT / rel_path, MAX_FIXTURE_BYTES
            )
        except FileSizeLimitExceeded as error:
            errors.add(f"cannot hash canonical fixture {rel_path}: {error}")
            continue
        except OSError as error:
            errors.add(f"cannot read canonical fixture {rel_path}: {error}")
            continue
        actual_aggregate += len(actual)
        expected = fixtures[rel_path][0]
        if actual != expected:
            errors.add(f"fixture byte mismatch: {rel_path}")
        if hashlib.sha256(actual).hexdigest() != hashlib.sha256(expected).hexdigest():
            errors.add(f"fixture SHA-256 mismatch: {rel_path}")
    if actual_aggregate > MAX_CORPUS_BYTES:
        errors.add(f"committed aggregate corpus exceeds {MAX_CORPUS_BYTES} bytes")
    manifest, checksums = expected_metadata(fixtures)
    for path, expected in [(MANIFEST_PATH, manifest), (CHECKSUMS_PATH, checksums)]:
        try:
            actual = read_file_bounded(
                ROOT, path.relative_to(ROOT), MAX_METADATA_BYTES
            )
        except (OSError, FileSizeLimitExceeded) as error:
            errors.add(f"cannot read metadata file {path.relative_to(ROOT)}: {error}")
            continue
        if actual != expected:
            errors.add(f"non-canonical metadata: {path.relative_to(ROOT)}")
    if errors.has_errors:
        errors.emit()
        return 1
    print(f"verified {len(fixtures)} synthetic fixtures, manifest, and SHA-256 checksums")
    return 0


def write(fixtures: dict[str, tuple[bytes, str, str, str]]) -> int:
    errors = validate_definitions(fixtures)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    for directory in (BENIGN_DIR, SUSPICIOUS_DIR, MALFORMED_DIR, EDGE_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    for rel_path, (data, _, _, _) in sorted(fixtures.items()):
        path = FIXTURES_DIR / rel_path
        path.write_bytes(data)
        print(f"wrote {path.relative_to(ROOT)} ({len(data)} bytes)")
    manifest, checksums = expected_metadata(fixtures)
    MANIFEST_PATH.write_bytes(manifest)
    CHECKSUMS_PATH.write_bytes(checksums)
    print("wrote canonical fixture manifest and checksums; golden files were not touched")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="read-only verification")
    mode.add_argument("--write", action="store_true", help="regenerate synthetic fixtures and metadata")
    args = parser.parse_args()
    fixtures = fixture_definitions()
    return check(fixtures) if args.check else write(fixtures)


if __name__ == "__main__":
    raise SystemExit(main())
