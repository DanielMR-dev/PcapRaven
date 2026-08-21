# Synthetic PCAP Fixture Corpus

This directory contains the canonical synthetic PCAP fixture corpus for PcapRaven Phase 17 regression, integration, and golden testing.

## Provenance and Privacy

- **100% Synthetic:** All captures in this directory are generated deterministically by `scripts/generate_fixtures.py` using standard packet structures and synthetic payloads.
- **No Real or Sensitive Data:** Zero production captures, customer identifiers, credentials, private keys, or actual organizational traffic.
- **Documentation Address Space:** All IP addresses use RFC 5737 documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Reserved Domain Names:** All domain names use RFC 2606 / RFC 6761 reserved top-level and second-level domains (`example.com`, `example.org`, `.example`, `.test`).
- **Reproducibility:** Running `python3 scripts/generate_fixtures.py` reproduces byte-identical captures matching `checksums.sha256`.

---

## Fixture Inventory

### 1. Benign Traffic (`benign/`)

| File | Protocol | Description | Expected Findings |
|---|---|---|---|
| `clean_dns.pcap` | UDP 53 | Benign DNS query and A record response for `example.com`. | *(None)* |
| `clean_http.pcap` | TCP 80 | Benign HTTP/1.1 3-way handshake, GET request, 200 OK response, and FIN teardown. | *(None)* |
| `clean_tls.pcap` | TCP 443 | Benign TLS 1.3 ClientHello with SNI `secure.example.com` and supported versions. | *(None)* |
| `clean_tcp_flows.pcap` | TCP 8080/9090 | Two benign completed TCP flows with clean SYN/FIN lifecycles. | *(None)* |
| `clean_udp_flows.pcap` | UDP 7000/7001 | Two benign completed UDP flows. | *(None)* |

### 2. Suspicious Heuristic Traffic (`suspicious/`)

| File | Heuristic Focus | Description | Expected Findings |
|---|---|---|---|
| `periodic_beaconing.pcap` | Periodic Beaconing | 10 packets sent at exact 5.0-second intervals with minimal jitter (< 2%). | `behavior.periodic_beaconing` |
| `dns_long_query.pcap` | DNS Long Query | DNS query with long label (> 40 bytes), wire length > 120 bytes, diversity ratio > 0.33. | `dns.long_query_name` |
| `dns_tunneling.pcap` | DNS Tunneling | 10 DNS queries with long, high-diversity hex subdomains to `tunnel.example.org`. | `dns.possible_tunneling` |
| `repeated_low_volume.pcap` | Repeated Low-Volume | 5 short TCP connection instances between the same peer IPs with <= 2 packets each. | `behavior.repeated_low_volume_flows` |
| `c2_multi_signal.pcap` | Multi-Signal C2 Correlation | Single flow exhibiting both periodic timing (5s intervals) and high-diversity DNS queries. | `behavior.periodic_beaconing`, `dns.possible_tunneling`, `behavior.possible_c2_multi_signal` |

### 3. Malformed and Boundary Captures (`malformed/`)

| File | Type | Description | Expected Exit Code |
|---|---|---|:---:|
| `truncated_header.pcap` | Truncated PCAP Header | 12-byte truncated PCAP global header. | 1 |
| `corrupt_packet.pcap` | Truncated Packet Record | Valid PCAP header followed by an incomplete packet truncated before claimed length. | 3 |
| `zero_length.pcap` | Empty File | 0-byte empty file. | 1 |

### 4. Edge Cases (`edge_cases/`)

| File | Type | Description | Expected Exit Code |
|---|---|---|:---:|
| `non_monotonic_timestamps.pcap` | Temporal Edge Case | Packets with decreasing timestamps (`t=100s`, then `t=50s`). | 0 / 3 (Handled cleanly without negative interval panics) |
