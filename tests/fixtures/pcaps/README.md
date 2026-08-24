# Synthetic PCAP Fixture Corpus

This directory contains the canonical synthetic PCAP fixture corpus for PcapRaven Phase 17 regression, integration, and golden testing.

## Provenance and Privacy

- **100% Synthetic:** All captures in this directory are generated deterministically by `scripts/generate_fixtures.py` using standard packet structures and synthetic payloads.
- **No Real or Sensitive Data:** Zero production captures, customer identifiers, credentials, private keys, or actual organizational traffic.
- **Documentation Address Space:** All IP addresses use RFC 5737 documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Reserved Domain Names:** All domain names use RFC 2606 / RFC 6761 reserved top-level and second-level domains (`example.com`, `example.org`, `.example`, `.test`).
- **Reproducibility:** `python3 scripts/generate_fixtures.py --check` read-only verifies byte-identical generated captures, canonical `manifest.json`, and `checksums.sha256`. Explicit `--write` regenerates only synthetic fixtures and metadata, never goldens.
- **Finite Corpus:** Each fixture is capped at 256 KiB and the aggregate corpus at 4 MiB.

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
| `repeated_low_volume.pcap` | Repeated Low-Volume | 8 short TCP connection instances between the same peer IPs with <= 2 packets each. | `behavior.repeated_low_volume_flows` |
| `c2_multi_signal.pcap` | Multi-Signal C2 Correlation | Single flow exhibiting both periodic timing (5s intervals) and high-diversity DNS queries. | `behavior.periodic_beaconing`, `dns.possible_tunneling`, `behavior.possible_c2_multi_signal` |

### 3. Malformed and Boundary Captures (`malformed/`)

| File | Type | Description | Expected Exit Code |
|---|---|---|:---:|
| `truncated_header.pcap` | Truncated PCAP Header | 12-byte truncated PCAP global header. | 1 |
| `corrupt_packet.pcap` | Truncated First Packet Record | Valid PCAP header followed by an incomplete first packet. No useful record exists. | 1 |
| `useful_then_truncated_record.pcap` | Useful Then Truncated | One valid DNS packet followed by an incomplete packet record. | 3 |
| `zero_length.pcap` | Empty File | 0-byte empty file. | 1 |

### 4. Edge Cases (`edge_cases/`)

| File | Type | Description | Expected Exit Code |
|---|---|---|:---:|
| `non_monotonic_timestamps.pcap` | Temporal Edge Case | Packets with decreasing timestamps (`t=100s`, then `t=50s`). | 0 |
| `multi_section.pcapng` | PCAPNG Sections | Two sections, each with section-local IDB state and EPB/SPB packet data. | 0 |
| `flow_close_out_of_creation_order.pcap` | Flow Ordering | `flow:0` is created first but closes after `flow:1`. | 0 |
| `local_http_partial_with_dns_detection.pcap` | Independent Degradation | Partial HTTP metadata plus independently clean suspicious DNS observations. | 3 |
| `csv_formula_sentinels.pcap` | CSV Safety | Retained HTTP fields beginning `=`, `+`, `-`, and `@`. | 0 |
| `http_privacy_sentinels.pcap` | Privacy | Sensitive header sentinels retained only as presence booleans. | 0 |
