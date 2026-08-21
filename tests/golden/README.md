# PcapRaven Golden Reports Matrix

This directory contains the canonical golden output files for PcapRaven Phase 17 end-to-end regression testing.

## Purpose

The golden suite verifies that PcapRaven CLI commands produce exact, deterministic, byte-for-byte consistent outputs across all supported subcommands and serialization formats (`table`, `json`, `ndjson`, `csv`).

---

## Directory Structure

```text
tests/golden/
├── validate/
│   ├── clean_dns.table.txt
│   ├── clean_dns.json
│   ├── clean_dns.ndjson
│   └── clean_dns.csv
├── flows/
│   ├── clean_tcp_flows.table.txt
│   ├── clean_tcp_flows.json
│   ├── clean_tcp_flows.ndjson
│   └── clean_tcp_flows.csv
├── dns/
│   ├── clean_dns.table.txt
│   ├── clean_dns.json
│   ├── clean_dns.ndjson
│   └── clean_dns.csv
├── http/
│   ├── clean_http.table.txt
│   ├── clean_http.json
│   ├── clean_http.ndjson
│   └── clean_http.csv
├── tls/
│   ├── clean_tls.table.txt
│   ├── clean_tls.json
│   ├── clean_tls.ndjson
│   └── clean_tls.csv
├── findings/
│   ├── periodic_beaconing.{table.txt, json, ndjson, csv}
│   ├── dns_tunneling.{table.txt, json, ndjson, csv}
│   ├── c2_multi_signal.{table.txt, json, ndjson, csv}
│   └── c2_multi_signal_mitre_filter.{table.txt, json, ndjson, csv}
└── analyze/
    ├── clean_dns.{table.txt, json, ndjson}
    └── c2_multi_signal.{table.txt, json, ndjson}
```

*Note: `analyze` does not include CSV goldens because CSV export is intentionally rejected for multi-layer forensic analyses with Exit Code 2.*

---

## Golden Update Policy

1. **Never Update Blindly:** Golden outputs must never be updated merely to resolve failing tests.
2. **Intentional Semantic Changes Only:** Any change to a golden file requires explicit justification, a clear explanation of what semantic fact changed, and verification that the change adheres to the frozen schema version (`v1.0`).
3. **Regeneration:** Golden files can be deterministically updated via `python3 scripts/generate_goldens.py` after building the CLI binary.
