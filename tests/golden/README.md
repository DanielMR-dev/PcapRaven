# PcapRaven Golden Reports Matrix

This directory contains the canonical golden output files for PcapRaven Phase 17 end-to-end regression testing.

## Purpose

The golden suite verifies that PcapRaven CLI commands produce exact, deterministic, byte-for-byte consistent outputs across all supported subcommands and serialization formats (`table`, `json`, `ndjson`, `csv`).

Canonical golden text files are stored and checked out with LF (`\n`) line endings on every supported platform. Golden verification is byte-exact, so platform checkout conversion must not change their bytes.

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
    ├── c2_multi_signal.{table.txt, json, ndjson}
    └── useful_then_truncated_record.json
```

The matrix also includes `validate/multi_section.json`, canonical flow-creation
ordering, local HTTP degradation with independent DNS detection, CSV formula
sentinels, and selected frozen failure diagnostics under `stderr/`.

*Note: `analyze` does not include CSV goldens because CSV export is intentionally rejected for multi-layer forensic analyses with Exit Code 2.*

---

## Golden Update Policy

1. **Never Update Blindly:** Golden outputs must never be updated merely to resolve failing tests.
2. **Intentional Semantic Changes Only:** Any change to a golden file requires explicit justification, a clear explanation of what semantic fact changed, and verification that the change adheres to the frozen schema version (`v1.0`).
3. **Read-Only Verification First:** Run `python3 scripts/check_goldens.py`; it builds or locates the CLI, executes the canonical scenario matrix, and compares exit states and bytes without writing this directory. A missing stdout or stderr path in the scenario model means that stream must be exactly empty, never ignored.
4. **Safe Candidate Staging:** `python3 scripts/stage_goldens.py --output <empty-directory>` creates candidates outside `tests/golden/` only. It refuses this canonical tree and has no accept/environment-variable/blind-update path.
5. **Manual Acceptance:** Review semantic behavior, privacy, exit state, and frozen schema-v1.0 diffs before intentionally copying any selected candidate. PCAPNG goldens represent the supported real section/IDB/EPB/SPB subset; failure scenarios freeze exit states 1, 2, and 3 where applicable.
