#!/usr/bin/env python3
"""Generate deterministic golden report matrices for PcapRaven Phase 17."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

GOLDEN_DIR = Path("tests/golden")
FIXTURES_DIR = Path("tests/fixtures/pcaps")
BIN_PATH = Path("target/debug/pcapraven")


def run_cmd(args: list[str]) -> str:
    res = subprocess.run([str(BIN_PATH)] + args, capture_output=True, text=True, check=False)
    if res.returncode not in (0, 3):
        print(f"Command failed with {res.returncode}: {args}\nStderr: {res.stderr}", file=sys.stderr)
        sys.exit(1)
    return res.stdout


def main() -> None:
    # Ensure binary exists
    if not BIN_PATH.exists():
        subprocess.run(["cargo", "build", "-p", "pcapraven-cli"], check=True)

    cases = [
        # validate
        ("validate", FIXTURES_DIR / "benign/clean_dns.pcap", "validate/clean_dns", ["table", "json", "ndjson", "csv"], []),
        # flows
        ("flows", FIXTURES_DIR / "benign/clean_tcp_flows.pcap", "flows/clean_tcp_flows", ["table", "json", "ndjson", "csv"], []),
        # dns
        ("dns", FIXTURES_DIR / "benign/clean_dns.pcap", "dns/clean_dns", ["table", "json", "ndjson", "csv"], []),
        # http
        ("http", FIXTURES_DIR / "benign/clean_http.pcap", "http/clean_http", ["table", "json", "ndjson", "csv"], []),
        # tls
        ("tls", FIXTURES_DIR / "benign/clean_tls.pcap", "tls/clean_tls", ["table", "json", "ndjson", "csv"], []),
        # findings
        ("findings", FIXTURES_DIR / "suspicious/periodic_beaconing.pcap", "findings/periodic_beaconing", ["table", "json", "ndjson", "csv"], []),
        ("findings", FIXTURES_DIR / "suspicious/dns_tunneling.pcap", "findings/dns_tunneling", ["table", "json", "ndjson", "csv"], []),
        ("findings", FIXTURES_DIR / "suspicious/c2_multi_signal.pcap", "findings/c2_multi_signal", ["table", "json", "ndjson", "csv"], []),
        ("findings", FIXTURES_DIR / "suspicious/c2_multi_signal.pcap", "findings/c2_multi_signal_mitre_filter", ["table", "json", "ndjson", "csv"], ["--mitre", "T1071.004"]),
        # analyze (table, json, ndjson only; csv is rejected)
        ("analyze", FIXTURES_DIR / "benign/clean_dns.pcap", "analyze/clean_dns", ["table", "json", "ndjson"], []),
        ("analyze", FIXTURES_DIR / "suspicious/c2_multi_signal.pcap", "analyze/c2_multi_signal", ["table", "json", "ndjson"], []),
    ]

    for subcommand, pcap, out_prefix, formats, extra_args in cases:
        out_path_prefix = GOLDEN_DIR / out_prefix
        out_path_prefix.parent.mkdir(parents=True, exist_ok=True)
        for fmt in formats:
            ext = "txt" if fmt == "table" else fmt
            out_file = out_path_prefix.parent / f"{out_path_prefix.name}.{fmt}.{ext}" if fmt == "table" else out_path_prefix.parent / f"{out_path_prefix.name}.{ext}"
            args = [subcommand, "--format", fmt] + extra_args + [str(pcap)]
            stdout = run_cmd(args)
            out_file.write_text(stdout, encoding="utf-8")
            print(f"Generated golden: {out_file} ({len(stdout)} bytes)")

    print("Successfully generated all golden report matrices.")


if __name__ == "__main__":
    main()
