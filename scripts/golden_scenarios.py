"""Canonical, platform-independent Phase 17 golden scenario matrix."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Scenario:
    """Exact CLI result; a missing stream path requires that stream to be empty."""

    name: str
    args: tuple[str, ...]
    expected_exit: int
    stdout_path: str | None
    stderr_path: str | None = None


def scenarios(root: Path) -> tuple[Scenario, ...]:
    fixtures = root / "tests/fixtures/pcaps"

    def fixture(path: str) -> str:
        return str(fixtures / path)

    cases: list[Scenario] = []

    def formats(command: str, capture: str, prefix: str, supported: tuple[str, ...], extra: tuple[str, ...] = ()) -> None:
        for output_format in supported:
            extension = "table.txt" if output_format == "table" else output_format
            cases.append(Scenario(
                f"{prefix}-{output_format}",
                (command, "--format", output_format, *extra, fixture(capture)),
                0,
                f"{prefix}.{extension}",
            ))

    formats("validate", "benign/clean_dns.pcap", "validate/clean_dns", ("table", "json", "ndjson", "csv"))
    formats("flows", "benign/clean_tcp_flows.pcap", "flows/clean_tcp_flows", ("table", "json", "ndjson", "csv"))
    formats("dns", "benign/clean_dns.pcap", "dns/clean_dns", ("table", "json", "ndjson", "csv"))
    formats("http", "benign/clean_http.pcap", "http/clean_http", ("table", "json", "ndjson", "csv"))
    formats("tls", "benign/clean_tls.pcap", "tls/clean_tls", ("table", "json", "ndjson", "csv"))
    formats("findings", "suspicious/periodic_beaconing.pcap", "findings/periodic_beaconing", ("table", "json", "ndjson", "csv"))
    formats("findings", "suspicious/dns_tunneling.pcap", "findings/dns_tunneling", ("table", "json", "ndjson", "csv"))
    formats("findings", "suspicious/c2_multi_signal.pcap", "findings/c2_multi_signal", ("table", "json", "ndjson", "csv"))
    formats(
        "findings",
        "suspicious/c2_multi_signal.pcap",
        "findings/c2_multi_signal_mitre_filter",
        ("table", "json", "ndjson", "csv"),
        ("--mitre", "T1071.004"),
    )
    formats("analyze", "benign/clean_dns.pcap", "analyze/clean_dns", ("table", "json", "ndjson"))
    formats("analyze", "suspicious/c2_multi_signal.pcap", "analyze/c2_multi_signal", ("table", "json", "ndjson"))

    cases.extend([
        Scenario("multi-section", ("validate", "--format", "json", fixture("edge_cases/multi_section.pcapng")), 0, "validate/multi_section.json"),
        Scenario("flow-close-order", ("flows", "--format", "table", fixture("edge_cases/flow_close_out_of_creation_order.pcap")), 0, "flows/flow_close_out_of_creation_order.table.txt"),
        Scenario("local-http-partial-dns", ("findings", "--format", "table", "--detector", "dns.possible_tunneling", fixture("edge_cases/local_http_partial_with_dns_detection.pcap")), 3, "findings/local_http_partial_with_dns_detection.table.txt", "stderr/local_http_partial_with_dns_detection.txt"),
        Scenario("useful-then-truncated", ("analyze", "--format", "json", fixture("malformed/useful_then_truncated_record.pcap")), 3, "analyze/useful_then_truncated_record.json", "stderr/useful_then_truncated_record.txt"),
        Scenario("corrupt-no-useful", ("validate", fixture("malformed/corrupt_packet.pcap")), 1, None, "stderr/corrupt_packet.txt"),
        Scenario("analyze-csv-rejected", ("analyze", "--format", "csv", fixture("benign/clean_dns.pcap")), 2, None, "stderr/analyze_csv_rejected.txt"),
    ])

    cases.append(Scenario(
        "csv-sentinels",
        ("http", "--format", "csv", fixture("edge_cases/csv_formula_sentinels.pcap")),
        0,
        "http/csv_formula_sentinels.csv",
    ))

    return tuple(cases)
