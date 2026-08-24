#!/usr/bin/env python3
"""Run bounded, dependency-free Phase 18 release-CLI benchmarks."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from typing import Callable


MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_RECORDS = 4096
MAX_GENERATED_RECORDS = 50_000
MAX_GENERATED_BYTES = 256 * 1024 * 1024
MAX_PROVENANCE_BYTES = 1024 * 1024
BENCHMARK_SCHEMA_VERSION = "phase18.2-measurement-v1"
BENCHMARK_IMPLEMENTATION = "phase18.2-methodology-v1"

RecordTransform = Callable[[bytes, int, str], bytes]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the release CLI and run bounded synthetic PCAP benchmarks."
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="run the separate one-sample tooling matrix instead of five measured runs",
    )
    return parser.parse_args()


def read_bounded(path: Path, maximum_bytes: int) -> bytes:
    with path.open("rb") as source:
        data = source.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise ValueError(f"bounded read exceeds {maximum_bytes} bytes: {path}")
    return data


def classic_pcap_records(data: bytes) -> tuple[bytes, list[bytes], str, int]:
    if len(data) < 24:
        raise ValueError("benchmark source has a truncated PCAP global header")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        byte_order, timestamp_units = "<", 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        byte_order, timestamp_units = "<", 1_000_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        byte_order, timestamp_units = ">", 1_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        byte_order, timestamp_units = ">", 1_000_000_000
    else:
        raise ValueError("benchmark source is not a supported classic PCAP")

    records: list[bytes] = []
    offset = 24
    while offset < len(data):
        if len(records) >= MAX_SOURCE_RECORDS:
            raise ValueError("benchmark source record count exceeds finite limit")
        header_end = offset + 16
        if header_end > len(data):
            raise ValueError("benchmark source has a truncated record header")
        included_length = struct.unpack_from(f"{byte_order}I", data, offset + 8)[0]
        record_end = header_end + included_length
        if record_end > len(data):
            raise ValueError("benchmark source has truncated record bytes")
        records.append(data[offset:record_end])
        offset = record_end
    if not records:
        raise ValueError("benchmark source contains no packet records")
    return data[:24], records, byte_order, timestamp_units


def load_fixture(path: Path) -> tuple[bytes, list[bytes], str, int]:
    return classic_pcap_records(read_bounded(path, MAX_SOURCE_BYTES))


def stamp_record(
    record: bytes,
    output_index: int,
    byte_order: str,
    timestamp_units: int,
    step_nanoseconds: int,
) -> bytes:
    if len(record) < 16:
        raise ValueError("benchmark packet record lacks its record header")
    elapsed_units = output_index * step_nanoseconds * timestamp_units // 1_000_000_000
    seconds = 1_700_000_000 + elapsed_units // timestamp_units
    fraction = elapsed_units % timestamp_units
    if seconds > 0xFFFFFFFF:
        raise ValueError("generated benchmark timestamp exceeds classic-PCAP range")
    stamped = bytearray(record)
    struct.pack_into(f"{byte_order}II", stamped, 0, seconds, fraction)
    return bytes(stamped)


def distinct_flow_record(record: bytes, flow_index: int, _byte_order: str) -> bytes:
    packet_offset = 16
    ethernet_length = 14
    ip_offset = packet_offset + ethernet_length
    if len(record) < ip_offset + 20 or record[packet_offset + 12 : packet_offset + 14] != b"\x08\x00":
        raise ValueError("flow-cardinality source must contain Ethernet IPv4 packets")
    ihl = (record[ip_offset] & 0x0F) * 4
    transport_offset = ip_offset + ihl
    if ihl < 20 or len(record) < transport_offset + 4:
        raise ValueError("flow-cardinality source has a truncated IPv4 transport header")
    if record[ip_offset + 9] not in {6, 17}:
        raise ValueError("flow-cardinality source must contain TCP or UDP")

    distinct = bytearray(record)
    address_value = flow_index + 1
    distinct[ip_offset + 12 : ip_offset + 16] = bytes(
        [10, (address_value >> 16) & 0xFF, (address_value >> 8) & 0xFF, address_value & 0xFF]
    )
    source_port = 1024 + flow_index % (65_535 - 1024)
    struct.pack_into(">H", distinct, transport_offset, source_port)
    return bytes(distinct)


def write_capture(
    path: Path,
    header: bytes,
    records: list[bytes],
    byte_order: str,
    timestamp_units: int,
    record_count: int,
    step_nanoseconds: int,
    transform: RecordTransform | None = None,
) -> int:
    if not 1 <= record_count <= MAX_GENERATED_RECORDS:
        raise ValueError(
            f"generated record count must be within 1..={MAX_GENERATED_RECORDS}"
        )
    if not records:
        raise ValueError("cannot generate a capture without source records")
    estimated_bytes = len(header) + max(len(record) for record in records) * record_count
    if estimated_bytes > MAX_GENERATED_BYTES:
        raise ValueError("generated benchmark capture exceeds finite byte limit")

    written = len(header)
    with path.open("xb") as output:
        output.write(header)
        for output_index in range(record_count):
            record = records[output_index % len(records)]
            stamped = stamp_record(
                record,
                output_index,
                byte_order,
                timestamp_units,
                step_nanoseconds,
            )
            if transform is not None:
                stamped = transform(stamped, output_index, byte_order)
            written += len(stamped)
            if written > MAX_GENERATED_BYTES:
                raise ValueError("generated benchmark capture exceeds finite byte limit")
            output.write(stamped)
    return written


def run_checked(command: list[str], root: Path) -> None:
    # Keep the machine-readable benchmark stream pure while leaving Cargo's
    # diagnostics visible on stderr when a build fails.
    subprocess.run(command, cwd=root, check=True, stdout=subprocess.DEVNULL)


def run_benchmark_command(command: list[str], root: Path) -> int:
    started = time.perf_counter_ns()
    result = subprocess.run(
        command,
        cwd=root,
        stdout=subprocess.DEVNULL,
        check=False,
    )
    elapsed = time.perf_counter_ns() - started
    if result.returncode != 0:
        raise RuntimeError(
            f"benchmark command exited {result.returncode}: {' '.join(command)}"
        )
    return elapsed


def benchmark(command: list[str], root: Path, samples: int) -> tuple[int, list[int]]:
    run_benchmark_command(command, root)
    durations = [run_benchmark_command(command, root) for _ in range(samples)]
    return statistics.median_low(sorted(durations)), durations


def bounded_command_output(command: list[str], root: Path) -> tuple[int, bytes, bool]:
    process = subprocess.Popen(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise RuntimeError(f"provenance command has no output pipe: {' '.join(command)}")
    output = process.stdout.read(MAX_PROVENANCE_BYTES + 1)
    exceeded = len(output) > MAX_PROVENANCE_BYTES
    if exceeded:
        process.kill()
    return_code = process.wait()
    return return_code, output, exceeded


def capture_command(command: list[str], root: Path) -> str:
    return_code, output, exceeded = bounded_command_output(command, root)
    if return_code != 0 or exceeded:
        return "unreported"
    return output.decode("utf-8", errors="replace").strip() or "unreported"


def required_command(command: list[str], root: Path, allow_empty: bool = False) -> str:
    return_code, output, exceeded = bounded_command_output(command, root)
    if return_code != 0 or exceeded:
        raise RuntimeError(f"provenance command failed: {' '.join(command)}")
    value = output.decode("utf-8", errors="replace").strip()
    if not value and not allow_empty:
        raise RuntimeError(f"provenance command returned no output: {' '.join(command)}")
    return value


def memory_bytes(name: str) -> int | None:
    try:
        pages = os.sysconf(name)
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        return None
    if not isinstance(pages, int) or not isinstance(page_size, int):
        return None
    return pages * page_size


def cpu_model() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in read_bounded(cpuinfo, MAX_PROVENANCE_BYTES).decode(
            "utf-8", errors="replace"
        ).splitlines():
            if line.startswith(("model name", "Hardware")) and ":" in line:
                return line.split(":", 1)[1].strip() or "unreported"
    return platform.processor() or "unreported"


def power_mode() -> str:
    governor = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    if not governor.is_file():
        return "unreported; power state was not controlled"
    value = read_bounded(governor, 256).decode("utf-8", errors="replace").strip()
    return f"reported governor={value}; power state was not controlled"


def environment(root: Path) -> dict[str, object]:
    git_status = required_command(["git", "status", "--porcelain"], root, allow_empty=True)
    git_dirty = bool(git_status)
    return {
        "git_sha": required_command(["git", "rev-parse", "HEAD"], root),
        "git_dirty": git_dirty,
        "git_worktree_status": "dirty" if git_dirty else "clean",
        "rustc": capture_command(["rustc", "--version", "--verbose"], root),
        "active_toolchain": capture_command(["rustup", "show", "active-toolchain"], root),
        "cargo": capture_command(["cargo", "--version"], root),
        "python": platform.python_version(),
        "build_profile": "release",
        "os": platform.system() or "unreported",
        "kernel": platform.release() or "unreported",
        "platform": platform.platform(),
        "machine": platform.machine() or "unreported",
        "cpu_model": cpu_model(),
        "logical_cpu_count": os.cpu_count(),
        "total_memory_bytes": memory_bytes("SC_PHYS_PAGES"),
        "available_memory_bytes": memory_bytes("SC_AVPHYS_PAGES"),
        "power_mode": power_mode(),
        "background_load": "not controlled, pinned, or sampled",
        "limitations": (
            "Whole-process timings include CLI startup and filesystem cache effects; "
            "CPU affinity, power state, thermal state, and background load are uncontrolled."
        ),
    }


def scenario_matrix(smoke: bool) -> list[dict[str, object]]:
    if smoke:
        return [
            {"name": "validate_smoke", "family": "validate", "workload": "record_scaling", "records": 64, "source": "tcp", "command": "validate", "format": "json"},
            {"name": "flows_low_smoke", "family": "flows", "workload": "flow_cardinality", "records": 32, "source": "flow", "command": "flows", "format": "json"},
            {"name": "dns_smoke", "family": "dns", "workload": "dns_scaling", "records": 64, "source": "dns", "command": "dns", "format": "json"},
            *[
                {"name": f"analyze_{workload}_smoke", "family": "analyze", "workload": workload, "records": 64, "source": workload, "command": "analyze", "format": "json"}
                for workload in ("benign_mixed", "repeated", "dns_heavy", "multi_signal")
            ],
            *[
                {"name": f"reporting_{report_format}_smoke", "family": "reporting", "workload": "multi_signal_findings", "records": 64, "source": "multi_signal", "command": "findings", "format": report_format}
                for report_format in ("table", "json", "ndjson", "csv")
            ],
        ]

    scenarios: list[dict[str, object]] = []
    for record_count in (1_000, 10_000, 50_000):
        scenarios.append({"name": f"validate_{record_count}", "family": "validate", "workload": "record_scaling", "records": record_count, "source": "tcp", "command": "validate", "format": "json"})
    for label, flow_count in (("low", 128), ("medium", 2_048), ("higher", 8_192)):
        scenarios.append({"name": f"flows_{label}", "family": "flows", "workload": "flow_cardinality", "records": flow_count, "source": "flow", "command": "flows", "format": "json"})
    for record_count in (1_000, 10_000):
        scenarios.append({"name": f"dns_{record_count}", "family": "dns", "workload": "dns_scaling", "records": record_count, "source": "dns", "command": "dns", "format": "json"})
    for workload in ("benign_mixed", "repeated", "dns_heavy", "multi_signal"):
        for record_count in (1_000, 10_000):
            scenarios.append({"name": f"analyze_{workload}_{record_count}", "family": "analyze", "workload": workload, "records": record_count, "source": workload, "command": "analyze", "format": "json"})
    for report_format in ("table", "json", "ndjson", "csv"):
        for record_count in (1_000, 10_000):
            scenarios.append({"name": f"reporting_{report_format}_{record_count}", "family": "reporting", "workload": "multi_signal_findings", "records": record_count, "source": "multi_signal", "command": "findings", "format": report_format})
    return scenarios


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parent.parent
    fixture_root = root / "tests/fixtures/pcaps"
    fixture_paths = {
        "tcp": [fixture_root / "benign/clean_tcp_flows.pcap"],
        "flow": [fixture_root / "benign/clean_tcp_flows.pcap"],
        "dns": [fixture_root / "benign/clean_dns.pcap"],
        "benign_mixed": [
            fixture_root / "benign/clean_tcp_flows.pcap",
            fixture_root / "benign/clean_udp_flows.pcap",
            fixture_root / "benign/clean_dns.pcap",
            fixture_root / "benign/clean_http.pcap",
            fixture_root / "benign/clean_tls.pcap",
        ],
        "repeated": [fixture_root / "suspicious/repeated_low_volume.pcap"],
        "dns_heavy": [
            fixture_root / "suspicious/dns_tunneling.pcap",
            fixture_root / "suspicious/dns_long_query.pcap",
        ],
        "multi_signal": [fixture_root / "suspicious/c2_multi_signal.pcap"],
    }

    loaded: dict[str, tuple[bytes, list[bytes], str, int]] = {}
    for source_name, paths in fixture_paths.items():
        combined_records: list[bytes] = []
        canonical_header: bytes | None = None
        canonical_order: str | None = None
        canonical_units: int | None = None
        for path in paths:
            header, records, byte_order, timestamp_units = load_fixture(path)
            if canonical_header is None:
                canonical_header = header
                canonical_order = byte_order
                canonical_units = timestamp_units
            elif header != canonical_header:
                raise ValueError(f"benchmark fixtures have incompatible global headers: {path}")
            combined_records.extend(records)
            if len(combined_records) > MAX_SOURCE_RECORDS:
                raise ValueError("combined benchmark source record count exceeds finite limit")
        if canonical_header is None or canonical_order is None or canonical_units is None:
            raise ValueError(f"benchmark source set is empty: {source_name}")
        loaded[source_name] = (
            canonical_header,
            combined_records,
            canonical_order,
            canonical_units,
        )

    run_checked(["cargo", "build", "--release", "--locked", "-p", "pcapraven-cli"], root)
    binary_name = "pcapraven.exe" if os.name == "nt" else "pcapraven"
    binary = root / "target" / "release" / binary_name
    if not binary.is_file():
        raise RuntimeError(f"release CLI binary was not produced: {binary}")

    samples = 1 if args.smoke else 5
    scenarios = scenario_matrix(args.smoke)
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="pcapraven-phase18-bench-") as temp:
        temp_root = Path(temp)
        capture_cache: dict[tuple[str, int], tuple[Path, int]] = {}
        for scenario in scenarios:
            source_name = str(scenario["source"])
            record_count = int(scenario["records"])
            cache_key = (source_name, record_count)
            capture_details = capture_cache.get(cache_key)
            if capture_details is None:
                header, records, byte_order, timestamp_units = loaded[source_name]
                capture = temp_root / f"{source_name}-{record_count}.pcap"
                step_nanoseconds = 30_000_000_000 if source_name in {"repeated", "multi_signal"} else 1_000_000
                transform = distinct_flow_record if source_name == "flow" else None
                capture_bytes = write_capture(
                    capture,
                    header,
                    records,
                    byte_order,
                    timestamp_units,
                    record_count,
                    step_nanoseconds,
                    transform,
                )
                capture_details = (capture, capture_bytes)
                capture_cache[cache_key] = capture_details
            capture, capture_bytes = capture_details
            command = [
                str(binary),
                "--quiet",
                "--format",
                str(scenario["format"]),
                str(scenario["command"]),
                str(capture),
            ]
            median_ns, durations_ns = benchmark(command, root, samples)
            results.append(
                {
                    "scenario": scenario["name"],
                    "family": scenario["family"],
                    "workload": scenario["workload"],
                    "format": scenario["format"],
                    "source": scenario["source"],
                    "command": scenario["command"],
                    "capture_bytes": capture_bytes,
                    "packet_records": record_count,
                    "samples": samples,
                    "warmup_runs": 1,
                    "durations_ns": durations_ns,
                    "minimum_ns": min(durations_ns),
                    "median_ns": median_ns,
                    "maximum_ns": max(durations_ns),
                    "growth_ratio_basis_points": None,
                }
            )

    baselines: dict[tuple[str, str, str], int] = {}
    for result in results:
        key = (str(result["family"]), str(result["workload"]), str(result["format"]))
        median_ns = int(result["median_ns"])
        baseline = baselines.setdefault(key, median_ns)
        result["growth_ratio_basis_points"] = median_ns * 10_000 // baseline

    payload = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "phase": "18.2",
        "benchmark_implementation": BENCHMARK_IMPLEMENTATION,
        "mode": "smoke" if args.smoke else "benchmark",
        "timing_unit": "nanoseconds",
        "growth_ratio_unit": "basis_points_relative_to_smallest_matching_workload",
        "acceptance_status": "pending",
        "environment": environment(root),
        "results": results,
    }
    json.dump(payload, sys.stdout, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"phase 18 benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
