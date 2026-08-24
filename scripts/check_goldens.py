#!/usr/bin/env python3
"""Read-only verification of canonical CLI golden bytes and exit states."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from golden_scenarios import Scenario, scenarios
from verification_support import (
    BoundedDiagnostics,
    FileSizeLimitExceeded,
    discover_files,
    read_file_bounded,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_RELATIVE_ROOT = Path("tests/fixtures/pcaps")
GOLDEN_RELATIVE_ROOT = Path("tests/golden")
FIXTURE_DIR = ROOT / FIXTURE_RELATIVE_ROOT
MAX_DISCOVERY_ENTRIES = 4096
MAX_DISCOVERED_FIXTURE_FILES = 1024
MAX_DISCOVERED_GOLDEN_FILES = 1024
MAX_DISCOVERY_DEPTH = 8
MAX_GOLDEN_BYTES = 4 * 1024 * 1024
MAX_REPORTED_ERRORS = 50


def locate_binary(requested: Path | None) -> Path:
    if requested is not None:
        binary = requested.resolve()
        if not binary.is_file():
            raise SystemExit(f"requested CLI binary does not exist: {binary}")
        return binary
    subprocess.run(
        ["cargo", "build", "-p", "pcapraven-cli", "--bin", "pcapraven", "--locked"],
        cwd=ROOT,
        check=True,
    )
    name = "pcapraven.exe" if sys.platform == "win32" else "pcapraven"
    return ROOT / "target/debug" / name


def preflight_fixture_inputs(
    matrix: tuple[Scenario, ...], errors: BoundedDiagnostics
) -> bool:
    """Reject an unsafe canonical fixture tree before a scenario can open it."""
    discovery = discover_files(
        ROOT,
        FIXTURE_RELATIVE_ROOT,
        lambda path: path.suffix.lower() in {".pcap", ".pcapng"},
        errors,
        maximum_entries=MAX_DISCOVERY_ENTRIES,
        maximum_files=MAX_DISCOVERED_FIXTURE_FILES,
        maximum_depth=MAX_DISCOVERY_DEPTH,
        label="fixture",
    )
    actual_files = set(discovery.paths)
    for scenario in matrix:
        try:
            capture = Path(scenario.args[-1]).relative_to(FIXTURE_DIR).as_posix()
        except (IndexError, ValueError):
            errors.add(f"{scenario.name}: capture path is outside the canonical fixture root")
            continue
        if capture not in actual_files:
            errors.add(f"{scenario.name}: missing or non-regular fixture: {capture}")
    return discovery.complete and not errors.has_errors


def preflight_golden_inputs(
    expected_files: set[str], errors: BoundedDiagnostics
) -> set[str] | None:
    """Complete structural discovery before any canonical golden is read."""
    discovery = discover_files(
        ROOT,
        GOLDEN_RELATIVE_ROOT,
        lambda path: path.name != "README.md",
        errors,
        maximum_entries=MAX_DISCOVERY_ENTRIES,
        maximum_files=MAX_DISCOVERED_GOLDEN_FILES,
        maximum_depth=MAX_DISCOVERY_DEPTH,
        label="golden",
    )
    actual_files = set(discovery.paths)
    for missing in sorted(expected_files - actual_files):
        errors.add(f"missing or non-regular golden: {missing}")
    for unexpected in sorted(actual_files - expected_files):
        errors.add(f"unexpected golden: {unexpected}")
    if not discovery.complete or errors.has_errors:
        return None
    return actual_files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="use this already-built CLI binary")
    args = parser.parse_args()
    matrix = scenarios(ROOT)
    expected_files = {
        path
        for scenario in matrix
        for path in (scenario.stdout_path, scenario.stderr_path)
        if path is not None
    }
    errors = BoundedDiagnostics(MAX_REPORTED_ERRORS)
    fixtures_safe = preflight_fixture_inputs(matrix, errors)
    actual_files = preflight_golden_inputs(expected_files, errors)
    if not fixtures_safe or actual_files is None:
        errors.emit()
        return 1

    binary = locate_binary(args.binary)
    golden_bytes: dict[str, bytes] = {}
    for relative in sorted(expected_files):
        try:
            golden_bytes[relative] = read_file_bounded(
                ROOT, GOLDEN_RELATIVE_ROOT / relative, MAX_GOLDEN_BYTES
            )
        except (OSError, FileSizeLimitExceeded) as error:
            errors.add(f"cannot read golden {relative}: {error}")

    for scenario in matrix:
        completed = subprocess.run([str(binary), *scenario.args], cwd=ROOT, capture_output=True, check=False)
        if completed.returncode != scenario.expected_exit:
            errors.add(
                f"{scenario.name}: exit {completed.returncode}, expected {scenario.expected_exit}"
            )
        for stream_name, actual, relative in (
            ("stdout", completed.stdout, scenario.stdout_path),
            ("stderr", completed.stderr, scenario.stderr_path),
        ):
            if relative is None:
                if actual:
                    errors.add(f"{scenario.name}: expected empty {stream_name}")
                continue
            expected = golden_bytes.get(relative)
            if expected is not None and expected != actual:
                errors.add(f"{scenario.name}: {stream_name} differs from {relative}")

    if errors.has_errors:
        errors.emit()
        return 1
    print(f"verified {len(matrix)} CLI golden scenarios without modifying tests/golden")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
