#!/usr/bin/env python3
"""Stage candidate golden bytes outside tests/golden for manual semantic review."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from check_goldens import (
    MAX_REPORTED_ERRORS,
    ROOT,
    locate_binary,
    preflight_fixture_inputs,
)
from golden_scenarios import scenarios
from verification_support import BoundedDiagnostics

CANONICAL_GOLDENS = (ROOT / "tests/golden").resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="empty staging destination")
    parser.add_argument("--binary", type=Path, help="use this already-built CLI binary")
    args = parser.parse_args()
    matrix = scenarios(ROOT)
    errors = BoundedDiagnostics(MAX_REPORTED_ERRORS)
    if not preflight_fixture_inputs(matrix, errors):
        errors.emit()
        return 1

    output = args.output.resolve()
    if output == CANONICAL_GOLDENS or CANONICAL_GOLDENS in output.parents:
        raise SystemExit("refusing to stage within tests/golden")
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"staging destination must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    binary = locate_binary(args.binary)

    for scenario in matrix:
        completed = subprocess.run([str(binary), *scenario.args], cwd=ROOT, capture_output=True, check=False)
        if completed.returncode != scenario.expected_exit:
            raise SystemExit(
                f"{scenario.name}: exit {completed.returncode}, expected {scenario.expected_exit}"
            )
        for stream_name, relative, data in (
            ("stdout", scenario.stdout_path, completed.stdout),
            ("stderr", scenario.stderr_path, completed.stderr),
        ):
            if relative is None:
                if data:
                    raise SystemExit(f"{scenario.name}: expected empty {stream_name}")
                continue
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    print(f"staged candidates in {output}")
    print("Manually review semantic and schema-v1.0 diffs before copying selected files into tests/golden.")
    print("This tool has no acceptance or canonical-golden write mode.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
