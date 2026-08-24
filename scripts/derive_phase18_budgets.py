#!/usr/bin/env python3
"""Derive frozen Phase 18.2 performance budgets from three full runs.

The input measurements are intentionally validated more strictly than a normal
report reader.  A budget is an auditable contract for a later acceptance gate,
so malformed, incomplete, dirty, mixed-revision, or internally inconsistent
measurements are rejected rather than repaired.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


MAX_MEASUREMENT_BYTES = 16 * 1024 * 1024
EXPECTED_RUN_COUNT = 3
EXPECTED_SAMPLES_PER_SCENARIO = 5
EXPECTED_WARMUPS_PER_SCENARIO = 1
EXPECTED_SCENARIO_COUNT = 24

# These are frozen methodology constants.  They deliberately use basis points
# and integer ceiling division so budget generation never depends on floats.
STABILITY_LIMIT_BP = 1_500
REGRESSION_MARGIN_BP = 2_500
BUDGET_FACTOR_BP = 10_000 + REGRESSION_MARGIN_BP

ENVIRONMENT_IDENTITY_FIELDS = (
    "rustc",
    "active_toolchain",
    "cargo",
    "python",
    "build_profile",
    "os",
    "kernel",
    "platform",
    "machine",
    "cpu_model",
    "logical_cpu_count",
    "total_memory_bytes",
    "power_mode",
    "background_load",
    "limitations",
)
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class MeasurementError(ValueError):
    """A measurement failed the frozen Phase 18.2 input contract."""


def _benchmark_module() -> Any:
    """Load the benchmark implementation without executing its CLI entrypoint."""

    script_path = Path(__file__).resolve().with_name("run_phase18_benchmarks.py")
    spec = importlib.util.spec_from_file_location("phase18_benchmark_impl", script_path)
    if spec is None or spec.loader is None:
        raise MeasurementError(f"cannot load benchmark implementation: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_BENCHMARK = _benchmark_module()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MeasurementError(message)


def _require_string(value: object, field: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{field} must be a non-empty string")
    return value


def _require_positive_int(value: object, field: str) -> int:
    _require(_is_int(value) and value > 0, f"{field} must be a positive integer")
    return value


def _scenario_descriptors() -> list[tuple[str, str, str, str, int, str, str]]:
    scenarios = _BENCHMARK.scenario_matrix(False)
    _require(
        len(scenarios) == EXPECTED_SCENARIO_COUNT,
        "benchmark implementation does not expose the canonical 24-scenario matrix",
    )
    descriptors: list[tuple[str, str, str, str, int, str, str]] = []
    for scenario in scenarios:
        try:
            descriptor = (
                str(scenario["name"]),
                str(scenario["family"]),
                str(scenario["workload"]),
                str(scenario["format"]),
                int(scenario["records"]),
                str(scenario["source"]),
                str(scenario["command"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise MeasurementError(f"invalid canonical benchmark scenario: {error}") from None
        descriptors.append(descriptor)
    names = [descriptor[0] for descriptor in descriptors]
    _require(len(set(names)) == len(names), "canonical benchmark scenario names are not unique")
    return descriptors


def _validate_environment(environment: object, run_number: int) -> dict[str, object]:
    prefix = f"run {run_number} environment"
    _require(isinstance(environment, dict), f"{prefix} must be an object")
    environment_dict = environment
    for field in (
        "git_sha",
        "git_dirty",
        "git_worktree_status",
        "available_memory_bytes",
        *ENVIRONMENT_IDENTITY_FIELDS,
    ):
        _require(field in environment_dict, f"{prefix} is missing {field}")
    git_sha = _require_string(environment_dict["git_sha"], f"{prefix}.git_sha")
    _require(
        GIT_SHA_PATTERN.fullmatch(git_sha) is not None,
        f"{prefix}.git_sha must be a 40-character lowercase hexadecimal revision",
    )
    _require(
        environment_dict["git_dirty"] is False,
        f"run {run_number} must report git_dirty = false",
    )
    _require(
        environment_dict["git_worktree_status"] == "clean",
        f"run {run_number} must report a clean Git worktree",
    )
    _require_string(environment_dict["git_worktree_status"], f"{prefix}.git_worktree_status")
    _require(
        environment_dict["build_profile"] == "release",
        f"run {run_number} must use the release build profile",
    )
    for field in (
        "rustc",
        "active_toolchain",
        "cargo",
        "python",
        "build_profile",
        "os",
        "kernel",
        "platform",
        "machine",
        "cpu_model",
        "power_mode",
        "background_load",
        "limitations",
    ):
        _require_string(environment_dict[field], f"{prefix}.{field}")
    total_memory = environment_dict["total_memory_bytes"]
    _require(
        total_memory is None or (_is_int(total_memory) and total_memory > 0),
        f"{prefix}.total_memory_bytes must be positive when reported",
    )
    available_memory = environment_dict["available_memory_bytes"]
    _require(
        available_memory is None
        or (_is_int(available_memory) and available_memory > 0),
        f"{prefix}.available_memory_bytes must be positive when reported",
    )
    logical_cpu_count = environment_dict["logical_cpu_count"]
    _require(
        logical_cpu_count is None
        or (_is_int(logical_cpu_count) and logical_cpu_count > 0),
        f"{prefix}.logical_cpu_count must be positive when reported",
    )
    return environment_dict


def _validate_result(
    result: object,
    expected: tuple[str, str, str, str, int, str, str],
    run_number: int,
) -> dict[str, object]:
    _require(isinstance(result, dict), f"run {run_number} contains a non-object scenario")
    result_dict = result
    scenario, family, workload, output_format, records, source, command = expected
    fields = (
        ("scenario", scenario),
        ("family", family),
        ("workload", workload),
        ("format", output_format),
        ("source", source),
        ("command", command),
    )
    for field, expected_value in fields:
        _require(
            result_dict.get(field) == expected_value,
            f"run {run_number} scenario {scenario} has inconsistent {field}",
        )
    _require(
        result_dict.get("packet_records") == records,
        f"run {run_number} scenario {scenario} has inconsistent packet_records",
    )
    _require(
        result_dict.get("samples") == EXPECTED_SAMPLES_PER_SCENARIO,
        f"run {run_number} scenario {scenario} must contain exactly five measured samples",
    )
    _require(
        result_dict.get("warmup_runs") == EXPECTED_WARMUPS_PER_SCENARIO,
        f"run {run_number} scenario {scenario} must contain exactly one warmup",
    )
    durations = result_dict.get("durations_ns")
    _require(
        isinstance(durations, list) and len(durations) == EXPECTED_SAMPLES_PER_SCENARIO,
        f"run {run_number} scenario {scenario} has an incorrect duration sample count",
    )
    for index, duration in enumerate(durations):
        _require_positive_int(
            duration,
            f"run {run_number} scenario {scenario} duration {index}",
        )
    ordered = sorted(durations)
    _require(
        result_dict.get("minimum_ns") == ordered[0],
        f"run {run_number} scenario {scenario} has an inconsistent minimum",
    )
    _require(
        result_dict.get("median_ns") == ordered[EXPECTED_SAMPLES_PER_SCENARIO // 2],
        f"run {run_number} scenario {scenario} has an inconsistent integer median",
    )
    _require(
        result_dict.get("maximum_ns") == ordered[-1],
        f"run {run_number} scenario {scenario} has an inconsistent maximum",
    )
    _require_positive_int(
        result_dict.get("capture_bytes"),
        f"run {run_number} scenario {scenario} capture_bytes",
    )
    growth = result_dict.get("growth_ratio_basis_points")
    _require(
        _is_int(growth) and growth > 0,
        f"run {run_number} scenario {scenario} has an invalid growth ratio",
    )
    return result_dict


def validate_measurement(document: object, run_number: int) -> dict[str, object]:
    """Validate and return one complete full benchmark measurement."""

    _require(isinstance(document, dict), f"run {run_number} measurement must be a JSON object")
    measurement = document
    benchmark_schema_version = getattr(_BENCHMARK, "BENCHMARK_SCHEMA_VERSION", None)
    implementation = getattr(_BENCHMARK, "BENCHMARK_IMPLEMENTATION", None)
    _require(
        measurement.get("schema_version") == benchmark_schema_version,
        f"run {run_number} has an unsupported measurement schema",
    )
    _require(measurement.get("phase") == "18.2", f"run {run_number} is not a Phase 18.2 measurement")
    _require(
        measurement.get("benchmark_implementation") == implementation,
        f"run {run_number} uses a different benchmark implementation",
    )
    _require(measurement.get("mode") == "benchmark", f"run {run_number} is not a full benchmark")
    _require(measurement.get("timing_unit") == "nanoseconds", f"run {run_number} has an invalid timing unit")
    _require(
        measurement.get("growth_ratio_unit")
        == "basis_points_relative_to_smallest_matching_workload",
        f"run {run_number} has an invalid growth-ratio unit",
    )
    _require(
        measurement.get("acceptance_status") == "pending",
        f"run {run_number} must not claim performance acceptance",
    )
    environment = _validate_environment(measurement.get("environment"), run_number)
    raw_results = measurement.get("results")
    _require(
        isinstance(raw_results, list) and len(raw_results) == EXPECTED_SCENARIO_COUNT,
        f"run {run_number} must contain exactly 24 scenarios",
    )
    descriptors = _scenario_descriptors()
    results = [
        _validate_result(result, descriptor, run_number)
        for result, descriptor in zip(raw_results, descriptors, strict=True)
    ]
    _validate_growth(results, run_number)
    # Keep this value available to callers without modifying the source JSON.
    measurement["environment"] = environment
    measurement["results"] = results
    return measurement


def _validate_growth(results: list[dict[str, object]], run_number: int) -> None:
    baselines: dict[tuple[str, str, str], int] = {}
    group_records: dict[tuple[str, str, str], list[int]] = {}
    for result in results:
        key = (str(result["family"]), str(result["workload"]), str(result["format"]))
        median_ns = int(result["median_ns"])
        packet_records = int(result["packet_records"])
        baseline = baselines.setdefault(key, median_ns)
        group_records.setdefault(key, []).append(packet_records)
        expected_growth = median_ns * 10_000 // baseline
        _require(
            result["growth_ratio_basis_points"] == expected_growth,
            f"run {run_number} scenario {result['scenario']} has an inconsistent growth ratio",
        )
    for key, records in group_records.items():
        smallest = min(records)
        _require(
            records.count(smallest) == 1,
            f"run {run_number} growth group {key} must have one smallest baseline",
        )


def load_measurement(path: Path, run_number: int) -> tuple[dict[str, object], str]:
    """Read one bounded measurement and return it with its source SHA-256."""

    try:
        with path.open("rb") as source:
            raw = source.read(MAX_MEASUREMENT_BYTES + 1)
    except OSError as error:
        raise MeasurementError(f"cannot read baseline run {run_number}: {path}: {error}") from None
    _require(
        len(raw) <= MAX_MEASUREMENT_BYTES,
        f"baseline run {run_number} exceeds the {MAX_MEASUREMENT_BYTES}-byte input limit",
    )
    digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MeasurementError(f"baseline run {run_number} is not valid UTF-8 JSON: {error}") from None
    return validate_measurement(document, run_number), digest


def _ceil_scaled(value: int) -> int:
    """Apply the predeclared 125% factor using integer ceiling arithmetic."""

    return (value * BUDGET_FACTOR_BP + 9_999) // 10_000


def derive_budget_document(
    measurements: list[dict[str, object]], source_hashes: list[str]
) -> dict[str, object]:
    """Derive one deterministic, frozen budget document from three runs."""

    _require(
        len(measurements) == EXPECTED_RUN_COUNT,
        "exactly three full baseline measurements are required",
    )
    _require(
        len(source_hashes) == EXPECTED_RUN_COUNT,
        "exactly three source measurement hashes are required",
    )
    for index, source_hash in enumerate(source_hashes, start=1):
        _require(
            isinstance(source_hash, str) and SHA256_PATTERN.fullmatch(source_hash) is not None,
            f"source measurement hash run {index} must be a 64-character lowercase hexadecimal SHA-256",
        )
    first = measurements[0]
    first_environment = first["environment"]
    first_git_sha = first_environment["git_sha"]
    first_identity = {
        field: first_environment[field] for field in ENVIRONMENT_IDENTITY_FIELDS
    }
    for index, measurement in enumerate(measurements[1:], start=2):
        environment = measurement["environment"]
        _require(
            environment["git_sha"] == first_git_sha,
            f"baseline run {index} uses a different Git SHA",
        )
        identity = {field: environment[field] for field in ENVIRONMENT_IDENTITY_FIELDS}
        _require(
            identity == first_identity,
            f"baseline run {index} uses an incompatible benchmark environment",
        )
        _require(
            measurement["benchmark_implementation"]
            == first["benchmark_implementation"],
            f"baseline run {index} uses a different release benchmark implementation",
        )

    descriptors = _scenario_descriptors()
    budgets: list[dict[str, object]] = []
    meaningful_growth_count = 0
    for scenario_index, descriptor in enumerate(descriptors):
        (
            scenario_name,
            family,
            workload,
            output_format,
            packet_records,
            _source,
            _command,
        ) = descriptor
        scenario_runs = [measurement["results"][scenario_index] for measurement in measurements]
        capture_sizes = [int(result["capture_bytes"]) for result in scenario_runs]
        _require(
            len(set(capture_sizes)) == 1,
            f"scenario {scenario_name} has inconsistent generated capture bytes across baseline runs",
        )
        medians = [int(result["median_ns"]) for result in scenario_runs]
        reference_median = sorted(medians)[1]
        spread_bp = (max(medians) - min(medians)) * 10_000 // reference_median
        _require(
            spread_bp <= STABILITY_LIMIT_BP,
            f"scenario {scenario_name} exceeds the frozen 15% baseline stability limit",
        )

        growth_values = [
            int(result["growth_ratio_basis_points"]) for result in scenario_runs
        ]
        group_key = (family, workload, output_format)
        group_records = [
            int(result["packet_records"])
            for result in measurements[0]["results"]
            if (
                result["family"],
                result["workload"],
                result["format"],
            )
            == group_key
        ]
        smallest_record_count = min(group_records)
        is_smallest = packet_records == smallest_record_count
        if is_smallest:
            reference_growth: int | None = None
            growth_budget: int | None = None
        else:
            reference_growth = sorted(growth_values)[1]
            growth_budget = _ceil_scaled(reference_growth)
            meaningful_growth_count += 1

        budgets.append(
            {
                "scenario": scenario_name,
                "family": family,
                "workload": workload,
                "format": output_format,
                "packet_records": packet_records,
                "baseline_medians_ns": medians,
                "reference_median_ns": reference_median,
                "median_spread_basis_points": spread_bp,
                "frozen_median_budget_ns": _ceil_scaled(reference_median),
                "baseline_growth_basis_points": growth_values,
                "reference_growth_basis_points": reference_growth,
                "frozen_growth_budget_basis_points": growth_budget,
            }
        )

    _require(
        len(budgets) == EXPECTED_SCENARIO_COUNT,
        "derived budget count does not match the canonical scenario count",
    )
    _require(
        meaningful_growth_count == 13,
        "derived meaningful growth budget count does not match the canonical matrix",
    )
    return {
        "schema_version": "phase18.2-budgets-v1",
        "phase": "18.2",
        "artifact_kind": "performance_baseline_budgets",
        "budget_status": "frozen_for_phase_18.3",
        "acceptance_status": "not_executed",
        "acceptance_statement": (
            "FROZEN FOR PHASE 18.3; NOT YET EXECUTED AS THE FINAL ACCEPTANCE GATE"
        ),
        "measurement_git_sha": first_git_sha,
        "benchmark_implementation": first["benchmark_implementation"],
        "baseline_environment": first_environment,
        "baseline_run_count": EXPECTED_RUN_COUNT,
        "samples_per_scenario_per_run": EXPECTED_SAMPLES_PER_SCENARIO,
        "warmups_per_scenario": EXPECTED_WARMUPS_PER_SCENARIO,
        "scenario_count": EXPECTED_SCENARIO_COUNT,
        "meaningful_growth_budget_count": meaningful_growth_count,
        "stability_limit_basis_points": STABILITY_LIMIT_BP,
        "median_regression_margin_basis_points": REGRESSION_MARGIN_BP,
        "growth_regression_margin_basis_points": REGRESSION_MARGIN_BP,
        "budget_factor_basis_points": BUDGET_FACTOR_BP,
        "frozen_policy": {
            "stability_rule": "spread_bp = (max(medians) - min(medians)) * 10000 // reference_median",
            "stability_limit_basis_points": STABILITY_LIMIT_BP,
            "absolute_median_rule": "ceil(reference_median_ns * 12500 / 10000)",
            "growth_rule": "ceil(reference_growth_basis_points * 12500 / 10000)",
            "regression_margin_basis_points": REGRESSION_MARGIN_BP,
            "smallest_group_growth_budget": None,
        },
        "source_measurement_sha256": {
            f"run_{index}": digest
            for index, digest in enumerate(source_hashes, start=1)
        },
        "budgets": budgets,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Derive frozen Phase 18.2 budgets from exactly three full benchmark JSON files."
    )
    parser.add_argument("measurements", nargs=3, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    measurements: list[dict[str, object]] = []
    source_hashes: list[str] = []
    for index, path in enumerate(args.measurements, start=1):
        measurement, digest = load_measurement(path, index)
        measurements.append(measurement)
        source_hashes.append(digest)
    payload = derive_budget_document(measurements, source_hashes)
    json.dump(payload, sys.stdout, sort_keys=True, indent=2, allow_nan=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, MeasurementError, TypeError, ValueError) as error:
        print(f"phase 18 budget derivation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
