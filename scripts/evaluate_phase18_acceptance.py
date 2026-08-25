#!/usr/bin/env python3
"""Evaluate three later Phase 18 runs against the frozen Phase 18.2 budgets.

This is a read-only, dependency-free acceptance evaluator.  It validates the
Phase 18.2 measurement contract before evaluating any budget, and emits one
deterministic JSON result for structurally valid evidence.  A stable set of
measurements that exceeds a frozen budget is a valid ``failed`` result; an
unstable but otherwise valid evidence set is reported as ``unstable``. A
malformed or incompatible evidence set is rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
from typing import Any


# This tool must not create __pycache__ files while loading the validated
# Phase 18.2 parser and benchmark matrix.
sys.dont_write_bytecode = True


MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_JSON_INTEGER = (1 << 128) - 1
MAX_GIT_OUTPUT_BYTES = 64 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 5
EXPECTED_RUN_COUNT = 3
EXPECTED_SAMPLES_PER_SCENARIO = 5
EXPECTED_WARMUPS_PER_SCENARIO = 1
EXPECTED_SCENARIO_COUNT = 24
EXPECTED_GROWTH_BUDGET_COUNT = 13
STABILITY_LIMIT_BP = 1_500
REGRESSION_MARGIN_BP = 2_500
BUDGET_FACTOR_BP = 12_500
ACCEPTANCE_SCHEMA_VERSION = "phase18.3-acceptance-v1"
ACCEPTANCE_ARTIFACT_KIND = "performance_final_acceptance"
FROZEN_BUDGET_SHA256 = "d873a70258b6a52ae4a58e99515fb3caa8790fb75fa4f4a97d76a901e5b301c1"
ENVIRONMENT_COMPATIBILITY_POLICY_ID = "phase18.3-linux-wsl2-total-memory-one-page-v1"
MEMORY_PAGE_BYTES = 4_096
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
FROZEN_BUDGET_PATH = REPOSITORY_ROOT / "docs" / "performance" / "phase18-2-budgets.json"
FROZEN_BASELINE_PATHS = tuple(
    REPOSITORY_ROOT / "docs" / "performance" / f"phase18-2-baseline-run-{run}.json"
    for run in range(1, EXPECTED_RUN_COUNT + 1)
)
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

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
ENVIRONMENT_FIELDS = frozenset(
    {
        "git_sha",
        "git_dirty",
        "git_worktree_status",
        "available_memory_bytes",
        *ENVIRONMENT_IDENTITY_FIELDS,
    }
)

RAW_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "phase",
        "benchmark_implementation",
        "mode",
        "timing_unit",
        "growth_ratio_unit",
        "acceptance_status",
        "environment",
        "results",
    }
)
RAW_RESULT_FIELDS = frozenset(
    {
        "scenario",
        "family",
        "workload",
        "format",
        "source",
        "command",
        "capture_bytes",
        "packet_records",
        "samples",
        "warmup_runs",
        "durations_ns",
        "minimum_ns",
        "median_ns",
        "maximum_ns",
        "growth_ratio_basis_points",
    }
)
BUDGET_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "phase",
        "artifact_kind",
        "budget_status",
        "acceptance_status",
        "acceptance_statement",
        "measurement_git_sha",
        "benchmark_implementation",
        "baseline_environment",
        "baseline_run_count",
        "samples_per_scenario_per_run",
        "warmups_per_scenario",
        "scenario_count",
        "meaningful_growth_budget_count",
        "stability_limit_basis_points",
        "median_regression_margin_basis_points",
        "growth_regression_margin_basis_points",
        "budget_factor_basis_points",
        "frozen_policy",
        "source_measurement_sha256",
        "budgets",
    }
)
BUDGET_ENTRY_FIELDS = frozenset(
    {
        "scenario",
        "family",
        "workload",
        "format",
        "packet_records",
        "baseline_medians_ns",
        "reference_median_ns",
        "median_spread_basis_points",
        "frozen_median_budget_ns",
        "baseline_growth_basis_points",
        "reference_growth_basis_points",
        "frozen_growth_budget_basis_points",
    }
)
FROZEN_POLICY_FIELDS = frozenset(
    {
        "stability_rule",
        "stability_limit_basis_points",
        "absolute_median_rule",
        "growth_rule",
        "regression_margin_basis_points",
        "smallest_group_growth_budget",
    }
)

# This list is intentionally independent of run_phase18_benchmarks.py.  The
# evaluator must reject a changed or shortened runner matrix instead of
# silently treating the changed matrix as canonical acceptance evidence.
CANONICAL_SCENARIOS: tuple[tuple[str, str, str, str, int, str, str], ...] = (
    ("validate_1000", "validate", "record_scaling", "json", 1_000, "tcp", "validate"),
    ("validate_10000", "validate", "record_scaling", "json", 10_000, "tcp", "validate"),
    ("validate_50000", "validate", "record_scaling", "json", 50_000, "tcp", "validate"),
    ("flows_low", "flows", "flow_cardinality", "json", 128, "flow", "flows"),
    ("flows_medium", "flows", "flow_cardinality", "json", 2_048, "flow", "flows"),
    ("flows_higher", "flows", "flow_cardinality", "json", 8_192, "flow", "flows"),
    ("dns_1000", "dns", "dns_scaling", "json", 1_000, "dns", "dns"),
    ("dns_10000", "dns", "dns_scaling", "json", 10_000, "dns", "dns"),
    (
        "analyze_benign_mixed_1000",
        "analyze",
        "benign_mixed",
        "json",
        1_000,
        "benign_mixed",
        "analyze",
    ),
    (
        "analyze_benign_mixed_10000",
        "analyze",
        "benign_mixed",
        "json",
        10_000,
        "benign_mixed",
        "analyze",
    ),
    (
        "analyze_repeated_1000",
        "analyze",
        "repeated",
        "json",
        1_000,
        "repeated",
        "analyze",
    ),
    (
        "analyze_repeated_10000",
        "analyze",
        "repeated",
        "json",
        10_000,
        "repeated",
        "analyze",
    ),
    (
        "analyze_dns_heavy_1000",
        "analyze",
        "dns_heavy",
        "json",
        1_000,
        "dns_heavy",
        "analyze",
    ),
    (
        "analyze_dns_heavy_10000",
        "analyze",
        "dns_heavy",
        "json",
        10_000,
        "dns_heavy",
        "analyze",
    ),
    (
        "analyze_multi_signal_1000",
        "analyze",
        "multi_signal",
        "json",
        1_000,
        "multi_signal",
        "analyze",
    ),
    (
        "analyze_multi_signal_10000",
        "analyze",
        "multi_signal",
        "json",
        10_000,
        "multi_signal",
        "analyze",
    ),
    (
        "reporting_table_1000",
        "reporting",
        "multi_signal_findings",
        "table",
        1_000,
        "multi_signal",
        "findings",
    ),
    (
        "reporting_table_10000",
        "reporting",
        "multi_signal_findings",
        "table",
        10_000,
        "multi_signal",
        "findings",
    ),
    (
        "reporting_json_1000",
        "reporting",
        "multi_signal_findings",
        "json",
        1_000,
        "multi_signal",
        "findings",
    ),
    (
        "reporting_json_10000",
        "reporting",
        "multi_signal_findings",
        "json",
        10_000,
        "multi_signal",
        "findings",
    ),
    (
        "reporting_ndjson_1000",
        "reporting",
        "multi_signal_findings",
        "ndjson",
        1_000,
        "multi_signal",
        "findings",
    ),
    (
        "reporting_ndjson_10000",
        "reporting",
        "multi_signal_findings",
        "ndjson",
        10_000,
        "multi_signal",
        "findings",
    ),
    (
        "reporting_csv_1000",
        "reporting",
        "multi_signal_findings",
        "csv",
        1_000,
        "multi_signal",
        "findings",
    ),
    (
        "reporting_csv_10000",
        "reporting",
        "multi_signal_findings",
        "csv",
        10_000,
        "multi_signal",
        "findings",
    ),
)


class AcceptanceError(ValueError):
    """The acceptance input is not a valid, complete evidence set."""


def _benchmark_module() -> Any:
    script_path = Path(__file__).resolve().with_name("run_phase18_benchmarks.py")
    spec = importlib.util.spec_from_file_location("phase18_acceptance_benchmark", script_path)
    if spec is None or spec.loader is None:
        raise AcceptanceError(f"cannot load benchmark implementation: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _derive_module() -> Any:
    script_path = Path(__file__).resolve().with_name("derive_phase18_budgets.py")
    spec = importlib.util.spec_from_file_location("phase18_acceptance_derive", script_path)
    if spec is None or spec.loader is None:
        raise AcceptanceError(f"cannot load budget validator: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_BENCHMARK = _benchmark_module()
_DERIVE = _derive_module()
# Kept as an explicit name for focused tooling tests and for callers that need
# the already-audited Phase 18.2 validation helpers.
_BUDGET_VALIDATOR = _DERIVE


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def _require_string(value: object, field: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{field} must be a non-empty string")
    return value


def _require_positive_int(value: object, field: str) -> int:
    _require(
        _is_int(value) and 0 < value <= MAX_JSON_INTEGER,
        f"{field} must be a positive bounded integer",
    )
    return value


def _require_exact_keys(value: object, expected: frozenset[str], label: str) -> dict[str, object]:
    _require(isinstance(value, dict), f"{label} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    _require(
        not missing and not unexpected,
        f"{label} has an invalid key set (missing={len(missing)}, unexpected={len(unexpected)})",
    )
    return value


def _parse_json_int(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    _require(len(digits) <= 39, "JSON integer exceeds the bounded 128-bit input limit")
    value = int(token)
    _require(
        -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER,
        "JSON integer exceeds the bounded 128-bit input limit",
    )
    return value


def _reject_json_float(_value: str) -> object:
    raise AcceptanceError("floating-point JSON values are not permitted")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AcceptanceError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise AcceptanceError(f"non-finite JSON number is not allowed: {value}")


def _read_json(path: Path, label: str) -> tuple[dict[str, object], str]:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise AcceptanceError(f"cannot read {label}: {path}: {error}") from None
    _require(len(raw) <= MAX_INPUT_BYTES, f"{label} exceeds the {MAX_INPUT_BYTES}-byte input limit")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_int=_parse_json_int,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise AcceptanceError(f"{label} is not valid bounded UTF-8 JSON: {error}") from None
    _require(isinstance(document, dict), f"{label} must contain a JSON object")
    return document, digest


def _run_bounded_git(arguments: list[str], repository_root: Path) -> tuple[int, bytes]:
    """Run one local, read-only Git query with bounded output and time."""

    _require(arguments and all(isinstance(argument, str) and argument for argument in arguments), "invalid Git query")
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        process = subprocess.Popen(
            ["git", *arguments],
            cwd=repository_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
        )
    except OSError as error:
        raise AcceptanceError(f"cannot execute local Git query: {error}") from None

    output = bytearray()
    output_too_large = False

    def drain_stdout() -> None:
        nonlocal output_too_large
        stream = process.stdout
        if stream is None:
            output_too_large = True
            return
        while True:
            chunk = stream.read(4_096)
            if not chunk:
                return
            if len(output) + len(chunk) > MAX_GIT_OUTPUT_BYTES:
                output_too_large = True
                try:
                    process.kill()
                except OSError:
                    pass
                return
            output.extend(chunk)

    reader = threading.Thread(target=drain_stdout, daemon=True)
    reader.start()
    try:
        return_code = process.wait(timeout=GIT_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            raise AcceptanceError("local Git query did not terminate after its time limit") from None
        reader.join(timeout=1)
        raise AcceptanceError("local Git query exceeded its time limit") from None
    reader.join(timeout=1)
    if reader.is_alive():
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        raise AcceptanceError("local Git query did not terminate cleanly")
    _require(not output_too_large, "local Git query exceeded its output limit")
    return return_code, bytes(output)


def _verify_live_git(acceptance_git_sha: str, repository_root: Path = REPOSITORY_ROOT) -> None:
    """Verify the measured revision and worktree without trusting raw fields."""

    _require(
        GIT_SHA_PATTERN.fullmatch(acceptance_git_sha) is not None,
        "acceptance Git SHA is not a lowercase 40-character revision",
    )
    return_code, head_output = _run_bounded_git(["rev-parse", "--verify", "HEAD"], repository_root)
    _require(return_code == 0, "cannot resolve the current Git HEAD")
    try:
        live_head = head_output.decode("ascii").strip()
    except UnicodeDecodeError:
        raise AcceptanceError("local Git HEAD is not valid ASCII") from None
    _require(
        GIT_SHA_PATTERN.fullmatch(live_head) is not None,
        "local Git HEAD is not a complete lowercase 40-character revision",
    )
    _require(live_head == acceptance_git_sha, "acceptance Git SHA does not match the current HEAD")

    return_code, _ = _run_bounded_git(
        ["cat-file", "-e", f"{acceptance_git_sha}^{{commit}}"], repository_root
    )
    _require(return_code == 0, "acceptance Git SHA is not an existing commit")

    return_code, status_output = _run_bounded_git(
        ["status", "--porcelain=v1", "--untracked-files=all", "--"], repository_root
    )
    _require(return_code == 0, "cannot verify the current Git worktree status")
    _require(status_output == b"", "the current Git worktree is dirty")


def _canonical_descriptors() -> tuple[tuple[str, str, str, str, int, str, str], ...]:
    try:
        runner_descriptors = tuple(_DERIVE._scenario_descriptors())
    except (AttributeError, TypeError, ValueError, KeyError) as error:
        raise AcceptanceError(f"cannot inspect canonical benchmark matrix: {error}") from None
    _require(
        runner_descriptors == CANONICAL_SCENARIOS,
        "benchmark implementation does not expose the frozen canonical 24-scenario matrix",
    )
    return CANONICAL_SCENARIOS


def _validate_environment(environment: object, label: str) -> dict[str, object]:
    environment_dict = _require_exact_keys(environment, ENVIRONMENT_FIELDS, label)
    try:
        _DERIVE._validate_environment(environment_dict, 0)
    except (TypeError, ValueError, KeyError) as error:
        raise AcceptanceError(f"{label} is invalid: {error}") from None
    return environment_dict


def _validate_raw_measurement(
    document: object,
    run_number: int,
    expected_implementation: str,
) -> dict[str, object]:
    label = f"acceptance run {run_number}"
    measurement = _require_exact_keys(document, RAW_TOP_LEVEL_FIELDS, label)
    _validate_environment(measurement["environment"], f"{label} environment")
    raw_results = measurement["results"]
    _require(
        isinstance(raw_results, list) and len(raw_results) == EXPECTED_SCENARIO_COUNT,
        f"{label} must contain exactly 24 scenarios",
    )
    for index, result in enumerate(raw_results):
        result_dict = _require_exact_keys(result, RAW_RESULT_FIELDS, f"{label} scenario {index + 1}")
        _require(
            _is_int(result_dict["samples"])
            and result_dict["samples"] == EXPECTED_SAMPLES_PER_SCENARIO,
            f"{label} scenario {index + 1} must contain exactly five samples",
        )
        _require(
            _is_int(result_dict["warmup_runs"])
            and result_dict["warmup_runs"] == EXPECTED_WARMUPS_PER_SCENARIO,
            f"{label} scenario {index + 1} must contain exactly one warmup",
        )
        durations = result_dict["durations_ns"]
        _require(
            isinstance(durations, list) and len(durations) == EXPECTED_SAMPLES_PER_SCENARIO,
            f"{label} scenario {index + 1} must contain exactly five durations",
        )

    _canonical_descriptors()
    try:
        validated = _DERIVE.validate_measurement(measurement, run_number)
    except (TypeError, ValueError, KeyError, AttributeError) as error:
        raise AcceptanceError(f"{label} failed Phase 18.2 measurement validation: {error}") from None

    _require(
        validated["benchmark_implementation"] == expected_implementation,
        f"{label} uses a different benchmark implementation",
    )
    for result, descriptor in zip(validated["results"], CANONICAL_SCENARIOS, strict=True):
        scenario, family, workload, output_format, records, source, command = descriptor
        expected_values = {
            "scenario": scenario,
            "family": family,
            "workload": workload,
            "format": output_format,
            "source": source,
            "command": command,
            "packet_records": records,
        }
        for field, expected in expected_values.items():
            if field == "packet_records":
                _require(
                    _is_int(result[field]) and result[field] == expected,
                    f"{label} scenario {scenario} has an invalid packet_records type or value",
                )
            else:
                _require(
                    result[field] == expected,
                    f"{label} scenario {scenario} is not the canonical matrix entry",
                )
        _require_positive_int(
            result["capture_bytes"],
            f"{label} scenario {scenario} capture_bytes",
        )
        _require_positive_int(
            result["packet_records"],
            f"{label} scenario {scenario} packet_records",
        )
        for duration in result["durations_ns"]:
            _require_positive_int(duration, f"{label} scenario {scenario} duration")
        for field in ("minimum_ns", "median_ns", "maximum_ns", "growth_ratio_basis_points"):
            _require_positive_int(result[field], f"{label} scenario {scenario} {field}")
    return validated


def _ceil_scaled(value: int, factor_basis_points: int = BUDGET_FACTOR_BP) -> int:
    _require_positive_int(value, "scaled value")
    _require_positive_int(factor_basis_points, "budget factor")
    return (value * factor_basis_points + 9_999) // 10_000


def _validate_sha_map(value: object, label: str) -> dict[str, str]:
    mapping = _require_exact_keys(value, frozenset({"run_1", "run_2", "run_3"}), label)
    result: dict[str, str] = {}
    for key in ("run_1", "run_2", "run_3"):
        digest = mapping[key]
        _require(
            isinstance(digest, str) and SHA256_PATTERN.fullmatch(digest) is not None,
            f"{label}.{key} must be a lowercase SHA-256 digest",
        )
        result[key] = digest
    _require(len(set(result.values())) == EXPECTED_RUN_COUNT, f"{label} must contain three unique hashes")
    return result


def _validate_budget(document: object) -> dict[str, object]:
    budget = _require_exact_keys(document, BUDGET_TOP_LEVEL_FIELDS, "budget")
    _require(budget["schema_version"] == "phase18.2-budgets-v1", "budget has an unsupported schema")
    _require(budget["phase"] == "18.2", "budget is not a Phase 18.2 budget document")
    _require(budget["artifact_kind"] == "performance_baseline_budgets", "budget has an invalid artifact kind")
    _require(budget["budget_status"] == "frozen_for_phase_18.3", "budget is not frozen for Phase 18.3")
    _require(budget["acceptance_status"] == "not_executed", "budget must still have not_executed acceptance status")
    _require(
        budget["acceptance_statement"]
        == "FROZEN FOR PHASE 18.3; NOT YET EXECUTED AS THE FINAL ACCEPTANCE GATE",
        "budget has an invalid frozen acceptance statement",
    )
    baseline_sha = budget["measurement_git_sha"]
    _require(
        isinstance(baseline_sha, str) and GIT_SHA_PATTERN.fullmatch(baseline_sha) is not None,
        "budget.measurement_git_sha must be a lowercase 40-character Git SHA",
    )
    expected_implementation = getattr(_BENCHMARK, "BENCHMARK_IMPLEMENTATION", None)
    _require(
        budget["benchmark_implementation"] == expected_implementation,
        "budget uses an unsupported benchmark implementation",
    )
    baseline_environment = _validate_environment(
        budget["baseline_environment"], "budget baseline_environment"
    )
    _require(
        baseline_environment["git_sha"] == baseline_sha,
        "budget baseline environment Git SHA does not match measurement_git_sha",
    )
    for field, expected in (
        ("baseline_run_count", EXPECTED_RUN_COUNT),
        ("samples_per_scenario_per_run", EXPECTED_SAMPLES_PER_SCENARIO),
        ("warmups_per_scenario", EXPECTED_WARMUPS_PER_SCENARIO),
        ("scenario_count", EXPECTED_SCENARIO_COUNT),
        ("meaningful_growth_budget_count", EXPECTED_GROWTH_BUDGET_COUNT),
        ("stability_limit_basis_points", STABILITY_LIMIT_BP),
        ("median_regression_margin_basis_points", REGRESSION_MARGIN_BP),
        ("growth_regression_margin_basis_points", REGRESSION_MARGIN_BP),
        ("budget_factor_basis_points", BUDGET_FACTOR_BP),
    ):
        _require(budget[field] == expected, f"budget.{field} must be the frozen value {expected}")
        _require(_is_int(budget[field]), f"budget.{field} must be an integer")

    _require(
        budget["budget_factor_basis_points"]
        == 10_000 + budget["median_regression_margin_basis_points"]
        == 10_000 + budget["growth_regression_margin_basis_points"],
        "budget regression margins do not match the frozen factor",
    )
    frozen_policy = _require_exact_keys(budget["frozen_policy"], FROZEN_POLICY_FIELDS, "budget frozen_policy")
    _require(
        frozen_policy["stability_rule"]
        == "spread_bp = (max(medians) - min(medians)) * 10000 // reference_median",
        "budget frozen_policy has an invalid stability rule",
    )
    _require(frozen_policy["stability_limit_basis_points"] == STABILITY_LIMIT_BP, "budget policy stability limit is not frozen")
    _require(
        frozen_policy["absolute_median_rule"] == "ceil(reference_median_ns * 12500 / 10000)",
        "budget frozen_policy has an invalid absolute-median rule",
    )
    _require(
        frozen_policy["growth_rule"] == "ceil(reference_growth_basis_points * 12500 / 10000)",
        "budget frozen_policy has an invalid growth rule",
    )
    _require(frozen_policy["regression_margin_basis_points"] == REGRESSION_MARGIN_BP, "budget policy margin is not frozen")
    _require(frozen_policy["smallest_group_growth_budget"] is None, "budget policy must leave the smallest group without a growth budget")
    baseline_hashes = _validate_sha_map(budget["source_measurement_sha256"], "budget source_measurement_sha256")

    descriptors = _canonical_descriptors()
    raw_budgets = budget["budgets"]
    _require(
        isinstance(raw_budgets, list) and len(raw_budgets) == EXPECTED_SCENARIO_COUNT,
        "budget must contain exactly 24 scenario budgets",
    )
    entries: list[dict[str, object]] = []
    for entry_index, raw_entry in enumerate(raw_budgets):
        entry = _require_exact_keys(raw_entry, BUDGET_ENTRY_FIELDS, f"budget scenario {entry_index + 1}")
        scenario, family, workload, output_format, packet_records, _source, _command = descriptors[entry_index]
        for field, expected in (
            ("scenario", scenario),
            ("family", family),
            ("workload", workload),
            ("format", output_format),
            ("packet_records", packet_records),
        ):
            if field == "packet_records":
                _require(
                    _is_int(entry[field]) and entry[field] == expected,
                    f"budget scenario {scenario} has an invalid packet_records type or value",
                )
            else:
                _require(entry[field] == expected, f"budget scenario {scenario} has an invalid {field}")
        medians = entry["baseline_medians_ns"]
        _require(
            isinstance(medians, list)
            and len(medians) == EXPECTED_RUN_COUNT
            and all(_is_int(value) and 0 < value <= MAX_JSON_INTEGER for value in medians),
            f"budget scenario {scenario} has invalid baseline medians",
        )
        reference_median = sorted(medians)[1]
        _require(
            _is_int(entry["reference_median_ns"])
            and 0 < entry["reference_median_ns"] <= MAX_JSON_INTEGER
            and entry["reference_median_ns"] == reference_median,
            f"budget scenario {scenario} has an invalid reference median",
        )
        spread = (max(medians) - min(medians)) * 10_000 // reference_median
        _require(
            _is_int(entry["median_spread_basis_points"])
            and 0 <= entry["median_spread_basis_points"] <= MAX_JSON_INTEGER
            and entry["median_spread_basis_points"] == spread,
            f"budget scenario {scenario} has invalid median spread arithmetic",
        )
        _require(spread <= STABILITY_LIMIT_BP, f"budget scenario {scenario} exceeds the frozen stability limit")
        _require(
            _is_int(entry["frozen_median_budget_ns"])
            and 0 < entry["frozen_median_budget_ns"] <= MAX_JSON_INTEGER
            and entry["frozen_median_budget_ns"] == _ceil_scaled(reference_median),
            f"budget scenario {scenario} has invalid frozen median arithmetic",
        )
        growth = entry["baseline_growth_basis_points"]
        _require(
            isinstance(growth, list)
            and len(growth) == EXPECTED_RUN_COUNT
            and all(_is_int(value) and 0 < value <= MAX_JSON_INTEGER for value in growth),
            f"budget scenario {scenario} has invalid baseline growth ratios",
        )
        for field in ("reference_growth_basis_points", "frozen_growth_budget_basis_points"):
            value = entry[field]
            _require(
                value is None or (_is_int(value) and 0 < value <= MAX_JSON_INTEGER),
                f"budget scenario {scenario} has an invalid bounded {field}",
            )
        entries.append(entry)

    groups: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for entry in entries:
        key = (str(entry["family"]), str(entry["workload"]), str(entry["format"]))
        groups.setdefault(key, []).append(entry)
    meaningful_growth_count = 0
    for key, group in groups.items():
        smallest_records = min(int(entry["packet_records"]) for entry in group)
        smallest = [entry for entry in group if entry["packet_records"] == smallest_records]
        _require(len(smallest) == 1, f"budget growth group {key} must have one smallest scenario")
        baseline = smallest[0]["baseline_medians_ns"]
        for entry in group:
            medians = entry["baseline_medians_ns"]
            expected_growth = [median * 10_000 // base for median, base in zip(medians, baseline, strict=True)]
            _require(
                entry["baseline_growth_basis_points"] == expected_growth,
                f"budget scenario {entry['scenario']} has invalid internal growth arithmetic",
            )
            if entry is smallest[0]:
                _require(entry["reference_growth_basis_points"] is None, f"budget scenario {entry['scenario']} must not have a reference growth")
                _require(entry["frozen_growth_budget_basis_points"] is None, f"budget scenario {entry['scenario']} must not have a growth budget")
            else:
                meaningful_growth_count += 1
                reference_growth = sorted(expected_growth)[1]
                _require(
                    entry["reference_growth_basis_points"] == reference_growth,
                    f"budget scenario {entry['scenario']} has an invalid reference growth",
                )
                _require(
                    entry["frozen_growth_budget_basis_points"] == _ceil_scaled(reference_growth),
                    f"budget scenario {entry['scenario']} has invalid frozen growth arithmetic",
                )
    _require(meaningful_growth_count == EXPECTED_GROWTH_BUDGET_COUNT, "budget meaningful growth count is not canonical")
    _require(len(baseline_hashes) == EXPECTED_RUN_COUNT, "budget source hash count is not canonical")
    return budget


def _load_frozen_baseline_capture_bytes(
    budget: dict[str, object], expected_implementation: str
) -> list[int]:
    """Load and validate the immutable baseline files used for capture sizing."""

    source_hashes = _validate_sha_map(
        budget["source_measurement_sha256"], "budget source_measurement_sha256"
    )
    baseline_environment = budget["baseline_environment"]
    baseline_captures: list[int] | None = None
    for run_number, path in enumerate(FROZEN_BASELINE_PATHS, start=1):
        baseline, digest = _read_json(path, f"frozen baseline run {run_number}")
        _require(
            digest == source_hashes[f"run_{run_number}"],
            f"frozen baseline run {run_number} does not match its budget SHA-256",
        )
        validated = _validate_raw_measurement(baseline, run_number, expected_implementation)
        _require(
            validated["environment"]["git_sha"] == budget["measurement_git_sha"],
            f"frozen baseline run {run_number} uses a different Git SHA than the budget",
        )
        _require(
            _environment_identity(validated["environment"]) == _environment_identity(baseline_environment),
            f"frozen baseline run {run_number} uses an incompatible environment",
        )
        captures = [int(result["capture_bytes"]) for result in validated["results"]]
        if baseline_captures is None:
            baseline_captures = captures
        else:
            _require(
                captures == baseline_captures,
                f"frozen baseline run {run_number} has different capture sizes",
            )
    _require(baseline_captures is not None, "frozen baseline capture sizes are unavailable")
    return baseline_captures


def _require_canonical_budget_document(budget: object) -> None:
    """Prevent API callers from bypassing the pinned raw-budget digest."""

    canonical_budget, canonical_digest = _read_json(FROZEN_BUDGET_PATH, "canonical frozen budget")
    _require(
        canonical_digest == FROZEN_BUDGET_SHA256,
        "repository canonical frozen budget does not match its pinned SHA-256",
    )
    _require(
        budget == canonical_budget,
        "budget document does not match the canonical frozen artifact",
    )


def _environment_identity(environment: dict[str, object]) -> dict[str, object]:
    return {field: environment[field] for field in ENVIRONMENT_IDENTITY_FIELDS}


def _is_linux_wsl2(environment: dict[str, object]) -> bool:
    return (
        environment["os"] == "Linux"
        and "WSL2" in str(environment["kernel"])
        and "WSL2" in str(environment["platform"])
    )


def _is_positive_page_aligned(value: object) -> bool:
    return _is_int(value) and value > 0 and value % MEMORY_PAGE_BYTES == 0


def _environment_compatibility(
    baseline_environment: dict[str, object], acceptance_environment: dict[str, object]
) -> dict[str, object]:
    """Apply the frozen, narrow Phase 18.3 environment equivalence policy."""

    baseline_identity = _environment_identity(baseline_environment)
    acceptance_identity = _environment_identity(acceptance_environment)
    differing_fields = [
        field
        for field in ENVIRONMENT_IDENTITY_FIELDS
        if baseline_identity[field] != acceptance_identity[field]
    ]
    tolerance: dict[str, object] = {
        "field": "total_memory_bytes",
        "page_size_bytes": MEMORY_PAGE_BYTES,
        "maximum_absolute_difference_bytes": MEMORY_PAGE_BYTES,
        "requires_positive_page_aligned_values": True,
        "scope": "Linux WSL2 only; not a general cross-machine tolerance",
    }
    baseline_memory = baseline_environment["total_memory_bytes"]
    acceptance_memory = acceptance_environment["total_memory_bytes"]
    _require(
        _is_positive_page_aligned(baseline_memory)
        and _is_positive_page_aligned(acceptance_memory),
        "environment total_memory_bytes values must be positive and 4096-byte aligned",
    )
    memory_difference = abs(int(acceptance_memory) - int(baseline_memory))
    if not differing_fields:
        return {
            "policy_identifier": ENVIRONMENT_COMPATIBILITY_POLICY_ID,
            "status": "exact_match",
            "differing_fields": [],
            "observed_total_memory_difference_bytes": memory_difference,
            "tolerance": tolerance,
        }

    _require(
        differing_fields == ["total_memory_bytes"],
        "acceptance environment differs in a stable field outside the frozen memory exception",
    )
    _require(
        _is_linux_wsl2(baseline_environment) and _is_linux_wsl2(acceptance_environment),
        "the total-memory equivalence exception is limited to Linux WSL2",
    )
    _require(
        memory_difference <= MEMORY_PAGE_BYTES,
        "acceptance total_memory_bytes differs by more than one 4096-byte page",
    )
    return {
        "policy_identifier": ENVIRONMENT_COMPATIBILITY_POLICY_ID,
        "status": "equivalent_within_one_page",
        "differing_fields": ["total_memory_bytes"],
        "observed_total_memory_difference_bytes": memory_difference,
        "tolerance": tolerance,
    }


def _acceptance_result(
    budget: dict[str, object],
    budget_sha256: str,
    runs: list[dict[str, object]],
    run_sha256: list[str],
) -> dict[str, object]:
    _require(len(runs) == EXPECTED_RUN_COUNT, "exactly three acceptance runs are required")
    _require(len(run_sha256) == EXPECTED_RUN_COUNT, "exactly three acceptance run hashes are required")
    _require(
        all(isinstance(digest, str) and SHA256_PATTERN.fullmatch(digest) is not None for digest in run_sha256),
        "acceptance run hashes must be lowercase SHA-256 digests",
    )
    _require(
        len(set(run_sha256)) == EXPECTED_RUN_COUNT,
        "distinct source SHA-256 values are required for independent runs",
    )
    budget_hashes = set(_validate_sha_map(budget["source_measurement_sha256"], "budget source_measurement_sha256").values())
    _require(not budget_hashes.intersection(run_sha256), "acceptance runs must not reuse a frozen baseline evidence file")

    baseline_environment = budget["baseline_environment"]
    baseline_git_sha = str(budget["measurement_git_sha"])
    acceptance_git_sha = str(runs[0]["environment"]["git_sha"])
    _require(
        all(run["environment"]["git_sha"] == acceptance_git_sha for run in runs),
        "acceptance runs must use one Git SHA",
    )
    _require(
        GIT_SHA_PATTERN.fullmatch(acceptance_git_sha) is not None,
        "acceptance Git SHA is not a lowercase 40-character revision",
    )
    _require(
        acceptance_git_sha != baseline_git_sha,
        "acceptance must use a later Git revision than the frozen baseline",
    )
    acceptance_identity = _environment_identity(runs[0]["environment"])
    _require(
        all(_environment_identity(run["environment"]) == acceptance_identity for run in runs),
        "acceptance runs do not share one stable environment identity",
    )
    environment_compatibility = _environment_compatibility(
        baseline_environment, runs[0]["environment"]
    )
    _require(
        all(run["benchmark_implementation"] == budget["benchmark_implementation"] for run in runs),
        "acceptance runs do not use the frozen benchmark implementation",
    )
    baseline_capture_sizes = _load_frozen_baseline_capture_bytes(
        budget, str(budget["benchmark_implementation"])
    )
    _verify_live_git(acceptance_git_sha)

    budget_entries = budget["budgets"]
    scenarios: list[dict[str, object]] = []
    failed_scenarios: list[str] = []
    unstable_scenarios: list[str] = []
    stability_checks_passed = 0
    median_budgets_passed = 0
    growth_budgets_passed = 0
    maximum_spread = 0
    for scenario_index, (descriptor, budget_entry) in enumerate(zip(CANONICAL_SCENARIOS, budget_entries, strict=True)):
        scenario, family, workload, output_format, packet_records, _source, _command = descriptor
        run_results = [run["results"][scenario_index] for run in runs]
        capture_sizes = [int(result["capture_bytes"]) for result in run_results]
        _require(
            len(set(capture_sizes)) == 1,
            f"acceptance scenario {scenario} has inconsistent generated capture bytes",
        )
        _require(
            capture_sizes[0] == baseline_capture_sizes[scenario_index],
            f"acceptance scenario {scenario} capture bytes do not match the frozen baseline",
        )
        medians = [int(result["median_ns"]) for result in run_results]
        reference_median = sorted(medians)[1]
        median_spread = (max(medians) - min(medians)) * 10_000 // reference_median
        stability_pass = median_spread <= STABILITY_LIMIT_BP
        if stability_pass:
            stability_checks_passed += 1
        else:
            unstable_scenarios.append(scenario)
        maximum_spread = max(maximum_spread, median_spread)
        growth_values = [int(result["growth_ratio_basis_points"]) for result in run_results]
        reference_growth = sorted(growth_values)[1]
        median_budget = int(budget_entry["frozen_median_budget_ns"])
        growth_budget_value = budget_entry["frozen_growth_budget_basis_points"]
        growth_budget = int(growth_budget_value) if growth_budget_value is not None else None
        median_within_budget = reference_median <= median_budget
        if median_within_budget:
            median_budgets_passed += 1
        if growth_budget is None:
            reported_reference_growth: int | None = None
            growth_within_budget: bool | None = None
        else:
            reported_reference_growth = reference_growth
            growth_within_budget = reference_growth <= growth_budget
            if growth_within_budget:
                growth_budgets_passed += 1
        scenario_passed = stability_pass and median_within_budget and growth_within_budget is not False
        if not scenario_passed:
            failed_scenarios.append(scenario)
        scenarios.append(
            {
                "scenario": scenario,
                "family": family,
                "workload": workload,
                "format": output_format,
                "packet_records": packet_records,
                "acceptance_run_medians_ns": medians,
                "acceptance_reference_median_ns": reference_median,
                "acceptance_spread_basis_points": median_spread,
                "frozen_median_budget_ns": median_budget,
                "median_pass": median_within_budget,
                "acceptance_growth_values_basis_points": growth_values,
                "acceptance_reference_growth_basis_points": reported_reference_growth,
                "frozen_growth_budget_basis_points": growth_budget,
                "growth_pass": growth_within_budget,
                "stability_pass": stability_pass,
                "scenario_pass": scenario_passed,
            }
        )

    passed_count = EXPECTED_SCENARIO_COUNT - len(failed_scenarios)
    acceptance_status = (
        "unstable"
        if unstable_scenarios
        else "passed"
        if not failed_scenarios
        else "failed"
    )
    if acceptance_status == "passed":
        statement = "PASSED: all 24 scenarios are within the frozen Phase 18.2 budgets"
    elif acceptance_status == "unstable":
        statement = (
            f"UNSTABLE: {len(unstable_scenarios)} of 24 scenarios exceed the frozen stability limit"
        )
    else:
        statement = (
            f"FAILED: {len(failed_scenarios)} of 24 scenarios exceed the frozen Phase 18.2 budgets"
        )
    return {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "phase": "18.3",
        "artifact_kind": ACCEPTANCE_ARTIFACT_KIND,
        "budget_status": budget["budget_status"],
        "acceptance_status": acceptance_status,
        "acceptance_statement": statement,
        "overall_pass": not failed_scenarios,
        "budget_schema_version": budget["schema_version"],
        "budget_artifact_sha256": budget_sha256,
        "baseline_measurement_git_sha": baseline_git_sha,
        "acceptance_measurement_git_sha": acceptance_git_sha,
        "source_measurement_sha256": {
            f"run_{index}": digest for index, digest in enumerate(run_sha256, start=1)
        },
        "benchmark_implementation": budget["benchmark_implementation"],
        "acceptance_environment": runs[0]["environment"],
        "baseline_environment": baseline_environment,
        "environment_compatibility": environment_compatibility,
        "acceptance_run_count": EXPECTED_RUN_COUNT,
        "samples_per_scenario_per_run": EXPECTED_SAMPLES_PER_SCENARIO,
        "warmups_per_scenario": EXPECTED_WARMUPS_PER_SCENARIO,
        "scenario_count": EXPECTED_SCENARIO_COUNT,
        "absolute_budget_count": EXPECTED_SCENARIO_COUNT,
        "meaningful_growth_count": EXPECTED_GROWTH_BUDGET_COUNT,
        "stability_checks_passed": stability_checks_passed,
        "stability_checks_total": EXPECTED_SCENARIO_COUNT,
        "maximum_acceptance_spread_basis_points": maximum_spread,
        "median_budgets_passed": median_budgets_passed,
        "median_budgets_total": EXPECTED_SCENARIO_COUNT,
        "growth_budgets_passed": growth_budgets_passed,
        "growth_budgets_total": EXPECTED_GROWTH_BUDGET_COUNT,
        "passed_scenario_count": passed_count,
        "failed_scenario_count": len(failed_scenarios),
        "failed_scenarios": failed_scenarios,
        "unstable_scenarios": unstable_scenarios,
        "scenarios": scenarios,
    }


def evaluate_acceptance(
    budget: object,
    runs: list[object],
    run_sha256: list[str],
    budget_sha256: str | None = None,
) -> dict[str, object]:
    """Validate documents and return the deterministic Phase 18.3 result."""

    _require(len(runs) == EXPECTED_RUN_COUNT, "exactly three acceptance runs are required")
    _require(len(run_sha256) == EXPECTED_RUN_COUNT, "exactly three acceptance run hashes are required")
    _require(
        isinstance(budget_sha256, str) and SHA256_PATTERN.fullmatch(budget_sha256) is not None,
        "budget SHA-256 must be a lowercase 64-character digest",
    )
    _require(
        budget_sha256 == FROZEN_BUDGET_SHA256,
        "budget artifact SHA-256 does not match the frozen Phase 18.2 artifact",
    )
    _require_canonical_budget_document(budget)
    validated_budget = _validate_budget(budget)
    expected_implementation = str(validated_budget["benchmark_implementation"])
    validated_runs = [
        _validate_raw_measurement(document, index, expected_implementation)
        for index, document in enumerate(runs, start=1)
    ]
    return _acceptance_result(validated_budget, budget_sha256, validated_runs, run_sha256)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate exactly three later full Phase 18 runs against frozen budgets."
    )
    parser.add_argument("budget", type=Path, help="frozen phase18-2-budgets-v1 JSON")
    parser.add_argument("measurements", nargs=3, type=Path, help="three full benchmark JSON runs")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    budget, budget_sha256 = _read_json(args.budget, "budget")
    measurements: list[dict[str, object]] = []
    measurement_hashes: list[str] = []
    for index, path in enumerate(args.measurements, start=1):
        measurement, digest = _read_json(path, f"acceptance run {index}")
        measurements.append(measurement)
        measurement_hashes.append(digest)
    result = evaluate_acceptance(budget, measurements, measurement_hashes, budget_sha256)
    json.dump(result, sys.stdout, sort_keys=True, indent=2, allow_nan=False)
    sys.stdout.write("\n")
    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, AcceptanceError, TypeError, ValueError, RecursionError, MemoryError) as error:
        print(f"phase 18 acceptance failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
