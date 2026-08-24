#!/usr/bin/env python3
"""Focused, dependency-free regression tests for Phase 18.2 benchmark tooling."""

from __future__ import annotations

import ast
from copy import deepcopy
from collections import defaultdict
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
BENCHMARK_PATH = SCRIPTS / "run_phase18_benchmarks.py"
DERIVE_PATH = SCRIPTS / "derive_phase18_budgets.py"


def load_script(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load test module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BENCHMARK = load_script("phase18_benchmark_tests_impl", BENCHMARK_PATH)
DERIVE = load_script("phase18_budget_tests_impl", DERIVE_PATH)


def synthetic_environment(git_sha: str = "a" * 40, dirty: bool = False) -> dict[str, object]:
    return {
        "git_sha": git_sha,
        "git_dirty": dirty,
        "git_worktree_status": "dirty" if dirty else "clean",
        "rustc": "rustc 1.97.1 (synthetic)",
        "active_toolchain": "1.97.1-x86_64-unknown-linux-gnu (synthetic)",
        "cargo": "cargo 1.97.1 (synthetic)",
        "python": "3.12.0",
        "build_profile": "release",
        "os": "Linux",
        "kernel": "6.0.0-synthetic",
        "platform": "Linux-6.0.0-synthetic-x86_64",
        "machine": "x86_64",
        "cpu_model": "Synthetic CPU",
        "logical_cpu_count": 8,
        "total_memory_bytes": 16 * 1024 * 1024 * 1024,
        "available_memory_bytes": 8 * 1024 * 1024 * 1024,
        "power_mode": "reported governor=performance; power state was not controlled",
        "background_load": "not controlled, pinned, or sampled",
        "limitations": "synthetic test environment; uncontrolled background load",
    }


def synthetic_measurement(run_number: int = 1) -> dict[str, object]:
    scenarios = BENCHMARK.scenario_matrix(False)
    results: list[dict[str, object]] = []
    medians: list[int] = []
    for index, scenario in enumerate(scenarios):
        # The first scenario intentionally yields 100001, 100003, and 100005
        # across runs so the integer ceiling rule has a non-even test case.
        median = 100_001 + index * 1_000 + (run_number - 1) * 2
        medians.append(median)
        results.append(
            {
                "scenario": scenario["name"],
                "family": scenario["family"],
                "workload": scenario["workload"],
                "format": scenario["format"],
                "source": scenario["source"],
                "command": scenario["command"],
                "capture_bytes": 256 + index,
                "packet_records": scenario["records"],
                "samples": 5,
                "warmup_runs": 1,
                "durations_ns": [median - 2, median - 1, median, median + 1, median + 2],
                "minimum_ns": median - 2,
                "median_ns": median,
                "maximum_ns": median + 2,
                "growth_ratio_basis_points": None,
            }
        )

    baselines: dict[tuple[str, str, str], int] = {}
    for result, median in zip(results, medians, strict=True):
        key = (str(result["family"]), str(result["workload"]), str(result["format"]))
        baseline = baselines.setdefault(key, median)
        result["growth_ratio_basis_points"] = median * 10_000 // baseline

    return {
        "schema_version": BENCHMARK.BENCHMARK_SCHEMA_VERSION,
        "phase": "18.2",
        "benchmark_implementation": BENCHMARK.BENCHMARK_IMPLEMENTATION,
        "mode": "benchmark",
        "timing_unit": "nanoseconds",
        "growth_ratio_unit": "basis_points_relative_to_smallest_matching_workload",
        "acceptance_status": "pending",
        "environment": synthetic_environment(),
        "results": results,
    }


class Phase18BenchmarkMatrixTests(unittest.TestCase):
    def test_smoke_matrix_is_finite(self) -> None:
        smoke = BENCHMARK.scenario_matrix(True)
        full = BENCHMARK.scenario_matrix(False)
        self.assertGreater(len(smoke), 0)
        self.assertLessEqual(len(smoke), len(full))
        self.assertTrue(all(1 <= int(scenario["records"]) <= BENCHMARK.MAX_GENERATED_RECORDS for scenario in smoke))
        self.assertEqual(len({str(scenario["name"]) for scenario in smoke}), len(smoke))

    def test_full_matrix_has_exact_canonical_scales(self) -> None:
        scenarios = BENCHMARK.scenario_matrix(False)
        self.assertEqual(len(scenarios), 24)
        self.assertEqual(
            [int(scenario["records"]) for scenario in scenarios if scenario["family"] == "validate"],
            [1_000, 10_000, 50_000],
        )
        self.assertEqual(
            [int(scenario["records"]) for scenario in scenarios if scenario["family"] == "flows"],
            [128, 2_048, 8_192],
        )
        self.assertEqual(
            [int(scenario["records"]) for scenario in scenarios if scenario["family"] == "dns"],
            [1_000, 10_000],
        )
        self.assertEqual(
            {
                str(scenario["workload"]): [
                    int(item["records"])
                    for item in scenarios
                    if item["family"] == "analyze" and item["workload"] == scenario["workload"]
                ]
                for scenario in scenarios
                if scenario["family"] == "analyze"
            },
            {
                workload: [1_000, 10_000]
                for workload in ("benign_mixed", "repeated", "dns_heavy", "multi_signal")
            },
        )
        reporting = defaultdict(list)
        for scenario in scenarios:
            if scenario["family"] == "reporting":
                reporting[str(scenario["format"])].append(int(scenario["records"]))
        self.assertEqual(
            dict(reporting),
            {output_format: [1_000, 10_000] for output_format in ("table", "json", "ndjson", "csv")},
        )

    def test_names_are_unique_and_growth_groups_have_one_smallest(self) -> None:
        scenarios = BENCHMARK.scenario_matrix(False)
        names = [str(scenario["name"]) for scenario in scenarios]
        self.assertEqual(len(names), len(set(names)))
        groups: dict[tuple[str, str, str], list[int]] = defaultdict(list)
        for scenario in scenarios:
            key = (str(scenario["family"]), str(scenario["workload"]), str(scenario["format"]))
            groups[key].append(int(scenario["records"]))
        self.assertEqual(len(groups), 11)
        for records in groups.values():
            self.assertEqual(records.count(min(records)), 1)

    def test_reporting_growth_is_not_self_only(self) -> None:
        scenarios = BENCHMARK.scenario_matrix(False)
        for output_format in ("table", "json", "ndjson", "csv"):
            records = [
                int(scenario["records"])
                for scenario in scenarios
                if scenario["family"] == "reporting" and scenario["format"] == output_format
            ]
            self.assertEqual(records, [1_000, 10_000])
            self.assertEqual(len(records), 2)


class Phase18BudgetValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.measurements = [synthetic_measurement(run_number) for run_number in (1, 2, 3)]

    def test_budget_arithmetic_is_integer_only_and_ceil_is_exact(self) -> None:
        source = Path(DERIVE_PATH).read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Div) for node in ast.walk(tree)))
        self.assertEqual(DERIVE._ceil_scaled(100_003), 125_004)
        document = DERIVE.derive_budget_document(
            deepcopy(self.measurements), ["0" * 64, "1" * 64, "2" * 64]
        )
        self.assertEqual(document["scenario_count"], 24)
        self.assertEqual(document["meaningful_growth_budget_count"], 13)
        first = document["budgets"][0]
        self.assertEqual(first["reference_median_ns"], 100_003)
        self.assertEqual(first["frozen_median_budget_ns"], 125_004)
        self.assertIsNone(first["reference_growth_basis_points"])
        self.assertIsNone(first["frozen_growth_budget_basis_points"])

    def test_valid_budget_document_has_frozen_pending_status(self) -> None:
        document = DERIVE.derive_budget_document(
            deepcopy(self.measurements), ["0" * 64, "1" * 64, "2" * 64]
        )
        self.assertEqual(document["budget_status"], "frozen_for_phase_18.3")
        self.assertEqual(document["acceptance_status"], "not_executed")
        self.assertIn("FROZEN FOR PHASE 18.3", document["acceptance_statement"])
        self.assertIn("NOT YET EXECUTED", document["acceptance_statement"])

    def assert_cli_rejects(self, documents: list[dict[str, object]] | None = None, missing: bool = False) -> None:
        with tempfile.TemporaryDirectory(prefix="pcapraven-phase18-tests-") as temporary:
            root = Path(temporary)
            paths: list[Path] = []
            for index in range(3):
                path = root / f"run-{index + 1}.json"
                if not missing or index != 2:
                    payload = (documents or self.measurements)[index]
                    path.write_text(json.dumps(payload), encoding="utf-8")
                paths.append(path)
            process = subprocess.run(
                [sys.executable, str(DERIVE_PATH), *(str(path) for path in paths)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(process.stdout, "")
            self.assertIn("phase 18 budget derivation failed", process.stderr)

    def test_missing_baseline_input_is_rejected(self) -> None:
        self.assert_cli_rejects(missing=True)

    def test_inconsistent_git_revision_is_rejected(self) -> None:
        documents = deepcopy(self.measurements)
        documents[2]["environment"]["git_sha"] = "b" * 40
        self.assert_cli_rejects(documents)

    def test_invalid_git_revision_shape_is_rejected(self) -> None:
        documents = deepcopy(self.measurements)
        documents[0]["environment"]["git_sha"] = "not-a-revision"
        self.assert_cli_rejects(documents)

    def test_inconsistent_generated_capture_bytes_are_rejected(self) -> None:
        documents = deepcopy(self.measurements)
        documents[2]["results"][0]["capture_bytes"] += 1
        self.assert_cli_rejects(documents)

    def test_unstable_baseline_is_rejected_at_frozen_limit(self) -> None:
        documents = deepcopy(self.measurements)
        result = documents[2]["results"][0]
        result["durations_ns"] = [200_000, 200_001, 200_002, 200_003, 200_004]
        result["minimum_ns"] = 200_000
        result["median_ns"] = 200_002
        result["maximum_ns"] = 200_004
        # The first scenario is its group's smallest baseline, so its growth
        # ratio remains the self-ratio even though its timing is unstable.
        result["growth_ratio_basis_points"] = 10_000
        baselines: dict[tuple[str, str, str], int] = {}
        for item in documents[2]["results"]:
            key = (str(item["family"]), str(item["workload"]), str(item["format"]))
            baseline = baselines.setdefault(key, int(item["median_ns"]))
            item["growth_ratio_basis_points"] = int(item["median_ns"]) * 10_000 // baseline
        self.assert_cli_rejects(documents)

    def test_dirty_baseline_is_rejected(self) -> None:
        documents = deepcopy(self.measurements)
        documents[1]["environment"]["git_dirty"] = True
        documents[1]["environment"]["git_worktree_status"] = "dirty"
        self.assert_cli_rejects(documents)

    def test_incorrect_sample_count_is_rejected(self) -> None:
        documents = deepcopy(self.measurements)
        documents[0]["results"][0]["durations_ns"] = [100_000]
        documents[0]["results"][0]["samples"] = 1
        self.assert_cli_rejects(documents)

    def test_missing_scenario_is_rejected(self) -> None:
        documents = deepcopy(self.measurements)
        documents[0]["results"].pop()
        self.assert_cli_rejects(documents)

    def test_invalid_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pcapraven-phase18-tests-") as temporary:
            root = Path(temporary)
            paths = []
            for index, measurement in enumerate(self.measurements):
                path = root / f"run-{index + 1}.json"
                path.write_text("not-json" if index == 0 else json.dumps(measurement), encoding="utf-8")
                paths.append(path)
            process = subprocess.run(
                [sys.executable, str(DERIVE_PATH), *(str(path) for path in paths)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(process.stdout, "")

    def test_inconsistent_growth_calculation_is_rejected(self) -> None:
        documents = deepcopy(self.measurements)
        documents[0]["results"][1]["growth_ratio_basis_points"] += 1
        self.assert_cli_rejects(documents)


if __name__ == "__main__":
    unittest.main()
