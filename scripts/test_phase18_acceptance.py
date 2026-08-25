#!/usr/bin/env python3
"""Focused, dependency-free tests for the Phase 18.3 acceptance evaluator."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
EVALUATOR_PATH = SCRIPTS / "evaluate_phase18_acceptance.py"


def load_script(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load test module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EVALUATOR = load_script("phase18_acceptance_tests_impl", EVALUATOR_PATH)
BENCHMARK = EVALUATOR._BENCHMARK
FROZEN_BUDGET = json.loads(
    (ROOT / "docs" / "performance" / "phase18-2-budgets.json").read_text(encoding="utf-8")
)
FROZEN_BUDGET_SHA256 = EVALUATOR.FROZEN_BUDGET_SHA256
FROZEN_BASELINE_CAPTURE_BYTES = [
    json.loads(
        (ROOT / "docs" / "performance" / f"phase18-2-baseline-run-{run}.json").read_text(
            encoding="utf-8"
        )
    )["results"]
    for run in range(1, 4)
]
FROZEN_CAPTURE_SIZES = [
    int(result["capture_bytes"]) for result in FROZEN_BASELINE_CAPTURE_BYTES[0]
]


def synthetic_environment(git_sha: str = "a" * 40, dirty: bool = False) -> dict[str, object]:
    environment = deepcopy(FROZEN_BUDGET["baseline_environment"])
    environment["git_sha"] = git_sha
    environment["git_dirty"] = dirty
    environment["git_worktree_status"] = "dirty" if dirty else "clean"
    return environment


def synthetic_measurement(run_number: int = 1, git_sha: str = "a" * 40) -> dict[str, object]:
    scenarios = BENCHMARK.scenario_matrix(False)
    results: list[dict[str, object]] = []
    for index, scenario in enumerate(scenarios):
        median = 100_001 + index * 1_000 + (run_number - 1) * 2
        results.append(
            {
                "scenario": scenario["name"],
                "family": scenario["family"],
                "workload": scenario["workload"],
                "format": scenario["format"],
                "source": scenario["source"],
                "command": scenario["command"],
                "capture_bytes": FROZEN_CAPTURE_SIZES[index],
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
    recalculate_growth(results)
    return {
        "schema_version": BENCHMARK.BENCHMARK_SCHEMA_VERSION,
        "phase": "18.2",
        "benchmark_implementation": BENCHMARK.BENCHMARK_IMPLEMENTATION,
        "mode": "benchmark",
        "timing_unit": "nanoseconds",
        "growth_ratio_unit": "basis_points_relative_to_smallest_matching_workload",
        "acceptance_status": "pending",
        "environment": synthetic_environment(git_sha),
        "results": results,
    }


def recalculate_growth(results: list[dict[str, object]]) -> None:
    baselines: dict[tuple[str, str, str], int] = {}
    for result in results:
        key = (str(result["family"]), str(result["workload"]), str(result["format"]))
        median = int(result["median_ns"])
        baseline = baselines.setdefault(key, median)
        result["growth_ratio_basis_points"] = median * 10_000 // baseline


def set_median(result: dict[str, object], median: int) -> None:
    result["durations_ns"] = [median - 2, median - 1, median, median + 1, median + 2]
    result["minimum_ns"] = median - 2
    result["median_ns"] = median
    result["maximum_ns"] = median + 2


class Phase18AcceptanceTests(unittest.TestCase):
    def make_case(self) -> tuple[dict[str, object], list[dict[str, object]]]:
        budget = deepcopy(FROZEN_BUDGET)
        acceptance = [synthetic_measurement(run, "b" * 40) for run in (1, 2, 3)]
        return budget, acceptance

    def run_cli(
        self,
        budget: dict[str, object],
        measurements: list[dict[str, object]],
        same_measurement_path: bool = False,
        budget_sha256: str = FROZEN_BUDGET_SHA256,
    ) -> subprocess.CompletedProcess[str]:
        # Valid synthetic cases use the evaluator API with only the live-Git
        # subprocess seam mocked; the real CLI parser and digest pin are
        # exercised separately by run_cli_raw tests.
        encoded_measurements = [
            json.dumps(measurement, sort_keys=True, indent=2).encode("utf-8")
            for measurement in measurements
        ]
        hashes = [hashlib.sha256(encoded).hexdigest() for encoded in encoded_measurements]
        if same_measurement_path:
            hashes[1:] = [hashes[0], hashes[0]]
        try:
            with mock.patch.object(EVALUATOR, "_verify_live_git"):
                result = EVALUATOR.evaluate_acceptance(
                    deepcopy(budget),
                    deepcopy(measurements),
                    hashes,
                    budget_sha256,
                )
        except EVALUATOR.AcceptanceError as error:
            return subprocess.CompletedProcess(
                args=[str(EVALUATOR_PATH)],
                returncode=1,
                stdout="",
                stderr=f"phase 18 acceptance failed: {error}\n",
            )
        output = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        return subprocess.CompletedProcess(
            args=[str(EVALUATOR_PATH)],
            returncode=0 if result["overall_pass"] else 1,
            stdout=output,
            stderr="",
        )

    def run_cli_raw(
        self, budget_text: str, measurement_texts: list[str]
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="pcapraven-phase18-3-tests-") as temporary:
            root = Path(temporary)
            budget_path = root / "budgets.json"
            budget_path.write_text(budget_text, encoding="utf-8")
            paths: list[Path] = []
            for index, measurement_text in enumerate(measurement_texts, start=1):
                path = root / f"run-{index}.json"
                path.write_text(measurement_text, encoding="utf-8")
                paths.append(path)
            return subprocess.run(
                [sys.executable, str(EVALUATOR_PATH), str(budget_path), *(str(path) for path in paths)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

    def assert_rejected(
        self, budget: dict[str, object], measurements: list[dict[str, object]], message: str = ""
    ) -> None:
        process = self.run_cli(budget, measurements)
        self.assertNotEqual(process.returncode, 0, message)
        self.assertEqual(process.stdout, "", message)
        self.assertIn("phase 18 acceptance failed", process.stderr, message)

    def assert_budget_rejected(self, budget: dict[str, object]) -> None:
        with self.assertRaises(EVALUATOR.AcceptanceError):
            EVALUATOR._validate_budget(deepcopy(budget))

    def test_valid_three_run_acceptance_all_24_and_13_pass(self) -> None:
        budget, measurements = self.make_case()
        process = self.run_cli(budget, measurements)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["acceptance_status"], "passed")
        self.assertEqual(result["artifact_kind"], EVALUATOR.ACCEPTANCE_ARTIFACT_KIND)
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["stability_checks_passed"], 24)
        self.assertEqual(result["median_budgets_passed"], 24)
        self.assertEqual(result["growth_budgets_passed"], 13)
        self.assertEqual(result["stability_checks_total"], 24)
        self.assertEqual(result["median_budgets_total"], 24)
        self.assertEqual(result["growth_budgets_total"], 13)
        self.assertEqual(len(result["scenarios"]), 24)
        self.assertEqual(result["acceptance_run_count"], 3)
        self.assertEqual(result["samples_per_scenario_per_run"], 5)
        self.assertEqual(result["warmups_per_scenario"], 1)
        self.assertEqual(result["meaningful_growth_count"], 13)
        self.assertEqual(result["baseline_measurement_git_sha"], FROZEN_BUDGET["measurement_git_sha"])
        self.assertEqual(result["acceptance_measurement_git_sha"], "b" * 40)
        self.assertEqual(result["acceptance_environment"]["git_sha"], "b" * 40)
        self.assertEqual(len(result["source_measurement_sha256"]), 3)
        self.assertEqual(len(result["budget_artifact_sha256"]), 64)
        self.assertEqual(
            result["environment_compatibility"]["policy_identifier"],
            EVALUATOR.ENVIRONMENT_COMPATIBILITY_POLICY_ID,
        )
        self.assertEqual(result["environment_compatibility"]["status"], "exact_match")
        self.assertEqual(result["environment_compatibility"]["differing_fields"], [])
        self.assertEqual(
            result["environment_compatibility"]["tolerance"]["page_size_bytes"],
            EVALUATOR.MEMORY_PAGE_BYTES,
        )
        required = {
            "scenario",
            "family",
            "workload",
            "format",
            "packet_records",
            "acceptance_run_medians_ns",
            "acceptance_reference_median_ns",
            "acceptance_spread_basis_points",
            "frozen_median_budget_ns",
            "median_pass",
            "acceptance_growth_values_basis_points",
            "acceptance_reference_growth_basis_points",
            "frozen_growth_budget_basis_points",
            "growth_pass",
            "scenario_pass",
        }
        self.assertTrue(all(required <= set(scenario) for scenario in result["scenarios"]))

    def test_wrong_budget_type_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["artifact_kind"] = "performance_final_acceptance"
        self.assert_budget_rejected(budget)

    def test_malformed_budget_json_is_rejected_without_result(self) -> None:
        budget, measurements = self.make_case()
        process = self.run_cli_raw(
            "{not-json",
            [json.dumps(measurement) for measurement in measurements],
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("phase 18 acceptance failed", process.stderr)

    def test_malformed_raw_json_is_rejected_without_result(self) -> None:
        budget, measurements = self.make_case()
        process = self.run_cli_raw(
            json.dumps(budget),
            ["{not-json", json.dumps(measurements[1]), json.dumps(measurements[2])],
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("phase 18 acceptance failed", process.stderr)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget_text = json.dumps(budget, sort_keys=True, indent=2).replace(
            '"phase": "18.2"', '"phase": "18.2", "phase": "18.2"', 1
        )
        process = self.run_cli_raw(
            budget_text,
            [json.dumps(measurement) for measurement in measurements],
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("duplicate JSON object key", process.stderr)

    def test_nonfinite_json_number_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget_text = json.dumps(budget, sort_keys=True, indent=2).replace(
            '"phase": "18.2"', '"phase": NaN', 1
        )
        process = self.run_cli_raw(
            budget_text,
            [json.dumps(measurement) for measurement in measurements],
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("non-finite JSON number", process.stderr)

    def test_wrong_number_of_runs_is_rejected_by_cli(self) -> None:
        process = subprocess.run(
            [sys.executable, str(EVALUATOR_PATH), "budget.json", "run-1.json", "run-2.json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")

    def test_unfrozen_budget_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["budget_status"] = "pending"
        self.assert_budget_rejected(budget)

    def test_structurally_valid_altered_budget_digest_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["baseline_environment"]["available_memory_bytes"] += 1
        process = self.run_cli(budget, measurements, budget_sha256="0" * 64)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("does not match the frozen", process.stderr)

    def test_cli_rejects_structurally_valid_altered_budget_digest(self) -> None:
        budget, measurements = self.make_case()
        budget["baseline_environment"]["available_memory_bytes"] += 1
        process = self.run_cli_raw(
            json.dumps(budget, sort_keys=True, indent=2),
            [json.dumps(measurement, sort_keys=True, indent=2) for measurement in measurements],
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("does not match the frozen", process.stderr)

    def test_altered_budget_count_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["scenario_count"] = 23
        self.assert_budget_rejected(budget)

    def test_altered_growth_budget_count_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["meaningful_growth_budget_count"] = 12
        self.assert_budget_rejected(budget)

    def test_budget_internal_median_arithmetic_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["budgets"][0]["reference_median_ns"] += 1
        self.assert_budget_rejected(budget)

    def test_budget_internal_growth_arithmetic_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["budgets"][1]["baseline_growth_basis_points"][0] += 1
        self.assert_budget_rejected(budget)

    def test_duplicate_frozen_source_hashes_are_rejected(self) -> None:
        budget, measurements = self.make_case()
        budget["source_measurement_sha256"]["run_2"] = budget["source_measurement_sha256"]["run_1"]
        self.assert_budget_rejected(budget)

    def test_missing_scenario_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["results"].pop()
        self.assert_rejected(budget, measurements)

    def test_duplicate_scenario_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["results"][1]["scenario"] = measurements[0]["results"][0]["scenario"]
        self.assert_rejected(budget, measurements)

    def test_smoke_input_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["mode"] = "smoke"
        self.assert_rejected(budget, measurements)

    def test_dirty_git_input_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[1]["environment"]["git_dirty"] = True
        measurements[1]["environment"]["git_worktree_status"] = "dirty"
        self.assert_rejected(budget, measurements)

    def test_live_git_checks_accept_matching_existing_clean_head(self) -> None:
        git_sha = "b" * 40
        with mock.patch.object(
            EVALUATOR,
            "_run_bounded_git",
            side_effect=[(0, f"{git_sha}\n".encode()), (0, b""), (0, b"")],
        ) as query:
            EVALUATOR._verify_live_git(git_sha, ROOT)
        self.assertEqual(query.call_count, 3)

    def test_live_git_mismatched_head_is_rejected(self) -> None:
        with mock.patch.object(
            EVALUATOR,
            "_run_bounded_git",
            return_value=(0, f"{'a' * 40}\n".encode()),
        ):
            with self.assertRaises(EVALUATOR.AcceptanceError):
                EVALUATOR._verify_live_git("b" * 40, ROOT)

    def test_live_git_nonexistent_commit_is_rejected(self) -> None:
        git_sha = "b" * 40
        with mock.patch.object(
            EVALUATOR,
            "_run_bounded_git",
            side_effect=[(0, f"{git_sha}\n".encode()), (1, b"")],
        ):
            with self.assertRaises(EVALUATOR.AcceptanceError):
                EVALUATOR._verify_live_git(git_sha, ROOT)

    def test_live_git_dirty_worktree_is_rejected(self) -> None:
        git_sha = "b" * 40
        with mock.patch.object(
            EVALUATOR,
            "_run_bounded_git",
            side_effect=[(0, f"{git_sha}\n".encode()), (0, b""), (0, b" M scripts/example.py\n")],
        ):
            with self.assertRaises(EVALUATOR.AcceptanceError):
                EVALUATOR._verify_live_git(git_sha, ROOT)

    def test_mixed_acceptance_revisions_are_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[2]["environment"]["git_sha"] = "c" * 40
        self.assert_rejected(budget, measurements)

    def test_baseline_acceptance_revision_is_rejected(self) -> None:
        budget, _ = self.make_case()
        measurements = [
            synthetic_measurement(run, FROZEN_BUDGET["measurement_git_sha"])
            for run in (1, 2, 3)
        ]
        self.assert_rejected(budget, measurements)

    def test_invalid_acceptance_revision_shape_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["environment"]["git_sha"] = "not-a-revision"
        self.assert_rejected(budget, measurements)

    def test_duplicate_source_hashes_are_rejected(self) -> None:
        budget, measurements = self.make_case()
        process = self.run_cli(budget, measurements, same_measurement_path=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertIn("distinct source SHA-256", process.stderr)

    def test_incompatible_benchmark_implementation_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["benchmark_implementation"] = "other-methodology"
        self.assert_rejected(budget, measurements)

    def test_incompatible_stable_environment_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[1]["environment"]["cpu_model"] = "Other CPU"
        self.assert_rejected(budget, measurements)

    def test_incompatible_benchmark_environment_python_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[2]["environment"]["python"] = "other-python"
        self.assert_rejected(budget, measurements)

    def test_available_memory_is_treated_as_transient(self) -> None:
        budget, measurements = self.make_case()
        measurements[1]["environment"]["available_memory_bytes"] += 1
        process = self.run_cli(budget, measurements)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["overall_pass"])

    def test_one_page_total_memory_equivalence_is_allowed(self) -> None:
        budget, measurements = self.make_case()
        accepted_total_memory = (
            int(FROZEN_BUDGET["baseline_environment"]["total_memory_bytes"])
            - EVALUATOR.MEMORY_PAGE_BYTES
        )
        for measurement in measurements:
            measurement["environment"]["total_memory_bytes"] = accepted_total_memory
        process = self.run_cli(budget, measurements)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        compatibility = result["environment_compatibility"]
        self.assertTrue(result["overall_pass"])
        self.assertEqual(compatibility["status"], "equivalent_within_one_page")
        self.assertEqual(compatibility["differing_fields"], ["total_memory_bytes"])
        self.assertEqual(compatibility["observed_total_memory_difference_bytes"], 4_096)

    def test_total_memory_difference_above_one_page_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        rejected_total_memory = (
            int(FROZEN_BUDGET["baseline_environment"]["total_memory_bytes"])
            + 2 * EVALUATOR.MEMORY_PAGE_BYTES
        )
        for measurement in measurements:
            measurement["environment"]["total_memory_bytes"] = rejected_total_memory
        self.assert_rejected(budget, measurements)

    def test_unaligned_total_memory_equivalence_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        rejected_total_memory = int(
            FROZEN_BUDGET["baseline_environment"]["total_memory_bytes"]
        ) - 1
        for measurement in measurements:
            measurement["environment"]["total_memory_bytes"] = rejected_total_memory
        self.assert_rejected(budget, measurements)

    def test_non_wsl_environment_cannot_use_memory_equivalence(self) -> None:
        budget, measurements = self.make_case()
        accepted_total_memory = (
            int(FROZEN_BUDGET["baseline_environment"]["total_memory_bytes"])
            - EVALUATOR.MEMORY_PAGE_BYTES
        )
        for measurement in measurements:
            measurement["environment"]["total_memory_bytes"] = accepted_total_memory
            measurement["environment"]["kernel"] = "6.18.33.2-native-linux"
            measurement["environment"]["platform"] = "Linux-6.18.33.2-native-linux-x86_64"
        self.assert_rejected(budget, measurements)

    def test_non_wsl_policy_branch_is_rejected(self) -> None:
        baseline_environment = deepcopy(FROZEN_BUDGET["baseline_environment"])
        acceptance_environment = deepcopy(baseline_environment)
        for environment in (baseline_environment, acceptance_environment):
            environment["kernel"] = "6.18.33.2-native-linux"
            environment["platform"] = "Linux-6.18.33.2-native-linux-x86_64"
        acceptance_environment["total_memory_bytes"] -= EVALUATOR.MEMORY_PAGE_BYTES
        with self.assertRaises(EVALUATOR.AcceptanceError):
            EVALUATOR._environment_compatibility(baseline_environment, acceptance_environment)

    def test_other_stable_field_cannot_use_memory_equivalence(self) -> None:
        budget, measurements = self.make_case()
        accepted_total_memory = (
            int(FROZEN_BUDGET["baseline_environment"]["total_memory_bytes"])
            - EVALUATOR.MEMORY_PAGE_BYTES
        )
        for measurement in measurements:
            measurement["environment"]["total_memory_bytes"] = accepted_total_memory
            measurement["environment"]["cpu_model"] = "Other CPU"
        self.assert_rejected(budget, measurements)

    def test_wrong_warmup_count_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["results"][0]["warmup_runs"] = 2
        self.assert_rejected(budget, measurements)

    def test_wrong_sample_count_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["results"][0]["samples"] = 4
        self.assert_rejected(budget, measurements)

    def test_wrong_duration_sample_count_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["results"][0]["durations_ns"] = [100_000]
        measurements[0]["results"][0]["samples"] = 1
        self.assert_rejected(budget, measurements)

    def test_invalid_median_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["results"][0]["median_ns"] += 1
        self.assert_rejected(budget, measurements)

    def test_invalid_growth_calculation_is_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[0]["results"][1]["growth_ratio_basis_points"] += 1
        self.assert_rejected(budget, measurements)

    def test_inconsistent_capture_bytes_are_rejected(self) -> None:
        budget, measurements = self.make_case()
        measurements[2]["results"][0]["capture_bytes"] += 1
        self.assert_rejected(budget, measurements)

    def test_capture_bytes_must_match_frozen_baseline(self) -> None:
        budget, measurements = self.make_case()
        for measurement in measurements:
            measurement["results"][0]["capture_bytes"] += 1
        self.assert_rejected(budget, measurements)

    def test_frozen_budget_status_is_rejected_when_changed(self) -> None:
        budget, measurements = self.make_case()
        budget["acceptance_status"] = "passed"
        self.assert_budget_rejected(budget)

    def test_acceptance_spread_above_limit_is_a_deterministic_failure(self) -> None:
        budget, measurements = self.make_case()
        set_median(measurements[2]["results"][0], 200_005)
        recalculate_growth(measurements[2]["results"])
        process = self.run_cli(budget, measurements)
        self.assertNotEqual(process.returncode, 0)
        result = json.loads(process.stdout)
        self.assertEqual(result["acceptance_status"], "unstable")
        self.assertFalse(result["overall_pass"])
        self.assertGreater(result["scenarios"][0]["acceptance_spread_basis_points"], 1_500)

    def test_absolute_median_budget_failure_is_a_deterministic_failure(self) -> None:
        budget, measurements = self.make_case()
        for measurement in measurements:
            set_median(measurement["results"][0], 2_000_000)
            recalculate_growth(measurement["results"])
        process = self.run_cli(budget, measurements)
        self.assertNotEqual(process.returncode, 0)
        result = json.loads(process.stdout)
        self.assertEqual(result["acceptance_status"], "failed")
        self.assertFalse(result["overall_pass"])
        self.assertFalse(result["scenarios"][0]["median_pass"])

    def test_growth_budget_failure_is_a_deterministic_failure(self) -> None:
        budget, measurements = self.make_case()
        for measurement in measurements:
            set_median(measurement["results"][0], 80_000)
            set_median(measurement["results"][1], 160_000)
            set_median(measurement["results"][2], 161_000)
            recalculate_growth(measurement["results"])
        process = self.run_cli(budget, measurements)
        self.assertNotEqual(process.returncode, 0)
        result = json.loads(process.stdout)
        self.assertEqual(result["acceptance_status"], "failed")
        self.assertFalse(result["overall_pass"])
        self.assertEqual(result["median_budgets_passed"], 24)
        self.assertLess(result["growth_budgets_passed"], 13)

    def test_smallest_group_preserves_null_growth(self) -> None:
        budget, measurements = self.make_case()
        with mock.patch.object(EVALUATOR, "_verify_live_git"):
            result = EVALUATOR.evaluate_acceptance(
                deepcopy(budget),
                deepcopy(measurements),
                ["3" * 64, "4" * 64, "5" * 64],
                FROZEN_BUDGET_SHA256,
            )
        smallest = result["scenarios"][0]
        self.assertIsNone(smallest["acceptance_reference_growth_basis_points"])
        self.assertIsNone(smallest["frozen_growth_budget_basis_points"])
        self.assertIsNone(smallest["growth_pass"])
        self.assertTrue(smallest["scenario_pass"])

    def test_deterministic_result_json(self) -> None:
        budget, measurements = self.make_case()
        first = self.run_cli(budget, measurements)
        second = self.run_cli(budget, measurements)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)


if __name__ == "__main__":
    unittest.main()
