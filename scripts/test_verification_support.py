#!/usr/bin/env python3
"""Focused self-tests for bounded repository verification support."""

from __future__ import annotations

import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

sys.dont_write_bytecode = True

from verification_support import (
    BoundedDiagnostics,
    FileSizeLimitExceeded,
    discover_files,
    read_file_bounded,
)
import generate_fixtures
import check_goldens
import stage_goldens
import verification_support


class BoundedDiagnosticsTests(unittest.TestCase):
    def test_retains_finite_sample_and_reports_omitted_count(self) -> None:
        diagnostics = BoundedDiagnostics(2)
        diagnostics.extend(["first", "second", "third", "fourth"])

        self.assertEqual(diagnostics.total, 4)
        self.assertEqual(
            diagnostics.rendered(),
            (
                "error: first",
                "error: second",
                "error: 2 additional verification mismatch(es) omitted",
            ),
        )


class DiscoveryTests(unittest.TestCase):
    def test_huge_entry_set_stops_at_streaming_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(1024):
                (root / f"entry-{index:04}.txt").write_bytes(b"")
            diagnostics = BoundedDiagnostics(4)

            result = discover_files(
                root,
                Path(),
                lambda _path: False,
                diagnostics,
                maximum_entries=32,
                maximum_files=8,
                maximum_depth=1,
                label="large test tree",
            )

            self.assertFalse(result.complete)
            self.assertEqual(result.paths, frozenset())
            self.assertTrue(any("exceeded 32" in line for line in diagnostics.rendered()))

    def test_metadata_failures_consume_entry_budget_before_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stat_calls = 0

            class FailingEntry:
                def __init__(self, ordinal: int) -> None:
                    self.path = str(root / f"entry-{ordinal}")

                def stat(self, *, follow_symlinks: bool = True) -> object:
                    nonlocal stat_calls
                    self.assert_no_follow(follow_symlinks)
                    stat_calls += 1
                    raise OSError("synthetic metadata failure")

                @staticmethod
                def assert_no_follow(follow_symlinks: bool) -> None:
                    if follow_symlinks:
                        raise AssertionError("metadata lookup followed a symlink")

            class StreamingEntries:
                def __enter__(self) -> object:
                    return iter(FailingEntry(index) for index in range(1000))

                def __exit__(self, *_args: object) -> None:
                    return None

            diagnostics = BoundedDiagnostics(8)
            with mock.patch.object(verification_support.os, "scandir", return_value=StreamingEntries()):
                result = discover_files(
                    root,
                    Path(),
                    lambda _path: True,
                    diagnostics,
                    maximum_entries=3,
                    maximum_files=8,
                    maximum_depth=1,
                    label="metadata failure tree",
                )

            self.assertFalse(result.complete)
            self.assertEqual(stat_calls, 3)
            self.assertGreaterEqual(diagnostics.total, 4)

    def test_matching_file_cap_fails_without_retaining_every_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(4):
                (root / f"{index}.pcap").write_bytes(b"")
            diagnostics = BoundedDiagnostics(8)

            result = discover_files(
                root,
                Path(),
                lambda path: path.suffix == ".pcap",
                diagnostics,
                maximum_entries=16,
                maximum_files=2,
                maximum_depth=2,
                label="test fixtures",
            )

            self.assertFalse(result.complete)
            self.assertLessEqual(len(result.paths), 2)
            self.assertTrue(diagnostics.has_errors)
            self.assertTrue(
                any("additional files omitted" in line for line in diagnostics.rendered())
            )

    def test_entry_cap_fails_before_unbounded_tree_walk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(5):
                (root / f"entry-{index}.txt").write_text("test", encoding="utf-8")
            diagnostics = BoundedDiagnostics(8)

            result = discover_files(
                root,
                Path(),
                lambda _path: True,
                diagnostics,
                maximum_entries=3,
                maximum_files=8,
                maximum_depth=2,
                label="test reports",
            )

            self.assertFalse(result.complete)
            self.assertTrue(diagnostics.has_errors)
            self.assertTrue(
                any("additional entries omitted" in line for line in diagnostics.rendered())
            )

    def test_depth_cap_rejects_deep_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one/two/three").mkdir(parents=True)
            (root / "one/two/three/deep.pcap").write_bytes(b"pcap")
            diagnostics = BoundedDiagnostics(8)

            result = discover_files(
                root,
                Path(),
                lambda path: path.suffix == ".pcap",
                diagnostics,
                maximum_entries=16,
                maximum_files=8,
                maximum_depth=2,
                label="test fixtures",
            )

            self.assertFalse(result.complete)
            self.assertEqual(result.paths, frozenset())
            self.assertTrue(any("maximum depth 2" in line for line in diagnostics.rendered()))

    def test_symlink_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = parent / "target"
            target.mkdir()
            root = parent / "root"
            try:
                root.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            diagnostics = BoundedDiagnostics(8)

            result = discover_files(
                parent,
                Path("root"),
                lambda _path: True,
                diagnostics,
                maximum_entries=16,
                maximum_files=8,
                maximum_depth=2,
                label="test fixtures",
            )

            self.assertFalse(result.complete)
            self.assertTrue(any("must not be a symlink" in line for line in diagnostics.rendered()))

    def test_regular_file_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "not-a-directory"
            root.write_bytes(b"file")
            diagnostics = BoundedDiagnostics(4)

            result = discover_files(
                root.parent,
                Path(root.name),
                lambda _path: True,
                diagnostics,
                maximum_entries=4,
                maximum_files=4,
                maximum_depth=1,
                label="file root",
            )

            self.assertFalse(result.complete)
            self.assertTrue(any("not a directory" in line for line in diagnostics.rendered()))

    def test_every_file_and_directory_symlink_is_rejected_before_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_directory = root / "real-directory"
            target_directory.mkdir()
            matching_target = root / "matching-target.pcap"
            matching_target.write_bytes(b"pcap")
            nonmatching_target = root / "nonmatching-target.txt"
            nonmatching_target.write_bytes(b"text")
            links = (
                (root / "matching-link.pcap", matching_target, False),
                (root / "nonmatching-link.txt", nonmatching_target, False),
                (root / "matching-directory.pcap", target_directory, True),
                (root / "nonmatching-directory.txt", target_directory, True),
            )
            try:
                for link, target, is_directory in links:
                    link.symlink_to(target, target_is_directory=is_directory)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            diagnostics = BoundedDiagnostics(16)

            result = discover_files(
                root,
                Path(),
                lambda path: path.suffix == ".pcap",
                diagnostics,
                maximum_entries=32,
                maximum_files=8,
                maximum_depth=2,
                label="test fixtures",
            )

            self.assertFalse(result.complete)
            rendered = "\n".join(diagnostics.rendered())
            for link, _, _ in links:
                self.assertIn(link.name, rendered)

    def test_bounded_read_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(b"bounded")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

            with self.assertRaises(OSError):
                read_file_bounded(root, Path("link"), 16)

    def test_bounded_read_rejects_symlinked_ancestor_before_opening_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trusted_root = Path(temporary) / "trusted"
            trusted_root.mkdir()
            external = Path(temporary) / "external"
            external.mkdir()
            (external / "target").write_bytes(b"must-not-be-consumed")
            try:
                (trusted_root / "linked").symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

            with mock.patch.object(
                verification_support.os,
                "fdopen",
                wraps=verification_support.os.fdopen,
            ) as fdopen:
                with self.assertRaises(OSError):
                    read_file_bounded(trusted_root, Path("linked/target"), 64)

            fdopen.assert_not_called()

    def test_discovery_rejects_symlinked_ancestor_before_scanning_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trusted_root = Path(temporary) / "trusted"
            trusted_root.mkdir()
            external = Path(temporary) / "external"
            external.mkdir()
            (external / "target.pcap").write_bytes(b"must-not-be-discovered")
            try:
                (trusted_root / "linked").symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            diagnostics = BoundedDiagnostics(8)

            with mock.patch.object(
                verification_support.os,
                "scandir",
                wraps=verification_support.os.scandir,
            ) as scandir:
                result = discover_files(
                    trusted_root,
                    Path("linked"),
                    lambda path: path.suffix == ".pcap",
                    diagnostics,
                    maximum_entries=8,
                    maximum_files=8,
                    maximum_depth=2,
                    label="test fixtures",
                )

            self.assertFalse(result.complete)
            scandir.assert_not_called()

    def test_bounded_read_rejects_oversized_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized"
            path.write_bytes(b"12345")

            with self.assertRaises(FileSizeLimitExceeded):
                read_file_bounded(path.parent, Path(path.name), 4)

    def test_bounded_read_detects_replacement_during_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "canonical"
            replacement = root / "replacement"
            path.write_bytes(b"original")
            replacement.write_bytes(b"different")
            real_open = verification_support.os.open

            replaced = False

            def replacing_open(open_path: object, flags: int) -> int:
                nonlocal replaced
                if not replaced:
                    replacement.replace(path)
                    replaced = True
                return real_open(open_path, flags)

            with (
                mock.patch.object(
                    verification_support,
                    "_can_use_anchored_unix_open",
                    return_value=False,
                ),
                mock.patch.object(
                    verification_support.os, "open", side_effect=replacing_open
                ),
            ):
                with self.assertRaisesRegex(OSError, "changed while being opened"):
                    read_file_bounded(root, Path("canonical"), 32)

    def test_diagnostic_cap_counts_all_mismatches(self) -> None:
        diagnostics = BoundedDiagnostics(1)
        for index in range(100):
            diagnostics.add(f"mismatch {index}")
        self.assertEqual(diagnostics.total, 100)
        self.assertEqual(len(diagnostics.rendered()), 2)
        self.assertIn("99 additional", diagnostics.rendered()[1])


class FixtureCheckerTests(unittest.TestCase):
    def test_discovery_cap_fails_before_any_expected_fixture_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixtures_root = root / "fixtures"
            (fixtures_root / "benign").mkdir(parents=True)
            expected = {
                "benign/expected.pcap": (
                    b"expected",
                    "Expected test fixture.",
                    "Exact bytes are verified.",
                    "pcap",
                )
            }
            (fixtures_root / "benign/expected.pcap").write_bytes(b"changed")
            manifest, checksums = generate_fixtures.expected_metadata(expected)
            manifest_path = fixtures_root / "manifest.json"
            checksums_path = fixtures_root / "checksums.sha256"
            manifest_path.write_bytes(manifest)
            checksums_path.write_bytes(checksums)

            original = (
                generate_fixtures.ROOT,
                generate_fixtures.FIXTURES_RELATIVE_ROOT,
                generate_fixtures.FIXTURES_DIR,
                generate_fixtures.MANIFEST_PATH,
                generate_fixtures.CHECKSUMS_PATH,
                generate_fixtures.MAX_DISCOVERY_ENTRIES,
            )
            try:
                generate_fixtures.ROOT = root
                generate_fixtures.FIXTURES_RELATIVE_ROOT = Path("fixtures")
                generate_fixtures.FIXTURES_DIR = fixtures_root
                generate_fixtures.MANIFEST_PATH = manifest_path
                generate_fixtures.CHECKSUMS_PATH = checksums_path
                generate_fixtures.MAX_DISCOVERY_ENTRIES = 2
                stderr = StringIO()
                with (
                    redirect_stdout(StringIO()),
                    redirect_stderr(stderr),
                    mock.patch.object(
                        generate_fixtures, "read_file_bounded"
                    ) as bounded_read,
                ):
                    result = generate_fixtures.check(expected)
                bounded_read.assert_not_called()
            finally:
                (
                    generate_fixtures.ROOT,
                    generate_fixtures.FIXTURES_RELATIVE_ROOT,
                    generate_fixtures.FIXTURES_DIR,
                    generate_fixtures.MANIFEST_PATH,
                    generate_fixtures.CHECKSUMS_PATH,
                    generate_fixtures.MAX_DISCOVERY_ENTRIES,
                ) = original

            self.assertEqual(result, 1)
            diagnostics = stderr.getvalue()
            self.assertIn("discovery exceeded", diagnostics)


class GoldenCheckerTests(unittest.TestCase):
    def test_structural_failure_prevents_golden_reads_and_cli_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / "tests/fixtures/pcaps"
            fixture_root.mkdir(parents=True)
            capture = fixture_root / "input.pcap"
            capture.write_bytes(b"pcap")
            golden_root = root / "tests/golden"
            golden_root.mkdir(parents=True)
            external = root / "external"
            external.mkdir()
            (external / "expected.json").write_bytes(b"external")
            try:
                (golden_root / "linked").symlink_to(
                    external, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            scenario = SimpleNamespace(
                name="unsafe-golden",
                args=("validate", str(capture)),
                expected_exit=0,
                stdout_path="linked/expected.json",
                stderr_path=None,
            )

            with (
                mock.patch.object(check_goldens, "ROOT", root),
                mock.patch.object(check_goldens, "FIXTURE_DIR", fixture_root),
                mock.patch.object(check_goldens, "scenarios", return_value=(scenario,)),
                mock.patch.object(check_goldens, "read_file_bounded") as bounded_read,
                mock.patch.object(check_goldens, "locate_binary") as locate_binary,
                mock.patch.object(sys, "argv", ["check_goldens.py"]),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                result = check_goldens.main()

            self.assertEqual(result, 1)
            bounded_read.assert_not_called()
            locate_binary.assert_not_called()

    def test_staging_preflight_rejects_fixture_ancestor_before_output_or_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / "tests/fixtures/pcaps"
            fixture_root.mkdir(parents=True)
            external = root / "external"
            external.mkdir()
            capture = external / "input.pcap"
            capture.write_bytes(b"must-not-be-consumed")
            try:
                (fixture_root / "linked").symlink_to(
                    external, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            scenario = SimpleNamespace(
                name="unsafe-fixture",
                args=("validate", str(fixture_root / "linked/input.pcap")),
                expected_exit=0,
                stdout_path="validate/input.json",
                stderr_path=None,
            )
            output = root / "staged"

            with (
                mock.patch.object(check_goldens, "ROOT", root),
                mock.patch.object(check_goldens, "FIXTURE_DIR", fixture_root),
                mock.patch.object(stage_goldens, "ROOT", root),
                mock.patch.object(stage_goldens, "scenarios", return_value=(scenario,)),
                mock.patch.object(stage_goldens, "locate_binary") as locate_binary,
                mock.patch.object(
                    sys,
                    "argv",
                    ["stage_goldens.py", "--output", str(output)],
                ),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                result = stage_goldens.main()

            self.assertEqual(result, 1)
            self.assertFalse(output.exists())
            locate_binary.assert_not_called()


if __name__ == "__main__":
    unittest.main()
