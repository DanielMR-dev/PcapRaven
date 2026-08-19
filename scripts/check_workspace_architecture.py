#!/usr/bin/env python3
"""Check the Phase 12 Cargo package roles and audited dependency topology."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path


EXPECTED = {
    "pcapraven-domain": {"role": "lib", "dependencies": set()},
    "pcapraven-pcap": {
        "role": "lib",
        "dependencies": {"pcapraven-domain"},
    },
    "pcapraven-protocols": {
        "role": "lib",
        "dependencies": {"pcapraven-domain"},
    },
    "pcapraven-flows": {
        "role": "lib",
        "dependencies": {"pcapraven-domain"},
    },
    "pcapraven-detection": {
        "role": "lib",
        "dependencies": {"pcapraven-domain"},
    },
    "pcapraven-reporting": {
        "role": "lib",
        "dependencies": {"pcapraven-domain"},
    },
    "pcapraven-cli": {
        "role": "bin",
        "dependencies": {
            "pcapraven-domain",
            "pcapraven-pcap",
            "pcapraven-protocols",
            "pcapraven-flows",
            "pcapraven-detection",
            "pcapraven-reporting",
        },
    },
}

EXPECTED_NAMES = set(EXPECTED)
EXPECTED_TEST_TARGETS = {
    "pcapraven-domain": {"observation_evidence", "finding"},
    "pcapraven-pcap": {"reader"},
    "pcapraven-protocols": {"normalization", "dns", "http", "tls"},
    "pcapraven-flows": {"reconstruction", "statistics"},
    "pcapraven-detection": {
        "engine",
        "periodic_beaconing",
        "dns_anomaly",
        "connection_behavior",
        "correlation",
        "filtering",
    },
    "pcapraven-cli": {"cli"},
}
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
EXPECTED_EXTERNAL = {
    "pcapraven-pcap": {
        "pcap-parser": {
            "req": "=0.17.0",
            "kind": None,
            "features": [],
            "uses_default_features": False,
        },
        "proptest": {
            "req": "=1.11.0",
            "kind": "dev",
            "features": ["std"],
            "uses_default_features": False,
        },
    },
    "pcapraven-protocols": {
        "etherparse": {
            "req": "=0.21.0",
            "kind": None,
            "features": [],
            "uses_default_features": False,
        },
        "proptest": {
            "req": "=1.11.0",
            "kind": "dev",
            "features": ["std"],
            "uses_default_features": False,
        },
    },
    "pcapraven-flows": {
        "proptest": {
            "req": "=1.11.0",
            "kind": "dev",
            "features": ["std"],
            "uses_default_features": False,
        },
    },
    "pcapraven-cli": {
        "clap": {
            "req": "=4.6.4",
            "kind": None,
            "features": ["std", "help", "usage", "error-context"],
            "uses_default_features": False,
        },
    },
}


def has_exact_string(value: object, expected: str) -> bool:
    return type(value) is str and value == expected


def is_unpublished(value: object) -> bool:
    return (type(value) is bool and value is False) or (
        type(value) is list and len(value) == 0
    )


def report_failure(message: str) -> int:
    print(f"workspace architecture check failed: {message}", file=sys.stderr)
    return 1


def canonical_path(repository_root: Path, raw_path: object) -> Path | None:
    if type(raw_path) is not str or not raw_path:
        return None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repository_root / candidate
    try:
        return candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def dependency_manifest_path(
    repository_root: Path, raw_path: object
) -> Path | None:
    if type(raw_path) is not str or not raw_path:
        return None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repository_root / candidate
    if candidate.name != "Cargo.toml":
        candidate = candidate / "Cargo.toml"
    try:
        return candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def validate_root_manifest(repository_root: Path) -> str | None:
    try:
        with (repository_root / "Cargo.toml").open("rb") as manifest_file:
            manifest = tomllib.load(manifest_file)
    except (OSError, tomllib.TOMLDecodeError):
        return "workspace manifest could not be parsed"

    if type(manifest) is not dict:
        return "workspace manifest has an unexpected shape"
    workspace = manifest.get("workspace")
    if type(workspace) is not dict:
        return "workspace manifest has no workspace table"
    if not has_exact_string(workspace.get("resolver"), "3"):
        return "workspace resolver is not 3"
    return None


def main() -> int:
    repository_root = Path(__file__).resolve().parent.parent
    manifest_error = validate_root_manifest(repository_root)
    if manifest_error is not None:
        return report_failure(manifest_error)

    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--locked",
        "--offline",
    ]

    try:
        result = subprocess.run(
            command,
            cwd=repository_root,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError:
        return report_failure("cargo metadata could not be executed")

    if result.returncode != 0:
        return report_failure("cargo metadata failed")

    try:
        metadata = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return report_failure("cargo metadata returned invalid JSON")

    if type(metadata) is not dict:
        return report_failure("cargo metadata returned an unexpected JSON value")
    if type(metadata.get("version")) is not int or metadata["version"] != 1:
        return report_failure("cargo metadata returned an unsupported format")

    packages = metadata.get("packages")
    if type(packages) is not list:
        return report_failure("metadata has no package list")

    packages_by_name = {}
    packages_by_id = {}
    packages_by_manifest = {}
    for package in packages:
        if type(package) is not dict:
            return report_failure("metadata contains an invalid package")
        name = package.get("name")
        package_id = package.get("id")
        manifest_path = canonical_path(repository_root, package.get("manifest_path"))
        if (
            type(name) is not str
            or not name
            or type(package_id) is not str
            or not package_id
        ):
            return report_failure("metadata contains a package without an identity")
        if manifest_path is None:
            return report_failure(f"{name} has an invalid manifest path")
        if name in packages_by_name:
            return report_failure(f"duplicate package name: {name}")
        if package_id in packages_by_id:
            return report_failure("duplicate package identity")
        if manifest_path in packages_by_manifest:
            return report_failure("duplicate package manifest path")
        packages_by_name[name] = package
        packages_by_id[package_id] = package
        packages_by_manifest[manifest_path] = package

    actual_names = set(packages_by_name)
    if actual_names != EXPECTED_NAMES:
        unexpected = ", ".join(sorted(actual_names - EXPECTED_NAMES)) or "none"
        missing = ", ".join(sorted(EXPECTED_NAMES - actual_names)) or "none"
        return report_failure(
            f"package set mismatch (unexpected: {unexpected}; missing: {missing})"
        )

    workspace_root = canonical_path(repository_root, metadata.get("workspace_root"))
    if workspace_root != repository_root.resolve():
        return report_failure("workspace root is not the repository root")
    if "root_package" in metadata and metadata["root_package"] is not None:
        return report_failure("workspace has a root package")

    workspace_members = metadata.get("workspace_members")
    if type(workspace_members) is not list or any(
        type(member) is not str or not member for member in workspace_members
    ):
        return report_failure("workspace member metadata has an invalid shape")
    if len(workspace_members) != len(set(workspace_members)):
        return report_failure("workspace member metadata contains duplicates")
    if set(workspace_members) != set(packages_by_id):
        return report_failure("workspace member set does not match package set")

    for name in sorted(EXPECTED):
        package = packages_by_name[name]
        expected = EXPECTED[name]
        package_manifest = canonical_path(
            repository_root, package.get("manifest_path")
        )
        expected_manifest = (
            repository_root / "crates" / name / "Cargo.toml"
        ).resolve()

        if package_manifest != expected_manifest:
            return report_failure(f"{name} is at an unexpected workspace path")
        if "source" not in package or package["source"] is not None:
            return report_failure(f"{name} is not a workspace path package")
        if not has_exact_string(package.get("version"), "0.0.0"):
            return report_failure(f"{name} does not use version 0.0.0")
        if not has_exact_string(package.get("license"), "MIT"):
            return report_failure(f"{name} does not use the MIT license")
        if not is_unpublished(package.get("publish")):
            return report_failure(f"{name} is publishable")
        if type(package.get("rust_version")) is not str or package[
            "rust_version"
        ] not in {"1.85", "1.85.0"}:
            return report_failure(f"{name} does not declare Rust 1.85")
        if not has_exact_string(package.get("edition"), "2024"):
            return report_failure(f"{name} does not use Edition 2024")
        if type(package.get("features")) is not dict or package["features"]:
            return report_failure(f"{name} declares unexpected features")

        targets = package.get("targets")
        if type(targets) is not list:
            return report_failure(f"{name} has no valid target list")
        primary_targets = []
        test_targets = set()
        for candidate in targets:
            if type(candidate) is not dict:
                return report_failure(f"{name} has an invalid target")
            candidate_kind = candidate.get("kind")
            if (
                type(candidate_kind) is not list
                or len(candidate_kind) != 1
                or type(candidate_kind[0]) is not str
            ):
                return report_failure(f"{name} has an invalid target kind")
            if candidate_kind[0] == expected["role"]:
                primary_targets.append(candidate)
            elif candidate_kind[0] == "test":
                test_name = candidate.get("name")
                if type(test_name) is not str or not test_name:
                    return report_failure(f"{name} has an invalid test target")
                if test_name in test_targets:
                    return report_failure(f"{name} has duplicate test targets")
                test_targets.add(test_name)
            else:
                return report_failure(f"{name} has an unexpected target kind")
        if len(primary_targets) != 1:
            return report_failure(f"{name} does not have exactly one primary target")
        if test_targets != EXPECTED_TEST_TARGETS.get(name, set()):
            return report_failure(f"{name} has an unexpected test-target set")
        target = primary_targets[0]
        if type(target) is not dict:
            return report_failure(f"{name} has an invalid target")
        target_kind = target.get("kind")
        if (
            type(target_kind) is not list
            or len(target_kind) != 1
            or not has_exact_string(target_kind[0], expected["role"])
        ):
            return report_failure(f"{name} has the wrong crate role")
        expected_target_name = (
            "pcapraven" if name == "pcapraven-cli" else name.replace("-", "_")
        )
        if not has_exact_string(target.get("name"), expected_target_name):
            return report_failure(f"{name} has an unexpected target name")

        dependencies = package.get("dependencies")
        if type(dependencies) is not list:
            return report_failure(f"{name} has no dependency list")
        dependency_names = set()
        for dependency in dependencies:
            if (
                type(dependency) is not dict
                or type(dependency.get("name")) is not str
                or not dependency["name"]
            ):
                return report_failure(f"{name} has an invalid dependency entry")
            dependency_name = dependency["name"]
            if dependency_name in dependency_names:
                return report_failure(f"{name} has a duplicate dependency edge")
            dependency_names.add(dependency_name)
            external = EXPECTED_EXTERNAL.get(name, {}).get(dependency_name)
            if dependency_name not in EXPECTED_NAMES and external is None:
                return report_failure(f"{name} has an unexpected external dependency")
            if dependency_name not in EXPECTED_NAMES:
                if dependency.get("source") != REGISTRY_SOURCE:
                    return report_failure(
                        f"{name} external dependency has an unexpected source"
                    )
                if not has_exact_string(dependency.get("req"), external["req"]):
                    return report_failure(
                        f"{name} external dependency has an unexpected version"
                    )
                if dependency.get("kind") != external["kind"]:
                    return report_failure(
                        f"{name} external dependency has an unexpected kind"
                    )
                if dependency.get("features") != external["features"]:
                    return report_failure(
                        f"{name} external dependency has unexpected features"
                    )
                if (
                    dependency.get("uses_default_features")
                    is not external["uses_default_features"]
                ):
                    return report_failure(
                        f"{name} external dependency has an unexpected default-feature policy"
                    )
                if (
                    dependency.get("optional") is not False
                    or dependency.get("target") is not None
                    or dependency.get("rename") is not None
                    or dependency.get("package") is not None
                ):
                    return report_failure(
                        f"{name} external dependency has unexpected declaration fields"
                    )
                continue
            if dependency_name not in expected["dependencies"]:
                return report_failure(f"{name} has an unexpected dependency edge")
            if "source" not in dependency or dependency["source"] is not None:
                return report_failure(f"{name} has a non-path dependency")

            target_package = packages_by_name[dependency_name]
            target_manifest = canonical_path(
                repository_root, target_package.get("manifest_path")
            )
            expected_target_manifest = (
                repository_root / "crates" / dependency_name / "Cargo.toml"
            ).resolve()
            if (
                target_manifest is None
                or target_manifest != expected_target_manifest
            ):
                return report_failure(
                    f"{name} dependency does not resolve to {dependency_name}"
                )
            if "path" in dependency:
                dependency_path = dependency["path"]
                if dependency_path is not None:
                    edge_manifest = dependency_manifest_path(
                        repository_root, dependency_path
                    )
                    if edge_manifest != expected_target_manifest:
                        return report_failure(
                            f"{name} dependency has an unexpected manifest path"
                        )
            resolved_package = packages_by_manifest.get(target_manifest)
            if (
                resolved_package is None
                or resolved_package.get("id") != target_package.get("id")
            ):
                return report_failure(
                    f"{name} dependency has an unexpected package identity"
                )
            declared_package = dependency.get("package")
            if declared_package is not None and (
                type(declared_package) is not str
                or declared_package
                not in {dependency_name, target_package.get("id")}
            ):
                return report_failure(
                    f"{name} dependency declares an unexpected package identity"
                )
            if "rename" not in dependency or dependency["rename"] is not None:
                return report_failure(f"{name} has a renamed dependency")
            if (
                type(dependency.get("optional")) is not bool
                or dependency["optional"] is not False
            ):
                return report_failure(f"{name} has an optional dependency")
            if type(dependency.get("features")) is not list or dependency["features"]:
                return report_failure(f"{name} enables dependency features")
            if (
                type(dependency.get("uses_default_features")) is not bool
                or dependency["uses_default_features"] is not True
            ):
                return report_failure(f"{name} disables or alters dependency defaults")
            if "kind" not in dependency or dependency["kind"] is not None:
                return report_failure(f"{name} has a non-normal dependency")
            if "target" not in dependency or dependency["target"] is not None:
                return report_failure(f"{name} has a target-specific dependency")

        expected_dependency_names = expected["dependencies"] | set(
            EXPECTED_EXTERNAL.get(name, {})
        )
        if dependency_names != expected_dependency_names:
            actual = ", ".join(sorted(dependency_names)) or "none"
            wanted = ", ".join(sorted(expected_dependency_names)) or "none"
            return report_failure(
                f"{name} dependency mismatch (actual: {actual}; expected: {wanted})"
            )

    expected_external_names = {
        dependency_name
        for dependencies in EXPECTED_EXTERNAL.values()
        for dependency_name in dependencies
    }
    print(
        "workspace architecture: OK (7 packages; audited external dependencies: "
        + ", ".join(sorted(expected_external_names))
        + ")"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
