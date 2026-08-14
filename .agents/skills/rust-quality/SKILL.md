---
name: rust-quality
description: Use for Rust source, Cargo workspace, dependency, lint, test, documentation, or unsafe-code changes in PcapRaven; do not run it as a Rust gate during documentation-only Phase 0.
---

# Rust Quality

## Preconditions

1. Read `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`,
   `docs/TESTING.md`, and the current `docs/ROADMAP.md` phase.
2. Confirm the current phase permits Rust or Cargo changes. Phase 0 does not.
3. Inspect existing workspace policy and preserve unrelated changes.

## Role-aware use

### Developer

The Developer runs every applicable required gate and owns its execution
evidence: record each exact command, result, unavailable tool, and failure. The
Developer must keep the dependency graph, unsafe-code policy, and phase boundary
from `AGENTS.md`, inspect the complete diff, and report all limitations to the
Orchestrator.

### Reviewer

The Reviewer remains source-read-only and cannot modify project files. The
Reviewer inspects the Developer's evidence, workspace policy, dependency graph,
unsafe-code posture, and changed files, and may independently rerun explicitly
permitted non-mutating gates to compare their results with that evidence. Any
discrepancy or finding is reported to the Orchestrator with an exact path and
reference; Reviewer execution does not replace Developer gate evidence.

## Review and Implementation Checklist

- Use Rust Edition 2024 and the accepted workspace dependency direction.
- Keep CLI behavior out of libraries and external-byte parsing out of domain,
  detection, and reporting.
- Use safe Rust. If unsafe code is proposed, stop unless the documented
  exception, invariants, focused tests, and security review are in scope.
- Prevent attacker data from reaching `unwrap`, `expect`, `panic`, unchecked
  indexing, or unchecked arithmetic.
- Use checked conversions and arithmetic, explicit limits, deterministic
  ordering, bounded errors/logs/output, and structured error categories.
- Avoid speculative dependencies, features, abstractions, and compatibility.
- Before adding a dependency, validate exact version, enabled/default features,
  MSRV requirements, license compatibility, maintenance posture, transitive
  footprint, unsafe use, and network/telemetry behavior.
- Add tests for success, boundaries, malformed/error paths, determinism, and
  phase-appropriate properties or regressions.

## Verification

When the workspace exists and the current phase permits it, the Developer runs:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo metadata --format-version 1 --no-deps --locked
python3 scripts/check_workspace_architecture.py
```

Run narrower relevant tests first when useful, but do not substitute them for
required gates. Inspect the final diff and report every command that could not
run. During the historical Phase 0 documentation-only gate, these Rust checks
could not be claimed; they are applicable to the current Phase 3 workspace,
reader, and protocol normalization changes.
