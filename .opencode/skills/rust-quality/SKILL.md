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

When the workspace exists and the current phase permits it, run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

Run narrower relevant tests first when useful, but do not substitute them for
required gates. Inspect the final diff and report every command that could not
run. Never claim these gates passed in Phase 0 because no workspace exists.
