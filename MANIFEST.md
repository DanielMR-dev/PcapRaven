# Repository Manifest

## Purpose

This is a human-readable repository inventory and governance document. It is
not a Cargo manifest and does not imply that a Rust workspace exists.

## Current Phase 0 Inventory

| Path | Purpose |
| --- | --- |
| `README.md` | Honest project overview and early-development status. |
| `LICENSE` | Apache License 2.0 terms. |
| `SECURITY.md` | Private vulnerability disclosure process. |
| `CONTRIBUTING.md` | Phase-aware contributor policy. |
| `AGENTS.md` | Authoritative AI-agent engineering and review workflow. |
| `MANIFEST.md` | Repository structure, current inventory, and future path status. |
| `docs/PRODUCT.md` | Product identity, scope, goals, non-goals, and target v1 CLI. |
| `docs/ARCHITECTURE.md` | Target workspace, crate boundaries, dependency direction, errors, and logging. |
| `docs/DOMAIN_MODEL.md` | Target packet, flow, protocol observation, evidence, finding, and result concepts. |
| `docs/DETECTION_MODEL.md` | Target detector/finding contract, severity, confidence, and mappings. |
| `docs/TESTING.md` | Future testing pyramid, property tests, fuzzing, fixtures, and CI gates. |
| `docs/SECURITY_MODEL.md` | Technical threat model and mandatory hostile-input controls. |
| `docs/ROADMAP.md` | Ordered Phase 0 through Phase 19 path to v1.0.0. |
| `.opencode/agents/orchestrator.md` | Primary agent that delegates implementation and review. |
| `.opencode/agents/developer.md` | Phase-scoped implementation subagent. |
| `.opencode/agents/reviewer.md` | Strictly read-only review subagent. |
| `.opencode/skills/rust-quality/SKILL.md` | Reusable future Rust quality procedure. |
| `.opencode/skills/secure-parser-review/SKILL.md` | Reusable hostile-input parser review procedure. |
| `.opencode/skills/phase-validation/SKILL.md` | Reusable phase scope and completion procedure. |

The `.git/` directory is repository metadata and is not a project artifact.

## Planned Paths That Must Not Yet Exist

The following paths are documented targets for later phases, not current
inventory:

```text
Cargo.toml
Cargo.lock
crates/
  pcapraven-domain/
  pcapraven-pcap/
  pcapraven-protocols/
  pcapraven-flows/
  pcapraven-detection/
  pcapraven-reporting/
  pcapraven-cli/
.github/workflows/
fixtures/pcaps/benign/
fixtures/pcaps/suspicious/
fixtures/pcaps/malformed/
fixtures/pcaps/edge-cases/
fixtures/expected/
```

`Cargo.toml`, source files, and baseline CI begin in Phase 1. Capture fixtures
are formally established in Phase 17, although minimal test inputs and fuzz
corpora may be introduced earlier when required by their owning implementation
phase and documented accordingly.

## Phase 0 Boundary

Phase 0 contains documentation and project-local agent configuration only. It
contains no parser, packet decoder, flow reconstruction, statistics engine,
protocol parser, detector, reporter, CLI behavior, Rust crate skeleton, CI
workflow, test fixture, or generated implementation artifact.

Any inventory change must update this document in the same contribution and
must be permitted by the current entry in [docs/ROADMAP.md](docs/ROADMAP.md).
