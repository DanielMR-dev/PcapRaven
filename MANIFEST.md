# Repository Manifest

## Purpose and Phase Status

This is a human-readable inventory and governance document, not a Cargo
manifest. Phase 0 product and governance work is complete. Phase 1 is complete
with the virtual workspace, seven compile-only crate skeletons, pinned
toolchain, architecture checker, and baseline CI. Phase 2, safe capture reading,
is next; no capture or analysis capability is available yet.

## Tracked Current Inventory

| Path | Purpose |
| --- | --- |
| `README.md` | Project overview, current status, and documentation links. |
| `LICENSE` | Standard MIT license terms for PcapRaven. |
| `SECURITY.md` | Private vulnerability disclosure process. |
| `CONTRIBUTING.md` | Phase-aware contributor policy and quality guidance. |
| `AGENTS.md` | Authoritative AI-agent engineering and review workflow. |
| `MANIFEST.md` | Repository structure, current inventory, and phase status. |
| `.gitignore` | Rust build, editor, operating-system, and local-environment ignores. |
| `Cargo.toml` | Virtual Edition 2024 workspace, package metadata, lints, and internal path dependencies. |
| `Cargo.lock` | Cargo-generated lockfile for the dependency-free project workspace. |
| `rust-toolchain.toml` | Exact pinned stable development toolchain and components. |
| `scripts/check_workspace_architecture.py` | Dependency-free Cargo-metadata package and dependency-graph checker. |
| `.github/workflows/ci.yml` | Pull-request and `main` push quality, MSRV, and cross-platform skeleton CI. |
| `docs/PRODUCT.md` | Product identity, scope, goals, non-goals, and target CLI behavior. |
| `docs/ARCHITECTURE.md` | Workspace, crate boundaries, dependency direction, errors, logging, and unsafe Rust. |
| `docs/DOMAIN_MODEL.md` | Target packet, flow, observation, evidence, finding, and result concepts. |
| `docs/DETECTION_MODEL.md` | Target detector/finding contract, severity, confidence, and mappings. |
| `docs/SECURITY_MODEL.md` | Technical threat model and mandatory hostile-input controls. |
| `docs/TESTING.md` | Phase 1 gates and future unit, fixture, property, fuzz, and integration strategy. |
| `docs/ROADMAP.md` | Ordered Phase 0 through Phase 19 path to v1.0.0. |
| `.opencode/agents/orchestrator.md` | Primary agent that delegates implementation and review. |
| `.opencode/agents/developer.md` | Phase-scoped implementation subagent. |
| `.opencode/agents/reviewer.md` | Strictly read-only review subagent. |
| `.agents/skills/phase-validation/SKILL.md` | Reusable phase-scope and completion procedure. |
| `.agents/skills/rust-quality/SKILL.md` | Reusable Rust and Cargo quality procedure. |
| `.agents/skills/secure-parser-review/SKILL.md` | Reusable hostile-input parser review procedure. |
| `crates/pcapraven-domain/Cargo.toml` | Domain library package manifest. |
| `crates/pcapraven-domain/src/lib.rs` | Domain library Phase 1 documentation skeleton. |
| `crates/pcapraven-pcap/Cargo.toml` | Capture-ingestion library package manifest. |
| `crates/pcapraven-pcap/src/lib.rs` | Capture-ingestion Phase 1 documentation skeleton. |
| `crates/pcapraven-protocols/Cargo.toml` | Protocol-normalization library package manifest. |
| `crates/pcapraven-protocols/src/lib.rs` | Protocol-normalization Phase 1 documentation skeleton. |
| `crates/pcapraven-flows/Cargo.toml` | Flow-analysis library package manifest. |
| `crates/pcapraven-flows/src/lib.rs` | Flow-analysis Phase 1 documentation skeleton. |
| `crates/pcapraven-detection/Cargo.toml` | Detection library package manifest. |
| `crates/pcapraven-detection/src/lib.rs` | Detection Phase 1 documentation skeleton. |
| `crates/pcapraven-reporting/Cargo.toml` | Reporting library package manifest. |
| `crates/pcapraven-reporting/src/lib.rs` | Reporting Phase 1 documentation skeleton. |
| `crates/pcapraven-cli/Cargo.toml` | Binary package manifest for the `pcapraven` executable. |
| `crates/pcapraven-cli/src/main.rs` | Compile-only CLI binary skeleton with no arguments or output. |

The former duplicate skill copies are intentionally absent. Future
capture fixtures, fuzz targets, parser implementations, analysis behavior,
reporters, and functional CLI commands are not current inventory and may be
added only by their owning roadmap phases.

## Inventory Rules

Every current project path added to the workspace, tooling, CI, or agent
governance must be recorded here in the same contribution. Generated build
output under `/target/` is ignored and is not an inventory artifact. Future
paths mentioned in canonical documents are plans, not claims that those paths
exist.
