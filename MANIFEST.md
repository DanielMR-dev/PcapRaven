# Repository Manifest

## Purpose and Phase Status

This is a human-readable inventory and governance document, not a Cargo
manifest. Phase 0 product and governance work, Phase 1 workspace/tooling work,
Phase 2 safe PCAP/PCAPNG container reader work, Phase 3 packet normalization
work, Phase 4 bidirectional flow reconstruction work, and Phase 5 checked flow
statistics and exact temporal metrics are complete.
Phase 6 functional CLI and later analysis capabilities remain future work.

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
| `Cargo.lock` | Cargo-generated locked dependency graph for the seven-package main workspace. |
| `rust-toolchain.toml` | Exact pinned stable development toolchain and components. |
| `scripts/check_workspace_architecture.py` | Dependency-free Cargo-metadata package, internal-graph, and audited-dependency checker. |
| `.github/workflows/ci.yml` | Pull-request and `main` push quality, MSRV, cross-platform, and bounded fuzz-target build CI. |
| `docs/PRODUCT.md` | Product identity, scope, goals, non-goals, and target CLI behavior. |
| `docs/ARCHITECTURE.md` | Workspace, crate boundaries, dependency direction, errors, logging, and unsafe Rust. |
| `docs/DOMAIN_MODEL.md` | Target packet, flow, observation, evidence, finding, and result concepts. |
| `docs/DETECTION_MODEL.md` | Target detector/finding contract, severity, confidence, and mappings. |
| `docs/SECURITY_MODEL.md` | Technical threat model and mandatory hostile-input controls. |
| `docs/TESTING.md` | Reader, normalizer, and flow reconstructor tests, dependency audits, quality gates, fuzzing, and later test strategy. |
| `docs/ROADMAP.md` | Ordered Phase 0 through Phase 19 path to v1.0.0. |
| `.opencode/agents/orchestrator.md` | Primary agent that delegates implementation and review. |
| `.opencode/agents/developer.md` | Phase-scoped implementation subagent. |
| `.opencode/agents/reviewer.md` | Source-read-only review subagent with bounded non-mutating verification. |
| `.agents/skills/flow-reconstruction/SKILL.md` | Reusable bidirectional flow reconstruction procedure. |
| `.agents/skills/flow-statistics/SKILL.md` | Reusable flow statistics and temporal metrics review procedure. |
| `.agents/skills/phase-validation/SKILL.md` | Reusable phase-scope and completion procedure. |
| `.agents/skills/rust-quality/SKILL.md` | Reusable Rust and Cargo quality procedure. |
| `.agents/skills/secure-parser-review/SKILL.md` | Reusable hostile-input parser review procedure. |
| `crates/pcapraven-domain/Cargo.toml` | Domain library package manifest. |
| `crates/pcapraven-domain/src/lib.rs` | Domain library entry point and type exports. |
| `crates/pcapraven-domain/src/packet.rs` | Normalized packet model, metadata, diagnostics, addresses, flags, and completeness states. |
| `crates/pcapraven-domain/src/flow.rs` | Capture-independent flow endpoints, keys, references, directions, associations, end reasons, and records. |
| `crates/pcapraven-domain/src/flow_metrics.rs` | Domain models for directional traffic statistics, exact rational `FlowDuration`, and temporal metrics. |
| `crates/pcapraven-pcap/Cargo.toml` | Capture-ingestion manifest with the audited `pcap-parser` and dev-only `proptest` dependencies. |
| `crates/pcapraven-pcap/src/lib.rs` | Public bounded PCAP/PCAPNG reader contract and crate boundary. |
| `crates/pcapraven-pcap/src/reader.rs` | Safe streaming reader implementation, limits, metadata, diagnostics, error mapping, and normalization adapter. |
| `crates/pcapraven-pcap/tests/reader.rs` | Synthetic boundary, endian, recovery, limit, I/O, and property tests. |
| `crates/pcapraven-protocols/Cargo.toml` | Protocol-normalization manifest with audited `etherparse` and dev-only `proptest` dependencies. |
| `crates/pcapraven-protocols/src/lib.rs` | Protocol-normalization library entry point and public exports. |
| `crates/pcapraven-protocols/src/limits.rs` | Finite normalization resource limits and builder. |
| `crates/pcapraven-protocols/src/normalizer.rs` | Bounded Ethernet, IPv4, IPv6, TCP, and UDP packet normalization engine. |
| `crates/pcapraven-protocols/tests/normalization.rs` | Unit, boundary, property, and regression tests for packet normalization. |
| `crates/pcapraven-flows/Cargo.toml` | Flow-analysis library package manifest with dev-only `proptest`. |
| `crates/pcapraven-flows/src/lib.rs` | Flow-analysis library entry point and re-exports. |
| `crates/pcapraven-flows/src/config.rs` | Configurable finite flow reconstruction limits and builder. |
| `crates/pcapraven-flows/src/error.rs` | Structured flow reconstruction error types. |
| `crates/pcapraven-flows/src/metrics.rs` | Exact rational timestamp arithmetic, fixed-size traffic counters, and online inter-arrival accumulators. |
| `crates/pcapraven-flows/src/reconstructor.rs` | Stateful deterministic bidirectional flow reconstruction and metrics accumulation engine. |
| `crates/pcapraven-flows/tests/reconstruction.rs` | Unit, boundary, lifecycle, and property tests for flow reconstruction. |
| `crates/pcapraven-flows/tests/statistics.rs` | Unit, boundary, lifecycle, and property tests for flow statistics and exact temporal metrics. |
| `crates/pcapraven-detection/Cargo.toml` | Detection library package manifest. |
| `crates/pcapraven-detection/src/lib.rs` | Detection Phase 1 documentation skeleton. |
| `crates/pcapraven-reporting/Cargo.toml` | Reporting library package manifest. |
| `crates/pcapraven-reporting/src/lib.rs` | Reporting Phase 1 documentation skeleton. |
| `crates/pcapraven-cli/Cargo.toml` | Binary package manifest for the `pcapraven` executable. |
| `crates/pcapraven-cli/src/main.rs` | Compile-only CLI binary skeleton with no arguments or output. |
| `fuzz/Cargo.toml` | Excluded independent cargo-fuzz project manifest with separately audited fuzz-only dependency. |
| `fuzz/Cargo.lock` | Cargo-generated lockfile for the excluded fuzz project. |
| `fuzz/fuzz_targets/fuzz_pcap_reader.rs` | Stable-name libFuzzer target using only the public bounded reader API. |
| `fuzz/fuzz_targets/fuzz_packet_normalizer.rs` | Stable-name libFuzzer target for bounded protocol normalization. |
| `fuzz/fuzz_targets/fuzz_flow_reconstructor.rs` | Stable-name libFuzzer target for bounded bidirectional flow reconstruction and metric invariant validation. |

The former duplicate skill copies are intentionally absent. Future capture
fixtures, application protocol analysis, reporters, and functional CLI commands
are not current inventory and may be added only by their owning roadmap phases.
The excluded `fuzz/` project is current Phase 5 inventory but is not one of the
seven main workspace packages.

## Inventory Rules

Every current project path added to the workspace, tooling, CI, or agent
governance must be recorded here in the same contribution. Generated build
output under `/target/` is ignored and is not an inventory artifact. Future
paths mentioned in canonical documents are plans, not claims that those paths
exist.
