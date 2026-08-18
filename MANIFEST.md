# Repository Manifest

## Purpose and Phase Status

This is a human-readable inventory and governance document, not a Cargo
manifest. Phase 0 product and governance work, Phase 1 workspace/tooling work,
Phase 2 safe PCAP/PCAPNG container reader work, Phase 3 packet normalization
work, Phase 4 bidirectional flow reconstruction work, Phase 5 checked flow
statistics and exact temporal metrics, Phase 6 initial functional CLI
with streaming capture and flow inspection, Phase 7 bounded DNS protocol
analysis with normalized DNS observations and DNS CLI inspection,
Phase 8 bounded HTTP/1.x metadata analysis with normalized HTTP observations
and HTTP CLI inspection, Phase 9 bounded visible TLS 1.2 / TLS 1.3
handshake metadata analysis with normalized TLS observations and TLS CLI inspection,
Phase 10 unified protocol observations and structured evidence foundation,
Phase 11 detection engine architecture,
Phase 12 explainable periodic beaconing detection, and
Phase 13 explainable DNS anomaly and possible tunneling detection are complete.
Phase 14 (connection/C2-like behavioral heuristics) and later analysis capabilities remain future work.

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
| `docs/TESTING.md` | Reader, normalizer, flow reconstructor, DNS/HTTP/TLS, observations, evidence, detection engine, periodic beaconing, DNS anomaly/tunneling, and CLI integration tests, dependency audits, quality gates, fuzzing, and later test strategy. |
| `docs/ROADMAP.md` | Ordered Phase 0 through Phase 19 path to v1.0.0. |
| `docs/detectors/PERIODIC_BEACONING.md` | Specification and statistical contract for the periodic beaconing detector. |
| `docs/detectors/DNS_ANOMALY_TUNNELING.md` | Specification and analytical contract for DNS anomaly and possible tunneling detectors. |
| `.opencode/agents/orchestrator.md` | Primary agent that delegates implementation and review. |
| `.opencode/agents/developer.md` | Phase-scoped implementation subagent. |
| `.opencode/agents/reviewer.md` | Source-read-only review subagent with bounded non-mutating verification. |
| `.agents/skills/cli-contract/SKILL.md` | Reusable command-line interface, streaming orchestration, and exit status procedure. |
| `.agents/skills/detection-engine/SKILL.md` | Reusable detection engine architecture, detector registration, configuration, and evaluation procedure. |
| `.agents/skills/dns-detection/SKILL.md` | Reusable DNS anomaly and possible tunneling detection procedure. |
| `.agents/skills/dns-protocol-analysis/SKILL.md` | Reusable DNS wire parser, candidate classification, and observation extraction procedure. |
| `.agents/skills/flow-reconstruction/SKILL.md` | Reusable bidirectional flow reconstruction procedure. |
| `.agents/skills/flow-statistics/SKILL.md` | Reusable flow statistics and temporal metrics review procedure. |
| `.agents/skills/http-protocol-analysis/SKILL.md` | Reusable HTTP/1.x header parser, candidate classification, sensitive header masking, and observation extraction procedure. |
| `.agents/skills/observation-evidence-model/SKILL.md` | Reusable unified protocol observation and structured evidence procedure. |
| `.agents/skills/periodic-beaconing/SKILL.md` | Reusable explainable periodic beaconing detection procedure. |
| `.agents/skills/phase-validation/SKILL.md` | Reusable phase-scope and completion procedure. |
| `.agents/skills/rust-quality/SKILL.md` | Reusable Rust and Cargo quality procedure. |
| `.agents/skills/secure-parser-review/SKILL.md` | Reusable hostile-input parser review procedure. |
| `.agents/skills/tls-protocol-analysis/SKILL.md` | Reusable TLS 1.2 / TLS 1.3 handshake parser, candidate classification, privacy non-retention, and observation extraction procedure. |
| `crates/pcapraven-domain/Cargo.toml` | Domain library package manifest. |
| `crates/pcapraven-domain/src/lib.rs` | Domain library entry point and type exports. |
| `crates/pcapraven-domain/src/dns.rs` | Normalized DNS observation model, question, RR, EDNS metadata, and diagnostic types. |
| `crates/pcapraven-domain/src/evidence.rs` | Structured evidence records, exact rational `EvidenceRatio`, measurements, and schema anchors. |
| `crates/pcapraven-domain/src/finding.rs` | Finding domain models, detector identifiers, detector versions, severity, confidence, subjects, and records. |
| `crates/pcapraven-domain/src/http.rs` | Normalized HTTP/1.x observation model, request/response metadata, selected headers, sensitive flags, and diagnostic types. |
| `crates/pcapraven-domain/src/observation.rs` | Unified protocol observations, explicit flow associations, completeness states, and bounded collections. |
| `crates/pcapraven-domain/src/tls.rs` | Normalized TLS 1.2 / TLS 1.3 handshake observation model, Hello metadata, extension metadata, and diagnostic types. |
| `crates/pcapraven-domain/src/packet.rs` | Normalized packet model, metadata, diagnostics, addresses, flags, and completeness states. |
| `crates/pcapraven-domain/src/flow.rs` | Capture-independent flow endpoints, keys, references, directions, associations, exclusions, end reasons, and records. |
| `crates/pcapraven-domain/src/flow_metrics.rs` | Domain models for directional traffic statistics, exact rational `FlowDuration`, and temporal metrics. |
| `crates/pcapraven-domain/tests/observation_evidence.rs` | Integration tests for unified protocol observations and structured evidence models. |
| `crates/pcapraven-pcap/Cargo.toml` | Capture-ingestion manifest with the audited `pcap-parser` and dev-only `proptest` dependencies. |
| `crates/pcapraven-pcap/src/lib.rs` | Public bounded PCAP/PCAPNG reader contract and crate boundary. |
| `crates/pcapraven-pcap/src/reader.rs` | Safe streaming reader implementation, limits, metadata, diagnostics, error mapping, and normalization adapter. |
| `crates/pcapraven-pcap/tests/reader.rs` | Synthetic boundary, endian, recovery, limit, I/O, and property tests. |
| `crates/pcapraven-protocols/Cargo.toml` | Protocol-normalization manifest with audited `etherparse` and dev-only `proptest` dependencies. |
| `crates/pcapraven-protocols/src/lib.rs` | Protocol-normalization library entry point and public exports. |
| `crates/pcapraven-protocols/src/dns.rs` | Bounded DNS wire-format parser and candidate classification engine. |
| `crates/pcapraven-protocols/src/dns_limits.rs` | Validated finite resource limits for DNS parsing. |
| `crates/pcapraven-protocols/src/http.rs` | Bounded HTTP/1.x wire-format parser and candidate classification engine. |
| `crates/pcapraven-protocols/src/http_limits.rs` | Validated finite resource limits for HTTP parsing. |
| `crates/pcapraven-protocols/src/tls.rs` | Bounded visible TLS 1.2 / TLS 1.3 handshake parser and candidate classification engine. |
| `crates/pcapraven-protocols/src/tls_limits.rs` | Validated finite resource limits for TLS parsing. |
| `crates/pcapraven-protocols/src/limits.rs` | Finite normalization resource limits and builder. |
| `crates/pcapraven-protocols/src/normalizer.rs` | Bounded Ethernet, IPv4, IPv6, TCP, and UDP packet normalization engine. |
| `crates/pcapraven-protocols/tests/dns.rs` | Integration, boundary, security, and property tests for bounded DNS wire parsing. |
| `crates/pcapraven-protocols/tests/http.rs` | Integration, boundary, security, and property tests for bounded HTTP parsing. |
| `crates/pcapraven-protocols/tests/tls.rs` | Integration, boundary, security, and property tests for bounded TLS parsing. |
| `crates/pcapraven-protocols/tests/normalization.rs` | Unit, boundary, property, and regression tests for packet normalization. |
| `crates/pcapraven-protocols/tests/fixtures/dns/README.md` | Provenance and inventory documentation for synthetic DNS binary test fixtures. |
| `crates/pcapraven-protocols/tests/fixtures/http/README.md` | Provenance and inventory documentation for synthetic HTTP test fixtures. |
| `crates/pcapraven-protocols/tests/fixtures/tls/README.md` | Provenance and inventory documentation for synthetic TLS test fixtures. |
| `crates/pcapraven-flows/Cargo.toml` | Flow-analysis library package manifest with dev-only `proptest`. |
| `crates/pcapraven-flows/src/lib.rs` | Flow-analysis library entry point and re-exports. |
| `crates/pcapraven-flows/src/config.rs` | Configurable finite flow reconstruction limits and builder. |
| `crates/pcapraven-flows/src/error.rs` | Structured flow reconstruction error types. |
| `crates/pcapraven-flows/src/metrics.rs` | Exact rational timestamp arithmetic, fixed-size traffic counters, and online inter-arrival accumulators. |
| `crates/pcapraven-flows/src/reconstructor.rs` | Stateful deterministic bidirectional flow reconstruction and metrics accumulation engine. |
| `crates/pcapraven-flows/tests/reconstruction.rs` | Unit, boundary, lifecycle, and property tests for flow reconstruction. |
| `crates/pcapraven-flows/tests/statistics.rs` | Unit, boundary, lifecycle, and property tests for flow statistics and exact temporal metrics. |
| `crates/pcapraven-detection/Cargo.toml` | Detection library package manifest. |
| `crates/pcapraven-detection/src/lib.rs` | Detection library entry point and re-exports. |
| `crates/pcapraven-detection/src/config.rs` | Detector configuration, typed parameters, and validated parameter keys. |
| `crates/pcapraven-detection/src/detector.rs` | Pure Detector trait, detector metadata, and incomplete data policies. |
| `crates/pcapraven-detection/src/engine.rs` | Detection engine execution pipeline, borrowed domain input, preflight validation, and canonical assignment. |
| `crates/pcapraven-detection/src/error.rs` | Structured error models for detector config, registry, evaluation, and engine output. |
| `crates/pcapraven-detection/src/periodic_beaconing.rs` | Explainable periodic beaconing detector over exact directional flow temporal metrics. |
| `crates/pcapraven-detection/src/dns_anomaly.rs` | Explainable DNS anomaly and possible tunneling detectors over normalized DNS observations. |
| `crates/pcapraven-detection/src/registry.rs` | Deterministic bounded registry for active compiled detectors. |
| `crates/pcapraven-detection/tests/engine.rs` | Integration tests for detection engine, registry ordering, preflight config, and deterministic finding generation. |
| `crates/pcapraven-detection/tests/periodic_beaconing.rs` | Integration tests for explainable periodic beaconing detector, exact rational thresholds, and directional analysis. |
| `crates/pcapraven-detection/tests/dns_anomaly.rs` | Integration tests for DNS anomaly and possible tunneling detectors. |
| `crates/pcapraven-reporting/Cargo.toml` | Reporting library package manifest. |
| `crates/pcapraven-reporting/src/lib.rs` | Reporting Phase 1 documentation skeleton. |
| `crates/pcapraven-cli/Cargo.toml` | Binary package manifest for the `pcapraven` executable with audited `clap` dependency. |
| `crates/pcapraven-cli/src/main.rs` | Functional CLI binary entry point and exit-code mapping. |
| `crates/pcapraven-cli/src/args.rs` | Command-line argument parsing and configuration types. |
| `crates/pcapraven-cli/src/app.rs` | CLI application orchestration for validation, flow inspection, DNS inspection, HTTP inspection, and TLS inspection. |
| `crates/pcapraven-cli/src/output.rs` | Factual human inspection output rendering for stdout. |
| `crates/pcapraven-cli/src/diagnostics.rs` | Bounded diagnostic emission and suppression tracking. |
| `crates/pcapraven-cli/tests/cli.rs` | End-to-end integration tests for the PcapRaven CLI. |
| `fuzz/Cargo.toml` | Excluded independent cargo-fuzz project manifest with separately audited fuzz-only dependency. |
| `fuzz/Cargo.lock` | Cargo-generated lockfile for the excluded fuzz project. |
| `fuzz/fuzz_targets/fuzz_pcap_reader.rs` | Stable-name libFuzzer target using only the public bounded reader API. |
| `fuzz/fuzz_targets/fuzz_packet_normalizer.rs` | Stable-name libFuzzer target for bounded protocol normalization. |
| `fuzz/fuzz_targets/fuzz_flow_reconstructor.rs` | Stable-name libFuzzer target for bounded bidirectional flow reconstruction and metric invariant validation. |
| `fuzz/fuzz_targets/fuzz_dns_parser.rs` | Stable-name libFuzzer target for bounded DNS wire parsing. |
| `fuzz/fuzz_targets/fuzz_http_parser.rs` | Stable-name libFuzzer target for bounded HTTP/1.x wire parsing. |
| `fuzz/fuzz_targets/fuzz_tls_parser.rs` | Stable-name libFuzzer target for bounded TLS 1.2 / TLS 1.3 wire parsing. |

The former duplicate skill copies are intentionally absent. Future capture
fixtures, threat detection heuristics, correlation, reporters, and advanced CLI commands
are not current inventory and may be added only by their owning roadmap phases.
The excluded `fuzz/` project is tracked repository inventory but is not one of the
seven main workspace packages.

## Inventory Rules

Every current project path added to the workspace, tooling, CI, or agent
governance must be recorded here in the same contribution. Generated build
output under `/target/` is ignored and is not an inventory artifact. Future
paths mentioned in canonical documents are plans, not claims that those paths
exist.
