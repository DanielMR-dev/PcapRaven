# Repository Manifest

## Purpose and Phase Status

This is a human-readable inventory and governance document, not a Cargo
manifest. Phase 0 product and governance work, Phase 1 workspace/tooling work,
Phase 2 safe PCAP/PCAPNG container reader work, Phase 3 packet normalization
work, Phase 4 bidirectional flow reconstruction work, Phase 5 checked flow
statistics and exact temporal metrics, Phase 6 initial functional CLI
with streaming capture and flow inspection, Phase 7 bounded DNS protocol
11: analysis with normalized DNS observations and DNS CLI inspection,
12: Phase 8 bounded HTTP/1.x metadata analysis with normalized HTTP observations
13: and HTTP CLI inspection, and Phase 9 bounded visible TLS 1.2 / TLS 1.3
14: handshake metadata analysis with normalized TLS observations and TLS CLI inspection are complete.
15: Phase 10 (DNS / HTTP / TLS correlation) and later analysis capabilities remain future work.
16: 
17: ## Tracked Current Inventory
18: 
19: | Path | Purpose |
20: | --- | --- |
21: | `README.md` | Project overview, current status, and documentation links. |
22: | `LICENSE` | Standard MIT license terms for PcapRaven. |
23: | `SECURITY.md` | Private vulnerability disclosure process. |
24: | `CONTRIBUTING.md` | Phase-aware contributor policy and quality guidance. |
25: | `AGENTS.md` | Authoritative AI-agent engineering and review workflow. |
26: | `MANIFEST.md` | Repository structure, current inventory, and phase status. |
27: | `.gitignore` | Rust build, editor, operating-system, and local-environment ignores. |
28: | `Cargo.toml` | Virtual Edition 2024 workspace, package metadata, lints, and internal path dependencies. |
29: | `Cargo.lock` | Cargo-generated locked dependency graph for the seven-package main workspace. |
30: | `rust-toolchain.toml` | Exact pinned stable development toolchain and components. |
31: | `scripts/check_workspace_architecture.py` | Dependency-free Cargo-metadata package, internal-graph, and audited-dependency checker. |
32: | `.github/workflows/ci.yml` | Pull-request and `main` push quality, MSRV, cross-platform, and bounded fuzz-target build CI. |
33: | `docs/PRODUCT.md` | Product identity, scope, goals, non-goals, and target CLI behavior. |
34: | `docs/ARCHITECTURE.md` | Workspace, crate boundaries, dependency direction, errors, logging, and unsafe Rust. |
35: | `docs/DOMAIN_MODEL.md` | Target packet, flow, observation, evidence, finding, and result concepts. |
36: | `docs/DETECTION_MODEL.md` | Target detector/finding contract, severity, confidence, and mappings. |
37: | `docs/SECURITY_MODEL.md` | Technical threat model and mandatory hostile-input controls. |
38: | `docs/TESTING.md` | Reader, normalizer, flow reconstructor, DNS/HTTP/TLS, and CLI integration tests, dependency audits, quality gates, fuzzing, and later test strategy. |
39: | `docs/ROADMAP.md` | Ordered Phase 0 through Phase 19 path to v1.0.0. |
40: | `.opencode/agents/orchestrator.md` | Primary agent that delegates implementation and review. |
41: | `.opencode/agents/developer.md` | Phase-scoped implementation subagent. |
42: | `.opencode/agents/reviewer.md` | Source-read-only review subagent with bounded non-mutating verification. |
43: | `.agents/skills/cli-contract/SKILL.md` | Reusable command-line interface, streaming orchestration, and exit status procedure. |
44: | `.agents/skills/dns-protocol-analysis/SKILL.md` | Reusable DNS wire parser, candidate classification, and observation extraction procedure. |
45: | `.agents/skills/flow-reconstruction/SKILL.md` | Reusable bidirectional flow reconstruction procedure. |
46: | `.agents/skills/flow-statistics/SKILL.md` | Reusable flow statistics and temporal metrics review procedure. |
47: | `.agents/skills/http-protocol-analysis/SKILL.md` | Reusable HTTP/1.x header parser, candidate classification, sensitive header masking, and observation extraction procedure. |
48: | `.agents/skills/phase-validation/SKILL.md` | Reusable phase-scope and completion procedure. |
49: | `.agents/skills/rust-quality/SKILL.md` | Reusable Rust and Cargo quality procedure. |
50: | `.agents/skills/secure-parser-review/SKILL.md` | Reusable hostile-input parser review procedure. |
51: | `.agents/skills/tls-protocol-analysis/SKILL.md` | Reusable TLS 1.2 / TLS 1.3 handshake parser, candidate classification, privacy non-retention, and observation extraction procedure. |
52: | `crates/pcapraven-domain/Cargo.toml` | Domain library package manifest. |
53: | `crates/pcapraven-domain/src/lib.rs` | Domain library entry point and type exports. |
54: | `crates/pcapraven-domain/src/dns.rs` | Normalized DNS observation model, question, RR, EDNS metadata, and diagnostic types. |
55: | `crates/pcapraven-domain/src/http.rs` | Normalized HTTP/1.x observation model, request/response metadata, selected headers, sensitive flags, and diagnostic types. |
56: | `crates/pcapraven-domain/src/tls.rs` | Normalized TLS 1.2 / TLS 1.3 handshake observation model, Hello metadata, extension metadata, and diagnostic types. |
57: | `crates/pcapraven-domain/src/packet.rs` | Normalized packet model, metadata, diagnostics, addresses, flags, and completeness states. |
58: | `crates/pcapraven-domain/src/flow.rs` | Capture-independent flow endpoints, keys, references, directions, associations, end reasons, and records. |
59: | `crates/pcapraven-domain/src/flow_metrics.rs` | Domain models for directional traffic statistics, exact rational `FlowDuration`, and temporal metrics. |
60: | `crates/pcapraven-pcap/Cargo.toml` | Capture-ingestion manifest with the audited `pcap-parser` and dev-only `proptest` dependencies. |
61: | `crates/pcapraven-pcap/src/lib.rs` | Public bounded PCAP/PCAPNG reader contract and crate boundary. |
62: | `crates/pcapraven-pcap/src/reader.rs` | Safe streaming reader implementation, limits, metadata, diagnostics, error mapping, and normalization adapter. |
63: | `crates/pcapraven-pcap/tests/reader.rs` | Synthetic boundary, endian, recovery, limit, I/O, and property tests. |
64: | `crates/pcapraven-protocols/Cargo.toml` | Protocol-normalization manifest with audited `etherparse` and dev-only `proptest` dependencies. |
65: | `crates/pcapraven-protocols/src/lib.rs` | Protocol-normalization library entry point and public exports. |
66: | `crates/pcapraven-protocols/src/dns.rs` | Bounded DNS wire-format parser and candidate classification engine. |
67: | `crates/pcapraven-protocols/src/dns_limits.rs` | Validated finite resource limits for DNS parsing. |
68: | `crates/pcapraven-protocols/src/http.rs` | Bounded HTTP/1.x wire-format parser and candidate classification engine. |
69: | `crates/pcapraven-protocols/src/http_limits.rs` | Validated finite resource limits for HTTP parsing. |
70: | `crates/pcapraven-protocols/src/tls.rs` | Bounded visible TLS 1.2 / TLS 1.3 handshake parser and candidate classification engine. |
71: | `crates/pcapraven-protocols/src/tls_limits.rs` | Validated finite resource limits for TLS parsing. |
72: | `crates/pcapraven-protocols/src/limits.rs` | Finite normalization resource limits and builder. |
73: | `crates/pcapraven-protocols/src/normalizer.rs` | Bounded Ethernet, IPv4, IPv6, TCP, and UDP packet normalization engine. |
74: | `crates/pcapraven-protocols/tests/dns.rs` | Integration, boundary, security, and property tests for bounded DNS wire parsing. |
75: | `crates/pcapraven-protocols/tests/http.rs` | Integration, boundary, security, and property tests for bounded HTTP parsing. |
76: | `crates/pcapraven-protocols/tests/tls.rs` | Integration, boundary, security, and property tests for bounded TLS parsing. |
77: | `crates/pcapraven-protocols/tests/normalization.rs` | Unit, boundary, property, and regression tests for packet normalization. |
78: | `crates/pcapraven-protocols/tests/fixtures/dns/README.md` | Provenance and inventory documentation for synthetic DNS binary test fixtures. |
79: | `crates/pcapraven-protocols/tests/fixtures/http/README.md` | Provenance and inventory documentation for synthetic HTTP test fixtures. |
80: | `crates/pcapraven-protocols/tests/fixtures/tls/README.md` | Provenance and inventory documentation for synthetic TLS test fixtures. |
81: | `crates/pcapraven-flows/Cargo.toml` | Flow-analysis library package manifest with dev-only `proptest`. |
82: | `crates/pcapraven-flows/src/lib.rs` | Flow-analysis library entry point and re-exports. |
83: | `crates/pcapraven-flows/src/config.rs` | Configurable finite flow reconstruction limits and builder. |
84: | `crates/pcapraven-flows/src/error.rs` | Structured flow reconstruction error types. |
85: | `crates/pcapraven-flows/src/metrics.rs` | Exact rational timestamp arithmetic, fixed-size traffic counters, and online inter-arrival accumulators. |
86: | `crates/pcapraven-flows/src/reconstructor.rs` | Stateful deterministic bidirectional flow reconstruction and metrics accumulation engine. |
87: | `crates/pcapraven-flows/tests/reconstruction.rs` | Unit, boundary, lifecycle, and property tests for flow reconstruction. |
88: | `crates/pcapraven-flows/tests/statistics.rs` | Unit, boundary, lifecycle, and property tests for flow statistics and exact temporal metrics. |
89: | `crates/pcapraven-detection/Cargo.toml` | Detection library package manifest. |
90: | `crates/pcapraven-detection/src/lib.rs` | Detection Phase 1 documentation skeleton. |
91: | `crates/pcapraven-reporting/Cargo.toml` | Reporting library package manifest. |
92: | `crates/pcapraven-reporting/src/lib.rs` | Reporting Phase 1 documentation skeleton. |
93: | `crates/pcapraven-cli/Cargo.toml` | Binary package manifest for the `pcapraven` executable with audited `clap` dependency. |
94: | `crates/pcapraven-cli/src/main.rs` | Functional CLI binary entry point and exit-code mapping. |
95: | `crates/pcapraven-cli/src/args.rs` | Command-line argument parsing and configuration types. |
96: | `crates/pcapraven-cli/src/app.rs` | CLI application orchestration for validation, flow inspection, DNS inspection, HTTP inspection, and TLS inspection. |
97: | `crates/pcapraven-cli/src/output.rs` | Factual human inspection output rendering for stdout. |
98: | `crates/pcapraven-cli/src/diagnostics.rs` | Bounded diagnostic emission and suppression tracking. |
99: | `crates/pcapraven-cli/tests/cli.rs` | End-to-end integration tests for the PcapRaven CLI. |
100: | `fuzz/Cargo.toml` | Excluded independent cargo-fuzz project manifest with separately audited fuzz-only dependency. |
101: | `fuzz/Cargo.lock` | Cargo-generated lockfile for the excluded fuzz project. |
102: | `fuzz/fuzz_targets/fuzz_pcap_reader.rs` | Stable-name libFuzzer target using only the public bounded reader API. |
103: | `fuzz/fuzz_targets/fuzz_packet_normalizer.rs` | Stable-name libFuzzer target for bounded protocol normalization. |
104: | `fuzz/fuzz_targets/fuzz_flow_reconstructor.rs` | Stable-name libFuzzer target for bounded bidirectional flow reconstruction and metric invariant validation. |
105: | `fuzz/fuzz_targets/fuzz_dns_parser.rs` | Stable-name libFuzzer target for bounded DNS wire parsing. |
106: | `fuzz/fuzz_targets/fuzz_http_parser.rs` | Stable-name libFuzzer target for bounded HTTP/1.x wire parsing. |
107: | `fuzz/fuzz_targets/fuzz_tls_parser.rs` | Stable-name libFuzzer target for bounded TLS 1.2 / TLS 1.3 wire parsing. |
108: 
109: The former duplicate skill copies are intentionally absent. Future capture
110: fixtures, threat detection heuristics, correlation, reporters, and advanced CLI commands
111: are not current inventory and may be added only by their owning roadmap phases.
112: The excluded `fuzz/` project is current Phase 9 inventory but is not one of the
113: seven main workspace packages.

## Inventory Rules

Every current project path added to the workspace, tooling, CI, or agent
governance must be recorded here in the same contribution. Generated build
output under `/target/` is ignored and is not an inventory artifact. Future
paths mentioned in canonical documents are plans, not claims that those paths
exist.
