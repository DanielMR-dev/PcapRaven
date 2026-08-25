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
Phase 12 explainable periodic beaconing detection,
Phase 13 explainable DNS anomaly and possible tunneling detection,
Phase 14 explainable repeated low-volume flow behavior and deterministic cross-detector C2-like correlation,
Phase 15 severity and confidence finalization, MITRE ATT&CK mapping provenance, finding filtering, and findings CLI inspection,
Phase 16 deterministic reporting architecture (table, JSON, NDJSON, CSV), safe output files, and unified `analyze` CLI command, and
Phase 17 synthetic fixture corpus, schema freeze verification, golden reports matrix, cross-crate integration, end-to-end regression testing, and the mandatory Phase 17.1 hardening gate are complete.
Phase 18 property testing, fuzzing, robustness, and performance verification is
complete. Phase 18.1 full fuzz acceptance campaigns, Phase 18.2 performance
baseline/budget work, and Phase 18.3 final performance acceptance are complete.
Phase 19 is the next roadmap scope and remains future work; no Phase 19
capability is implemented.

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
| `.gitattributes` | Cross-platform LF checkout policy for repository text and binary protocol/capture fixture exclusions. |
| `Cargo.toml` | Virtual Edition 2024 workspace, package metadata, lints, and internal path dependencies. |
| `Cargo.lock` | Cargo-generated locked dependency graph for the seven-package main workspace. |
| `rust-toolchain.toml` | Exact pinned stable development toolchain and components. |
| `scripts/check_workspace_architecture.py` | Dependency-free Cargo-metadata package, internal-graph, and audited-dependency checker. |
| `scripts/verification_support.py` | Shared trusted-root-relative component validation, streaming bounded discovery, Unix descriptor-anchored no-follow reads, portable observable-state checks, and bounded diagnostics. |
| `scripts/test_verification_support.py` | Focused adversarial self-tests for discovery/read bounds, fail-before-read ordering, static symlink-ancestor rejection without target consumption, metadata failures, and observable replacement. |
| `scripts/generate_fixtures.py` | Root-independent deterministic synthetic PCAP/PCAPNG writer and read-only integrity checker. |
| `scripts/golden_scenarios.py` | Canonical platform-independent CLI golden scenario matrix. |
| `scripts/check_goldens.py` | Read-only canonical CLI exit/stdout/stderr golden checker with hard fixture/golden structural preflight before reads or execution. |
| `scripts/stage_goldens.py` | Safe explicit-output candidate staging tool that preflights fixture inputs and refuses `tests/golden/`. |
| `scripts/run_phase18_benchmarks.py` | Dependency-free bounded release-CLI semantic scenario benchmark and separate smoke tool with one warmup, five measured samples, integer nanosecond summaries, growth ratios, and environment provenance. |
| `scripts/derive_phase18_budgets.py` | Dependency-free strict validator and integer-only derivation tool for the three-run Phase 18.2 baseline budget document. |
| `scripts/test_phase18_performance.py` | Focused dependency-free regression tests for the Phase 18.2 benchmark matrix, growth groups, budget arithmetic, and invalid-input rejection. |
| `scripts/evaluate_phase18_acceptance.py` | Dependency-free strict integer-only evaluator for exactly three Phase 18.3 acceptance measurements against the frozen Phase 18.2 budgets. |
| `scripts/test_phase18_acceptance.py` | Focused dependency-free tests for Phase 18.3 acceptance evidence validation, aggregation, stability, budget failures, null growth, and deterministic results. |
| `.github/workflows/ci.yml` | Pull-request and `main` push quality, MSRV, cross-platform, and eight-target bounded Linux fuzz-smoke CI. |
| `tests/fixtures/pcaps/README.md` | Provenance and inventory documentation for synthetic PCAP fixture corpus. |
| `tests/fixtures/pcaps/manifest.json` | Canonical schema-v1/generator-v1 path-sorted fixture provenance, behavior, and SHA-256 manifest. |
| `tests/fixtures/pcaps/checksums.sha256` | SHA-256 integrity checksums for synthetic PCAP fixture corpus. |
| `tests/fixtures/pcaps/edge_cases/multi_section.pcapng` | Supported two-section PCAPNG with section-local interfaces and EPB/SPB records. |
| `tests/fixtures/pcaps/malformed/useful_then_truncated_record.pcap` | Useful packet followed by a physically truncated packet record. |
| `tests/fixtures/pcaps/edge_cases/flow_close_out_of_creation_order.pcap` | Flow lifecycle ordering regression capture. |
| `tests/fixtures/pcaps/edge_cases/local_http_partial_with_dns_detection.pcap` | Independent partial HTTP and suspicious DNS detection regression capture. |
| `tests/fixtures/pcaps/edge_cases/csv_formula_sentinels.pcap` | Retained HTTP CSV formula-trigger sentinel capture. |
| `tests/fixtures/pcaps/edge_cases/http_privacy_sentinels.pcap` | HTTP sensitive-header non-retention sentinel capture. |
| `tests/golden/README.md` | Documentation and golden update policy for CLI golden reports matrix. |
| `tests/golden/validate/multi_section.json` | Frozen supported multi-section PCAPNG validation output. |
| `tests/golden/flows/flow_close_out_of_creation_order.table.txt` | Frozen canonical flow creation-order output. |
| `tests/golden/findings/local_http_partial_with_dns_detection.table.txt` | Frozen independent DNS finding despite local HTTP degradation. |
| `tests/golden/http/csv_formula_sentinels.csv` | Frozen CSV formula-prefix output. |
| `tests/golden/analyze/useful_then_truncated_record.json` | Frozen useful partial analysis with capture truncation limitation. |
| `tests/golden/stderr/useful_then_truncated_record.txt` | Frozen useful-partial capture diagnostics. |
| `tests/golden/stderr/corrupt_packet.txt` | Frozen failed-before-useful capture diagnostics/error. |
| `tests/golden/stderr/analyze_csv_rejected.txt` | Frozen exit-2 unsupported-format error. |
| `tests/golden/stderr/local_http_partial_with_dns_detection.txt` | Frozen expected local HTTP degradation diagnostic. |
| `docs/PRODUCT.md` | Product identity, scope, goals, non-goals, and target CLI behavior. |
| `docs/ARCHITECTURE.md` | Workspace, crate boundaries, dependency direction, errors, logging, and unsafe Rust. |
| `docs/DOMAIN_MODEL.md` | Target packet, flow, observation, evidence, finding, and result concepts. |
| `docs/DETECTION_MODEL.md` | Target detector/finding contract, severity, confidence, and mappings. |
| `docs/REPORTING.md` | Reporting architecture, formats (table, JSON, NDJSON, CSV), schema versioning, and sanitization. |
| `docs/ROBUSTNESS.md` | Phase 18 bounded fuzz matrix, completed Phase 18.1 acceptance campaign ledger, invariants, and completed Phase 18.3 performance acceptance. |
| `docs/PERFORMANCE.md` | Phase 18 benchmark methodology, complexity audit, baseline and acceptance environments, frozen budgets, and completed Phase 18.3 acceptance. |
| `docs/performance/` | Tracked Phase 18.2 baseline/budget evidence and Phase 18.3 final acceptance evidence. |
| `docs/performance/phase18-2-baseline-run-1.json` | Raw full baseline measurement run 1 for the clean Phase 18.2 measurement revision. |
| `docs/performance/phase18-2-baseline-run-2.json` | Raw full baseline measurement run 2 for the clean Phase 18.2 measurement revision. |
| `docs/performance/phase18-2-baseline-run-3.json` | Raw full baseline measurement run 3 for the clean Phase 18.2 measurement revision. |
| `docs/performance/phase18-2-budgets.json` | Machine-readable Phase 18.2 budgets frozen and consumed by the Phase 18.3 final acceptance evaluator. |
| `docs/performance/phase18-3-acceptance-run-1.json` | Raw full Phase 18.3 final acceptance measurement run 1. |
| `docs/performance/phase18-3-acceptance-run-2.json` | Raw full Phase 18.3 final acceptance measurement run 2. |
| `docs/performance/phase18-3-acceptance-run-3.json` | Raw full Phase 18.3 final acceptance measurement run 3. |
| `docs/performance/phase18-3-acceptance-result.json` | Deterministic Phase 18.3 final acceptance result: 24/24 median, 13/13 growth, and overall pass. |
| `docs/SECURITY_MODEL.md` | Technical threat model and mandatory hostile-input controls. |
| `docs/TESTING.md` | Reader, normalizer, flow reconstructor, DNS/HTTP/TLS, observations, evidence, detection engine, periodic beaconing, DNS anomaly/tunneling, connection behavior, cross-detector correlation, reporting, CLI integration, fixture corpus, and golden tests, dependency audits, quality gates, fuzzing, and later test strategy. |
| `docs/ROADMAP.md` | Ordered Phase 0 through Phase 19 path to v1.0.0. |
| `docs/detectors/PERIODIC_BEACONING.md` | Specification and statistical contract for the periodic beaconing detector. |
| `docs/detectors/DNS_ANOMALY_TUNNELING.md` | Specification and analytical contract for DNS anomaly and possible tunneling detectors. |
| `docs/detectors/CONNECTION_C2_BEHAVIOR.md` | Specification and analytical contract for connection behavior detector and cross-detector finding correlators. |
| `docs/MITRE_ATTACK_MAPPING.md` | Specification and analytical mapping provenance for MITRE ATT&CK Enterprise Matrix v19.2 relationships. |
| `.opencode/agents/orchestrator.md` | Primary agent that delegates implementation and review. |
| `.opencode/agents/developer.md` | Phase-scoped implementation subagent. |
| `.opencode/agents/reviewer.md` | Source-read-only review subagent with bounded non-mutating verification. |
| `.agents/skills/cli-contract/SKILL.md` | Reusable command-line interface, streaming orchestration, and exit status procedure. |
| `.agents/skills/connection-behavior-detection/SKILL.md` | Reusable explainable repeated low-volume flow behavior detection procedure. |
| `.agents/skills/detection-engine/SKILL.md` | Reusable detection engine architecture, detector registration, configuration, and evaluation procedure. |
| `.agents/skills/developer/SKILL.md` | Reusable senior Rust developer instructions, safety invariants, and implementation procedure. |
| `.agents/skills/dns-detection/SKILL.md` | Reusable DNS anomaly and possible tunneling detection procedure. |
| `.agents/skills/dns-protocol-analysis/SKILL.md` | Reusable DNS wire parser, candidate classification, and observation extraction procedure. |
| `.agents/skills/finding-correlation/SKILL.md` | Reusable cross-detector finding correlation procedure. |
| `.agents/skills/finding-filtering/SKILL.md` | Reusable explainable finding filtering procedure. |
| `.agents/skills/fixture-golden-testing/SKILL.md` | Reusable synthetic fixture corpus, schema freeze verification, golden reports, and end-to-end regression testing procedure. |
| `.agents/skills/flow-reconstruction/SKILL.md` | Reusable bidirectional flow reconstruction procedure. |
| `.agents/skills/flow-statistics/SKILL.md` | Reusable flow statistics and temporal metrics review procedure. |
| `.agents/skills/fuzz-robustness/SKILL.md` | Reusable bounded fuzz harness, corpus, campaign, invariant, and triage procedure. |
| `.agents/skills/http-protocol-analysis/SKILL.md` | Reusable HTTP/1.x header parser, candidate classification, sensitive header masking, and observation extraction procedure. |
| `.agents/skills/mitre-attack-mapping/SKILL.md` | Reusable MITRE ATT&CK Enterprise Matrix v19.2 mapping provenance and validation procedure. |
| `.agents/skills/observation-evidence-model/SKILL.md` | Reusable unified protocol observation and structured evidence procedure. |
| `.agents/skills/orchestrator/SKILL.md` | Reusable software architect and multi-agent orchestrator planning and delegation procedure. |
| `.agents/skills/periodic-beaconing/SKILL.md` | Reusable explainable periodic beaconing detection procedure. |
| `.agents/skills/performance-analysis/SKILL.md` | Reusable worst-case complexity, scalable benchmark, and performance regression procedure. |
| `.agents/skills/phase-validation/SKILL.md` | Reusable phase-scope and completion procedure. |
| `.agents/skills/reporting/SKILL.md` | Reusable multi-format reporting, schema serialization, sanitization, and output file procedure. |
| `.agents/skills/reviewer/SKILL.md` | Reusable independent read-only code and security reviewer auditing procedure. |
| `.agents/skills/rust-quality/SKILL.md` | Reusable Rust and Cargo quality procedure. |
| `.agents/skills/secure-parser-review/SKILL.md` | Reusable hostile-input parser review procedure. |
| `.agents/skills/tls-protocol-analysis/SKILL.md` | Reusable TLS 1.2 / TLS 1.3 handshake parser, candidate classification, privacy non-retention, and observation extraction procedure. |
| `crates/pcapraven-domain/Cargo.toml` | Domain library package manifest. |
| `crates/pcapraven-domain/src/lib.rs` | Domain library entry point and type exports. |
| `crates/pcapraven-domain/src/dns.rs` | Normalized DNS observation model, question, RR, EDNS metadata, and diagnostic types. |
| `crates/pcapraven-domain/src/evidence.rs` | Structured evidence records, exact rational `EvidenceRatio`, measurements, and schema anchors. |
| `crates/pcapraven-domain/src/finding.rs` | Finding domain models, detector identifiers, detector versions, severity, confidence, subjects, and records. |
| `crates/pcapraven-domain/src/mitre_attack.rs` | MITRE ATT&CK Enterprise Matrix v19.2 technique, tactic, rationale, provenance, and mapping models. |
| `crates/pcapraven-domain/src/http.rs` | Normalized HTTP/1.x observation model, request/response metadata, selected headers, sensitive flags, and diagnostic types. |
| `crates/pcapraven-domain/src/observation.rs` | Unified protocol observations, explicit flow associations, completeness states, and bounded collections. |
| `crates/pcapraven-domain/src/tls.rs` | Normalized TLS 1.2 / TLS 1.3 handshake observation model, Hello metadata, extension metadata, and diagnostic types. |
| `crates/pcapraven-domain/src/packet.rs` | Normalized packet model, metadata, diagnostics, addresses, flags, and completeness states. |
| `crates/pcapraven-domain/src/flow.rs` | Capture-independent flow endpoints, keys, references, directions, associations, exclusions, end reasons, and records. |
| `crates/pcapraven-domain/src/flow_metrics.rs` | Domain models for directional traffic statistics, exact rational `FlowDuration`, and temporal metrics. |
| `crates/pcapraven-domain/tests/finding.rs` | Integration tests for domain finding records, subjects, references, and validation rules. |
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
| `crates/pcapraven-detection/src/connection_behavior.rs` | Explainable repeated low-volume flow behavior detector and connection peer key. |
| `crates/pcapraven-detection/src/correlation.rs` | Cross-detector finding correlation architecture and multi-signal C2 heuristics. |
| `crates/pcapraven-detection/src/detector.rs` | Pure Detector trait, detector metadata, and incomplete data policies. |
| `crates/pcapraven-detection/src/engine.rs` | Detection engine execution pipeline, borrowed domain input, preflight validation, and canonical assignment. |
| `crates/pcapraven-detection/src/error.rs` | Structured error models for detector config, registry, evaluation, and engine output. |
| `crates/pcapraven-detection/src/filtering.rs` | Finding filtering model and multi-criteria evaluation across severity, confidence, detector, and MITRE. |
| `crates/pcapraven-detection/src/periodic_beaconing.rs` | Explainable periodic beaconing detector over exact directional flow temporal metrics. |
| `crates/pcapraven-detection/src/dns_anomaly.rs` | Explainable DNS anomaly and possible tunneling detectors over normalized DNS observations. |
| `crates/pcapraven-detection/src/registry.rs` | Deterministic bounded registry for active compiled detectors. |
| `crates/pcapraven-detection/tests/connection_behavior.rs` | Integration tests for explainable repeated low-volume flow behavior detector. |
| `crates/pcapraven-detection/tests/correlation.rs` | Integration tests for cross-detector finding correlation and multi-signal C2 heuristics. |
| `crates/pcapraven-detection/tests/engine.rs` | Integration tests for detection engine, registry ordering, preflight config, and deterministic finding generation. |
| `crates/pcapraven-detection/tests/filtering.rs` | Integration tests for multi-criteria finding filtering. |
| `crates/pcapraven-detection/tests/periodic_beaconing.rs` | Integration tests for explainable periodic beaconing detector, exact rational thresholds, and directional analysis. |
| `crates/pcapraven-detection/tests/dns_anomaly.rs` | Integration tests for DNS anomaly and possible tunneling detectors. |
| `crates/pcapraven-reporting/Cargo.toml` | Reporting library package manifest with audited `serde`, `serde_json`, and `csv` dependencies. |
| `crates/pcapraven-reporting/src/lib.rs` | Reporting library entry point, format dispatchers, and public exports. |
| `crates/pcapraven-reporting/src/format.rs` | Report format enum, report kind enum, and error definitions. |
| `crates/pcapraven-reporting/src/csv_escape.rs` | Formula injection defense and CSV cell sanitizer. |
| `crates/pcapraven-reporting/src/dto/mod.rs` | Serializable Data Transfer Object root and module declarations. |
| `crates/pcapraven-reporting/src/dto/validation.rs` | DTO models for capture validation reports. |
| `crates/pcapraven-reporting/src/dto/flows.rs` | DTO models for network flow reports. |
| `crates/pcapraven-reporting/src/dto/dns.rs` | DTO models for DNS observation reports. |
| `crates/pcapraven-reporting/src/dto/http.rs` | DTO models for HTTP observation reports. |
| `crates/pcapraven-reporting/src/dto/tls.rs` | DTO models for TLS observation reports. |
| `crates/pcapraven-reporting/src/dto/findings.rs` | DTO models for analytical findings and evidence reports. |
| `crates/pcapraven-reporting/src/dto/analysis.rs` | DTO models for unified forensic analysis reports. |
| `crates/pcapraven-reporting/src/table/mod.rs` | Deterministic ASCII table and terminal card formatters. |
| `crates/pcapraven-reporting/src/json/mod.rs` | Deterministic pretty-printed JSON serialization engine. |
| `crates/pcapraven-reporting/src/ndjson/mod.rs` | Deterministic newline-delimited JSON streaming serializer. |
| `crates/pcapraven-reporting/src/csv/mod.rs` | Deterministic 2D tabular CSV serializer with formula injection sanitization. |
| `crates/pcapraven-reporting/tests/reporting.rs` | Integration, schema anchor, format projection, CSV formula defense, and property tests for reporting. |
| `crates/pcapraven-reporting/tests/schema_contract.rs` | Schema contract tests verifying wide integer string formatting, null preservation, and NDJSON envelope structures. |
| `crates/pcapraven-cli/Cargo.toml` | Binary package manifest for the `pcapraven` executable with audited `clap` dependency. |
| `crates/pcapraven-cli/src/main.rs` | Functional CLI binary entry point and exit-code mapping. |
| `crates/pcapraven-cli/src/analysis.rs` | Shared capture analysis pipeline and detection engine orchestration. |
| `crates/pcapraven-cli/src/args.rs` | Command-line argument parsing, format options, output file options, and subcommand definitions. |
| `crates/pcapraven-cli/src/app.rs` | CLI application orchestration for validation, flow inspection, DNS, HTTP, TLS, findings, and unified analysis inspection. |
| `crates/pcapraven-cli/src/diagnostics.rs` | Bounded diagnostic emission and suppression tracking. |
| `crates/pcapraven-cli/tests/cli.rs` | End-to-end integration tests for the PcapRaven CLI across subcommands, formats, and safe output writing. |
| `crates/pcapraven-cli/tests/corpus.rs` | Cross-crate integration tests with trusted-root fixture preflight before manifest reads or CLI execution. |
| `crates/pcapraven-cli/tests/golden.rs` | End-to-end golden regressions with fixture/golden structural preflight before execution and expected-byte reads. |
| `crates/pcapraven-cli/tests/support/mod.rs` | Shared trusted-root-relative bounded traversal/read support with component validation and static symlink-ancestor regressions. |
| `fuzz/Cargo.toml` | Excluded independent cargo-fuzz project manifest with exact audited fuzz-only dependencies and eight binary targets. |
| `fuzz/Cargo.lock` | Cargo-generated lockfile for the excluded fuzz project. |
| `fuzz/fuzz_targets/fuzz_pcap_reader.rs` | Stable-name libFuzzer target using only the public bounded reader API. |
| `fuzz/fuzz_targets/fuzz_packet_normalizer.rs` | Stable-name libFuzzer target for bounded protocol normalization. |
| `fuzz/fuzz_targets/fuzz_flow_reconstructor.rs` | Stable-name libFuzzer target for bounded bidirectional flow reconstruction and metric invariant validation. |
| `fuzz/fuzz_targets/fuzz_dns_parser.rs` | Stable-name libFuzzer target for bounded DNS wire parsing and aggregate expanded question/owner/RDATA name accounting. |
| `fuzz/fuzz_targets/fuzz_http_parser.rs` | Stable-name libFuzzer target for bounded HTTP/1.x wire parsing. |
| `fuzz/fuzz_targets/fuzz_tls_parser.rs` | Stable-name libFuzzer target for bounded TLS 1.2 / TLS 1.3 wire parsing. |
| `fuzz/fuzz_targets/fuzz_detection_engine.rs` | Stable-name libFuzzer target for bounded built-in detection and correlation over synthetic normalized facts. |
| `fuzz/fuzz_targets/fuzz_reporting.rs` | Stable-name libFuzzer target for deterministic reporting, strict packet/flow/observation/evidence/source-finding reference closure, serialization validity, terminal safety, and writer failures. |
| `fuzz/corpus/fuzz_pcap_reader/seed-minimal` | Curated synthetic 24-byte empty classic-PCAP seed. |
| `fuzz/corpus/fuzz_pcap_reader/seed-structured` | Curated synthetic 28-byte empty PCAPNG-section seed. |
| `fuzz/corpus/fuzz_packet_normalizer/seed-minimal` | Curated synthetic 14-byte Ethernet-frame seed. |
| `fuzz/corpus/fuzz_packet_normalizer/seed-structured` | Curated synthetic Ethernet/IPv4/UDP/DNS frame seed. |
| `fuzz/corpus/fuzz_flow_reconstructor/seed-minimal` | Curated synthetic single flow-control-record seed. |
| `fuzz/corpus/fuzz_flow_reconstructor/seed-structured` | Curated synthetic three-record timestamped flow seed. |
| `fuzz/corpus/fuzz_dns_parser/seed-minimal` | Curated synthetic empty DNS-header seed. |
| `fuzz/corpus/fuzz_dns_parser/seed-structured` | Curated synthetic `example.com` A-query seed. |
| `fuzz/corpus/fuzz_http_parser/seed-minimal` | Curated synthetic complete minimal HTTP request seed. |
| `fuzz/corpus/fuzz_http_parser/seed-structured` | Curated synthetic HTTP request with selected headers. |
| `fuzz/corpus/fuzz_tls_parser/seed-minimal` | Curated synthetic empty TLS handshake-record seed. |
| `fuzz/corpus/fuzz_tls_parser/seed-structured` | Curated synthetic TLS 1.3 ClientHello seed. |
| `fuzz/corpus/fuzz_detection_engine/seed-minimal` | Curated synthetic one-flow/one-observation control seed. |
| `fuzz/corpus/fuzz_detection_engine/seed-structured` | Curated synthetic 16-flow/32-observation control seed. |
| `fuzz/corpus/fuzz_reporting/seed-minimal` | Curated one-byte attacker-control reporting seed. |
| `fuzz/corpus/fuzz_reporting/seed-structured` | Curated bounded control/Unicode/formula reporting seed. |

The former duplicate skill copies are intentionally absent. Additional roadmap
artifacts may be added only by their owning delegated phase scope.
The excluded `fuzz/` project is tracked repository inventory but is not one of the
seven main workspace packages.

## Inventory Rules

Every current project path added to the workspace, tooling, CI, or agent
governance must be recorded here in the same contribution. Generated build
output under `/target/` is ignored and is not an inventory artifact. Future
paths mentioned in canonical documents are plans, not claims that those paths
exist.
