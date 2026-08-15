# Roadmap to v1.0.0

## Status and Rules

The phases below are ordered gates. Later work may be researched, but it must
not be implemented before its prerequisite phase is accepted. Completion means
the phase deliverables, tests, documentation, and security review are complete;
it does not mean all later capabilities are available.

Phase 0, Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, and Phase 6 are complete. Phase 6
delivered the initial functional CLI (`validate` and `flows`), streaming capture and flow
inspection orchestration without bulk packet retention, multiplication-free Euclidean
`FlowDuration` total rational ordering, removal of production `.expect()` calls in
`FlowReconstructor`, exact exit codes (0, 1, 2, 3), stdout/stderr stream separation, bounded
diagnostic budgets with quiet mode support, audited `clap = "=4.6.4"`, and comprehensive
end-to-end CLI integration tests.
Phase 7 (DNS protocol analysis) is next.

## Phase 0 - Product definition, architecture and engineering foundation

Defined product scope, architecture, domain and detection concepts, security and
testing policies, contributor governance, repository manifest, agent workflow,
and the complete roadmap. Delivered documentation and OpenCode configuration
only; no Phase 1 implementation was included in this gate.

## Phase 1 - Cargo workspace, crate skeletons, baseline CI and tooling

Created the Rust Edition 2024 virtual workspace and seven documented crate
skeletons. The workspace commits only the documented internal path edges and no
third-party dependencies or features, declares MSRV 1.85, pins a separate
stable development toolchain, and establishes formatting, linting, test,
documentation, dependency-boundary, architecture-checker, lockfile, and
baseline CI tooling without implementing capture analysis.

## Phase 2 - Safe PCAP/PCAPNG capture reader

Implemented bounded capture-container ingestion and capture record metadata for
the documented PCAP/PCAPNG subset. The reader accepts a generic `Read` source,
supports legacy PCAP little/big-endian microsecond and nanosecond variants plus
PCAPNG section/interface description, enhanced-packet, and simple-packet blocks,
enforces finite bounds, preserves recoverable diagnostics without unbounded
allocation, and guarantees that external bytes never panic the reader. Delivered
unit, boundary, property, and fuzzing targets.

## Phase 3 - Ethernet + IPv4/IPv6 + TCP/UDP normalization

Implemented bounded protocol normalization in `pcapraven-protocols` converting
opaque packet bytes into capture-independent normalized domain models. Normalizes
Ethernet II headers with padding stripping, IPv4 with options and total length
validation, IPv6 with bounded extension header traversal, and TCP/UDP transport
headers with flags and ports. Handles fragmentation explicitly without whole-packet
reassembly, bounds transport payload retention, emits structured diagnostics,
enforces the zero-panic invariant, and delivers comprehensive unit, boundary,
property, and fuzzing targets.

## Phase 4 - Bidirectional flow reconstruction

Implemented deterministic bidirectional flow reconstruction and lifecycle management
in `pcapraven-flows` over normalized packet streams. Canonicalized `FlowKey` endpoints
via binary total ordering (`endpoint_a <= endpoint_b`), classified directional flow
relations (`AToB`, `BToA`, `SameEndpoint`), assigned stable zero-based `FlowReference`
ordinals, enforced strict `capture_record_ordinal` sequence monotonicity, managed
integer-only idle timeouts without float conversions, tracked TCP initial SYN retransmissions
and new initial SYNs, handled immediate RST closures, applied non-forcing FIN policies,
enforced strict finite state bounds (`maximum_tracked_flows`, `maximum_flow_instances`),
and ensured zero memory retention of packet payloads in active state. Delivered unit
and boundary tests, property-based tests with `proptest`, and the `fuzz_flow_reconstructor`
target.

## Phase 5 - Flow statistics and temporal metrics

Implemented checked directional traffic statistics and exact rational temporal metrics
in `pcapraven-flows` and `pcapraven-domain`. Computed directional traffic buckets (`total`,
`a_to_b`, `b_to_a`, `same_endpoint`) for packet counts, captured bytes, wire bytes, and
truncation counts with strict sum invariant verification. Defined `FlowDuration` as exact
rational seconds (`u128 / u128`) reduced to lowest terms via GCD with a strict zero-float
invariant across all durations, means, deltas, and timeouts. Validated decimal and binary
timestamp resolutions and signed offsets with checked arithmetic. Handled missing, invalid,
and non-monotonic timestamps by breaking sequence chains without interval bridging or
negative durations. Implemented inter-arrival metrics with explicit sample requirements,
fixed-size online accumulators ($O(1)$ memory per active flow), and transactional error
semantics. Delivered unit, boundary, lifecycle, and property tests with `proptest`, and
updated `fuzz_flow_reconstructor`.

## Phase 6 - Initial CLI + capture/flow inspection

Implemented the initial functional CLI in `pcapraven-cli` with `validate` and `flows`
commands. Delivered streaming reader orchestration connecting `CaptureReader` ->
`normalize_packet` -> `FlowReconstructor` -> immediate closed `FlowRecord` tabular
output without bulk packet memory retention. Hardened `FlowDuration::cmp` with a
multiplication-free Euclidean continued-fraction rational comparison algorithm ensuring
total ordering without integer overflow across the full `u128` rational domain, and
eliminated production `.expect()` calls in `FlowReconstructor`. Implemented exact exit
codes (`0` complete, `1` fatal failure before useful result, `2` usage/config error, `3`
useful partial result), strict stdout/stderr stream separation, bounded diagnostics
budget (100 lines default) with suppression summary unless `--quiet`, audited minimal
`clap = "=4.6.4"` dependency, and comprehensive end-to-end integration tests in
`crates/pcapraven-cli/tests/cli.rs`.

## Phase 7 - DNS protocol analysis

Implement bounded DNS metadata parsing over normalized transport data and emit
normalized DNS observations. Add malformed fixtures, properties, fuzzing, and
inspection support. Do not add DNS threat heuristics.

## Phase 8 - HTTP/1.x metadata analysis

Implement bounded HTTP/1.x metadata analysis for the documented subset without
collecting bodies by default. Emit normalized observations and add security,
fixture, property, and fuzz coverage. Do not add HTTP detections.

## Phase 9 - TLS handshake metadata analysis

Implement bounded visible TLS handshake metadata analysis for the documented
subset without decryption or trust claims. Emit normalized observations and add
malformed, property, and fuzz coverage.

## Phase 10 - Unified protocol observations and evidence

Stabilize shared observation identity, completeness, packet/flow association,
and structured evidence records across DNS, HTTP, and TLS. Document deterministic
ordering and prepare versioned result projections.

## Phase 11 - Detection engine architecture

Implement detector registration/execution contracts, stable identifiers and
versions, deterministic finding identity, parameter validation, evidence
requirements, and incomplete-data behavior. Do not yet implement the planned
behavioral detector families.

## Phase 12 - Periodic beaconing detection

Implement and validate explainable possible-periodic-beaconing heuristics using
flow temporal metrics. Include sample/threshold rationale, benign alternatives,
false-positive analysis, and evidence-rich findings.

## Phase 13 - DNS anomaly/tunneling heuristics

Implement and validate explainable DNS anomaly and possible-tunneling
heuristics over normalized observations and flows. Use cautious language and
cover benign high-entropy or high-volume alternatives.

## Phase 14 - Connection/C2-like behavioral heuristics

Implement and validate explainable connection and C2-like behavioral
heuristics without asserting malware or confirmed command-and-control. Include
cross-detector interaction and false-positive testing.

## Phase 15 - Severity, confidence, filtering and MITRE mappings

Finalize independent severity and confidence assignment, CLI filtering,
mapping provenance, and applicable MITRE ATT&CK relationships. Verify every
finding answers the required explanatory questions.

## Phase 16 - Table/JSON/NDJSON/CSV reporting

Implement deterministic reporters and documented schemas, terminal/CSV
injection defenses, output-file behavior, and strict stdout/stderr separation.
Define lossless or explicit command-specific projections for each format.

## Phase 17 - Fixture corpus + golden/integration/E2E tests

Establish the documented synthetic, sanitized, redistributable fixture tree and
provenance records. Complete golden, cross-crate integration, and CLI end-to-end
coverage for supported behavior and partial failures.

## Phase 18 - Property testing, fuzzing, robustness and performance

Expand `proptest`, `cargo-fuzz`, regression corpus, resource-limit tests,
long-running campaigns, worst-case performance analysis, and practical
benchmarks. Resolve crashes, hangs, unbounded behavior, and material performance
risks before release hardening.

## Phase 19 - Security hardening, documentation, packaging and v1.0.0

Perform final threat-model and unsafe/dependency review, resolve release-blocking
security findings, validate documentation against behavior, stabilize schemas
and CLI contracts, prepare reproducible packaging and release artifacts, and
release v1.0.0 only after all quality gates pass.
