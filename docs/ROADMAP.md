# Roadmap to v1.0.0

## Status and Rules

The phases below are ordered gates. Later work may be researched, but it must
not be implemented before its prerequisite phase is accepted. Completion means
the phase deliverables, tests, documentation, and security review are complete;
it does not mean all later capabilities are available.

## Phase 0 - Product definition, architecture and engineering foundation

Define product scope, architecture, domain and detection concepts, security and
testing policies, contributor governance, repository manifest, agent workflow,
and the complete roadmap. Deliver documentation and OpenCode configuration
only. Do not create the Cargo workspace, source code, CI workflows, fixtures,
or functional CLI.

## Phase 1 - Cargo workspace, crate skeletons, baseline CI and tooling

Create the Rust Edition 2024 workspace and seven documented crate skeletons.
Validate dependency versions, features, MSRV requirements, and licenses before
committing dependencies. Establish formatting, linting, test, documentation,
dependency-boundary, and baseline CI tooling without implementing capture
analysis.

## Phase 2 - Safe PCAP/PCAPNG capture reader

Implement bounded capture-container ingestion and capture record metadata for
the documented PCAP/PCAPNG subset. Define limits, recovery behavior, malformed
input tests, property tests, and initial fuzz targets. Do not decode packet
protocols.

## Phase 3 - Ethernet + IPv4/IPv6 + TCP/UDP normalization

Implement bounded normalization for the documented Ethernet, IPv4, IPv6, TCP,
and UDP subset. Preserve unsupported, fragmented, truncated, and malformed
states explicitly. Do not reconstruct flows or parse application protocols.

## Phase 4 - Bidirectional flow reconstruction

Implement canonical flow keys, direction assignment, lifecycle boundaries, and
deterministic packet association from normalized packet records. Do not add
detections.

## Phase 5 - Flow statistics and temporal metrics

Implement checked directional totals and documented temporal metrics with
explicit units, sample requirements, and incomplete-timestamp behavior. Add
boundary and property tests.

## Phase 6 - Initial CLI + capture/flow inspection

Implement the first orchestration and inspection commands for capture and flow
data, including baseline stdout/stderr, exit-status, limits, and table/output
behavior. Do not advertise protocol or detection commands before they work.

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
