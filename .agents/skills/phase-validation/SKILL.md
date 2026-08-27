---
name: phase-validation
description: Use before completing any PcapRaven phase or change to verify roadmap scope, required artifacts, canonical-document consistency, paths, validation evidence, and absence of premature functionality.
---

# Phase Validation

## Procedure

1. Read `AGENTS.md`, `MANIFEST.md`, the current entry in `docs/ROADMAP.md`, and
   all canonical documents affected by the change.
2. Build a checklist from the user's requirements and phase deliverables,
   exclusions, tests, documentation, and review obligations.
3. Enumerate repository files and compare them with `MANIFEST.md`. Identify
   missing, extra, generated, or premature artifacts.
4. Inspect every changed or created file in full and inspect the complete diff.
5. Verify referenced repository paths exist unless text explicitly marks them as
   planned. Resolve relative Markdown links with exact case.
6. Search for contradictory terminology, crate/dependency direction, phase
   numbering, security invariants, finding semantics, and present-tense claims
   about future work.
7. Run only verification allowed and meaningful for the current phase. Record
   exact commands and failures; do not claim unrun gates.
8. Confirm any required independent source-read-only Reviewer pass occurred
   after Developer verification. The Reviewer may run explicitly permitted
   non-mutating checks but cannot modify project files. Route CRITICAL/HIGH
   findings through remediation and re-review.
9. Report changed paths, verification, unavailable commands, and every
   remaining MEDIUM/LOW observation with rationale.

## Phase 0 Gate

The historical Phase 0 inventory was limited to the documentation and OpenCode
governance artifacts then listed in `MANIFEST.md`. Its gate rejected
`Cargo.toml`, `Cargo.lock`, Rust source, `crates/`, fixture trees, CI workflows,
parsers, packet decoders, flow logic, protocol analysis, detection, reporting,
and functional CLI behavior. README and all examples had to label future
capabilities as planned or targeted.

At the historical Phase 0 gate, reject completion when any required path was
missing, any internal link was broken, the roadmap did not contain exactly
Phase 0 through Phase 19 in the required order, OpenCode frontmatter or
reviewer permissions were invalid, or a document contradicted its canonical
owner. That exact Phase 0-through-19 roadmap requirement was historical; the
current roadmap may list future phases after Phase 19.

## Phase 1 Gate

Phase 1 must contain a virtual Edition 2024, resolver 3 Cargo workspace with
exactly the six library crates and `pcapraven` binary defined by
`docs/ARCHITECTURE.md`. Workspace packages use version `0.0.0`, license `MIT`,
`publish = false`, and explicit Rust version `1.85`. The workspace must have
workspace-level unsafe-code denial, only the documented internal dependency
edges, no third-party Rust dependencies, and a tracked `Cargo.lock` generated
by Cargo.

The six libraries and binary are documented skeletons only. They must not
contain domain or business types, parsers, protocol analysis, flow logic,
detection, reporting behavior, or functional CLI behavior. The exact stable
development toolchain is pinned with the minimal profile and `rustfmt` and
`clippy` components. Baseline CI and the dependency-free Cargo-metadata
architecture checker must enforce the Phase 1 topology and quality gates,
including locked MSRV `1.85.0` verification. Documentation and the repository
manifest had to identify Phase 0 and Phase 1 as complete and Phase 2 as next
without claiming later functionality was available. That historical gate is
superseded by the current Phase 2 gate below.

## Phase 2 Gate

Phase 2 must keep the exact seven-package main workspace graph and add capture
ingestion only to `pcapraven-pcap`. The reader must accept a generic bounded
streaming input, support only the documented PCAP/PCAPNG container subset, keep
packet bytes owned and bounded, expose capture metadata and explicit completion
state, distinguish malformed, unsupported, incomplete, invalid-reference, I/O,
and resource-limit conditions, and recover only at validated block boundaries.

Phase 2 may add the audited exact-version parser dependency, focused synthetic
tests, property tests, and an excluded fuzz target using the public reader API.
It must not add protocol decoding, normalized domain packet types, flow logic,
detection, reporting, or functional CLI behavior. Documentation must describe
the reader as present while keeping Phase 3 protocol normalization and all later
phases future work. The main workspace remains seven packages; excluded fuzz
tooling is not a production workspace member. That historical gate is superseded
by the current Phase 3 gate below.

## Phase 3 Gate

Phase 3 implements bounded Ethernet II, IPv4, IPv6, TCP, and UDP packet
normalization. `pcapraven-domain` defines normalized packet metadata, reference
identity, timestamp representations, and layer diagnostics. `pcapraven-protocols`
normalizes borrowed `PacketNormalizationInput` into `NormalizedPacket` using audited
`etherparse = 0.21.0` with `default-features = false`. It excludes trailing Ethernet
padding from network and transport payloads, bounds IPv6 extension header traversal
and byte budgets, models fragmentation explicitly without reassembly, bounds
application payload retention by `maximum_retained_payload_bytes`, and limits
diagnostic emission.

Phase 3 adds comprehensive unit, boundary, property (`proptest`), and fuzzing
(`fuzz_packet_normalizer`) tests. It must not add flow reconstruction, application
decoders (DNS/HTTP/TLS), threat detectors, reporting, or functional CLI commands.
The architecture checker must enforce the seven-package graph and audited external
dependencies. That historical gate is superseded by the current Phase 4 gate below.

## Phase 4 Gate

Phase 4 implements deterministic bidirectional flow reconstruction. `pcapraven-domain`
defines capture-independent flow identity (`FlowEndpoint`, `FlowKey`, `FlowReference`,
`FlowDirection`, `FlowPacketAssociation`, `FlowRecord`, `FlowEndReason`).
`pcapraven-flows` reconstructs flows statefully from `NormalizedPacket` streams:
- `FlowKey` endpoints are canonicalized by total ordering (`endpoint_a <= endpoint_b`).
- `FlowDirection` explicitly distinguishes `AToB`, `BToA`, and `SameEndpoint`.
- Monotonic `capture_record_ordinal` ordering is strictly enforced without reordering.
- Sequential five-tuple reuse across lifecycles is disambiguated by `FlowReference`.
- Integer-only timestamp arithmetic governs exact idle timeouts without floats.
- TCP lifecycle tracks initial SYN retransmissions without false splits, terminates
  prior flows on new initial SYN after activity (`TcpNewInitialSyn`), associates and
  terminates on RST (`TcpReset`), and treats FIN conservatively without premature split.
- UDP lifecycle tracks key continuity and idle timeouts.
- Active state is finite and bounded (`maximum_tracked_flows`, `maximum_flow_instances`)
  without arbitrary eviction or packet payload retention.
- Completed flow records stream out upon closure and `finish()` orders records by
  `FlowReference` ordinal.
- Property tests (`proptest`) and `fuzz_flow_reconstructor` are added and verified.
- Flow statistics, temporal metrics, application decoders, detections, reporters, and
  functional CLI behavior remain out of scope. That historical gate is superseded
  by the current Phase 5 gate below.

## Phase 5 Gate

Phase 5 implements checked flow traffic statistics and exact rational temporal metrics.
- `pcapraven-domain` defines immutable domain types: `FlowTrafficCounters`,
  `FlowTrafficStatistics`, `FlowDuration`, `FlowTemporalUnavailableReason`,
  `FlowTemporalValue`, `FlowTimestampCoverage`, `FlowInterArrivalMetrics`, and
  `FlowTemporalMetrics`.
- `pcapraven-flows` computes directional traffic statistics (`total`, `a_to_b`, `b_to_a`,
  `same_endpoint`) and verifies directional-sum invariants for packet counts, captured bytes,
  wire bytes, and truncation counts.
- `FlowDuration` is an exact rational seconds representation (`u128 / u128`) reduced to lowest
  terms via GCD. Floating-point types (`f32`/`f64`) are strictly forbidden.
- Timestamp validation handles decimal and binary resolutions and signed offsets.
- Unavailable, invalid, and non-monotonic timestamps break sequence chains without panic or
  interval bridging. Non-monotonic transitions never create negative durations.
- Inter-arrival metrics enforce explicit sample requirements and derive exact mean intervals
  and mean absolute successive interval deltas.
- Active flow state uses fixed-size scalar accumulators ($O(1)$ per flow); storing interval
  vectors, timestamp vectors, or packet payloads is forbidden.
- Lifecycle attribution integrates statistics cleanly with `IdleTimeout`, `TcpNewInitialSyn`,
  `TcpReset`, and `EndOfInput`.
- Observation errors (`observe(...) -> Err`) are strictly transactional.
- No new production dependencies are added (`proptest` remains dev-only).
- Comprehensive unit, boundary, lifecycle, property, and strengthened fuzzing tests pass.
- Application decoders (DNS/HTTP/TLS), CLI commands, threat detection, and reporting remain
  future roadmap phases. That historical gate is superseded by the current Phase 6 gate below.

## Phase 6 Gate

Phase 6 implements the initial functional command-line interface and streaming capture/flow inspection.
- Phase 5.1 hardening is complete: `FlowDuration::cmp` is exact, total, and panic/overflow-free for all valid
  public fractions; all production `expect()` paths in `FlowReconstructor` are removed and replaced with
  structured invariant errors without sacrificing `observe()` transactionality.
- Implements exactly `pcapraven validate <capture>` and `pcapraven flows <capture>`.
- Root `--help` and `--version` are functional and do not advertise future subcommands (`analyze`, `dns`,
  `http`, `tls`, `findings`).
- Bounded streaming capture reader orchestration; zero whole-capture `CaptureRecord` bulk accumulation.
- `flows` streams reader -> normalization -> flow reconstruction -> immediate closed `FlowRecord` output.
- Truthful finalization: clean EOF yields `FlowEndReason::EndOfInput`; early/abnormal termination yields
  `FlowEndReason::AnalysisStopped` via `finish_partial()`.
- Exact exit codes: `0` (complete), `1` (fatal failure before useful result), `2` (usage/configuration error),
  `3` (useful partial result).
- Strict separation: stdout is result-only, stderr is diagnostics/errors only.
- Zero ANSI styling/color.
- Stderr diagnostics bounded by display budget (default 100 lines) with suppression summary unless `--quiet`.
- `--quiet` suppresses nonfatal stderr diagnostics without altering exit codes, stdout results, or fatal errors.
- CLI arguments/limits validated through existing library builder APIs.
- Audited `clap = "=4.6.4"` minimal dependency (`default-features = false`, features: `std`, `help`, `usage`, `error-context`).
- Architecture checker updated and verified for Phase 6.
- Cross-platform integration tests in `crates/pcapraven-cli/tests/cli.rs` pass.
- Application decoders (DNS/HTTP/TLS), threat detection, formal reporting, and output files remain strictly future work.
  That historical gate is superseded by the current Phase 7 gate below.

## Phase 7 Gate

Phase 7 implements bounded DNS protocol analysis, normalized DNS observations, and DNS CLI inspection.
- `pcapraven-domain` defines DNS domain types: `DnsTransport`, `DnsMessageKind`, `DnsFlags`, `DnsName`,
  `DnsQuestion`, `DnsSection`, `DnsRdataMetadata`, `DnsResourceRecord`, `DnsEdnsOptionMetadata`,
  `DnsEdnsMetadata`, `DnsObservationCompleteness`, `DnsObservation`, `DnsDiagnosticKind`, and `DnsDiagnostic`.
- `DnsName` enforces RFC 1035 label length (<= 63) and expanded wire length (<= 255) bounds, preserving raw byte
  fidelity and providing terminal-safe `display_escaped()` rendering without ANSI escape risks.
- `pcapraven-protocols` implements `DnsLimits`, `DnsLimitsBuilder`, and `parse_dns_packet`.
- Candidate classification handles UDP and TCP port 53; non-candidate packets and candidate packets without application
  payload are handled safely and deterministically.
- TCP framing decodes 2-byte length prefixes and processes multiple framed messages per packet without cross-packet reassembly.
- Compression decompression enforces the strict backward-pointer rule (`target_offset < pointer_location_offset`),
  preventing self-loops, cycles, and forward pointers, with pointer hops capped by `maximum_name_pointer_hops`.
- Decodes A (IPv4), AAAA (IPv6), CNAME, NS, PTR, MX, and EDNS(0) OPT pseudo-records with extended RCODE and DO bit.
- CLI adds `pcapraven dns <capture>` with streaming execution and immediate observation row rendering.
- HTTP/1.x (Phase 8), TLS (Phase 9), threat detection, and reporting remain strictly future work.
  That historical gate is superseded by the current Phase 8 gate below.

## Phase 8 Gate

Phase 8 implements bounded HTTP/1.x protocol analysis, normalized HTTP observations, and HTTP CLI inspection.
- `pcapraven-domain` defines HTTP domain types: `HttpVersion`, `HttpMessageKind`, `HttpByteString`,
  `HttpRequestMetadata`, `HttpResponseMetadata`, `HttpContentLengthState`, `HttpSelectedHeaders`,
  `HttpFramingMetadata`, `HttpObservationCompleteness`, `HttpObservation`, `HttpDiagnosticKind`, and `HttpDiagnostic`.
- `HttpByteString` preserves raw wire bytes and renders via `display_escaped()` with `\xHH` / `\\` notation for terminal safety.
- `pcapraven-protocols` implements `HttpLimits`, `HttpLimitsBuilder`, and `parse_http_packet`.
- Candidate classification inspects TCP port 80; non-candidates and non-start midstream packets are handled deterministically.
- Line scanning is strictly bounded by the minimum of available payload, configured line budget, and header section budget.
- Header section budget (`maximum_header_section_bytes`) encompasses start-line through terminal `\r\n\r\n`.
- Oversized selected headers emit `ResourceLimit`, mark `Partial`, and do not silently truncate or retain.
- Informational selected headers retain first value deterministically and aggregate presence flags.
- Complete headers with truncated body payload produce `Complete` observation.
- Strict response status-line requires second `SP`.
- Content-Length supports comma-delimited identical values; conflicting values mark `Invalid` and `Partial`.
- Sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`) record presence flags only.
- CLI adds `pcapraven http <capture>` with streaming execution and bounded table presentation.
- Synthetic micro-fixtures in `tests/fixtures/http/`, unit tests, proptests, and `fuzz_http_parser` pass.
- TLS (Phase 9), threat detection, and reporting remain strictly future work.
  That historical gate is superseded by the current Phase 9 gate below.

## Phase 9 Gate

Phase 9 implements bounded visible TLS 1.2 / TLS 1.3 handshake metadata analysis, normalized TLS observations, and TLS CLI inspection.
- `pcapraven-domain` defines TLS domain types: `TlsVersion`, `TlsRecordContentType`, `TlsHandshakeKind`,
  `TlsByteString`, `TlsExtensionMetadata`, `TlsClientHelloMetadata`, `TlsServerHelloMetadata`,
  `TlsObservationCompleteness`, `TlsObservation`, `TlsDiagnosticKind`, and `TlsDiagnostic`.
- `TlsByteString` preserves raw wire bytes and renders via `display_escaped()` with `\xHH` / `\\` notation for terminal safety.
- `pcapraven-protocols` implements `TlsLimits`, `TlsLimitsBuilder`, and `parse_tls_packet`.
- Candidate classification inspects TCP port 443; non-candidates (UDP/443, non-443) and candidate packets without TLS records are handled deterministically.
- Packet-local multi-record handshake assembly handles fragmented Hello messages across adjacent Handshake records within the same packet up to `maximum_handshake_message_bytes`, retaining only unconsumed buffer suffixes.
- Enforces aggregate per-packet handshake message limits across all records in a packet.
- Privacy Non-Retention: raw 32-byte randoms, session IDs, key exchange public bytes, PSK binders/identities, early data payloads, certificate DER, and ciphertext payloads are strictly never retained.
- Decodes ClientHello, ServerHello, and HelloRetryRequest (detected via RFC 9846 SHA-256 random sentinel).
- Decodes SNI (full list consumption with duplicate `host_name` rejection), Supported Versions (policy: TLS 1.2/1.3 only), Supported Groups, Signature Algorithms, ALPN (cleartext ALPN in TLS 1.3 ServerHello prohibited), Key Share (group ID only; finite entry limits with `ResourceLimit`), PSK presence, and Early Data presence.
- Enforces maximum record fragment bounds (16 KiB plaintext, 18 KiB opaque) before body processing.
- Enforces duplicate extension detection per Hello message.
- Contextually validates ServerHello extension lengths and decouples per-observation completeness from subsequent unrelated packet errors.
- CLI adds `pcapraven tls <capture>` with streaming execution and bounded table presentation.
- Synthetic micro-fixtures in `tests/fixtures/tls/`, unit tests, 20 Gate 9.1 regression tests, proptests, and `fuzz_tls_parser` pass.
- Threat detection heuristics, correlation (Phase 11), and reporting remain strictly future work.
  That historical gate is superseded by the current Phase 10 gate below.

## Phase 10 Gate

Phase 10 implements unified protocol observations, explicit flow association, and the structured evidence foundation in `pcapraven-domain`.
- `pcapraven-domain` defines observation domain types: `ProtocolKind`, `ObservationReference`, `ObservationCompleteness`,
  `ObservationFlowAssociation`, `ProtocolObservationData`, `ProtocolObservation`, `ProtocolObservationCollection`, and `ProtocolObservationCollectionError`.
- Unified observation architecture wraps DNS, HTTP, and TLS observations in typed `ProtocolObservationData` while preserving packet provenance and explicit flow association (`Associated`, `Excluded`, `Unassociated`).
- `pcapraven-domain` defines evidence domain types: `SchemaVersion`, `EvidenceReference`, `EvidenceKind`, `EvidenceDescription`,
  `EvidenceMetricKey`, `EvidenceRatio`, `EvidenceUnit`, `EvidenceValue`, `EvidenceComparison`, `EvidenceMeasurement`, `EvidenceLimitation`, and `EvidenceRecord`.
- Exact rational arithmetic in `EvidenceRatio`: zero floats (`f32`/`f64`), canonical fraction reduction via GCD, and exact Euclidean continued-fraction comparison across all `u128` pairs without overflow.
- Evidence records decouple factual context from security findings, referencing packets, flows, and observations by reference without copying raw payloads.
- Terminal safety and privacy non-retention: descriptions and metric keys sanitize control characters and enforce length bounds; sensitive payloads are never retained.
- Zero third-party dependencies added to `pcapraven-domain` (pure `std`-only domain types).
- Comprehensive integration tests in `crates/pcapraven-domain/tests/observation_evidence.rs` pass.
- Architecture checker updated and verified for Phase 10.
- Detection engine architecture (Phase 11) is current; periodic beaconing detection (Phase 12) and formal reporting (Phase 16) remain strictly future roadmap phases.
  That historical gate is superseded by the current Phase 11 gate below.

## Phase 11 Gate

Phase 11 implements the detection engine architecture in `pcapraven-detection` and finding domain models in `pcapraven-domain`.
- `pcapraven-domain` defines finding domain models: `DetectorId`, `DetectorVersion`, `FindingReference`, `FindingSubject`, `FindingTitle`, `FindingSummary`, `FindingRationale`, `FindingDraft`, `FindingRecord`, `Severity`, `Confidence`, and `FindingValidationError`.
- `pcapraven-detection` defines detector trait and metadata: `Detector`, `DetectorMetadata`, and `IncompleteDataPolicy` (`Skip`, `AllowWithLimitations`).
- `pcapraven-detection` defines parameter models: `DetectorParameterKey`, `DetectorParameterValue` (strictly zero floats: `Boolean`, `Unsigned`, `Signed`, `Ratio`, `Duration`), `DetectorParameters`, `DetectorParametersBuilder`, `DetectorConfig`, and `DetectorConfigurations`.
- `pcapraven-detection` defines deterministic registry: `DetectorRegistry` with capacity limits, duplicate ID rejection, and execution order strictly sorted by canonical `DetectorId`.
- Whole-configuration preflight validation: invalid parameters on any detector transactionally abort the entire execution before evaluating any detector.
- Detection engine execution pipeline: `execute_detection` consumes borrowed domain facts (`DetectionInput`), enforces incomplete data policies, verifies referential integrity against flows and observations, detects duplicate finding key collisions `(DetectorId, FindingSubject)`, enforces total output bounds, and assigns canonical `FindingReference` and `EvidenceReference` ordinals.
- Zero third-party production dependencies added to `pcapraven-detection` or `pcapraven-domain` (pure safe Rust and `std`).
- Periodic beaconing detection (Phase 12), DNS anomaly heuristics (Phase 13), C2 heuristics (Phase 14), and formal reporting (Phase 16) remain strictly future roadmap phases.
  That historical gate is superseded by the current Phase 12 gate below.

## Phase 12 Gate

Phase 12 implements explainable periodic beaconing detection over exact directional flow temporal metrics in `pcapraven-detection`.
- `pcapraven-detection` implements `PeriodicBeaconingDetector` (`behavior.periodic_beaconing`, version `1.0.0`, policy `Skip`).
- Evaluates directional temporal metrics independently for Direction A -> B (`a_to_b_inter_arrival`) and Direction B -> A (`b_to_a_inter_arrival`).
- Enforces strict statistical invariants:
  - Clean timestamps: zero discontinuities (`discontinuity_count == 0`), no unavailable/invalid/non-monotonic timestamps, and flow not stopped by analysis limit (`FlowEndReason != AnalysisStopped`).
  - Sample count: $N \ge \text{minimum\_interval\_samples}$ (default 6, hard minimum 3).
  - Mean interval: $\mu \ge \text{minimum\_mean\_interval}$ (default 1s).
  - Jitter ratio: $\delta_{MAD} / \mu \le \text{maximum\_jitter\_ratio}$ (default 10%, bounded $0..=1$).
  - Spread ratio: $(\text{max} - \text{min}) / \mu \le \text{maximum\_spread\_ratio}$ (default 25%, bounded $0..=1$).
- Exact rational arithmetic: constructs exact duration ratios using `compute_duration_ratio` (with cross-cancellation GCD and checked multiplication) and compares using `EvidenceRatio::Ord` without floating-point numbers (`f32`/`f64`) or intermediate cross-multiplication overflow.
- Structured evidence: constructs directional `TemporalMetric` evidence drafts with strict metric keys (`discontinuity_count`, `interval_sample_count`, `maximum_interval`, `mean_absolute_successive_interval_delta`, `mean_interval`, `minimum_interval`, `relative_jitter_ratio`, `spread_ratio`, `successive_delta_sample_count`) and threshold comparisons.
- Engine output bounding: emits findings into an engine-controlled bounded sink (`DetectorDraftSink`). Reaching capacity yields `ResourceLimited` and transactionally discards partial findings.
- Canonical sorting: accepted drafts are sorted by `(FindingSubject, FindingTitle)` prior to sequential identifier assignment.
- Emits at most 1 finding per matching flow, with `Severity::Low`, `Confidence::Medium`, and cautious explanatory wording.
- Full verification: integration tests in `crates/pcapraven-detection/tests/periodic_beaconing.rs`, documentation in `docs/detectors/PERIODIC_BEACONING.md`, and skill in `.agents/skills/periodic-beaconing/SKILL.md`.
- DNS anomaly heuristics (Phase 13), C2 heuristics (Phase 14), and formal reporting (Phase 16) remain strictly future roadmap phases.
  That historical gate is superseded by the current Phase 13 gate below.

## Phase 13 Gate

Phase 13 implements explainable DNS anomaly and possible tunneling detection over normalized DNS observations in `pcapraven-detection`.
- `pcapraven-detection` implements `DnsLongQueryNameDetector` (`dns.long_query_name`, version `1.0.1`, policy `Skip`, severity `Info`, confidence `Medium`, evidence kind `ProtocolObservation`).
- `pcapraven-detection` implements `DnsPossibleTunnelingDetector` (`dns.possible_tunneling`, version `1.1.1`, policy `Skip`, severity `Low`, confidence `Medium`, evidence kind `RatioComparison`).
- `pcapraven-detection` implements `label_octet_diversity_ratio` as a pure helper function:
  - Exact rational formula: `distinct label octets / label length` (`EvidenceRatio`).
  - Fixed-size `[bool; 256]` bitmap memory without heap allocations.
  - Zero floats (`f32`/`f64`), zero logarithms, zero Shannon entropy approximations.
- Canonical DNS query classification: enforces `completeness.is_complete() && message_kind == DnsMessageKind::Query && flags.qr == false`.
- Causally coherent evidence: structural maxima derive strictly from matching questions and qualifying labels (`label.len() >= minimum_label_length`).
- Flow lookup complexity: verified via binary search on `input.flows()` ($O(\log F)$).
- Enforces strict parameter validation:
  - `DnsLongQueryNameDetector`: `minimum_qname_wire_length` ($1..=255$, default 120), `minimum_label_length` ($1..=63$, default 40), `minimum_label_octet_diversity_ratio` ($0..=1$, default 1/3).
  - `DnsPossibleTunnelingDetector`: `minimum_query_observations` ($2..=u64::MAX$, default 8), `minimum_candidate_query_ratio` ($0 < r \le 1$, default 3/4), `minimum_qname_wire_length` ($1..=255$, default 120), `minimum_label_length` ($1..=63$, default 40), `minimum_label_octet_diversity_ratio` ($0..=1$, default 1/3), `maximum_tracked_dns_flows` ($1..=1\_000\_000$, default 65_536).
- Structured evidence with strictly sorted alphabetical metric keys:
  - `DnsLongQueryNameDetector`: `matching_question_count`, `maximum_label_length`, `maximum_label_octet_diversity_ratio`, `maximum_qname_wire_length`, `question_count`.
  - `DnsPossibleTunnelingDetector`: `candidate_query_count`, `candidate_query_ratio`, `dns_query_observation_count`, `maximum_label_length`, `maximum_label_octet_diversity_ratio`, `maximum_qname_wire_length`.
- Resource and sink bounding: flow aggregation is bounded by `maximum_tracked_dns_flows` (exceeding returns `ResourceLimited`); findings are emitted into `DetectorDraftSink` with transactional discard on capacity exhaustion.
- Non-attribution principle: rationales clearly describe factual observations and emphasize benign alternatives (CDNs, anti-spam lookups, DKIM/SPF TXT records, security scanners) without claiming confirmed malware or C2.
- Full verification: integration tests in `crates/pcapraven-detection/tests/dns_anomaly.rs` and `crates/pcapraven-detection/tests/engine.rs`, detector documentation in `docs/detectors/DNS_ANOMALY_TUNNELING.md`, and skill in `.agents/skills/dns-detection/SKILL.md`.
- Connection/C2-like behavioral heuristics (Phase 14) are complete.
  That historical gate is superseded by the current Phase 14 gate below.

## Phase 14 Gate

Phase 14 implements explainable repeated low-volume flow behavior detection and deterministic cross-detector finding correlation in `pcapraven-detection`.
- `pcapraven-domain` extends `FindingRecord` with `source_finding_references: Vec<FindingReference>`, enforced by `HARD_MAX_SOURCE_FINDING_REFERENCES = 256` and strict sort/uniqueness/capacity validation. Verified in `crates/pcapraven-domain/tests/finding.rs`.
- `pcapraven-detection` implements `RepeatedLowVolumeFlowDetector` (`behavior.repeated_low_volume_flows`, version `1.0.0`, policy `Skip`, severity `Low`, confidence `Medium`, evidence kind `FlowMeasurement`).
- Aggregates flows using port-agnostic `ConnectionPeerKey` (`TransportProtocol`, `peer_a <= peer_b` where ports are excluded), bounded by `maximum_tracked_peer_groups` ($1..=1\_000\_000$).
- Enforces flow eligibility: excludes flows with `AnalysisStopped`, `same_endpoint > 0`, `packet_count == 0`, and flows exceeding byte/packet caps.
- Emits structured evidence with 6 factual measurements in strict alphabetical order: `candidate_flow_count`, `candidate_flow_ratio`, `eligible_flow_instance_count`, `maximum_candidate_duration`, `maximum_candidate_packet_count`, `maximum_candidate_wire_bytes`.
- Implements finding correlation pipeline in `crates/pcapraven-detection/src/correlation.rs` and `engine.rs` (`FindingCorrelator` trait, `CorrelationRegistry`, `CorrelationDraftSink`, `execute_detection_with_correlators`).
- Implements `PossibleC2MultiSignalCorrelator` (`behavior.possible_c2_multi_signal`, version `1.1.1`, severity `Medium`, confidence `Medium`) correlating `behavior.periodic_beaconing` + `dns.possible_tunneling` on the same flow, reusing existing evidence without redundant allocations.
- Full verification: integration tests in `crates/pcapraven-detection/tests/connection_behavior.rs` and `crates/pcapraven-detection/tests/correlation.rs`, detector documentation in `docs/detectors/CONNECTION_C2_BEHAVIOR.md`, and skills in `.agents/skills/connection-behavior-detection/SKILL.md` and `.agents/skills/finding-correlation/SKILL.md`.
- Severity/confidence assignment, CLI filtering, and MITRE ATT&CK mappings (Phase 15), formal reporting (Phase 16), and fixture corpus/golden testing (Phase 17) are documented below.
  That historical gate is superseded by the current Phase 15 gate below.

## Phase 15 Gate

Phase 15 finalizes severity and confidence assignment, implements the MITRE ATT&CK Enterprise Matrix (v19.2) mapping domain model in `pcapraven-domain` with strict format validation and engine-stamped provenance, implements multi-criteria finding filtering in `pcapraven-detection`, extracts the shared capture analysis pipeline in `pcapraven-cli`, and introduces the minimal `pcapraven findings` CLI subcommand.
- Severity and confidence ordering: `Severity::from_str` (`info < low < medium < high < critical`) and `Confidence::from_str` (`low < medium < high`).
- MITRE ATT&CK mapping provenance: `MitreAttackId`, `MitreTactic`, `MitreMappingDeclaration`, `MitreMappingProvenance`, and `MitreMapping` in `pcapraven-domain::mitre_attack`.
- Multi-criteria finding filtering: `FindingFilter` in `pcapraven-detection::filtering`.
- CLI findings inspection: `pcapraven findings <capture>` with `--min-severity`, `--min-confidence`, `--detector`, `--mitre`.
- Verified in `crates/pcapraven-detection/tests/filtering.rs` and `crates/pcapraven-cli/tests/cli.rs`.

## Phase 16 Gate

Phase 16 implements deterministic reporting architecture (Table, JSON, NDJSON, CSV) in `pcapraven-reporting`, safe output file creation via `with_output_sink` in `pcapraven-cli`, and the unified forensic analysis subcommand `pcapraven analyze`.
- Multi-format serialization: `report_validation`, `report_flows`, `report_dns`, `report_http`, `report_tls`, `report_findings`, and `report_analysis`.
- CSV formula injection defense via `sanitize_csv_cell`.
- Strict LF line endings (`\n`) for CSV output across all platforms.
- Atomic file output creation via `std::fs::OpenOptions::new().create_new(true)`.
- Rejection of CSV format for `analyze` with Exit Code 2.

## Phase 16.1 Hardening Gate

Phase 16.1 freezes the machine reporting schema (`v1.0`) and hardens analysis completeness and lifecycle behavior:
- Frozen schema version anchor: `REPORT_SCHEMA_VERSION = "v1.0"`.
- Wide integer string policy: all 64-bit and larger integers (`u64`, `i64`, `u128`, `i128`, `usize`), ordinals, and sample counts serialize as decimal string tokens.
- Exact rational duration and ratio formats (`numerator` and `denominator` as strings).
- Complete `EvidenceRecordDto` provenance (`packet_references`, `flow_references`, `observation_references`).
- Complete `FlowRecordDto` machine projection (4 directional traffic buckets, duration, exact temporal metrics).
- Preserved `ProtocolObservationDto` identity and flow association facts for `analyze`.
- Evidence closure: filtered reports emit only evidence records referenced by retained findings.
- Whole-analysis `ReportCompletionDto` reflecting reader, flow, observation, and detection completeness.
- Self-describing tagged NDJSON envelopes (`{"schema_version": "v1.0", "kind": "...", "record_type": "...", "data": { ... }}`).
- Output file write lifecycle: atomic creation, explicit flush, and cleanup of newly created files on error.
- Verified in `crates/pcapraven-reporting/tests/schema_contract.rs` and `crates/pcapraven-cli/tests/cli.rs`.

## Phase 17 Gate

Phase 17 establishes the documented synthetic, sanitized, redistributable PCAP/PCAPNG fixture corpus, generates golden output matrices across all commands and formats, and delivers cross-crate integration and end-to-end regression testing.
- Top-level reproducible synthetic corpus under `tests/fixtures/pcaps/`.
- Canonical schema-v1/generator-v1 manifest and true SHA-256 checksums in `tests/fixtures/pcaps/manifest.json` and `checksums.sha256`.
- Exact golden output matrices under `tests/golden/` across commands and formats (`table`, `json`, `ndjson`, `csv`).
- Comprehensive cross-crate integration tests in `crates/pcapraven-cli/tests/corpus.rs` and golden regression tests in `crates/pcapraven-cli/tests/golden.rs`.
- Read-only fixture/golden checks, safe candidate staging, exact exit states,
  supported multi-section PCAPNG, partial-result/resource-limit regressions,
  CSV injection, HTTP privacy, and deterministic repeatability form mandatory
  Gate 17.1.

## Phase 18 Gate (completed)

Phase 18 expands property testing, bounded fuzz campaigns, robustness analysis,
and practical performance verification. The Part B foundation requires exactly
eight bounded targets, curated synthetic seeds with generated fuzz noise ignored,
an architecture audit of the excluded fuzz package, 30-second Linux CI smoke
runs with explicit length/timeout/RSS limits, bounded fixture/golden verification,
writer failure tests, and a dependency-free release-CLI benchmark tool. The
eight 600-second campaigns and final acceptance benchmark results have been
completed and must remain backed by the tracked evidence. Phase 19 is outside
the completed Phase 18 gate; its current requirements are defined in the
dedicated Phase 19 Gate below.

## Phase 19 Gate (COMPLETE; ACCEPTED)

Phase 19 was the release code-health audit and targeted behavior-preserving
internal-refactoring gate. It may start only from the
accepted Phase 18 baseline, including the Phase 18.3 final robustness and
performance acceptance evidence. The gate requires:

- A complete, evidence-backed audit of every production Rust file under
  `crates/*/src`, covering panic/unwrap/expect, `allow` attributes, unsafe code,
  indexing and slicing, casts and arithmetic, visibility and public API,
  duplication/clones/allocations, complexity and module ownership, errors,
  TODO/FIXME debt, parser bounds/progress, and allowed dispositions.
- A tracked `docs/CODE_HEALTH.md` report containing the baseline identity,
  methodology, complete production inventory, findings, dispositions,
  intentional non-refactors, contract preservation, golden/schema evidence,
  performance and fuzz implications, remaining review observations, and the
  current Phase 19 status.
- Only evidence-backed internal refactoring. Phase 19 must not add product
  features, detectors, MITRE mappings, CLI commands or contract changes,
  reporting-schema changes, dependencies, crates, workspace edges, release
  packaging, or future-phase capability claims.
- Cargo.lock, the workspace package graph, fixture corpus, schema anchors, and
  golden outputs remain unchanged. Applicable formatting, lint, workspace,
  schema, golden, documentation, metadata, architecture, MSRV,
  fuzz/robustness, and Phase 18 performance/acceptance checks must pass after
  any authorized refactor.
- The Phase 18 performance methodology and budgets remain frozen. Any change
  to `analysis.rs` or `app.rs` requires exactly three full Phase 18 benchmark
  runs followed by the Phase 18 acceptance evaluation against the frozen
  budgets; the evaluation must pass. Raw benchmark output stays under `/tmp`.
- An independent Reviewer confirms that no CRITICAL or HIGH findings remain,
  phase boundaries and canonical documents agree, and no premature
  functionality is present. The gate is complete because the listed evidence
  passed and the independent Reviewer confirmed these requirements.

## Phase 20 Gate (COMPLETE; ACCEPTED)

Phase 20 is the final security and supply-chain hardening gate after the
accepted Phase 19 baseline. It adds policy, evidence, CI, and governance
controls only; it must not implement product functionality or any Phase 21
through Phase 28 capability. The gate requires:

- accepted Phase 19 baseline and the dedicated
  `phase-20-security-supply-chain` branch;
- final security-model review and a complete `docs/SUPPLY_CHAIN.md` evidence
  ledger;
- `cargo audit --file Cargo.lock --deny warnings` and the corresponding audit
  for `fuzz/Cargo.lock`;
- cargo-deny advisories, bans, licenses, and sources checks for both the main
  workspace and excluded fuzz package;
- no unresolved CRITICAL/HIGH advisory, hidden advisory ignore, unknown
  dependency source, or unreviewed Git dependency;
- reviewed SPDX inventory and narrow license allowlist, with exceptions and
  clarifications explicitly documented when present;
- reviewed duplicate/wildcard state, direct-dependency maintenance decisions,
  transitive provenance, compile-time build/proc-macro inventory, and
  third-party unsafe-code exposure appropriate to scope;
- immutable full-SHA GitHub Action pins, `persist-credentials: false` on
  read-only checkouts, least-privilege workflow permissions, and no new CI
  secrets or privileged PR trigger;
- review-only Dependabot surveillance for the root Cargo workspace, excluded
  fuzz package, and GitHub Actions;
- an exact tested dated fuzz nightly pin, with all eight bounded smoke targets
  passing after the pin;
- no new runtime dependency unless required by a demonstrated security
  remediation, no product feature, no CLI freeze, no schema finalization, no
  packaging or release automation, and no v1.0.0 claim;
- applicable full formatting, lint, test, documentation, metadata,
  architecture, MSRV, fixture/golden, robustness, fuzz, and performance gates;
- conditional full fuzz/performance reruns when a production surface,
  dependency, or relevant toolchain changes;
- independent source-read-only Reviewer completion after Developer
  verification, with every CRITICAL/HIGH finding remediated and re-reviewed;
- final PR-head CI passing, including Linux quality, MSRV, all three
  cross-platform checks, all eight fuzz-smoke jobs, and the security job;
- `CRITICAL = 0` and `HIGH = 0`, with every remaining MEDIUM/LOW observation
  reported and justified.

The Security Model remains the policy owner; the supply-chain ledger records
evidence. Phase 20 is complete only after the independent review and final
PR-head CI exist. Phase 21 is the next scoped gate, and Phases 22 through 28
remain future.

## Phase 21 Gate

Phase 21 freezes the implemented PcapRaven CLI v1 surface after the accepted
Phase 20 prerequisite. The detailed contract is owned by
`docs/CLI_V1_CONTRACT.md`; this gate verifies that implementation, tests, and
governance agree. The gate requires:

- the dedicated `phase-21-cli-v1-contract-freeze` branch;
- a complete implemented CLI inventory and exact seven-command freeze;
- `docs/CLI_V1_CONTRACT.md`;
- exact global-option freeze and command-specific option scope;
- exact public aliases, including `-h`, `-V`, `-q`, and `-o` where
  exposed;
- default table format and the command/format compatibility matrix;
- exact exit-code classifications 0, 1, 2, and 3;
- stdout/stderr separation, quiet semantics, diagnostic bounding, and safe
  output-file semantics;
- help snapshots and a dynamic version grammar test;
- usage/error snapshots and a dedicated CLI contract integration test;
- all 49 existing report goldens unchanged;
- schema v1.0 unchanged;
- no detector or MITRE semantic change;
- no dependency change unless independently justified;
- MSRV 1.85 unchanged and seven-package topology unchanged;
- the cross-platform contract test passing on Ubuntu, Windows, and macOS;
- the existing security/supply-chain job passing;
- all eight fuzz-smoke jobs passing;
- conditional full Phase 18 performance revalidation when production CLI
  source changes;
- an independent source-read-only Reviewer;
- CRITICAL = 0 and HIGH = 0, with remaining MEDIUM/LOW observations reported
  and justified.

The dedicated contract test must remain separate from the report golden
matrix. It must verify help and version behavior, argument scope and
placement, canonical and invalid values, format support, default output,
aliases, exit states, stream separation, quiet behavior, diagnostics, output
files, collisions, and analyze CSV rejection. No Phase 22 schema audit or
Phase 23 platform-runtime claim is part of this gate.
