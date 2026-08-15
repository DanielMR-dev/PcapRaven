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

Reject completion when any required path is missing, any internal link is
broken, the roadmap does not contain exactly Phase 0 through Phase 19 in the
required order, OpenCode frontmatter or reviewer permissions are invalid, or a
document contradicts its canonical owner.

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
- Exit codes for `dns`: `0` (complete), `1` (fatal failure before useful result), `2` (usage/config error), `3` (useful partial result).
- Synthetic micro-fixtures with documentation, unit tests, proptests, and `fuzz_dns_parser` are added and pass.
- HTTP/1.x (Phase 8), TLS (Phase 9), threat detection, and reporting remain strictly future work.

