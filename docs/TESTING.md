# Testing Strategy

## Status

Phase 0 documentation and governance work, Phase 1 workspace/tooling work,
Phase 2 capture-container ingestion tests, Phase 3 protocol normalization tests,
Phase 4 bidirectional flow reconstruction tests, Phase 5 flow statistics and
exact temporal metric tests, Phase 6 functional CLI integration tests,
Phase 7 bounded DNS protocol analysis tests, Phase 8 bounded HTTP/1.x protocol analysis tests,
Phase 9 bounded TLS 1.2 / TLS 1.3 handshake metadata analysis tests,
Phase 10 unified protocol observations and structured evidence integration tests,
Phase 11 detection engine architecture tests, Phase 12 explainable periodic beaconing detection tests,
Phase 13 explainable DNS anomaly and possible tunneling detection tests,
Phase 14 repeated low-volume flow and correlation tests,
Phase 15 finding classification, filtering, and MITRE ATT&CK mapping provenance tests,
Phase 16 deterministic reporting architecture and schema contract tests,
and Phase 17 synthetic fixture corpus, golden report matrix, cross-crate integration,
end-to-end regression testing, and mandatory Phase 17.1 hardening are complete.
Phase 18 robustness and performance verification is complete; Phase 19 is the
next roadmap scope and is not implemented.

## Testing Pyramid

### Unit Tests

Unit tests cover local invariants and transformations: checked length and
offset calculations, Ethernet II header normalization, IPv4 options and total
length checks, IPv6 extension header bounded traversal, TCP/UDP headers and
flags, payload truncation, diagnostic emission, flow key canonicalization,
direction assignment, timestamp arithmetic, and TCP/UDP lifecycle state machines.

### Fixture and Golden Tests

Fixture tests pass known captures or normalized inputs through one or more
stages. Golden outputs lock intentional diagnostics, normalized records,
findings, ordering, and serialized schemas. Golden changes require human review
and an explanation; they must never be updated blindly merely to make tests
pass.

### Integration Tests

Integration tests verify crate boundaries and data exchange, including
capture ingestion to normalization, normalized packets to flows, observations
and flows to detectors, and domain results to reporters. Error and partial-data
paths are first-class cases.

### End-to-End Tests

End-to-end tests invoke the compiled CLI with synthetic captures and
verify exit status, stdout/stderr separation, output-file behavior, format
validity, filters, quiet/verbose behavior, deterministic output, and hostile
terminal text handling.

### Property-Based Tests

Property tests use `proptest` for the reader, normalizer, and flow reconstructor.
Implemented properties include:

- Parsing arbitrary bytes never panics and respects configured limits.
- Arbitrary link types are handled deterministically without panics.
- Truncating valid PCAP/PCAPNG and packet prefixes never panics or claims
  completeness.
- Identical input yields strictly identical normalized and flow output (determinism).
- Retained transport payload never exceeds `maximum_retained_payload_bytes`.
- Emitted diagnostics never exceed `maximum_diagnostics_per_packet`.
- `FlowKey` canonical ordering and reversibility: `FlowKey::new(p, a, b) == FlowKey::new(p, b, a)`
  and `endpoint_a <= endpoint_b`.
- Arbitrary combinations of TCP flags never cause panics or unexpected crashes.
- Arbitrary endpoint addresses, port numbers, and timestamp configurations never overflow
  or panic.
- Directional traffic counter sum invariant: `total == a_to_b + b_to_a + same_endpoint`
  for packet counts, captured bytes, wire bytes, and truncated packet counts.
- Rational `FlowDuration` representations are strictly canonicalized (`gcd(num, den) == 1`)
  with `denominator > 0` and zero canonicalized as `0 / 1`.
- Inter-arrival sample ordering: `min <= mean <= max` whenever `interval_sample_count > 0`.
- Missing and non-monotonic timestamps break sequence chains without panic or negative intervals.
- HTTP wire parser handling of arbitrary TCP byte sequences over port 80 never panics.
- TLS handshake parser handling of arbitrary TCP byte sequences over port 443 never panics and strictly respects finite bounds.

### Fuzzing Strategy

Fuzzing uses an excluded `fuzz/` package and `libfuzzer-sys` with eight targets:
`fuzz_pcap_reader` for capture-container parsing, `fuzz_packet_normalizer` for
protocol normalization, `fuzz_flow_reconstructor` for flow reconstruction
and traffic/temporal metric invariant validation, `fuzz_dns_parser` for
bounded DNS wire parsing, `fuzz_http_parser` for bounded HTTP/1.x wire parsing,
`fuzz_tls_parser` for bounded TLS 1.2 / TLS 1.3 handshake parsing,
`fuzz_detection_engine` for bounded normalized facts through built-in detectors
and correlation, and `fuzz_reporting` for deterministic serialization,
sanitization, strict machine-reference token validation, complete
packet/flow/observation/evidence/source-finding reference closure, canonical
source ordering, malformed JSON values, and writer failures.
The targets call only public bounded APIs and do not access files or networks.
The checked-in CI build commands are:

```text
cargo +nightly fuzz build fuzz_pcap_reader
cargo +nightly fuzz build fuzz_packet_normalizer
cargo +nightly fuzz build fuzz_flow_reconstructor
cargo +nightly fuzz build fuzz_dns_parser
cargo +nightly fuzz build fuzz_http_parser
cargo +nightly fuzz build fuzz_tls_parser
cargo +nightly fuzz build fuzz_detection_engine
cargo +nightly fuzz build fuzz_reporting
```

Exactly two curated synthetic seeds are tracked under each
`fuzz/corpus/<target>/` directory (16 total); their exact encodings, sizes, and
provenance are inventoried in `ROBUSTNESS.md`. Newly mutated hash-named corpus
entries and artifacts remain ignored and are removed after local smoke runs.
Linux CI runs each target for 30 seconds with `-timeout=5`,
`-rss_limit_mb=1024`, and target-specific maximum input lengths documented in
`ROBUSTNESS.md`. The eight 600-second Phase 18.1 acceptance campaigns completed
and passed; that result is recorded in `ROBUSTNESS.md` and cannot be inferred
from build or smoke success alone.

Fuzz harnesses must configure conservative memory, record, nesting, and work
limits; avoid network and nondeterministic dependencies; and treat panics,
out-of-bounds access, integer overflow, hangs, and uncontrolled allocation as
failures. "No crash" is necessary but not sufficient: harnesses should assert
progress and output invariants.

Crashes and hangs are minimized, triaged, fixed, and promoted to the regression
corpus. Corpus files must follow the fixture privacy and provenance policy.
Long-running campaigns supplement, but do not replace, deterministic CI smoke
runs. Platform sanitizer coverage is part of the completed Phase 18 robustness
contract. Phase 18.2 performance budgets were frozen and the final Phase 18.3
acceptance passed against them.

## Fixture Policy

The canonical fixture and golden layout is:

```text
tests/fixtures/pcaps/benign/
tests/fixtures/pcaps/suspicious/
tests/fixtures/pcaps/malformed/
tests/fixtures/pcaps/edge_cases/
tests/fixtures/pcaps/manifest.json
tests/fixtures/pcaps/checksums.sha256
tests/golden/{validate,flows,dns,http,tls,findings,analyze,stderr}/
```

The corpus is generated by `scripts/generate_fixtures.py --write`; routine
verification uses the completely read-only `--check` mode. Each capture is at
most 256 KiB and the aggregate corpus is at most 4 MiB. The canonical manifest
uses schema version 1 and generator version 1, path-sorted entries, SHA-256,
synthetic/MIT provenance, purpose, and expected behavior without environment metadata.
Verification tree discovery, individual reads, and retained mismatch diagnostics
have explicit hard caps. Exceeding a discovery cap fails verification and reports
that additional entries were omitted. No canonical fixture, manifest, or golden
bytes are read until structural discovery succeeds completely; byte identity and
SHA-256 checks run only after that hard precondition.

### Categories

- `benign`: ordinary traffic that must not produce the targeted suspicious
  finding.
- `suspicious`: synthetic behavior intended to exercise a detector without
  claiming the traffic is real malware.
- `malformed`: truncated, contradictory, or structurally invalid captures and
  packets.
- `edge-cases`: valid or partially supported boundary cases, unusual ordering,
  timestamp behavior, and uncommon values.
- `expected`: reviewed golden outputs and diagnostics associated with fixtures.

### Admission Rules

Fixtures should preferably be synthetic, generated locally, sanitized, minimal,
and redistributable under terms compatible with MIT. Every fixture must
have provenance, generation or sanitization notes, expected purpose, and a
license/redistribution statement in fixture metadata or an adjacent index.

Do not commit production captures, credentials, personal data, third-party
traffic without explicit permission, or payloads unnecessary for the test.
Sanitization must cover payload and metadata, including addresses, names,
headers, certificate fields, timestamps, comments, and PCAPNG metadata.
Compression does not make sensitive data acceptable.

Synthetic fixture generators should be reproducible and version-controlled
when introduced. Generated captures are reviewed as binary artifacts and kept
as small as practical. Large or legally ambiguous samples are excluded rather
than fetched during tests.

Canonical golden text files are stored and checked out with LF (`\n`) line
endings on every supported platform. The repository `.gitattributes` policy
preserves this checkout contract, while capture and protocol-wire fixtures are
excluded from text conversion. Canonical golden bytes are checked read-only by
`scripts/check_goldens.py`.
For each scenario, an absent stdout or stderr golden path means that stream must
be exactly empty; unexpected successful-command warnings therefore fail the gate.
`scripts/stage_goldens.py --output <empty-directory>` may create review
candidates only outside `tests/golden/`; it has no accept or blind-update mode.
Candidates require manual semantic and frozen schema-v1.0 diff review before an
intentional selected file is copied into the canonical tree.

## Regression Corpus

Every security, parser, crash, hang, or incorrect-result defect should add the
smallest safe reproducer. Regression entries include the failure class and
expected behavior without exposing embargoed vulnerability detail before
coordinated disclosure. Duplicate corpus cases are consolidated where they
exercise the same boundary.

## Phase 5 Quality Gates

The Phase 5 Linux quality job runs the following baseline gates with the pinned
development toolchain:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo metadata --format-version 1 --no-deps --locked
python3 scripts/check_workspace_architecture.py
```

The separate Linux CI fuzz matrix verifies the excluded fuzz harnesses using the
nightly toolchain and pinned `cargo-fuzz = 0.13.2`. Each matrix entry runs:

```text
cargo +nightly fuzz run <target> fuzz/corpus/<target> -- \
  -max_len=<target-limit> -max_total_time=30 -timeout=5 -rss_limit_mb=1024
```

The CI job uses locked dependency resolution for workspace quality, metadata,
test, and documentation invocations where Cargo supports it. The architecture
checker also passes `--locked` and `--offline` to Cargo metadata for both the
main workspace and excluded fuzz package. A separate locked MSRV job runs
`cargo +1.85.0 check --workspace --all-targets --locked`, `cargo +1.85.0 build
--workspace --locked`, and `cargo +1.85.0 test --workspace --locked`. A
lightweight `cargo check --workspace --locked` runs across Linux, Windows, and
macOS. The architecture checker rejects unexpected packages, roles, external
dependencies, and dependency directions. The workspace lint policy rejects
project `unsafe` code by default. The fuzz package remains excluded from the
seven-package main workspace and its exact dependencies and eight binary targets
are validated separately by the architecture checker.

## Phase 0 Validation (completed)

Phase 0 used read-only repository inspection rather than Cargo gates. It
required the governance files, valid internal links and OpenCode frontmatter,
consistent terminology, the exact roadmap, and confirmation that no
implementation or later-phase functionality had been introduced.

## Phase 1 Validation (completed)

Phase 1 validation confirmed the exact seven-package virtual workspace, Edition
2024 and resolver 3 settings, workspace package metadata, internal-only graph,
forbidden-unsafe lint, generated lockfile, pinned development toolchain, and
absence of protocol or analysis behavior.

## Phase 2 Validation (completed)

Phase 2 validation confirmed the documented PCAP/PCAPNG subset, owned packet-byte
extraction, integer-only timestamp handling, section-local interface state,
bounded records and diagnostics, explicit completion state, safe recovery only at
validated block boundaries, arbitrary-input no-panic properties, truncation and
limit boundaries, and the public-API fuzz target build.

## Phase 3 Validation (completed)

Phase 3 validation confirmed Ethernet II, IPv4, IPv6, TCP, and UDP normalization,
Ethernet padding stripping, bounded IPv6 extension header traversal, explicit
fragmentation handling without reassembly, bounded transport payload retention,
structured diagnostics, property tests, and the `fuzz_packet_normalizer` target.

## Phase 4 Validation (completed)

Phase 4 validation confirmed bidirectional flow key canonicalization, direction
assignment, monotonic ordinal enforcement, zero packet memory retention, exact
integer timestamp timeout arithmetic, TCP SYN retransmission retention, new initial
SYN handling, RST immediate termination, non-forcing FIN policy, bounded resource
limits, deterministic finalization ordering, property tests, and `fuzz_flow_reconstructor`.

## Phase 5 Validation (completed)

Phase 5 validation confirms checked directional traffic statistics (`total`,
`a_to_b`, `b_to_a`, `same_endpoint`), directional sum invariants, exact rational
`FlowDuration` arithmetic (`u128 / u128` canonicalized via GCD), zero-float policy,
safe timestamp structure validation, sequence chain breaking on unavailable/invalid/non-monotonic
timestamps without interval bridging, sample requirements on inter-arrival metrics,
fixed-size online accumulators, transactional error semantics on `observe()`,
comprehensive property tests, and metric invariant verification in `fuzz_flow_reconstructor`.

## Phase 6 Quality Gates (completed)

Phase 6 validation confirms:
- **Phase 5.1 Hardening:** `FlowDuration::cmp` uses a multiplication-free Euclidean continued-fraction
  rational comparison algorithm, guaranteeing exact, total, and panic-free ordering across all valid
  `u128` rational numbers without intermediate integer overflow. All production `.expect()` paths in
  `FlowReconstructor` are eliminated in favor of structured invariant errors while maintaining strict
  `observe()` transactionality.
- **Initial Functional CLI Commands:** `pcapraven validate <capture>` and `pcapraven flows <capture>`
  are fully implemented. Future subcommands (`analyze`, `dns`, `http`, `tls`, `findings`) remain
  unimplemented and are not advertised in `--help`.
- **Streaming Pipeline:** Captures stream incrementally via `CaptureReader::next_record()`, normalize
  via `normalize_packet()`, and reconstruct flows via `FlowReconstructor::observe()`, emitting closed
  flows immediately without retaining raw packet byte vectors or all historical flow records.
- **Truthful Finalization:** Clean input termination assigns `FlowEndReason::EndOfInput` via `finish()`;
  early or abnormal termination assigns `FlowEndReason::AnalysisStopped` via `finish_partial()`.
- **Exit Code Contracts:** Exactly verifies exit codes `0` (complete), `1` (fatal failure before useful result),
  `2` (usage/config error), and `3` (useful partial result).
- **Stream Separation and Bounds:** Stdout is reserved for requested factual results (summary/table),
  stderr is reserved for diagnostics and fatal errors. Nonfatal diagnostics are capped at 100 lines with a
  suppression summary unless `--quiet`. Zero ANSI color codes.
- **Comprehensive Integration Tests:** End-to-end integration tests in `crates/pcapraven-cli/tests/cli.rs`
  exercise all commands, help, version, usage errors, nonexistent files, complete/partial captures,
  quiet mode, UDP/TCP flows, exclusions, early stopping, and determinism.

## Phase 7 Quality Gates (completed)

- **DNS Wire Parser Invariants:** Implements bounded parsing in `pcapraven-protocols` with zero `.unwrap()`,
  zero `.expect()`, zero panics, and checked arithmetic at all offsets.
- **Candidate Classification:** Accurately routes UDP/TCP port 53 traffic, handles empty-payload TCP packets safely,
  and skips non-candidate packets deterministically.
- **Framing & Decompression:** Decodes 2-byte length TCP frames up to configured message caps without cross-packet
  stream reassembly. Strictly enforces the backward-pointer rule (`target_offset < pointer_location_offset`),
  eliminating self-loops, cycle recursion, and forward pointer exploits.
- **Section and Name Bounds:** Validates label length (<= 63), expanded wire length (<= 255), and message-wide
  retained name bytes limits. RDATA offsets and lengths are strictly checked against message buffer bounds.
- **Normalized Observation Model:** Emits `DnsObservation` records in `pcapraven-domain` with decoded flags,
  effective response codes (incorporating EDNS extended RCODE), parsed questions, decoded standard RRs (A, AAAA,
  CNAME, NS, PTR, MX), and EDNS(0) OPT pseudo-records.
- **Output Safety & CLI Inspection:** Renders domain names using terminal-safe `display_escaped()` notation
  (`\DDD` for non-printable octets and dots inside labels) with zero ANSI escape risks. Implements `pcapraven dns <capture>`
  with streaming output and standard exit codes (0, 1, 2, 3).
- **Comprehensive Verification:** 11 synthetic micro-fixtures with provenance docs, integration tests in `tests/dns.rs`,
  CLI tests in `tests/cli.rs`, proptests for arbitrary byte sequences, and the `fuzz_dns_parser` fuzz target.

## Phase 8 Quality Gates (completed)

- **Bounded HTTP/1.x Parsing:** Implements bounded cleartext HTTP/1.0 and HTTP/1.1 message header parsing in
  `pcapraven-protocols` with zero panics, checked arithmetic, and bounded line scanning (`scan_line_bounded`).
- **Exact Section Budgets:** Enforces `maximum_header_section_bytes` from offset zero through terminal `\r\n\r\n`.
  Lines exceeding line or section budgets emit `ResourceLimit` and mark `Partial`.
- **Selected Header Retention & Privacy:** Retains bounded values for `Host`, `User-Agent`, `Server`, `Content-Type`,
  `Transfer-Encoding`, `Connection`, and `Upgrade`. Oversized values emit `ResourceLimit` and are not retained.
  Sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`) record boolean presence only.
- **Framing & Strict Status-Line:** Strictly validates 3-digit status codes followed by mandatory second `SP`.
  Parses comma-delimited identical Content-Length lists per RFC 9110 Section 8.6; flags conflicting framing.
- **Terminal Safety & CLI Inspection:** `HttpByteString` renders via `display_escaped()` (`\xHH` / `\\`).
  CLI adds streaming `pcapraven http <capture>` with bounded column presentation and standard exit codes (0, 1, 2, 3).
- **Verification & Fuzzing:** 12 synthetic micro-fixtures in `tests/fixtures/http/`, integration tests in `tests/http.rs`,
  CLI tests in `tests/cli.rs`, proptests for arbitrary bytes, and `fuzz_http_parser` fuzz target.

## Phase 9 Quality Gates (completed)

- **Bounded Visible TLS 1.2 / TLS 1.3 Handshake Parsing:** Implements bounded handshake parsing in
  `pcapraven-protocols` with zero panics, checked slice arithmetic, finite bounds, and RFC 9846 / RFC 5246 compliance.
- **Packet-Wide Handshake Limits & Multi-Record Assembly:** Tracks aggregate handshake messages per packet
  across all records. Assembles multi-record handshakes in the same packet by retaining only unconsumed buffer
  suffixes, eliminating duplicate message emissions.
- **Privacy Non-Retention Invariants (MANDATORY):**
  - Raw 32-byte ClientHello / ServerHello random values are NEVER retained (only inspected transiently for the HRR sentinel).
  - Session ID bytes are NEVER retained (only `session_id_length` is recorded).
  - Key Share public key bytes are NEVER retained (only named group IDs are recorded).
  - PSK identities and binders are NEVER retained (only boolean presence flag).
  - Early Data payloads are NEVER retained (only boolean presence flag).
  - Certificate DER and ciphertext payloads are NEVER retained.
  - Zero TLS decryption, private key loading, or `SSLKEYLOGFILE` support.
- **Hardened Gate 9.1 Rules:** Complete SNI list consumption with duplicate `host_name` rejection; client key-share
  count bounds with `ResourceLimit` emission and zero key-exchange bytes; maximum record fragment limits (16 KiB
  plaintext, 18 KiB opaque) checked before body processing; server selected-version policy (only TLS 1.2 or TLS 1.3
  accepted as complete selections); cleartext ALPN in TLS 1.3 ServerHello rejected (`Malformed`/`Partial`); contextual
  ServerHello extension validation; decoupled per-observation completeness.
- **Terminal Safety & CLI Inspection:** `TlsByteString` renders via `display_escaped()` (`\xHH` / `\\`).
  CLI adds streaming `pcapraven tls <capture>` with bounded column presentation and standard exit codes (0, 1, 2, 3).
- **Verification & Fuzzing:** 12 synthetic micro-fixtures in `tests/fixtures/tls/`, comprehensive integration and regression
  tests in `tests/tls.rs`, CLI tests in `tests/cli.rs`, proptests for arbitrary bytes, and `fuzz_tls_parser` fuzz target.

## Phase 10 Unified Protocol Observations and Structured Evidence Foundation

Phase 10 establishes the cross-protocol observation architecture and immutable structured evidence records in `pcapraven-domain`:

- **Unified Protocol Observations:** Integrates DNS, HTTP, and TLS domain observations into `ProtocolObservationData`,
  linking packet provenance (`PacketReference`), explicit flow associations (`Associated`, `Excluded`, `Unassociated`),
  derived completeness, and bounded collection enforcement.
- **Structured Evidence Records:** Provides typed measurements, comparisons, descriptions, limitations, and `SchemaVersion`
  anchoring for findings without raw byte retention.
- **Exact Rational Arithmetic:** `EvidenceRatio` guarantees exact rational arithmetic ($n / d$) in canonical lowest terms via GCD
  and exact total ordering via Euclidean continued fractions without float approximation or arithmetic overflow.
- **Integration Tests:** 14 comprehensive unit/integration tests in `crates/pcapraven-domain/tests/observation_evidence.rs` verifying
  all observation kinds, flow associations, bounds, schema versions, description sanitization, and exact rational comparisons.
- **Pure `std` Invariant:** Zero external dependencies added to `pcapraven-domain`.

## Phase 11 Detection Engine Architecture Testing Foundation

Phase 11 establishes test-only stub detectors and integration test suites in `crates/pcapraven-detection/tests/engine.rs`:

- **Test-Only Stubs:** Pure synthetic stubs for zero matches (`NoMatchStubDetector`), single findings (`OneFindingStubDetector`),
  parameter validation (`ParameterValidationStubDetector`), execution errors (`FailingStubDetector`), incomplete input policies
  (`IncompleteInputStubDetector`), and duplicate finding draft collisions (`DuplicateDraftsStubDetector`).
- **Registry & Execution Determinism:** Verifies that detector execution order is strictly sorted by `DetectorId` regardless of registration
  order, and that duplicate `DetectorId`s are rejected.
- **Preflight Configuration Validation:** Verifies whole-configuration preflight validation, ensuring invalid parameters on any detector
  transactionally abort the entire run before evaluating any detector.
- **Incomplete Input Policies:** Tests `Skip` and `AllowWithLimitations` behavior, enforcing that findings on partial input without
  supporting limitations are rejected.
- **Canonical Finding & Evidence Ordering:** Verifies deterministic `FindingReference` (`find:0`, `find:1`, ...) and `EvidenceReference`
  (`evi:0`, `evi:1`, ...) assignments.
- **Referential Integrity:** Verifies that findings referencing nonexistent flows or observations are rejected.
- **Pure `std` Invariant:** Zero external dependencies added to `pcapraven-detection`.

## Phase 12 Periodic Beaconing Detection Validation (completed)

Phase 12 validation and Phase 12.1 hardening confirm:

- **Periodic Beaconing Detector Implementation:** `PeriodicBeaconingDetector` (`behavior.periodic_beaconing`, v1.0.0, policy `Skip`, severity `Low`, confidence `Medium`) implemented in `crates/pcapraven-detection/src/periodic_beaconing.rs`.
- **Directional Analysis:** Evaluates directional inter-arrival metrics for Direction A -> B (`a_to_b_inter_arrival`) and Direction B -> A (`b_to_a_inter_arrival`) independently.
- **Exact Rational Metrics & Comparisons:** Constructs exact rational ratios using `compute_duration_ratio` (cross-cancellation GCD + checked multiplication) and compares against threshold parameters (`maximum_jitter_ratio: 0..=1`, `maximum_spread_ratio: 0..=1`, `minimum_interval_samples >= 3`, `minimum_mean_interval > 0`) using `EvidenceRatio::Ord` without intermediate cross-multiplication overflow or floating-point approximation.
- **Structured Evidence Records:** Emits structured `TemporalMetric` evidence drafts with 9 canonical measurements (`discontinuity_count`, `interval_sample_count`, `maximum_interval`, `mean_absolute_successive_interval_delta`, `mean_interval`, `minimum_interval`, `relative_jitter_ratio`, `spread_ratio`, `successive_delta_sample_count`).
- **Engine Output Bounding:** Detectors emit findings into an engine-controlled bounded sink (`DetectorDraftSink`). Sink capacity exhaustion transactionally returns `DetectorExecutionStatus::ResourceLimited` with zero partial findings accepted.
- **Canonical Identity Determinism:** Accepted finding drafts are sorted canonically by `(FindingSubject, FindingTitle)` prior to sequential identifier assignment (`find:{ordinal}`, `evi:{ordinal}`).
- **Comprehensive Integration Tests:** Unit and integration tests in `crates/pcapraven-detection/tests/periodic_beaconing.rs` verify clean matches in both directions, discontinuity rejection, insufficient samples, short mean intervals, jitter/spread threshold rejections, ratio bounds `0..=1`, large `u128` values, coverage/end reason rejections, TCP/UDP qualification, and sink capacity limits.

## Phase 13 Explainable DNS Anomaly and Possible Tunneling Detection Validation (completed)

Phase 13 validation and Phase 13.1 hardening confirm:

- **DNS Anomaly and Tunneling Detector Implementations:** `DnsLongQueryNameDetector` (`dns.long_query_name`, v1.0.1, policy `Skip`, severity `Info`, confidence `Medium`) and `DnsPossibleTunnelingDetector` (`dns.possible_tunneling`, v1.1.1, policy `Skip`, severity `Low`, confidence `Medium`) implemented in `crates/pcapraven-detection/src/dns_anomaly.rs`.
- **Exact Label Octet Diversity Metric:** Computes `label_octet_diversity_ratio` using a fixed `[bool; 256]` bitmap with zero floats, zero heap allocations, and zero Shannon entropy approximations.
- **Canonical DNS Query Classification:** Enforces strict query validation (`completeness.is_complete() && message_kind == DnsMessageKind::Query && flags.qr == false`). Responses and contradictory message states are safely ignored.
- **Causally Coherent Evidence:** Finding threshold measurements derive strictly from matching questions and qualifying labels (`label.len() >= min_label_length`). Non-matching questions and short unrelated labels cannot inflate displayed evidence metrics.
- **$O(\log F)$ Binary Search Flow Lookup:** Flow existence verification and `AnalysisStopped` filtering use binary search over strictly sorted `DetectionInput::flows()`.
- **Checked Counters & Parameter Validation:** Replaces saturating arithmetic with checked addition; strictly validates `minimum_query_observations` within range `2..=u64::MAX`.
- **Engine Output Bounding & Transactional Discard:** Output capacity exhaustion records `ResourceLimited` status and transactionally discards all partial findings from the failing detector.
- **Comprehensive Integration Tests:** Integration tests in `crates/pcapraven-detection/tests/dns_anomaly.rs` and `crates/pcapraven-detection/tests/engine.rs` verify all match rules, non-matches, parameter boundaries (`u64::MAX`, `u64::MAX + 1`), multi-question causal metrics, response/contradiction exclusions, candidate ratio thresholds, flow exclusions, capacity limits, and deterministic output ordering.

## Phase 14 Explainable Repeated Low-Volume Flow Behavior and Cross-Detector Correlation Validation (completed)

Phase 14 validation confirms:

- **Finding Domain Model Extension:** Added `source_finding_references: Vec<FindingReference>` to `FindingRecord` in `crates/pcapraven-domain/src/finding.rs` with `HARD_MAX_SOURCE_FINDING_REFERENCES = 256` and strict sort/uniqueness/capacity validation. Verified via `crates/pcapraven-domain/tests/finding.rs`.
- **Repeated Low-Volume Flow Detector:** `RepeatedLowVolumeFlowDetector` (`behavior.repeated_low_volume_flows`, v1.0.0, policy `Skip`, severity `Low`, confidence `Medium`) implemented in `crates/pcapraven-detection/src/connection_behavior.rs`.
- **Canonical Peer Aggregation:** Aggregates flows using port-agnostic `ConnectionPeerKey` (`peer_a <= peer_b`), bounded by `maximum_tracked_peer_groups` ($1..=1\_000\_000$).
- **Flow Qualification & Exclusions:** Excludes flows with `AnalysisStopped`, `same_endpoint > 0`, `packet_count == 0`, and flows exceeding byte/packet caps.
- **Ordered Factual Evidence:** Emits `EvidenceKind::RatioComparison` with 6 canonical measurements in strict alphabetical order (`candidate_flow_count`, `candidate_flow_ratio`, `eligible_flow_instance_count`, `maximum_candidate_duration`, `maximum_candidate_packet_count`, `maximum_candidate_wire_bytes`).
- **Cross-Detector Correlation Pipeline:** Implemented `FindingCorrelator` trait, `CorrelationRegistry`, `CorrelationDraftSink`, and `execute_detection_with_correlators` in `crates/pcapraven-detection/src/correlation.rs` and `engine.rs`.
- **Multi-Signal C2 Correlator:** `PossibleC2MultiSignalCorrelator` (`behavior.possible_c2_multi_signal`, v1.1.1, severity `Medium`, confidence `Medium`) correlates `behavior.periodic_beaconing` + `dns.possible_tunneling` on the same flow, reusing existing evidence without redundant allocations.
- **Comprehensive Integration Tests:** Unit and integration tests in `crates/pcapraven-detection/tests/connection_behavior.rs` and `crates/pcapraven-detection/tests/correlation.rs` verify all match rules, thresholds, flow exclusions, incomplete data handling, parameter validation, multi-signal matching, partial signal rejections, and capacity bounds.

## Phase 15 Severity, Confidence, MITRE ATT&CK Mapping Provenance, and Findings CLI Validation (completed)

Phase 15 validation and Phase 15.1 hardening confirm:

- **Severity and Confidence Finalization:** Independent ordering (`info < low < medium < high < critical` and `low < medium < high`) across built-in detectors and correlators.
- **MITRE ATT&CK Enterprise Matrix v19.2 Provenance:** Full domain mapping model with explicit validation, immutable declarations, and engine provenance stamping (`T1071.004`).
- **Multi-Criteria Finding Filtering:** Multi-criteria evaluation in `pcapraven-detection::filtering::FindingFilter` supporting minimum severity, minimum confidence, detector ID, and MITRE ATT&CK technique filtering.
- **Minimal Findings CLI Inspection:** Minimal `pcapraven findings` CLI subcommand with exact filtering arguments and resource limit boundaries.

## Phase 16 Deterministic Reporting Architecture, Safe Output Files, and Unified Analysis Validation (completed)

Phase 16 validation confirms:

- **Dedicated Reporting Crate (`pcapraven-reporting`):** Pure serialization and presentation layer with full DTO schemas, maintaining `pcapraven-domain` independence without `serde`.
- **Deterministic Multi-Format Serialization:** Clean formatting across `table`, `json`, `ndjson`, and `csv` with `"schema_version": "v1.0"` root anchors.
- **CSV Formula Injection Sanitization:** Cell sanitization via `sanitize_csv_cell` ensuring any untrusted string starting with `=`, `+`, `-`, `@`, `\t`, `\r`, or `\n` is prefixed with `'`.
- **CSV Analyze Rejection Contract:** Rejection of `pcapraven analyze --format csv` with Exit Code 2, preventing ambiguous flat projections of multi-layer hierarchical analysis data.
- **Safe Output Files (`--output`):** Enforces `create_new(true)` atomic file creation, exiting with code 2 on collisions and keeping stdout clean.
- **Unified Forensic Analysis CLI (`pcapraven analyze`):** Complete multi-layer analysis orchestrating capture metadata, flows, DNS, HTTP, TLS, analytical findings, and causal evidence.

## Phase 17 Quality Gates

Phase 17 and mandatory Gate 17.1 are complete. The gate verifies:

- `tests/fixtures/pcaps/manifest.json` and `checksums.sha256` exactly match
  deterministic in-memory generated bytes, with no missing/unexpected capture,
  unknown category, provenance mismatch, or size-budget violation.
- Every one of the 20 manifest fixtures is executed through the compiled CLI
  with an exact expected exit state and behavior assertion, including malformed
  failed-before-useful inputs and detector-specific suspicious fixtures.
- The canonical scenario model covers commands/formats plus exact exit states
  0, 1, 2, and 3. Present stdout/stderr goldens are compared as bytes and absent
  paths require empty streams; golden verification never writes `tests/golden/`.
- Supported multi-section PCAPNG, useful-then-truncated PCAP, no-useful corrupt
  PCAP, canonical flow creation order, independent DNS detection beside local
  HTTP degradation, CSV formula defense, HTTP secret non-retention, and exact
  record/flow/flow-instance/observation budget limitations are regression tested.
- Representative table, JSON, NDJSON, CSV, and filtered findings runs are
  repeated with exact exit/stdout/stderr equality.
- Linux CI runs the two read-only checks below. Ubuntu, Windows, and macOS run
  locked workspace check, reporting `schema_contract`, and CLI `golden` tests
  against one canonical golden set.

```text
python3 scripts/test_verification_support.py
python3 scripts/generate_fixtures.py --check
python3 scripts/check_goldens.py
cargo test -p pcapraven-reporting --test schema_contract --locked
cargo test -p pcapraven-cli --test corpus --locked
cargo test -p pcapraven-cli --test golden --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo metadata --format-version 1 --no-deps --locked
python3 scripts/check_workspace_architecture.py
cargo +1.85.0 check --workspace --all-targets --locked
cargo +1.85.0 build --workspace --locked
cargo +1.85.0 test --workspace --locked
cargo +nightly fuzz build
python3 scripts/run_phase18_benchmarks.py --smoke
```

Phase 18 is complete. Its bounded fuzz, verifier-hardening, CI-smoke, benchmark
foundation, Phase 18.1 full fuzz acceptance campaigns, Phase 18.2 performance
baseline/budget work, and Phase 18.3 final performance acceptance are all
implemented and verified. Phase 19 remains the next, unimplemented roadmap
scope.

Phase 18 hardening also verifies that Python and Rust canonical-tree discovery
streams entries under explicit depth, examined-entry, file-count, and byte
limits; charges entries before metadata inspection; rejects symlinks and
non-regular nodes; validates every component from an explicit trusted repository
root; and detects replacements observable through pre/open/post checks. Focused
regressions place canonical files below a static symlinked ancestor and prove
that file-open/read hooks and target scans are not reached. Fixture and golden
checks must finish structural discovery and fail before manifest/golden reads or
CLI scenario execution; golden candidate staging performs the fixture preflight
before creating output or invoking the CLI. Unix device/inode checks represent
observable identity, while Windows/non-Unix metadata tuples are only portable
observable-state snapshots. Concurrent hostile local mutation of the trusted
checkout remains outside the atomicity guarantee.

DNS N-1/N/N+1 regressions cover compressed and uncompressed
CNAME messages whose aggregate expanded question, owner, and RDATA names total
39 wire bytes. This parser resource-accounting correction does not change DNS
detector identifiers, detector versions, finding semantics, report schema, or
golden report bytes.

## Phase 18.2 Performance Methodology and Baseline Evidence

The dependency-free benchmark tooling is covered by
`scripts/test_phase18_performance.py`, which verifies the finite smoke matrix,
the exact 24-scenario full matrix, all required workload scales, meaningful
two-scale reporting growth groups, integer-only budget arithmetic, and strict
rejection of invalid baseline measurements. Linux quality CI runs this focused
test and the separate `--smoke` benchmark invocation. CI does not run the full
benchmark as a performance gate and does not treat runner timing as canonical
baseline evidence.

The full benchmark methodology requires one warmup and five measured samples
for each scenario, exactly three sequential clean-revision runs, a predeclared
15% run-to-run stability limit, and predeclared integer 125% absolute and
growth budget margins. `scripts/derive_phase18_budgets.py` accepts exactly
three complete full-run JSON documents and rejects smoke, dirty, mixed-revision,
incomplete, inconsistent, duplicate, or unstable input. The official three-run
baseline was collected from clean revision
`cd98fa6164ce0a6473386e9dca841cd57c599427`; all 24 scenarios met the frozen
stability ceiling, with a maximum spread of 1,158 basis points. The raw runs
and the derived 24 absolute / 13 meaningful growth budgets are tracked under
`docs/performance/`. The final Phase 18.3 comparison passed with 24/24 median
budgets, 13/13 growth budgets, and 24/24 stability checks; the result and raw
acceptance runs are tracked under `docs/performance/`.

## Dependency Audits

### `pcap-parser = 0.17.0` (Phase 2)

The production parser dependency in `pcapraven-pcap` is exact `pcap-parser = 0.17.0`,
licensed MIT/Apache-2.0, with declared MSRV 1.65. Its default feature set is empty
and optional `data` and `serialize` features are disabled. Direct transitive footprint:
`circular 0.3`, `nom 8`, `rusticata-macros 5`. No telemetry or network behavior.

### `etherparse = 0.21.0` (Phase 3)

The production protocol parser dependency in `pcapraven-protocols` is exact
`etherparse = 0.21.0`, licensed MIT/Apache-2.0, with declared MSRV 1.83.0. Default
features are disabled. Direct transitive footprint: `arrayvec = 0.7.8`. No telemetry
or network behavior.

### `pcapraven-flows` (Phase 4 and Phase 5)

`pcapraven-flows` introduces zero third-party production dependencies.

### `pcapraven-detection` (Phase 11, Phase 12, Phase 13, Phase 14, Phase 15)

`pcapraven-detection` introduces zero third-party production dependencies (pure safe Rust and `std`).

### `serde = "1.0"`, `serde_json = "1.0"`, `csv = "1.3"` (Phase 16)

The production reporting dependencies in `pcapraven-reporting` are exact `serde = "1.0"`,
`serde_json = "1.0"`, and `csv = "1.3"`, licensed MIT/Apache-2.0. They are restricted strictly
to the `pcapraven-reporting` presentation crate. `pcapraven-domain` remains pure `std` without
any serialization dependencies. No telemetry or network behavior. Zero project `unsafe` code.

### `clap = "=4.6.4"` (Phase 6)

The production CLI dependency in `pcapraven-cli` is exact `clap = "=4.6.4"`, licensed
MIT/Apache-2.0, with declared MSRV 1.85. It uses `default-features = false` and enabled
features `["std", "help", "usage", "error-context"]`. Audited transitive tree:
`clap_builder = 4.6.2`, `clap_lex = 1.1.0`, `anstyle = 1.0.14`. Zero network or telemetry
behavior. Zero project `unsafe` code.

### `proptest = 1.11.0` (Dev-only)

The test dependency is exact `proptest = 1.11.0`, licensed MIT/Apache-2.0, with
declared MSRV 1.85. It uses `default-features = false` and only the `std` feature.
Dev-only; no telemetry or network behavior.

### `libfuzzer-sys = 0.4.13` (Fuzz-only)

The excluded fuzz package uses exact `libfuzzer-sys = 0.4.13`, licensed
`(MIT OR Apache-2.0) AND NCSA`. It is excluded from the production workspace and
runtime.

### `serde_json = 1.0.140` (Fuzz-only reuse)

The excluded fuzz package reuses the exact already-locked reporting version
with `default-features = false` and `features = ["alloc"]`. It validates emitted
JSON/NDJSON records and exercises bounded malformed JSON values. This does not
add a dependency to any runtime crate.

### `csv = 1.3.1` (Fuzz-only reuse)

The excluded fuzz package reuses exact `csv = 1.3.1` with
`default-features = false` to parse emitted CSV structurally in the reporting
harness. This is an already-locked reporting dependency, adds no runtime crate
dependency, performs no network or telemetry activity, and retains its
MIT/Apache-2.0 licensing.

## Test Quality Rules

- Tests must be deterministic and offline by default.
- Tests must not depend on wall-clock timing, hash iteration order, or public
  services.
- Security limits need exact boundary tests and failure-path assertions.
- A parser success test needs malformed and truncated counterparts.
- Detector tests need benign alternatives and non-match cases.
- Machine output tests validate syntax, schema semantics, ordering, and stdout
  purity.
- Tests may not hide panics or accept broad output merely to tolerate defects.
