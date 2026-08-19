# Roadmap to v1.0.0

## Status and Rules

The phases below are ordered gates. Later work may be researched, but it must
not be implemented before its prerequisite phase is accepted. Completion means
the phase deliverables, tests, documentation, and security review are complete;
it does not mean all later capabilities are available.

Phase 0, Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, Phase 6, Phase 7, Phase 8, Phase 9, Phase 10, Phase 11, Phase 12, Phase 13, and Phase 14 are complete.
Phase 14 delivered explainable repeated low-volume flow behavior detection in `pcapraven-detection` (`RepeatedLowVolumeFlowDetector`, `behavior.repeated_low_volume_flows`)
and deterministic cross-detector finding correlation (`PossibleC2MultiSignalCorrelator`, `behavior.possible_c2_multi_signal`)
over normalized flow statistics and temporal metrics, featuring canonical `ConnectionPeerKey` aggregation, 5 factual traffic measurements,
finding domain model extension (`source_finding_references`), zero new evidence allocation during correlation, and comprehensive integration tests
in `crates/pcapraven-domain/tests/finding.rs`, `crates/pcapraven-detection/tests/connection_behavior.rs`, and `crates/pcapraven-detection/tests/correlation.rs`.
Phase 15 (severity, confidence, filtering, and MITRE ATT&CK mappings) is next.

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

Implemented bounded DNS wire-format parsing over normalized transport data and emitted
normalized DNS observations in `pcapraven-protocols` and `pcapraven-domain`. Classified
candidate traffic on UDP and TCP port 53, decoded length-prefixed TCP frames, applied
strict backward-pointer decompression rules (`target_offset < pointer_location_offset`) to
prevent pointer loops and cycles, parsed standard RR types (A, AAAA, CNAME, NS, PTR, MX),
decoded EDNS(0) OPT pseudo-records (extended RCODE, DO bit, options), rendered terminal-safe
domain name escaping (`\DDD`), implemented the `pcapraven dns <capture>` CLI inspection
command, and added synthetic micro-fixtures, unit tests, property tests, and the `fuzz_dns_parser`
target. Threat detection heuristics and application decoders for HTTP/TLS remain future work.

## Phase 8 - HTTP/1.x metadata analysis

Implemented bounded cleartext HTTP/1.0 and HTTP/1.1 message header parsing and
normalized HTTP observation extraction in `pcapraven-protocols` and `pcapraven-domain`.
Classified candidate traffic on TCP port 80, implemented packet-local start-line and
strict header parsing without cross-packet TCP reassembly, body retention, chunked
decoding, or decompression. Parsed HTTP methods, request targets, 3-digit status codes,
and selected headers (Host, User-Agent, Server, Content-Type, Content-Length,
Transfer-Encoding, Connection, Upgrade). Enforced sensitive header privacy protections
for Authorization, Proxy-Authorization, Cookie, and Set-Cookie by recording boolean
presence flags without retaining or serializing header values. Enforced RFC 9112 / 7230
validation rules including mandatory Host header in HTTP/1.1 requests, rejection of
duplicate Host headers, rejection of obs-fold line folding, rejection of bare CR/LF,
rejection of whitespace before colon, validation of non-conflicting Content-Length, and
detection of conflicting Transfer-Encoding / Content-Length framing. Implemented
terminal-safe byte string escaping (`display_escaped()`), the `pcapraven http <capture>`
CLI inspection command with exit code contracts (0 complete, 1 failure, 2 usage, 3 partial),
end-to-end integration tests in `crates/pcapraven-cli/tests/cli.rs`, unit and property
tests in `crates/pcapraven-protocols/tests/http.rs`, and the `fuzz_http_parser` fuzz target.
Threat detection heuristics and TLS decoders remain future work.

## Phase 9 - TLS handshake metadata analysis

Implemented bounded visible TLS 1.2 and TLS 1.3 handshake metadata analysis
and normalized TLS observation extraction in `pcapraven-protocols` and `pcapraven-domain`.
Classified candidate traffic on TCP port 443, implemented packet-local record parsing
and adjacent multi-record handshake assembly up to `maximum_handshake_message_bytes`
without cross-packet TCP stream reassembly. Parsed `ClientHello`, `ServerHello`, and
`HelloRetryRequest` (detected via RFC 9846 SHA-256 random sentinel). Decoded extensions
including SNI (Server Name Indication), Supported Versions (RFC 9846), Supported Groups,
Signature Algorithms, ALPN (Application-Layer Protocol Negotiation), Key Share (group ID
only), Pre-Shared Key (presence flag only), and Early Data (presence flag only). Enforced
strict privacy non-retention invariants: zero retention of raw 32-byte randoms, session ID
bytes, key exchange public bytes, PSK identities/binders, early data payloads, certificate DER,
or ciphertext bytes, with zero payload decryption or private key loading. Enforced finite
resource bounds on records, messages, bytes, ciphers, extensions, versions, groups, schemes,
and server name lengths. Implemented terminal-safe byte string escaping (`display_escaped()`),
the `pcapraven tls <capture>` CLI inspection command with exact exit codes (0 complete, 1 failure,
2 usage, 3 partial), end-to-end integration tests in `crates/pcapraven-cli/tests/cli.rs`, unit,
boundary, and property tests in `crates/pcapraven-protocols/tests/tls.rs`, and the `fuzz_tls_parser`
fuzz target. Threat detection heuristics and correlation remain future work.

## Phase 10 - Unified protocol observations and evidence

Implemented unified protocol observations across DNS, HTTP, and TLS in `pcapraven-domain`
(`ProtocolObservationData`, `ProtocolObservation`, `ObservationFlowAssociation`, `ProtocolObservationCollection`),
explicit flow reconstruction exclusion reasons (`FlowExclusionReason`), and structured evidence records
(`EvidenceRecord`, `EvidenceMeasurement`, `EvidenceRatio`, `SchemaVersion`). Enforced exact rational
arithmetic in canonical lowest terms with Euclidean continued-fraction total ordering (zero floats,
zero overflow), bounded descriptions/identifiers with terminal safety, explicit analysis limitations,
pure `std` domain invariants, and comprehensive integration testing in `crates/pcapraven-domain/tests/observation_evidence.rs`.
Detection engine architecture is complete; periodic beaconing detection remains future work.

## Phase 11 - Detection engine architecture

Implemented detector registration/execution contracts, stable identifiers (`DetectorId`) and
versions (`DetectorVersion`), deterministic finding identity (`FindingReference`), parameter validation
with whole-configuration preflight (`DetectorParameters`), evidence requirements (`FindingRecord`, `FindingDraft`),
referential integrity verification, and incomplete-data policies (`IncompleteDataPolicy`). Implemented pure
`Detector` trait, `DetectorRegistry`, and `execute_detection` in `pcapraven-detection`, finding domain models in
`pcapraven-domain`, and comprehensive integration tests in `crates/pcapraven-detection/tests/engine.rs`.
Specific behavioral detector families remain future work.

## Phase 12 - Periodic beaconing detection

Implemented explainable periodic beaconing detection (`PeriodicBeaconingDetector`, `behavior.periodic_beaconing`)
over exact directional flow temporal metrics in `pcapraven-detection`. Evaluated inter-arrival timing statistics
independently for both flow directions (`A -> B` and `B -> A`), applying exact rational thresholds for sample count
($N \ge \text{minimum\_interval\_samples}$, default 6, minimum 3), mean duration ($\mu \ge \text{minimum\_mean\_interval}$, default 1s),
jitter ratio ($\delta_{MAD} / \mu \le \text{maximum\_jitter\_ratio}$, default 10%), and spread ratio
($(\text{max} - \text{min}) / \mu \le \text{maximum\_spread\_ratio}$, default 25%). Enforced clean timestamp invariants
(`discontinuity_count == 0`), exact rational ratio construction (`compute_duration_ratio` with cross-cancellation GCD)
and `EvidenceRatio::Ord` total comparison without floating-point numbers (`f32`/`f64`) or intermediate cross-multiplication
overflow, single finding per matching flow with up to 2 directional `TemporalMetric` evidence drafts,
and cautious explanatory wording avoiding uncorroborated malware or C2 claims. Implemented comprehensive integration
tests in `crates/pcapraven-detection/tests/periodic_beaconing.rs`, detector documentation in `docs/detectors/PERIODIC_BEACONING.md`,
and the `periodic-beaconing` skill in `.agents/skills/periodic-beaconing/SKILL.md`.
DNS anomaly/tunneling heuristics and C2-like behavioral rules remain future work.

## Phase 13 - DNS anomaly/tunneling heuristics

Implemented explainable DNS anomaly and possible tunneling detectors (`DnsLongQueryNameDetector`, `dns.long_query_name`,
and `DnsPossibleTunnelingDetector`, `dns.possible_tunneling`) over normalized DNS observations in `pcapraven-detection`.
Implemented the exact rational `label_octet_diversity_ratio` metric using fixed `[bool; 256]` bitmap memory without
floating-point arithmetic or Shannon entropy approximations. Enforced strict parameter validation, finite flow-tracking
capacity (`maximum_tracked_dns_flows`), structured evidence measurements with comparison operators, terminal-safe
string escaping, and cautious non-attribution rationales covering benign high-diversity lookups. Implemented comprehensive
integration tests in `crates/pcapraven-detection/tests/dns_anomaly.rs`, detector documentation in `docs/detectors/DNS_ANOMALY_TUNNELING.md`,
and the `dns-detection` skill in `.agents/skills/dns-detection/SKILL.md`.
## Phase 14 - Connection/C2-like behavioral heuristics

Implemented explainable repeated low-volume flow behavior detector (`RepeatedLowVolumeFlowDetector`, `behavior.repeated_low_volume_flows`)
and deterministic cross-detector finding correlation (`PossibleC2MultiSignalCorrelator`, `behavior.possible_c2_multi_signal`) in `pcapraven-detection`.
Aggregated flows using port-agnostic `ConnectionPeerKey` (`peer_a <= peer_b`), evaluated 5 factual traffic measurements (`flow_count`, `maximum_flow_bytes`,
`maximum_flow_packets`, `total_aggregate_bytes`, `total_aggregate_packets`), extended the finding domain model with `source_finding_references`,
and implemented the post-evaluation correlation pipeline reusing existing primary evidence without redundant allocations or unevidenced malware/C2 assertions.
Delivered comprehensive integration tests in `crates/pcapraven-domain/tests/finding.rs`, `crates/pcapraven-detection/tests/connection_behavior.rs`,
and `crates/pcapraven-detection/tests/correlation.rs`, detector documentation in `docs/detectors/CONNECTION_C2_BEHAVIOR.md`,
and the `connection-behavior-detection` and `finding-correlation` skills.
Severity/confidence assignment, CLI filtering, and MITRE ATT&CK mappings remain future work.

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
