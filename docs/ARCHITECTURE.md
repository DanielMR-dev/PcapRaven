# Architecture

## Status

Phase 0 product and architecture definition, Phase 1 workspace/tooling work,
Phase 2 capture-container ingestion, Phase 3 packet normalization, Phase 4
bidirectional flow reconstruction, Phase 5 checked flow statistics and exact
temporal metrics, Phase 6 initial functional CLI with streaming capture and
flow inspection, Phase 7 bounded DNS protocol analysis, Phase 8 bounded HTTP/1.x
protocol analysis, Phase 9 bounded visible TLS 1.2 / TLS 1.3 handshake
metadata analysis, Phase 10 unified protocol observations and structured evidence
foundation, and Phase 11 detection engine architecture are complete.
`pcapraven-domain` defines normalized packet, flow, DNS, HTTP, TLS, observation,
evidence, and finding models, statistics, and exact temporal metrics,
`pcapraven-pcap` provides capture ingestion, `pcapraven-protocols` provides packet normalization,
DNS parsing, HTTP/1.x parsing, and TLS handshake parsing, `pcapraven-flows` provides stateful
flow reconstruction, traffic statistics, and exact rational temporal metrics,
`pcapraven-detection` provides detection engine execution pipeline, detector registry,
and parameter configuration, and `pcapraven-cli` provides the functional CLI.
Phase 12 (periodic beaconing detection), threat detection heuristics, and reporting remain future work.

## Architectural Principles

- Keep the domain model independent of capture formats, presentation, and CLI
  frameworks.
- Convert external bytes into bounded normalized records before higher layers
  consume them.
- Separate parsing from detection: parsers report facts; detectors interpret
  normalized facts.
- Make evidence references and incomplete-data state explicit.
- Prefer deterministic data transformations and stable ordering.
- Preserve recoverable diagnostics without turning every malformed record into
  a whole-capture failure.
- Keep library crates usable independently of the CLI.
- Enforce one-way dependency direction and prohibit circular dependencies.
- Treat resource limits and error context as parts of the API contract.
- Use safe Rust in project code by default.

## Phase 1 Workspace

The Rust Edition 2024 Cargo workspace contains exactly these initial
architectural crates:

```text
crates/
  pcapraven-domain/
  pcapraven-pcap/
  pcapraven-protocols/
  pcapraven-flows/
  pcapraven-detection/
  pcapraven-reporting/
  pcapraven-cli/
```

The `pcapraven-cli` package has one binary target named `pcapraven`; the other
six packages each have one library target.

The workspace is virtual, uses resolver 3, and applies version `0.0.0`, license
`MIT`, `publish = false`, and Rust `1.85` as workspace package metadata. The
development toolchain is pinned separately in `rust-toolchain.toml` and is
intentionally newer than the declared MSRV. The only dependencies are the
documented path edges below and the audited external dependencies. Every member
opts into the workspace lint policy, which forbids project `unsafe` code by default.

The source files for detection and reporting packages remain
compile-only documentation skeletons. They do not define business behavior or
implement analysis.

## Phase 2 Capture-Container Boundary

`pcapraven-pcap` is the only package that reads capture-container bytes. Its
public reader accepts a generic `std::io::Read + Send` source and does not access
the filesystem or expose `pcap-parser` types. It returns owned packet bytes,
capture metadata, fixed diagnostic messages with structured locations, and an
explicit complete, partial, or failed-before-useful-records state.

The supported Phase 2 subset is legacy PCAP in both byte orders with
microsecond/nanosecond precision, and PCAPNG section headers, interface
descriptions, enhanced packet blocks, and simple packet blocks. PCAPNG interface
descriptions are assigned positional slots within each section; malformed IDBs
are recorded as unusable slots so that subsequent interface indexing and EPB/SPB
resolution remain strictly deterministic without shift. PCAPNG interface
timestamp resolution and signed offsets are section-local, and section
boundaries reset interface state. Unsupported valid blocks are skipped only
after the low-level parser establishes their boundary; malformed or incomplete
input is never guessed through.

The default finite limits are: 64 KiB initial buffer, 4 MiB maximum buffer and
block, 1 MiB individual packet bytes, 16 MiB aggregate retained packet bytes for
collection, 1,024 interfaces per section, 1,024 sections, 256 diagnostics,
100,000 emitted records, and 1,000,000 processed blocks. Validation also enforces
nonzero limits, `initial_buffer_size <= maximum_buffer_size`, and
`maximum_packet_bytes <= maximum_block_size <= maximum_buffer_size`; hard caps
prevent callers from raising these budgets beyond 64 MiB for byte/block/retention
limits, 65,536 sections/interfaces, 1,000,000 diagnostics, or 10,000,000
records/blocks. `CaptureReader` is strictly streaming and emits records without
internal accumulation; convenience collection functions enforce the aggregate
retained packet byte budget.

Phase 2 uses `pcap-parser = 0.17.0` as a normal dependency with default,
`data`, and `serialize` features disabled. The parser dependency is kept behind
the capture crate boundary. `proptest = 1.11.0` is dev-only for capture tests.
The excluded `fuzz/` package is not part of the seven-package production graph.

## Phase 3 Protocol Normalization Boundary

`pcapraven-protocols` transforms opaque packet bytes into capture-independent
domain facts defined in `pcapraven-domain`. It accepts borrowed
`PacketNormalizationInput` records and normalizes:

- Link layer: `LINKTYPE_ETHERNET = 1` and standard Ethernet II headers.
- Network layer: IPv4 (with header length, DSCP/ECN, total length bounds,
  fragmentation classification, and Ethernet padding exclusion) and IPv6 (with
  traffic class, flow label, bounded extension header traversal, fragmentation
  classification, and padding exclusion).
- Transport layer: TCP (ports, seq/ack numbers, flags, options length, checksum,
  and bounded application payload) and UDP (ports, length validation, checksum,
  and bounded application payload).
- Explicit diagnostics and completeness states (`Complete`, `Partial`, or
  `Unsupported`) without panicking or guessing.

Default finite limits for normalization: 4 KiB maximum retained transport
application payload bytes (hard cap 64 MiB), 16 maximum diagnostics per packet
(hard cap 1,024), 8 maximum IPv6 extension headers (hard cap 64), and 2 KiB
maximum IPv6 extension bytes (hard cap 64 KiB).

Phase 3 uses `etherparse = 0.21.0` as a normal dependency in `pcapraven-protocols`
with default features disabled. `proptest = 1.11.0` is dev-only. `pcapraven-protocols`
depends only on `pcapraven-domain` and does not depend on `pcapraven-pcap`.

## Phase 4 Bidirectional Flow Reconstruction Boundary

`pcapraven-flows` reconstructs bidirectional communication streams from normalized
packet domain facts (`NormalizedPacket`) into deterministic flow identities:

- **Flow Domain Representations:** `pcapraven-domain` defines `FlowEndpoint`,
  `FlowKey`, `FlowDirection`, `FlowReference`, `FlowPacketAssociation`,
  `FlowEndReason`, and `FlowRecord`.
- **Canonical Ordering:** Endpoints are canonicalized by binary total ordering
  (`endpoint_a <= endpoint_b`). Reversing the observed direction yields the
  identical `FlowKey`.
- **Direction Semantics:** Relative packet direction is explicitly classified as
  `AToB`, `BToA`, or `SameEndpoint` (for synthetic same IP/port packets).
- **Packet Stream Ordering:** Requires strictly increasing `capture_record_ordinal`
  values in capture stream order. Input is never reordered.
- **Lifecycle Boundaries:**
  - Idle timeouts: integer-only timestamp comparisons (default 300s for TCP, 60s for UDP).
  - TCP SYN retransmissions: initial SYNs before handshake completion remain in the same flow.
  - TCP new initial SYN: initial SYN observed after activity closes the prior flow (`TcpNewInitialSyn`)
    and creates a new flow reference.
  - TCP reset: RST associates with the current flow and then immediately closes it (`TcpReset`).
  - TCP FIN: conservative policy (FIN does not force immediate closure without timeout or termination).
- **Memory Non-Retention:** Active flow state retains only scalar and reference lifecycle
  metadata (`FlowReference`, `FlowKey`, first/last `PacketReference`, timestamp anchor, TCP phase).
  It never retains packet payload or `NormalizedPacket` structs.
- **Resource Bounds:** Finite limits on `maximum_tracked_flows` (default 65,536, hard cap 1,000,000)
  and `maximum_flow_instances` (default 1,000,000, hard cap 10,000,000).

Phase 4 established deterministic flow reconstruction with dev-only `proptest = 1.11.0`.
`pcapraven-flows` depends only on `pcapraven-domain`.

## Phase 5 Checked Flow Statistics and Exact Temporal Metrics Boundary

`pcapraven-flows` extends active flow reconstruction with checked traffic accumulation
and exact rational temporal metric calculations:

- **Domain Types:** `pcapraven-domain` defines `FlowTrafficCounters`,
  `FlowTrafficStatistics`, `FlowDuration`, `FlowTemporalUnavailableReason`,
  `FlowTemporalValue`, `FlowTimestampCoverage`, `FlowInterArrivalMetrics`, and
  `FlowTemporalMetrics`.
- **Directional Counters:** Accumulates `packet_count`, `captured_bytes`, `wire_bytes`,
  and `truncated_packet_count` across `total`, `a_to_b`, `b_to_a`, and `same_endpoint`
  buckets. Enforces the invariant `total == a_to_b + b_to_a + same_endpoint`.
- **Exact Rational Duration:** All flow durations, intervals, means, successive deltas,
  and timeouts are represented as exact rational numbers (`FlowDuration` with
  `numerator: u128`, `denominator: u128`) reduced to lowest terms by GCD. Floats
  (`f32`/`f64`) are strictly forbidden.
- **Timestamp Arithmetic:** Supports decimal and binary timestamp resolutions and signed
  offsets. Missing, invalid, and non-monotonic timestamps break sequence chains without
  bridging intervals or producing negative durations.
- **Fixed-Size Online Accumulators:** Active flow state uses scalar accumulators
  ($O(1)$ memory per active flow). Vector collections of timestamps, intervals, or
  payload bytes in active state are forbidden.
- **Error Transactionality:** An `observe()` call that fails (`Err`) leaves active flows,
  packet ordinals, and allocated references completely unmodified.

Phase 5 adds no new production dependencies; `proptest = 1.11.0` remains dev-only.

## Phase 6 Initial Functional CLI and Streaming Orchestration Boundary

`pcapraven-cli` provides the binary orchestration layer for streaming capture validation
and flow inspection:

- **Implemented Commands:** Implements `pcapraven validate <capture>` and
  `pcapraven flows <capture>`. Future subcommands (`analyze`, `dns`, `http`, `tls`, `findings`)
  remain unimplemented and are not advertised in `--help`.
- **Streaming Pipeline:** Incremental record streaming connects `CaptureReader::next_record()`
  to `normalize_packet()` to `FlowReconstructor::observe()`. Emits closed `FlowRecord` rows
  immediately without whole-capture packet retention.
- **Truthful Finalization:** Clean end-of-input finalizes remaining flows with
  `FlowEndReason::EndOfInput` via `finish()`; early/abnormal stop finalizes with
  `FlowEndReason::AnalysisStopped` via `finish_partial()`.
- **Exit Code Contract:** Exactly defines:
  - `0`: Successful complete command execution.
  - `1`: Fatal input, I/O, or analysis failure before any useful result was produced.
  - `2`: Usage or configuration error.
  - `3`: Useful result produced, but analysis/validation was partial.
- **Stream Separation:** `stdout` is reserved strictly for requested factual results (validation
  summary or flow table). `stderr` is reserved for diagnostics and fatal errors. Zero ANSI color.
- **Bounded Diagnostics:** Stderr nonfatal diagnostics are capped at 100 lines default, followed
  by a single suppression summary line unless `--quiet`.
- **Presentation Exception:** Prior to Phase 16 formal reporting, `pcapraven-cli` implements minimal
  factual table rendering for human stdout inspection.
- **Audited Dependency:** Adds `clap = "=4.6.4"` with `default-features = false` and features
  `["std", "help", "usage", "error-context"]`.

## Phase 7 DNS Protocol Analysis Boundary

`pcapraven-protocols` derives bounded DNS observations from normalized packet transport
data (`NormalizedPacket`), and `pcapraven-domain` defines the capture-independent DNS models:

- **DNS Domain Models:** `pcapraven-domain` defines `DnsTransport`, `DnsMessageKind`, `DnsFlags`,
  `DnsName`, `DnsQuestion`, `DnsSection`, `DnsRdataMetadata`, `DnsResourceRecord`, `DnsEdnsOptionMetadata`,
  `DnsEdnsMetadata`, `DnsObservationCompleteness`, `DnsObservation`, `DnsDiagnosticKind`, and `DnsDiagnostic`.
- **Domain Name Invariants:** `DnsName` preserves raw wire label bytes with RFC 1035 bounds
  (label length $\le 63$, expanded wire length $\le 255$) and provides terminal-safe `display_escaped()`
  rendering (`\DDD` notation) preventing ANSI escape code injection.
- **Candidate Selection:** Transparent candidate classification on UDP and TCP port 53.
- **Decompression Invariants:** Enforces strict backward-only pointer rules (`target_offset < pointer_location_offset`),
  eliminating compression self-loops, cycle recursion, and forward pointers. Pointer traversal is bounded by
  `maximum_name_pointer_hops`.
- **Framing:** UDP single message processing and TCP 2-byte length-prefixed framing up to `maximum_messages_per_packet`
  without cross-packet TCP stream reassembly.
- **Record Decoding:** Decodes standard RR types (A, AAAA, CNAME, NS, PTR, MX) with strict RDLENGTH validation
  and extracts EDNS(0) OPT pseudo-record metadata (UDP size, extended RCODE, DO bit, bounded option TLVs).
- **CLI Inspection:** `pcapraven dns <capture>` streams capture reading and immediately renders factual
  inspection tables to stdout with exact exit codes (0, 1, 2, 3).
- **Zero Production Dependencies:** Implemented with safe Rust and `std`; `proptest = 1.11.0` is dev-only.

## Phase 8 HTTP/1.x Metadata Analysis Boundary

`pcapraven-protocols` derives bounded HTTP/1.x observations from normalized packet transport
data (`NormalizedPacket`), and `pcapraven-domain` defines the capture-independent HTTP models:

- **HTTP Domain Models:** `pcapraven-domain` defines `HttpVersion`, `HttpMessageKind`, `HttpByteString`,
  `HttpRequestMetadata`, `HttpResponseMetadata`, `HttpContentLengthState`, `HttpSelectedHeaders`,
  `HttpFramingMetadata`, `HttpObservationCompleteness`, `HttpObservation`, `HttpDiagnosticKind`,
  and `HttpDiagnostic`.
- **Candidate Selection:** Transparent candidate classification on cleartext TCP port 80.
- **Packet-Local Scope:** Parses start-lines and headers on packet boundaries without cross-packet
  TCP stream reassembly, body retention, chunked body decoding, or decompression.
- **RFC 9112 / 7230 Hardened Parser:** Enforces canonical CRLF line endings (bare CR/LF rejected),
  rejects whitespace before colon, rejects obs-fold line folding, enforces mandatory Host header
  on HTTP/1.1 requests, rejects duplicate Host headers, parses decimal Content-Length, and detects
  conflicting Transfer-Encoding / Content-Length framing.
- **Privacy Controls:** Enforces sensitive header masking (Authorization, Proxy-Authorization, Cookie,
  Set-Cookie) by capturing boolean presence flags without retaining header values.
- **Terminal Safety:** `HttpByteString::display_escaped()` renders bytes safely in `\xHH` / `\\` notation,
  preventing terminal escape sequence injection.
- **CLI Inspection:** `pcapraven http <capture>` streams capture reading and renders factual
  inspection tables to stdout with exact exit codes (0, 1, 2, 3).
- **Zero Production Dependencies:** Implemented with safe Rust and `std`; `proptest = 1.11.0` is dev-only.

## Phase 9 TLS Handshake Metadata Analysis Boundary

`pcapraven-protocols` derives bounded TLS 1.2 / TLS 1.3 handshake observations from normalized
packet transport data (`NormalizedPacket`), and `pcapraven-domain` defines the capture-independent TLS models:

- **TLS Domain Models:** `pcapraven-domain` defines `TlsVersion`, `TlsRecordContentType`,
  `TlsHandshakeKind`, `TlsByteString`, `TlsExtensionMetadata`, `TlsClientHelloMetadata`,
  `TlsServerHelloMetadata`, `TlsObservationCompleteness`, `TlsObservation`, `TlsDiagnosticKind`,
  and `TlsDiagnostic`.
- **Standards Baseline:** RFC 9846 (published July 2026) is the current standard for TLS 1.3
  (obsoleting RFC 8446). RFC 5246 is historical reference for TLS 1.2.
- **Candidate Selection:** Transparent candidate classification on TCP port 443 (source or destination).
  UDP/443 and non-443 traffic are excluded deterministically (`NotTlsCandidate`). Non-TLS payloads on
  TCP 443 are classified safely as `CandidateWithoutRecord`.
- **Packet-Local Multi-Record Assembly:** Handshake messages spanning adjacent Handshake records within
  the *same* packet are assembled up to `maximum_handshake_message_bytes`. Cross-packet TCP stream
  reassembly is strictly forbidden.
- **Privacy Non-Retention Invariants (MANDATORY):**
  - Raw 32-byte ClientHello / ServerHello random values are NEVER retained (only inspected transiently for the HRR sentinel).
  - Session ID bytes are NEVER retained (only `session_id_length` is recorded).
  - Key Share public key bytes are NEVER retained (only named group IDs are recorded).
  - PSK identities and binders are NEVER retained (only boolean presence flag).
  - Early Data payloads are NEVER retained (only boolean presence flag).
  - Certificate DER and ciphertext payloads are NEVER retained.
  - Zero TLS decryption, private key loading, or `SSLKEYLOGFILE` support.
- **Terminal Safety:** `TlsByteString::display_escaped()` renders strings in deterministic `\xHH` / `\\` notation,
  preventing terminal escape sequence injection.
- **CLI Inspection:** `pcapraven tls <capture>` streams capture reading and renders factual inspection
  tables to stdout with exact exit codes (0, 1, 2, 3).
- **Zero Production Dependencies:** Implemented with safe Rust and `std`; `proptest = 1.11.0` is dev-only.

## Phase 10 Unified Protocol Observations and Structured Evidence Boundary

`pcapraven-domain` defines the unified application protocol observation architecture, explicit flow associations,
and structured evidence foundation:

- **Observation Domain Models:** `pcapraven-domain` defines `ProtocolKind`, `ObservationReference`,
  `ObservationCompleteness`, `ObservationFlowAssociation`, `ProtocolObservationData`, `ProtocolObservation`,
  `ProtocolObservationCollection`, and `ProtocolObservationCollectionError`.
- **Unified Observation Architecture:** Wraps DNS, HTTP, and TLS observations in typed `ProtocolObservationData`,
  maintaining explicit packet provenance (`PacketReference`), explicit flow association (`ObservationFlowAssociation`:
  `Associated`, `Excluded`, `Unassociated`), and derived/explicit completeness.
- **Evidence Domain Models:** `pcapraven-domain` defines `SchemaVersion`, `EvidenceReference`, `EvidenceKind`,
  `EvidenceDescription`, `EvidenceMetricKey`, `EvidenceRatio`, `EvidenceUnit`, `EvidenceValue`, `EvidenceComparison`,
  `EvidenceMeasurement`, `EvidenceLimitation`, and `EvidenceRecord`.
- **Exact Rational Arithmetic:** `EvidenceRatio` guarantees exact rational ratios (`numerator / denominator`)
  in canonical lowest terms via GCD. Compares with exact Euclidean continued-fraction algorithms without floats
  (`f32`/`f64`) or integer overflow.
- **Separation of Facts from Detection:** Evidence records capture immutable factual measurements supporting
  findings, referencing packets, flows, and observations by reference without copying raw bytes.
- **Terminal Safety & Privacy:** Descriptions and metric keys sanitize control characters and enforce length bounds;
  sensitive credentials/payloads are never retained.
- **Schema Versioning:** `SchemaVersion::CURRENT` (`v1.0`) anchors evidence records for forward/backward compatibility.
- **Zero External Dependencies:** Implemented purely with safe Rust and `std`.

## Phase 11 Detection Engine Architecture Boundary

`pcapraven-detection` implements the detector evaluation engine, deterministic registry, preflight configuration
validation, and canonical finding/evidence generation over borrowed domain facts:

- **Finding Domain Models:** `pcapraven-domain` defines `DetectorId`, `DetectorVersion`, `FindingReference`,
  `FindingSubject`, `FindingTitle`, `FindingSummary`, `FindingRationale`, `FindingDraft`, `FindingRecord`,
  `Severity`, `Confidence`, and `FindingValidationError`.
- **Pure Detector Trait:** `Detector` declares pure analytical functions (`metadata()`, `validate_parameters()`,
  `evaluate()`) evaluated solely over borrowed domain facts (`DetectionInput`) and validated parameters.
  Detectors perform zero network, filesystem, or process side effects.
- **Whole-Configuration Preflight Validation:** Validates all detector configurations prior to executing any
  detector. If any detector configuration fails validation, execution halts transactionally without evaluating
  any detector.
- **Deterministic Registry:** `DetectorRegistry` enforces bounded capacity (default 64, hard 256), duplicate
  `DetectorId` rejection (even across different versions), and strictly sorted execution order by canonical
  `DetectorId`.
- **Incomplete Data Policies:** `IncompleteDataPolicy` enforces deterministic handling of partial traffic inputs:
  - `Skip`: Skips detector evaluation on partial input (`DetectorExecutionStatus::SkippedIncompleteData`).
  - `AllowWithLimitations`: Evaluates on partial input, requiring all emitted findings to contain explicit
    `EvidenceLimitation` items.
- **Canonical Determinism & Identity Assignment:** Accepted finding drafts are deterministically sorted by
  `(DetectorId, FindingSubject, Title)` and assigned sequential, immutable `FindingReference` and `EvidenceReference`
  identifiers. Duplicate finding keys `(DetectorId, FindingSubject)` within a detector are strictly rejected.
- **Zero Float Discipline:** All detection parameter models, ratio calculations, and thresholds operate exclusively
  over integers, `FlowDuration`, and `EvidenceRatio`.

## Crate Responsibilities

The crates have the following responsibilities:

### `pcapraven-domain`

Owns capture-independent domain types and invariants: normalized packet
metadata (`NormalizedPacket`, `EthernetMetadata`, `Ipv4Metadata`, `Ipv6Metadata`,
`TcpMetadata`, `UdpMetadata`, `FragmentationState`, `TcpFlags`), endpoints
(`FlowEndpoint`), flow keys (`FlowKey`), flow references (`FlowReference`),
directions (`FlowDirection`), associations (`FlowPacketAssociation`), completed
records (`FlowRecord`), end reasons (`FlowEndReason`), traffic statistics
(`FlowTrafficStatistics`, `FlowTrafficCounters`), temporal metrics (`FlowDuration`,
`FlowTemporalMetrics`, `FlowInterArrivalMetrics`), DNS observations (`DnsObservation`),
HTTP observations (`HttpObservation`), TLS observations (`TlsObservation`),
protocol observations (`ProtocolObservation`), evidence (`EvidenceRecord`, `EvidenceMeasurement`),
findings (`FindingRecord`, `FindingSubject`, `DetectorId`, `DetectorVersion`, `Severity`, `Confidence`),
diagnostics, and analysis result metadata. It contains no capture parser, protocol parser, CLI,
terminal, filesystem orchestration, detector implementation, or serializer-specific logic.

### `pcapraven-pcap`

Owns capture ingestion only: safe reading of PCAP/PCAPNG containers, capture
record metadata, bounded extraction of packet bytes, interface/link metadata,
and capture-level diagnostics. It exposes a zero-allocation adapter converting
`CaptureRecord` into `pcapraven_domain::PacketNormalizationInput`. It does not
decode Ethernet, IP, TCP, UDP, DNS, HTTP, or TLS; reconstruct flows; detect
threats; format reports; or interact with users.

### `pcapraven-protocols`

Owns normalization of supported network and application protocol data. Normalizes
Ethernet, IPv4, IPv6, TCP, and UDP into domain packet observations, and parses bounded
DNS wire messages, cleartext HTTP/1.x headers, and visible TLS 1.2 / TLS 1.3 handshake
metadata into normalized observations. It does not read capture container files,
reconstruct global flow state, assign security findings, serialize reports, or
implement CLI behavior.

### `pcapraven-flows`

Owns bidirectional communication reconstruction, canonical flow keys,
direction assignment, lifecycle state management, checked traffic counter
accumulation, and exact rational temporal metric calculations. It consumes
normalized domain packet metadata and does not parse capture containers or
application protocols, produce security findings, serialize reports, or
interact with users.

### `pcapraven-detection`

Owns the detection engine execution pipeline, detector registry, parameter configuration
validation, and detector traits. It consumes normalized domain observations and flow
information. It does not parse external bytes, mutate parser results, own report formatting,
or handle CLI interaction.

### `pcapraven-reporting`

Owns deterministic serialization and presentation of domain analysis results
in supported output formats. It does not ingest captures, parse protocols,
reconstruct flows, run detectors, or define finding semantics. It may define
format-specific adapters, schemas, and escaping rules while consuming canonical
domain results.

### `pcapraven-cli`

Owns argument parsing, user interaction, file selection, pipeline orchestration,
configuration of limits and filters, exit status mapping, and stdout/stderr
routing. It delegates all analysis and serialization to library crates and
contains no packet parser, flow algorithm, protocol parser, detector, or report
encoder.

## Dependency Direction

The domain crate is the shared foundation. The allowed direct dependencies are:

| Crate | May depend on project crates |
| --- | --- |
| `pcapraven-domain` | None |
| `pcapraven-pcap` | `pcapraven-domain` |
| `pcapraven-protocols` | `pcapraven-domain` |
| `pcapraven-flows` | `pcapraven-domain` |
| `pcapraven-detection` | `pcapraven-domain` |
| `pcapraven-reporting` | `pcapraven-domain` |
| `pcapraven-cli` | All six library crates |

The minimal graph intentionally shares normalized contracts through
`pcapraven-domain`; sibling library crates do not depend on each other. The CLI
coordinates their data flow. If a future phase demonstrates that a direct
sibling dependency is necessary, that change requires an architecture review,
must preserve acyclicity, and must update this table before implementation.

Forbidden directions include any library depending on `pcapraven-cli`, domain
depending on a parser or serializer, detection depending on parser crates, and
reporting invoking detection. `scripts/check_workspace_architecture.py` checks
the seven-package graph, documented internal edges, and audited external
dependencies from Cargo metadata.

## Target Data Flow

```text
untrusted capture bytes
        |
        v
pcapraven-pcap (bounded capture records + diagnostics)
        |
        v
pcapraven-protocols (normalized packets + protocol observations)
        |
        +--------------------+
        v                    v
pcapraven-flows       domain observation store
        |                    |
        +----------+---------+
                   v
          pcapraven-detection
                   |
                   v
           domain analysis result
                   |
                   v
         pcapraven-reporting

pcapraven-cli configures and orchestrates each stage.
```

Capture records are streamed by the Phase 2 reader, normalized by the Phase 3
normalizer, and associated into flows by the Phase 4 flow reconstructor.
Detection, reporting, and CLI stages in this diagram remain a logical contract
for later phases.

## Domain Boundary

The canonical conceptual model is in [Domain Model](DOMAIN_MODEL.md). Domain
types represent validated or explicitly incomplete facts, not unchecked views
over attacker-controlled buffers. Raw packet bytes may be retained only behind
bounded, intentional ownership and must not become an implicit requirement for
all downstream processing.

## Error-Handling Policy

PcapRaven distinguishes these conditions:

- **Fatal error:** safe analysis cannot begin or continue, such as an unreadable
  file or invalid capture-container structure that prevents bounded progress.
- **Recoverable malformed input:** a record or packet is invalid, but the next
  safe boundary is known and analysis may continue with a diagnostic.
- **Unsupported input:** structure is valid enough to identify but the feature,
  link type, or protocol is not supported; this is not automatically malformed.
- **Incomplete input:** expected bytes or capture context are absent, commonly
  because of truncation; consumers must know results may be partial.
- **Invalid reference:** a structurally parsed packet block names unavailable
  section-local state; the block is skipped only when the next boundary is safe.
- **Resource limit:** a validated finite budget prevents safe continuation; the
  result records the limit rather than silently dropping the boundary.
- **I/O failure:** the caller's streaming source returns an error; no payload or
  reader error text is copied into diagnostics.

Errors crossing crate boundaries use structured categories with operation and
capture-local context where available. External input must not reach
`unwrap()`, `expect()`, `panic!`, unchecked indexing, or unchecked arithmetic.
Malformed data must not cause panics. Libraries return errors and diagnostics;
only the CLI maps them to user-facing messages and exit status.

Recoverable errors should be accumulated subject to explicit count and memory
limits. Once a limit is reached, PcapRaven emits a summary diagnostic rather
than allocating without bound. Continuing is allowed only when parser progress
and a trustworthy next boundary are guaranteed.

Internal invariant violations are programming defects, not malformed-input
handling. They should be prevented by types and tests; they must not expose
sensitive data in diagnostics.

## Logging and Diagnostics Policy

Structured diagnostics and warnings are emitted to stderr via bounded diagnostic
emitters. No external logging dependency is present in the current library crates.

- Stdout is reserved for requested result output.
- Logs, warnings, progress, and diagnostics go to stderr.
- Default output should be concise; `--quiet`, `-v`, and `-vv` control
  diagnostic verbosity without changing result data.
- Libraries do not initialize subscribers or choose presentation; the CLI does.
- Logs must not include packet payloads, credentials, secrets, or large
  attacker-controlled fields by default.
- Capture paths and protocol values are potentially sensitive and must be
  minimized, escaped, and emitted only when useful at the selected verbosity.
- User-controlled text must not inject terminal control sequences.
- Logging must be bounded and resistant to amplification by repeated malformed
  input.
- No telemetry or network log sink is enabled by default.

## Unsafe Rust Policy

Unsafe Rust is prohibited in project code by the workspace lint policy by
default. An exception requires a
documented need, proof that a safe alternative is unsuitable, narrowly scoped
unsafe blocks with stated invariants, dedicated tests, and explicit security
review. Dependency use of unsafe code is evaluated during dependency review
and does not weaken the requirements at project boundaries.

## Architectural Change Control

Changes to crate responsibilities, allowed dependency direction, security
invariants, or canonical domain semantics require documentation changes in the
same contribution and review under [AGENTS.md](../AGENTS.md). Implementation
must never silently establish a conflicting architecture.
