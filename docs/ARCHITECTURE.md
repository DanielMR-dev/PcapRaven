# Architecture

## Status

Phase 0 product and architecture definition, Phase 1 workspace/tooling work,
Phase 2 capture-container ingestion, Phase 3 packet normalization, and Phase 4
bidirectional flow reconstruction are complete. `pcapraven-domain` defines
normalized packet and flow models, `pcapraven-pcap` provides capture ingestion,
`pcapraven-protocols` provides packet normalization, and `pcapraven-flows`
provides stateful bidirectional flow reconstruction. Phase 5 flow statistics,
application decoders (DNS/HTTP/TLS), threat detection, reporting, and
user-facing CLI behavior remain future work.

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

The source files for detection, reporting, and CLI packages remain
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

Phase 4 adds no new production dependencies; `proptest = 1.11.0` is dev-only.
`pcapraven-flows` depends only on `pcapraven-domain`.

## Crate Responsibilities

The crates have the following responsibilities:

### `pcapraven-domain`

Owns capture-independent domain types and invariants: normalized packet
metadata (`NormalizedPacket`, `EthernetMetadata`, `Ipv4Metadata`, `Ipv6Metadata`,
`TcpMetadata`, `UdpMetadata`, `FragmentationState`, `TcpFlags`), endpoints
(`FlowEndpoint`), flow keys (`FlowKey`), flow references (`FlowReference`),
directions (`FlowDirection`), associations (`FlowPacketAssociation`), completed
records (`FlowRecord`), end reasons (`FlowEndReason`), protocol observations,
evidence, findings, severity, confidence, diagnostics, and analysis result metadata.
It contains no capture parser, protocol parser, CLI, terminal, filesystem orchestration,
detector implementation, or serializer-specific logic.

### `pcapraven-pcap`

Owns capture ingestion only: safe reading of PCAP/PCAPNG containers, capture
record metadata, bounded extraction of packet bytes, interface/link metadata,
and capture-level diagnostics. It exposes a zero-allocation adapter converting
`CaptureRecord` into `pcapraven_domain::PacketNormalizationInput`. It does not
decode Ethernet, IP, TCP, UDP, DNS, HTTP, or TLS; reconstruct flows; detect
threats; format reports; or interact with users.

### `pcapraven-protocols`

Owns normalization of supported network and application protocol data. Normalizes
Ethernet, IPv4, IPv6, TCP, and UDP into domain packet observations. Future phases
will derive DNS, HTTP/1.x, and TLS handshake observations from normalized data. It
does not read capture container files, reconstruct global flow state, assign
security findings, serialize reports, or implement CLI behavior.

### `pcapraven-flows`

Owns bidirectional communication reconstruction, canonical flow keys,
direction assignment, lifecycle state management, and packet associations.
Phase 5 will add packet/byte counters and temporal statistics. It consumes
normalized domain packet metadata and does not parse capture containers or
application protocols, produce security findings, serialize reports, or
interact with users.

### `pcapraven-detection`

Owns detector contracts, detector execution, and heuristic implementations. It
consumes normalized domain observations and flow information. It does not parse
external bytes, mutate parser results, own report formatting, or handle CLI
interaction.

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

## Logging Policy

Later analysis phases will use structured `tracing` diagnostics. No tracing
dependency or logging behavior is present in the current library crates; the
detailed dependency choice remains subject to the dependency review required
when CLI/logging behavior is introduced.

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
