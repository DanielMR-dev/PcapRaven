# Architecture

## Status

This document defines the target architecture. Phase 0 does not create a Cargo
workspace or any Rust crates. Workspace and crate skeletons begin in Phase 1.

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

## Target Workspace

The future Rust Edition 2024 Cargo workspace will contain exactly these initial
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

These paths are planned and intentionally do not exist in Phase 0. No minimum
supported Rust version (MSRV) is hard-coded in Phase 0. Dependency versions,
features, MSRV requirements, and licenses must be validated in Phase 1 before
dependencies are committed.

## Crate Responsibilities

### `pcapraven-domain`

Owns capture-independent domain types and invariants: normalized packet
metadata, endpoints, flow identities and summaries, protocol observations,
evidence, findings, severity, confidence, diagnostics, and analysis result
metadata. It contains no capture parser, protocol parser, CLI, terminal,
filesystem orchestration, detector implementation, or serializer-specific
logic.

### `pcapraven-pcap`

Owns capture ingestion only: safe reading of PCAP/PCAPNG containers, capture
record metadata, bounded extraction of packet bytes, interface/link metadata,
and capture-level diagnostics. It does not decode Ethernet, IP, TCP, UDP, DNS,
HTTP, or TLS; reconstruct flows; detect threats; format reports; or interact
with users.

### `pcapraven-protocols`

Owns normalization of supported network and application protocol data. It will
decode the supported link/network/transport layers and produce normalized
packet metadata, then derive DNS, HTTP/1.x, and TLS handshake observations from
normalized data. It does not read capture container files, reconstruct global
flow state, assign security findings, serialize reports, or implement CLI
behavior.

"Operates on normalized data" means application protocol analyzers consume
normalized transport/packet inputs rather than capture-container bytes.
Container ingestion remains exclusively in `pcapraven-pcap`.

### `pcapraven-flows`

Owns bidirectional communication reconstruction, canonical flow keys,
direction assignment, lifecycle state, packet/byte counters, and temporal
statistics. It consumes normalized domain packet metadata and does not parse
capture containers or application protocols, produce security findings,
serialize reports, or interact with users.

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
reporting invoking detection. Cargo workspace checks should enforce the graph
once the workspace exists.

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

Records can be streamed or retained according to later phase design, but every
boundary must carry bounded data and explicit diagnostics. This diagram is a
logical contract, not a Phase 0 implementation.

## Domain Boundary

The canonical conceptual model is in [Domain Model](DOMAIN_MODEL.md). Domain
types represent validated or explicitly incomplete facts, not unchecked views
over attacker-controlled buffers. Raw packet bytes may be retained only behind
bounded, intentional ownership and must not become an implicit requirement for
all downstream processing.

## Error-Handling Policy

PcapRaven distinguishes four conditions:

- **Fatal error:** safe analysis cannot begin or continue, such as an unreadable
  file or invalid capture-container structure that prevents bounded progress.
- **Recoverable malformed input:** a record or packet is invalid, but the next
  safe boundary is known and analysis may continue with a diagnostic.
- **Unsupported input:** structure is valid enough to identify but the feature,
  link type, or protocol is not supported; this is not automatically malformed.
- **Incomplete input:** expected bytes or capture context are absent, commonly
  because of truncation; consumers must know results may be partial.

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

PcapRaven will use structured `tracing` diagnostics. The detailed dependency
choice is deferred to Phase 1 validation.

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

Unsafe Rust is prohibited in project code by default. An exception requires a
documented need, proof that a safe alternative is unsuitable, narrowly scoped
unsafe blocks with stated invariants, dedicated tests, and explicit security
review. Dependency use of unsafe code is evaluated during dependency review
and does not weaken the requirements at project boundaries.

## Architectural Change Control

Changes to crate responsibilities, allowed dependency direction, security
invariants, or canonical domain semantics require documentation changes in the
same contribution and review under [AGENTS.md](../AGENTS.md). Implementation
must never silently establish a conflicting architecture.
