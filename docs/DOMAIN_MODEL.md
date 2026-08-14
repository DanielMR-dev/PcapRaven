# Domain Model

## Purpose and Status

This document defines conceptual, capture-independent records and invariants.
It does not prescribe final Rust field names, serialization schemas, or storage
strategy. Phase 2 implements capture-container metadata and owned packet records
in `pcapraven-pcap`; those capture-specific types are not the normalized domain
packet model defined here. Domain implementation begins in a later roadmap phase
after capture and protocol-normalization contracts are established.

## Modeling Rules

- Preserve what was observed separately from what was inferred.
- Use capture-local stable identifiers instead of pointers or byte-buffer
  lifetimes across architectural boundaries.
- Represent missing, unsupported, malformed, and intentionally redacted values
  distinctly where that distinction affects interpretation.
- Preserve original direction and timing while allowing canonical grouping.
- Use explicit units for lengths, counts, durations, and timestamps.
- Keep attacker-controlled collections and text bounded.
- Avoid placeholder values that could be mistaken for observed facts.

## Capture and Packet Identity

### Phase 2 Capture Boundary

The Phase 2 reader owns format-specific facts such as PCAP/PCAPNG byte order,
section and interface declarations, link type, snap length, captured/original
lengths, container timestamps, and capture-level diagnostics. It preserves
unavailable timestamps and truncation explicitly, assigns ordinals only to
emitted records, and retains packet bytes only within validated configured
limits. These values must be translated into normalized domain facts by a later
phase; they must not be treated as decoded network addresses, transport roles,
protocol observations, or security evidence.

### Capture Context

A capture context identifies one analysis input and records facts needed to
interpret it, including capture format, interfaces, timestamp resolution,
declared link types, byte order where relevant, and completeness diagnostics.
It must not require a global database identity or include a content hash unless
a later phase explicitly computes one.

### Packet Reference

A packet reference is stable within one analysis result. It identifies the
capture record ordinal and, for PCAPNG, the interface or section context needed
to resolve that record. It may include a normalized timestamp and original
captured/wire lengths as supporting context.

Packet references never claim that a malformed record decoded successfully.
One capture record can yield no normalized packet when unsupported or malformed.

### Time

Capture timestamps represent recorded event time, not processing time. The
model preserves available resolution and defines a deterministic ordering for
equal or absent timestamps using capture record order. Negative durations and
arithmetic overflow are invalid. Metrics that require missing or unreliable
timestamps are unavailable rather than fabricated as zero.

## Normalized Packet Model

A normalized packet is an observation derived safely from one capture record.
Its conceptual fields include:

- Packet reference and timestamp state.
- Interface and supported link-layer context.
- Source and destination network addresses.
- Transport protocol and source/destination ports where applicable.
- Captured length and original wire length.
- Fragmentation, truncation, and decode-completeness state.
- Bounded transport payload metadata needed by later protocol analysis.
- Diagnostics associated with normalization.

An absent port is distinct from port zero. Unknown transport is distinct from
malformed transport. Original packet direction is retained exactly as observed.

## Endpoints and Communication Keys

An endpoint combines a network address with transport protocol and port when
the protocol has ports. Address family is part of address identity. Values are
compared by canonical binary representation, not display strings.

A directional communication tuple is:

```text
(transport protocol, source endpoint, destination endpoint)
```

A bidirectional flow key contains the same protocol and two endpoints ordered
by a deterministic total ordering. Canonical ordering groups reverse traffic;
it does not imply client/server, initiator/responder, trusted/untrusted, or
request/response roles.

## Flow Model

### Identity and Direction

A flow represents normalized packets sharing one canonical bidirectional key
within a defined lifetime. Each packet is assigned direction A-to-B or B-to-A
relative to the canonical endpoints. If later phases infer initiator or
responder roles, those are separate, evidence-backed attributes.

A flow reference is stable within one analysis result. Flow identity must also
account for lifecycle boundaries so sequential communications with the same
endpoint tuple are not necessarily merged forever. Timeout and TCP lifecycle
rules are deferred to Phase 4 and must be deterministic and documented there.

### Flow Contents

A flow conceptually contains:

- Flow reference and canonical key.
- First and last reliable timestamps and duration availability.
- First and last packet references.
- Directional and total packet counts.
- Directional and total captured/wire byte counts with explicit semantics.
- Transport lifecycle or completeness state where observable.
- Ordered or bounded packet references sufficient for evidence.
- Temporal metrics added in Phase 5.
- Diagnostics indicating gaps, truncation, or ambiguous ordering.

Counters use checked arithmetic and may report limit exhaustion instead of
wrapping. Flow summaries must not imply full TCP stream reassembly; that is not
part of the defined v1 architecture unless separately proposed and approved.

### Temporal Metrics

Future temporal metrics may include inter-arrival distributions, active span,
idle intervals, directional cadence, and regularity measures. Every metric must
define units, minimum sample count, timestamp assumptions, and behavior for
ties, gaps, and incomplete captures. "Not computable" is distinct from numeric
zero.

## Protocol Observation Model

Protocol parsers produce normalized observations, not findings. Every
observation has:

- A capture-local observation reference.
- A protocol and observation kind.
- One or more packet references.
- A flow reference when flow association is available.
- Event time or explicit timestamp-unavailable state.
- Parsed metadata with bounded text and collection sizes.
- Completeness and parser diagnostics.
- Direction as observed, without unsupported role assumptions.

### DNS Observations

Planned DNS observations represent message metadata such as query/response
role, transaction identifier, opcode/status, bounded question names and types,
record counts, and selected bounded answer metadata. Names retain enough
normalized structure for analysis without asserting that they are trustworthy
host identities. Unsupported record types remain distinguishable from malformed
messages.

### HTTP Observations

Planned HTTP/1.x observations represent request/response metadata such as
method, target metadata, status, version, and a deliberately selected bounded
header set. They are not full body capture, browser interpretation, or proof of
transaction pairing. Sensitive values require minimization in logs and careful
report escaping.

### TLS Observations

Planned TLS observations represent visible handshake metadata such as record
and handshake types, versions, bounded cipher/extension identifiers, server
name indication when visible, and certificate metadata selected by later
design. They do not imply payload decryption or validation of a peer's trust.

## Evidence Model

Evidence is a structured, immutable explanation input attached to a finding.
Each evidence item conceptually contains:

- Evidence kind and stable capture-local reference.
- A concise factual description safe for output.
- Typed references to involved packets, flows, and observations.
- Measurements, thresholds, or compared values with explicit units.
- Relevant time range and direction when applicable.
- Completeness limitations that affect interpretation.

Evidence references canonical records rather than copying arbitrary packet
payloads. A bounded excerpt may be introduced only with a documented analytical
need, format-safe encoding, privacy consideration, and strict size limit.
Evidence never contains a detector conclusion disguised as an observed fact.

## Finding Model

A finding is a detector-produced interpretation over normalized domain data.
Its conceptual envelope contains:

- Stable finding identity within the analysis result.
- Detector identifier, detector version, and finding category/title.
- Cautious summary of what was detected.
- Human-readable rationale explaining why it was produced.
- Structured evidence items.
- Deduplicated packet, flow, and observation references.
- Severity and confidence as separate values.
- Zero or more applicable MITRE ATT&CK mappings.
- Analysis limitations or suppression-relevant context.

Canonical semantics are defined in [Detection Model](DETECTION_MODEL.md).

## Diagnostic Model

A diagnostic communicates processing state without becoming a finding. It has
a category, bounded message, recoverability, stage, and available capture-local
context. Diagnostics must be deterministically ordered and rate-limited or
aggregated under repeated malformed input.

Diagnostics distinguish malformed, truncated/incomplete, unsupported,
resource-limit, I/O, and internal conditions. A diagnostic is not evidence of
hostile activity merely because the capture data caused it.

## Analysis Result

A complete result envelope conceptually groups:

- Tool and result-schema version metadata.
- Input metadata that is safe and necessary to interpret results.
- Applied configuration and relevant resource limits.
- Completion state: complete, partial, or failed before results.
- Normalized summaries, flows, observations, evidence-backed findings, and
  diagnostics applicable to the requested command.

Output formats are projections of this domain result. Serialization concerns
must not alter canonical findings or make a partial result look complete.

## Determinism and Ordering

Default ordering follows capture order for packet-derived records, canonical
flow identity plus first occurrence for flows, and stable detector and evidence
keys for findings. Exact tie-break rules will be frozen with schemas and golden
tests in later phases. Hash-map iteration order or execution scheduling must
never leak into output ordering.
