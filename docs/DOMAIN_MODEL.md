# Domain Model

## Purpose and Status

This document defines conceptual, capture-independent records and invariants.
Phase 2 implements capture-container metadata and owned packet records in
`pcapraven-pcap`. Phase 3 implements the normalized domain packet model,
reference identity, timestamp representation, and layer metadata in
`pcapraven-domain`. Phase 4 implements the domain flow model and identity
types (`FlowEndpoint`, `FlowKey`, `FlowDirection`, `FlowReference`,
`FlowPacketAssociation`, `FlowRecord`, `FlowEndReason`) in `pcapraven-domain`.
Phase 5 implements checked directional flow traffic statistics and exact rational
temporal metrics in `pcapraven-domain`. Application protocol observations and threat
findings remain future work.

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
limits.

`CaptureRecord` provides a zero-allocation borrowed adapter into
`pcapraven_domain::PacketNormalizationInput` for consumption by Phase 3
protocol normalization.

### Capture Context

A capture context identifies one analysis input and records facts needed to
interpret it, including capture format, interfaces, timestamp resolution,
declared link types, byte order where relevant, and completeness diagnostics.
It must not require a global database identity or include a content hash unless
a later phase explicitly computes one.

### Packet Reference

A packet reference is stable within one analysis result. It identifies the
capture record ordinal and, for PCAPNG, the interface or section context needed
to resolve that record. It includes original captured/wire lengths and truncation
flags as supporting context.

Packet references never claim that a malformed record decoded successfully.
One capture record can yield no normalized packet when unsupported or malformed.

### Time

Capture timestamps represent recorded event time, not processing time. The
model preserves available resolution (Decimal or Binary fractional units) and
defines a deterministic ordering for equal or absent timestamps using capture
record order. Negative durations and arithmetic overflow are invalid. Metrics
that require missing or unreliable timestamps are unavailable rather than
fabricated as zero.

## Normalized Packet Model

A normalized packet is an observation derived safely from one capture record
(`NormalizedPacket` in `pcapraven-domain`). Its concrete fields include:

- `reference`: `PacketReference` identifying the source capture record.
- `timestamp`: `PacketTimestamp` (`Available` or `Unavailable`).
- `link_layer`: `Option<EthernetMetadata>` with MAC addresses, EtherType, and header length.
- `network_layer`: `Option<NetworkLayer>` (`Ipv4(Ipv4Metadata)` or `Ipv6(Ipv6Metadata)`).
- `transport_layer`: `Option<TransportLayer>` (`Tcp(TcpMetadata)` or `Udp(UdpMetadata)`).
- `payload`: `Option<Vec<u8>>` bounded to configured payload retention limit.
- `completeness`: `PacketCompleteness` (`Complete`, `Partial { reason }`, or `Unsupported { reason }`).

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
within a defined lifecycle. The implemented Phase 4 domain types include:

- `TransportProtocol`: `Tcp` or `Udp`.
- `FlowEndpoint`: binary `IpAddress` and `u16` transport port with total ordering.
- `FlowKey`: canonical `(protocol, endpoint_a, endpoint_b)` where `endpoint_a <= endpoint_b`.
- `FlowDirection`: relative packet direction (`AToB`, `BToA`, or `SameEndpoint`).
- `FlowReference`: zero-based monotonic flow instance ordinal distinguishing sequential reuse.
- `FlowPacketAssociation`: compact reference association (`flow`, `packet`, `direction`).
- `FlowEndReason`: lifecycle closure reason (`EndOfInput`, `IdleTimeout`, `TcpReset`, `TcpNewInitialSyn`).
- `FlowRecord`: completed record (`reference`, `key`, `first_packet`, `last_packet`, `end_reason`, `traffic`, `temporal`).

### Phase 5 Flow Traffic Statistics and Exact Temporal Metrics

`pcapraven-domain` defines factual traffic and exact rational temporal domain representations:

- `FlowTrafficCounters`: records `packet_count`, `captured_bytes`, `wire_bytes`, and `truncated_packet_count`.
- `FlowTrafficStatistics`: contains directional buckets `total`, `a_to_b`, `b_to_a`, and `same_endpoint`. Enforces the invariant `total == a_to_b + b_to_a + same_endpoint`.
- `FlowDuration`: exact rational duration (`numerator: u128`, `denominator: u128`) reduced to lowest terms via GCD. `FlowDuration::ZERO` is canonicalized to `0 / 1`. Float types (`f32`/`f64`) are strictly forbidden.
- `FlowTemporalUnavailableReason`: explains why a temporal metric could not be computed (`InsufficientSamples`, `TimestampUnavailable`, `InvalidTimestamp`, `NonMonotonicTimestamp`, `ArithmeticOverflow`).
- `FlowTemporalValue<T>`: enum holding `Available(T)` or `Unavailable(FlowTemporalUnavailableReason)`.
- `FlowTimestampCoverage`: tracks `available_timestamps`, `unavailable_timestamps`, `invalid_timestamps`, and `non_monotonic_transitions`.
- `FlowInterArrivalMetrics`: tracks `interval_sample_count`, `discontinuity_count`, `minimum_interval`, `maximum_interval`, `mean_interval`, `successive_delta_sample_count`, and `mean_absolute_successive_interval_delta`.
- `FlowTemporalMetrics`: combines `first_packet_timestamp`, `last_packet_timestamp`, `duration`, `coverage`, `overall_inter_arrival`, `a_to_b_inter_arrival`, `b_to_a_inter_arrival`, and `same_endpoint_inter_arrival`.

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
