# Domain Model

## Purpose and Status

This document defines conceptual, capture-independent records and invariants.
Phase 2 implements capture-container metadata and owned packet records in
`pcapraven-pcap`. Phase 3 implements the normalized domain packet model,
reference identity, timestamp representation, and layer metadata in
`pcapraven-domain`. Phase 4 implements the domain flow model and identity
types (`FlowEndpoint`, `FlowKey`, `FlowDirection`, `FlowReference`,
`FlowPacketAssociation`, `FlowRecord`, `FlowEndReason`, `FlowExclusionReason`) in `pcapraven-domain`.
Phase 5 implements checked directional flow traffic statistics and exact rational
temporal metrics in `pcapraven-domain`. Phase 7 implements normalized DNS observation
models in `pcapraven-domain`. Phase 8 implements normalized HTTP/1.x observation models
in `pcapraven-domain`. Phase 9 implements normalized visible TLS 1.2 / TLS 1.3 handshake
observation models in `pcapraven-domain`. Phase 10 implements unified protocol observations
(`ProtocolObservationData`, `ProtocolObservation`, `ObservationFlowAssociation`), bounded collections,
and the structured evidence foundation (`EvidenceRecord`, `EvidenceRatio`, `EvidenceMeasurement`, `SchemaVersion`)
in `pcapraven-domain`. Threat findings (Phase 12+) and cross-protocol correlation (Phase 11) remain future work.

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
- `FlowEndReason`: lifecycle closure reason (`EndOfInput`, `IdleTimeout`, `TcpReset`, `TcpNewInitialSyn`, `AnalysisStopped`).
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

Phase 7 DNS observations (`DnsObservation` in `pcapraven-domain`) represent factual
message metadata: transport (`UDP`/`TCP`), query/response role (`Query`/`Response`),
transaction ID, flags, opcode, base and effective response codes, declared section counts,
bounded questions, parsed resource records (A, AAAA, CNAME, NS, PTR, MX, and unknown types),
EDNS(0) pseudo-record metadata (UDP payload size, extended RCODE, DO bit, options), and explicit
completeness status (`Complete` or `Partial`). Domain names retain raw wire label fidelity
with RFC 1035 bounds (label length <= 63, wire length <= 255) and terminal-safe escaping.

### HTTP Observations

Phase 8 HTTP observations (`HttpObservation` in `pcapraven-domain`) represent factual
cleartext HTTP/1.0 and HTTP/1.1 message metadata: version (`Http10`/`Http11`), message kind
(`Request`/`Response`), request start-line (`HttpRequestMetadata` with `method` and `target`),
response status-line (`HttpResponseMetadata` with 3-digit `status_code`), selected headers
(`HttpSelectedHeaders` holding `host`, `user_agent`, `server`, `content_type`, `content_length`,
`transfer_encoding`, `connection`, `upgrade`), sensitive header presence flags (`has_authorization`,
`has_proxy_authorization`, `has_cookie`, `has_set_cookie`), framing metadata (`HttpFramingMetadata`
with `content_length`, `is_chunked`, `is_upgrade`, `is_close`, `is_keep_alive`, `has_conflicting_framing`),
declared field count, header section byte length, and explicit completeness status (`Complete`
or `Partial`). Raw text is preserved in `HttpByteString` and rendered via terminal-safe
`display_escaped()` notation (`\xHH`/`\\`). Sensitive values are never retained or serialized.

### TLS Observations

Phase 9 TLS observations (`TlsObservation` in `pcapraven-domain`) represent factual visible
TLS 1.2 / TLS 1.3 handshake metadata: record version (`TlsVersion`), handshake kind
(`TlsHandshakeKind` with `ClientHello`, `ServerHello`, `HelloRetryRequest`), ClientHello metadata
(`TlsClientHelloMetadata` with `legacy_version`, `session_id_length`, `cipher_suites`, `compression_methods`,
`server_name`, `supported_versions`, `supported_groups`, `signature_algorithms`, `alpn_protocols`,
`key_share_groups`, `has_pre_shared_key`, `has_early_data`, `extensions`), ServerHello metadata
(`TlsServerHelloMetadata` with `legacy_version`, `session_id_echo_length`, `cipher_suite`,
`compression_method`, `selected_version`, `selected_group`, `selected_alpn`, `has_pre_shared_key`,
`has_early_data`, `extensions`), declared record length, declared handshake message length, and
explicit completeness status (`Complete` or `Partial`). Raw text is preserved in `TlsByteString`
and rendered via terminal-safe `display_escaped()` notation (`\xHH`/`\\`).

**Privacy Non-Retention Invariants:** Raw 32-byte ClientHello / ServerHello random values, session ID
bytes, key exchange public bytes, PSK identities/binders, early data payloads, certificate DER,
and ciphertext payloads are strictly NEVER retained. Zero payload decryption or private key recovery
### Unified Protocol Observations

Phase 10 unifies protocol observations across DNS, HTTP, and TLS under `pcapraven-domain`:

- `ProtocolKind` identifies the application protocol (`Dns`, `Http`, `Tls`).
- `ObservationReference` assigns a deterministic, monotonic reference string (`obs:{id}`).
- `ObservationCompleteness` reflects whether the observation parsed fully (`Complete`) or experienced non-fatal bounded degradation (`Partial`).
- `ObservationFlowAssociation` explicitly classifies flow linkage:
  - `Associated(FlowReference)`: Associated with a reconstructed bidirectional flow.
  - `Excluded(FlowExclusionReason)`: Flow reconstruction was explicitly excluded (e.g. `MissingNetworkLayer`, `MissingTransportLayer`, `FragmentedWithoutTransport`, `UnsupportedTransport`).
  - `Unassociated`: Observation has not been or cannot be associated with a flow.
- `ProtocolObservationData` is a typed enum wrapping `DnsObservation`, `HttpObservation`, or `TlsObservation`.
- `ProtocolObservation` records link an observation reference, packet provenance (`PacketReference`), explicit flow association, completeness, and typed observation data.
- `ProtocolObservationCollection` provides a bounded collection enforcing `maximum_observations` and tracking truncation counters.

## Evidence Model

Phase 10 establishes the structured, immutable evidence foundation in `pcapraven-domain`:

- `SchemaVersion`: Explicit schema versioning (`SchemaVersion::CURRENT = v1.0`) ensuring forward/backward compatibility.
- `EvidenceReference`: Stable capture-local reference formatted as `evi:{id}`.
- `EvidenceKind`: Categorizes evidence into `PacketMeasurement`, `FlowMeasurement`, `ProtocolObservation`, `TemporalMetric`, `RatioComparison`, or `StructuralAnomaly`.
- `EvidenceDescription`: Bounded (up to 1,024 characters), terminal-safe sanitized factual description.
- `EvidenceMetricKey`: Bounded (up to 128 characters), terminal-safe metric identifier.
- `EvidenceRatio`: Exact rational representation ($n / d$) stored as `u128` numerator and `u128` denominator reduced via GCD. Enforces zero float arithmetic (`f32`/`f64`) and exact total ordering via Euclidean continued-fraction decomposition without overflow across all $u128$ ranges.
- `EvidenceUnit`: Explicit units (`Bytes`, `Packets`, `Nanoseconds`, `Microseconds`, `Milliseconds`, `Seconds`, `Ratio`, `Count`, `PercentageInteger`, `Custom`).
- `EvidenceValue`: Exact typed value (`Integer(i128)`, `Unsigned(u128)`, `Ratio(EvidenceRatio)`, `Boolean(bool)`, `Text(String)` — zero floats).
- `EvidenceComparison`: Comparison operator (`Equal`, `NotEqual`, `LessThan`, `LessThanOrEqual`, `GreaterThan`, `GreaterThanOrEqual`, `InRange`, `OutsideRange`).
- `EvidenceMeasurement`: Structured measurement combining observed value, optional reference threshold, optional comparison operator, and explicit unit.
- `EvidenceLimitation`: Explicit analysis limitations affecting evidence interpretation (`TruncatedPayload`, `MissingNetworkLayer`, `IncompleteHandshake`, `PacketCountBudgetReached`, `ObservationBudgetReached`, `FlowBudgetReached`, `HeaderBudgetExceeded`).
- `EvidenceRecord`: Complete evidence record anchoring schema version, references to packets (`PacketReference`), flows (`FlowReference`), and observations (`ObservationReference`), structured measurements, description, and limitations.

Evidence references canonical records rather than copying arbitrary packet payloads.
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
