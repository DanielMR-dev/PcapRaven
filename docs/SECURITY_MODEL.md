# Security and Threat Model

## Scope and Status

This document defines PcapRaven's technical security posture. Operational
vulnerability reporting is covered by [SECURITY.md](../SECURITY.md). Phase 2
contains a bounded library-only PCAP/PCAPNG container reader in
`pcapraven-pcap`. Phase 3 adds bounded Ethernet, IPv4/IPv6, and TCP/UDP packet
normalization in `pcapraven-protocols`. Phase 4 adds deterministic bidirectional
flow reconstruction and Phase 5 adds checked flow traffic statistics and exact
rational temporal metrics in `pcapraven-flows`.

## Assets

- Availability and integrity of the analyst's workstation and analysis process.
- Confidentiality of packet captures and derived network metadata.
- Integrity, completeness, and provenance of analysis results.
- Predictable consumption of memory, CPU, disk, file descriptors, and output.
- Trust in diagnostics, terminal output, and machine-readable reports.
- Project source, dependencies, release artifacts, and fixture provenance.

## Trust Boundaries

The following are untrusted:

- All PCAP and PCAPNG bytes, including headers, lengths, timestamps, link types,
  packet data, options, comments, names, and nested protocol fields.
- File names, paths, metadata, and output paths supplied by users or automation.
- Protocol text displayed in terminals, logs, CSV, JSON, or other reports.
- Capture provenance and claims that a capture is benign or sanitized.

Configuration, dependencies, build inputs, and fixtures also require review;
they are not trusted merely because they are stored locally.

## Threat Actors and Capabilities

An attacker may provide a deliberately malformed capture intended to trigger a
panic, excessive allocation, integer overflow, out-of-bounds access, infinite
loop, pathological CPU use, disk exhaustion, diagnostic amplification, or
terminal/report injection. A capture may combine valid outer structure with
malicious nested lengths and may be truncated at any byte.

An attacker may also craft plausible traffic to evade or trigger heuristics,
poison analyst conclusions, expose sensitive values through logs, or exploit a
downstream consumer of exported data. PcapRaven does not assume that Rust memory
safety alone prevents resource exhaustion or logic vulnerabilities.

## Mandatory Invariants

- Malformed data must not cause panics.
- Packet-controlled lengths, counts, offsets, recursion, and nesting must not
  produce unbounded allocation or work.
- External input must not reach `unwrap()`, `expect()`, `panic!`, unchecked
  indexing, or unchecked arithmetic.
- Recoverable malformed packets should not necessarily abort an entire capture.
- Recovery is allowed only when a trustworthy next boundary exists and parser
  progress is guaranteed.
- Unsafe Rust is prohibited in project code by default and requires explicit
  justification and security review under the architecture policy.
- PcapRaven performs no external network requests by default.
- PcapRaven has no telemetry and does not upload captures.
- Stdout is reserved for requested result output.
- Diagnostics and logs use stderr through structured tracing.

These are release-blocking requirements, not best-effort guidelines.

## Parser Safety Requirements

The Phase 2 capture reader and Phase 3 protocol normalizers must:

- Check all additions, multiplications, conversions, and offset calculations.
- Validate declared lengths against format minima, enclosing bounds, available
  bytes, configured limits, and representable host sizes before allocation.
- Borrow bounded slices where practical instead of allocating attacker-sized
  buffers.
- Strip trailing Ethernet padding from network and transport payloads by
  bounding strictly to IPv4 `total_length` and IPv6 `payload_length`.
- Bound IPv6 extension header traversal by explicit count and byte budgets.
- Classify fragmented packets explicitly and refuse to interpret transport
  layers without reassembly.
- Bound retained transport application payloads by `maximum_retained_payload_bytes`.
- Cap record size, packet size, aggregate retained bytes, option count, nesting depth,
  text length, diagnostic count, emitted records, and total work with documented policies.
- Reject contradictions and distinguish malformed, unsupported, and incomplete
  input.
- Guarantee that every successful loop iteration consumes input or makes a
  bounded state transition.
- Avoid recursive descent controlled by packet nesting; use bounded iteration.
- Avoid interpreting unvalidated data as UTF-8; preserve or encode bytes safely.
- Keep parse errors contextual but bounded, without copying payloads into
  messages.
- Continue after a malformed record only when resynchronization is specified
  and safe; never scan unbounded input for a guessed boundary.

## Flow Reconstruction and Metrics Safety Requirements

The Phase 4 and Phase 5 flow engine in `pcapraven-flows` must:

- Enforce strictly increasing `capture_record_ordinal` sequence without sorting
  or reordering, immediately failing on out-of-order records.
- Avoid retaining packet payloads, `NormalizedPacket` structs, or growing collections
  of timestamps/intervals in active flow state; use only fixed-size scalar accumulators ($O(1)$ memory per active flow).
- Use exact rational integer arithmetic (`FlowDuration` `u128 / u128` reduced via GCD)
  for all duration, inter-arrival, mean, delta, and timeout calculations; floating-point
  types (`f32`/`f64`) are strictly forbidden.
- Bound and validate all timestamp structures (resolutions and signed offsets); missing,
  invalid, or non-monotonic timestamps must break sequence chains without panic, negative
  durations, or interval bridging.
- Enforce strict resource bounds on `maximum_tracked_flows` and `maximum_flow_instances`,
  failing safely with structured resource errors upon exhaustion rather than performing
  lossy or non-deterministic eviction.
- Ensure strict transactionality on observation errors: failed observations (`observe(...) -> Err`)
  must leave active flow state, packet ordinals, and allocated flow references completely unmutated.
- Order all completed flow records deterministically by monotonic `FlowReference`
  ordinals on finalization.

## Resource Exhaustion

Memory, CPU, elapsed work, output size, open files, and retained diagnostics are
security concerns. Defaults must be conservative and limits configurable only
within validated ranges. Limit exhaustion yields a structured diagnostic or
fatal error according to whether sound partial analysis remains possible.

Attack-controlled cardinality must not directly determine collection capacity.
Repeated errors should be aggregated after a bounded sample. Output writers
must handle disk-full and broken-pipe conditions without panic or corruption of
other outputs.

Algorithm choices must consider worst-case behavior, not only average captures.
Benchmarks and fuzzing in Phase 18 will establish practical budgets without
weakening the boundedness requirement.

## Partial and Malformed Captures

PcapRaven favors useful partial analysis when safety and interpretability are
preserved. Skipped records and unavailable metrics are surfaced in diagnostics
and result completion state. A partial result must not look complete, and
detectors must not silently convert missing evidence into negative evidence.

The application aborts processing when it cannot establish a safe next record
boundary, when a configured critical resource limit is exhausted, or when
continuation would make results misleading.

## Output and Terminal Safety

- Escape or encode control characters and delimiters for each output format.
- Never emit terminal escape sequences derived from capture content.
- Prevent spreadsheet formula interpretation in CSV text fields according to a
  documented CSV policy before that reporter ships.
- Validate output paths and make overwrite behavior explicit.
- Do not include raw payloads, secrets, or sensitive metadata in logs by
  default.
- Ensure diagnostics cannot corrupt JSON, NDJSON, or CSV on stdout.
- Bound output fields and explicitly represent truncation where applicable.

Machine-readable output is untrusted data to downstream consumers and must use
standards-compliant encoders rather than manual string concatenation.

## Privacy

Packet captures can contain credentials, personal data, internal topology,
session identifiers, and proprietary traffic. Analysis remains offline by
default; there is no telemetry, capture upload, remote enrichment, or automatic
network lookup. Documentation and diagnostics must not encourage users to post
captures publicly.

Reports minimize copied packet content. Future features that require network
access or external enrichment are outside the current product contract and
would require explicit opt-in design, privacy review, threat-model revision,
and conspicuous documentation.

## Detection Abuse and Limitations

Attackers can shape traffic to evade statistical heuristics or create false
positives. Findings are explainable leads, not proof. Severity and confidence
remain independent, missing context is visible, and MITRE ATT&CK mappings do
not establish attribution. The canonical policy is in
[Detection Model](DETECTION_MODEL.md).

## Unsafe Code and Dependencies

Project unsafe code follows the exception process in
[Architecture](ARCHITECTURE.md#unsafe-rust-policy). Third-party dependencies
expand the attack surface.

- `pcap-parser = 0.17.0` (in `pcapraven-pcap`): normal dependency, default/data/serialize
  features disabled. MIT/Apache-2.0, MSRV 1.65.
- `etherparse = 0.21.0` (in `pcapraven-protocols`): normal dependency, default features
  disabled. Direct dependency `arrayvec` (locked `0.7.8`). MIT/Apache-2.0, MSRV 1.83.0.
- `pcapraven-flows`: zero third-party production dependencies.
- `proptest = 1.11.0`: dev-only in test targets, `std` feature only. MIT/Apache-2.0, MSRV 1.85.
- `libfuzzer-sys = 0.4.13`: separate `fuzz/` package only.

No dependency may introduce default telemetry or network behavior that
contradicts this model.

## Fixtures and Development Data

Real captures are sensitive even in test environments. The fixture rules in
[Testing](TESTING.md#fixture-policy) require synthetic or demonstrably
sanitized, redistributable inputs. Agents and contributors must not inspect or
move unrelated captures, credentials, or files outside the repository.

## Out of Scope Guarantees

PcapRaven cannot guarantee detection of compromise, authenticity of capture
contents, completeness of traffic that was not captured, correctness of remote
endpoint claims, or safety of third-party tools that consume exported reports.
It does aim to guarantee bounded, panic-free handling of untrusted input within
documented resource and platform assumptions.

## Security Verification

Security controls will be exercised through boundary-focused unit tests,
malformed fixtures, `proptest`, `cargo-fuzz`, regression cases, deterministic
output tests, dependency review, and read-only secure parser review. Details
are defined in [Testing](TESTING.md).
