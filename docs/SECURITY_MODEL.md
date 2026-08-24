# Security and Threat Model

## Scope and Status

This document defines PcapRaven's technical security posture. Operational
vulnerability reporting is covered by [SECURITY.md](../SECURITY.md). Phase 2
contains a bounded library-only PCAP/PCAPNG container reader in
`pcapraven-pcap`. Phase 3 adds bounded Ethernet, IPv4/IPv6, and TCP/UDP packet
normalization in `pcapraven-protocols`. Phase 4 adds deterministic bidirectional
flow reconstruction, Phase 5 adds checked flow traffic statistics and exact
rational temporal metrics in `pcapraven-flows`, Phase 6 adds initial functional
CLI orchestration (`validate` and `flows`), Phase 7 adds bounded DNS protocol analysis
and DNS inspection (`pcapraven dns`), Phase 8 adds bounded HTTP/1.x protocol analysis
and HTTP inspection (`pcapraven http`), Phase 9 adds bounded visible TLS 1.2 / TLS 1.3
handshake metadata analysis and TLS inspection (`pcapraven tls`), Phase 10 adds
unified protocol observations and structured evidence foundation in `pcapraven-domain`,
Phase 11 adds detection engine architecture in `pcapraven-detection`, Phase 12 adds
explainable periodic beaconing detection in `pcapraven-detection`, Phase 13 adds
explainable DNS anomaly and possible tunneling detection in `pcapraven-detection`, Phase 14 adds
explainable repeated low-volume flow behavior detection and deterministic cross-detector finding correlation in `pcapraven-detection`,
Phase 15 adds severity/confidence classification, finding filtering, and MITRE ATT&CK mapping provenance,
Phase 16 adds deterministic reporting architecture (Table, JSON, NDJSON, CSV), CSV formula injection defenses, safe output file lifecycle, and unified forensic analysis (`analyze`),
and Phase 17 adds the manifest-backed synthetic fixture corpus, golden reports,
and end-to-end regression testing. Phase 18 robustness and performance verification is current.

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
- Fixture manifests, checksums, generated binary artifacts, and proposed golden updates.

Configuration, dependencies, build inputs, and fixtures also require review;
they are not trusted merely because they are stored locally.

Fixture poisoning can hide parser or detector regressions by changing a capture
without updating its stated semantics. Blind golden acceptance can freeze a
security defect or schema drift as expected behavior. The Phase 17.1 controls
therefore require deterministic in-memory fixture generation, canonical SHA-256
manifest/checksum comparison, rejection of missing or unexpected captures,
read-only golden checking, and candidate staging outside `tests/golden/` for
manual semantic and schema-v1.0 review. Neither verification tool downloads data
or writes canonical fixtures/goldens.

Canonical fixture and golden verification APIs take the repository root and a
relative path separately. Every component below that root is checked as a
non-symlink directory before a regular file can be opened. Structural discovery
is a hard precondition: symlink, non-regular-node, metadata, depth, entry-count,
or file-count failures stop canonical reads and CLI scenario execution. Golden
candidate staging applies the same fixture preflight before invoking the CLI.
Unix Python reads use directory-descriptor-relative `O_NOFOLLOW` opens where the
standard library supports them; portable Python and safe Rust use bounded
pre/open/post observable-state checks. Non-Unix metadata snapshots are not true
file identity, and verification assumes no concurrent hostile local mutation of
the trusted checkout; replacement detected at a comparison point is rejected.

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
- Diagnostics and logs use stderr through bounded structured diagnostic emitters.

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

## DNS, HTTP, and TLS Protocol Parser Safety Requirements

The Phase 7 DNS, Phase 8 HTTP, and Phase 9 TLS parsers in `pcapraven-protocols` must:

- **DNS:** Enforce strict backward-pointer decompression rules (`target_offset < pointer_location_offset`),
  eliminating self-loops, forward pointer corruption, and cyclical recursion. Bound pointer traversal hops
  and aggregate expanded name bytes per message. The aggregate charges label-length octets and the root octet
  for every decoded question, record owner, and name-bearing CNAME/NS/PTR/MX RDATA value before its owning
  question or record is retained. Strict RDLENGTH consumption verification applies to standard records.
- **HTTP:** Enforce packet-local start-line and header parsing without cross-packet TCP stream reassembly,
  body retention, chunked body decoding, or decompression. Require canonical CRLF line endings (bare CR/LF rejected),
  reject whitespace before colon, reject obs-fold line folding, enforce mandatory Host header on HTTP/1.1 requests,
  reject duplicate Host headers, parse decimal Content-Length, and detect conflicting Transfer-Encoding / Content-Length framing.
- **TLS:** Enforce packet-local record parsing without cross-packet TCP stream reassembly. Assemble adjacent
  Handshake records in the same packet up to `maximum_handshake_message_bytes` while retaining only unconsumed
  buffer suffixes to prevent duplicate message emissions. Enforce packet-wide handshake message limits across
  all records in a packet. Enforce maximum record fragment bounds (16 KiB plaintext, 18 KiB opaque) on complete
  records before body processing. Full SNI `ServerNameList` consumption with duplicate `host_name` rejection.
  Enforce finite bounds on client key-shares (emitting `ResourceLimit` and marking `Partial` on limit reached,
  with zero key exchange bytes retained). Enforce server selected-version policy (only TLS 1.2 or TLS 1.3 are valid
  complete selections). Prohibit cleartext ALPN in TLS 1.3 ServerHello (`Malformed` and `Partial`). Contextually
  validate ServerHello extensions and decouple per-observation completeness from subsequent unrelated packet errors.
  Detect duplicate extensions per Hello message.
- **Privacy Non-Retention Invariants (MANDATORY):**
  - Raw 32-byte ClientHello / ServerHello random values are NEVER retained (only inspected transiently for the HRR sentinel).
  - Session ID bytes are NEVER retained (only `session_id_length` is recorded).
  - Key Share public key bytes are NEVER retained (only named group IDs are recorded).
  - PSK identities and binders are NEVER retained (only boolean presence flag).
  - Early Data payloads are NEVER retained (only boolean presence flag).
  - Certificate DER and ciphertext payloads are NEVER retained.
  - Zero TLS decryption, private key loading, or `SSLKEYLOGFILE` support.
  - HTTP sensitive header values (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`) are never retained.
- **Output Safety:** Render all domain names and raw byte strings via deterministic terminal-safe escaping
  (`\DDD` or `\xHH`/`\\`), preventing terminal control sequence injection.
- **Diagnostics & Error Boundaries:** Cap diagnostic emission per packet and ensure malformed/partial packets
  never panic or abort capture processing.

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

## Detection Engine and Threat Detection Safety Requirements

The Phase 11 detection engine in `pcapraven-detection` and Phase 12 periodic beaconing detector must:

- **Detector Provenance Spoofing:** The engine strictly owns `DetectorId` and `DetectorVersion` provenance on all `FindingRecord` structures. Detectors produce `FindingDraft` instances containing only findings and factual `EvidenceDraft` records; detectors cannot forge or override their assigned identity or version.
- **Whole-Configuration Preflight Validation:** All detector configurations and parameters are strictly validated prior to evaluating any detector. Parameter types, value ranges, and detector registration status are checked beforehand. If any configured detector or parameter is invalid, execution fails immediately before allocating finding buffers or evaluating input facts.
- **Detector Output Bounds and Finding/Evidence Amplification:** Detectors emit finding drafts into an engine-controlled bounded output sink (`DetectorDraftSink`). Every push verifies remaining finding budget and cumulative evidence capacity using checked arithmetic. Reaching output capacity returns a structured resource-limit error. Failed or resource-limited detector output is discarded transactionally, ensuring zero partial findings reach the run result.
- **Referential Integrity Verification:** Finding subjects and supporting evidence records must strictly reference valid flow ordinals, observation ordinals, or packet ordinals present in the borrowed `DetectionInput`. Dangling or forged references are rejected by the engine before identity assignment.
- **Incomplete Input Handling:** Detectors declare their `IncompleteDataPolicy` (`Skip` or `AllowWithLimitations`). When analysis is partial, `Skip` detectors are skipped without evaluation, while `AllowWithLimitations` detectors must explicitly provide supporting `EvidenceLimitation` records for all input limitations.
- **Deterministic Identity & Canonical Order:** Within each detector, accepted finding drafts are sorted canonically by `(FindingSubject, FindingTitle)` prior to sequential assignment of monotonic `FindingReference` (`find:{ordinal}`) and `EvidenceReference` (`evi:{ordinal}`) ordinals. Registry iteration order (`DetectorId`) ensures identical bit-for-bit results regardless of internal emission order. Duplicate finding identities (`DetectorId + FindingSubject`) are strictly rejected.
- **Diagnostic Amplification Protection:** Engine-level execution diagnostics are capped at `max_execution_diagnostics`. Error messages from detectors are bounded to 512 UTF-8 bytes and sanitized to strip all control characters (including Unicode controls).
- **Transactional Output Acceptance:** Output from each detector is canonicalized into temporary finding and evidence batches before committing to global run state. If any conversion fails, global output remains completely unmutated.

## Periodic Beaconing Detector Risks and Controls

The Phase 12 `PeriodicBeaconingDetector` (`behavior.periodic_beaconing`) addresses specific analytical and adversarial risks:

- **Adversarially Regular Traffic & Benign False Positives:** Periodic traffic timing is common in benign software (keepalives, health checks, NTP, telemetry, scheduled polling). Findings are classified with `Severity::Low` and `Confidence::Medium`, using cautious language that explains benign alternatives and avoids claiming malware or confirmed C2.
- **Jitter Manipulation and Evasion:** Attackers may introduce artificial jitter or sleep variance to avoid detection. Thresholds are configurable within strict validated bounds (`maximum_jitter_ratio: 0..=1`, `maximum_spread_ratio: 0..=1`, `minimum_interval_samples >= 3`, `minimum_mean_interval > 0`).
- **Incomplete Timestamp Coverage:** Flows with unavailable, invalid, or non-monotonic timestamps, or flows terminated due to analysis limits (`FlowEndReason::AnalysisStopped`), are strictly skipped to prevent false inferences from corrupted timing.
- **Rational Arithmetic Overflow Prevention:** All timing, jitter, spread, and mean comparisons use exact rational arithmetic (`compute_duration_ratio` with cross-cancellation GCD and `EvidenceRatio::Ord` total continued-fraction comparison), completely eliminating floating-point imprecision and intermediate cross-multiplication overflow.
- **Single-Flow Isolation:** The detector evaluates timing strictly within reconstructed bidirectional flows (`A -> B` and `B -> A`), preventing cross-flow cardinality explosion.

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
The Phase 18 bounded fuzz/benchmark foundation and complexity audit are
documented in `ROBUSTNESS.md` and `PERFORMANCE.md`. Long acceptance campaigns
and final measured budgets remain pending; boundedness may not be weakened to
improve results.

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
- Prevent spreadsheet formula interpretation in CSV text fields according to
  the implemented leading-trigger prefix policy.
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
- `pcapraven-detection`: zero third-party production dependencies (`std` and `pcapraven-domain` only).
- `clap = "=4.6.4"` (in `pcapraven-cli`): normal dependency, `default-features = false`,
  features `["std", "help", "usage", "error-context"]`. Audited transitive tree:
  `clap_builder 4.6.2`, `clap_lex 1.1.0`, `anstyle 1.0.14`. MIT/Apache-2.0, MSRV 1.85.
- `proptest = 1.11.0`: dev-only in test targets, `std` feature only. MIT/Apache-2.0, MSRV 1.85.
- `libfuzzer-sys = 0.4.13`: separate `fuzz/` package only.

No dependency may introduce default telemetry or network behavior that
contradicts this model.

## Fixtures and Development Data

Real captures are sensitive even in test environments. The fixture rules in
[Testing](TESTING.md#fixture-policy) require synthetic or demonstrably
sanitized, redistributable inputs. Agents and contributors must not inspect or
move unrelated captures, credentials, or files outside the repository.
Every canonical capture is generated locally, listed in
`tests/fixtures/pcaps/manifest.json` with MIT provenance and expected behavior,
and verified against both generated bytes and `checksums.sha256` before use.
Static symlinked ancestors below the explicit repository root are rejected
before external target bytes can be opened.

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
