# Testing Strategy

## Status

Phase 0 documentation and governance work, Phase 1 workspace/tooling work,
Phase 2 capture-container ingestion tests, Phase 3 protocol normalization tests,
Phase 4 bidirectional flow reconstruction tests, Phase 5 flow statistics and
exact temporal metric tests, Phase 6 functional CLI integration tests,
Phase 7 bounded DNS protocol analysis tests, Phase 8 bounded HTTP/1.x protocol
analysis tests, Phase 9 bounded visible TLS 1.2 / TLS 1.3 handshake metadata analysis tests,
and Phase 10 unified protocol observations and structured evidence integration tests
are complete. Phase 11 (cross-protocol correlation), detection,
and advanced reporting testing remain future phase work.

## Testing Pyramid

### Unit Tests

Unit tests cover local invariants and transformations: checked length and
offset calculations, Ethernet II header normalization, IPv4 options and total
length checks, IPv6 extension header bounded traversal, TCP/UDP headers and
flags, payload truncation, diagnostic emission, flow key canonicalization,
direction assignment, timestamp arithmetic, and TCP/UDP lifecycle state machines.

### Fixture and Golden Tests

Fixture tests will pass known captures or normalized inputs through one or more
stages. Golden outputs will lock intentional diagnostics, normalized records,
findings, ordering, and serialized schemas. Golden changes require human review
and an explanation; they must never be updated blindly merely to make tests
pass.

### Integration Tests

Integration tests verify crate boundaries and data exchange, including
capture ingestion to normalization, normalized packets to flows, observations
and flows to detectors, and domain results to reporters. Error and partial-data
paths are first-class cases.

### End-to-End Tests

End-to-end tests will invoke the compiled CLI with synthetic captures and
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

Fuzzing uses an excluded `fuzz/` package and `libfuzzer-sys` with six targets:
`fuzz_pcap_reader` for capture-container parsing, `fuzz_packet_normalizer` for
protocol normalization, `fuzz_flow_reconstructor` for flow reconstruction
and traffic/temporal metric invariant validation, `fuzz_dns_parser` for
bounded DNS wire parsing, `fuzz_http_parser` for bounded HTTP/1.x wire parsing,
and `fuzz_tls_parser` for bounded TLS 1.2 / TLS 1.3 handshake parsing.
The targets call only public bounded APIs and do not access files or networks.
The checked-in CI build commands are:

```text
cargo +nightly fuzz build fuzz_pcap_reader
cargo +nightly fuzz build fuzz_packet_normalizer
cargo +nightly fuzz build fuzz_flow_reconstructor
cargo +nightly fuzz build fuzz_dns_parser
cargo +nightly fuzz build fuzz_http_parser
cargo +nightly fuzz build fuzz_tls_parser
```

Long-running `cargo-fuzz` campaigns and additional structured targets remain
future work. Planned targets include:

- PCAP and PCAPNG container ingestion.
- Link, network, and transport normalization.
- Stateful bidirectional flow reconstruction.
- DNS, HTTP/1.x, and TLS handshake parsers.
- Report escaping and serializers for attacker-controlled text and values.

Fuzz harnesses must configure conservative memory, record, nesting, and work
limits; avoid network and nondeterministic dependencies; and treat panics,
out-of-bounds access, integer overflow, hangs, and uncontrolled allocation as
failures. "No crash" is necessary but not sufficient: harnesses should assert
progress and output invariants.

Crashes and hangs are minimized, triaged, fixed, and promoted to the regression
corpus. Corpus files must follow the fixture privacy and provenance policy.
Long-running campaigns supplement, but do not replace, deterministic CI smoke
runs. Platform sanitizer coverage and exact budgets will be defined in Phase
18 based on supported toolchains.

## Fixture Policy

The future fixture layout is:

```text
fixtures/pcaps/benign/
fixtures/pcaps/suspicious/
fixtures/pcaps/malformed/
fixtures/pcaps/edge-cases/
fixtures/expected/
```

The full fixture corpus is deferred to Phase 17.

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

The separate CI fuzz build job verifies the excluded fuzz harnesses using the
nightly toolchain and pinned `cargo-fuzz = 0.13.2`:

```text
cargo +nightly fuzz build fuzz_pcap_reader
cargo +nightly fuzz build fuzz_packet_normalizer
cargo +nightly fuzz build fuzz_flow_reconstructor
cargo +nightly fuzz build fuzz_dns_parser
cargo +nightly fuzz build fuzz_http_parser
```

The CI job uses locked dependency resolution for workspace quality, metadata,
test, and documentation invocations where Cargo supports it. The architecture
checker also passes `--locked` and `--offline` to Cargo metadata. A separate
locked MSRV job runs `cargo +1.85.0 check --workspace --locked`, `cargo +1.85.0 build
--workspace --locked`, and `cargo +1.85.0 test --workspace --locked`. A
lightweight `cargo check --workspace --locked` runs across Linux, Windows, and
macOS. The architecture checker rejects unexpected packages, roles, external
dependencies, and dependency directions. The workspace lint policy rejects
project `unsafe` code by default. The fuzz package is excluded from the seven
package main workspace and is validated by its separate locked fuzz build command.

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
- **Integration Tests:** 17 comprehensive unit/integration tests in `crates/pcapraven-domain/tests/observation_evidence.rs` verifying
  all observation kinds, flow associations, bounds, schema versions, description sanitization, and exact rational comparisons.
- **Pure `std` Invariant:** Zero external dependencies added to `pcapraven-domain`.

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

## Phase 10 Quality Gates

The full workspace verification commands for Phase 10 are:

```text
# 1. Format check
cargo fmt --all -- --check

# 2. Workspace lints
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# 3. Full workspace tests
cargo test --workspace --all-features --locked

# 4. CLI end-to-end integration tests
cargo test -p pcapraven-cli --locked

# 5. Documentation build
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

# 6. Architecture & dependency validation
python3 scripts/check_workspace_architecture.py

# 7. MSRV check
cargo +1.85.0 check --workspace --all-targets --locked

# 8. Excluded fuzz targets build
cargo +nightly fuzz build
```
