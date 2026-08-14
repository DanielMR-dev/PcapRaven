# Testing Strategy

## Status

Phase 0 documentation and governance work, Phase 1 workspace/tooling work,
Phase 2 capture-container ingestion tests, Phase 3 protocol normalization tests,
and Phase 4 bidirectional flow reconstruction tests are complete. Application
decoders, detection, reporting, and CLI testing remain future phase work.

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

### Fuzzing Strategy

Fuzzing uses an excluded `fuzz/` package and `libfuzzer-sys` with three targets:
`fuzz_pcap_reader` for capture-container parsing, `fuzz_packet_normalizer` for
protocol normalization, and `fuzz_flow_reconstructor` for flow reconstruction.
The targets call only public bounded APIs and do not access files or networks.
The checked-in CI build commands are:

```text
cargo +nightly fuzz build fuzz_pcap_reader
cargo +nightly fuzz build fuzz_packet_normalizer
cargo +nightly fuzz build fuzz_flow_reconstructor
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

These paths are planned for Phase 17 and intentionally do not exist in Phase 4.

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

## Phase 4 Quality Gates

The Phase 4 Linux quality job runs the following baseline gates with the pinned
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

## Phase 4 Validation

Phase 4 validation confirms bidirectional flow key canonicalization, direction
assignment, monotonic ordinal enforcement, zero packet memory retention, exact
integer timestamp timeout arithmetic, TCP SYN retransmission retention, new initial
SYN handling, RST immediate termination, non-forcing FIN policy, bounded resource
limits, deterministic finalization ordering, property tests, and `fuzz_flow_reconstructor`.
It also confirms that Phase 5 temporal metrics, flow counters, byte totals, application
decoders, detectors, reporters, and CLI commands remain absent.

## Dependency Audits

### `pcap-parser = 0.17.0` (Phase 2)

The production parser dependency in `pcapraven-pcap` is exact `pcap-parser = 0.17.0`,
licensed MIT/Apache-2.0, with declared MSRV 1.65. Its default feature set is empty
and optional `data` and `serialize` features are disabled. Direct transitive footprint:
`circular 0.3`, `nom 8`, `rusticata-macros 5`. No telemetry or network behavior.

### `etherparse = 0.21.0` (Phase 3)

The production protocol parser dependency in `pcapraven-protocols` is exact
`etherparse = 0.21.0`, licensed MIT/Apache-2.0, with declared MSRV 1.61. Default
features are disabled. Zero transitive third-party dependencies. No telemetry or
network behavior.

### `pcapraven-flows` (Phase 4)

`pcapraven-flows` introduces zero third-party production dependencies.

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
