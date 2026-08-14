# Testing Strategy

## Status

Phase 0 documentation and governance work, Phase 1 workspace/tooling work, and
Phase 2 capture-container ingestion tests are complete. Phase 3 adds unit,
boundary, property, and fuzz tests for Ethernet, IPv4/IPv6, and TCP/UDP
normalization in `pcapraven-protocols`. Flow, application decoders, detection,
reporting, and CLI testing remain future phase work.

## Testing Pyramid

### Unit Tests

Unit tests cover local invariants and transformations: checked length and
offset calculations, Ethernet II header normalization, IPv4 options and total
length checks, IPv6 extension header bounded traversal, TCP/UDP headers and
flags, payload truncation, and diagnostic emission.

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

Property tests use `proptest` for the Phase 2 reader and Phase 3 normalizer.
Implemented properties include:

- Parsing arbitrary bytes never panics and respects configured limits.
- Arbitrary link types are handled deterministically without panics.
- Truncating valid PCAP/PCAPNG and packet prefixes never panics or claims
  completeness.
- Identical input yields strictly identical normalized output (determinism).
- Retained transport payload never exceeds `maximum_retained_payload_bytes`.
- Emitted diagnostics never exceed `maximum_diagnostics_per_packet`.

### Fuzzing Strategy

Fuzzing uses an excluded `fuzz/` package and `libfuzzer-sys` with two targets:
`fuzz_pcap_reader` for capture-container parsing and `fuzz_packet_normalizer`
for protocol normalization. The targets call only public bounded APIs and do
not access files or networks. The checked-in CI build commands are:

```text
cargo +nightly fuzz build fuzz_pcap_reader
cargo +nightly fuzz build fuzz_packet_normalizer
```

Long-running `cargo-fuzz` campaigns and additional structured targets remain
future work. Planned targets include:

- PCAP and PCAPNG container ingestion.
- Link, network, and transport normalization.
- DNS, HTTP/1.x, and TLS handshake parsers.
- Stateful parser sequences and flow updates with structured generated input.
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

These paths are planned for Phase 17 and intentionally do not exist in Phase 2.

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

## Phase 2 Quality Gates

The Phase 2 Linux quality job runs the following baseline gates with the pinned
development toolchain:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo metadata --format-version 1 --no-deps --locked
python3 scripts/check_workspace_architecture.py
```

The separate CI fuzz build job verifies the excluded fuzz harness using the
nightly toolchain and pinned `cargo-fuzz = 0.13.2`:

```text
cargo +nightly fuzz build fuzz_pcap_reader
```

The CI job uses locked dependency resolution for workspace quality, metadata,
test, and documentation invocations where Cargo supports it. The architecture
checker also passes `--locked` and `--offline` to Cargo metadata. A separate
locked MSRV job runs `cargo +1.85.0 check --workspace --locked`, `cargo +1.85.0 build
--workspace --locked`, and `cargo +1.85.0 test --workspace --locked`. A
lightweight `cargo check --workspace --locked` runs on Linux, Windows, and
macOS. The architecture checker rejects unexpected packages, roles, external
dependencies, and dependency directions. The workspace lint policy rejects
project `unsafe` code by default. The fuzz package is excluded from the seven
package main workspace and is validated by its separate locked fuzz build command.
Phase-appropriate fixtures and long-running fuzz campaigns remain future work.

## Phase 0 Validation (completed)

Phase 0 used read-only repository inspection rather than Cargo gates. It
required the governance files, valid internal links and OpenCode frontmatter,
consistent terminology, the exact roadmap, and confirmation that no
implementation or later-phase functionality had been introduced. Phase 1
replaced the Phase 0 absence checks with the workspace and topology gates above.

## Phase 1 Validation

Phase 1 validation confirms the exact seven-package virtual workspace, Edition
2024 and resolver 3 settings, workspace package metadata, internal-only graph,
forbidden-unsafe lint, generated lockfile, pinned development toolchain, and
absence of protocol or analysis behavior. It also checks that documentation and
the repository manifest identify Phase 0 and Phase 1 as complete and Phase 2 as
the current capture-reader phase.

## Phase 2 Validation

Phase 2 validation confirms the documented PCAP/PCAPNG subset, owned packet-byte
extraction, integer-only timestamp handling, section-local interface state,
bounded records and diagnostics, explicit completion state, safe recovery only at
validated block boundaries, arbitrary-input no-panic properties, truncation and
limit boundaries, and the public-API fuzz target build. It also confirms that no
protocol normalization, flow reconstruction, detector, reporter, or functional
CLI behavior has been introduced.

## Phase 2 Dependency Audit

The production parser dependency is exact `pcap-parser = 0.17.0`, licensed
MIT/Apache-2.0, with declared MSRV 1.65. Its default feature set is empty in this
project and the optional `data` and `serialize` features are disabled. The direct
normal dependency footprint is `circular 0.3`, `nom 8`, and
`rusticata-macros 5`; it has no application network or telemetry behavior. The
source audit found a narrowly scoped explicitly allowed unsafe helper in
`pcap-parser` and unsafe pointer-copy internals in transitive `circular`; no
project unsafe code is added. Crates.io release metadata and the upstream
project were inspected for maintenance posture at audit time:
<https://crates.io/crates/pcap-parser/0.17.0> and
<https://github.com/rusticata/pcap-parser>. Any update requires repeating this
review.

The test dependency is exact `proptest = 1.11.0`, licensed MIT/Apache-2.0, with
declared MSRV 1.85. It uses `default-features = false` and only the `std`
feature, avoiding unrelated optional features. It is dev-only and performs local
property generation without application network behavior.
The crates.io release and upstream project were inspected at audit time:
<https://crates.io/crates/proptest/1.11.0> and
<https://github.com/proptest-rs/proptest>. Any update requires repeating this
review.

The excluded fuzz package uses exact `libfuzzer-sys = 0.4.13`, licensed
`(MIT OR Apache-2.0) AND NCSA`, with its default `link_libfuzzer` feature. It
builds native libFuzzer code through `cc` and is intentionally confined to fuzz
development/CI; it is not linked into the production workspace or application
runtime. Its build has no configured telemetry or capture upload path. The
fuzz-only dependency has no declared MSRV and is therefore separately checked
by its locked build rather than changing the project MSRV contract.
Its release metadata was inspected at
<https://crates.io/crates/libfuzzer-sys/0.4.13>; any update requires a separate
fuzz dependency review.

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
