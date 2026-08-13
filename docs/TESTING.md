# Testing Strategy

## Status

Phase 0 contains no Rust workspace, tests, fixtures, fuzz targets, or CI
workflow. This document defines the strategy to be implemented in later roadmap
phases. The commands below are future quality gates and are not currently
runnable in this repository.

## Testing Pyramid

### Unit Tests

Unit tests will cover local invariants and transformations: checked length and
offset calculations, normalization, canonical flow keys, statistics, detector
thresholds, escaping, filtering, and error classification. Tests should favor
small exhaustive boundary tables where practical.

### Fixture and Golden Tests

Fixture tests will pass known captures or normalized inputs through one or more
stages. Golden outputs will lock intentional diagnostics, normalized records,
findings, ordering, and serialized schemas. Golden changes require human review
and an explanation; they must never be updated blindly merely to make tests
pass.

### Integration Tests

Integration tests will verify crate boundaries and data exchange, including
capture ingestion to normalization, normalized packets to flows, observations
and flows to detectors, and domain results to reporters. Error and partial-data
paths are first-class cases.

### End-to-End Tests

End-to-end tests will invoke the compiled CLI with synthetic captures and
verify exit status, stdout/stderr separation, output-file behavior, format
validity, filters, quiet/verbose behavior, deterministic output, and hostile
terminal text handling.

### Property-Based Tests

Property tests will use `proptest`. Target properties include:

- Parsing arbitrary bytes never panics and respects configured limits.
- Successful parser steps consume input or transition state; loops always make
  progress.
- Declared and captured lengths cannot cause overflow or out-of-bounds access.
- Normalizing an already normalized supported value is stable where the
  operation is defined as idempotent.
- Reversing packet direction preserves the canonical bidirectional flow key and
  swaps only directional statistics.
- Packet and byte totals equal checked sums of directional values.
- Flow duration and inter-arrival metrics are never negative.
- Shuffling independent detector execution does not change canonical findings.
- Serialization round trips preserve the documented machine-readable domain
  projection where round trips are supported.
- Filters are monotonic: raising a minimum threshold cannot add findings.

Generators must emphasize zero, one-less-than, exact, and one-more-than limit
boundaries; truncation at every structural boundary; extreme timestamps and
lengths; duplicated and reordered events; unknown values; and valid structures
with adversarial nesting or counts.

Property regressions are reduced to minimal examples and retained as ordinary
tests or corpus entries.

## Fuzzing Strategy

Fuzzing will use `cargo-fuzz` beginning with the capture reader in Phase 2 and
expanding with each parser. Planned targets include:

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

These paths are planned for Phase 17 and intentionally do not exist in Phase
0.

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
and redistributable under terms compatible with Apache-2.0. Every fixture must
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

## Future CI Quality Gates

Once the Phase 1 workspace and CI exist, every supported change must pass:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

CI must also reject committed project `unsafe` code unless it follows the
approved exception process, verify required documentation and dependency
boundaries, and run phase-appropriate fixture/property/fuzz smoke tests as they
are introduced. Additional tools and gates require dependency/toolchain review
rather than being silently assumed in Phase 0.

## Phase 0 Validation

Phase 0 uses read-only repository inspection rather than Cargo gates. It
requires all planned governance files, valid internal links and OpenCode
frontmatter, consistent terminology, the exact roadmap, and confirmation that
no workspace, source code, fixtures, CI, parser, or later-phase functionality
has been introduced.

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
