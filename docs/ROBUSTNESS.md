# Robustness Verification

## Status

Phase 18.1 has executed and completed all eight required 600-second full fuzz
acceptance campaigns. All eight public-API fuzz targets passed without crashes,
panics, hangs, uncontrolled memory growth, or invariant violations. All discovered
boundary edge cases were triaged, fixed in safe Rust, and hardened with deterministic
regression test coverage. Phase 18.2 performance baseline and acceptance
budgets are complete and tracked in `PERFORMANCE.md` and `docs/performance/`.
Phase 18.3 final performance acceptance is complete and passed the frozen
budgets. Phase 19 release code-health audit and targeted behavior-preserving
internal refactoring is complete and accepted. Phase 20 final security and
supply-chain hardening is complete and accepted without changing the fuzzed
production surfaces. Release packaging is Phase 24 future work; Phase 21 is
next, future, and not implemented; Phases 22 through 28 remain future and not
implemented.

## Threat Model and Invariants

All capture bytes, protocol bytes, structured fuzz bytes, serialized values,
paths, and output failures are untrusted. Robustness verification requires:

- no malformed-input panic, unchecked external-input indexing, unchecked
  narrowing, or unchecked length arithmetic before a product API is called;
- finite packet, record, flow, observation, finding, evidence, diagnostic,
  retained-byte, recursion, and output bounds;
- deterministic output for identical normalized input;
- explicit partial/resource-limited outcomes rather than silent truncation;
- canonical flow/finding/evidence ordering and resolvable references;
- non-retention of sensitive HTTP header values and TLS random/session-secret
  material; and
- no filesystem or network access from fuzz targets.

The Python and Rust fixture/golden verifiers accept an explicit trusted
repository root plus a relative canonical path. They validate every component
below that root, use streaming directory iteration and bounded reads, and apply
explicit path-component, depth, examined-entry, and regular-file limits. Static
symlinked ancestors, symlink leaves, and non-regular roots/files/directories are
rejected before the target file is opened or its directory is scanned. Canonical
fixture/golden checks complete structural discovery as a hard precondition;
discovery failure prevents expected-byte reads and CLI scenario execution.

On Unix, Python canonical reads open each relative component from a directory
descriptor with `O_NOFOLLOW` where the standard library exposes the required
operations, then compare descriptor/path identity. The portable Python fallback
and the safe standard-library Rust helper perform bounded component validation
before and after opening or traversal. Unix device/inode pairs are observable
identity; the Windows/non-Unix file-type, length, and modification-time tuples
are only portable observable-state snapshots and are not described as true file
identity.

These controls guarantee refusal for a static symlinked ancestor in the trusted
checkout. Except for the anchored Unix Python read path, they do not claim an
atomic defense against a concurrently mutating local filesystem: a replacement
between validation and open can be opened before a later observable-state check
rejects it. Verification therefore assumes the trusted checkout is not being
concurrently modified by another local actor. No cross-platform universal
atomic-traversal guarantee is claimed.

## Fuzz Target Matrix

The excluded `fuzz/` package has exactly eight public-API targets. Curated,
synthetic seeds live under `fuzz/corpus/<target>/`; all newly generated corpus
entries, artifacts, coverage files, and profiles remain ignored.

The reviewed corpus contains exactly 16 named seeds, two per target. There are
no checked-in libFuzzer hash-named mutations:

| Target | `seed-minimal` | `seed-structured` |
| --- | --- | --- |
| `fuzz_pcap_reader` | 24-byte empty classic PCAP | 28-byte empty PCAPNG section |
| `fuzz_packet_normalizer` | 14-byte Ethernet frame | 71-byte Ethernet/IPv4/UDP/DNS frame |
| `fuzz_flow_reconstructor` | one 18-byte control record | three timestamped control records |
| `fuzz_dns_parser` | 12-byte empty DNS header | 29-byte `example.com` A query |
| `fuzz_http_parser` | complete minimal request | complete request with selected headers |
| `fuzz_tls_parser` | empty TLS handshake record | synthetic TLS 1.3 ClientHello fixture bytes |
| `fuzz_detection_engine` | one flow and observation controls | 16-flow/32-observation detector controls |
| `fuzz_reporting` | one-byte attacker-control input | bounded control/Unicode/formula selector bytes |

All seeds are project-generated synthetic encodings or control bytes and contain
no production traffic or sensitive data. A short fuzz run may create ignored
hash-named mutations; verification records the physical inventory before and
after each run and removes those mutations before review.

| Target | Maximum input bytes | Primary assertions |
| --- | ---: | --- |
| `fuzz_pcap_reader` | 4096 | deterministic records/diagnostics, record and retained-byte limits, streaming progress |
| `fuzz_packet_normalizer` | 8192 | deterministic normalization, payload/diagnostic/IPv6-extension limits |
| `fuzz_flow_reconstructor` | 4096 | deterministic lifecycle output, unique ordered flow references, directional sums, exact temporal invariants |
| `fuzz_dns_parser` | 4096 | bounded observations/diagnostics/questions/records and aggregate expanded bytes for question, owner, and name-bearing RDATA names |
| `fuzz_http_parser` | 8192 | bounded deterministic parsing and sensitive-header value non-retention |
| `fuzz_tls_parser` | 32768 | bounded deterministic handshake parsing and TLS random non-retention |
| `fuzz_detection_engine` | 4096 | at most 16 flows/32 observations, bounded engine output, canonical references, correlation evidence reuse |
| `fuzz_reporting` | 8192 | deterministic Table/JSON/NDJSON/CSV rendering, strict machine-reference token types, packet/flow/observation/evidence/source-finding closure, canonical source ordering, terminal safety, and writer failures |

`serde_json = 1.0.140` is an exact fuzz-only dependency used to validate emitted
JSON/NDJSON and exercise bounded malformed JSON values. It is already the exact
version audited and locked for `pcapraven-reporting`; it does not change a
runtime crate dependency. `csv = 1.3.1` is likewise exact, uses
`default-features = false`, and is reused only to structurally validate emitted
CSV records in `fuzz_reporting`.

## CI Smoke Profile

Linux CI runs each matrix target independently with its target-specific
`-max_len` and the common finite profile:

```text
-max_total_time=30 -timeout=5 -rss_limit_mb=1024
```

The architecture checker audits the excluded package, exact dependency forms,
and exact eight-target set without adding it to the seven-package main
workspace.

## Acceptance Campaigns

Acceptance campaigns executed full 600-second fuzzing campaigns independently
and sequentially for each of the eight public-API fuzz targets on Linux x86_64
(`rustc 1.99.0-nightly`, `cargo-fuzz 0.13.2`). Over 101 million total executions
were performed with zero crashes, hangs, sanitizer violations, or unhandled
panics.

| Target | Duration | Executions | Result | Regression promoted |
| --- | ---: | ---: | --- | --- |
| `fuzz_pcap_reader` | 600 s | 11,563,611 | Passed | `crates/pcapraven-pcap/tests/reader.rs:phase18_pcapng_short_block_length_handled_without_panic` |
| `fuzz_packet_normalizer` | 600 s | 65,804,400 | Passed | `crates/pcapraven-protocols/tests/normalization.rs:ipv6_extension_count_and_byte_limits_boundary` |
| `fuzz_flow_reconstructor` | 600 s | 3,410,610 | Passed | None (zero defects) |
| `fuzz_dns_parser` | 600 s | 8,168,151 | Passed | None (zero defects) |
| `fuzz_http_parser` | 600 s | 6,242,558 | Passed | None (zero defects) |
| `fuzz_tls_parser` | 600 s | 5,663,878 | Passed | None (zero defects) |
| `fuzz_detection_engine` | 600 s | 407,715 | Passed | None (zero defects) |
| `fuzz_reporting` | 600 s | 65,794 | Passed | None (zero defects) |

Any crash, timeout, sanitizer finding, invariant failure, or uncontrolled memory
growth blocks acceptance. Reproducers must be minimized, reviewed for privacy,
fixed at the owning layer, and then checked in only as an intentional regression
test with documented provenance. All 16 curated synthetic seed fixtures remain
intact and verified.

The Phase 18.1 fuzz evidence remains applicable: no production Rust surface
changed after the accepted fuzz revision. The Phase 18.2 Windows EOL remediation
and Phase 18.3 acceptance evaluator/evidence changes were repository-policy,
tooling, or documentation changes and did not alter fuzzed production behavior.
Together with the completed final performance acceptance, this closes the
Phase 18 robustness and performance gate.
