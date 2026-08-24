# Robustness Verification

## Status

Phase 18 Part B has implemented the bounded fuzzing and verifier-hardening
foundation described here. The eight required 600-second acceptance campaigns
have not been run in this change and remain **pending**. This document therefore
does not claim Phase 18 completion or release readiness.

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

Acceptance requires a separate, controlled run of every target for 600 seconds
using the same maximum input lengths and documented environment/tool versions.
No row may be marked passed from a build or 30-second smoke run.

| Target | Duration | Result | Regression promoted |
| --- | ---: | --- | --- |
| `fuzz_pcap_reader` | 600 s | Pending | Pending |
| `fuzz_packet_normalizer` | 600 s | Pending | Pending |
| `fuzz_flow_reconstructor` | 600 s | Pending | Pending |
| `fuzz_dns_parser` | 600 s | Pending | Pending |
| `fuzz_http_parser` | 600 s | Pending | Pending |
| `fuzz_tls_parser` | 600 s | Pending | Pending |
| `fuzz_detection_engine` | 600 s | Pending | Pending |
| `fuzz_reporting` | 600 s | Pending | Pending |

Any crash, timeout, sanitizer finding, invariant failure, or uncontrolled memory
growth blocks acceptance. Reproducers must be minimized, reviewed for privacy,
fixed at the owning layer, and then checked in only as an intentional regression
seed with documented provenance. No `fuzz/regressions/` result is claimed by
this foundation change.
