# Code Health Audit

## Scope

This ledger records Phase 19, Release code-health audit and targeted internal
refactoring. The audit covers every production Rust file under `crates/*/src`
in the seven-package runtime workspace. The authorized implementation adds no
feature, changes no public product contract, alters no reporting schema, changes
no detector or MITRE mapping, changes no workspace graph, and adds no dependency.

The governance stage added this ledger and reconciled its path in `MANIFEST.md`.
The implementation stage changes production code only in the two private CLI
orchestration files named in the Phase 19 scope; no test, Cargo, script, fixture,
CI, or reporting implementation file was changed.

## Audit Baseline

| Item | Evidence |
| --- | --- |
| Starting Git SHA | `ca325aed2d9fb1f89041a6959d665bfcc1fca099` |
| Branch | `phase-19-release-code-health` |
| Phase 18.3 prerequisite | `db1b861ef0b761859a11e9d55b6f560e05f07582` is an ancestor of the starting SHA |
| Runtime packages | 7: `pcapraven-domain`, `pcapraven-pcap`, `pcapraven-protocols`, `pcapraven-flows`, `pcapraven-detection`, `pcapraven-reporting`, `pcapraven-cli` |
| Production inventory | 59 Rust files and 28,954 source lines under `crates/*/src` |
| Workspace MSRV | Rust `1.85` |
| Pinned development toolchain | Rust `1.97.1`, `rust-toolchain.toml`, minimal profile with `rustfmt` and `clippy` |
| Observed audit environment | Linux on WSL2, `x86_64`, kernel `6.18.33.2-microsoft-standard-WSL2`; `rustc 1.97.1`, `cargo 1.97.1` |
| Cargo lock fingerprint | `ca4e23d1a3de6493a35425fbbaf69f8ba5588d90dbd351fb75c695ed3828cb19` |
| Worktree at baseline | Clean before the approved governance-only corrections; no production or golden changes |

The complete mandatory pre-refactor baseline passed. The raw smoke benchmark
JSON was retained outside the repository at
`/tmp/pcapraven-phase19-baseline-smoke.json`.

| # | Exact command | Result |
| ---: | --- | --- |
| 1 | `cargo fmt --all -- --check` | PASS |
| 2 | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | PASS |
| 3 | `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_verification_support.py` | PASS, 18 tests |
| 4 | `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_phase18_performance.py` | PASS, 17 tests |
| 5 | `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_phase18_acceptance.py` | PASS, 50 tests |
| 6 | `PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate_fixtures.py --check` | PASS, 20 fixtures |
| 7 | `PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_goldens.py` | PASS, 49 scenarios |
| 8 | `cargo test --workspace --all-features --locked` | PASS |
| 9 | `cargo test -p pcapraven-reporting --test schema_contract --locked` | PASS, 5 tests |
| 10 | `cargo test -p pcapraven-cli --test golden --locked` | PASS, 9 tests |
| 11 | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | PASS |
| 12 | `cargo metadata --format-version 1 --no-deps --locked` | PASS; seven runtime packages |
| 13 | `PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_workspace_architecture.py` | PASS |
| 14 | `cargo +1.85.0 check --workspace --all-targets --locked` | PASS |
| 15 | `cargo +1.85.0 build --workspace --locked` | PASS |
| 16 | `cargo +1.85.0 test --workspace --locked` | PASS |
| 17 | `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_phase18_benchmarks.py --smoke > /tmp/pcapraven-phase19-baseline-smoke.json` | PASS |
| 18 | `python3 -m json.tool /tmp/pcapraven-phase19-baseline-smoke.json > /dev/null` | PASS |

## Audit Methodology

The audit used the repository's Developer, Rust-quality, secure-parser,
CLI-contract, reporting, fixture/golden, fuzz-robustness, performance-analysis,
and phase-validation procedures. The methodology was:

- Enumerate the complete source set with `rg --files crates/*/src | sort` and
  verify line totals with `find crates -path '*/src/*.rs' ... wc -l`.
- Search all production sources for exact `unwrap(` and `expect(` calls,
  panic-like macros, `#[allow(...)]`, the `unsafe` token, and TODO/FIXME/XXX/HACK
  debt markers. Case-insensitive `XXX` matches in DNS binary-prefix comments
  were distinguished from actual debt markers.
- Search direct bracket expressions and slices, then inspect the surrounding
  guards, fixed-size invariants, `windows(2)` preconditions, parser offsets,
  and bounded collection operations rather than treating every array literal
  or type expression as an unsafe access.
- Search checked and saturating arithmetic and `try_from`/`try_into` usage,
  then inspect the capture and protocol trust boundaries for overflow,
  narrowing, progress, and allocation behavior.
- Inspect public and crate-private visibility, re-exports, error paths,
  diagnostics, clones, vector/string construction, repeated lifecycle logic,
  and the largest cohesive modules. Existing tests and the clean baseline were
  used as behavioral evidence; no golden was regenerated.
- Compare candidate cleanups against the canonical product, architecture,
  security, domain, detection, reporting, testing, robustness, performance,
  and roadmap contracts. A candidate is a Phase 19 target only when it is
  private, behavior-preserving, and supported by a concrete maintenance issue.

Observed audit metrics were 10 `#[allow]` attributes, two exact test-only
`unwrap`/`expect` sites, no panic-like macros, no Rust `unsafe` code, 1,317
bracket-expression candidates (including array literals and type syntax), 294
checked/saturating/try-conversion matches, 75 `.clone()` matches, 131
`Vec::...`/`vec![]` matches, and 404 string-construction matches. These are
search metrics, not defect counts.

## Audited Production Inventory

The following is the complete 59-file production inventory audited at the
baseline. Counts are files and source lines per runtime package.

- `pcapraven-cli` — 5 files, 2,576 lines:

  ```text
  crates/pcapraven-cli/src/analysis.rs
  crates/pcapraven-cli/src/app.rs
  crates/pcapraven-cli/src/args.rs
  crates/pcapraven-cli/src/diagnostics.rs
  crates/pcapraven-cli/src/main.rs
  ```

- `pcapraven-detection` — 11 files, 6,203 lines:

  ```text
  crates/pcapraven-detection/src/config.rs
  crates/pcapraven-detection/src/connection_behavior.rs
  crates/pcapraven-detection/src/correlation.rs
  crates/pcapraven-detection/src/detector.rs
  crates/pcapraven-detection/src/dns_anomaly.rs
  crates/pcapraven-detection/src/engine.rs
  crates/pcapraven-detection/src/error.rs
  crates/pcapraven-detection/src/filtering.rs
  crates/pcapraven-detection/src/lib.rs
  crates/pcapraven-detection/src/periodic_beaconing.rs
  crates/pcapraven-detection/src/registry.rs
  ```

- `pcapraven-domain` — 11 files, 6,864 lines:

  ```text
  crates/pcapraven-domain/src/dns.rs
  crates/pcapraven-domain/src/evidence.rs
  crates/pcapraven-domain/src/finding.rs
  crates/pcapraven-domain/src/flow.rs
  crates/pcapraven-domain/src/flow_metrics.rs
  crates/pcapraven-domain/src/http.rs
  crates/pcapraven-domain/src/lib.rs
  crates/pcapraven-domain/src/mitre_attack.rs
  crates/pcapraven-domain/src/observation.rs
  crates/pcapraven-domain/src/packet.rs
  crates/pcapraven-domain/src/tls.rs
  ```

- `pcapraven-flows` — 5 files, 1,386 lines:

  ```text
  crates/pcapraven-flows/src/config.rs
  crates/pcapraven-flows/src/error.rs
  crates/pcapraven-flows/src/lib.rs
  crates/pcapraven-flows/src/metrics.rs
  crates/pcapraven-flows/src/reconstructor.rs
  ```

- `pcapraven-pcap` — 2 files, 2,718 lines:

  ```text
  crates/pcapraven-pcap/src/lib.rs
  crates/pcapraven-pcap/src/reader.rs
  ```

- `pcapraven-protocols` — 9 files, 5,593 lines:

  ```text
  crates/pcapraven-protocols/src/dns.rs
  crates/pcapraven-protocols/src/dns_limits.rs
  crates/pcapraven-protocols/src/http.rs
  crates/pcapraven-protocols/src/http_limits.rs
  crates/pcapraven-protocols/src/lib.rs
  crates/pcapraven-protocols/src/limits.rs
  crates/pcapraven-protocols/src/normalizer.rs
  crates/pcapraven-protocols/src/tls.rs
  crates/pcapraven-protocols/src/tls_limits.rs
  ```

- `pcapraven-reporting` — 16 files, 3,614 lines:

  ```text
  crates/pcapraven-reporting/src/csv/mod.rs
  crates/pcapraven-reporting/src/csv_escape.rs
  crates/pcapraven-reporting/src/dto/analysis.rs
  crates/pcapraven-reporting/src/dto/dns.rs
  crates/pcapraven-reporting/src/dto/findings.rs
  crates/pcapraven-reporting/src/dto/flows.rs
  crates/pcapraven-reporting/src/dto/http.rs
  crates/pcapraven-reporting/src/dto/mod.rs
  crates/pcapraven-reporting/src/dto/tls.rs
  crates/pcapraven-reporting/src/dto/validation.rs
  crates/pcapraven-reporting/src/error.rs
  crates/pcapraven-reporting/src/format.rs
  crates/pcapraven-reporting/src/json/mod.rs
  crates/pcapraven-reporting/src/lib.rs
  crates/pcapraven-reporting/src/ndjson/mod.rs
  crates/pcapraven-reporting/src/table/mod.rs
  ```

## Audit Findings

Only evidence-backed observations are listed. `REFACTOR_PHASE_19` identifies a
private, behavior-preserving target; the implemented targets are recorded below.

| ID | Path | Category | Observation | Risk | Disposition |
| --- | --- | --- | --- | --- | --- |
| CH-001 | `crates/pcapraven-cli/src/analysis.rs:331-485` | Duplication / observation lifecycle | The DNS, HTTP, and TLS branches each repeat completeness handling, checked observation-subindex conversion, `ObservationReference` construction, `ProtocolObservation::try_new`, and budget insertion while keeping separate parser calls and diagnostics. | Parallel edits can drift in reference ordering, fatal messages, or budget behavior. | REFACTOR_PHASE_19 |
| CH-002 | `crates/pcapraven-cli/src/analysis.rs:566-614` | Duplication / private construction | Built-in detector and correlator registration is an inline sequence in the shared analysis pipeline. The exact component set and registration error messages are concrete private construction logic. | Registry changes are harder to review independently from capture execution. | REFACTOR_PHASE_19 |
| CH-003 | `crates/pcapraven-cli/src/analysis.rs:76-87` | Visibility / lint signal | `AnalysisResult` is public within the binary crate and its fields are consumed by `app.rs`, but a broad `#[allow(dead_code)]` suppresses dead-code diagnostics for the whole struct. | A future unused field could be hidden by a broad suppression. | REFACTOR_PHASE_19 |
| CH-004 | `crates/pcapraven-cli/src/app.rs:364-505` | Duplication / diagnostics lifecycle | `run_flows`, `run_dns`, `run_http`, and `run_tls` repeat emitter creation, `run_analysis` error mapping, finish/error handling, and option setup. | Lifecycle or exit-status behavior could diverge between inspection commands. | REFACTOR_PHASE_19 |
| CH-005 | `crates/pcapraven-cli/src/app.rs:529-680` | Duplication / finding filtering | `run_findings` and `run_analyze` repeat `FindingFilterDto` construction, `FindingFilter` setup, filtered finding selection, and canonical evidence closure. | Filter or evidence ordering changes may be applied to one command but not the other. | REFACTOR_PHASE_19 |
| CH-006 | `crates/pcapraven-cli/src/app.rs:427-513` | Duplication / projection allocation | DNS, HTTP, and TLS inspection commands each clone matching protocol observations from the unified collection using nearly identical loops. | Repeated projection code increases maintenance surface; the clones themselves are required by current reporting ownership. | REFACTOR_PHASE_19 |
| CH-007 | `crates/pcapraven-cli/src/analysis.rs:657-730`; `crates/pcapraven-cli/src/diagnostics.rs:131-227` | Panic search / tests | The only exact `expect(` and `unwrap(` matches are in test-only helpers: repository fixture path setup and UTF-8 conversion of a test-owned buffer. No production path contains these calls. | No malformed capture or protocol input reaches either test assertion. | NO_ISSUE |
| CH-009 | `crates/pcapraven-detection/src/correlation.rs:198`; `crates/pcapraven-domain/src/{finding,flow_metrics,mitre_attack}.rs`; `crates/pcapraven-pcap/src/reader.rs:705,1956`; `crates/pcapraven-protocols/src/normalizer.rs:729` | Allow attributes / cohesive APIs | Nine narrowly scoped `clippy::too_many_arguments` allowances occur at cohesive parser, builder, or domain-construction boundaries. | Removing them would obscure cohesive parameter contracts without improving safety. | KEEP_WITH_RATIONALE |
| CH-010 | `crates/pcapraven-protocols/src/normalizer.rs:298` | Unsafe Rust | The only `unsafe` token is in a comment explaining why fragmented transport interpretation is unsafe without reassembly. No `unsafe` item or block exists in production Rust. | No unsafe operation is enabled. | NO_ISSUE |
| CH-011 | `crates/pcapraven-detection/src/engine.rs`; `crates/pcapraven-detection/src/config.rs`; `crates/pcapraven-domain/src/{flow,finding}.rs`; `crates/pcapraven-protocols/src/{dns,http,tls}.rs`; `crates/pcapraven-pcap/src/reader.rs`; `crates/pcapraven-reporting/src/table/mod.rs` | Indexing / slicing | Direct indexing and slices occur after fixed-size, length, `windows(2)`, or parser-offset checks. Examples include byte-array formatting, DNS/TCP framing, HTTP status parsing, TLS records, and the table ALPN first-element branch. | An unreviewed boundary access would be a hostile-input defect. | NO_ISSUE |
| CH-012 | `crates/*/src/**/*.rs` | Arithmetic / conversions | The audit found checked, saturating, and `try_from`/`try_into` operations at capture, parser, flow, detector, and reporting boundaries. Narrowing casts are paired with protocol or configured limits where inspected. | Unchecked length or narrowing arithmetic could panic or mis-size work. | NO_ISSUE |
| CH-013 | `crates/pcapraven-pcap/src/reader.rs`; `crates/pcapraven-protocols/src/{normalizer,dns,http,tls}.rs` | Parser bounds / progress | Capture reads use checked offsets and bounded reads; DNS name-pointer traversal has a configured hop cap; HTTP line scanning is bounded; DNS, HTTP, and TLS cursor movement is checked or saturating and terminates on incomplete/resource-limited input. | Parser loops must remain finite and must not retain or allocate unbounded attacker-controlled data. | NO_ISSUE |
| CH-014 | `crates/*/src/**/*.rs` | Errors / diagnostics | Production fallible boundaries use `Result`, typed errors, bounded diagnostics, or explicit partial outcomes. The panic search found no panic macros, and the baseline clippy/test gates passed. | Collapsing malformed input into a panic or unbounded diagnostic would violate the security model. | NO_ISSUE |
| CH-015 | `crates/*/src/lib.rs`; `crates/pcapraven-cli/src/analysis.rs`; `crates/pcapraven-reporting/src/{dto,lib.rs}` | Visibility / public API | Library re-exports and reporting DTOs define the accepted crate boundaries. `AnalysisResult` is an internal binary-crate result consumed by the CLI dispatcher; no public API cleanup is justified outside the private Phase 19 targets. | Public signature changes would exceed a behavior-preserving code-health audit. | KEEP_WITH_RATIONALE |
| CH-016 | `crates/*/src/**/*.rs` | Clones / allocations | The inventory contains 75 `.clone()` matches, 131 vector-construction matches, and 404 string-construction matches. Most support ownership, bounded retention, deterministic DTO conversion, or terminal-safe rendering; the repeated CLI projections are separately targeted in CH-006. | Blanket allocation removal could change ownership, retention, output, or bounds. | KEEP_WITH_RATIONALE |
| CH-017 | `crates/pcapraven-pcap/src/reader.rs`; `crates/pcapraven-protocols/src/{dns,http,tls}.rs`; `crates/pcapraven-detection/src/{engine,dns_anomaly,connection_behavior}.rs` | Large cohesive modules | The largest modules are cohesive capture, protocol, domain, detection, and CLI units. The largest are `reader.rs` (2,702 lines), `tls.rs` (1,516), `evidence.rs` (1,466), `engine.rs` (1,429), and `dns_anomaly.rs` (1,230). | Splitting solely by line count could obscure parser or invariant ownership and create new interfaces. | KEEP_WITH_RATIONALE |
| CH-018 | `crates/pcapraven-cli/src/args.rs:1-696` | CLI contract | Argument declarations, defaults, validation, and subcommand routing are intentionally centralized and are covered by the CLI contract and golden tests. No code-health issue warrants changing this public behavior in Phase 19. | A cosmetic argument refactor could alter help, defaults, exit codes, or accepted syntax. | KEEP_WITH_RATIONALE |
| CH-019 | `crates/pcapraven-reporting/src/**/*.rs` | Reporting contract | Reporting DTO, Table, JSON, NDJSON, CSV, escaping, and output error modules are already separated by format and schema responsibility. Their structure and serialized fields are not refactoring targets. | Changing shape or field order could invalidate frozen schema and golden outputs. | KEEP_WITH_RATIONALE |
| CH-020 | `crates/pcapraven-protocols/src/dns.rs`; `crates/pcapraven-protocols/src/http.rs`; `crates/pcapraven-protocols/src/tls.rs`; `crates/pcapraven-detection/src/{engine,dns_anomaly,connection_behavior}.rs` | Security / robustness debt | No actual TODO, FIXME, HACK, or XXX debt marker was found. Case-insensitive `XXX` search hits are DNS comments describing binary prefixes, not deferred work. | No evidence supports speculative cleanup. | NO_ISSUE |

The `Path` cells using a brace list are exact members of the inventory listed
above; they are only a compact presentation of multiple audited files.

## Implemented Refactors

The following audited targets were implemented as private helpers without
changing observable behavior:

- CH-001 — `crates/pcapraven-cli/src/analysis.rs`: `ObservationIngestion` and
  `ingest_observations` now own the shared DNS/HTTP/TLS observation lifecycle.
  The three parser calls and diagnostic loops remain explicit. The helper keeps
  completeness marking, checked `usize` to `u32` conversion, exact protocol and
  packet ordering, exact overflow/construction messages, budget handling, fatal
  errors, and insertion order unchanged.
- CH-002 — `crates/pcapraven-cli/src/analysis.rs`: `build_builtin_registries`
  contains the same four detectors and one correlator in the same registration
  order, with the same metadata validation, canonical registry behavior, and
  error strings.
- CH-003 — `crates/pcapraven-cli/src/analysis.rs`: the broad
  `AnalysisResult` `#[allow(dead_code)]` was removed; all fields, methods, and
  ownership remain intact.
- CH-004 — `crates/pcapraven-cli/src/app.rs`: `execute_analysis` centralizes
  emitter creation, `run_analysis` error translation, finalization, and I/O
  handling for analysis-backed inspection commands while preserving exit codes.
- CH-005 — `crates/pcapraven-cli/src/app.rs`: `build_finding_filter_dto` and
  `filter_findings_and_evidence` centralize DTO construction, owned filter IDs,
  finding order, and canonical evidence closure for findings and analysis.
- CH-006 — `crates/pcapraven-cli/src/app.rs`:
  `project_protocol_observations` centralizes only the DNS/HTTP/TLS clone loops;
  it preserves clone ownership and the existing reporting API inputs.

All helpers are private to the CLI binary. No parser, detector, correlator,
MITRE, reporting DTO, serialization, argument, or workspace interface was
changed.

## Intentional Non-Refactors

- The cohesive capture reader, packet normalizer, DNS/HTTP/TLS parsers,
  domain evidence/finding models, flow metrics, detection engine, and reporting
  format modules remain intact. Their boundaries follow the architecture and
  security contracts; line count alone is not evidence for a safe split.
- The nine narrow `clippy::too_many_arguments` allowances remain because the
  audited functions are cohesive constructors or parser/building boundaries.
- Existing clones and bounded allocations remain where they preserve ownership,
  report DTO independence, deterministic order, or explicit resource limits.
- Reporting DTOs, schema fields, serialization order, sanitization, and output
  file behavior remain unchanged. No golden or fixture is regenerated.
- No dependency, workspace membership, public library API, detector set,
  correlator set, detector metadata, MITRE mapping, or evidence contract is
  changed by this implementation stage.

## Contract Preservation

The audit preserves the accepted Phase 18.3 baseline and the repository
invariants: untrusted capture/protocol input remains bounded; parsing produces
normalized facts; detection consumes facts; severity and confidence remain
separate; no heuristic is promoted to a definitive malware or C2 claim; unsafe
Rust remains denied; and stdout remains result-only while diagnostics use
stderr.

The implementation keeps the three parser calls (`parse_dns_packet`,
`parse_http_packet`, and `parse_tls_packet`) explicit, retains exact diagnostic
text and observation-reference ordering, preserves budget and fatal-error
behavior, retains built-in detector/correlator metadata and order, preserves
finding/evidence order and filters, and leaves all reporting public types
untouched.

## Golden/Schema Verification

The clean baseline passed the frozen golden and schema gates: 49 golden
scenarios, five reporting schema-contract tests, and nine CLI golden tests.
After any authorized Phase 19 implementation refactor, the unchanged golden
and schema contracts must be rerun exactly as follows:

```text
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_goldens.py
cargo test -p pcapraven-reporting --test schema_contract --locked
cargo test -p pcapraven-cli --test golden --locked
```

The acceptance condition is zero diff under `tests/golden`, no staging or
regeneration of golden files, and unchanged schema-contract and CLI-golden
results. The implementation stage made no golden or schema changes. Post-change
verification passed with 49 `check_goldens.py` scenarios, five reporting
schema-contract tests, and nine CLI golden tests; `tests/golden` remained
byte-identical.

## Performance Implications

The refactors add private dispatch helpers but no additional retained data,
nested scans, parser passes, or unbounded allocations. The projection helper
retains the existing bounded clone ownership. The first three-run full
revalidation set for the remediation baseline,
`/tmp/pcapraven-phase19-final-run-1.json` through
`/tmp/pcapraven-phase19-final-run-3.json`, was not accepted: stability was
`23/24` because `flows_higher` was unstable.

The subsequent retry set is the accepted performance evidence for remediation
baseline commit `dbcf108f1ec4f8f9c9bf14f83ef2bfb0ed3de0e6`:
`/tmp/pcapraven-phase19-final-retry-1.json` through
`/tmp/pcapraven-phase19-final-retry-3.json` passed with stability `24/24`,
median budgets `24/24`, growth budgets `13/13`, and `overall_pass = true`; the
measurement SHA is `dbcf108f1ec4f8f9c9bf14f83ef2bfb0ed3de0e6`. These files remain
outside the repository. Phase 18 evidence was not replaced, and no Phase 19
benchmark output was committed.

The fresh docs-only commit
`85764a12440bee41e4ff5ed2368717b427cdf5ee` was also evaluated with
`/tmp/pcapraven-phase19-accepted-run-1.json` through
`/tmp/pcapraven-phase19-accepted-run-3.json`; the set was `unstable`, with
stability `23/24`, median budgets `24/24`, growth budgets `13/13`, failed
scenario `flows_higher`, and `overall_pass = false`. It was not accepted and is
not a runtime regression because `85764a1` changed documentation only.

The performance gate used exactly three full runs from the compatible baseline
environment:

```text
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_phase18_benchmarks.py > /tmp/pcapraven-phase19-run-1.json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_phase18_benchmarks.py > /tmp/pcapraven-phase19-run-2.json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_phase18_benchmarks.py > /tmp/pcapraven-phase19-run-3.json
python3 scripts/evaluate_phase18_acceptance.py docs/performance/phase18-2-budgets.json /tmp/pcapraven-phase19-run-1.json /tmp/pcapraven-phase19-run-2.json /tmp/pcapraven-phase19-run-3.json > /tmp/pcapraven-phase19-performance-result.json
python3 -m json.tool /tmp/pcapraven-phase19-performance-result.json > /dev/null
```

Acceptance requires stability `24/24`, median `24/24`, growth `13/13`, and
overall `true`. The earlier `bdd913e2c52b48cdb96c6a887b989f605cb6a5fa` retry is
historical context only and is not the final accepted set for this remediation
baseline.

## Fuzz/Robustness Implications

Only private CLI orchestration changed; no fuzzed library or parser surface
changed. The accepted Phase 18.1 full eight-target fuzz evidence therefore
remains applicable to this refactor and is not replaced by the local evidence
below.

The exact CI-form `fuzz_pcap_reader` command was attempted on WSL2 with
`ptrace_scope=1`:

```text
cargo +nightly fuzz run "fuzz_pcap_reader" "fuzz/corpus/fuzz_pcap_reader" -- \
  -max_len=4096 -max_total_time=30 -timeout=5 -rss_limit_mb=1024
```

The 30-second campaign completed without a code crash, but LeakSanitizer
teardown exited 1 because the host ptrace policy is incompatible with the
sanitizer. The generated empty artifact was removed. This is a WSL2
host/tooling result, not a passing CI result.

A local `ASAN_OPTIONS=detect_leaks=0` workaround completed all eight targets
with the exact CI limits. The logs are retained outside the repository under
`/tmp/pcapraven-fuzz-fuzz_*.log`, including
`/tmp/pcapraven-fuzz-fuzz_pcap_reader.log`:

| Target | CI `max_len` | Local log |
| --- | ---: | --- |
| `fuzz_pcap_reader` | 4096 | `/tmp/pcapraven-fuzz-fuzz_pcap_reader.log` |
| `fuzz_packet_normalizer` | 8192 | `/tmp/pcapraven-fuzz-fuzz_packet_normalizer.log` |
| `fuzz_flow_reconstructor` | 4096 | `/tmp/pcapraven-fuzz-fuzz_flow_reconstructor.log` |
| `fuzz_dns_parser` | 4096 | `/tmp/pcapraven-fuzz-fuzz_dns_parser.log` |
| `fuzz_http_parser` | 8192 | `/tmp/pcapraven-fuzz-fuzz_http_parser.log` |
| `fuzz_tls_parser` | 32768 | `/tmp/pcapraven-fuzz-fuzz_tls_parser.log` |
| `fuzz_detection_engine` | 4096 | `/tmp/pcapraven-fuzz-fuzz_detection_engine.log` |
| `fuzz_reporting` | 8192 | `/tmp/pcapraven-fuzz-fuzz_reporting.log` |

Every local command used `-max_total_time=30`, `-timeout=5`, and
`-rss_limit_mb=1024` in addition to the target-specific `max_len` above. This
local workaround evidence is not equivalent to authoritative Linux CI. PR
workflow run `32889910915` for HEAD `674c8fd` completed successfully with 13
logical jobs: Linux quality, MSRV `1.85`, three cross-platform workspace checks
(Linux, Windows, and macOS), and eight Linux fuzz-smoke matrix jobs. All eight
fuzz jobs passed,
and no crash artifacts were uploaded. A full new 600-second campaign is not
required for a CLI-only private refactor unless a fuzzed library surface
changes; any such change must be re-audited before that exception is used.

## Remaining Review Observations

- The independent source-read-only Reviewer re-review confirmed scope, behavior
  preservation, hostile-input safety, phase boundaries, and final validation
  evidence with zero CRITICAL and zero HIGH findings. The temporary CI and
  review gate observation is closed by workflow run `32889910915` and this
  review result.
- The first three-run full revalidation set,
  `/tmp/pcapraven-phase19-final-run-1.json` through
  `/tmp/pcapraven-phase19-final-run-3.json`, was not accepted because
  `flows_higher` made stability fail at `23/24`. The subsequent retry inputs,
  `/tmp/pcapraven-phase19-final-retry-1.json`,
  `/tmp/pcapraven-phase19-final-retry-2.json`, and
  `/tmp/pcapraven-phase19-final-retry-3.json`, passed with `24/24` stability,
  `24/24` median budgets, `13/13` growth budgets, and `overall_pass = true` at
  measurement SHA `dbcf108f1ec4f8f9c9bf14f83ef2bfb0ed3de0e6`. They remain outside
  the repository and do not replace Phase 18 evidence. The earlier
  `bdd913e2c52b48cdb96c6a887b989f605cb6a5fa` retry is historical context only,
  not the final accepted set.
- The authoritative eight-target Linux fuzz smoke and PR CI result are
  recorded above as successful in workflow run `32889910915` for HEAD
  `674c8fd`; the local LeakSanitizer workaround remains separately disclosed
  because it is not equivalent to Linux CI.
- The governance stage updated `MANIFEST.md` to include `docs/CODE_HEALTH.md`;
  the new ledger path is reconciled with the repository inventory.
- No additional evidence-backed code-health issue was identified beyond the
  listed Phase 19 private targets and intentional non-refactors.

## Phase Status

Phase 18.3 remains complete. Phase 19 is COMPLETE and accepted: the complete
production audit, targeted private refactors, final post-change gates, and
independent Reviewer pass are recorded. Phase 20 final security and
supply-chain hardening is complete and accepted; its evidence is recorded in
`docs/SUPPLY_CHAIN.md`. Phase 21 is next, future, and not implemented; Phases
22 through 28 remain future and not implemented. No Phase 19 feature, release,
or later-phase capability is claimed.
