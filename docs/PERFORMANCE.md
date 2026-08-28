# Performance Verification

## Status

Phase 18.1 fuzz acceptance, Phase 18.2 performance baseline/budget work, and
the separately reviewed Phase 18.3 final performance acceptance are complete.
Three full baseline runs and the machine-readable budget artifact were
established from clean revision
`cd98fa6164ce0a6473386e9dca841cd57c599427`; three later full acceptance runs
passed the frozen budgets from clean revision
`406df29befee99d737c43728943f5daef55ea7f1`.

The accepted Phase 18 state has three distinct states:

```text
Performance baseline: ESTABLISHED
Performance budgets: FROZEN
Final acceptance execution: PASSED (Phase 18.3)
Phase 18 status: COMPLETE
```

Phase 19 release code-health audit and targeted behavior-preserving internal
refactoring is complete and accepted. Phase 19 changed only private CLI
orchestration in `analysis.rs` and `app.rs`; the frozen Phase 18 methodology,
budgets, and tracked evidence remain unchanged. The accepted three-run retry at
measurement SHA `dbcf108f1ec4f8f9c9bf14f83ef2bfb0ed3de0e6` passed stability
`24/24`, median budgets `24/24`, and growth budgets `13/13`. Rejected unstable
sets remain disclosed in `docs/CODE_HEALTH.md`. Final PR workflow run
`32889910915` for HEAD `674c8fd` passed all 13 logical jobs, and the
source-read-only Reviewer re-review found no CRITICAL or HIGH findings. Phase
20 final security and supply-chain hardening is complete and accepted; it
changed no production behavior or runtime dependency, so no new performance
comparison was required. The Phase 21 conditional performance requirement
passed using the frozen methodology, as recorded in the clean tracked result
`docs/performance/phase21-acceptance-result.json`. The independent
source-read-only Reviewer found no CRITICAL or HIGH findings, and PR-head CI
run `33091771181` passed. Phase 21 CLI v1 contract-freeze acceptance is
complete and accepted.
Phase 22 reporting schema v1 final audit is complete and accepted. Phase 23
cross-platform runtime acceptance is NEXT / NOT IMPLEMENTED; Phases 24 through
28 remain FUTURE / NOT IMPLEMENTED.

## Benchmark Infrastructure

`scripts/run_phase18_benchmarks.py` is a dependency-free tool that:

1. reads only bounded synthetic classic-PCAP fixtures;
2. creates deterministic, monotonically timestamped semantic workload captures
   in a temporary directory under a 50,000-record/256-MiB generation ceiling;
3. builds `pcapraven-cli` with `cargo build --release --locked`;
4. warms each command once;
5. measures complete CLI invocations with `time.perf_counter_ns()`;
6. reports integer nanosecond samples, minimum, median, maximum, and integer
   basis-point growth ratios; and
7. discards command stdout while preserving command/build failures on stderr and
   removes temporary captures automatically.

The release benchmark JSON identifies its schema, Phase 18.2 benchmark
implementation, exact Git revision, dirty/clean state, toolchain, operating
environment, workload identity, capture bytes, sample durations, and integer
summaries. It does not claim CPU affinity, cache isolation, thermal control,
power control, or zero background load.

The focused dependency-free tooling tests are in
`scripts/test_phase18_performance.py`. They cover matrix cardinality and scales,
unique scenario identity, growth grouping, integer budget arithmetic, and
rejection of malformed or incompatible baseline input. Linux CI runs those
tests and the separate smoke matrix; it does not run the full benchmark as a
performance gate.

## Canonical Full Matrix

The full matrix contains exactly 24 scenarios. Every full scenario executes one
unmeasured warmup followed by five measured samples (an odd sample count so the
integer median is unambiguous):

| Family | Workload/scales | Count |
| --- | --- | ---: |
| Validation | `validate_1000`, `validate_10000`, `validate_50000` records | 3 |
| Flow reconstruction | `flows_low`/128, `flows_medium`/2,048, `flows_higher`/8,192 distinct five-tuples | 3 |
| DNS analysis | `dns_1000`, `dns_10000` records | 2 |
| Unified analysis | `analyze_{benign_mixed,repeated,dns_heavy,multi_signal}_{1000,10000}` | 8 |
| Reporting / Table | `reporting_table_1000`, `reporting_table_10000` | 2 |
| Reporting / JSON | `reporting_json_1000`, `reporting_json_10000` | 2 |
| Reporting / NDJSON | `reporting_ndjson_1000`, `reporting_ndjson_10000` | 2 |
| Reporting / CSV | `reporting_csv_1000`, `reporting_csv_10000` | 2 |
| **Total** |  | **24** |

Reporting intentionally has two scales per format. Its growth groups therefore
compare 1,000 records with 10,000 records instead of comparing a format only to
itself. The smoke matrix is deliberately smaller and is tooling verification,
never baseline evidence:

```text
python3 scripts/run_phase18_benchmarks.py --smoke
```

The full matrix is run without `--smoke` from a clean revision, with each
complete run written outside the repository. Official evidence must not be
redirected into the checkout because the output file would make the measured
Git worktree dirty.

## Frozen Measurement and Budget Policy

This policy was committed before any official baseline numbers were observed
and was applied unchanged to the three replacement runs:

- Collect exactly three independent, sequential full executions from one exact
  clean Git revision. Never mix revisions, discard an unfavorable run, or rerun
  only a slow scenario.
- For scenario `S`, let `m1`, `m2`, and `m3` be the three run medians. The
  reference median is the middle ordered value.
- Run-to-run stability is
  `SPREAD_BP = (max(m1,m2,m3) - min(m1,m2,m3)) * 10000 // REFERENCE_MEDIAN`.
  Every scenario must satisfy `SPREAD_BP <= 1500` (15%). An unstable complete
  dataset is discarded as a dataset and replaced by three new runs from the
  same clean revision after investigating the environment.
- Every scenario receives an absolute median budget of
  `ceil(REFERENCE_MEDIAN * 12500 / 10000)`, a predeclared 25% margin.
- For each non-smallest scenario in a matching family/workload/format group,
  the reference growth ratio is the middle ordered value of the three baseline
  growth ratios. Its budget is
  `ceil(REFERENCE_GROWTH_BP * 12500 / 10000)`, also a predeclared 25% margin.
  The smallest scenario in each group has no growth budget (`null`).

All calculations use integer nanoseconds, basis points, and exact integer
ceiling division. The full matrix produces 24 absolute median budgets and 13
meaningful scaled growth budgets. These remain frozen regression budgets; the
independent Phase 18.3 comparison is recorded below.

## Phase 18.2 Baseline Results

The official baseline consists of exactly three sequential full benchmark runs
from clean revision `cd98fa6164ce0a6473386e9dca841cd57c599427`. Every run
reports `mode = benchmark`, the same release benchmark implementation, 24
scenarios, one warmup, and five measured samples per scenario. All three runs
report the same Git SHA and `git_dirty = false`.

Baseline stability satisfied the frozen ceiling for all 24 scenarios. The
largest observed run-to-run median spread was **1,158 basis points** for
`reporting_csv_1000`, below the 1,500-basis-point (15%) limit. No baseline run
or scenario was discarded.

| Family | Scenarios | Reference median range (ns) | Maximum spread (bp) |
| --- | ---: | ---: | ---: |
| Validation | 3 | 1,138,072–4,066,935 | 740 |
| Flows | 3 | 2,910,334–114,310,015 | 455 |
| DNS | 2 | 5,610,245–44,282,184 | 441 |
| Analyze | 8 | 7,370,879–266,752,884 | 710 |
| Reporting | 8 | 10,441,663–178,820,717 | 1,158 |

The budget derivation produced 24 absolute median budgets and 13 meaningful
scaled growth budgets. These results establish the baseline and freeze the
budgets; the separate Phase 18.3 final acceptance result is recorded below.

## Baseline Environment Contract

Absolute median timings are valid only on the baseline machine or a deliberately
established equivalent environment. Each raw measurement records, when
discoverable, the OS, kernel, architecture/platform, CPU model, logical CPU
count, total/available memory, Rust compiler, active Rust toolchain, Cargo,
Python, release profile, and reported power governor. It also states that CPU
affinity, cache state, thermal state, power state, and background load were not
controlled unless separately evidenced.

Growth ratios provide supplementary scaling evidence; they do not make absolute
cross-machine timings automatically comparable.

The official baseline environment recorded by run 1 was:

| Field | Value |
| --- | --- |
| OS | Linux |
| Kernel | `6.18.33.2-microsoft-standard-WSL2` |
| Architecture/platform | `x86_64`; `Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.43` |
| CPU | AMD Ryzen 5 5600G with Radeon Graphics |
| Logical CPUs | 12 |
| Total memory | 16,698,191,872 bytes |
| Available memory | 10,510,102,528 bytes |
| Rust compiler | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Active Rust toolchain | `1.97.1-x86_64-unknown-linux-gnu` (overridden by `rust-toolchain.toml`) |
| Cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Python | `3.14.4` |
| Build profile | `release` |
| Power/governor | Unreported; power state was not controlled |
| Limitations | Whole-process timings include CLI startup and filesystem cache effects; CPU affinity, power state, thermal state, and background load are uncontrolled. |

The complete provenance, including the full `rustc` version output, remains in
each raw measurement artifact.

### Frozen Phase 18.3 environment-equivalence amendment

Before official Phase 18.3 timing, the acceptance methodology permits one
narrow, explicit equivalence case for the frozen baseline environment. All
stable identity fields other than `total_memory_bytes` must match exactly, and
all three acceptance runs must share that same stable identity. Only Linux WSL2
may use the exception: both total-memory values must be positive and aligned to
4096 bytes, and their absolute difference must be at most one 4096-byte page.
Any larger difference, unaligned or non-positive value, non-WSL2 environment, or
difference in another stable identity field is rejected.

The evaluator records policy identifier
`phase18.3-linux-wsl2-total-memory-one-page-v1`, compatibility status, differing
fields, observed difference, and the fixed tolerance in the acceptance result.
This is a frozen Phase 18.3 equivalence policy requiring independent Reviewer
approval before official timing; it is not a general cross-machine tolerance.
It did not change the Phase 18.2 budgets, raw baseline evidence, benchmark
runner, workloads, or measurement semantics.

## Phase 18.3 Final Acceptance Results

The final acceptance methodology and measurement revision is
`406df29befee99d737c43728943f5daef55ea7f1`. It reused benchmark implementation
`phase18.2-methodology-v1` and compared exactly three sequential full runs with
one warmup and five measured samples for each of the 24 scenarios against the
frozen Phase 18.2 budget artifact. The frozen baseline measurement revision was
`cd98fa6164ce0a6473386e9dca841cd57c599427`, and the budget SHA-256 was
`d873a70258b6a52ae4a58e99515fb3caa8790fb75fa4f4a97d76a901e5b301c1`.

The result is a performance PASS: all 24/24 stability checks passed, with a
maximum observed spread of 1,485 basis points; all 24/24 absolute median
budgets passed; all 13/13 meaningful growth budgets passed; and
`overall_pass = true`.

The acceptance environment recorded by the result was:

```text
os: Linux
kernel: 6.18.33.2-microsoft-standard-WSL2
machine: x86_64
platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.43
cpu_model: AMD Ryzen 5 5600G with Radeon Graphics
logical_cpu_count: 12
total_memory_bytes: 16698187776
available_memory_bytes: 13544247296
rustc: rustc 1.97.1 (8bab26f4f 2026-07-14)
  binary: rustc
  commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452
  commit-date: 2026-07-14
  host: x86_64-unknown-linux-gnu
  release: 1.97.1
  LLVM version: 22.1.6
active_toolchain: 1.97.1-x86_64-unknown-linux-gnu (overridden by '/home/danielmr-dev/Dev/PcapRaven/rust-toolchain.toml')
cargo: cargo 1.97.1 (c980f4866 2026-06-30)
python: 3.14.4
build_profile: release
git_sha: 406df29befee99d737c43728943f5daef55ea7f1
git_dirty: false
git_worktree_status: clean
background_load: not controlled, pinned, or sampled
power_mode: unreported; power state was not controlled
limitations: Whole-process timings include CLI startup and filesystem cache effects; CPU affinity, power state, thermal state, and background load are uncontrolled.
```

The acceptance total memory differs from the frozen baseline by exactly one
4096-byte page (`16698191872` versus `16698187776`). The approved, frozen
equivalence policy `phase18.3-linux-wsl2-total-memory-one-page-v1` permits this
single positive page-aligned difference only on Linux WSL2 when every other
stable identity field matches exactly. The evaluator recorded
`equivalent_within_one_page`; this is not a general cross-machine tolerance.

The tracked Phase 18.3 evidence and SHA-256 values are:

| Artifact | SHA-256 |
| --- | --- |
| `phase18-3-acceptance-run-1.json` | `834847892046b49f154be7aec2cbc87e079c978da91fa3b19564a704a704e186` |
| `phase18-3-acceptance-run-2.json` | `af07fb7e96953491ba62d0f1126f24cd246de70c986802adf741f293e6865152` |
| `phase18-3-acceptance-run-3.json` | `3e8e4f6c238a886b4952a0513db4d0cb6f90949f307d1fb10869ea4fc5190c7a` |
| `phase18-3-acceptance-result.json` | `7ca94bcd23d87db44072edeba1afa283a343ba541072b1523c19b08e47043383` |

Two complete candidate datasets were discarded after investigation because
they exceeded the frozen stability ceiling. Candidate dataset #1 was unstable
at `dns_10000` with a 2,828-basis-point spread. Candidate dataset #2 was
unstable at `validate_50000`, `dns_1000`, `analyze_multi_signal_1000`,
`reporting_ndjson_10000`, and `reporting_csv_1000`, with a maximum spread of
17,391 basis points. Their raw files remain external diagnostics only and are
not tracked acceptance evidence; no individual run or scenario was selected
from either dataset.

## Phase 21 Conditional Performance Revalidation

Phase 21 changed production CLI source, so its acceptance gate required a new
comparison using the frozen Phase 18.2 runner, workloads, budgets, and
Phase 18.3 evaluator. The candidate was measured from clean branch
`phase-21-acceptance-closure` at SHA
`1e651373c8ddf120e46612dd47c5b547185afcb5`. No WSL restart completed during
this campaign; a restart command had been attempted earlier and aborted.
The benchmark runner and evaluator, frozen budgets, lockfiles, workload matrix,
and measurement semantics were not changed.

The exact sequential commands were:

```text
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_phase18_benchmarks.py > /tmp/pcapraven-phase21-acceptance-clean-run-1.json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_phase18_benchmarks.py > /tmp/pcapraven-phase21-acceptance-clean-run-2.json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_phase18_benchmarks.py > /tmp/pcapraven-phase21-acceptance-clean-run-3.json
python3 scripts/evaluate_phase18_acceptance.py docs/performance/phase18-2-budgets.json /tmp/pcapraven-phase21-acceptance-clean-run-1.json /tmp/pcapraven-phase21-acceptance-clean-run-2.json /tmp/pcapraven-phase21-acceptance-clean-run-3.json > /tmp/pcapraven-phase21-acceptance-clean-result.json
```

All three full benchmark commands exited `0`; the unchanged evaluator exited
`0` with `acceptance_status = passed` and `overall_pass = true`:

| Check | Result |
| --- | ---: |
| Sequential full runs | 3 |
| Scenarios per run | 24 |
| Warmup samples per scenario | 1 |
| Measured samples per scenario | 5 |
| Stability checks | 24/24 |
| Absolute median budgets | 24/24 |
| Meaningful growth budgets | 13/13 |
| Maximum acceptance spread | 1,481 bp (`validate_10000`) |
| Failed scenarios | `[]` |
| Unstable scenarios | `[]` |
| Frozen budget SHA-256 | `d873a70258b6a52ae4a58e99515fb3caa8790fb75fa4f4a97d76a901e5b301c1` |

The acceptance result recorded the following environment and compatibility
evidence:

```text
os: Linux
kernel: 6.18.33.2-microsoft-standard-WSL2
machine: x86_64
platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.43
cpu_model: AMD Ryzen 5 5600G with Radeon Graphics
logical_cpu_count: 12
page_size_bytes: 4096
physical_pages: 4076706
total_memory_bytes: 16698187776
available_memory_bytes: 14762438656
rustc: rustc 1.97.1 (8bab26f4f 2026-07-14)
  binary: rustc
  commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452
  commit-date: 2026-07-14
  host: x86_64-unknown-linux-gnu
  release: 1.97.1
  LLVM version: 22.1.6
active_toolchain: 1.97.1-x86_64-unknown-linux-gnu (overridden by '/home/danielmr-dev/Dev/PcapRaven/rust-toolchain.toml')
cargo: cargo 1.97.1 (c980f4866 2026-06-30)
python: 3.14.4
build_profile: release
git_sha: 1e651373c8ddf120e46612dd47c5b547185afcb5
git_dirty: false
git_worktree_status: clean
background_load: not controlled, pinned, or sampled
power_mode: unreported; power state was not controlled
limitations: Whole-process timings include CLI startup and filesystem cache effects; CPU affinity, power state, thermal state, and background load are uncontrolled.
```

The frozen baseline total memory was `16698191872` bytes. The candidate value
was `16698187776` bytes, a positive page-aligned difference of exactly `4096`
bytes. The unchanged evaluator recorded compatibility status
`equivalent_within_one_page` under
`phase18.3-linux-wsl2-total-memory-one-page-v1`; `total_memory_bytes` was the
only differing stable field. This is the existing Linux WSL2 one-page policy,
not a new or general cross-machine tolerance.

The exact raw measurement and evaluator JSON files are tracked under
`docs/performance/`. Each tracked file is a byte-for-byte copy of the exact
temporary path used by the evaluator; the evaluator was run while the
worktree was clean, before these copies were added to the checkout. Their
SHA-256 values are:

| Artifact | SHA-256 |
| --- | --- |
| `docs/performance/phase21-acceptance-run-1.json` (source `/tmp/pcapraven-phase21-acceptance-clean-run-1.json`) | `3d19b8c5b5e02e3248432de7f891158af2a97b03b3c64f58a5c45d277ab0e6ea` |
| `docs/performance/phase21-acceptance-run-2.json` (source `/tmp/pcapraven-phase21-acceptance-clean-run-2.json`) | `0b3e25f208544edd33fd331dcb064462c3e12641e026dbfb3efa4cb97bd50e79` |
| `docs/performance/phase21-acceptance-run-3.json` (source `/tmp/pcapraven-phase21-acceptance-clean-run-3.json`) | `ad9344bb8c53466d544f7c9cbb2d61dad939e51fa41a44ec8cdd1fb82fbc88f8` |
| `docs/performance/phase21-acceptance-result.json` (source `/tmp/pcapraven-phase21-acceptance-clean-result.json`) | `4b2db4b51a21df0ccc913f4f87189bd86d628ba517c3d20c9455da831aa7dea8` |

All three tracked run artifacts retain `git_dirty = false`,
`git_worktree_status = clean`, the candidate SHA above, and all 24 measured
scenarios. No individual run or scenario was discarded from this passing
dataset.

This dataset replaces the previously rejected Phase 21 comparison: that
candidate was two 4096-byte pages below the frozen total-memory value and was
rejected by the unchanged evaluator before timing acceptance. None of its runs
or scenarios were reused here.

## Source-Level Complexity Audit

The current implementation preserves the following bounded model:

| Layer | Expected complexity | Governing bound |
| --- | --- | --- |
| Capture reader | Linear in consumed capture bytes | maximum block, packet, buffer, record, section, and diagnostic limits |
| Packet normalizer | Linear in retained packet bytes | packet payload and IPv6 extension count/byte limits |
| DNS parser | Linear bounded wire traversal; compression revisits are finite | message, name, pointer, question, record, and retained-name limits |
| HTTP parser | Linear bounded header-line scanning | payload, line, header, selected-value, and diagnostic limits |
| TLS parser | Linear bounded record/handshake/extension scanning | payload, handshake, extension, cipher, group, and server-name limits |
| Flow reconstruction | `O(log F)` active-flow lookup per eligible packet; final ordering `O(F log F)` | tracked-flow and flow-instance limits |
| Detection | Linear or ordered-map `O(log G)` aggregation over bounded facts | flow, observation, peer-group, detector, finding, evidence, and diagnostic limits |
| Correlation | Bounded scans over primary findings and references | finding and source-reference limits |
| Reporting | Linear in bounded records plus encoded output bytes | analysis budgets, validated field limits, and writer backpressure/errors |

These controls are subordinate to correctness, security, privacy, deterministic
ordering, evidence integrity, finite resource limits, and frozen report schemas.
No production optimization is authorized merely to improve a benchmark number.

## Evidence Artifacts

The validated, tracked evidence is:

```text
docs/performance/phase18-2-baseline-run-1.json
docs/performance/phase18-2-baseline-run-2.json
docs/performance/phase18-2-baseline-run-3.json
docs/performance/phase18-2-budgets.json
```

`scripts/derive_phase18_budgets.py` accepted exactly the three full replacement
measurements, rejected smoke/dirty/mixed/duplicate/incomplete/inconsistent
inputs, checked the frozen 15% stability limit, and wrote the deterministic
budget document. The budget artifact includes source measurement SHA-256
values, baseline environment identity, and all 24 scenario budgets. The
Phase 18.3 evaluator separately validated the tracked final acceptance result.

SHA-256 checksums of the tracked evidence are:

| Artifact | SHA-256 |
| --- | --- |
| `phase18-2-baseline-run-1.json` | `cd4622f9ed0c240b5a0c5bd8d1b3d96df90128940a4154bc4e9fb13070d6c145` |
| `phase18-2-baseline-run-2.json` | `ef58cf5e29c2792147939ba23708be8d3c7a58eae517afeb2c2e43ae72766462` |
| `phase18-2-baseline-run-3.json` | `57e1b576146828f6a20ac0753509dbb8046d8c51758500862aaa41765276cbd4` |
| `phase18-2-budgets.json` | `d873a70258b6a52ae4a58e99515fb3caa8790fb75fa4f4a97d76a901e5b301c1` |

Baseline and budget status remain established and frozen. The final Phase 18.3
performance acceptance is recorded above and completes the Phase 18 gate.
