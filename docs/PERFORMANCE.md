# Performance Verification

## Status

Phase 18.1 fuzz acceptance and Phase 18.2 performance baseline/budget work are
complete. Three full baseline runs and the machine-readable budget artifact are
established from clean revision
`cd98fa6164ce0a6473386e9dca841cd57c599427`. Final performance acceptance has
not been executed; Phase 18.3 remains separate and pending.

The current Phase 18 state has three distinct states:

```text
Performance baseline: ESTABLISHED
Performance budgets: FROZEN
Final acceptance execution: PENDING (Phase 18.3)
```

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
meaningful scaled growth budgets. These are frozen regression budgets, not
measured acceptance results; Phase 18.3 must execute a later independent
comparison.

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
budgets; they do not execute or declare the Phase 18.3 final acceptance gate.

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
values, baseline environment identity, all 24 scenario budgets, and an explicit
statement that budgets are frozen for Phase 18.3 but have not yet been executed
as the final acceptance gate.

SHA-256 checksums of the tracked evidence are:

| Artifact | SHA-256 |
| --- | --- |
| `phase18-2-baseline-run-1.json` | `cd4622f9ed0c240b5a0c5bd8d1b3d96df90128940a4154bc4e9fb13070d6c145` |
| `phase18-2-baseline-run-2.json` | `ef58cf5e29c2792147939ba23708be8d3c7a58eae517afeb2c2e43ae72766462` |
| `phase18-2-baseline-run-3.json` | `57e1b576146828f6a20ac0753509dbb8046d8c51758500862aaa41765276cbd4` |
| `phase18-2-budgets.json` | `d873a70258b6a52ae4a58e99515fb3caa8790fb75fa4f4a97d76a901e5b301c1` |

Baseline and budget status are now established and frozen. Phase 18.3 remains
the only place where final performance acceptance may be executed or declared.
