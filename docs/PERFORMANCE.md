# Performance Verification

## Status

Phase 18.1 fuzz acceptance is complete. Phase 18.2 now freezes the benchmark
methodology and budget derivation policy; the three-run baseline and frozen
budget artifact are still pending on this branch. No final performance
acceptance or Phase 18 completion is claimed. The later Phase 18.3 gate remains
separate.

The eventual Phase 18.2 result has three distinct states:

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

## Frozen Pre-Measurement Policy

This policy is committed before observing official baseline numbers:

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
meaningful scaled growth budgets. These are regression budgets, not measured
acceptance results; Phase 18.3 must execute a later independent comparison.

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

After the three-run baseline is validated, the tracked evidence will be:

```text
docs/performance/phase18-2-baseline-run-1.json
docs/performance/phase18-2-baseline-run-2.json
docs/performance/phase18-2-baseline-run-3.json
docs/performance/phase18-2-budgets.json
```

`scripts/derive_phase18_budgets.py` accepts exactly those three full JSON
measurements, rejects smoke/dirty/mixed/incomplete/inconsistent inputs, checks
the frozen 15% stability limit, and writes one deterministic budget document to
stdout. The budget artifact will include source measurement SHA-256 values,
baseline environment identity, all 24 scenario budgets, and an explicit
statement that budgets are frozen for Phase 18.3 but have not yet been executed
as the final acceptance gate.

Until those artifacts exist and are reviewed, baseline and budget status remain
pending. Phase 18.3 remains the only place where final performance acceptance
may be declared.
