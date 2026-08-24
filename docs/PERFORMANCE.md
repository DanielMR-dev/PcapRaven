# Performance Verification

## Status

Phase 18 Part B provides a reproducible benchmark foundation and a source-level
complexity audit. Acceptance measurements and thresholds are **pending**; no
performance pass or Phase 18 completion is claimed here.

## Methodology

`scripts/run_phase18_benchmarks.py` is dependency-free and:

1. reads only bounded synthetic classic-PCAP fixtures and validates their
   record framing;
2. creates deterministic, monotonically timestamped semantic workload captures
   in a temporary directory under a 50,000-record/256-MiB generation ceiling;
3. builds `pcapraven-cli` with `cargo build --release --locked`;
4. warms each command once;
5. measures complete CLI invocations with `time.perf_counter_ns()`;
6. reports all samples plus integer nanosecond minimum, median, and maximum
   values and integer basis-point growth ratios; and
7. discards command output and removes temporary captures automatically.

The canonical default matrix uses exactly five measured runs after one
unmeasured warmup for every row:

| Family | Semantic workloads |
| --- | --- |
| Validation | exactly 1,000, 10,000, and 50,000 packet records |
| Flow reconstruction | 128 low, 2,048 medium, and 8,192 higher distinct five-tuples |
| DNS analysis | exactly 1,000 and 10,000 DNS packet records |
| Unified analysis | benign mixed, repeated low-volume, DNS-heavy, and multi-signal fixture workloads, each at 1,000 and 10,000 packet records |
| Reporting | findings reports over the multi-signal workload in Table, JSON, NDJSON, and CSV |

Distinct-flow workloads deterministically vary synthetic source addresses and
ports without introducing production data. Other scenarios cycle only the
named synthetic fixture families and assign deterministic monotonic timestamps;
repeated and multi-signal scenarios use 30-second spacing. The bounded developer
smoke mode runs one measured sample after one warmup over a reduced scenario
matrix. Smoke timings are tooling evidence only and are never acceptance
measurements:

```text
python3 scripts/run_phase18_benchmarks.py --smoke
```

The JSON result records exact Git SHA and dirty status, verbose Rust compiler and
active toolchain, Cargo and Python versions, release build profile, OS, kernel,
platform, machine architecture, CPU model, logical CPU count, total and available memory
when discoverable, reported power governor when available, explicit uncontrolled
power/background limitations, capture bytes, packet records, warmups, sample
count, every integer duration, integer summaries, and growth ratios. The script
does not claim CPU affinity, cache isolation, thermal control, power control, or
background-load control.

## Source-Level Complexity Audit

The Phase 18 audit found the following intended upper bounds:

| Layer | Expected complexity | Governing bound |
| --- | --- | --- |
| Capture reader | Linear in consumed capture bytes | maximum block, packet, buffer, record, section, and diagnostic limits |
| Packet normalizer | Linear in retained packet bytes | packet payload and IPv6 extension count/byte limits |
| DNS parser | Linear bounded wire traversal; compression revisits are finite | message, name, pointer, question, record, and retained-name limits |
| HTTP parser | Linear bounded header-line scanning | payload, line, header, selected-value, and diagnostic limits |
| TLS parser | Linear bounded record/handshake/extension scanning | payload, handshake, extension, cipher, group, and diagnostic limits |
| Flow reconstruction | `O(log F)` active-flow lookup per eligible packet; final ordering `O(F log F)` | tracked-flow and flow-instance limits |
| Detection | Linear or ordered-map `O(log G)` aggregation over bounded facts | flow, observation, peer-group, detector, finding, evidence, and diagnostic limits |
| Correlation | Bounded scans over primary findings and references | finding and source-reference limits |
| Reporting | Linear in bounded records plus encoded output bytes | analysis budgets, validated field limits, and writer backpressure/errors |

Static review found no production `remove(0)`, front insertion, unbounded
recursive traversal, or floating-point detector calculations. HTTP line
delimiter searches operate within bounded lines. Flow and detection maps use
deterministic ordered structures rather than attacker-dependent randomized
ordering. No material complexity defect requiring a runtime semantic change was
identified by this foundation audit.

## Acceptance Placeholders

Final acceptance must compare at least two workload scales and evaluate both
absolute medians and growth ratios. Thresholds must be selected from controlled
measurements and approved before they become gates; they must not be backfilled
to fit observed results.

| Scenario | Baseline environment | Median threshold | Growth threshold | Result |
| --- | --- | --- | --- | --- |
| Validation, 1k/10k/50k records | Pending | Pending | Pending | Pending |
| Flows, low/medium/higher cardinality | Pending | Pending | Pending | Pending |
| DNS, 1k/10k records | Pending | Pending | Pending | Pending |
| Analyze, benign/repeated/DNS-heavy/multi-signal | Pending | Pending | Pending | Pending |
| Reporting, Table/JSON/NDJSON/CSV | Pending | Pending | Pending | Pending |

Regressions require source-level profiling and an owning fix. Safety limits,
determinism, evidence integrity, privacy controls, and exact schemas may not be
weakened to improve a benchmark.
