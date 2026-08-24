---
name: performance-analysis
description: Use for PcapRaven worst-case complexity review, bounded benchmark design, integer timing summaries, scalability analysis, and performance regression triage.
---

# Performance Analysis

## Procedure

1. Read `AGENTS.md`, `docs/SECURITY_MODEL.md`, `docs/PERFORMANCE.md`, and the
   active roadmap scope. Performance work must not weaken safety or semantics.
2. Enumerate major loops, maps, sorts, retained collections, parser revisits,
   output materialization, and attacker-controlled cardinalities. State a
   worst-case complexity and explicit finite bound for each.
3. Search for front removal/insertion, nested scans, repeated cloning, hidden
   whole-input buffering, recursive traversal, unchecked growth, and accidental
   floating-point use in exact analytical paths.
4. Use release builds, synthetic sanitized workloads, warmups, multiple odd
   sample counts, monotonic nanosecond clocks, and integer medians. Suppress
   result output without suppressing failures.
5. Include at least two controlled scales and report capture bytes, record
   counts, environment, toolchain, revision, minima, medians, maxima, and growth
   ratios. Never invent a threshold or measurement.
6. Reproduce regressions, profile the owning layer, and prefer the smallest
   complexity or allocation fix. Re-run exact behavior, schema, privacy, and
   full quality gates after any optimization.
7. Distinguish benchmark foundation, smoke execution, measured baseline, and
   accepted gate. Unrun acceptance work remains explicitly pending.
