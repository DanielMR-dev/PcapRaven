---
name: finding-correlation
description: Explainable cross-detector finding correlation in PcapRaven.
---

# Finding Correlation Skill

This skill documents requirements and procedures for implementing, testing, and reviewing
finding correlators and multi-signal heuristics in PcapRaven.

## Core Invariants

1. **Post-Primary Evaluation:** Correlators run strictly after primary detectors have executed.
2. **Evidence Reuse:** Correlated findings reuse existing `EvidenceReference`s from primary findings; zero new `EvidenceRecord`s are generated during correlation.
3. **Source Finding Traceability:** Correlated findings must reference $\ge 2$ unique, sorted `FindingReference`s corresponding to accepted primary findings.
4. **Referential Integrity:** All `source_finding_references` and `evidence_references` must resolve to existing records in the run outcome.
5. **Deterministic Execution:** Correlators are registered in `CorrelationRegistry` and executed in canonical `DetectorId` order.
6. **Bounded Output:** Correlation sinks enforce finite capacity limits governed by the engine's `max_total_findings`.
7. **No Floating-Point Arithmetic:** Zero `f32`/`f64` usage.
8. **Balanced Rationale:** Do not assert confirmed malware presence; document multi-signal characteristics and benign alternative explanations (such as CDN telemetry or automated sync).
