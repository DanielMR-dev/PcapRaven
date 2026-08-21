---
name: finding-correlation
description: Explainable cross-detector finding correlation in PcapRaven.
---

# Finding Correlation Skill

This skill documents requirements and procedures for implementing, testing, and reviewing
finding correlators and multi-signal heuristics in PcapRaven.

## Core Invariants

1. **Post-Primary Evaluation:** Correlators run strictly after all primary detectors have finished, operating over a frozen snapshot of accepted primary findings.
2. **No Correlation-of-Correlation:** Correlators consume primary findings only; they never correlate previously correlated findings.
3. **Evidence Reuse:** Correlated findings reuse existing `EvidenceReference`s from primary findings; zero new `EvidenceRecord`s are allocated during correlation.
4. **Source Finding Traceability:** Correlated findings must reference $\ge 2$ unique, sorted `FindingReference`s corresponding to accepted primary findings.
5. **Direct Lookup & Referential Integrity:** Source findings are resolved by direct `FindingReference` ordinal indexing. The engine verifies evidence ownership and subject relationship.
6. **Transactional Correlator Isolation:** A failed correlator's draft findings are transactionally discarded without aborting the entire run. Subsequent correlators continue evaluation.
7. **Deterministic Execution:** Correlators are registered in `CorrelationRegistry` and executed in canonical `DetectorId` order.
8. **Engine-Stamped MITRE Provenance:** The engine stamps `MitreMappingProvenance::CorrelatorDeclared { correlator_id, correlator_version }` on accepted correlated findings.
9. **No Floating-Point Arithmetic:** Zero `f32`/`f64` usage.
10. **Balanced Rationale:** Do not assert confirmed malware presence; document multi-signal characteristics and benign alternative explanations (such as CDN telemetry or automated sync).
