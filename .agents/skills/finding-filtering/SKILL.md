---
name: finding-filtering
description: Use for PcapRaven explainable finding filtering by severity, confidence, detector identifier, and MITRE ATT&CK technique.
---

# Finding Filtering Skill

This skill documents requirements and procedures for filtering security findings in PcapRaven.

## Core Invariants

1. **Deterministic Predicate Conjunction:** Multiple filter criteria combine via logical conjunction (`AND`). If no criteria are specified, all findings match.
2. **Severity Thresholds:** `--min-severity` filters findings with severity greater than or equal to the threshold (`Info` < `Low` < `Medium` < `High` < `Critical`).
3. **Confidence Thresholds:** `--min-confidence` filters findings with confidence greater than or equal to the threshold (`Low` < `Medium` < `High`).
4. **Detector Identification:** `--detector` filters findings emitted by the exact specified `DetectorId`.
5. **MITRE ATT&CK Mapping Matching:** `--mitre` filters findings that contain at least one stamped `MitreMapping` matching the specified `MitreAttackId`.
6. **No Mutation:** Filtering operates on borrowed finding slices and returns matching finding references or cloned records without modifying finding identifiers or order.
7. **Strict CLI Validation:** Unknown severities, confidences, invalid detector IDs, or invalid MITRE technique IDs are rejected with exit code 2.
