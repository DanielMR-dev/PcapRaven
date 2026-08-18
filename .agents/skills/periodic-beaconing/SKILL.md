---
name: periodic-beaconing
description: Use for PcapRaven explainable periodic beaconing detection over exact flow temporal metrics.
---

# Explainable Periodic Beaconing Detection Skill

This skill governs the design, implementation, review, and verification of the
explainable periodic beaconing detector (`PeriodicBeaconingDetector`, `behavior.periodic_beaconing`)
in `pcapraven-detection`.

## Core Responsibilities

- Detect periodic, low-jitter communication streams across reconstructed bidirectional flow records.
- Implement the `Detector` trait with metadata contract:
  - ID: `behavior.periodic_beaconing`
  - Version: `v1.0.0`
  - Policy: `IncompleteDataPolicy::Skip`
  - Subject: `FindingSubject [flow.reference]`
  - Severity: `Severity::Low`
  - Confidence: `Confidence::Medium`
- Evaluate directional flow temporal series independently:
  - Direction A -> B (`a_to_b_inter_arrival`)
  - Direction B -> A (`b_to_a_inter_arrival`)
- Enforce strict statistical and temporal invariants:
  - Clean timestamps: zero discontinuities (`discontinuity_count == 0`)
  - Sample count: $N \ge \text{minimum\_interval\_samples}$ (default 6, hard minimum 3)
  - Mean interval: $\mu \ge \text{minimum\_mean\_interval}$ (default 1s)
  - Jitter ratio: $\delta_{MAD} / \mu \le \text{maximum\_jitter\_ratio}$ (default 10%)
  - Spread ratio: $(\text{max} - \text{min}) / \mu \le \text{maximum\_spread\_ratio}$ (default 25%)
- Construct structured `EvidenceDraft`s (`EvidenceKind::TemporalMetric`) with factual measurements and threshold comparisons:
  - `discontinuity_count`
  - `interval_sample_count`
  - `maximum_interval`
  - `mean_absolute_successive_interval_delta`
  - `mean_interval`
  - `minimum_interval`
  - `relative_jitter_ratio`
  - `spread_ratio`
  - `successive_delta_sample_count`

## Invariants and Rules

### 1. Zero Floating-Point Arithmetic
- All calculations, ratio checks, spread evaluations, and temporal comparisons MUST use exact rational numbers (`FlowDuration` and `EvidenceRatio`) with checked arithmetic.
- Floating-point types (`f32`, `f64`) are strictly forbidden.

### 2. Cross-Multiplication Without Overflow
- Jitter condition: $(N_\delta \cdot D_\mu) \cdot D_j \le (D_\delta \cdot N_\mu) \cdot N_j$
- Spread condition: $(N_s \cdot D_\mu) \cdot D_{smax} \le (D_s \cdot N_\mu) \cdot N_{smax}$
- Every intermediate multiplication must be checked for overflow (`checked_mul`).

### 3. Non-Attribution & Explainability
- Benign periodicity is common in NTP, telemetry, heartbeats, polling, and health checks.
- Finding descriptions and rationales must explain the factual timing characteristics observed and state clearly that periodicity does not confirm malware or C2 without external context.
