---
name: observation-evidence-model
description: Use for PcapRaven unified protocol observation and structured evidence design, implementation, and review.
---

# Unified Protocol Observations and Structured Evidence Skill

This skill governs the design, implementation, review, and verification of
unified protocol observations and structured evidence models in `pcapraven-domain`.

## Core Responsibilities

- `pcapraven-domain` owns the immutable domain types for observation identity,
  protocol encapsulation, explicit flow association, completeness tracking,
  bounded observation collections, evidence reference identity, exact rational
  ratio metrics, measurements, comparisons, limitations, and schema anchors:
  - `ProtocolKind`
  - `ObservationReference`
  - `ObservationCompleteness`
  - `ObservationFlowAssociation`
  - `ProtocolObservationData`
  - `ProtocolObservation`
  - `ProtocolObservationCollection`
  - `SchemaVersion`
  - `EvidenceReference`
  - `EvidenceKind`
  - `EvidenceDescription`
  - `EvidenceMetricKey`
  - `EvidenceRatio`
  - `EvidenceUnit`
  - `EvidenceValue`
  - `EvidenceComparison`
  - `EvidenceMeasurement`
  - `EvidenceLimitation`
  - `EvidenceRecord`

## Invariants and Rules

### 1. Unified Protocol Observation Architecture
- Observations across all supported application protocols (DNS, HTTP/1.x, TLS 1.2/1.3)
  must share a uniform representation via `ProtocolObservation` and `ProtocolObservationData`.
- Every observation maintains explicit provenance to its source packet via `PacketReference`.
- Every observation maintains explicit bidirectional flow association via `ObservationFlowAssociation`:
  - `Associated(FlowReference)` when correlated with a reconstructed flow instance.
  - `Excluded(FlowExclusionReason)` when originating from a flow-ineligible packet.
  - `Unassociated` when flow correlation has not occurred.
- Completeness is derived from the underlying protocol observation payload or explicitly declared.

### 2. Structured Evidence Discipline (Separation of Facts from Detection)
- Evidence records (`EvidenceRecord`) represent factual, immutable supporting artifacts.
- Evidence records reference packets (`PacketReference`), flows (`FlowReference`), and observations (`ObservationReference`) by reference rather than copying arbitrary unparsed bytes.
- Findings and detectors in future detection phases consume `EvidenceRecord` items to justify heuristic alerts without embedding raw payloads.

### 3. Exact Rational Arithmetic (Strictly Zero Floats)
- Never use `f32` or `f64` in `EvidenceRatio` or `EvidenceValue`.
- `EvidenceRatio` represents exact non-negative rational ratios as `numerator / denominator` in lowest terms via GCD.
- `EvidenceRatio` comparison (`Ord` / `PartialOrd`) must use exact Euclidean continued-fraction algorithms, guaranteeing overflow-free, division-by-zero-free, and float-free total ordering across the entire `u128` domain.

### 4. Terminal Safety and Privacy Non-Retention
- `EvidenceDescription` and `EvidenceMetricKey` sanitize control characters and enforce fixed length bounds to prevent terminal injection.
- Protocol observation payloads adhere strictly to privacy non-retention: secret keys, plaintext passwords, session tickets, and sensitive headers are never retained in observation data or evidence.

### 5. Schema Version Anchoring
- `EvidenceRecord` items are stamped with `SchemaVersion` (canonical Phase 10 version is `v1.0`).
- Schema versioning provides forward and backward compatibility contracts for future persistence and reporting.
