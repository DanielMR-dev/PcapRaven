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
  - `ObservationError`
  - `ProtocolObservationCollection`
  - `ProtocolObservationCollectionError`
  - `SchemaVersion`
  - `PROTOCOL_OBSERVATION_SCHEMA_VERSION`
  - `EVIDENCE_SCHEMA_VERSION`
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
  - `EvidenceRecordBuilder`
  - `EvidenceValidationError`

## Invariants and Rules

### 1. Structural Observation Identity & Provenance
- `ObservationReference` is a structural, capture-local deterministic tuple `(packet_ordinal, protocol, ordinal_within_packet)` with total ordering `(packet_ordinal, protocol, ordinal_within_packet)` and protocol ordering `Dns < Http < Tls`. Display is `obs:<packet_ordinal>:<protocol>:<ordinal_within_packet>`.
- `ProtocolObservation` fields are private. Invariant validation strictly enforces:
  - `reference.packet_ordinal == payload.packet.capture_record_ordinal` (mismatch returns `ObservationError::PacketReferenceMismatch`).
  - `reference.protocol == payload.protocol_kind()` (mismatch returns `ObservationError::ProtocolMismatch`).
- Completeness is ALWAYS derived directly from the underlying protocol payload. There is no public constructor or method capable of creating `inner Partial / wrapper Complete`.
- `ObservationFlowAssociation` preserves packet direction relative to the canonical flow key:
  - `Associated { flow: FlowReference, direction: FlowDirection }` preserving `AToB`, `BToA`, or `SameEndpoint`.
  - `from_flow_packet_association` validates packet ordinal equality; mismatch returns structured error.
  - `Excluded(FlowExclusionReason)` for flow-ineligible packets.
  - `Unassociated` when flow correlation has not been performed.

### 2. Observation Collection Hard Bounds & Monotonicity
- `ProtocolObservationCollection` enforces non-zero capacity and hard maximum limit (`HARD_MAX_OBSERVATIONS = 1_000_000`).
- Insertion via `push(&mut self, observation)` returns `Result<(), ProtocolObservationCollectionError>`.
- References must strictly increase (`observation.reference() > last_reference`). Out-of-order references return `OutOfOrderReference`; duplicate references return `DuplicateReference`.
- Capacity exhaustion returns explicit `Err(ResourceLimit)` and sets `is_truncated = true`. Silent observation dropping or eviction is strictly prohibited.
- Failed insertions are transactional and do not mutate collection state.

### 3. Factual Evidence Discipline (Strict Separation of Facts from Detection)
- Evidence records (`EvidenceRecord`) represent factual, immutable supporting artifacts.
- Evidence records reference packets (`PacketReference`), flows (`FlowReference`), and observations (`ObservationReference`) by reference rather than copying arbitrary unparsed bytes.
- `EvidenceKind` uses strictly factual terminology (`PacketMeasurement`, `FlowMeasurement`, `ProtocolObservation`, `TemporalMetric`, `RatioComparison`, `ProtocolFact`). Evidence must NEVER assert interpretive labels (e.g. `Malware`, `C2`, `Suspicious`, `HighSeverity`).
- An evidence record must contain actual supporting context: empty evidence (where packet, flow, observation references and measurements are all empty) is strictly rejected (`EmptyEvidenceRecord`).

### 4. Validated Bounded Text & Metric Keys
- `EvidenceDescription` enforces maximum 512 UTF-8 bytes and strictly rejects empty text and all control characters (including NUL, ESC, CR, LF, TAB). Silent truncation or mutation is prohibited.
- `EvidenceMetricKey` enforces ASCII grammar `[a-z0-9][a-z0-9._-]*` and maximum 64 bytes, rejecting empty keys, uppercase letters, whitespace, and control characters.
- Generic unbounded `EvidenceValue::Text(String)` and custom `EvidenceUnit::Custom(String)` are strictly prohibited. Units are a finite enum (`Bytes`, `Packets`, `Nanoseconds`, `Microseconds`, `Milliseconds`, `Seconds`, `Ratio`, `Count`, `PercentageInteger`).
- Single-threshold fake range comparisons are prohibited. `EvidenceComparison` provides exact relations: `Equal`, `NotEqual`, `LessThan`, `LessThanOrEqual`, `GreaterThan`, `GreaterThanOrEqual`.

### 5. Exact Rational Arithmetic (Strictly Zero Floats)
- Never use `f32` or `f64` in `EvidenceRatio` or `EvidenceValue`.
- `EvidenceRatio` represents exact non-negative rational ratios as `numerator / denominator` in lowest terms via GCD.
- `EvidenceRatio` comparison (`Ord` / `PartialOrd`) uses exact Euclidean continued-fraction algorithms, guaranteeing overflow-free, division-by-zero-free, and float-free total ordering across the entire `u128` domain.

### 6. Evidence Record Bounds & Integrity
- `EvidenceRecord` fields are private and constructed via `EvidenceRecordBuilder`.
- Per-record collections have enforced hard caps:
  - `packet_references`: max 1,024, strictly increasing by `capture_record_ordinal`, duplicate-free.
  - `flow_references`: max 256, strictly increasing by `ordinal`, duplicate-free.
  - `observation_references`: max 4,096, strictly increasing by `ObservationReference` total order, duplicate-free.
  - `measurements`: max 256, unique `EvidenceMetricKey` per record.
  - `limitations`: max 64, sorted in canonical order, duplicate-free.
- Measurement type/unit compatibility is validated at construction.

### 7. Schema Version Anchoring
- `PROTOCOL_OBSERVATION_SCHEMA_VERSION` (`v1.0`) anchors protocol observations.
- `EVIDENCE_SCHEMA_VERSION` (`v1.0`) anchors structured evidence records.
- Schema versioning provides forward and backward compatibility contracts without dynamic serialization dependencies.
