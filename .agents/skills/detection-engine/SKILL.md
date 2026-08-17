---
name: detection-engine
description: Use for PcapRaven detection engine architecture, detector registration, configuration, evaluation, and deterministic finding generation.
---

# Detection Engine Architecture Skill

This skill governs the design, implementation, review, and verification of the
detection engine architecture in `pcapraven-detection` and finding domain models
in `pcapraven-domain`.

## Core Responsibilities

- `pcapraven-domain` owns the immutable finding domain models:
  - `DetectorId` (namespaced, lowercase ASCII, max 96 bytes, `^[a-z0-9]+(\.[a-z0-9_-]+)+$`)
  - `DetectorVersion` (`v{major}.{minor}.{patch}`)
  - `FindingReference` (`find:{ordinal}`)
  - `FindingSubject` (typed, non-empty, strictly ordered, duplicate-free references to packets, flows, observations)
  - `FindingTitle` (max 128 bytes, terminal-safe, non-empty)
  - `FindingSummary` (max 512 bytes, terminal-safe, non-empty)
  - `FindingRationale` (max 2,048 bytes, terminal-safe, non-empty)
  - `FindingDraft` (draft emitted by detector during evaluation)
  - `FindingRecord` (canonical engine record with assigned `FindingReference` and validated `EvidenceReference`s)
  - `Severity` (`Info`, `Low`, `Medium`, `High`, `Critical`)
  - `Confidence` (`Low`, `Medium`, `High`)
  - `FindingValidationError`
- `pcapraven-detection` owns the detection engine and execution pipeline:
  - `Detector` trait (`metadata()`, `validate_parameters()`, `evaluate()`)
  - `DetectorMetadata` (`id`, `version`, `title`, `purpose`, `incomplete_data_policy`)
  - `IncompleteDataPolicy` (`Skip`, `AllowWithLimitations`)
  - `DetectorParameterKey` (validated ASCII key `[a-z0-9][a-z0-9._-]*`, max 64 bytes)
  - `DetectorParameterValue` (`Boolean`, `Unsigned`, `Signed`, `Ratio`, `Duration` — strictly zero floats)
  - `DetectorParameters` & `DetectorParametersBuilder` (strictly sorted by key, unique keys, bounded)
  - `DetectorConfig` & `DetectorConfigurations`
  - `DetectorRegistry` (bounded, deterministic, duplicate ID rejection, sorted by `DetectorId`)
  - `DetectionInput` (borrowed slices of flows and observations; never raw packet bytes)
  - `DetectionInputCompleteness` (`Complete`, `Partial`)
  - `DetectionInputLimitation` (`CaptureTruncated`, `PacketCountBudgetReached`, `FlowBudgetReached`, `ObservationBudgetReached`)
  - `DetectionLimits` (bounded capacity for findings, evidence, detectors, parameters, diagnostics)
  - `DetectorExecutionStatus` (`Executed`, `Disabled`, `SkippedIncompleteData`, `Failed`, `ResourceLimited`)
  - `DetectionRunOutcome` (complete/partial status, detector execution records, canonical findings, canonical evidence, diagnostics)
  - `execute_detection()` (preflight configuration, deterministic evaluation, referential integrity check, canonical identity assignment)

## Invariants and Rules

### 1. Separation of Parsing and Detection
- Parsers produce normalized facts (`NormalizedPacket`, `FlowRecord`, `DnsObservation`, `HttpObservation`, `TlsObservation`).
- Detectors interpret normalized facts and produce finding drafts supported by `EvidenceRecord`s.
- Detection code must never inspect raw capture container bytes, parse packet bytes, or duplicate transport state tracking.

### 2. Whole-Configuration Preflight Validation
- Configuration errors must be caught before ANY detector is evaluated.
- If ANY detector configuration fails validation, `execute_detection` returns an error immediately and zero detectors run.

### 3. Deterministic Execution & Canonical Assignment
- Detector execution order is always sorted by `DetectorId`, regardless of registration sequence.
- Accepted finding drafts are sorted deterministically by `(DetectorId, FindingSubject, Title)`.
- `EvidenceReference` (`evi:0`, `evi:1`, ...) and `FindingReference` (`find:0`, `find:1`, ...) are assigned sequentially and deterministically.
- Duplicate finding collision (`(DetectorId, FindingSubject)` emitted twice by the same detector) is rejected with structured error `DuplicateFindingIdentity`.
- Different detectors reporting on the same `FindingSubject` are both accepted with their respective `DetectorId`s.

### 4. Referential Integrity & Evidence Discipline
- Every finding MUST have at least one supporting `EvidenceRecord` (`FindingWithoutEvidence` error).
- Finding subjects and evidence records must reference valid flow ordinals and observation references present in `DetectionInput`.
- Evidence records contain only factual data and measurements; never interpretive detector conclusions.

### 5. Incomplete Data Policies
- `Skip`: if `DetectionInputCompleteness` is `Partial`, detector is skipped and status is recorded as `SkippedIncompleteData`.
- `AllowWithLimitations`: detector evaluates on partial input, but all emitted findings MUST contain evidence records with explicit `EvidenceLimitation`s.

### 6. Float-Free & Bounded Execution
- Floating-point arithmetic (`f32`/`f64`) is strictly forbidden across all detection parameter, ratio, and threshold models.
- All collections and text fields have enforced hard capacity bounds.
