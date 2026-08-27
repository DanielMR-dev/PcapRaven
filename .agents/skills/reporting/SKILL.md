---
name: reporting
description: Deterministic multi-format reporting architecture, serialization schemas, sanitization, and safe output writing in PcapRaven.
---

# Reporting Skill

This skill governs the design, implementation, review, and verification of the
`pcapraven-reporting` crate, DTO schemas, and structured output formats (`table`, `json`, `ndjson`, `csv`).
The canonical schema owner is [`docs/REPORTING.md`](../../docs/REPORTING.md).
The Phase 22 source-backed evidence ledger is
[`docs/REPORTING_SCHEMA_V1_AUDIT.md`](../../docs/REPORTING_SCHEMA_V1_AUDIT.md).

## Core Invariants

1. **Domain Model Purity:** `pcapraven-domain` must remain pure `std` and never depend on `serde`, `serde_json`, `csv`, or any third-party serializer. All serializable structures reside in `pcapraven-reporting::dto`.
2. **Schema Versioning Anchor:** All structured outputs anchor to `REPORT_SCHEMA_VERSION = "v1.0"`.
3. **Wide Integer String Policy:** All 64-bit and larger integers (`u64`, `i64`, `u128`, `i128`, `usize`), packet/flow/observation/evidence/finding ordinals, and sample counts serialize as decimal string tokens (`String`). Standard protocol types (`u8`, `u16`, `u32`, `bool`) remain JSON numbers/booleans.
4. **Duration and Ratio Exactness:** `DurationDto` and `RatioDto` serialize `numerator` and `denominator` as decimal strings and preserve their existing display/string-representation fields. Durations and ratios never use floating-point numbers.
5. **Complete Evidence Provenance:** `EvidenceRecordDto` includes `packet_references`, `flow_references`, `observation_references`, structured `measurements`, and `limitations`.
6. **Full Machine Flow Projection:** `FlowRecordDto` includes 4-directional traffic counters (`total`, `a_to_b`, `b_to_a`, `same_endpoint`), timestamp coverage, exact timestamps, and inter-arrival statistics.
7. **Unified Observation Identity:** For `analyze`, `ProtocolObservationDto` preserves `ObservationReference`, protocol kind, completeness, and `ObservationFlowAssociation`.
8. **Filter Metadata and Evidence Closure:** Filtered reports serialize `FindingFilterDto` and restrict emitted evidence records to only those referenced by retained findings.
9. **Whole-Analysis Completion:** `ReportCompletionDto` captures `status` and structured `limitations` reflecting reader, flow, observation, and detection completeness.
10. **Self-Describing NDJSON:** Every NDJSON line is a tagged envelope: `{"schema_version": "v1.0", "kind": "...", "record_type": "...", "data": { ... }}` in canonical record order.
11. **Strict LF CSV:** CSV output uses explicit LF (`\n`) line endings across all platforms with no BOM.
12. **CSV Formula Injection Defense:** Untrusted string values starting with `=, +, -, @, \t, \r, \n` or whitespace followed by `=, +, -, @` are prefixed with `'` without mutating or trimming original content.
13. **Safe Output Lifecycle:** `with_output_sink` creates files exclusively via `create_new(true)`, flushes explicitly, cleans up newly created files on failure, and returns Exit Code 2 on collision.
14. **Null and Empty Array Invariants:** `None` serializes as `null`; empty collections serialize as `[]`.
15. **Schema Freeze Policy:** `REPORT_SCHEMA_VERSION` remains `"v1.0"` for the audited contract. After Phase 22 acceptance, breaking changes to fields, types, nullability, tokens, tagged values, reference grammar, envelopes, ordering, CSV headers, missing values, integer representation, or rational representation require explicit user approval and a schema-versioning decision.

## Verification

- Schema contract tests in `crates/pcapraven-reporting/tests/schema_contract.rs`.
- Format projection and formula defense tests in `crates/pcapraven-reporting/tests/reporting.rs`.
- CLI integration tests in `crates/pcapraven-cli/tests/cli.rs`.
