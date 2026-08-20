---
name: reporting
description: Deterministic multi-format reporting architecture, serialization schemas, sanitization, and safe output writing in PcapRaven.
---

# Reporting Skill

This skill governs the design, implementation, review, and verification of the
`pcapraven-reporting` crate and structured output formats (`table`, `json`, `ndjson`, `csv`).

## Core Invariants

1. **Domain Model Purity:** `pcapraven-domain` must remain pure `std` and never depend on `serde`, `serde_json`, `csv`, or any third-party serializer. All serializable structures reside in `pcapraven-reporting::dto`.
2. **Schema Versioning:** All structured outputs anchor to `REPORT_SCHEMA_VERSION = "v1.0"`.
3. **CSV Formula Injection Defense:** Untrusted string values written to CSV that start with dangerous characters (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`) or leading spaces followed by dangerous characters are safely prefixed with `'` via `sanitize_csv_cell`.
4. **Terminal Escaping:** Table formatters escape control codes and non-printable characters into hex sequences (`\xNN`).
5. **CSV Analyze Rejection:** Multi-section hierarchical analysis cannot be represented as a flat 2D CSV table without schema corruption; `report_analysis(ReportFormat::Csv, ...)` must return `ReportError::UnsupportedFormat`, which the CLI translates into Exit Code 2.
6. **Safe Output Files:** Writing to external files via `--output <PATH>` must strictly use `std::fs::OpenOptions::new().write(true).create_new(true).open(path)`. If the file already exists, it must refuse to overwrite and fail with Exit Code 2.
7. **Deterministic Ordering:** Collections in reports must be deterministically sorted by their canonical domain reference ordinals.

## Verification

- Unit and integration tests in `crates/pcapraven-reporting/tests/reporting.rs`.
- Formula injection property tests with `proptest`.
- CLI integration tests in `crates/pcapraven-cli/tests/cli.rs`.
