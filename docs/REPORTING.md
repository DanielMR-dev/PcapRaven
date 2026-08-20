# PcapRaven Reporting Architecture and Output Formats

## 1. Overview

`pcapraven-reporting` is the dedicated presentation and serialization subsystem of PcapRaven. It converts capture validation metadata, network flows, protocol observations (DNS, HTTP/1.x, TLS), security findings, and unified forensic analyses into deterministic, structured formats.

### Core Design Principles

- **Zero Serialization in Domain Model:** `pcapraven-domain` remains pure `std` Rust with zero external dependencies (no `serde`). Serialization is strictly encapsulated within the Data Transfer Object (DTO) layer in `pcapraven-reporting`.
- **Schema Version Anchor:** All structured outputs (JSON, NDJSON) include a root schema version anchor: `"schema_version": "v1.0"`.
- **Deterministic Presentation:** Serialization ordering is strictly canonical (flows sorted by reference ordinal, findings sorted by reference, observations sorted by packet ordinal and sequence index).
- **Defense-in-Depth Sanitization:** All untrusted string fields are sanitized against terminal injection (control character escaping) and CSV formula injection.
- **Safe Output Files:** Writing to an external file via `--output <PATH>` enforces atomic `create_new(true)` semantics to prevent accidental data overwrites.

---

## 2. Output Formats

PcapRaven supports four distinct output formats selectable via `--format <FORMAT>` (or `--format <table|json|ndjson|csv>`):

| Format | Option | Description | Target Use Case |
|---|---|---|---|
| **Table** | `table` *(default)* | Fixed-width ASCII tables and formatted findings cards with ANSI/control character sanitization. | Interactive terminal inspection. |
| **JSON** | `json` | Formatted, indented hierarchical JSON document. | Automated tooling, SIEM ingestion, API consumers. |
| **NDJSON** | `ndjson` | Newline-delimited JSON stream where each line is a self-contained JSON record. | Streaming log pipelines, BigQuery, ClickHouse, ELK stack. |
| **CSV** | `csv` | Flat 2D tabular CSV with sanitized cells and column headers. | Spreadsheet review and forensic export. |

---

## 3. Subcommand Matrix & Projection Support

| Subcommand | Table | JSON | NDJSON | CSV | Notes |
|---|:---:|:---:|:---:|:---:|---|
| `validate` | Supported | Supported | Supported | Supported | Container metadata, diagnostics, completion status. |
| `flows` | Supported | Supported | Supported | Supported | Exact packet/byte counters, duration, inter-arrival metrics. |
| `dns` | Supported | Supported | Supported | Supported | Normalized query names, flags, EDNS(0), resource records. |
| `http` | Supported | Supported | Supported | Supported | Method, target, status, selected headers, sensitive flags. |
| `tls` | Supported | Supported | Supported | Supported | ClientHello, ServerHello, SNI, ALPN, cipher suites, versions. |
| `findings` | Supported | Supported | Supported | Supported | Analytical security findings, severity, confidence, MITRE mappings. |
| `analyze` | Supported | Supported | Supported | **Rejected (Exit Code 2)** | Multi-layer analysis cannot be flattened into a single 2D CSV table. |

### CSV Rejection for `analyze`
The `analyze` subcommand performs unified forensic analysis across capture metadata, flows, DNS, HTTP, TLS, findings, and evidence. Because these entities have mutually incompatible columnar schemas and relational cardinality, attempting to flatten them into a single CSV would produce an ambiguous or corrupted tabular representation. Consequently, `pcapraven analyze --format csv` is rejected with **Exit Code 2** (Usage Error). Users desiring CSV exports should invoke the layer-specific subcommands (`pcapraven flows --format csv`, `pcapraven findings --format csv`, etc.).

---

## 4. Security & Hardening Controls

### 4.1 Terminal Control Sanitization
All raw strings from capture payloads (DNS query names, HTTP request targets, TLS SNI / ALPN strings, header values) are escaped to prevent terminal escape sequence injection (e.g. ANSI escape codes, cursor positioning, screen clearing). Non-printable bytes and control codes (`0x00..=0x1F`, `0x7F..=0xFF`) are rendered as hex escape sequences (`\xNN`).

### 4.2 CSV Formula Injection Defense
When exporting to CSV, untrusted fields that begin with dangerous formula trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`) or whitespace followed by formula triggers are prefixed with a single quote character (`'`). This prevents spreadsheet applications (e.g., Microsoft Excel, LibreOffice Calc, Google Sheets) from executing untrusted cell content as formulas or DDE macros.

### 4.3 Safe Output File Creation (`--output`)
When an output destination file is specified via `-o <PATH>` or `--output <PATH>`:
- The file is created using `std::fs::OpenOptions::new().write(true).create_new(true).open(path)`.
- If the file already exists (`ErrorKind::AlreadyExists`), PcapRaven immediately stops execution, prints an error message to `stderr`, and exits with **Exit Code 2**.
- When `--output` succeeds, standard output (`stdout`) remains completely empty, ensuring clean CLI pipeability. All nonfatal diagnostics and progress logs continue to use standard error (`stderr`).

---

## 5. DTO Schema Reference

### 5.1 JSON Root Envelopes
All JSON output objects adhere to the structure:
```json
{
  "schema_version": "v1.0",
  "kind": "validation | flows | dns | http | tls | findings | analysis",
  "metadata": { ... },
  "summary": { ... },
  "records": [ ... ]
}
```

### 5.2 Exact Rational Arithmetic
Duration and temporal metric ratios in flows and findings are represented with exact numerator/denominator representations (`numerator`, `denominator`, `unit`) alongside a human-readable display string, eliminating floating-point approximation inaccuracies across serialization boundaries.
