# PcapRaven Reporting Architecture and Output Formats

## 1. Overview and Scope

`pcapraven-reporting` is the dedicated presentation and serialization subsystem of PcapRaven. It converts capture validation metadata, network flows, protocol observations (DNS, HTTP/1.x, TLS), analytical security findings, and unified forensic analyses into deterministic, structured formats.

### Core Design Principles

- **Zero Serialization in Domain Model:** `pcapraven-domain` remains pure `std` Rust with zero external dependencies (no `serde`). Serialization is strictly encapsulated within the Data Transfer Object (DTO) layer in `pcapraven-reporting`.
- **Schema Version Anchor:** All structured outputs (JSON, NDJSON) include a root schema version anchor: `"schema_version": "v1.0"`.
- **Wide Integer String Policy:** All 64-bit and larger integers (`u64`, `i64`, `u128`, `i128`, `usize`), packet/flow/observation/evidence/finding ordinals, and sample counts serialize as decimal string tokens (`String`). This guarantees exact integer fidelity across JSON parsers and 64-bit float limitations in downstream environments (such as JavaScript). Standard protocol types (`u8`, `u16`, `u32`, `bool`) remain JSON numbers/booleans.
- **Null and Array Invariants:** Missing optional values consistently serialize as `null` (no `skip_serializing_if`). Empty collections consistently serialize as `[]`.
- **Deterministic Presentation:** Serialization ordering is strictly canonical (flows sorted by reference ordinal, findings sorted by reference, observations sorted by canonical `ObservationReference` order).
- **Defense-in-Depth Sanitization:** All untrusted string fields are sanitized against terminal injection (control character escaping) and CSV formula injection.
- **Safe Output Files:** Writing to an external file via `--output <PATH>` enforces atomic `create_new(true)` semantics to prevent accidental data overwrites.

---

## 2. Output Formats

PcapRaven supports four distinct output formats selectable via `--format <FORMAT>` (or `--format <table|json|ndjson|csv>`):

| Format | Option | Description | Target Use Case |
|---|---|---|---|
| **Table** | `table` *(default)* | Fixed-width ASCII tables and formatted findings cards with ANSI/control character sanitization. | Interactive terminal inspection. |
| **JSON** | `json` | Formatted, indented hierarchical JSON document with trailing newline. | Automated tooling, SIEM ingestion, API consumers. |
| **NDJSON** | `ndjson` | Newline-delimited JSON stream where each line is a self-describing tagged envelope (`{"schema_version": "v1.0", "kind": "...", "record_type": "...", "data": { ... }}`). | Streaming log pipelines, BigQuery, ClickHouse, ELK stack. |
| **CSV** | `csv` | Flat 2D tabular CSV with sanitized cells, column headers, and strict LF (`\n`) terminators. | Spreadsheet review and forensic export. |

---

## 3. Subcommand Matrix & Projection Support

| Subcommand | Table | JSON | NDJSON | CSV | Notes |
|---|:---:|:---:|:---:|:---:|---|
| `validate` | Supported | Supported | Supported | Supported | Container metadata, diagnostics, completion status. |
| `flows` | Supported | Supported | Supported | Supported | Complete 4-directional traffic counters, duration, exact temporal metrics. |
| `dns` | Supported | Supported | Supported | Supported | Normalized query names, flags, EDNS(0), resource records. |
| `http` | Supported | Supported | Supported | Supported | Method, target, status, selected headers, sensitive presence flags. |
| `tls` | Supported | Supported | Supported | Supported | ClientHello, ServerHello, SNI, ALPN, cipher suites, versions. |
| `findings` | Supported | Supported | Supported | Supported | Analytical security findings, severity, confidence, MITRE mappings, referenced evidence closure. |
| `analyze` | Supported | Supported | Supported | **Rejected (Exit Code 2)** | Multi-layer analysis cannot be flattened into a single 2D CSV table. |

### CSV Rejection for `analyze`
The `analyze` subcommand performs unified forensic analysis across capture metadata, flows, DNS, HTTP, TLS, findings, and evidence. Because these entities have mutually incompatible columnar schemas and relational cardinality, attempting to flatten them into a single CSV would produce an ambiguous or corrupted tabular representation. Consequently, `pcapraven analyze --format csv` is rejected with **Exit Code 2** (Usage Error). Users desiring CSV exports should invoke the layer-specific subcommands (`pcapraven flows --format csv`, `pcapraven findings --format csv`, etc.).

---

## 4. Machine Schema Specification (v1.0)

### 4.1 Schema Version Anchor
The canonical schema version is defined as:
```rust
pub const REPORT_SCHEMA_VERSION: &str = "v1.0";
```

### 4.2 Machine Enum Tokens
All enum values in JSON and NDJSON serialize as lowercase `snake_case` string tokens:
- Transport protocols: `"tcp"`, `"udp"`.
- Direction: `"a_to_b"`, `"b_to_a"`, `"same_endpoint"`.
- Completion status: `"complete"`, `"partial"`, `"failed"`.
- Severity: `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"`.
- Confidence: `"low"`, `"medium"`, `"high"`.
- MITRE Domain: `"enterprise"`.
- MITRE Relationship: `"analytical"`.
- MITRE Tactics: `"command_and_control"`, `"initial_access"`, etc.

### 4.3 Full Flow Machine Projection (`FlowRecordDto`)
`FlowRecordDto` represents the complete factual flow domain projection:
- `reference`: Flow reference ordinal string (`"flow:0"`).
- `protocol`: Transport protocol (`"tcp"` or `"udp"`).
- `endpoint_a` / `endpoint_b`: Address and port string endpoints.
- `first_packet` / `last_packet`: Capture record ordinal strings.
- `end_reason`: Flow end reason token (`"end_of_input"`, `"analysis_stopped"`, `"tcp_reset"`, `"tcp_new_initial_syn"`, `"idle_timeout"`).
- `traffic`: Directional traffic metrics across 4 buckets (`total`, `a_to_b`, `b_to_a`, `same_endpoint`), each containing `packet_count`, `captured_bytes`, `wire_bytes`, and `truncated_packet_count` as decimal strings.
- `temporal`: Contains `first_packet_timestamp`, `last_packet_timestamp`, `duration` (with `numerator`, `denominator`, and `display`), `timestamp_coverage`, and inter-arrival statistics (`overall`, `a_to_b`, `b_to_a`, `same_endpoint`).

### 4.4 Unified Protocol Observations (`ProtocolObservationDto`)
For `analyze`, observations preserve exact identity and flow associations:
- `id`: Canonical observation reference string (`"obs:0:dns:0"`).
- `protocol`: Protocol kind token (`"dns"`, `"http"`, `"tls"`).
- `packet_reference`: Capture record ordinal string.
- `completeness`: Completeness token (`"complete"` or `"partial"`).
- `association`: Flow association object containing `status` (`"associated"`, `"unassociated"`, `"excluded"`), optional `flow_reference`, optional `direction`, and optional `exclusion_reason`.
- `data`: Typed observation payload (`dns`, `http`, or `tls`).

### 4.5 Evidence Records (`EvidenceRecordDto`)
Preserves complete provenance:
- `id`: Evidence reference string (`"evi:0"`).
- `kind`: Evidence kind string.
- `description`: Human-readable factual description.
- `packet_references`: List of referenced capture record ordinals (`["0", "1"]`).
- `flow_references`: List of referenced flow reference strings (`["flow:0"]`).
- `observation_references`: List of referenced observation reference strings (`["obs:0:dns:0"]`).
- `measurements`: List of structured measurements (`name`, `observed_value` with exact rational `numerator`/`denominator` or integer/boolean string, and optional `threshold`).
- `limitations`: List of evidence limitation tokens.

### 4.6 MITRE ATT&CK Mapping Provenance (`MitreMappingDto`)
Structured mapping provenance:
```json
{
  "domain": "enterprise",
  "catalog_version": "19.2",
  "technique_id": "T1071.004",
  "technique_name": "Application Layer Protocol: DNS",
  "technique_version": "1.4",
  "tactic_id": "TA0011",
  "tactic": "command_and_control",
  "relationship": "analytical",
  "provenance": {
    "kind": "detector",
    "component_id": "dns.possible_tunneling",
    "component_version": "v1.1.1"
  },
  "rationale": "..."
}
```

### 4.7 Filter Metadata and Evidence Closure
When findings filtering is applied (`--min-severity`, `--min-confidence`, `--detector`, `--mitre`):
- `filter`: Active filter state serialized as `FindingFilterDto`.
- Evidence closure: The emitted `evidence` array contains only evidence records referenced by at least one of the retained findings. Canonical reference IDs are never renumbered.

### 4.8 Whole-Analysis Completion Model
`AnalysisReportDto.completion` is represented by `ReportCompletionDto`:
- `status`: `"complete"`, `"partial"`, or `"failed"`.
- `limitations`: List of structured limitation tokens (`"capture_truncated"`, `"packet_count_budget_reached"`, `"flow_budget_reached"`, `"observation_budget_reached"`).

---

## 5. Self-Describing NDJSON Specifications

Every physical NDJSON line is a standalone, self-describing tagged envelope:
```json
{
  "schema_version": "v1.0",
  "kind": "analysis",
  "record_type": "flow",
  "data": { ... }
}
```

### Canonical Emission Order in `analyze` NDJSON
1. `summary` (includes metadata, counters, active filter, and whole-analysis completion status).
2. `flow` records in canonical `FlowReference` order.
3. `observation` records in canonical `ObservationReference` order.
4. `evidence` records in canonical `EvidenceReference` order.
5. `finding` records in canonical `FindingReference` order (primary findings followed by correlation findings).

---

## 6. CSV Specifications and Line Endings

- **Strict LF Line Endings:** All CSV writers explicitly use LF (`\n`) line endings across all operating systems.
- **No BOM:** Output files never include a byte order mark.
- **CSV Formula Injection Sanitization:** Cells beginning with dangerous formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`) or whitespace followed by formula triggers are prefixed with `'`. Original text is not mutated or stripped.

---

## 7. Output File Lifecycle and Failure Handling

The CLI manages safe file output via `with_output_sink`:
1. **Collision Prevention:** Target files are opened with `create_new(true)`. If the target exists, PcapRaven emits an error to `stderr` and terminates immediately with **Exit Code 2** without modifying the file.
2. **Explicit Flush:** All writes through `BufWriter` are explicitly flushed before exit. Flush failures return **Exit Code 1**.
3. **Atomic Failure Cleanup:** If an error occurs during report generation or flushing for a newly created file, the file handle is dropped and the incomplete file is removed. Files that existed before execution are never deleted.

---

## 8. Post-Phase 17 Schema Freeze Policy

Phase 17 intentionally freezes the machine output schema (`v1.0`). Following the acceptance of Phase 17:
- Any breaking or incompatible changes to field names, types, enum tokens, or envelope structures MUST increment `REPORT_SCHEMA_VERSION` (e.g. to `"v2.0"`).
- Additions of non-breaking optional fields must be documented and demonstrated to be backwards-compatible with existing consumers.
