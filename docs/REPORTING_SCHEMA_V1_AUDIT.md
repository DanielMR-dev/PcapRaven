# PcapRaven Reporting Schema v1 Final Audit

## Scope

This is the Phase 22 evidence ledger for the accepted reporting implementation.
It audits the seven report kinds (`validation`, `flows`, `dns`, `http`, `tls`,
`findings`, `analysis`) across JSON, NDJSON, CSV, and deterministic table
behavior. It records evidence and dispositions; the normative contract remains
in [REPORTING.md](REPORTING.md). No schema redesign or wire-format change is
authorized by this ledger.

## Phase 21 Prerequisite

Phase 21 is formally `COMPLETE / ACCEPTED` on the current baseline. The merge
commit is `458c567c7ad323a91f17460f7065cffded4932ce`, and the canonical status
and acceptance evidence are recorded in `AGENTS.md`, `docs/ROADMAP.md`,
`docs/TESTING.md`, and `docs/CLI_V1_CONTRACT.md`. Phase 22 did not close Phase
21; it starts from that accepted state.

## Baseline Identity

| Item | Observed value |
| --- | --- |
| Branch | `phase-22-reporting-schema-v1-final-audit` |
| Phase 21 starting baseline | `458c567c7ad323a91f17460f7065cffded4932ce` |
| Phase 22 schema-contract test commits | `d13fe54` (`test(phase-22): strengthen reporting schema contract`); `354dd3d` (`test(phase-22): close schema contract audit gaps`); `6e2fcec` (`test(phase-22): assert analysis branch nullability`); `1d278c0` (`test(phase-22): complete schema token coverage`) |
| Phase 22 documentation remediation commit | `ac72ea1` (`docs(phase-22): clarify reporting schema references`) |
| Workspace package count | 7 runtime packages |
| MSRV | Rust `1.85` (`Cargo.toml`) |
| Stable toolchain | `1.97.1` (`rust-toolchain.toml`) |
| Fuzz toolchain | `nightly-2026-08-13` (`fuzz/rust-toolchain.toml`) |
| Cargo.lock SHA-256 | `e4c1615538cfec6852e3c3b405548a9580f29b1def8ea57a21b27125f08d0dba` |
| fuzz/Cargo.lock SHA-256 | `f3c37867b80c9389e287e91d38e0f0446585c199444bcd671985a72f9106329f` |
| package version | `0.0.0` |
| schema version | `v1.0` |

The branch includes the Phase 22 schema-contract test remediations committed at
`d13fe54`, `354dd3d`, `6e2fcec`, and `1d278c0` in
`crates/pcapraven-reporting/tests/schema_contract.rs`. The follow-up
`1d278c0` directly covers validation `pcapng`/`big_endian`/`failed` tokens,
HTTP invalid `Content-Length`, and populated `PacketTimestampDto` and
`FindingFilterDto` shapes. The documentation-only follow-up `ac72ea1` resolves
the reporting reference wording, manifest inventory, and roadmap disclaimer
findings. These commits were applied after the Phase 21 starting baseline. The
current worktree has no uncommitted change in `schema_contract.rs`; the audit
ledger is the only intended uncommitted file.

## Serializer Dependency Baseline

The reporting crate pins `serde = 1.0.229`, `serde_json = 1.0.143`, and
`csv = 1.3.1` with the declared minimal features in
`crates/pcapraven-reporting/Cargo.toml`. No dependency, lockfile, or workspace
change was made.

## Methodology

Evidence was resolved in this order: accepted golden bytes; serializer and DTO
source; schema and integration tests; canonical documentation; then secondary
skills and summaries. Source inspection covered DTO definitions and conversion
paths, JSON/NDJSON/CSV/table renderers, CLI projection, the 49-scenario golden
matrix, and the frozen CLI contract. Commands actually run are listed in the
validation sections below. The audit uses source line references so that the
ledger does not become a competing schema specification.

## Reporting Source Inventory

| Surface | Evidence |
| --- | --- |
| schema/version/dispatch | `crates/pcapraven-reporting/src/format.rs`, `src/lib.rs` |
| DTOs | `src/dto/{validation,flows,dns,http,tls,findings,analysis}.rs` |
| JSON | `src/json/mod.rs` |
| NDJSON | `src/ndjson/mod.rs` |
| CSV and sanitization | `src/csv/mod.rs`, `src/csv_escape.rs` |
| human table | `src/table/mod.rs` |
| CLI projection | `crates/pcapraven-cli/src/app.rs`, `src/analysis.rs`, `src/args.rs` |
| regression tests | reporting `tests/reporting.rs`, `tests/schema_contract.rs`; CLI `tests/{cli,corpus,golden,contract}.rs` |
| accepted bytes | `tests/golden/` and `scripts/golden_scenarios.py` |

## DTO Inventory

The complete field/type/nullability inventory is canonicalized in
[REPORTING.md](REPORTING.md#json-root-objects-and-dto-fields), with source
ranges for every DTO. The audited families are:

`ValidationReportDto`, `ValidationMetadataDto`, `ValidationSummaryDto`,
`ValidationDiagnosticDto`, `ValidationCompletionDto`; `FlowsReportDto`,
`FlowRecordDto`, `FlowTrafficDto`, `FlowDirectionalTrafficDto`,
`FlowTemporalDto`, `FlowTimestampCoverageDto`, `PacketTimestampDto`,
`InterArrivalMetricsDto`, `DurationDto`; `DnsReportDto`, `DnsObservationDto`,
`DnsQuestionDto`, `DnsResourceRecordDto`, `DnsEdnsDto`; `HttpReportDto`,
`HttpObservationDto`, `HttpRequestDto`, `HttpResponseDto`, `HttpHeadersDto`,
`HttpSensitiveHeadersDto`; `TlsReportDto`, `TlsObservationDto`,
`TlsClientHelloDto`, `TlsServerHelloDto`, `TlsExtensionDto`; `FindingsReportDto`,
`FindingFilterDto`, `FindingRecordDto`, `FindingSubjectDto`,
`MitreMappingDto`, `MitreMappingProvenanceDto`, `EvidenceRecordDto`,
`EvidenceMeasurementDto`, `EvidenceValueDto`, `RatioDto`; and
`AnalysisReportDto`, `AnalysisSummaryDto`, `ReportCompletionDto`,
`ProtocolObservationDto`, `ObservationFlowAssociationDto`,
`ProtocolObservationDataDto`.

## JSON Root Matrix

| Kind | Exact root fields, source |
| --- | --- |
| validation | `schema_version`, `kind`, `source_path`, `metadata`, `summary`, `diagnostics`, `completion`; `dto/validation.rs:7-24` |
| flows | `schema_version`, `kind`, `total_flows`, `flows`; `dto/flows.rs:12-23` |
| dns | `schema_version`, `kind`, `total_observations`, `observations`; `dto/dns.rs:8-19` |
| http | `schema_version`, `kind`, `total_observations`, `observations`; `dto/http.rs:8-29` |
| tls | `schema_version`, `kind`, `total_observations`, `observations`; `dto/tls.rs:8-29` |
| findings | `schema_version`, `kind`, `total_findings`, `total_evidence_records`, `filter`, `findings`, `evidence`; `dto/findings.rs:12-29` |
| analysis | `schema_version`, `kind`, `metadata`, `summary`, `completion`, `filter`, `flows`, `observations`, `evidence`, `findings`; `dto/analysis.rs:16-39` |

All roots were checked by the existing schema-contract test and the golden
matrix. Totals are decimal strings; arrays remain present when empty.

## Nested Field/Type Audit

The complete nested field ledger is [REPORTING.md](REPORTING.md#json-root-objects-and-dto-fields).
The source evidence is the `Serialize` struct declaration and its
`from_domain` conversion in each listed DTO module. The audit specifically
verified: validation metadata/diagnostic/completion; all four flow traffic
buckets, counters, timestamps, duration, and four inter-arrival objects; all
DNS question/RR/EDNS arrays; HTTP request/response/header options and flags;
TLS Hello options, arrays, extensions, and selected fields; findings subjects,
MITRE provenance, evidence closure, measurements, and tagged values; and
analysis metadata, summary, completion, association, and nullable typed data.

No reporting DTO uses `skip_serializing_if` (the only `serde` attribute in the
DTO layer is the `EvidenceValueDto` tag). Therefore no frozen field is silently
omitted.

The following is the observed nested field ledger. The canonical document's
`S`, `N8`/`N16`/`N32`, `B`, `O`, `A`, and `?` notation records the corresponding
JSON type and nullability for every field below; the cited source ranges are
the declarations audited:

| DTO family | Exact observed fields | Source evidence |
| --- | --- | --- |
| validation | metadata: `format`, `byte_order`, `version_major`, `version_minor`, `linktype`, `snaplen`, `timestamp_resolution`, `section_count`, `interface_count`, `usable_interfaces`, `unusable_interfaces`; summary: `records_emitted`, `total_diagnostics`, `had_diagnostics`; diagnostic: `index`, `stage`, `kind`, `message`, `byte_offset`; completion: `status`, `is_complete`, `terminal_error` | `dto/validation.rs:40-101` |
| flows | record: `id`, `ordinal`, `protocol`, `endpoint_a`, `endpoint_b`, `first_packet`, `last_packet`, `end_reason`, `traffic`, `temporal`; traffic: `total`, `a_to_b`, `b_to_a`, `same_endpoint`; directional: `packet_count`, `captured_bytes`, `wire_bytes`, `truncated_packet_count`; temporal: `status`, `unavailable_reason`, `duration`, `timestamp_coverage`, `first_packet_timestamp`, `last_packet_timestamp`, `overall_inter_arrival`, `a_to_b_inter_arrival`, `b_to_a_inter_arrival`, `same_endpoint_inter_arrival`; timestamp coverage: `available_timestamps`, `unavailable_timestamps`, `invalid_timestamps`, `non_monotonic_transitions`; timestamp: `seconds`, `fractional_units`, `units_per_second`, `offset_seconds`; inter-arrival: `interval_sample_count`, `discontinuity_count`, `min_interval`, `max_interval`, `mean_interval`, `successive_delta_sample_count`, `mean_absolute_successive_interval_delta`; duration: `numerator`, `denominator`, `display` | `dto/flows.rs:38-349` |
| DNS | observation: `packet_ordinal`, `transport`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `transaction_id`, `message_kind`, `opcode`, `authoritative_answer`, `truncation`, `recursion_desired`, `recursion_available`, `response_code`, `questions`, `answers`, `authorities`, `additionals`, `edns`, `completeness`; question: `name`, `qtype`, `qtype_name`, `qclass`; resource record: `name`, `rtype`, `rclass`, `ttl`, `data`; EDNS: `udp_payload_size`, `extended_rcode`, `version`, `dnssec_ok`, `options` | `dto/dns.rs:21-260` |
| HTTP | observation: `packet_ordinal`, `transport`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `message_kind`, `version`, `request`, `response`, `headers`, `completeness`; request: `method`, `target`; response: `status_code`; headers: `host`, `content_type`, `content_length`, `transfer_encoding`, `server`, `user_agent`, `sensitive_headers`; sensitive headers: `authorization_present`, `cookie_present`, `set_cookie_present`, `proxy_authorization_present` | `dto/http.rs:21-199` |
| TLS | observation: `packet_ordinal`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `record_version`, `handshake_kind`, `client_hello`, `server_hello`, `completeness`; client hello: `client_version`, `server_name`, `supported_versions`, `alpn_protocols`, `cipher_suites`, `extensions`; server hello: `server_version`, `selected_version`, `selected_cipher_suite`, `selected_alpn`, `extensions`; extension: `extension_type`, `length` | `dto/tls.rs:21-200` |
| findings/evidence | filter: `min_severity`, `min_confidence`, `detector_id`, `mitre_attack_id`; finding: `id`, `ordinal`, `detector_id`, `detector_version`, `title`, `summary`, `rationale`, `severity`, `confidence`, `subject`, `evidence_references`, `source_finding_references`, `mitre_mappings`; subject: `packets`, `flows`, `observations`; MITRE: `domain`, `catalog_version`, `technique_id`, `technique_name`, `technique_version`, `tactic_id`, `tactic`, `relationship`, `rationale`, `provenance`; provenance: `kind`, `component_id`, `component_version`; evidence: `id`, `kind`, `description`, `packet_references`, `flow_references`, `observation_references`, `measurements`, `limitations`; measurement: `metric_key`, `observed_value`, `threshold`, `comparison`, `unit`; ratio: `numerator`, `denominator`, `string_representation` | `dto/findings.rs:31-414` |
| analysis | report: `schema_version`, `kind`, `metadata`, `summary`, `completion`, `filter`, `flows`, `observations`, `evidence`, `findings`; summary: `total_packets`, `total_flows`, `total_dns_observations`, `total_http_observations`, `total_tls_observations`, `total_findings`, `total_evidence_records`; completion: `status`, `limitations`; observation: `id`, `protocol`, `packet_reference`, `completeness`, `association`, `data`; association: `status`, `flow_reference`, `direction`, `exclusion_reason`; data: `dns`, `http`, `tls` | `dto/analysis.rs:16-194` |

This ledger is descriptive evidence of the frozen source; the linked canonical
field declarations remain the single normative schema contract.

## Wide Integer Audit

The DTO conversion paths call `to_string()` for totals, ordinals, packet/flow/
observation/evidence/finding references, samples, counters, timestamps,
durations, ratios, and `u64`/`i64`/`u128`/`i128`/`usize` values. Boundary coverage
in `schema_contract.rs` exercises `i128::MIN` and `u128::MAX` as JSON strings.
The protocol-sized `u8`, `u16`, and `u32` fields and booleans remain native JSON
numbers/booleans. No float is present in the reporting DTO layer.

## Null and Empty Collection Audit

`None` is serialized as explicit `null`, including validation source/metadata
options, flow timestamps/duration/reasons, HTTP request/response/selected
headers, TLS Hello fields, finding filters and measurement thresholds/
comparisons, and analysis filter/association/data fields. Empty vectors are
`[]`, including protocol sections, TLS lists/extensions, finding subjects/
mappings, evidence references/measurements/limitations, analysis collections,
and NDJSON record sequences with no item records. This is protected by the
schema-contract shape tests and the absence of omission attributes.

## Token Registry Audit

The exhaustive token registry is in [REPORTING.md](REPORTING.md#token-registry).
It includes report kinds, transports, flow lifecycle and temporal states,
validation format/order/completion/diagnostics, DNS/HTTP/TLS classifications,
association and exclusion states, severity/confidence, MITRE fields, evidence
kind/value/comparison/unit/limitation, analysis limitations, and NDJSON record
types. The registry records the intentional PascalCase exceptions for evidence
kind/value/limitation and flow exclusion labels. Validation conversion is
explicitly sourced from `app.rs:218-240` and uses the six stages and seven
diagnostic kinds listed there. Commit `51e9b4d` adds `app.rs:886-955` unit
coverage for all 42 stage/kind combinations, including the emitted stage/kind
tokens and converted summary.

## Duration and Ratio Audit

`DurationDto` contains decimal-string `numerator`, `denominator`, and the exact
existing `display`; `RatioDto` contains decimal-string `numerator`,
`denominator`, and `string_representation`. `EvidenceValueDto::Ratio` and
`::Duration` retain those objects. Schema tests cover reduced fractions and
large integer boundary values. No reporting duration or ratio is an IEEE-754
number.

## NDJSON Audit

The renderer emits one compact JSON object per LF-terminated line with exactly
`schema_version`, `kind`, `record_type`, and `data` (`ndjson/mod.rs:19-32`).
The verified sequences are: validation `summary, diagnostic*`; flows
`summary, flow*`; DNS `summary, dns*`; HTTP `summary, http*`; TLS `summary,
tls*`; findings `summary, finding*, evidence*`; analysis `summary, flow*,
observation*, evidence*, finding*`. The schema-contract test verifies envelope
keys, kind, version, sequence, deterministic repeatability, LF termination,
no BOM, and no blank lines.

## CSV Audit

The six supported headers and exact order are recorded canonically in
[REPORTING.md](REPORTING.md#csv). The source is `csv/mod.rs:21-471`. The audit
verified fixed column counts, `-` missing-value projection, list joining,
boolean/native numeric text, valid CSV escaping, LF terminators, and no BOM.
`analyze` CSV remains an explicit `UnsupportedFormat` and is covered by the
CLI contract and golden error artifact. `sanitize_csv_cell` prefixes all
formula/control triggers without trimming or mutating the original content;
formula sentinels are covered in the schema and reporting tests.

## Privacy / Non-Retention Audit

HTTP retains only selected safe headers and sensitive presence flags; no values
for Authorization, Proxy-Authorization, Cookie, or Set-Cookie are serialized.
TLS retains selected visible metadata but not raw randoms, session IDs, key
exchange bytes, PSK identities/binders, early data, ciphertext, or certificate
DER. Reporting consumes normalized facts and does not add payload retention,
network requests, telemetry, or capture upload. The HTTP privacy sentinel and
TLS DTO tests provide regression evidence.

## Deterministic Ordering Audit

DTO arrays preserve canonical source ordering. Flow records are ordered by flow
reference, observations by `ObservationReference`, and findings/evidence by
engine-assigned references; evidence closure does not renumber identifiers.
JSON field order follows struct declaration. NDJSON uses the sequence above;
CSV headers and rows are fixed. Repeated rendering is byte-identical in the
schema-contract and reporting tests, and table output is protected by goldens.

## Golden Compatibility Audit

`scripts/golden_scenarios.py` reports 49 scenarios. The read-only checker passed:
`verified 49 CLI golden scenarios without modifying tests/golden`. No golden,
fixture, CLI-contract artifact, or schema-version file was changed.

## Schema Contract Test Coverage

The Phase 22 schema-contract test remediations span commits `d13fe54`,
`354dd3d`, `6e2fcec`, and `1d278c0`; `354dd3d` closes the initial audit gaps,
`6e2fcec` adds the analysis-branch nullability assertions, and `1d278c0`
directly covers validation `pcapng`/`big_endian`/`failed`, HTTP invalid
`Content-Length`, and populated `PacketTimestampDto`/`FindingFilterDto`
shapes. The adjacent documentation reconciliation is committed at
`ac72ea1`, which resolves the reporting reference wording, manifest inventory,
and roadmap disclaimer findings. The final target run passed 9 tests. It
covers root and nested shapes, JSON types, wide integers, null/empty behavior,
token boundaries and reporting DTO/domain conversions, tagged evidence values,
JSON/NDJSON/CSV format properties, headers, privacy, formula safety, and
deterministic output. Direct application conversion coverage is provided by
`validation_conversion_maps_every_diagnostic_stage_and_kind` in commit
`51e9b4d` at `app.rs:886-955`; it covers all 42 stage/kind combinations.
`cargo test -p pcapraven-cli --bin pcapraven --locked` passed 11/11 tests. The
reporting schema target `cargo test -p pcapraven-reporting --test
schema_contract --locked` passed 9/9 tests, and remains complementary to the
49 end-to-end golden scenarios and the separate Phase 21 CLI contract test.

## Documentation Discrepancy Ledger

| ID | Source evidence | Documentation evidence | Actual v1 behavior | Severity / compatibility | Disposition |
| --- | --- | --- | --- | --- | --- |
| D-001 | `dto/flows.rs:40-44,80-88`; domain `flow.rs:250-253` | Previous `REPORTING.md` described `reference` and `flow:0` | JSON uses `id`, `ordinal`, and `Flow(0)` | Documentation defect; no wire impact | `DOC_CORRECTION` |
| D-002 | `dto/findings.rs:337-360` | Previous prose used a measurement `name` | Field is `metric_key`, followed by observed value, optional threshold/comparison, unit | Documentation defect; no wire impact | `DOC_CORRECTION` |
| D-003 | `dto/findings.rs:364-378` | Generic lowercase-snake-case wording | Tagged `type` values are `Integer`, `Unsigned`, `Ratio`, `Boolean`, `Duration` | Intentional accepted wire exception | `INTENTIONAL_WIRE_EXCEPTION` |
| D-004 | `app.rs:218-240,886-955`; Phase 22 schema-contract test remediations in `d13fe54`, `354dd3d`, `6e2fcec`, and `1d278c0`; direct conversion coverage in `51e9b4d` | Old test examples did not model application tokens | Stages are `format`, `header`, `block`, `interface`, `packet`, `reader`; kinds are `unsupported`, `malformed`, `incomplete`, `invalid_reference`, `resource_limit`, `io`, `internal`; all 42 combinations are covered by the application conversion test | Test evidence gap; no wire change | `ADDRESSED (51e9b4d); shape/token follow-up (1d278c0)` |
| D-005 | `csv/mod.rs:229-471`; `lib.rs` format dispatch | Hierarchical JSON field inventory was not a CSV projection inventory | CSV is a supported machine-readable flat projection for validation, flows, DNS, HTTP, TLS, and findings; analysis CSV is rejected. Table rendering is a separate human-facing format. | Supported machine-readable CSV projection; no wire redesign | `MACHINE_CSV_PROJECTION; TABLE_SEPARATE` |
| D-006 | DTO modules contain no omission attributes | Prior contract did not state omission behavior | Optional fields are `null`, vectors are `[]` | Contract clarification; no wire change | `ALREADY_CORRECT` |
| D-007 | `crates/pcapraven-cli/src/app.rs:113-245,886-955`; direct coverage added by `51e9b4d` | The audit previously implied validation conversion was tested only by the schema-contract suite | `convert_validation_outcome` has direct app.rs unit coverage for all 42 stage/kind combinations | Test coverage gap; no wire change | `ADDRESSED (51e9b4d)` |

No blocking schema defect was found. No accepted field, type, token, envelope,
CSV header, or schema version was changed.

## Dispositions

The dispositions above correct stale documentation, record the accepted tagged
enum exception, close the validation-conversion test gap, and distinguish
supported machine-readable flat CSV from separate human-facing table
presentation. `BLOCKING_SCHEMA_DEFECT_REQUIRES_USER_DECISION` was not required.

## Production Code Changes

The only production-tree path edited for direct validation coverage was
`crates/pcapraven-cli/src/app.rs`. Its addition is entirely under `#[cfg(test)]`
and exercises `convert_validation_outcome`; it does not alter production
runtime behavior. No reporting serializer source under
`crates/pcapraven-reporting/src/` was edited.

## Compatibility Conclusion

The accepted v1.0 wire schema is internally consistent with the DTOs,
renderers, conversion paths, schema tests, and goldens inspected. Phase 22
documentation work freezes no new wire behavior; it records the existing
contract for later phases. The Phase 21 CLI command/format matrix and stream
contract remain unchanged.

## CI Evidence

### Validation Evidence

The following final local gates were run against the tested remediation head
`ac72ea15b4e68aca3f90e6954932ea191317e674` and passed. The schema-contract
result was run with all four committed test remediations (`d13fe54`,
`354dd3d`, `6e2fcec`, `1d278c0`). This evidence update changes only this audit
document; no Rust source, test, fixture, golden, lockfile, or schema-version
file was changed here.

| Command | Result |
| --- | --- |
| `git diff --check` | `PASS` (no output) |
| `cargo fmt --all -- --check` | `PASS` |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | `PASS` |
| `cargo test --workspace --all-features --locked` | `PASS` |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | `PASS` |
| `cargo metadata --format-version 1 --no-deps --locked` | `PASS` |
| `python3 -B scripts/check_workspace_architecture.py` | `PASS` |
| `python3 -B scripts/test_phase18_performance.py` | `PASS` |
| `python3 -B scripts/test_phase18_acceptance.py` | `PASS` |
| `python3 -B scripts/run_phase18_benchmarks.py --smoke` | `PASS` |
| `python3 -m json.tool` | `PASS` — benchmark-smoke JSON validated |
| `cargo +1.85.0 check --workspace --locked` | `PASS` |
| `cargo +1.85.0 build --workspace --locked` | `PASS` |
| `cargo +1.85.0 test --workspace --locked` | `PASS` |
| `cargo audit --file Cargo.lock --deny warnings` | `PASS` |
| `cargo audit --file fuzz/Cargo.lock --deny warnings` | `PASS` |
| `cargo deny --all-features --config deny.toml --locked check advisories bans licenses sources` | `PASS` |
| `cargo deny --manifest-path fuzz/Cargo.toml --all-features --config deny.toml --locked check advisories bans licenses sources` | `PASS` |
| `cargo test -p pcapraven-reporting --test schema_contract --locked` | `PASS` — final result: 9 passed, 0 failed |
| `cargo test -p pcapraven-reporting --locked` | `PASS` — reporting unit/integration/schema/doc targets passed (4 + 11 + 9 + 0 tests) |
| `cargo test -p pcapraven-cli --test golden --locked` | `PASS` — 9 passed |
| `cargo test -p pcapraven-cli --test contract --locked` | `PASS` — 14 passed |
| `PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_goldens.py` | `PASS` — verified 49 CLI golden scenarios without modifying `tests/golden` |
| `PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate_fixtures.py --check` | `PASS` — verified 20 synthetic fixtures/checksums |
| `LSAN_OPTIONS=detect_leaks=0 cargo fuzz run <target> corpus/<target> -- -max_len=<target-limit> -max_total_time=30 -timeout=5 -rss_limit_mb=1024` | `PASS` — all 8 smoke targets: `fuzz_pcap_reader`, `fuzz_packet_normalizer`, `fuzz_flow_reconstructor`, `fuzz_dns_parser`, `fuzz_http_parser`, `fuzz_tls_parser`, `fuzz_detection_engine`, `fuzz_reporting` |

The initial unmodified `fuzz_pcap_reader` smoke attempt produced the reported
zero-byte result and failed only at sanitizer teardown because the WSL host
provided a ptrace-only environment. Re-running the complete eight-target smoke
set with `LSAN_OPTIONS=detect_leaks=0` passed; this is a local workaround and
does not replace authoritative CI sanitizer evidence.

The lockfile digests remain unchanged from the baseline: `Cargo.lock`
SHA-256 `e4c1615538cfec6852e3c3b405548a9580f29b1def8ea57a21b27125f08d0dba`
and `fuzz/Cargo.lock` SHA-256
`f3c37867b80c9389e287e91d38e0f0446585c199444bcd671985a72f9106329f`.

### Final PR-head CI evidence

PR #32 for `DanielMR-dev/PcapRaven` was verified at exact head
`ac72ea15b4e68aca3f90e6954932ea191317e674` by CI workflow run
`33123524823` (run number 108). This is the final CI evidence for the tested
code/remediation state. The run completed with conclusion `success`; all 14
jobs completed successfully:

| Job | Completed checks | Result |
| --- | --- | --- |
| `MSRV 1.85.0` | MSRV workspace check, build, and test | `success` |
| `Linux quality` | Pinned toolchain, formatting, Clippy, verification support, fixture integrity, goldens, workspace tests, documentation, metadata, architecture, Phase 18 methodology/acceptance, and benchmark smoke | `success` |
| `Security and supply chain` | Main/fuzz lockfile audits and main/fuzz dependency-policy checks | `success` |
| `Cross-platform workspace check (ubuntu-latest)` | Workspace, reporting schema, canonical goldens, and CLI v1 contract | `success` |
| `Cross-platform workspace check (windows-latest)` | Workspace, reporting schema, canonical goldens, and CLI v1 contract | `success` |
| `Cross-platform workspace check (macos-latest)` | Workspace, reporting schema, canonical goldens, and CLI v1 contract | `success` |
| `Linux fuzz smoke (fuzz_pcap_reader)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |
| `Linux fuzz smoke (fuzz_packet_normalizer)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |
| `Linux fuzz smoke (fuzz_flow_reconstructor)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |
| `Linux fuzz smoke (fuzz_dns_parser)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |
| `Linux fuzz smoke (fuzz_http_parser)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |
| `Linux fuzz smoke (fuzz_tls_parser)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |
| `Linux fuzz smoke (fuzz_detection_engine)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |
| `Linux fuzz smoke (fuzz_reporting)` | Bounded fuzz smoke; failure-artifact upload skipped as expected | `success` |

The cross-platform workspace, contract, golden, schema, MSRV, quality,
security/supply-chain, and all eight fuzz-smoke jobs are therefore covered by
this exact-head result. The conditional fuzz failure-artifact upload step was
skipped for each successful fuzz job as expected.

This branch changes tests, documentation, audit evidence, and governance only;
the sole production-tree edit is entirely under `#[cfg(test)]`. The conditional
full fuzz-acceptance campaign and full Phase 18 performance comparison were
therefore not required because no fuzzed or benchmarked production behavior
changed. The local eight-target fuzz smoke and benchmark smoke passed as
recorded above. The final audit-ledger commit itself is documentation-only and
is not represented by this run; after it is committed and pushed, its exact
head must receive its own PR CI verification.

## Reviewer Findings

The independent source-read-only review of HEAD `d3eefc0` was rejected. It
reported two HIGH findings and two MEDIUM findings; no CRITICAL finding was
reported.

| Severity | Finding | Disposition |
| --- | --- | --- |
| HIGH | Direct coverage for `app.rs` `convert_validation_outcome` was missing. | `REMEDIATED` by `51e9b4d`, which adds `app.rs:886-955` coverage for all 42 stage/kind combinations; the CLI-bin test passed 11/11. |
| HIGH | Mandatory Phase 22 acceptance evidence was missing. | The earlier evidence was insufficient for the later remediation head; the finding was subsequently addressed by exact-head PR CI run `33123524823` for `ac72ea15b4e68aca3f90e6954932ea191317e674`, as recorded below. The conditional full fuzz-acceptance and full Phase 18 performance reruns were not required because no fuzzed or benchmarked production behavior changed. |
| MEDIUM | The token registry omitted bounded HTTP and TLS version rows. | `REMEDIATED` by `30707e0`, which records the HTTP/1.0, HTTP/1.1, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, and `Unknown` tokens. |
| MEDIUM | The CSV disposition incorrectly labeled supported machine-readable CSV as non-machine table behavior. | `REMEDIATED` in this audit update; D-005 now distinguishes supported machine-readable CSV projections from human-facing table rendering. |

### Final independent source-read-only re-review

The final independent source-read-only re-review of HEAD
`3708b60474d6bfb0647eb2b1110b372d444c81f3` was `APPROVE FOR IMPLEMENTATION
REVIEW`.

| Severity | Count | Result |
| --- | ---: | --- |
| CRITICAL | 0 | No finding |
| HIGH | 0 | No finding |
| MEDIUM | 0 | No finding |
| LOW | 1 | The generated artifact `scripts/__pycache__/run_phase18_benchmarks.cpython-314.pyc` was identified. |

The exact generated artifact was removed before delivery, and no tracked
implementation change resulted. The LOW finding is therefore resolved. Final
acceptance-gate evidence is recorded above.

### Independent review of `a1c84ba`

The subsequent independent source-read-only review of
`a1c84ba5341c0b68f32e1cd6c04d2f290d6e1e7e` was `REJECT`. It reported one
HIGH, two MEDIUM, and one LOW finding; no CRITICAL finding was reported. The
review and its dispositions were:

| Severity | Finding | Disposition |
| --- | --- | --- |
| HIGH | The current head lacked exact-current-head PR CI evidence. | `ADDRESSED` by pushing `ac72ea1`; exact-head CI run `33123524823` passed all 14 jobs for `ac72ea15b4e68aca3f90e6954932ea191317e674`. |
| MEDIUM | Token coverage and populated `PacketTimestampDto`/`FindingFilterDto` shape coverage were incomplete. | `REMEDIATED` by `1d278c0`, which directly covers validation `pcapng`/`big_endian`/`failed`, HTTP invalid `Content-Length`, and the populated DTO shapes. |
| MEDIUM | Reporting reference wording was internally contradictory. | `REMEDIATED` by `ac72ea1`, which clarifies decimal ordinals versus structured reference identifiers. |
| LOW | The manifest inventory and roadmap disclaimer had summary drift. | `REMEDIATED` by `ac72ea1`, which updates both summaries. |

This records findings against `a1c84ba` only; it does not claim an independent
review of the later audit-ledger commit.

## Residual Limitations

- Local WSL validation is not native Windows or macOS execution; authoritative
  CI run `33123524823` supplied the passing Windows and macOS cross-platform
  contract, golden, and schema evidence for the tested `ac72ea1` remediation
  head.
- The local eight-target fuzz smoke pass required the documented
  `LSAN_OPTIONS=detect_leaks=0` workaround after the initial unmodified
  `fuzz_pcap_reader` zero-byte ptrace-only sanitizer teardown issue;
  authoritative CI fuzz smoke passed all eight targets.
- Full fuzz acceptance and the full Phase 18 performance comparison were not
  rerun because this branch did not change fuzzed or benchmarked production
  behavior. Local eight-target fuzz smoke and benchmark smoke passed.
- The final re-review's sole LOW cache artifact finding was resolved before
  delivery by removing `scripts/__pycache__/run_phase18_benchmarks.cpython-314.pyc`;
  it caused no tracked implementation change and is not a remaining limitation.
- The Phase 22 schema-contract test remediations are committed at `d13fe54`,
  `354dd3d`, `6e2fcec`, and `1d278c0`; `schema_contract.rs` has no uncommitted
  change. The current ledger update is documentation-only and does not modify
  that file.
- The final audit-ledger commit is not yet represented by CI. After this
  documentation-only change is committed and pushed, its exact-head PR CI is
  the last mechanical verification required for the ledger.

## Phase Status

Phase 21: `COMPLETE / ACCEPTED`

Phase 22: `COMPLETE / ACCEPTED` for the tested remediation state at
`ac72ea15b4e68aca3f90e6954932ea191317e674`; the audit-ledger commit itself
remains subject to its own exact-head PR CI after push.

Phase 23: `NEXT / NOT IMPLEMENTED`

Phases 24–28: `FUTURE / NOT IMPLEMENTED`

No v1.0.0 or release-readiness claim is made.
