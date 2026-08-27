# Reporting Contract

## Authority and scope

This document is the canonical owner of the accepted PcapRaven reporting wire
contract. `docs/REPORTING_SCHEMA_V1_AUDIT.md` records Phase 22 evidence and
dispositions; it does not replace this contract. Reporting DTOs are in
`crates/pcapraven-reporting/src/dto/`, and format dispatch is in
`crates/pcapraven-reporting/src/lib.rs`.

The contract projects normalized facts. It does not retain raw packet payloads,
credentials, TLS secrets, ciphertext, or certificate DER. Table output is
deterministic human-facing output, but is not the hierarchical machine schema.

## Schema version and format matrix

`pcapraven_reporting::REPORT_SCHEMA_VERSION` is exactly `"v1.0"`
([format.rs](../crates/pcapraven-reporting/src/format.rs#L7-L8)).

| Report kind | table | json | ndjson | csv |
| --- | --- | --- | --- | --- |
| `validation` | yes | yes | yes | yes |
| `flows` | yes | yes | yes | yes |
| `dns` | yes | yes | yes | yes |
| `http` | yes | yes | yes | yes |
| `tls` | yes | yes | yes | yes |
| `findings` | yes | yes | yes | yes |
| `analysis` | yes | yes | yes | no |

`analyze --format csv` is rejected as a configuration error by the frozen CLI
contract. No format or report kind is added here.

## Safe output-file lifecycle

The CLI's `with_output_sink` function is the source of truth for `--output
<PATH>` behavior ([app.rs](../crates/pcapraven-cli/src/app.rs#L31-L111)):

1. Target files are opened with `OpenOptions::create_new(true)`. If the target
   already exists, it is never opened or overwritten; the CLI emits a
   configuration diagnostic and returns exit code `2`. If diagnostic emission
   itself fails, the helper returns exit code `1`.
2. Missing or inaccessible parent paths are fatal output-creation failures and
   return exit code `1`; parent directories are not created.
3. Rendering is performed through a `BufWriter`, then `flush` is called
   explicitly ([app.rs](../crates/pcapraven-cli/src/app.rs#L44-L50)). A render or
   flush failure on a newly created output file drops the writer and
   best-effort removes that incomplete file. Ordinary rendering/flush failures
   return exit code `1`; `UnsupportedFormat` remains a configuration error and
   returns exit code `2`.
4. Existing files are not removed by failure cleanup because cleanup occurs
   only after successful exclusive creation. Stdout uses the same explicit
   render-and-flush path but has no file cleanup operation.

There is no force-overwrite option, and the CLI does not implicitly create
temporary files or parent directories or switch to stdin, network, or directory
output modes.

These output-sink errors are distinct from the successful command result codes:
complete analysis returns `0`, while a useful partial result returns `3`
([analysis.rs](../crates/pcapraven-cli/src/analysis.rs#L97-L112)).

## General representation rules

- Struct field order below is serialized field order. DTOs derive `Serialize`
  without `skip_serializing_if`; every field is emitted.
- `Option::None` is JSON `null`; empty `Vec` values are JSON `[]`.
- Report totals, ordinal and count fields (including packet ordinals and sample
  counts), and all `u64`, `i64`, `u128`, `i128`, and `usize` values are decimal
  JSON strings. Bounded `u8`, `u16`, `u32`, and `bool` fields remain JSON
  numbers or booleans.
- Structured reference identifiers retain their established grammars:
  `Flow(n)`, `obs:packet:protocol:ordinal`, `evi:n`, and `find:n`. Packet
  ordinal references in fields named `packet_*` or `packets` remain decimal
  strings. See the domain `Display` implementations ([flow.rs](../crates/pcapraven-domain/src/flow.rs#L232-L254),
  [observation.rs](../crates/pcapraven-domain/src/observation.rs#L57-L106),
  [evidence.rs](../crates/pcapraven-domain/src/evidence.rs#L75-L97),
  [finding.rs](../crates/pcapraven-domain/src/finding.rs#L546-L567)).
- Exact duration and ratio components are decimal strings; exact values never
  use floating-point numbers.

## JSON root objects and DTO fields

These are the complete serialized field sets, in order. `S` means JSON string,
`N8`/`N16`/`N32` a bounded JSON number, `B` boolean, `O` object, `A` array,
and `?` nullable.

### Validation

`ValidationReportDto` ([validation.rs](../crates/pcapraven-reporting/src/dto/validation.rs#L7-L24)):
`schema_version:S`, `kind:S`, `source_path:S?`, `metadata:O`, `summary:O`,
`diagnostics:A[O]`, `completion:O`.

`ValidationMetadataDto` ([validation.rs](../crates/pcapraven-reporting/src/dto/validation.rs#L40-L65)):
`format:S`, `byte_order:S`, `version_major:N16?`, `version_minor:N16?`,
`linktype:N32?`, `snaplen:N32?`, `timestamp_resolution:S?`,
`section_count:S?`, `interface_count:S?`, `usable_interfaces:S?`,
`unusable_interfaces:S?`. `ValidationSummaryDto` has
`records_emitted:S`, `total_diagnostics:S`, `had_diagnostics:B`.
`ValidationDiagnosticDto` has `index:S`, `stage:S`, `kind:S`, `message:S`,
`byte_offset:S?`. `ValidationCompletionDto` has `status:S`, `is_complete:B`,
`terminal_error:S?` ([validation.rs](../crates/pcapraven-reporting/src/dto/validation.rs#L67-L101)).

### Flows

`FlowsReportDto` is `schema_version:S`, `kind:S`, `total_flows:S`,
`flows:A[O]` ([flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L12-L23)).
`FlowRecordDto` is `id:S`, `ordinal:S`, `protocol:S`, `endpoint_a:S`,
`endpoint_b:S`, `first_packet:S`, `last_packet:S`, `end_reason:S`,
`traffic:O`, `temporal:O` ([flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L38-L91)).
`id` is the `FlowReference` string and `ordinal` its decimal ordinal; there is
no serialized field named `reference`.

`FlowTrafficDto` has `total:O`, `a_to_b:O`, `b_to_a:O`, `same_endpoint:O`;
each `FlowDirectionalTrafficDto` has `packet_count:S`, `captured_bytes:S`,
`wire_bytes:S`, `truncated_packet_count:S`
([flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L95-L145)).
`FlowTemporalDto` has `status:S`, `unavailable_reason:S?`, `duration:O?`,
`timestamp_coverage:O`, `first_packet_timestamp:O?`,
`last_packet_timestamp:O?`, `overall_inter_arrival:O`,
`a_to_b_inter_arrival:O`, `b_to_a_inter_arrival:O`,
`same_endpoint_inter_arrival:O` ([flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L207-L281)).
`PacketTimestampDto` has `seconds:S`, `fractional_units:S`,
`units_per_second:S`, `offset_seconds:S`. `FlowTimestampCoverageDto` has
`available_timestamps:S`, `unavailable_timestamps:S`, `invalid_timestamps:S`,
`non_monotonic_transitions:S` ([flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L147-L203)).
Each `InterArrivalMetricsDto` has `interval_sample_count:S`,
`discontinuity_count:S`, `min_interval:O?`, `max_interval:O?`,
`mean_interval:O?`, `successive_delta_sample_count:S`, and
`mean_absolute_successive_interval_delta:O?`
([flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L285-L326)).
`DurationDto` has `numerator:S`, `denominator:S`, `display:S`
([flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L329-L349)).

### DNS

`DnsReportDto` is `schema_version:S`, `kind:S`, `total_observations:S`,
`observations:A[O]`. `DnsObservationDto` is
`packet_ordinal:S`, `transport:S`, `source_ip:S`, `source_port:N16`,
`destination_ip:S`, `destination_port:N16`, `transaction_id:N16`,
`message_kind:S`, `opcode:N8`, `authoritative_answer:B`, `truncation:B`,
`recursion_desired:B`, `recursion_available:B`, `response_code:N16`,
`questions:A[O]`, `answers:A[O]`, `authorities:A[O]`, `additionals:A[O]`,
`edns:O?`, `completeness:S`
([dns.rs](../crates/pcapraven-reporting/src/dto/dns.rs#L8-L80)).
`DnsQuestionDto` is `name:S`, `qtype:N16`, `qtype_name:S`, `qclass:N16`.
`DnsResourceRecordDto` is `name:S`, `rtype:N16`, `rclass:N16`, `ttl:N32`,
`data:S`. `DnsEdnsDto` is `udp_payload_size:N16`, `extended_rcode:N8`,
`version:N8`, `dnssec_ok:B`, `options:A[N16]`
([dns.rs](../crates/pcapraven-reporting/src/dto/dns.rs#L146-L260)).

### HTTP

`HttpReportDto` is `schema_version:S`, `kind:S`, `total_observations:S`,
`observations:A[O]`. `HttpObservationDto` is
`packet_ordinal:S`, `transport:S`, `source_ip:S`, `source_port:N16`,
`destination_ip:S`, `destination_port:N16`, `message_kind:S`, `version:S`,
`request:O?`, `response:O?`, `headers:O`, `completeness:S`
([http.rs](../crates/pcapraven-reporting/src/dto/http.rs#L8-L98)).
`HttpRequestDto` is `method:S`, `target:S`; `HttpResponseDto` is
`status_code:N16`. `HttpHeadersDto` is `host:S?`, `content_type:S?`,
`content_length:S`, `transfer_encoding:S?`, `server:S?`, `user_agent:S?`,
`sensitive_headers:O`; the sensitive object has boolean fields
`authorization_present`, `cookie_present`, `set_cookie_present`, and
`proxy_authorization_present` ([http.rs](../crates/pcapraven-reporting/src/dto/http.rs#L101-L199)).
`content_length` is a decimal `u64` string, `not_present`, or `invalid`.

### TLS

`TlsReportDto` is `schema_version:S`, `kind:S`, `total_observations:S`,
`observations:A[O]`. `TlsObservationDto` is
`packet_ordinal:S`, `source_ip:S`, `source_port:N16`, `destination_ip:S`,
`destination_port:N16`, `record_version:S`, `handshake_kind:S`,
`client_hello:O?`, `server_hello:O?`, `completeness:S`
([tls.rs](../crates/pcapraven-reporting/src/dto/tls.rs#L8-L100)).
`TlsClientHelloDto` is `client_version:S`, `server_name:S?`,
`supported_versions:A[S]`, `alpn_protocols:A[S]`, `cipher_suites:A[S]`,
`extensions:A[O]`. `TlsServerHelloDto` is `server_version:S`,
`selected_version:S?`, `selected_cipher_suite:S`, `selected_alpn:S?`,
`extensions:A[O]`. `TlsExtensionDto` is `extension_type:N16`, `length:N16`
([tls.rs](../crates/pcapraven-reporting/src/dto/tls.rs#L103-L200)).

### Findings and evidence

`FindingsReportDto` is `schema_version:S`, `kind:S`, `total_findings:S`,
`total_evidence_records:S`, `filter:O?`, `findings:A[O]`, `evidence:A[O]`
([findings.rs](../crates/pcapraven-reporting/src/dto/findings.rs#L12-L29)).
`FindingFilterDto` has nullable strings `min_severity`, `min_confidence`,
`detector_id`, `mitre_attack_id`. `FindingRecordDto` has
`id:S`, `ordinal:S`, `detector_id:S`, `detector_version:S`, `title:S`,
`summary:S`, `rationale:S`, `severity:S`, `confidence:S`, `subject:O`,
`evidence_references:A[S]`, `source_finding_references:A[S]`,
`mitre_mappings:A[O]` ([findings.rs](../crates/pcapraven-reporting/src/dto/findings.rs#L57-L99)).
`FindingSubjectDto` has `packets:A[S]`, `flows:A[S]`, `observations:A[S]`.
`MitreMappingDto` has `domain:S`, `catalog_version:S`, `technique_id:S`,
`technique_name:S`, `technique_version:S`, `tactic_id:S`, `tactic:S`,
`relationship:S`, `rationale:S`, `provenance:O`; provenance has `kind:S`,
`component_id:S`, `component_version:S`
([findings.rs](../crates/pcapraven-reporting/src/dto/findings.rs#L149-L279)).

`EvidenceRecordDto` has `id:S`, `kind:S`, `description:S`,
`packet_references:A[S]`, `flow_references:A[S]`,
`observation_references:A[S]`, `measurements:A[O]`, `limitations:A[S]`.
`EvidenceMeasurementDto` has exactly `metric_key:S`, `observed_value:O`,
`threshold:O?`, `comparison:S?`, `unit:S`
([findings.rs](../crates/pcapraven-reporting/src/dto/findings.rs#L281-L362));
the field is `metric_key`, not `name`.

`EvidenceValueDto` uses `#[serde(tag = "type", content = "value")]`
([findings.rs](../crates/pcapraven-reporting/src/dto/findings.rs#L364-L391)).
Its exact objects are `{"type":"Integer","value":S}`,
`{"type":"Unsigned","value":S}`, `{"type":"Ratio","value":O}`,
`{"type":"Boolean","value":B}`, and `{"type":"Duration","value":O}`.
These PascalCase tags are an intentional exception to generalized lowercase
token guidance. `RatioDto` is `numerator:S`, `denominator:S`,
`string_representation:S` ([findings.rs](../crates/pcapraven-reporting/src/dto/findings.rs#L394-L414)).

### Unified analysis

`AnalysisReportDto` is, in order, `schema_version:S`, `kind:S`, `metadata:O`,
`summary:O`, `completion:O`, `filter:O?`, `flows:A[O]`, `observations:A[O]`,
`evidence:A[O]`, `findings:A[O]`
([analysis.rs](../crates/pcapraven-reporting/src/dto/analysis.rs#L16-L39)).
`AnalysisSummaryDto` has the seven string fields `total_packets`,
`total_flows`, `total_dns_observations`, `total_http_observations`,
`total_tls_observations`, `total_findings`, `total_evidence_records`.
`ReportCompletionDto` has `status:S`, `limitations:A[S]`
([analysis.rs](../crates/pcapraven-reporting/src/dto/analysis.rs#L58-L84)).
`ProtocolObservationDto` has `id:S`, `protocol:S`, `packet_reference:S`,
`completeness:S`, `association:O`, `data:O`. Association has `status:S`,
`flow_reference:S?`, `direction:S?`, `exclusion_reason:S?`; data has nullable
`dns:O?`, `http:O?`, `tls:O?`
([analysis.rs](../crates/pcapraven-reporting/src/dto/analysis.rs#L86-L194)).
Exactly one typed data member is non-null for a real protocol observation.

## Token registry

Categorical tokens are produced by explicit conversion matches, not an assumed
enum naming convention.

| Domain | Exact v1 tokens |
| --- | --- |
| report kind | `validation`, `flows`, `dns`, `http`, `tls`, `findings`, `analysis` |
| transport | `tcp`, `udp` (HTTP is `tcp`) |
| flow end reason | `end_of_input`, `idle_timeout`, `tcp_reset`, `tcp_new_initial_syn`, `analysis_stopped` |
| temporal status/reason | `available`, `unavailable`; `insufficient_samples`, `timestamp_unavailable`, `invalid_timestamp`, `non_monotonic_timestamp`, `arithmetic_overflow` |
| validation format/order | `pcap`, `pcapng`, `unknown`; `little_endian`, `big_endian`, `unknown` |
| validation completion | `complete`, `partial`, `failed` |
| validation diagnostic stage | `format`, `header`, `block`, `interface`, `packet`, `reader` |
| validation diagnostic kind | `unsupported`, `malformed`, `incomplete`, `invalid_reference`, `resource_limit`, `io`, `internal` |
| DNS message/completeness | `query`, `response`; `complete`, `partial` |
| HTTP message/completeness | `request`, `response`; `complete`, `partial` |
| HTTP version | `HTTP/1.0`, `HTTP/1.1` ([domain](../crates/pcapraven-domain/src/http.rs), [reporting DTO](../crates/pcapraven-reporting/src/dto/http.rs)) |
| HTTP Content-Length | `not_present`, `invalid`, or a decimal `u64` string |
| TLS handshake | `client_hello`, `server_hello`, `hello_retry_request`, `other` |
| TLS version | `SSLv3`, `TLS 1.0`, `TLS 1.1`, `TLS 1.2`, `TLS 1.3`, `Unknown` ([domain](../crates/pcapraven-domain/src/tls.rs), [reporting DTO](../crates/pcapraven-reporting/src/dto/tls.rs)); `Unknown` is the bounded DTO token for unknown wire codes |
| association status/direction | `associated`, `excluded`, `unassociated`; `a_to_b`, `b_to_a`, `same_endpoint` |
| flow exclusion | `MissingNetworkLayer`, `MissingTransportLayer`, `FragmentedWithoutTransport`, `UnsupportedTransport` |
| finding severity/confidence | `info`, `low`, `medium`, `high`, `critical`; `low`, `medium`, `high` |
| MITRE domain/relationship/provenance | `enterprise`; `analytical`; `detector`, `correlator` |
| MITRE tactic | `initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact` |
| evidence kind | `PacketMeasurement`, `FlowMeasurement`, `ProtocolObservation`, `TemporalMetric`, `RatioComparison`, `ProtocolFact` |
| evidence value type | `Integer`, `Unsigned`, `Ratio`, `Boolean`, `Duration` |
| evidence comparison | `==`, `!=`, `<`, `<=`, `>`, `>=` |
| evidence unit | `bytes`, `packets`, `ns`, `us`, `ms`, `s`, `ratio`, `count`, `%` |
| evidence limitation | `CaptureTruncated`, `TruncatedPayload`, `MissingNetworkLayer`, `IncompleteHandshake`, `PacketCountBudgetReached`, `ObservationBudgetReached`, `FlowBudgetReached`, `HeaderBudgetExceeded` |
| analysis completion/limitation | `complete`, `partial`; `capture_truncated`, `packet_count_budget_reached`, `flow_budget_reached`, `observation_budget_reached` |
| NDJSON `record_type` | `summary` (all kinds); `diagnostic` (validation); `flow` (flows, analysis); `dns` (dns); `http` (http); `tls` (tls); `finding` (findings, analysis); `observation` (analysis); `evidence` (findings, analysis) |

The lowercase DTO and validation tokens are established by DTO/CLI conversion
([app.rs](../crates/pcapraven-cli/src/app.rs#L113-L245),
[flows.rs](../crates/pcapraven-reporting/src/dto/flows.rs#L63-L90)); the
PascalCase evidence and exclusion labels are preserved domain labels
([evidence.rs](../crates/pcapraven-domain/src/evidence.rs#L116-L127),
[flow.rs](../crates/pcapraven-domain/src/flow.rs#L296-L305)).

## NDJSON

Each physical line is one compact JSON object with exactly these envelope fields,
in order: `schema_version`, `kind`, `record_type`, `data`. `schema_version` is
`v1.0`; `data` is the corresponding object. Lines use LF, with no BOM, blank
lines, or CR characters ([ndjson/mod.rs](../crates/pcapraven-reporting/src/ndjson/mod.rs#L19-L32)).

The exact sequences are `summary, diagnostic*` for validation;
`summary, flow*` for flows; `summary, dns*` for DNS; `summary, http*` for HTTP;
`summary, tls*` for TLS; `summary, finding*, evidence*` for findings; and
`summary, flow*, observation*, evidence*, finding*` for analysis. Collection
order is canonical input order and identifiers are never renumbered
([ndjson/mod.rs](../crates/pcapraven-reporting/src/ndjson/mod.rs#L43-L304)).

## CSV

CSV is a flat projection. Writers use explicit LF and no BOM
([csv/mod.rs](../crates/pcapraven-reporting/src/csv/mod.rs#L15-L19)). Exact
headers, in order, are:

| Report | Header |
| --- | --- |
| validation | `property,value` |
| flows | `id,ordinal,protocol,endpoint_a,endpoint_b,total_packets,packets_a_to_b,packets_b_to_a,packets_same_endpoint,total_captured_bytes,captured_bytes_a_to_b,captured_bytes_b_to_a,total_wire_bytes,wire_bytes_a_to_b,wire_bytes_b_to_a,duration_numerator,duration_denominator,duration_display,end_reason` |
| DNS | `packet_ordinal,transport,source_ip,source_port,destination_ip,destination_port,transaction_id,message_kind,opcode,authoritative_answer,truncation,recursion_desired,recursion_available,response_code,qname,qtype,qclass,answers_count,edns_present,completeness` |
| HTTP | `packet_ordinal,transport,source_ip,source_port,destination_ip,destination_port,message_kind,version,method,target,status_code,host,content_type,content_length,transfer_encoding,server,user_agent,authorization_present,cookie_present,set_cookie_present,proxy_authorization_present,completeness` |
| TLS | `packet_ordinal,source_ip,source_port,destination_ip,destination_port,record_version,handshake_kind,client_version,server_version,selected_version,selected_cipher_suite,server_name,alpn_protocols,ciphers_count,extensions_count,completeness` |
| findings | `id,ordinal,detector_id,detector_version,title,summary,rationale,severity,confidence,packets,flows,observations,evidence_references,source_finding_references,mitre_techniques` |

Validation emits eight property/value rows. Missing flat values are `-`;
HTTP method/target/status and optional headers use `-`; flow unavailable
durations use `-`, except `duration_display`, which uses the unavailable
reason; DNS uses the first question and `-` when absent; TLS selects the
applicable Hello projection and uses `-`; findings joins lists with `;` and
MITRE fields as `technique_id:tactic_id`. These projections are implemented in
[csv/mod.rs](../crates/pcapraven-reporting/src/csv/mod.rs#L21-L471).

Untrusted cell text beginning with `=`, `+`, `-`, `@`, tab, CR, or LF, or with
leading whitespace followed by `=`, `+`, `-`, or `@`, is prefixed with `'` and
otherwise retained ([csv_escape.rs](../crates/pcapraven-reporting/src/csv_escape.rs#L3-L22)).

## Table output

Table output is deterministic, terminal-safe human presentation and is not a
versioned hierarchical machine schema. Existing table goldens are byte-exact
regression evidence and must not be regenerated for documentation changes.

## Privacy, determinism, and evolution

HTTP emits selected safe headers and sensitive-header presence flags only;
`Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` values are
never retained or emitted. TLS emits selected visible handshake metadata only;
randoms, session IDs, key exchange bytes, PSK identities/binders, early-data
payloads, ciphertext, and certificate DER are not serialized. Parsers and domain
models own bounded retention and terminal-safe escaping.

JSON uses `serde_json::to_string_pretty` followed by one LF
([json/mod.rs](../crates/pcapraven-reporting/src/json/mod.rs#L14-L83)). The
49-scenario golden matrix and `schema_contract` protect wire behavior; the CLI
contract separately protects command compatibility and CSV rejection.

After Phase 22 acceptance, v1.0 is frozen. Any incompatible field, type,
nullability, token, tagged-value, reference grammar, envelope, ordering, CSV
header, missing-value, integer, or rational change requires explicit user
approval and a schema-versioning decision. Phase 22 does not bump the version.
