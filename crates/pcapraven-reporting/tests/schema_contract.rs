//! Machine schema contract tests for PcapRaven deterministic reporting.
//!
//! Validates the frozen v1.0 JSON and NDJSON contract rules:
//! - Wide integers (u64, i64, u128, i128, usize) serialize as decimal JSON strings.
//! - Options serialize as `null` when `None`.
//! - Vectors serialize as `[]` when empty.
//! - DTO conversion maps domain and CLI categorical values to their documented tokens.
//! - Exact rational arithmetic is preserved in `RatioDto` and `DurationDto`.

use std::collections::BTreeSet;
use std::fmt;

use pcapraven_domain::{
    Confidence, DnsEdnsMetadata, DnsEdnsOptionMetadata, DnsFlags, DnsMessageKind, DnsName,
    DnsObservation, DnsObservationCompleteness, DnsQuestion, DnsRdataMetadata, DnsResourceRecord,
    DnsSection, DnsTransport, EvidenceComparison, EvidenceDescription, EvidenceDraftBuilder,
    EvidenceKind, EvidenceLimitation, EvidenceMeasurement, EvidenceMetricKey, EvidenceRatio,
    EvidenceRecord, EvidenceReference, EvidenceUnit, EvidenceValue, FindingDraft, FindingRationale,
    FindingRecord, FindingSubject, FindingSummary, FindingTitle, FlowDirection, FlowDuration,
    FlowEndReason, FlowEndpoint, FlowExclusionReason, FlowInterArrivalMetrics, FlowKey, FlowRecord,
    FlowReference, FlowTemporalMetrics, FlowTemporalUnavailableReason, FlowTemporalValue,
    FlowTimestampCoverage, FlowTrafficCounters, HttpMessageKind, HttpObservationCompleteness,
    HttpResponseMetadata, IpAddress, MitreAttackCatalogVersion, MitreAttackDomain, MitreAttackId,
    MitreAttackObjectVersion, MitreAttackRelationship, MitreMapping, MitreMappingDeclaration,
    MitreMappingProvenance, MitreMappingRationale, MitreTactic, ObservationFlowAssociation,
    ObservationReference, PacketReference, PacketTimestamp, PacketTimestampResolution,
    ProtocolKind, ProtocolObservation, ProtocolObservationData, Severity, TlsHandshakeKind,
    TlsObservationCompleteness, TlsServerHelloMetadata, TlsVersion, TransportProtocol,
};
use pcapraven_reporting::dto::analysis::*;
use pcapraven_reporting::dto::dns::*;
use pcapraven_reporting::dto::findings::*;
use pcapraven_reporting::dto::flows::*;
use pcapraven_reporting::dto::http::*;
use pcapraven_reporting::dto::tls::*;
use pcapraven_reporting::dto::validation::*;
use pcapraven_reporting::{
    REPORT_SCHEMA_VERSION, ReportError, ReportFormat, ReportKind, report_analysis, report_dns,
    report_findings, report_flows, report_http, report_tls, report_validation, sanitize_csv_cell,
};
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;

#[test]
fn test_frozen_schema_version_constant() {
    assert_eq!(REPORT_SCHEMA_VERSION, "v1.0");
}

#[test]
fn test_validation_report_json_schema_contract() {
    let report = ValidationReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "validation",
        source_path: None,
        metadata: ValidationMetadataDto {
            format: "pcap".to_string(),
            byte_order: "little_endian".to_string(),
            version_major: Some(2),
            version_minor: Some(4),
            linktype: Some(1),
            snaplen: Some(65535),
            timestamp_resolution: Some("10^6 units/s".to_string()),
            section_count: None,
            interface_count: None,
            usable_interfaces: None,
            unusable_interfaces: None,
        },
        summary: ValidationSummaryDto {
            records_emitted: "18446744073709551615".to_string(), // u64::MAX as string
            total_diagnostics: "0".to_string(),
            had_diagnostics: false,
        },
        diagnostics: vec![ValidationDiagnosticDto {
            index: "0".to_string(),
            stage: "packet".to_string(),
            kind: "malformed".to_string(),
            message: "test warning".to_string(),
            byte_offset: Some("1024".to_string()),
        }],
        completion: ValidationCompletionDto {
            status: "complete".to_string(),
            is_complete: true,
            terminal_error: None,
        },
    };

    let json_val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();

    assert_eq!(json_val["schema_version"], "v1.0");
    assert_eq!(json_val["kind"], "validation");
    assert!(json_val["source_path"].is_null());
    assert_eq!(
        json_val["summary"]["records_emitted"],
        "18446744073709551615"
    );
    assert_eq!(json_val["summary"]["total_diagnostics"], "0");
    assert_eq!(json_val["metadata"]["byte_order"], "little_endian");
    assert!(json_val["metadata"]["section_count"].is_null());
    assert_eq!(json_val["diagnostics"][0]["index"], "0");
    assert_eq!(json_val["diagnostics"][0]["byte_offset"], "1024");
    assert!(json_val["completion"]["terminal_error"].is_null());
}

#[test]
fn test_flows_report_json_schema_contract() {
    let report = FlowsReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "flows",
        total_flows: "1".to_string(),
        flows: vec![FlowRecordDto {
            id: "Flow(0)".to_string(),
            ordinal: "0".to_string(),
            protocol: "tcp".to_string(),
            endpoint_a: "192.168.1.1:1000".to_string(),
            endpoint_b: "192.168.1.2:80".to_string(),
            first_packet: "0".to_string(),
            last_packet: "10".to_string(),
            end_reason: "end_of_input".to_string(),
            traffic: FlowTrafficDto {
                total: FlowDirectionalTrafficDto {
                    packet_count: "10".to_string(),
                    captured_bytes: "1500".to_string(),
                    wire_bytes: "1500".to_string(),
                    truncated_packet_count: "0".to_string(),
                },
                a_to_b: FlowDirectionalTrafficDto {
                    packet_count: "6".to_string(),
                    captured_bytes: "900".to_string(),
                    wire_bytes: "900".to_string(),
                    truncated_packet_count: "0".to_string(),
                },
                b_to_a: FlowDirectionalTrafficDto {
                    packet_count: "4".to_string(),
                    captured_bytes: "600".to_string(),
                    wire_bytes: "600".to_string(),
                    truncated_packet_count: "0".to_string(),
                },
                same_endpoint: FlowDirectionalTrafficDto {
                    packet_count: "0".to_string(),
                    captured_bytes: "0".to_string(),
                    wire_bytes: "0".to_string(),
                    truncated_packet_count: "0".to_string(),
                },
            },
            temporal: FlowTemporalDto {
                status: "available".to_string(),
                unavailable_reason: None,
                duration: Some(DurationDto {
                    numerator: "15".to_string(),
                    denominator: "2".to_string(),
                    display: "15/2s".to_string(),
                }),
                timestamp_coverage: FlowTimestampCoverageDto {
                    available_timestamps: "10".to_string(),
                    unavailable_timestamps: "0".to_string(),
                    invalid_timestamps: "0".to_string(),
                    non_monotonic_transitions: "0".to_string(),
                },
                first_packet_timestamp: Some(PacketTimestampDto {
                    seconds: "1600000000".to_string(),
                    fractional_units: "500000".to_string(),
                    units_per_second: "1000000".to_string(),
                    offset_seconds: "0".to_string(),
                }),
                last_packet_timestamp: None,
                overall_inter_arrival: InterArrivalMetricsDto {
                    interval_sample_count: "9".to_string(),
                    discontinuity_count: "0".to_string(),
                    min_interval: Some(DurationDto {
                        numerator: "1".to_string(),
                        denominator: "2".to_string(),
                        display: "0.500000000s".to_string(),
                    }),
                    max_interval: None,
                    mean_interval: None,
                    successive_delta_sample_count: "8".to_string(),
                    mean_absolute_successive_interval_delta: None,
                },
                a_to_b_inter_arrival: InterArrivalMetricsDto {
                    interval_sample_count: "0".to_string(),
                    discontinuity_count: "0".to_string(),
                    min_interval: None,
                    max_interval: None,
                    mean_interval: None,
                    successive_delta_sample_count: "0".to_string(),
                    mean_absolute_successive_interval_delta: None,
                },
                b_to_a_inter_arrival: InterArrivalMetricsDto {
                    interval_sample_count: "0".to_string(),
                    discontinuity_count: "0".to_string(),
                    min_interval: None,
                    max_interval: None,
                    mean_interval: None,
                    successive_delta_sample_count: "0".to_string(),
                    mean_absolute_successive_interval_delta: None,
                },
                same_endpoint_inter_arrival: InterArrivalMetricsDto {
                    interval_sample_count: "0".to_string(),
                    discontinuity_count: "0".to_string(),
                    min_interval: None,
                    max_interval: None,
                    mean_interval: None,
                    successive_delta_sample_count: "0".to_string(),
                    mean_absolute_successive_interval_delta: None,
                },
            },
        }],
    };

    let json_val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();

    assert_eq!(json_val["total_flows"], "1");
    assert_eq!(json_val["flows"][0]["ordinal"], "0");
    assert_eq!(json_val["flows"][0]["protocol"], "tcp");
    assert_eq!(json_val["flows"][0]["end_reason"], "end_of_input");
    assert_eq!(
        json_val["flows"][0]["traffic"]["total"]["packet_count"],
        "10"
    );
    assert_eq!(
        json_val["flows"][0]["temporal"]["duration"]["numerator"],
        "15"
    );
    assert!(json_val["flows"][0]["temporal"]["unavailable_reason"].is_null());
    assert!(json_val["flows"][0]["temporal"]["last_packet_timestamp"].is_null());
    assert!(json_val["flows"][0]["temporal"]["overall_inter_arrival"]["max_interval"].is_null());
}

#[test]
fn test_findings_report_json_schema_contract() {
    let report = FindingsReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "findings",
        total_findings: "1".to_string(),
        total_evidence_records: "1".to_string(),
        filter: Some(FindingFilterDto {
            min_severity: Some("high".to_string()),
            min_confidence: None,
            detector_id: None,
            mitre_attack_id: None,
        }),
        findings: vec![FindingRecordDto {
            id: "find:0".to_string(),
            ordinal: "0".to_string(),
            detector_id: "dns.tunneling".to_string(),
            detector_version: "1.0.0".to_string(),
            title: "DNS Tunneling".to_string(),
            summary: "Summary".to_string(),
            rationale: "Rationale".to_string(),
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            subject: FindingSubjectDto {
                packets: vec!["0".to_string()],
                flows: vec!["Flow(0)".to_string()],
                observations: vec!["obs:0:dns:0".to_string()],
            },
            evidence_references: vec!["evi:0".to_string()],
            source_finding_references: vec![],
            mitre_mappings: vec![MitreMappingDto {
                domain: "enterprise".to_string(),
                catalog_version: "19.2".to_string(),
                technique_id: "T1071.004".to_string(),
                technique_name: "DNS".to_string(),
                technique_version: "1.4".to_string(),
                tactic_id: "TA0011".to_string(),
                tactic: "command_and_control".to_string(),
                relationship: "analytical".to_string(),
                rationale: "Rationale".to_string(),
                provenance: MitreMappingProvenanceDto {
                    kind: "detector".to_string(),
                    component_id: "dns.tunneling".to_string(),
                    component_version: "1.0.0".to_string(),
                },
            }],
        }],
        evidence: vec![EvidenceRecordDto {
            id: "evi:0".to_string(),
            kind: "RatioComparison".to_string(),
            description: "Diversity ratio".to_string(),
            packet_references: vec!["0".to_string()],
            flow_references: vec!["Flow(0)".to_string()],
            observation_references: vec!["obs:0:dns:0".to_string()],
            measurements: vec![EvidenceMeasurementDto {
                metric_key: "ratio".to_string(),
                observed_value: EvidenceValueDto::Ratio(RatioDto {
                    numerator: "85".to_string(),
                    denominator: "100".to_string(),
                    string_representation: "17/20".to_string(),
                }),
                threshold: Some(EvidenceValueDto::Ratio(RatioDto {
                    numerator: "75".to_string(),
                    denominator: "100".to_string(),
                    string_representation: "3/4".to_string(),
                })),
                comparison: Some(">".to_string()),
                unit: "ratio".to_string(),
            }],
            limitations: vec!["CaptureTruncated".to_string()],
        }],
    };

    let json_val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();

    assert_eq!(json_val["total_findings"], "1");
    assert_eq!(json_val["total_evidence_records"], "1");
    assert_eq!(json_val["filter"]["min_severity"], "high");
    assert!(json_val["filter"]["min_confidence"].is_null());
    assert_eq!(json_val["findings"][0]["severity"], "high");
    assert_eq!(json_val["findings"][0]["confidence"], "medium");
    assert_eq!(json_val["findings"][0]["subject"]["packets"][0], "0");
    assert_eq!(
        json_val["findings"][0]["source_finding_references"],
        serde_json::json!([])
    );
    assert_eq!(
        json_val["findings"][0]["mitre_mappings"][0]["domain"],
        "enterprise"
    );
    assert_eq!(
        json_val["findings"][0]["mitre_mappings"][0]["tactic"],
        "command_and_control"
    );
    assert_eq!(
        json_val["findings"][0]["mitre_mappings"][0]["provenance"]["kind"],
        "detector"
    );
    assert_eq!(
        json_val["evidence"][0]["measurements"][0]["observed_value"]["type"],
        "Ratio"
    );
    assert_eq!(
        json_val["evidence"][0]["measurements"][0]["observed_value"]["value"]["numerator"],
        "85"
    );
}

#[test]
fn test_analysis_report_json_schema_contract() {
    let report = AnalysisReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "analysis",
        metadata: ValidationMetadataDto::default(),
        summary: AnalysisSummaryDto {
            total_packets: "100".to_string(),
            total_flows: "1".to_string(),
            total_dns_observations: "1".to_string(),
            total_http_observations: "0".to_string(),
            total_tls_observations: "0".to_string(),
            total_findings: "0".to_string(),
            total_evidence_records: "0".to_string(),
        },
        completion: ReportCompletionDto {
            status: "partial".to_string(),
            limitations: vec!["flow_budget_reached".to_string()],
        },
        filter: None,
        flows: vec![],
        observations: vec![ProtocolObservationDto {
            id: "obs:0:dns:0".to_string(),
            protocol: "dns".to_string(),
            packet_reference: "0".to_string(),
            completeness: "complete".to_string(),
            association: ObservationFlowAssociationDto {
                status: "associated".to_string(),
                flow_reference: Some("Flow(0)".to_string()),
                direction: Some("a_to_b".to_string()),
                exclusion_reason: None,
            },
            data: ProtocolObservationDataDto {
                dns: Some(DnsObservationDto {
                    packet_ordinal: "0".to_string(),
                    transport: "udp".to_string(),
                    source_ip: "10.0.0.1".to_string(),
                    source_port: 53,
                    destination_ip: "10.0.0.2".to_string(),
                    destination_port: 53,
                    transaction_id: 1,
                    message_kind: "query".to_string(),
                    opcode: 0,
                    authoritative_answer: false,
                    truncation: false,
                    recursion_desired: true,
                    recursion_available: false,
                    response_code: 0,
                    questions: vec![],
                    answers: vec![],
                    authorities: vec![],
                    additionals: vec![],
                    edns: None,
                    completeness: "complete".to_string(),
                }),
                http: None,
                tls: None,
            },
        }],
        evidence: vec![],
        findings: vec![],
    };

    let json_val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();

    assert_eq!(json_val["schema_version"], "v1.0");
    assert_eq!(json_val["kind"], "analysis");
    assert_eq!(json_val["completion"]["status"], "partial");
    assert_eq!(
        json_val["completion"]["limitations"][0],
        "flow_budget_reached"
    );
    assert_eq!(json_val["observations"][0]["id"], "obs:0:dns:0");
    assert_eq!(json_val["observations"][0]["protocol"], "dns");
    assert_eq!(
        json_val["observations"][0]["association"]["status"],
        "associated"
    );
    assert_eq!(
        json_val["observations"][0]["association"]["direction"],
        "a_to_b"
    );
    assert!(json_val["observations"][0]["association"]["exclusion_reason"].is_null());
    assert!(json_val["observations"][0]["data"]["http"].is_null());
    assert!(json_val["observations"][0]["data"]["tls"].is_null());
}

fn schema_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("schema value must serialize")
}

fn assert_object_keys(value: &Value, expected: &[&str]) {
    let object = value.as_object().expect("schema value must be an object");
    let actual: BTreeSet<String> = object.keys().cloned().collect();
    let expected: BTreeSet<String> = expected.iter().map(|key| (*key).to_string()).collect();
    assert_eq!(actual, expected);
}

fn assert_exact_keys<T: serde::Serialize>(value: &T, expected: &[&str]) {
    let bytes = serde_json::to_vec(value).expect("schema value must serialize");
    let parsed: Value = serde_json::from_slice(&bytes).expect("schema value must be JSON");
    assert_object_keys(&parsed, expected);

    let actual_order = ordered_object_keys_from_bytes(&bytes);
    let expected_order: Vec<String> = expected.iter().map(|key| (*key).to_string()).collect();
    assert_eq!(
        actual_order, expected_order,
        "serialized object key order changed"
    );
}

fn ordered_object_keys_from_bytes(bytes: &[u8]) -> Vec<String> {
    struct ObjectKeysVisitor;

    impl<'de> Visitor<'de> for ObjectKeysVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut keys = Vec::new();
            while let Some(key) = access.next_key::<String>()? {
                keys.push(key);
                let _: IgnoredAny = access.next_value()?;
            }
            Ok(keys)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    deserializer
        .deserialize_map(ObjectKeysVisitor)
        .expect("serialized DTO must be a JSON object")
}

fn assert_exact_keys_from_bytes(bytes: &[u8], expected: &[&str]) -> Value {
    let value: Value = serde_json::from_slice(bytes).expect("serialized object must be JSON");
    assert_object_keys(&value, expected);
    let actual_order = ordered_object_keys_from_bytes(bytes);
    let expected_order: Vec<String> = expected.iter().map(|key| (*key).to_string()).collect();
    assert_eq!(
        actual_order, expected_order,
        "serialized object key order changed"
    );
    value
}

fn assert_string_fields(value: &Value, fields: &[&str]) {
    for field in fields {
        assert!(value[field].is_string(), "{field} must be a JSON string");
    }
}

fn assert_number_fields(value: &Value, fields: &[&str]) {
    for field in fields {
        assert!(value[field].is_number(), "{field} must be a JSON number");
    }
}

fn assert_boolean_fields(value: &Value, fields: &[&str]) {
    for field in fields {
        assert!(value[field].is_boolean(), "{field} must be a JSON boolean");
    }
}

fn assert_array_fields(value: &Value, fields: &[&str]) {
    for field in fields {
        assert!(value[field].is_array(), "{field} must be a JSON array");
    }
}

fn assert_nullable_fields(value: &Value, fields: &[&str]) {
    for field in fields {
        assert!(
            value[field].is_null(),
            "{field} must be null in this fixture"
        );
    }
}

fn assert_json_document(bytes: &[u8]) -> Value {
    assert!(!bytes.is_empty(), "JSON output must not be empty");
    assert!(
        !bytes.windows(3).any(|window| window == [0xef, 0xbb, 0xbf]),
        "JSON must not have a BOM"
    );
    assert!(!bytes.contains(&b'\r'), "JSON must use LF, not CRLF or CR");
    assert!(
        bytes.ends_with(b"\n"),
        "JSON must end with exactly an LF terminator"
    );
    assert!(
        !bytes[..bytes.len() - 1].ends_with(b"\n"),
        "JSON must have exactly one final LF terminator"
    );
    serde_json::from_slice(bytes).expect("JSON output must parse")
}

fn assert_json_document_with_keys(bytes: &[u8], expected: &[&str]) -> Value {
    let value = assert_json_document(bytes);
    assert_object_keys(&value, expected);
    let actual_order = ordered_object_keys_from_bytes(bytes);
    let expected_order: Vec<String> = expected.iter().map(|key| (*key).to_string()).collect();
    assert_eq!(
        actual_order, expected_order,
        "serialized object key order changed"
    );
    value
}

fn assert_ndjson_document(bytes: &[u8], kind: &str, record_types: &[&str]) -> Vec<Value> {
    assert!(!bytes.is_empty(), "NDJSON output must not be empty");
    assert!(
        !bytes.windows(3).any(|window| window == [0xef, 0xbb, 0xbf]),
        "NDJSON must not have a BOM"
    );
    assert!(
        !bytes.contains(&b'\r'),
        "NDJSON must use LF, not CRLF or CR"
    );
    assert!(bytes.ends_with(b"\n"), "NDJSON must end with an LF");
    let body = &bytes[..bytes.len() - 1];
    assert!(
        !body.ends_with(b"\n"),
        "NDJSON must have exactly one final LF terminator"
    );
    assert!(
        !body.windows(2).any(|pair| pair == b"\n\n"),
        "NDJSON must not contain blank lines"
    );
    let lines: Vec<&[u8]> = body.split(|byte| *byte == b'\n').collect();
    assert_eq!(lines.len(), record_types.len());
    let mut records = Vec::with_capacity(lines.len());
    for (line, expected_record_type) in lines.iter().zip(record_types) {
        assert!(!line.is_empty(), "NDJSON must not contain blank records");
        let value =
            assert_exact_keys_from_bytes(line, &["schema_version", "kind", "record_type", "data"]);
        assert_eq!(value["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(value["kind"], kind);
        assert_eq!(value["record_type"], *expected_record_type);
        assert!(value["data"].is_object(), "NDJSON data must be an object");
        records.push(value);
    }
    records
}

fn assert_csv_document(bytes: &[u8], expected_header: &[&str]) {
    assert!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "CSV must not have a BOM"
    );
    assert!(bytes.ends_with(b"\n"), "CSV must end with an LF");
    assert!(
        !bytes.contains(&b'\r'),
        "CSV must use strict LF line endings"
    );

    let mut reader = csv::ReaderBuilder::new().from_reader(bytes);
    let headers: Vec<&str> = reader
        .headers()
        .expect("CSV header must parse")
        .iter()
        .collect();
    assert_eq!(headers, expected_header);
    for record in reader.records() {
        let record = record.expect("CSV row must parse");
        assert_eq!(record.len(), expected_header.len());
    }
}

fn schema_validation_report() -> ValidationReportDto {
    ValidationReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "validation",
        source_path: None,
        metadata: ValidationMetadataDto {
            format: "pcap".to_string(),
            byte_order: "little_endian".to_string(),
            version_major: Some(2),
            version_minor: Some(4),
            linktype: Some(1),
            snaplen: Some(65_535),
            timestamp_resolution: Some("10^6 units/s (1000000 Hz)".to_string()),
            section_count: None,
            interface_count: None,
            usable_interfaces: None,
            unusable_interfaces: None,
        },
        summary: ValidationSummaryDto {
            records_emitted: "18446744073709551615".to_string(),
            total_diagnostics: "2".to_string(),
            had_diagnostics: true,
        },
        diagnostics: vec![
            ValidationDiagnosticDto {
                index: "0".to_string(),
                stage: "packet".to_string(),
                kind: "malformed".to_string(),
                message: "bounded malformed packet diagnostic".to_string(),
                byte_offset: Some("1024".to_string()),
            },
            ValidationDiagnosticDto {
                index: "1".to_string(),
                stage: "reader".to_string(),
                kind: "io".to_string(),
                message: "bounded reader diagnostic".to_string(),
                byte_offset: None,
            },
        ],
        completion: ValidationCompletionDto {
            status: "complete".to_string(),
            is_complete: true,
            terminal_error: None,
        },
    }
}

fn schema_flow() -> FlowRecord {
    let ep_a = FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 10]), 54_321);
    let ep_b = FlowEndpoint::new(IpAddress::Ipv4([93, 184, 216, 34]), 80);
    let key = FlowKey::new(TransportProtocol::Tcp, ep_a, ep_b);
    let reference = FlowReference::new(0);
    let pkt = PacketReference::new(0, None, None, 128, 128, false);
    let traffic = pcapraven_domain::FlowTrafficStatistics::new(
        FlowTrafficCounters::new(10, 1500, 1500, 0),
        FlowTrafficCounters::new(6, 900, 900, 0),
        FlowTrafficCounters::new(4, 600, 600, 0),
        FlowTrafficCounters::empty(),
    );
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Available(FlowDuration::from_fraction(15, 2).unwrap()),
        FlowTimestampCoverage::new(10, 0, 0, 0),
        FlowInterArrivalMetrics::new(
            9,
            0,
            FlowTemporalValue::Available(FlowDuration::from_fraction(1, 2).unwrap()),
            FlowTemporalValue::Available(FlowDuration::from_fraction(2, 1).unwrap()),
            FlowTemporalValue::Available(FlowDuration::from_fraction(5, 6).unwrap()),
            8,
            FlowTemporalValue::Available(FlowDuration::from_fraction(1, 4).unwrap()),
        ),
        FlowInterArrivalMetrics::new(
            5,
            0,
            FlowTemporalValue::Available(FlowDuration::from_fraction(1, 1).unwrap()),
            FlowTemporalValue::Available(FlowDuration::from_fraction(2, 1).unwrap()),
            FlowTemporalValue::Available(FlowDuration::from_fraction(5, 4).unwrap()),
            4,
            FlowTemporalValue::Available(FlowDuration::from_fraction(1, 4).unwrap()),
        ),
        FlowInterArrivalMetrics::new(
            3,
            0,
            FlowTemporalValue::Available(FlowDuration::from_fraction(1, 1).unwrap()),
            FlowTemporalValue::Available(FlowDuration::from_fraction(2, 1).unwrap()),
            FlowTemporalValue::Available(FlowDuration::from_fraction(4, 3).unwrap()),
            2,
            FlowTemporalValue::Available(FlowDuration::from_fraction(1, 4).unwrap()),
        ),
        FlowInterArrivalMetrics::new(
            0,
            0,
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples),
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples),
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples),
            0,
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples),
        ),
    );
    FlowRecord::new(
        reference,
        key,
        pkt,
        pkt,
        FlowEndReason::EndOfInput,
        traffic,
        temporal,
    )
}

fn schema_dns_observation() -> DnsObservation {
    let pkt_ref = PacketReference::new(0, None, None, 128, 128, false);
    let name = DnsName::from_labels(vec![b"example".to_vec(), b"com".to_vec()]).unwrap();
    let question = DnsQuestion::new(name.clone(), 1, 1);
    let answer = DnsResourceRecord {
        name,
        rtype: 1,
        rclass: 1,
        ttl: 300,
        rdlength: 4,
        rdata: DnsRdataMetadata::A([93, 184, 216, 34]),
        section: DnsSection::Answer,
    };
    DnsObservation {
        packet: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        transport: DnsTransport::Udp,
        source_ip: IpAddress::Ipv4([192, 168, 1, 10]),
        source_port: 54_321,
        destination_ip: IpAddress::Ipv4([8, 8, 8, 8]),
        destination_port: 53,
        transaction_id: 0x1234,
        message_kind: DnsMessageKind::Response,
        opcode: 0,
        response_code: 0,
        effective_response_code: 0,
        flags: DnsFlags::from_u16(0x8180),
        declared_qdcount: 1,
        declared_ancount: 1,
        declared_nscount: 0,
        declared_arcount: 0,
        questions: vec![question],
        records: vec![answer],
        edns: None,
        completeness: DnsObservationCompleteness::Complete,
    }
}

fn schema_dns_edns_observation() -> DnsObservation {
    let mut observation = schema_dns_observation();
    let edns = DnsEdnsMetadata {
        udp_payload_size: 1_232,
        extended_rcode: 1,
        version: 0,
        dnssec_ok: true,
        z: 0,
        options: vec![
            DnsEdnsOptionMetadata { code: 8, length: 4 },
            DnsEdnsOptionMetadata {
                code: 10,
                length: 0,
            },
        ],
    };
    observation.packet = PacketReference::new(3, None, None, 128, 128, false);
    observation.transport = DnsTransport::Tcp;
    observation.message_kind = DnsMessageKind::Query;
    observation.flags = DnsFlags::from_u16(0x0100);
    observation.response_code = 0;
    observation.effective_response_code = 0x100;
    observation.declared_ancount = 0;
    observation.declared_arcount = 1;
    observation.questions[0].qtype = 28;
    observation.edns = Some(edns.clone());
    observation.records = vec![DnsResourceRecord {
        name: DnsName::root(),
        rtype: 41,
        rclass: edns.udp_payload_size,
        ttl: u32::from(edns.extended_rcode) << 24,
        rdlength: 4,
        rdata: DnsRdataMetadata::Opt(edns),
        section: DnsSection::Additional,
    }];
    observation
}

fn schema_http_observation() -> pcapraven_domain::HttpObservation {
    let pkt_ref = PacketReference::new(0, None, None, 128, 128, false);
    pcapraven_domain::HttpObservation {
        packet: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        source_ip: IpAddress::Ipv4([192, 168, 1, 10]),
        source_port: 54_321,
        destination_ip: IpAddress::Ipv4([93, 184, 216, 34]),
        destination_port: 80,
        version: pcapraven_domain::HttpVersion::Http11,
        message_kind: pcapraven_domain::HttpMessageKind::Request,
        request: Some(pcapraven_domain::HttpRequestMetadata {
            method: pcapraven_domain::HttpByteString::new(b"GET".to_vec()),
            target: pcapraven_domain::HttpByteString::new(b"/index.html".to_vec()),
        }),
        response: None,
        headers: pcapraven_domain::HttpSelectedHeaders {
            host: Some(pcapraven_domain::HttpByteString::new(
                b"example.com".to_vec(),
            )),
            user_agent: Some(pcapraven_domain::HttpByteString::new(b"curl/8.0".to_vec())),
            server: None,
            content_type: None,
            content_length: pcapraven_domain::HttpContentLengthState::NotPresent,
            transfer_encoding: None,
            connection: None,
            upgrade: None,
            has_authorization: false,
            has_proxy_authorization: false,
            has_cookie: false,
            has_set_cookie: false,
        },
        framing: pcapraven_domain::HttpFramingMetadata::default(),
        declared_field_count: 2,
        header_section_bytes: 45,
        completeness: pcapraven_domain::HttpObservationCompleteness::Complete,
    }
}

fn schema_http_response_observation() -> pcapraven_domain::HttpObservation {
    let mut observation = schema_http_observation();
    observation.packet = PacketReference::new(1, None, None, 128, 128, false);
    observation.source_port = 80;
    observation.destination_port = 54_321;
    observation.version = pcapraven_domain::HttpVersion::Http10;
    observation.message_kind = HttpMessageKind::Response;
    observation.request = None;
    observation.response = Some(HttpResponseMetadata { status_code: 204 });
    observation.headers.host = None;
    observation.headers.user_agent = None;
    observation.headers.server = Some(pcapraven_domain::HttpByteString::from("example"));
    observation.headers.content_type = Some(pcapraven_domain::HttpByteString::from("text/plain"));
    observation.headers.content_length = pcapraven_domain::HttpContentLengthState::Present(42);
    observation.headers.transfer_encoding = Some(pcapraven_domain::HttpByteString::from("chunked"));
    observation.completeness = HttpObservationCompleteness::Partial {
        reason: "response body truncated",
    };
    observation
}

fn schema_tls_observation() -> pcapraven_domain::TlsObservation {
    let pkt_ref = PacketReference::new(0, None, None, 128, 128, false);
    pcapraven_domain::TlsObservation {
        packet: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        source_ip: IpAddress::Ipv4([192, 168, 1, 10]),
        source_port: 54_321,
        destination_ip: IpAddress::Ipv4([93, 184, 216, 34]),
        destination_port: 443,
        record_version: pcapraven_domain::TlsVersion::Tls12,
        handshake_kind: pcapraven_domain::TlsHandshakeKind::ClientHello,
        client_hello: Some(pcapraven_domain::TlsClientHelloMetadata {
            legacy_version: pcapraven_domain::TlsVersion::Tls12,
            session_id_length: 32,
            cipher_suites: vec![0x1301, 0x1302],
            compression_methods: vec![0],
            server_name: Some(pcapraven_domain::TlsByteString::new(
                b"example.com".to_vec(),
            )),
            supported_versions: vec![
                pcapraven_domain::TlsVersion::Tls13,
                pcapraven_domain::TlsVersion::Tls12,
            ],
            supported_groups: vec![0x001d],
            signature_algorithms: vec![0x0403],
            alpn_protocols: vec![
                pcapraven_domain::TlsByteString::new(b"h2".to_vec()),
                pcapraven_domain::TlsByteString::new(b"http/1.1".to_vec()),
            ],
            key_share_groups: vec![0x001d],
            has_pre_shared_key: false,
            has_early_data: false,
            extensions: vec![
                pcapraven_domain::TlsExtensionMetadata {
                    extension_type: 0,
                    declared_length: 16,
                },
                pcapraven_domain::TlsExtensionMetadata {
                    extension_type: 43,
                    declared_length: 5,
                },
            ],
        }),
        server_hello: None,
        declared_record_bytes: 512,
        declared_handshake_bytes: 507,
        completeness: pcapraven_domain::TlsObservationCompleteness::Complete,
    }
}

fn schema_tls_server_hello_observation() -> pcapraven_domain::TlsObservation {
    let mut observation = schema_tls_observation();
    observation.packet = PacketReference::new(2, None, None, 128, 128, false);
    observation.source_port = 443;
    observation.destination_port = 54_321;
    observation.record_version = pcapraven_domain::TlsVersion::Tls13;
    observation.handshake_kind = TlsHandshakeKind::ServerHello;
    observation.client_hello = None;
    observation.server_hello = Some(TlsServerHelloMetadata {
        legacy_version: pcapraven_domain::TlsVersion::Tls12,
        session_id_echo_length: 32,
        cipher_suite: 0x1301,
        compression_method: 0,
        selected_version: Some(pcapraven_domain::TlsVersion::Tls13),
        selected_group: Some(0x001d),
        selected_alpn: Some(pcapraven_domain::TlsByteString::new(b"h2".to_vec())),
        has_pre_shared_key: true,
        has_early_data: true,
        extensions: vec![
            pcapraven_domain::TlsExtensionMetadata {
                extension_type: 43,
                declared_length: 2,
            },
            pcapraven_domain::TlsExtensionMetadata {
                extension_type: 51,
                declared_length: 2,
            },
        ],
    });
    observation.completeness = TlsObservationCompleteness::Complete;
    observation
}

fn schema_finding() -> (FindingRecord, EvidenceRecord) {
    schema_finding_at(0, 0, 0)
}

fn schema_finding_at(
    finding_id: u64,
    evidence_id: u64,
    flow_id: u64,
) -> (FindingRecord, EvidenceRecord) {
    schema_finding_at_with_levels(
        finding_id,
        evidence_id,
        flow_id,
        Severity::High,
        Confidence::Medium,
    )
}

fn schema_finding_at_with_levels(
    finding_id: u64,
    evidence_id: u64,
    flow_id: u64,
    severity: Severity,
    confidence: Confidence,
) -> (FindingRecord, EvidenceRecord) {
    let mut flow = schema_flow();
    flow.reference = FlowReference::new(flow_id);
    let subject = FindingSubject::try_new(
        vec![PacketReference::new(0, None, None, 128, 128, false)],
        vec![flow.reference],
        Vec::new(),
    )
    .unwrap();
    let title = FindingTitle::try_new("Possible DNS Tunneling Activity").unwrap();
    let summary = FindingSummary::try_new("High volume of suspicious subdomains").unwrap();
    let rationale = FindingRationale::try_new("Observed high query name diversity").unwrap();
    let description = EvidenceDescription::try_new("Query label diversity ratio exceeded").unwrap();
    let metric_key = EvidenceMetricKey::try_new("label_octet_diversity_ratio").unwrap();
    let ratio = EvidenceRatio::from_fraction(85, 100).unwrap();
    let threshold = EvidenceRatio::from_fraction(75, 100).unwrap();
    let measurement = EvidenceMeasurement::try_with_threshold(
        metric_key,
        EvidenceValue::Ratio(ratio),
        EvidenceValue::Ratio(threshold),
        EvidenceComparison::GreaterThan,
        EvidenceUnit::Ratio,
    )
    .unwrap();

    let mut evidence_builder =
        EvidenceDraftBuilder::new(EvidenceKind::RatioComparison, description);
    evidence_builder.add_measurement(measurement).unwrap();
    evidence_builder.add_flow_reference(flow.reference).unwrap();
    let evidence_draft = evidence_builder.build().unwrap();
    let evidence =
        EvidenceRecord::from_draft(EvidenceReference::new(evidence_id), evidence_draft.clone());

    let finding_draft = FindingDraft::try_new(
        subject,
        title,
        summary,
        rationale,
        severity,
        confidence,
        vec![evidence_draft],
    )
    .unwrap();
    let mitre_mapping = schema_mitre_mapping(
        MitreTactic::CommandAndControl,
        MitreMappingProvenance::DetectorDeclared {
            detector_id: pcapraven_domain::DetectorId::try_new("dns.possible_tunneling").unwrap(),
            detector_version: pcapraven_domain::DetectorVersion::new(1, 1, 1),
        },
    );
    let finding = FindingRecord::try_new(
        pcapraven_domain::FindingReference::new(finding_id),
        pcapraven_domain::DetectorId::try_new("dns.possible_tunneling").unwrap(),
        pcapraven_domain::DetectorVersion::new(1, 1, 1),
        finding_draft.subject().clone(),
        finding_draft.title().clone(),
        finding_draft.summary().clone(),
        finding_draft.rationale().clone(),
        finding_draft.severity(),
        finding_draft.confidence(),
        vec![evidence.reference()],
        Vec::new(),
        vec![mitre_mapping],
    )
    .unwrap();
    (finding, evidence)
}

fn schema_mitre_mapping(tactic: MitreTactic, provenance: MitreMappingProvenance) -> MitreMapping {
    let mitre_id = MitreAttackId::try_new("T1071.004").unwrap();
    let mitre_declaration = MitreMappingDeclaration::try_new(
        MitreAttackDomain::Enterprise,
        MitreAttackCatalogVersion::new(19, 2),
        mitre_id,
        "Application Layer Protocol: DNS",
        MitreAttackObjectVersion::new(1, 4),
        tactic,
        MitreAttackRelationship::Analytical,
        MitreMappingRationale::try_new("High diversity DNS tunneling behavior").unwrap(),
    )
    .unwrap();
    MitreMapping::from_declaration(&mitre_declaration, provenance)
}

fn schema_evidence_with_measurement(
    id: u64,
    kind: EvidenceKind,
    measurement: EvidenceMeasurement,
    limitation: Option<EvidenceLimitation>,
) -> EvidenceRecord {
    let description = EvidenceDescription::try_new("schema contract evidence").unwrap();
    let mut builder = EvidenceRecord::builder(EvidenceReference::new(id), kind, description);
    builder.add_measurement(measurement).unwrap();
    if let Some(limitation) = limitation {
        builder.add_limitation(limitation).unwrap();
    }
    builder.build().unwrap()
}

fn schema_analysis_report(
    flow: &FlowRecord,
    dns: &DnsObservation,
    finding: &FindingRecord,
    evidence: &EvidenceRecord,
) -> AnalysisReportDto {
    AnalysisReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "analysis",
        metadata: schema_validation_report().metadata,
        summary: AnalysisSummaryDto {
            total_packets: "1".to_string(),
            total_flows: "1".to_string(),
            total_dns_observations: "1".to_string(),
            total_http_observations: "0".to_string(),
            total_tls_observations: "0".to_string(),
            total_findings: "1".to_string(),
            total_evidence_records: "1".to_string(),
        },
        completion: ReportCompletionDto {
            status: "complete".to_string(),
            limitations: Vec::new(),
        },
        filter: None,
        flows: vec![FlowRecordDto::from_domain(flow)],
        observations: vec![ProtocolObservationDto {
            id: "obs:0:dns:0".to_string(),
            protocol: "dns".to_string(),
            packet_reference: "0".to_string(),
            completeness: "complete".to_string(),
            association: ObservationFlowAssociationDto {
                status: "associated".to_string(),
                flow_reference: Some(flow.reference.to_string()),
                direction: Some("a_to_b".to_string()),
                exclusion_reason: None,
            },
            data: ProtocolObservationDataDto {
                dns: Some(DnsObservationDto::from_domain(dns)),
                http: None,
                tls: None,
            },
        }],
        evidence: vec![EvidenceRecordDto::from_domain(evidence)],
        findings: vec![FindingRecordDto::from_domain(finding)],
    }
}

fn schema_protocol_observations() -> Vec<ProtocolObservation> {
    let dns = schema_dns_observation();
    let http = schema_http_response_observation();
    let tls = schema_tls_server_hello_observation();
    let excluded_dns = schema_dns_edns_observation();
    let mut unassociated_http = schema_http_observation();
    unassociated_http.packet = PacketReference::new(4, None, None, 128, 128, false);

    vec![
        ProtocolObservation::try_new(
            ObservationReference::new(0, ProtocolKind::Dns, 0),
            ObservationFlowAssociation::Associated {
                flow: FlowReference::new(0),
                direction: FlowDirection::AToB,
            },
            ProtocolObservationData::Dns(dns),
        )
        .unwrap(),
        ProtocolObservation::try_new(
            ObservationReference::new(1, ProtocolKind::Http, 0),
            ObservationFlowAssociation::Associated {
                flow: FlowReference::new(1),
                direction: FlowDirection::BToA,
            },
            ProtocolObservationData::Http(http),
        )
        .unwrap(),
        ProtocolObservation::try_new(
            ObservationReference::new(2, ProtocolKind::Tls, 0),
            ObservationFlowAssociation::Associated {
                flow: FlowReference::new(2),
                direction: FlowDirection::SameEndpoint,
            },
            ProtocolObservationData::Tls(tls),
        )
        .unwrap(),
        ProtocolObservation::try_new(
            ObservationReference::new(3, ProtocolKind::Dns, 0),
            ObservationFlowAssociation::Excluded(FlowExclusionReason::MissingTransportLayer),
            ProtocolObservationData::Dns(excluded_dns),
        )
        .unwrap(),
        ProtocolObservation::try_new(
            ObservationReference::new(4, ProtocolKind::Http, 0),
            ObservationFlowAssociation::Unassociated,
            ProtocolObservationData::Http(unassociated_http),
        )
        .unwrap(),
    ]
}

fn schema_analysis_report_from_domains(
    flows: &[FlowRecord],
    observations: &[ProtocolObservation],
    findings: &[FindingRecord],
    evidence: &[EvidenceRecord],
) -> AnalysisReportDto {
    AnalysisReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "analysis",
        metadata: schema_validation_report().metadata,
        summary: AnalysisSummaryDto {
            total_packets: observations.len().to_string(),
            total_flows: flows.len().to_string(),
            total_dns_observations: observations
                .iter()
                .filter(|observation| observation.protocol_kind() == ProtocolKind::Dns)
                .count()
                .to_string(),
            total_http_observations: observations
                .iter()
                .filter(|observation| observation.protocol_kind() == ProtocolKind::Http)
                .count()
                .to_string(),
            total_tls_observations: observations
                .iter()
                .filter(|observation| observation.protocol_kind() == ProtocolKind::Tls)
                .count()
                .to_string(),
            total_findings: findings.len().to_string(),
            total_evidence_records: evidence.len().to_string(),
        },
        completion: ReportCompletionDto {
            status: "partial".to_string(),
            limitations: vec![
                "capture_truncated".to_string(),
                "packet_count_budget_reached".to_string(),
                "flow_budget_reached".to_string(),
                "observation_budget_reached".to_string(),
            ],
        },
        filter: None,
        flows: flows.iter().map(FlowRecordDto::from_domain).collect(),
        observations: observations
            .iter()
            .map(ProtocolObservationDto::from_domain)
            .collect(),
        evidence: evidence
            .iter()
            .map(EvidenceRecordDto::from_domain)
            .collect(),
        findings: findings.iter().map(FindingRecordDto::from_domain).collect(),
    }
}

#[test]
fn test_all_dto_shapes_and_actual_conversion_domains() {
    let validation_dto = schema_validation_report();
    let validation = schema_json(&validation_dto);
    assert_exact_keys(
        &validation_dto,
        &[
            "schema_version",
            "kind",
            "source_path",
            "metadata",
            "summary",
            "diagnostics",
            "completion",
        ],
    );
    assert_exact_keys(
        &validation_dto.metadata,
        &[
            "format",
            "byte_order",
            "version_major",
            "version_minor",
            "linktype",
            "snaplen",
            "timestamp_resolution",
            "section_count",
            "interface_count",
            "usable_interfaces",
            "unusable_interfaces",
        ],
    );
    assert_string_fields(
        &validation["metadata"],
        &["format", "byte_order", "timestamp_resolution"],
    );
    assert_number_fields(
        &validation["metadata"],
        &["version_major", "version_minor", "linktype", "snaplen"],
    );
    assert_nullable_fields(
        &validation["metadata"],
        &[
            "section_count",
            "interface_count",
            "usable_interfaces",
            "unusable_interfaces",
        ],
    );
    assert_exact_keys(
        &validation_dto.summary,
        &["records_emitted", "total_diagnostics", "had_diagnostics"],
    );
    assert_string_fields(
        &validation["summary"],
        &["records_emitted", "total_diagnostics"],
    );
    assert_boolean_fields(&validation["summary"], &["had_diagnostics"]);
    assert_exact_keys(
        &validation_dto.diagnostics[0],
        &["index", "stage", "kind", "message", "byte_offset"],
    );
    assert_string_fields(
        &validation["diagnostics"][0],
        &["index", "stage", "kind", "message", "byte_offset"],
    );
    assert_exact_keys(
        &validation_dto.completion,
        &["status", "is_complete", "terminal_error"],
    );
    assert_string_fields(&validation["completion"], &["status"]);
    assert_boolean_fields(&validation["completion"], &["is_complete"]);
    assert!(validation["source_path"].is_null());
    assert!(validation["completion"]["terminal_error"].is_null());

    let flow = schema_flow();
    let flows_dto = FlowsReportDto::from_domain_flows(std::slice::from_ref(&flow));
    let flows = schema_json(&flows_dto);
    assert_exact_keys(
        &flows_dto,
        &["schema_version", "kind", "total_flows", "flows"],
    );
    assert_string_fields(&flows, &["schema_version", "kind", "total_flows"]);
    let flow = &flows["flows"][0];
    let flow_dto = &flows_dto.flows[0];
    assert_exact_keys(
        flow_dto,
        &[
            "id",
            "ordinal",
            "protocol",
            "endpoint_a",
            "endpoint_b",
            "first_packet",
            "last_packet",
            "end_reason",
            "traffic",
            "temporal",
        ],
    );
    assert_string_fields(
        flow,
        &[
            "id",
            "ordinal",
            "protocol",
            "endpoint_a",
            "endpoint_b",
            "first_packet",
            "last_packet",
            "end_reason",
        ],
    );
    assert_eq!(flow["id"], "Flow(0)");
    assert_eq!(flow["ordinal"], "0");
    assert_exact_keys(
        &flow_dto.traffic,
        &["total", "a_to_b", "b_to_a", "same_endpoint"],
    );
    for bucket in ["total", "a_to_b", "b_to_a", "same_endpoint"] {
        assert_exact_keys(
            match bucket {
                "total" => &flow_dto.traffic.total,
                "a_to_b" => &flow_dto.traffic.a_to_b,
                "b_to_a" => &flow_dto.traffic.b_to_a,
                "same_endpoint" => &flow_dto.traffic.same_endpoint,
                _ => unreachable!("schema traffic bucket is fixed"),
            },
            &[
                "packet_count",
                "captured_bytes",
                "wire_bytes",
                "truncated_packet_count",
            ],
        );
        assert_string_fields(
            &flow["traffic"][bucket],
            &[
                "packet_count",
                "captured_bytes",
                "wire_bytes",
                "truncated_packet_count",
            ],
        );
    }
    assert_exact_keys(
        &flow_dto.temporal,
        &[
            "status",
            "unavailable_reason",
            "duration",
            "timestamp_coverage",
            "first_packet_timestamp",
            "last_packet_timestamp",
            "overall_inter_arrival",
            "a_to_b_inter_arrival",
            "b_to_a_inter_arrival",
            "same_endpoint_inter_arrival",
        ],
    );
    assert_string_fields(&flow["temporal"], &["status"]);
    assert_exact_keys(
        flow_dto
            .temporal
            .duration
            .as_ref()
            .expect("schema flow has a duration"),
        &["numerator", "denominator", "display"],
    );
    assert_string_fields(
        &flow["temporal"]["duration"],
        &["numerator", "denominator", "display"],
    );
    assert_eq!(flow["temporal"]["duration"]["display"], "15/2s");
    assert!(flow["temporal"]["first_packet_timestamp"].is_null());
    assert!(flow["temporal"]["last_packet_timestamp"].is_null());
    let timestamp_dto = PacketTimestampDto::from_domain(&PacketTimestamp::Available {
        seconds: -1,
        fractional_units: 500_000,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 6,
            units_per_second: 1_000_000,
        },
        offset_seconds: -18_000,
    })
    .expect("schema packet timestamp is available");
    let timestamp = schema_json(&timestamp_dto);
    assert_exact_keys(
        &timestamp_dto,
        &[
            "seconds",
            "fractional_units",
            "units_per_second",
            "offset_seconds",
        ],
    );
    assert_string_fields(
        &timestamp,
        &[
            "seconds",
            "fractional_units",
            "units_per_second",
            "offset_seconds",
        ],
    );
    assert_eq!(timestamp["seconds"], "-1");
    assert_eq!(timestamp["fractional_units"], "500000");
    assert_eq!(timestamp["units_per_second"], "1000000");
    assert_eq!(timestamp["offset_seconds"], "-18000");
    assert_exact_keys(
        &flow_dto.temporal.timestamp_coverage,
        &[
            "available_timestamps",
            "unavailable_timestamps",
            "invalid_timestamps",
            "non_monotonic_transitions",
        ],
    );
    assert_string_fields(
        &flow["temporal"]["timestamp_coverage"],
        &[
            "available_timestamps",
            "unavailable_timestamps",
            "invalid_timestamps",
            "non_monotonic_transitions",
        ],
    );
    assert_exact_keys(
        &flow_dto.temporal.overall_inter_arrival,
        &[
            "interval_sample_count",
            "discontinuity_count",
            "min_interval",
            "max_interval",
            "mean_interval",
            "successive_delta_sample_count",
            "mean_absolute_successive_interval_delta",
        ],
    );
    assert_string_fields(
        &flow["temporal"]["overall_inter_arrival"],
        &[
            "interval_sample_count",
            "discontinuity_count",
            "successive_delta_sample_count",
        ],
    );

    let dns_domain = schema_dns_observation();
    let dns_dto = DnsReportDto::from_domain_observations(std::slice::from_ref(&dns_domain));
    let dns = schema_json(&dns_dto);
    assert_exact_keys(
        &dns_dto,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    let dns_observation = &dns["observations"][0];
    let dns_observation_dto = &dns_dto.observations[0];
    assert_exact_keys(
        dns_observation_dto,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "transaction_id",
            "message_kind",
            "opcode",
            "authoritative_answer",
            "truncation",
            "recursion_desired",
            "recursion_available",
            "response_code",
            "questions",
            "answers",
            "authorities",
            "additionals",
            "edns",
            "completeness",
        ],
    );
    assert_string_fields(
        dns_observation,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "destination_ip",
            "message_kind",
            "completeness",
        ],
    );
    assert_number_fields(
        dns_observation,
        &[
            "source_port",
            "destination_port",
            "transaction_id",
            "opcode",
            "response_code",
        ],
    );
    assert_boolean_fields(
        dns_observation,
        &[
            "authoritative_answer",
            "truncation",
            "recursion_desired",
            "recursion_available",
        ],
    );
    assert_array_fields(
        dns_observation,
        &["questions", "answers", "authorities", "additionals"],
    );
    assert!(dns_observation["edns"].is_null());
    assert_exact_keys(
        &dns_observation_dto.questions[0],
        &["name", "qtype", "qtype_name", "qclass"],
    );
    assert_string_fields(&dns_observation["questions"][0], &["name", "qtype_name"]);
    assert_number_fields(&dns_observation["questions"][0], &["qtype", "qclass"]);
    assert_exact_keys(
        &dns_observation_dto.answers[0],
        &["name", "rtype", "rclass", "ttl", "data"],
    );
    assert_string_fields(&dns_observation["answers"][0], &["name", "data"]);
    assert_number_fields(&dns_observation["answers"][0], &["rtype", "rclass", "ttl"]);

    let dns_edns_domain = schema_dns_edns_observation();
    let dns_edns_dto = DnsObservationDto::from_domain(&dns_edns_domain);
    let dns_edns = schema_json(&dns_edns_dto);
    assert_exact_keys(
        &dns_edns_dto,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "transaction_id",
            "message_kind",
            "opcode",
            "authoritative_answer",
            "truncation",
            "recursion_desired",
            "recursion_available",
            "response_code",
            "questions",
            "answers",
            "authorities",
            "additionals",
            "edns",
            "completeness",
        ],
    );
    assert_eq!(dns_edns["packet_ordinal"], "3");
    assert_eq!(dns_edns["transport"], "tcp");
    assert_eq!(dns_edns["message_kind"], "query");
    assert_eq!(dns_edns["response_code"], 256);
    assert_exact_keys(
        dns_edns_dto
            .edns
            .as_ref()
            .expect("schema EDNS metadata is present"),
        &[
            "udp_payload_size",
            "extended_rcode",
            "version",
            "dnssec_ok",
            "options",
        ],
    );
    assert_eq!(dns_edns["edns"]["udp_payload_size"], 1232);
    assert_eq!(dns_edns["edns"]["extended_rcode"], 1);
    assert_eq!(dns_edns["edns"]["version"], 0);
    assert_eq!(dns_edns["edns"]["dnssec_ok"], true);
    assert_eq!(dns_edns["edns"]["options"], serde_json::json!([8, 10]));
    assert_exact_keys(
        &dns_edns_dto.additionals[0],
        &["name", "rtype", "rclass", "ttl", "data"],
    );
    assert_eq!(dns_edns["additionals"][0]["rtype"], 41);
    assert_eq!(dns_edns["additionals"][0]["data"], "OPT udp=1232 do=true");

    let http_observation = schema_http_observation();
    let http_dto = HttpReportDto::from_domain_observations(std::slice::from_ref(&http_observation));
    let http = schema_json(&http_dto);
    assert_exact_keys(
        &http_dto,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    let http_observation = &http["observations"][0];
    let http_observation_dto = &http_dto.observations[0];
    assert_exact_keys(
        http_observation_dto,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "message_kind",
            "version",
            "request",
            "response",
            "headers",
            "completeness",
        ],
    );
    assert_string_fields(
        http_observation,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "destination_ip",
            "message_kind",
            "version",
            "completeness",
        ],
    );
    assert_number_fields(http_observation, &["source_port", "destination_port"]);
    assert_exact_keys(
        http_observation_dto
            .request
            .as_ref()
            .expect("schema request is present"),
        &["method", "target"],
    );
    assert_string_fields(&http_observation["request"], &["method", "target"]);
    assert!(http_observation["response"].is_null());
    assert_exact_keys(
        &http_observation_dto.headers,
        &[
            "host",
            "content_type",
            "content_length",
            "transfer_encoding",
            "server",
            "user_agent",
            "sensitive_headers",
        ],
    );
    assert_nullable_fields(
        &http_observation["headers"],
        &["content_type", "transfer_encoding", "server"],
    );
    assert_string_fields(
        &http_observation["headers"],
        &["host", "content_length", "user_agent"],
    );
    assert_exact_keys(
        &http_observation_dto.headers.sensitive_headers,
        &[
            "authorization_present",
            "cookie_present",
            "set_cookie_present",
            "proxy_authorization_present",
        ],
    );
    assert_boolean_fields(
        &http_observation["headers"]["sensitive_headers"],
        &[
            "authorization_present",
            "cookie_present",
            "set_cookie_present",
            "proxy_authorization_present",
        ],
    );

    let http_response_domain = schema_http_response_observation();
    let http_response_dto = HttpObservationDto::from_domain(&http_response_domain);
    let http_response = schema_json(&http_response_dto);
    assert_exact_keys(
        &http_response_dto,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "message_kind",
            "version",
            "request",
            "response",
            "headers",
            "completeness",
        ],
    );
    assert_eq!(http_response["packet_ordinal"], "1");
    assert_eq!(http_response["message_kind"], "response");
    assert_eq!(http_response["version"], "HTTP/1.0");
    assert!(http_response["request"].is_null());
    assert_exact_keys(
        http_response_dto
            .response
            .as_ref()
            .expect("schema HTTP response metadata is present"),
        &["status_code"],
    );
    assert_eq!(http_response["response"]["status_code"], 204);
    assert_exact_keys(
        &http_response_dto.headers,
        &[
            "host",
            "content_type",
            "content_length",
            "transfer_encoding",
            "server",
            "user_agent",
            "sensitive_headers",
        ],
    );
    assert!(http_response["headers"]["host"].is_null());
    assert_eq!(http_response["headers"]["content_type"], "text/plain");
    assert_eq!(http_response["headers"]["content_length"], "42");
    assert_eq!(http_response["headers"]["transfer_encoding"], "chunked");
    assert_eq!(http_response["headers"]["server"], "example");
    assert!(http_response["headers"]["user_agent"].is_null());
    assert_eq!(http_response["completeness"], "partial");

    let tls_observation = schema_tls_observation();
    let tls_dto = TlsReportDto::from_domain_observations(std::slice::from_ref(&tls_observation));
    let tls = schema_json(&tls_dto);
    assert_exact_keys(
        &tls_dto,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    let tls_observation = &tls["observations"][0];
    let tls_observation_dto = &tls_dto.observations[0];
    assert_exact_keys(
        tls_observation_dto,
        &[
            "packet_ordinal",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "record_version",
            "handshake_kind",
            "client_hello",
            "server_hello",
            "completeness",
        ],
    );
    assert_string_fields(
        tls_observation,
        &[
            "packet_ordinal",
            "source_ip",
            "destination_ip",
            "record_version",
            "handshake_kind",
            "completeness",
        ],
    );
    assert_number_fields(tls_observation, &["source_port", "destination_port"]);
    assert_exact_keys(
        tls_observation_dto
            .client_hello
            .as_ref()
            .expect("schema client hello is present"),
        &[
            "client_version",
            "server_name",
            "supported_versions",
            "alpn_protocols",
            "cipher_suites",
            "extensions",
        ],
    );
    assert_string_fields(&tls_observation["client_hello"], &["client_version"]);
    assert_array_fields(
        &tls_observation["client_hello"],
        &[
            "supported_versions",
            "alpn_protocols",
            "cipher_suites",
            "extensions",
        ],
    );
    assert!(tls_observation["server_hello"].is_null());
    assert_exact_keys(
        &tls_observation_dto
            .client_hello
            .as_ref()
            .expect("schema client hello is present")
            .extensions[0],
        &["extension_type", "length"],
    );
    assert_number_fields(
        &tls_observation["client_hello"]["extensions"][0],
        &["extension_type", "length"],
    );

    let tls_server_domain = schema_tls_server_hello_observation();
    let tls_server_dto = TlsObservationDto::from_domain(&tls_server_domain);
    let tls_server = schema_json(&tls_server_dto);
    assert_exact_keys(
        &tls_server_dto,
        &[
            "packet_ordinal",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "record_version",
            "handshake_kind",
            "client_hello",
            "server_hello",
            "completeness",
        ],
    );
    assert_eq!(tls_server["packet_ordinal"], "2");
    assert_eq!(tls_server["record_version"], "TLS 1.3");
    assert_eq!(tls_server["handshake_kind"], "server_hello");
    assert!(tls_server["client_hello"].is_null());
    let tls_server_hello_dto = tls_server_dto
        .server_hello
        .as_ref()
        .expect("schema TLS ServerHello metadata is present");
    assert_exact_keys(
        tls_server_hello_dto,
        &[
            "server_version",
            "selected_version",
            "selected_cipher_suite",
            "selected_alpn",
            "extensions",
        ],
    );
    assert_eq!(tls_server["server_hello"]["server_version"], "TLS 1.2");
    assert_eq!(tls_server["server_hello"]["selected_version"], "TLS 1.3");
    assert_eq!(
        tls_server["server_hello"]["selected_cipher_suite"],
        "0x1301"
    );
    assert_eq!(tls_server["server_hello"]["selected_alpn"], "h2");
    assert_exact_keys(
        &tls_server_hello_dto.extensions[0],
        &["extension_type", "length"],
    );
    assert_eq!(
        tls_server["server_hello"]["extensions"][0]["extension_type"],
        43
    );
    assert_eq!(
        tls_server["server_hello"]["extensions"][1]["extension_type"],
        51
    );

    let protocol_observations = schema_protocol_observations();
    let protocol_dtos: Vec<ProtocolObservationDto> = protocol_observations
        .iter()
        .map(ProtocolObservationDto::from_domain)
        .collect();
    assert_eq!(protocol_dtos.len(), 5);
    for observation_dto in &protocol_dtos {
        assert_exact_keys(
            observation_dto,
            &[
                "id",
                "protocol",
                "packet_reference",
                "completeness",
                "association",
                "data",
            ],
        );
        assert_exact_keys(
            &observation_dto.association,
            &["status", "flow_reference", "direction", "exclusion_reason"],
        );
        assert_exact_keys(&observation_dto.data, &["dns", "http", "tls"]);
    }
    assert_eq!(protocol_dtos[0].association.status, "associated");
    assert_eq!(
        protocol_dtos[0].association.direction.as_deref(),
        Some("a_to_b")
    );
    assert!(protocol_dtos[0].data.dns.is_some());
    assert!(protocol_dtos[0].data.http.is_none());
    assert!(protocol_dtos[0].data.tls.is_none());
    assert_eq!(
        protocol_dtos[1].association.direction.as_deref(),
        Some("b_to_a")
    );
    assert_eq!(protocol_dtos[1].protocol, "http");
    let protocol_http = protocol_dtos[1]
        .data
        .http
        .as_ref()
        .expect("schema protocol HTTP data is present");
    assert!(protocol_http.request.is_none());
    assert_eq!(
        protocol_http
            .response
            .as_ref()
            .expect("schema protocol HTTP response is present")
            .status_code,
        204
    );
    assert_eq!(
        protocol_dtos[2].association.direction.as_deref(),
        Some("same_endpoint")
    );
    assert_eq!(protocol_dtos[2].protocol, "tls");
    let protocol_tls = protocol_dtos[2]
        .data
        .tls
        .as_ref()
        .expect("schema protocol TLS data is present");
    assert!(protocol_tls.client_hello.is_none());
    assert!(protocol_tls.server_hello.is_some());
    assert_eq!(protocol_dtos[3].association.status, "excluded");
    assert_eq!(
        protocol_dtos[3].association.exclusion_reason.as_deref(),
        Some("MissingTransportLayer")
    );
    assert!(protocol_dtos[3].association.flow_reference.is_none());
    assert!(protocol_dtos[3].data.dns.as_ref().unwrap().edns.is_some());
    assert_eq!(protocol_dtos[4].association.status, "unassociated");
    assert!(protocol_dtos[4].association.flow_reference.is_none());
    assert!(protocol_dtos[4].association.direction.is_none());
    assert!(protocol_dtos[4].association.exclusion_reason.is_none());
    assert!(protocol_dtos[4].data.http.is_some());
    assert!(protocol_dtos[4].data.dns.is_none());
    assert!(protocol_dtos[4].data.tls.is_none());

    let (finding_domain, evidence_domain) = schema_finding();
    let findings_dto = FindingsReportDto::from_domain_findings(
        &[&finding_domain],
        &[&evidence_domain],
        Some(FindingFilterDto {
            min_severity: Some("medium".to_string()),
            min_confidence: Some("high".to_string()),
            detector_id: Some("dns.possible_tunneling".to_string()),
            mitre_attack_id: Some("T1071.004".to_string()),
        }),
    );
    let findings = schema_json(&findings_dto);
    assert_exact_keys(
        &findings_dto,
        &[
            "schema_version",
            "kind",
            "total_findings",
            "total_evidence_records",
            "filter",
            "findings",
            "evidence",
        ],
    );
    let filter_dto = findings_dto
        .filter
        .as_ref()
        .expect("schema findings filter is present");
    assert_exact_keys(
        filter_dto,
        &[
            "min_severity",
            "min_confidence",
            "detector_id",
            "mitre_attack_id",
        ],
    );
    assert_string_fields(
        &findings["filter"],
        &[
            "min_severity",
            "min_confidence",
            "detector_id",
            "mitre_attack_id",
        ],
    );
    assert_eq!(findings["filter"]["min_severity"], "medium");
    assert_eq!(findings["filter"]["min_confidence"], "high");
    assert_eq!(findings["filter"]["detector_id"], "dns.possible_tunneling");
    assert_eq!(findings["filter"]["mitre_attack_id"], "T1071.004");
    let unfiltered_findings = schema_json(&FindingsReportDto::from_domain_findings(
        &[&finding_domain],
        &[&evidence_domain],
        None,
    ));
    assert!(unfiltered_findings["filter"].is_null());
    let finding = &findings["findings"][0];
    let finding_dto = &findings_dto.findings[0];
    assert_exact_keys(
        finding_dto,
        &[
            "id",
            "ordinal",
            "detector_id",
            "detector_version",
            "title",
            "summary",
            "rationale",
            "severity",
            "confidence",
            "subject",
            "evidence_references",
            "source_finding_references",
            "mitre_mappings",
        ],
    );
    assert_string_fields(
        finding,
        &[
            "id",
            "ordinal",
            "detector_id",
            "detector_version",
            "title",
            "summary",
            "rationale",
            "severity",
            "confidence",
        ],
    );
    assert_eq!(finding["id"], "find:0");
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["confidence"], "medium");
    assert_exact_keys(&finding_dto.subject, &["packets", "flows", "observations"]);
    assert_array_fields(&finding["subject"], &["packets", "flows", "observations"]);
    assert_eq!(finding["subject"]["flows"][0], "Flow(0)");
    assert_array_fields(
        finding,
        &[
            "evidence_references",
            "source_finding_references",
            "mitre_mappings",
        ],
    );
    assert_exact_keys(
        &finding_dto.mitre_mappings[0],
        &[
            "domain",
            "catalog_version",
            "technique_id",
            "technique_name",
            "technique_version",
            "tactic_id",
            "tactic",
            "relationship",
            "rationale",
            "provenance",
        ],
    );
    assert_exact_keys(
        &finding_dto.mitre_mappings[0].provenance,
        &["kind", "component_id", "component_version"],
    );
    assert_eq!(
        finding["mitre_mappings"][0]["tactic"],
        "command_and_control"
    );
    let evidence = &findings["evidence"][0];
    let evidence_dto = &findings_dto.evidence[0];
    assert_exact_keys(
        evidence_dto,
        &[
            "id",
            "kind",
            "description",
            "packet_references",
            "flow_references",
            "observation_references",
            "measurements",
            "limitations",
        ],
    );
    assert_string_fields(evidence, &["id", "kind", "description"]);
    assert_array_fields(
        evidence,
        &[
            "packet_references",
            "flow_references",
            "observation_references",
            "measurements",
            "limitations",
        ],
    );
    assert_eq!(evidence["kind"], "RatioComparison");
    let measurement = &evidence["measurements"][0];
    let measurement_dto = &evidence_dto.measurements[0];
    assert_exact_keys(
        measurement_dto,
        &[
            "metric_key",
            "observed_value",
            "threshold",
            "comparison",
            "unit",
        ],
    );
    assert_string_fields(measurement, &["metric_key", "comparison", "unit"]);
    assert_eq!(measurement["metric_key"], "label_octet_diversity_ratio");
    assert_eq!(measurement["comparison"], ">");
    assert_eq!(measurement["observed_value"]["type"], "Ratio");
    assert_exact_keys(&measurement_dto.observed_value, &["type", "value"]);
    if let EvidenceValueDto::Ratio(ratio) = &measurement_dto.observed_value {
        assert_exact_keys(
            ratio,
            &["numerator", "denominator", "string_representation"],
        );
    } else {
        panic!("schema finding measurement must use a ratio");
    }
    assert_object_keys(
        &measurement["observed_value"]["value"],
        &["numerator", "denominator", "string_representation"],
    );
    assert_eq!(
        measurement["observed_value"]["value"]["string_representation"],
        "17/20"
    );

    let analysis_flow = schema_flow();
    let analysis_dns = schema_dns_observation();
    let (analysis_finding, analysis_evidence) = schema_finding();
    let analysis_dto = schema_analysis_report(
        &analysis_flow,
        &analysis_dns,
        &analysis_finding,
        &analysis_evidence,
    );
    let analysis = schema_json(&analysis_dto);
    assert_exact_keys(
        &analysis_dto,
        &[
            "schema_version",
            "kind",
            "metadata",
            "summary",
            "completion",
            "filter",
            "flows",
            "observations",
            "evidence",
            "findings",
        ],
    );
    assert_exact_keys(
        &analysis_dto.summary,
        &[
            "total_packets",
            "total_flows",
            "total_dns_observations",
            "total_http_observations",
            "total_tls_observations",
            "total_findings",
            "total_evidence_records",
        ],
    );
    assert_string_fields(
        &analysis["summary"],
        &[
            "total_packets",
            "total_flows",
            "total_dns_observations",
            "total_http_observations",
            "total_tls_observations",
            "total_findings",
            "total_evidence_records",
        ],
    );
    assert_exact_keys(&analysis_dto.completion, &["status", "limitations"]);
    assert_string_fields(&analysis["completion"], &["status"]);
    assert_array_fields(&analysis["completion"], &["limitations"]);
    assert!(analysis["filter"].is_null());
    let observation = &analysis["observations"][0];
    let observation_dto = &analysis_dto.observations[0];
    assert_exact_keys(
        observation_dto,
        &[
            "id",
            "protocol",
            "packet_reference",
            "completeness",
            "association",
            "data",
        ],
    );
    assert_string_fields(
        observation,
        &["id", "protocol", "packet_reference", "completeness"],
    );
    assert_exact_keys(
        &observation_dto.association,
        &["status", "flow_reference", "direction", "exclusion_reason"],
    );
    assert_string_fields(
        &observation["association"],
        &["status", "flow_reference", "direction"],
    );
    assert!(observation["association"]["exclusion_reason"].is_null());
    assert_exact_keys(&observation_dto.data, &["dns", "http", "tls"]);
    assert_exact_keys(
        observation_dto
            .data
            .dns
            .as_ref()
            .expect("schema analysis DNS data is present"),
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "transaction_id",
            "message_kind",
            "opcode",
            "authoritative_answer",
            "truncation",
            "recursion_desired",
            "recursion_available",
            "response_code",
            "questions",
            "answers",
            "authorities",
            "additionals",
            "edns",
            "completeness",
        ],
    );
    assert!(observation["data"]["dns"].is_object());
    assert!(observation["data"]["http"].is_null());
    assert!(observation["data"]["tls"].is_null());
}

#[test]
fn test_token_registries_boundaries_and_nullable_empty_values() {
    assert_eq!(
        [
            ReportKind::Validation.as_str(),
            ReportKind::Flows.as_str(),
            ReportKind::Dns.as_str(),
            ReportKind::Http.as_str(),
            ReportKind::Tls.as_str(),
            ReportKind::Findings.as_str(),
            ReportKind::Analysis.as_str(),
        ],
        [
            "validation",
            "flows",
            "dns",
            "http",
            "tls",
            "findings",
            "analysis"
        ]
    );

    let stages = ["format", "header", "block", "interface", "packet", "reader"];
    let kinds = [
        "unsupported",
        "malformed",
        "incomplete",
        "invalid_reference",
        "resource_limit",
        "io",
        "internal",
    ];
    let mut diagnostics = Vec::new();
    for stage in stages {
        for kind in kinds {
            diagnostics.push(ValidationDiagnosticDto {
                index: diagnostics.len().to_string(),
                stage: stage.to_string(),
                kind: kind.to_string(),
                message: "diagnostic".to_string(),
                byte_offset: None,
            });
        }
    }
    let report = ValidationReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "validation",
        source_path: None,
        metadata: ValidationMetadataDto {
            format: "pcapng".to_string(),
            byte_order: "big_endian".to_string(),
            ..ValidationMetadataDto::default()
        },
        summary: ValidationSummaryDto {
            records_emitted: "0".to_string(),
            total_diagnostics: diagnostics.len().to_string(),
            had_diagnostics: true,
        },
        diagnostics,
        completion: ValidationCompletionDto {
            status: "failed".to_string(),
            is_complete: false,
            terminal_error: Some("bounded terminal error".to_string()),
        },
    };
    let value = schema_json(&report);
    let actual_stages: BTreeSet<String> = value["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["stage"].as_str().unwrap().to_string())
        .collect();
    let actual_kinds: BTreeSet<String> = value["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["kind"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        actual_stages,
        stages.into_iter().map(str::to_string).collect()
    );
    assert_eq!(
        actual_kinds,
        kinds.into_iter().map(str::to_string).collect()
    );
    assert_eq!(value["summary"]["total_diagnostics"], "42");
    assert_eq!(value["metadata"]["format"], "pcapng");
    assert_eq!(value["metadata"]["byte_order"], "big_endian");
    assert_eq!(value["completion"]["status"], "failed");
    assert_eq!(value["completion"]["is_complete"], false);
    assert_eq!(
        value["completion"]["terminal_error"],
        "bounded terminal error"
    );
    assert!(value["diagnostics"][0]["byte_offset"].is_null());

    let flow = schema_flow();
    let flow_value = schema_json(&FlowRecordDto::from_domain(&flow));
    assert_eq!(flow_value["protocol"], "tcp");
    assert_eq!(flow_value["end_reason"], "end_of_input");
    assert_eq!(flow_value["temporal"]["status"], "available");

    for (end_reason, token) in [
        (FlowEndReason::EndOfInput, "end_of_input"),
        (FlowEndReason::IdleTimeout, "idle_timeout"),
        (FlowEndReason::TcpReset, "tcp_reset"),
        (FlowEndReason::TcpNewInitialSyn, "tcp_new_initial_syn"),
        (FlowEndReason::AnalysisStopped, "analysis_stopped"),
    ] {
        let mut flow = schema_flow();
        flow.end_reason = end_reason;
        let value = schema_json(&FlowRecordDto::from_domain(&flow));
        assert_eq!(value["end_reason"], token);
    }
    let mut udp_flow = schema_flow();
    udp_flow.key = FlowKey::new(
        TransportProtocol::Udp,
        udp_flow.key.endpoint_a(),
        udp_flow.key.endpoint_b(),
    );
    assert_eq!(
        schema_json(&FlowRecordDto::from_domain(&udp_flow))["protocol"],
        "udp"
    );
    for (reason, token) in [
        (
            FlowTemporalUnavailableReason::InsufficientSamples,
            "insufficient_samples",
        ),
        (
            FlowTemporalUnavailableReason::TimestampUnavailable,
            "timestamp_unavailable",
        ),
        (
            FlowTemporalUnavailableReason::InvalidTimestamp,
            "invalid_timestamp",
        ),
        (
            FlowTemporalUnavailableReason::NonMonotonicTimestamp,
            "non_monotonic_timestamp",
        ),
        (
            FlowTemporalUnavailableReason::ArithmeticOverflow,
            "arithmetic_overflow",
        ),
    ] {
        let mut flow = schema_flow();
        flow.temporal.duration = FlowTemporalValue::Unavailable(reason);
        let value = schema_json(&FlowRecordDto::from_domain(&flow));
        assert_eq!(value["temporal"]["status"], "unavailable");
        assert_eq!(value["temporal"]["unavailable_reason"], token);
        assert!(value["temporal"]["duration"].is_null());
    }

    for (association, status, direction, exclusion_reason) in [
        (
            ObservationFlowAssociation::Associated {
                flow: FlowReference::new(0),
                direction: FlowDirection::AToB,
            },
            "associated",
            Some("a_to_b"),
            None,
        ),
        (
            ObservationFlowAssociation::Associated {
                flow: FlowReference::new(0),
                direction: FlowDirection::BToA,
            },
            "associated",
            Some("b_to_a"),
            None,
        ),
        (
            ObservationFlowAssociation::Associated {
                flow: FlowReference::new(0),
                direction: FlowDirection::SameEndpoint,
            },
            "associated",
            Some("same_endpoint"),
            None,
        ),
        (
            ObservationFlowAssociation::Excluded(FlowExclusionReason::MissingNetworkLayer),
            "excluded",
            None,
            Some("MissingNetworkLayer"),
        ),
        (
            ObservationFlowAssociation::Excluded(FlowExclusionReason::MissingTransportLayer),
            "excluded",
            None,
            Some("MissingTransportLayer"),
        ),
        (
            ObservationFlowAssociation::Excluded(FlowExclusionReason::FragmentedWithoutTransport),
            "excluded",
            None,
            Some("FragmentedWithoutTransport"),
        ),
        (
            ObservationFlowAssociation::Excluded(FlowExclusionReason::UnsupportedTransport),
            "excluded",
            None,
            Some("UnsupportedTransport"),
        ),
        (
            ObservationFlowAssociation::Unassociated,
            "unassociated",
            None,
            None,
        ),
    ] {
        let value = schema_json(&ObservationFlowAssociationDto::from_domain(&association));
        assert_eq!(value["status"], status);
        assert_eq!(value["direction"].as_str(), direction);
        assert_eq!(value["exclusion_reason"].as_str(), exclusion_reason);
    }

    let dns = schema_json(&DnsObservationDto::from_domain(&schema_dns_observation()));
    assert_eq!(dns["transport"], "udp");
    assert_eq!(dns["message_kind"], "response");
    assert_eq!(dns["completeness"], "complete");

    let dns_query = schema_json(&DnsObservationDto::from_domain(
        &schema_dns_edns_observation(),
    ));
    assert_eq!(dns_query["transport"], "tcp");
    assert_eq!(dns_query["message_kind"], "query");
    assert_eq!(dns_query["completeness"], "complete");

    let http = schema_json(&HttpObservationDto::from_domain(&schema_http_observation()));
    assert_eq!(http["transport"], "tcp");
    assert_eq!(http["message_kind"], "request");
    assert_eq!(http["completeness"], "complete");

    let mut http_invalid_content_length = schema_http_observation();
    http_invalid_content_length.headers.content_length =
        pcapraven_domain::HttpContentLengthState::Invalid;
    let http_invalid_content_length = schema_json(&HttpObservationDto::from_domain(
        &http_invalid_content_length,
    ));
    assert_eq!(
        http_invalid_content_length["headers"]["content_length"],
        "invalid"
    );

    let http_response = schema_json(&HttpObservationDto::from_domain(
        &schema_http_response_observation(),
    ));
    assert_eq!(http_response["message_kind"], "response");
    assert_eq!(http_response["version"], "HTTP/1.0");
    assert_eq!(http_response["response"]["status_code"], 204);
    assert!(http_response["request"].is_null());
    assert_eq!(http_response["completeness"], "partial");

    let tls = schema_json(&TlsObservationDto::from_domain(&schema_tls_observation()));
    assert_eq!(tls["handshake_kind"], "client_hello");
    assert_eq!(tls["completeness"], "complete");
    assert_eq!(tls["client_hello"]["cipher_suites"][0], "0x1301");

    let tls_server = schema_json(&TlsObservationDto::from_domain(
        &schema_tls_server_hello_observation(),
    ));
    assert_eq!(tls_server["handshake_kind"], "server_hello");
    assert_eq!(tls_server["server_hello"]["selected_version"], "TLS 1.3");
    assert_eq!(tls_server["server_hello"]["selected_alpn"], "h2");
    assert!(tls_server["client_hello"].is_null());
    for (handshake_kind, token) in [
        (TlsHandshakeKind::ClientHello, "client_hello"),
        (TlsHandshakeKind::ServerHello, "server_hello"),
        (TlsHandshakeKind::HelloRetryRequest, "hello_retry_request"),
        (TlsHandshakeKind::Other(255), "other"),
    ] {
        let mut observation = schema_tls_observation();
        observation.handshake_kind = handshake_kind;
        let value = schema_json(&TlsObservationDto::from_domain(&observation));
        assert_eq!(value["handshake_kind"], token);
    }
    for (version, token) in [
        (TlsVersion::Ssl30, "SSLv3"),
        (TlsVersion::Tls10, "TLS 1.0"),
        (TlsVersion::Tls11, "TLS 1.1"),
        (TlsVersion::Tls12, "TLS 1.2"),
        (TlsVersion::Tls13, "TLS 1.3"),
        (TlsVersion::Unknown(0x1234), "Unknown"),
    ] {
        let mut observation = schema_tls_observation();
        observation.record_version = version;
        let value = schema_json(&TlsObservationDto::from_domain(&observation));
        assert_eq!(value["record_version"], token);
    }

    let (finding, evidence) = schema_finding();
    let finding_value = schema_json(&FindingRecordDto::from_domain(&finding));
    let evidence_value = schema_json(&EvidenceRecordDto::from_domain(&evidence));
    assert_eq!(finding_value["severity"], "high");
    assert_eq!(finding_value["confidence"], "medium");
    assert_eq!(finding_value["detector_version"], "v1.1.1");
    assert_eq!(evidence_value["kind"], "RatioComparison");
    assert_eq!(evidence_value["limitations"], serde_json::json!([]));
    assert_eq!(evidence_value["measurements"][0]["unit"], "ratio");
    assert_eq!(evidence_value["measurements"][0]["comparison"], ">");

    for (id, (kind, token)) in [
        (EvidenceKind::PacketMeasurement, "PacketMeasurement"),
        (EvidenceKind::FlowMeasurement, "FlowMeasurement"),
        (EvidenceKind::ProtocolObservation, "ProtocolObservation"),
        (EvidenceKind::TemporalMetric, "TemporalMetric"),
        (EvidenceKind::RatioComparison, "RatioComparison"),
        (EvidenceKind::ProtocolFact, "ProtocolFact"),
    ]
    .into_iter()
    .enumerate()
    {
        let measurement = EvidenceMeasurement::try_new(
            EvidenceMetricKey::try_new(format!("kind_{id}")).unwrap(),
            EvidenceValue::Unsigned(1),
            EvidenceUnit::Count,
        )
        .unwrap();
        let record = schema_evidence_with_measurement(id as u64 + 10, kind, measurement, None);
        let value = schema_json(&EvidenceRecordDto::from_domain(&record));
        assert_eq!(value["kind"], token);
        assert!(value["limitations"].as_array().unwrap().is_empty());
    }

    for (id, (comparison, token)) in [
        (EvidenceComparison::Equal, "=="),
        (EvidenceComparison::NotEqual, "!="),
        (EvidenceComparison::LessThan, "<"),
        (EvidenceComparison::LessThanOrEqual, "<="),
        (EvidenceComparison::GreaterThan, ">"),
        (EvidenceComparison::GreaterThanOrEqual, ">="),
    ]
    .into_iter()
    .enumerate()
    {
        let measurement = EvidenceMeasurement::try_with_threshold(
            EvidenceMetricKey::try_new(format!("comparison_{id}")).unwrap(),
            EvidenceValue::Ratio(EvidenceRatio::from_fraction(1, 2).unwrap()),
            EvidenceValue::Ratio(EvidenceRatio::from_fraction(1, 4).unwrap()),
            comparison,
            EvidenceUnit::Ratio,
        )
        .unwrap();
        let record = schema_evidence_with_measurement(
            id as u64 + 20,
            EvidenceKind::RatioComparison,
            measurement,
            None,
        );
        let value = schema_json(&EvidenceRecordDto::from_domain(&record));
        assert_eq!(value["measurements"][0]["comparison"], token);
    }

    for (id, (unit, value, token)) in [
        (EvidenceUnit::Bytes, EvidenceValue::Unsigned(8), "bytes"),
        (EvidenceUnit::Packets, EvidenceValue::Unsigned(2), "packets"),
        (EvidenceUnit::Nanoseconds, EvidenceValue::Unsigned(3), "ns"),
        (EvidenceUnit::Microseconds, EvidenceValue::Unsigned(4), "us"),
        (EvidenceUnit::Milliseconds, EvidenceValue::Unsigned(5), "ms"),
        (
            EvidenceUnit::Seconds,
            EvidenceValue::Duration(FlowDuration::from_secs(6)),
            "s",
        ),
        (
            EvidenceUnit::Ratio,
            EvidenceValue::Ratio(EvidenceRatio::from_fraction(1, 3).unwrap()),
            "ratio",
        ),
        (EvidenceUnit::Count, EvidenceValue::Boolean(true), "count"),
        (
            EvidenceUnit::PercentageInteger,
            EvidenceValue::Unsigned(50),
            "%",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let measurement = EvidenceMeasurement::try_new(
            EvidenceMetricKey::try_new(format!("unit_{id}")).unwrap(),
            value,
            unit,
        )
        .unwrap();
        let record = schema_evidence_with_measurement(
            id as u64 + 30,
            EvidenceKind::ProtocolFact,
            measurement,
            None,
        );
        let value = schema_json(&EvidenceRecordDto::from_domain(&record));
        assert_eq!(value["measurements"][0]["unit"], token);
        assert!(value["measurements"][0]["threshold"].is_null());
        assert!(value["measurements"][0]["comparison"].is_null());
    }

    for (id, limitation) in [
        EvidenceLimitation::CaptureTruncated,
        EvidenceLimitation::TruncatedPayload,
        EvidenceLimitation::MissingNetworkLayer,
        EvidenceLimitation::IncompleteHandshake,
        EvidenceLimitation::PacketCountBudgetReached,
        EvidenceLimitation::ObservationBudgetReached,
        EvidenceLimitation::FlowBudgetReached,
        EvidenceLimitation::HeaderBudgetExceeded,
    ]
    .into_iter()
    .enumerate()
    {
        let measurement = EvidenceMeasurement::try_new(
            EvidenceMetricKey::try_new(format!("limitation_{id}")).unwrap(),
            EvidenceValue::Unsigned(1),
            EvidenceUnit::Count,
        )
        .unwrap();
        let record = schema_evidence_with_measurement(
            id as u64 + 40,
            EvidenceKind::ProtocolFact,
            measurement,
            Some(limitation),
        );
        let value = schema_json(&EvidenceRecordDto::from_domain(&record));
        assert_eq!(value["limitations"][0], limitation.as_str());
    }

    for (severity, token) in [
        (Severity::Info, "info"),
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
        (Severity::Critical, "critical"),
    ] {
        let (finding, _) = schema_finding_at_with_levels(50, 50, 0, severity, Confidence::Low);
        let value = schema_json(&FindingRecordDto::from_domain(&finding));
        assert_eq!(value["severity"], token);
    }
    for (confidence, token) in [
        (Confidence::Low, "low"),
        (Confidence::Medium, "medium"),
        (Confidence::High, "high"),
    ] {
        let (finding, _) = schema_finding_at_with_levels(51, 51, 0, Severity::Info, confidence);
        let value = schema_json(&FindingRecordDto::from_domain(&finding));
        assert_eq!(value["confidence"], token);
    }

    let all_values = [
        (EvidenceValue::Integer(i128::MIN), "Integer"),
        (EvidenceValue::Unsigned(u128::MAX), "Unsigned"),
        (
            EvidenceValue::Ratio(EvidenceRatio::from_fraction(17, 20).unwrap()),
            "Ratio",
        ),
        (EvidenceValue::Boolean(true), "Boolean"),
        (
            EvidenceValue::Duration(FlowDuration::from_fraction(15, 2).unwrap()),
            "Duration",
        ),
    ];
    for (domain_value, tag) in all_values {
        let dto = EvidenceValueDto::from_domain(&domain_value);
        let value = schema_json(&dto);
        assert_exact_keys(&dto, &["type", "value"]);
        assert_eq!(value["type"], tag);
    }
    assert_eq!(
        schema_json(&EvidenceValueDto::from_domain(&EvidenceValue::Integer(
            i128::MIN
        )))["value"],
        i128::MIN.to_string()
    );
    assert_eq!(
        schema_json(&EvidenceValueDto::from_domain(&EvidenceValue::Unsigned(
            u128::MAX
        )))["value"],
        u128::MAX.to_string()
    );

    let edns = schema_json(&DnsEdnsDto {
        udp_payload_size: u16::MAX,
        extended_rcode: u8::MAX,
        version: u8::MAX,
        dnssec_ok: true,
        options: vec![u16::MAX],
    });
    assert_number_fields(&edns, &["udp_payload_size", "extended_rcode", "version"]);
    assert_eq!(edns["udp_payload_size"], u16::MAX);
    assert_eq!(edns["options"][0], u16::MAX);
    assert!(edns["dnssec_ok"].as_bool().unwrap());
}

#[test]
fn test_all_machine_formats_have_frozen_envelopes_headers_and_order() {
    let validation = schema_validation_report();
    let mut flow_0 = schema_flow();
    flow_0.reference = FlowReference::new(0);
    let mut flow_1 = schema_flow();
    flow_1.reference = FlowReference::new(1);
    let mut flow_2 = schema_flow();
    flow_2.reference = FlowReference::new(2);
    let flows = vec![flow_0, flow_1, flow_2];
    let dns_observations = vec![schema_dns_observation(), schema_dns_edns_observation()];
    let http_observations = vec![
        schema_http_observation(),
        schema_http_response_observation(),
    ];
    let tls_observations = vec![
        schema_tls_observation(),
        schema_tls_server_hello_observation(),
    ];
    let protocol_observations = schema_protocol_observations();
    let (finding_0, evidence_0) = schema_finding();
    let (finding_1, evidence_1) = schema_finding_at(1, 1, 1);
    let finding_domains = vec![finding_0, finding_1];
    let evidence_domains = vec![evidence_0, evidence_1];
    let findings: Vec<&FindingRecord> = finding_domains.iter().collect();
    let evidence_records: Vec<&EvidenceRecord> = evidence_domains.iter().collect();
    let analysis = schema_analysis_report_from_domains(
        &flows,
        &protocol_observations,
        &finding_domains,
        &evidence_domains,
    );

    let validation_json = render_deterministically(|output| {
        report_validation(
            ReportFormat::Json,
            &validation.metadata,
            &validation.summary,
            &validation.completion,
            &validation.diagnostics,
            output,
        )
        .unwrap();
    });
    let validation_json_value = assert_json_document_with_keys(
        &validation_json,
        &[
            "schema_version",
            "kind",
            "source_path",
            "metadata",
            "summary",
            "diagnostics",
            "completion",
        ],
    );
    assert_eq!(validation_json_value["kind"], "validation");
    let validation_ndjson = render_deterministically(|output| {
        report_validation(
            ReportFormat::Ndjson,
            &validation.metadata,
            &validation.summary,
            &validation.completion,
            &validation.diagnostics,
            output,
        )
        .unwrap();
    });
    let validation_records = assert_ndjson_document(
        &validation_ndjson,
        "validation",
        &["summary", "diagnostic", "diagnostic"],
    );
    assert_eq!(validation_records[0]["record_type"], "summary");
    assert_eq!(validation_records[1]["data"]["index"], "0");
    assert_eq!(validation_records[1]["data"]["stage"], "packet");
    assert_eq!(validation_records[1]["data"]["kind"], "malformed");
    assert_eq!(validation_records[2]["data"]["index"], "1");
    assert_eq!(validation_records[2]["data"]["stage"], "reader");
    assert_eq!(validation_records[2]["data"]["kind"], "io");
    let validation_csv = render_deterministically(|output| {
        report_validation(
            ReportFormat::Csv,
            &validation.metadata,
            &validation.summary,
            &validation.completion,
            &validation.diagnostics,
            output,
        )
        .unwrap();
    });
    assert_csv_document(&validation_csv, &["property", "value"]);
    let validation_table = render_deterministically(|output| {
        report_validation(
            ReportFormat::Table,
            &validation.metadata,
            &validation.summary,
            &validation.completion,
            &validation.diagnostics,
            output,
        )
        .unwrap();
    });
    assert!(!validation_table.is_empty());

    let flows_json = render_deterministically(|output| {
        report_flows(ReportFormat::Json, &flows, output).unwrap();
    });
    let flows_json_value = assert_json_document_with_keys(
        &flows_json,
        &["schema_version", "kind", "total_flows", "flows"],
    );
    assert_eq!(flows_json_value["kind"], "flows");
    let flows_ndjson = render_deterministically(|output| {
        report_flows(ReportFormat::Ndjson, &flows, output).unwrap();
    });
    let flow_records =
        assert_ndjson_document(&flows_ndjson, "flows", &["summary", "flow", "flow", "flow"]);
    assert_eq!(flow_records[1]["data"]["ordinal"], "0");
    assert_eq!(flow_records[2]["data"]["ordinal"], "1");
    assert_eq!(flow_records[3]["data"]["ordinal"], "2");
    let flows_csv = render_deterministically(|output| {
        report_flows(ReportFormat::Csv, &flows, output).unwrap();
    });
    assert_csv_document(
        &flows_csv,
        &[
            "id",
            "ordinal",
            "protocol",
            "endpoint_a",
            "endpoint_b",
            "total_packets",
            "packets_a_to_b",
            "packets_b_to_a",
            "packets_same_endpoint",
            "total_captured_bytes",
            "captured_bytes_a_to_b",
            "captured_bytes_b_to_a",
            "total_wire_bytes",
            "wire_bytes_a_to_b",
            "wire_bytes_b_to_a",
            "duration_numerator",
            "duration_denominator",
            "duration_display",
            "end_reason",
        ],
    );
    let flows_table = render_deterministically(|output| {
        report_flows(ReportFormat::Table, &flows, output).unwrap();
    });
    assert!(!flows_table.is_empty());

    let dns_json = render_deterministically(|output| {
        report_dns(ReportFormat::Json, &dns_observations, output).unwrap();
    });
    let dns_json_value = assert_json_document_with_keys(
        &dns_json,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    assert_eq!(dns_json_value["kind"], "dns");
    let dns_ndjson = render_deterministically(|output| {
        report_dns(ReportFormat::Ndjson, &dns_observations, output).unwrap();
    });
    let dns_records = assert_ndjson_document(&dns_ndjson, "dns", &["summary", "dns", "dns"]);
    assert_eq!(dns_records[1]["data"]["packet_ordinal"], "0");
    assert_eq!(dns_records[2]["data"]["packet_ordinal"], "3");
    let dns_csv = render_deterministically(|output| {
        report_dns(ReportFormat::Csv, &dns_observations, output).unwrap();
    });
    assert_csv_document(
        &dns_csv,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "transaction_id",
            "message_kind",
            "opcode",
            "authoritative_answer",
            "truncation",
            "recursion_desired",
            "recursion_available",
            "response_code",
            "qname",
            "qtype",
            "qclass",
            "answers_count",
            "edns_present",
            "completeness",
        ],
    );
    let dns_table = render_deterministically(|output| {
        report_dns(ReportFormat::Table, &dns_observations, output).unwrap();
    });
    assert!(!dns_table.is_empty());

    let http_json = render_deterministically(|output| {
        report_http(ReportFormat::Json, &http_observations, output).unwrap();
    });
    let http_json_value = assert_json_document_with_keys(
        &http_json,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    assert_eq!(http_json_value["kind"], "http");
    let http_ndjson = render_deterministically(|output| {
        report_http(ReportFormat::Ndjson, &http_observations, output).unwrap();
    });
    let http_records = assert_ndjson_document(&http_ndjson, "http", &["summary", "http", "http"]);
    assert_eq!(http_records[1]["data"]["packet_ordinal"], "0");
    assert_eq!(http_records[2]["data"]["packet_ordinal"], "1");
    let http_csv = render_deterministically(|output| {
        report_http(ReportFormat::Csv, &http_observations, output).unwrap();
    });
    assert_csv_document(
        &http_csv,
        &[
            "packet_ordinal",
            "transport",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "message_kind",
            "version",
            "method",
            "target",
            "status_code",
            "host",
            "content_type",
            "content_length",
            "transfer_encoding",
            "server",
            "user_agent",
            "authorization_present",
            "cookie_present",
            "set_cookie_present",
            "proxy_authorization_present",
            "completeness",
        ],
    );
    let http_table = render_deterministically(|output| {
        report_http(ReportFormat::Table, &http_observations, output).unwrap();
    });
    assert!(!http_table.is_empty());

    let tls_json = render_deterministically(|output| {
        report_tls(ReportFormat::Json, &tls_observations, output).unwrap();
    });
    let tls_json_value = assert_json_document_with_keys(
        &tls_json,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    assert_eq!(tls_json_value["kind"], "tls");
    let tls_ndjson = render_deterministically(|output| {
        report_tls(ReportFormat::Ndjson, &tls_observations, output).unwrap();
    });
    let tls_records = assert_ndjson_document(&tls_ndjson, "tls", &["summary", "tls", "tls"]);
    assert_eq!(tls_records[1]["data"]["packet_ordinal"], "0");
    assert_eq!(tls_records[2]["data"]["packet_ordinal"], "2");
    let tls_csv = render_deterministically(|output| {
        report_tls(ReportFormat::Csv, &tls_observations, output).unwrap();
    });
    assert_csv_document(
        &tls_csv,
        &[
            "packet_ordinal",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "record_version",
            "handshake_kind",
            "client_version",
            "server_version",
            "selected_version",
            "selected_cipher_suite",
            "server_name",
            "alpn_protocols",
            "ciphers_count",
            "extensions_count",
            "completeness",
        ],
    );
    let tls_table = render_deterministically(|output| {
        report_tls(ReportFormat::Table, &tls_observations, output).unwrap();
    });
    assert!(!tls_table.is_empty());

    let findings_json = render_deterministically(|output| {
        report_findings(
            ReportFormat::Json,
            &findings,
            &evidence_records,
            None,
            output,
        )
        .unwrap();
    });
    let findings_json_value = assert_json_document_with_keys(
        &findings_json,
        &[
            "schema_version",
            "kind",
            "total_findings",
            "total_evidence_records",
            "filter",
            "findings",
            "evidence",
        ],
    );
    assert_eq!(findings_json_value["kind"], "findings");
    let findings_ndjson = render_deterministically(|output| {
        report_findings(
            ReportFormat::Ndjson,
            &findings,
            &evidence_records,
            None,
            output,
        )
        .unwrap();
    });
    let findings_records = assert_ndjson_document(
        &findings_ndjson,
        "findings",
        &["summary", "finding", "finding", "evidence", "evidence"],
    );
    assert_eq!(findings_records[1]["data"]["id"], "find:0");
    assert_eq!(findings_records[2]["data"]["id"], "find:1");
    assert_eq!(findings_records[3]["data"]["id"], "evi:0");
    assert_eq!(findings_records[4]["data"]["id"], "evi:1");
    let findings_csv = render_deterministically(|output| {
        report_findings(
            ReportFormat::Csv,
            &findings,
            &evidence_records,
            None,
            output,
        )
        .unwrap();
    });
    assert_csv_document(
        &findings_csv,
        &[
            "id",
            "ordinal",
            "detector_id",
            "detector_version",
            "title",
            "summary",
            "rationale",
            "severity",
            "confidence",
            "packets",
            "flows",
            "observations",
            "evidence_references",
            "source_finding_references",
            "mitre_techniques",
        ],
    );
    let findings_table = render_deterministically(|output| {
        report_findings(
            ReportFormat::Table,
            &findings,
            &evidence_records,
            None,
            output,
        )
        .unwrap();
    });
    assert!(!findings_table.is_empty());

    let analysis_json = render_deterministically(|output| {
        report_analysis(ReportFormat::Json, &analysis, &flows, &findings, output).unwrap();
    });
    let analysis_json_value = assert_json_document_with_keys(
        &analysis_json,
        &[
            "schema_version",
            "kind",
            "metadata",
            "summary",
            "completion",
            "filter",
            "flows",
            "observations",
            "evidence",
            "findings",
        ],
    );
    assert_eq!(analysis_json_value["kind"], "analysis");
    let analysis_ndjson = render_deterministically(|output| {
        report_analysis(ReportFormat::Ndjson, &analysis, &flows, &findings, output).unwrap();
    });
    let analysis_records = assert_ndjson_document(
        &analysis_ndjson,
        "analysis",
        &[
            "summary",
            "flow",
            "flow",
            "flow",
            "observation",
            "observation",
            "observation",
            "observation",
            "observation",
            "evidence",
            "evidence",
            "finding",
            "finding",
        ],
    );
    assert_eq!(analysis_records[1]["data"]["ordinal"], "0");
    assert_eq!(analysis_records[2]["data"]["ordinal"], "1");
    assert_eq!(analysis_records[3]["data"]["ordinal"], "2");
    assert_eq!(analysis_records[4]["data"]["id"], "obs:0:dns:0");
    assert_eq!(analysis_records[5]["data"]["id"], "obs:1:http:0");
    assert_eq!(analysis_records[6]["data"]["id"], "obs:2:tls:0");
    assert_eq!(analysis_records[7]["data"]["id"], "obs:3:dns:0");
    assert_eq!(analysis_records[8]["data"]["id"], "obs:4:http:0");
    let analysis_dns = &analysis_records[4]["data"];
    assert_eq!(analysis_dns["protocol"], "dns");
    assert_eq!(analysis_dns["association"]["status"], "associated");
    assert_eq!(analysis_dns["association"]["flow_reference"], "Flow(0)");
    assert_eq!(analysis_dns["association"]["direction"], "a_to_b");
    assert!(analysis_dns["association"]["exclusion_reason"].is_null());
    assert_object_keys(
        &analysis_dns["association"],
        &["status", "flow_reference", "direction", "exclusion_reason"],
    );
    assert_object_keys(&analysis_dns["data"], &["dns", "http", "tls"]);
    assert!(analysis_dns["data"]["dns"].is_object());
    assert!(analysis_dns["data"]["http"].is_null());
    assert!(analysis_dns["data"]["tls"].is_null());

    let analysis_http = &analysis_records[5]["data"];
    assert_eq!(analysis_http["protocol"], "http");
    assert_eq!(analysis_http["association"]["status"], "associated");
    assert_eq!(analysis_http["association"]["flow_reference"], "Flow(1)");
    assert_eq!(analysis_http["association"]["direction"], "b_to_a");
    assert!(analysis_http["association"]["exclusion_reason"].is_null());
    assert_object_keys(
        &analysis_http["association"],
        &["status", "flow_reference", "direction", "exclusion_reason"],
    );
    assert_object_keys(&analysis_http["data"], &["dns", "http", "tls"]);
    assert!(analysis_http["data"]["dns"].is_null());
    assert!(analysis_http["data"]["http"].is_object());
    assert!(analysis_http["data"]["tls"].is_null());

    let analysis_tls = &analysis_records[6]["data"];
    assert_eq!(analysis_tls["protocol"], "tls");
    assert_eq!(analysis_tls["association"]["status"], "associated");
    assert_eq!(analysis_tls["association"]["flow_reference"], "Flow(2)");
    assert_eq!(analysis_tls["association"]["direction"], "same_endpoint");
    assert!(analysis_tls["association"]["exclusion_reason"].is_null());
    assert_object_keys(
        &analysis_tls["association"],
        &["status", "flow_reference", "direction", "exclusion_reason"],
    );
    assert_object_keys(&analysis_tls["data"], &["dns", "http", "tls"]);
    assert!(analysis_tls["data"]["dns"].is_null());
    assert!(analysis_tls["data"]["http"].is_null());
    assert!(analysis_tls["data"]["tls"].is_object());

    let analysis_excluded_dns = &analysis_records[7]["data"];
    assert_eq!(analysis_excluded_dns["protocol"], "dns");
    assert_eq!(analysis_excluded_dns["association"]["status"], "excluded");
    assert!(analysis_excluded_dns["association"]["flow_reference"].is_null());
    assert!(analysis_excluded_dns["association"]["direction"].is_null());
    assert_eq!(
        analysis_excluded_dns["association"]["exclusion_reason"],
        "MissingTransportLayer"
    );
    assert_object_keys(
        &analysis_excluded_dns["association"],
        &["status", "flow_reference", "direction", "exclusion_reason"],
    );
    assert_object_keys(&analysis_excluded_dns["data"], &["dns", "http", "tls"]);
    assert!(analysis_excluded_dns["data"]["dns"].is_object());
    assert!(analysis_excluded_dns["data"]["http"].is_null());
    assert!(analysis_excluded_dns["data"]["tls"].is_null());

    let analysis_unassociated_http = &analysis_records[8]["data"];
    assert_eq!(analysis_unassociated_http["protocol"], "http");
    assert_eq!(
        analysis_unassociated_http["association"]["status"],
        "unassociated"
    );
    assert!(analysis_unassociated_http["association"]["flow_reference"].is_null());
    assert!(analysis_unassociated_http["association"]["direction"].is_null());
    assert!(analysis_unassociated_http["association"]["exclusion_reason"].is_null());
    assert_object_keys(
        &analysis_unassociated_http["association"],
        &["status", "flow_reference", "direction", "exclusion_reason"],
    );
    assert_object_keys(&analysis_unassociated_http["data"], &["dns", "http", "tls"]);
    assert!(analysis_unassociated_http["data"]["dns"].is_null());
    assert!(analysis_unassociated_http["data"]["http"].is_object());
    assert!(analysis_unassociated_http["data"]["tls"].is_null());
    assert_eq!(analysis_records[9]["data"]["id"], "evi:0");
    assert_eq!(analysis_records[10]["data"]["id"], "evi:1");
    assert_eq!(analysis_records[11]["data"]["id"], "find:0");
    assert_eq!(analysis_records[12]["data"]["id"], "find:1");
    let analysis_table = render_deterministically(|output| {
        report_analysis(ReportFormat::Table, &analysis, &flows, &findings, output).unwrap();
    });
    assert!(!analysis_table.is_empty());

    let mut analysis_csv = Vec::new();
    let error = report_analysis(
        ReportFormat::Csv,
        &analysis,
        &flows,
        &findings,
        &mut analysis_csv,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ReportError::UnsupportedFormat {
            format: ReportFormat::Csv,
            kind: ReportKind::Analysis,
            ..
        }
    ));
    assert!(
        analysis_csv.is_empty(),
        "rejected analyze CSV must not write"
    );
}

fn render_deterministically<F>(render: F) -> Vec<u8>
where
    F: Fn(&mut Vec<u8>),
{
    let mut first = Vec::new();
    render(&mut first);
    let mut second = Vec::new();
    render(&mut second);
    assert_eq!(first, second, "report serialization must be deterministic");
    first
}

#[test]
fn test_csv_formula_safety_and_sensitive_header_non_retention() {
    for raw in [
        "=1+1", "+cmd", "-calc", "@SUM", "\t=test", "\r=test", "\n=test", "  =test",
    ] {
        assert!(
            sanitize_csv_cell(raw).starts_with('\''),
            "CSV trigger {raw:?} must be prefixed"
        );
    }
    assert_eq!(sanitize_csv_cell("normal"), "normal");

    let mut http = schema_http_observation();
    http.headers.has_authorization = true;
    http.headers.has_cookie = true;
    http.headers.has_set_cookie = true;
    http.headers.has_proxy_authorization = true;
    let dto = HttpObservationDto::from_domain(&http);
    let value = schema_json(&dto);
    assert_eq!(
        value["headers"]["sensitive_headers"]["authorization_present"],
        true
    );
    assert_eq!(
        value["headers"]["sensitive_headers"]["cookie_present"],
        true
    );
    assert_eq!(
        value["headers"]["sensitive_headers"]["set_cookie_present"],
        true
    );
    assert_eq!(
        value["headers"]["sensitive_headers"]["proxy_authorization_present"],
        true
    );
    assert!(!value.to_string().contains("secret"));
    assert!(!value.to_string().contains("token"));

    let mut csv_output = Vec::new();
    let dto = HttpReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "http",
        total_observations: "1".to_string(),
        observations: vec![HttpObservationDto {
            packet_ordinal: "0".to_string(),
            transport: "tcp",
            source_ip: "192.0.2.1".to_string(),
            source_port: 1,
            destination_ip: "192.0.2.2".to_string(),
            destination_port: 2,
            message_kind: "request".to_string(),
            version: "HTTP/1.1".to_string(),
            request: Some(HttpRequestDto {
                method: "GET".to_string(),
                target: "/".to_string(),
            }),
            response: None,
            headers: HttpHeadersDto {
                host: Some("=SUM(1,2)".to_string()),
                content_type: None,
                content_length: "not_present".to_string(),
                transfer_encoding: None,
                server: None,
                user_agent: None,
                sensitive_headers: HttpSensitiveHeadersDto {
                    authorization_present: true,
                    cookie_present: true,
                    set_cookie_present: true,
                    proxy_authorization_present: true,
                },
            },
            completeness: "complete".to_string(),
        }],
    };
    pcapraven_reporting::csv::render_http_csv(&dto, &mut csv_output).unwrap();
    let mut reader = csv::ReaderBuilder::new().from_reader(csv_output.as_slice());
    let headers = reader.headers().unwrap().clone();
    let record = reader.records().next().unwrap().unwrap();
    let host_index = headers.iter().position(|header| header == "host").unwrap();
    assert_eq!(&record[host_index], "'=SUM(1,2)");
}
