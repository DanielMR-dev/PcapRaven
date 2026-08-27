//! Machine schema contract tests for PcapRaven deterministic reporting.
//!
//! Validates the frozen v1.0 JSON and NDJSON contract rules:
//! - Wide integers (u64, i64, u128, i128, usize) serialize as decimal JSON strings.
//! - Options serialize as `null` when `None`.
//! - Vectors serialize as `[]` when empty.
//! - DTO conversion maps domain and CLI categorical values to their documented tokens.
//! - Exact rational arithmetic is preserved in `RatioDto` and `DurationDto`.

use std::collections::BTreeSet;

use pcapraven_domain::{
    Confidence, DnsFlags, DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness,
    DnsQuestion, DnsRdataMetadata, DnsResourceRecord, DnsSection, DnsTransport, EvidenceComparison,
    EvidenceDescription, EvidenceDraftBuilder, EvidenceKind, EvidenceMeasurement,
    EvidenceMetricKey, EvidenceRatio, EvidenceRecord, EvidenceUnit, EvidenceValue, FindingDraft,
    FindingRationale, FindingRecord, FindingSubject, FindingSummary, FindingTitle, FlowDuration,
    FlowEndReason, FlowEndpoint, FlowInterArrivalMetrics, FlowKey, FlowRecord, FlowReference,
    FlowTemporalMetrics, FlowTemporalUnavailableReason, FlowTemporalValue, FlowTimestampCoverage,
    FlowTrafficCounters, IpAddress, MitreAttackCatalogVersion, MitreAttackDomain, MitreAttackId,
    MitreAttackObjectVersion, MitreAttackRelationship, MitreMapping, MitreMappingDeclaration,
    MitreMappingProvenance, MitreMappingRationale, MitreTactic, PacketReference, PacketTimestamp,
    Severity, TransportProtocol,
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

fn assert_exact_keys(value: &Value, expected: &[&str]) {
    let actual: BTreeSet<String> = value
        .as_object()
        .expect("schema value must be an object")
        .keys()
        .cloned()
        .collect();
    let expected: BTreeSet<String> = expected.iter().map(|key| (*key).to_string()).collect();
    assert_eq!(actual, expected);
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
    assert!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "JSON must not have a BOM"
    );
    assert!(
        bytes.ends_with(b"\n"),
        "JSON must end with exactly an LF terminator"
    );
    serde_json::from_slice(bytes).expect("JSON output must parse")
}

fn assert_ndjson_document(bytes: &[u8], kind: &str, record_types: &[&str]) {
    assert!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "NDJSON must not have a BOM"
    );
    assert!(bytes.ends_with(b"\n"), "NDJSON must end with an LF");
    let lines: Vec<&[u8]> = bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .collect();
    assert_eq!(lines.len(), record_types.len());
    for (line, expected_record_type) in lines.iter().zip(record_types) {
        assert!(!line.is_empty(), "NDJSON must not contain blank records");
        let value: Value = serde_json::from_slice(line).expect("NDJSON record must parse");
        assert_exact_keys(&value, &["schema_version", "kind", "record_type", "data"]);
        assert_eq!(value["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(value["kind"], kind);
        assert_eq!(value["record_type"], *expected_record_type);
        assert!(value["data"].is_object(), "NDJSON data must be an object");
    }
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
            total_diagnostics: "1".to_string(),
            had_diagnostics: true,
        },
        diagnostics: vec![ValidationDiagnosticDto {
            index: "0".to_string(),
            stage: "packet".to_string(),
            kind: "malformed".to_string(),
            message: "bounded malformed packet diagnostic".to_string(),
            byte_offset: Some("1024".to_string()),
        }],
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

fn schema_finding() -> (FindingRecord, EvidenceRecord) {
    let flow = schema_flow();
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
    let evidence = EvidenceRecord::from_draft(
        pcapraven_domain::EvidenceReference::new(0),
        evidence_draft.clone(),
    );

    let finding_draft = FindingDraft::try_new(
        subject,
        title,
        summary,
        rationale,
        Severity::High,
        Confidence::Medium,
        vec![evidence_draft],
    )
    .unwrap();
    let mitre_id = MitreAttackId::try_new("T1071.004").unwrap();
    let mitre_declaration = MitreMappingDeclaration::try_new(
        MitreAttackDomain::Enterprise,
        MitreAttackCatalogVersion::new(19, 2),
        mitre_id,
        "Application Layer Protocol: DNS",
        MitreAttackObjectVersion::new(1, 4),
        MitreTactic::CommandAndControl,
        MitreAttackRelationship::Analytical,
        MitreMappingRationale::try_new("High diversity DNS tunneling behavior").unwrap(),
    )
    .unwrap();
    let mitre_mapping = MitreMapping::from_declaration(
        &mitre_declaration,
        MitreMappingProvenance::DetectorDeclared {
            detector_id: pcapraven_domain::DetectorId::try_new("dns.possible_tunneling").unwrap(),
            detector_version: pcapraven_domain::DetectorVersion::new(1, 1, 1),
        },
    );
    let finding = FindingRecord::try_new(
        pcapraven_domain::FindingReference::new(0),
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

#[test]
fn test_all_dto_shapes_and_actual_conversion_domains() {
    let validation = schema_json(&schema_validation_report());
    assert_exact_keys(
        &validation,
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
        &validation["metadata"],
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
        &validation["summary"],
        &["records_emitted", "total_diagnostics", "had_diagnostics"],
    );
    assert_string_fields(
        &validation["summary"],
        &["records_emitted", "total_diagnostics"],
    );
    assert_boolean_fields(&validation["summary"], &["had_diagnostics"]);
    assert_exact_keys(
        &validation["diagnostics"][0],
        &["index", "stage", "kind", "message", "byte_offset"],
    );
    assert_string_fields(
        &validation["diagnostics"][0],
        &["index", "stage", "kind", "message", "byte_offset"],
    );
    assert_exact_keys(
        &validation["completion"],
        &["status", "is_complete", "terminal_error"],
    );
    assert_string_fields(&validation["completion"], &["status"]);
    assert_boolean_fields(&validation["completion"], &["is_complete"]);
    assert!(validation["source_path"].is_null());
    assert!(validation["completion"]["terminal_error"].is_null());

    let flow = schema_flow();
    let flows = schema_json(&FlowsReportDto::from_domain_flows(std::slice::from_ref(
        &flow,
    )));
    assert_exact_keys(&flows, &["schema_version", "kind", "total_flows", "flows"]);
    assert_string_fields(&flows, &["schema_version", "kind", "total_flows"]);
    let flow = &flows["flows"][0];
    assert_exact_keys(
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
        &flow["traffic"],
        &["total", "a_to_b", "b_to_a", "same_endpoint"],
    );
    for bucket in ["total", "a_to_b", "b_to_a", "same_endpoint"] {
        assert_exact_keys(
            &flow["traffic"][bucket],
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
        &flow["temporal"],
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
        &flow["temporal"]["duration"],
        &["numerator", "denominator", "display"],
    );
    assert_string_fields(
        &flow["temporal"]["duration"],
        &["numerator", "denominator", "display"],
    );
    assert_eq!(flow["temporal"]["duration"]["display"], "15/2s");
    assert!(flow["temporal"]["first_packet_timestamp"].is_null());
    assert!(flow["temporal"]["last_packet_timestamp"].is_null());
    assert_exact_keys(
        &flow["temporal"]["timestamp_coverage"],
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
        &flow["temporal"]["overall_inter_arrival"],
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

    let dns = schema_json(&DnsReportDto::from_domain_observations(
        std::slice::from_ref(&schema_dns_observation()),
    ));
    assert_exact_keys(
        &dns,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    let dns_observation = &dns["observations"][0];
    assert_exact_keys(
        dns_observation,
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
        &dns_observation["questions"][0],
        &["name", "qtype", "qtype_name", "qclass"],
    );
    assert_string_fields(&dns_observation["questions"][0], &["name", "qtype_name"]);
    assert_number_fields(&dns_observation["questions"][0], &["qtype", "qclass"]);
    assert_exact_keys(
        &dns_observation["answers"][0],
        &["name", "rtype", "rclass", "ttl", "data"],
    );
    assert_string_fields(&dns_observation["answers"][0], &["name", "data"]);
    assert_number_fields(&dns_observation["answers"][0], &["rtype", "rclass", "ttl"]);

    let http_observation = schema_http_observation();
    let http = schema_json(&HttpReportDto::from_domain_observations(
        std::slice::from_ref(&http_observation),
    ));
    assert_exact_keys(
        &http,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    let http_observation = &http["observations"][0];
    assert_exact_keys(
        http_observation,
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
    assert_exact_keys(&http_observation["request"], &["method", "target"]);
    assert_string_fields(&http_observation["request"], &["method", "target"]);
    assert!(http_observation["response"].is_null());
    assert_exact_keys(
        &http_observation["headers"],
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
        &http_observation["headers"]["sensitive_headers"],
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

    let tls_observation = schema_tls_observation();
    let tls = schema_json(&TlsReportDto::from_domain_observations(
        std::slice::from_ref(&tls_observation),
    ));
    assert_exact_keys(
        &tls,
        &[
            "schema_version",
            "kind",
            "total_observations",
            "observations",
        ],
    );
    let tls_observation = &tls["observations"][0];
    assert_exact_keys(
        tls_observation,
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
        &tls_observation["client_hello"],
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
        &tls_observation["client_hello"]["extensions"][0],
        &["extension_type", "length"],
    );
    assert_number_fields(
        &tls_observation["client_hello"]["extensions"][0],
        &["extension_type", "length"],
    );

    let (finding, evidence) = schema_finding();
    let findings = schema_json(&FindingsReportDto::from_domain_findings(
        &[&finding],
        &[&evidence],
        None,
    ));
    assert_exact_keys(
        &findings,
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
    assert!(findings["filter"].is_null());
    let finding = &findings["findings"][0];
    assert_exact_keys(
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
    assert_exact_keys(&finding["subject"], &["packets", "flows", "observations"]);
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
        &finding["mitre_mappings"][0],
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
        &finding["mitre_mappings"][0]["provenance"],
        &["kind", "component_id", "component_version"],
    );
    assert_eq!(
        finding["mitre_mappings"][0]["tactic"],
        "command_and_control"
    );
    let evidence = &findings["evidence"][0];
    assert_exact_keys(
        evidence,
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
    assert_exact_keys(
        measurement,
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
    assert_exact_keys(
        &measurement["observed_value"]["value"],
        &["numerator", "denominator", "string_representation"],
    );
    assert_eq!(
        measurement["observed_value"]["value"]["string_representation"],
        "17/20"
    );

    let analysis = schema_json(&schema_analysis_report(
        &schema_flow(),
        &schema_dns_observation(),
        &schema_finding().0,
        &schema_finding().1,
    ));
    assert_exact_keys(
        &analysis,
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
    assert_exact_keys(&analysis["completion"], &["status", "limitations"]);
    assert_string_fields(&analysis["completion"], &["status"]);
    assert_array_fields(&analysis["completion"], &["limitations"]);
    assert!(analysis["filter"].is_null());
    let observation = &analysis["observations"][0];
    assert_exact_keys(
        observation,
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
        &observation["association"],
        &["status", "flow_reference", "direction", "exclusion_reason"],
    );
    assert_string_fields(
        &observation["association"],
        &["status", "flow_reference", "direction"],
    );
    assert!(observation["association"]["exclusion_reason"].is_null());
    assert_exact_keys(&observation["data"], &["dns", "http", "tls"]);
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
        metadata: ValidationMetadataDto::default(),
        summary: ValidationSummaryDto {
            records_emitted: "0".to_string(),
            total_diagnostics: diagnostics.len().to_string(),
            had_diagnostics: true,
        },
        diagnostics,
        completion: ValidationCompletionDto::default(),
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
    assert!(value["diagnostics"][0]["byte_offset"].is_null());

    let flow = schema_flow();
    let flow_value = schema_json(&FlowRecordDto::from_domain(&flow));
    assert_eq!(flow_value["protocol"], "tcp");
    assert_eq!(flow_value["end_reason"], "end_of_input");
    assert_eq!(flow_value["temporal"]["status"], "available");

    let dns = schema_json(&DnsObservationDto::from_domain(&schema_dns_observation()));
    assert_eq!(dns["transport"], "udp");
    assert_eq!(dns["message_kind"], "response");
    assert_eq!(dns["completeness"], "complete");

    let http = schema_json(&HttpObservationDto::from_domain(&schema_http_observation()));
    assert_eq!(http["transport"], "tcp");
    assert_eq!(http["message_kind"], "request");
    assert_eq!(http["completeness"], "complete");

    let tls = schema_json(&TlsObservationDto::from_domain(&schema_tls_observation()));
    assert_eq!(tls["handshake_kind"], "client_hello");
    assert_eq!(tls["completeness"], "complete");
    assert_eq!(tls["client_hello"]["cipher_suites"][0], "0x1301");

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

    let all_values = [
        (EvidenceValueDto::Integer(i128::MIN.to_string()), "Integer"),
        (
            EvidenceValueDto::Unsigned(u128::MAX.to_string()),
            "Unsigned",
        ),
        (
            EvidenceValueDto::Ratio(RatioDto {
                numerator: "17".to_string(),
                denominator: "20".to_string(),
                string_representation: "17/20".to_string(),
            }),
            "Ratio",
        ),
        (EvidenceValueDto::Boolean(true), "Boolean"),
        (
            EvidenceValueDto::Duration(DurationDto {
                numerator: "15".to_string(),
                denominator: "2".to_string(),
                display: "15/2s".to_string(),
            }),
            "Duration",
        ),
    ];
    for (value, tag) in all_values {
        let value = schema_json(&value);
        assert_exact_keys(&value, &["type", "value"]);
        assert_eq!(value["type"], tag);
    }
    assert_eq!(
        schema_json(&EvidenceValueDto::Integer(i128::MIN.to_string()))["value"],
        i128::MIN.to_string()
    );
    assert_eq!(
        schema_json(&EvidenceValueDto::Unsigned(u128::MAX.to_string()))["value"],
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
    let flow = schema_flow();
    let dns = schema_dns_observation();
    let http = schema_http_observation();
    let tls = schema_tls_observation();
    let (finding, evidence) = schema_finding();
    let findings = vec![&finding];
    let evidence_records = vec![&evidence];
    let analysis = schema_analysis_report(&flow, &dns, &finding, &evidence);

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
    assert_eq!(assert_json_document(&validation_json)["kind"], "validation");
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
    assert_ndjson_document(&validation_ndjson, "validation", &["summary", "diagnostic"]);
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
        report_flows(ReportFormat::Json, std::slice::from_ref(&flow), output).unwrap();
    });
    assert_eq!(assert_json_document(&flows_json)["kind"], "flows");
    let flows_ndjson = render_deterministically(|output| {
        report_flows(ReportFormat::Ndjson, std::slice::from_ref(&flow), output).unwrap();
    });
    assert_ndjson_document(&flows_ndjson, "flows", &["summary", "flow"]);
    let flows_csv = render_deterministically(|output| {
        report_flows(ReportFormat::Csv, std::slice::from_ref(&flow), output).unwrap();
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
        report_flows(ReportFormat::Table, std::slice::from_ref(&flow), output).unwrap();
    });
    assert!(!flows_table.is_empty());

    let dns_json = render_deterministically(|output| {
        report_dns(ReportFormat::Json, std::slice::from_ref(&dns), output).unwrap();
    });
    assert_eq!(assert_json_document(&dns_json)["kind"], "dns");
    let dns_ndjson = render_deterministically(|output| {
        report_dns(ReportFormat::Ndjson, std::slice::from_ref(&dns), output).unwrap();
    });
    assert_ndjson_document(&dns_ndjson, "dns", &["summary", "dns"]);
    let dns_csv = render_deterministically(|output| {
        report_dns(ReportFormat::Csv, std::slice::from_ref(&dns), output).unwrap();
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
        report_dns(ReportFormat::Table, std::slice::from_ref(&dns), output).unwrap();
    });
    assert!(!dns_table.is_empty());

    let http_json = render_deterministically(|output| {
        report_http(ReportFormat::Json, std::slice::from_ref(&http), output).unwrap();
    });
    assert_eq!(assert_json_document(&http_json)["kind"], "http");
    let http_ndjson = render_deterministically(|output| {
        report_http(ReportFormat::Ndjson, std::slice::from_ref(&http), output).unwrap();
    });
    assert_ndjson_document(&http_ndjson, "http", &["summary", "http"]);
    let http_csv = render_deterministically(|output| {
        report_http(ReportFormat::Csv, std::slice::from_ref(&http), output).unwrap();
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
        report_http(ReportFormat::Table, std::slice::from_ref(&http), output).unwrap();
    });
    assert!(!http_table.is_empty());

    let tls_json = render_deterministically(|output| {
        report_tls(ReportFormat::Json, std::slice::from_ref(&tls), output).unwrap();
    });
    assert_eq!(assert_json_document(&tls_json)["kind"], "tls");
    let tls_ndjson = render_deterministically(|output| {
        report_tls(ReportFormat::Ndjson, std::slice::from_ref(&tls), output).unwrap();
    });
    assert_ndjson_document(&tls_ndjson, "tls", &["summary", "tls"]);
    let tls_csv = render_deterministically(|output| {
        report_tls(ReportFormat::Csv, std::slice::from_ref(&tls), output).unwrap();
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
        report_tls(ReportFormat::Table, std::slice::from_ref(&tls), output).unwrap();
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
    assert_eq!(assert_json_document(&findings_json)["kind"], "findings");
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
    assert_ndjson_document(
        &findings_ndjson,
        "findings",
        &["summary", "finding", "evidence"],
    );
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
        report_analysis(
            ReportFormat::Json,
            &analysis,
            std::slice::from_ref(&flow),
            &findings,
            output,
        )
        .unwrap();
    });
    assert_eq!(assert_json_document(&analysis_json)["kind"], "analysis");
    let analysis_ndjson = render_deterministically(|output| {
        report_analysis(
            ReportFormat::Ndjson,
            &analysis,
            std::slice::from_ref(&flow),
            &findings,
            output,
        )
        .unwrap();
    });
    assert_ndjson_document(
        &analysis_ndjson,
        "analysis",
        &["summary", "flow", "observation", "evidence", "finding"],
    );
    let analysis_table = render_deterministically(|output| {
        report_analysis(
            ReportFormat::Table,
            &analysis,
            std::slice::from_ref(&flow),
            &findings,
            output,
        )
        .unwrap();
    });
    assert!(!analysis_table.is_empty());

    let mut analysis_csv = Vec::new();
    let error = report_analysis(
        ReportFormat::Csv,
        &analysis,
        std::slice::from_ref(&flow),
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
