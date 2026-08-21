//! Machine schema contract tests for PcapRaven deterministic reporting.
//!
//! Validates the frozen v1.0 JSON and NDJSON contract rules:
//! - Wide integers (u64, i64, u128, i128, usize) serialize as decimal JSON strings.
//! - Options serialize as `null` when `None`.
//! - Vectors serialize as `[]` when empty.
//! - Categorical machine tokens are lowercase snake_case.
//! - Exact rational arithmetic is preserved in `RatioDto` and `DurationDto`.

use pcapraven_reporting::dto::analysis::*;
use pcapraven_reporting::dto::dns::*;
use pcapraven_reporting::dto::findings::*;
use pcapraven_reporting::dto::flows::*;
use pcapraven_reporting::dto::validation::*;
use pcapraven_reporting::format::REPORT_SCHEMA_VERSION;

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
            stage: "linktype".to_string(),
            kind: "warning".to_string(),
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
            id: "flow:0".to_string(),
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
                    display: "7.500000000s".to_string(),
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
                flows: vec!["flow:0".to_string()],
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
            kind: "ratio_comparison".to_string(),
            description: "Diversity ratio".to_string(),
            packet_references: vec!["0".to_string()],
            flow_references: vec!["flow:0".to_string()],
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
                comparison: Some("greater_than".to_string()),
                unit: "ratio".to_string(),
            }],
            limitations: vec!["capture_truncated".to_string()],
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
                flow_reference: Some("flow:0".to_string()),
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
