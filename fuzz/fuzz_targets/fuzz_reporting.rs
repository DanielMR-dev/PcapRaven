#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, DnsFlags, DnsMessageKind, DnsName, DnsObservation,
    DnsObservationCompleteness, DnsQuestion, DnsTransport, EvidenceDescription,
    EvidenceDraftBuilder, EvidenceKind, EvidenceMeasurement, EvidenceMetricKey, EvidenceRecord,
    EvidenceReference, EvidenceUnit, EvidenceValue, FindingRationale, FindingRecord,
    FindingReference, FindingSubject, FindingSummary, FindingTitle, FlowDirection, FlowEndReason,
    FlowEndpoint, FlowInterArrivalMetrics, FlowKey, FlowRecord, FlowReference, FlowTemporalMetrics,
    FlowTemporalUnavailableReason, FlowTemporalValue, FlowTimestampCoverage, FlowTrafficCounters,
    FlowTrafficStatistics, IpAddress, ObservationFlowAssociation, ObservationReference,
    PacketReference, PacketTimestamp, ProtocolKind, ProtocolObservation, ProtocolObservationData,
    Severity, TransportProtocol,
};
use pcapraven_reporting::{
    AnalysisReportDto, AnalysisSummaryDto, EvidenceRecordDto, FindingRecordDto, REPORT_SCHEMA_VERSION,
    FlowRecordDto, ProtocolObservationDto, ReportCompletionDto, ReportFormat, ValidationMetadataDto,
    report_analysis, report_findings,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

const MAX_FINDINGS: usize = 4;
const MAX_MEASUREMENTS: usize = 4;
const MAX_REFERENCES_PER_RECORD: usize = 3;
const MAX_RENDERED_BYTES: usize = 256 * 1024;

fn invariant_failure(message: &str) {
    assert!(message.is_empty(), "{message}");
}

struct CapacityWriter {
    remaining: usize,
}

impl Write for CapacityWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "synthetic bounded writer failure",
            ));
        }
        let written = self.remaining.min(bytes.len());
        self.remaining = self.remaining.saturating_sub(written);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn attacker_text(data: &[u8], salt: usize) -> String {
    let mut text = String::new();
    for byte in data.iter().copied().skip(salt).take(96) {
        let character = match byte % 12 {
            0 => '\u{1b}',
            1 => '\n',
            2 => '\r',
            3 => '\0',
            4 => '=',
            5 => '+',
            6 => '-',
            7 => '@',
            8 => 'λ',
            9 => '中',
            value => char::from(b'a'.saturating_add(value)),
        };
        text.push(character);
    }
    if text.is_empty() {
        text.push_str("synthetic");
    }
    text
}

#[derive(Default)]
struct ReferenceUniverse {
    packets: BTreeSet<String>,
    flows: BTreeSet<String>,
    observations: BTreeSet<String>,
}

struct GeneratedRecords {
    findings: Vec<FindingRecord>,
    evidence: Vec<EvidenceRecord>,
    flows: Vec<FlowRecord>,
    observations: Vec<ProtocolObservation>,
    universe: ReferenceUniverse,
}

fn insufficient_inter_arrival() -> FlowInterArrivalMetrics {
    let unavailable =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    FlowInterArrivalMetrics::new(
        0,
        0,
        unavailable,
        unavailable,
        unavailable,
        0,
        unavailable,
    )
}

fn flow(reference: FlowReference, packet: PacketReference) -> Option<FlowRecord> {
    let source_port = 40_000_u16.checked_add(u16::try_from(reference.ordinal()).ok()?)?;
    let key = FlowKey::new(
        TransportProtocol::Udp,
        FlowEndpoint::new(IpAddress::Ipv4([192, 0, 2, 10]), source_port),
        FlowEndpoint::new(IpAddress::Ipv4([198, 51, 100, 53]), 53),
    );
    let counters = FlowTrafficCounters::new(1, 64, 64, 0);
    let traffic = FlowTrafficStatistics::new(
        counters,
        counters,
        FlowTrafficCounters::empty(),
        FlowTrafficCounters::empty(),
    );
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples),
        FlowTimestampCoverage::new(0, 1, 0, 0),
        insufficient_inter_arrival(),
        insufficient_inter_arrival(),
        insufficient_inter_arrival(),
        insufficient_inter_arrival(),
    );
    Some(FlowRecord::new(
        reference,
        key,
        packet,
        packet,
        FlowEndReason::EndOfInput,
        traffic,
        temporal,
    ))
}

fn observation(
    reference: ObservationReference,
    packet: PacketReference,
    flow: FlowReference,
) -> Option<ProtocolObservation> {
    let name = DnsName::from_labels(vec![b"synthetic".to_vec(), b"example".to_vec()])?;
    let dns = DnsObservation {
        packet,
        timestamp: PacketTimestamp::Unavailable,
        transport: DnsTransport::Udp,
        source_ip: IpAddress::Ipv4([192, 0, 2, 10]),
        source_port: 53_000,
        destination_ip: IpAddress::Ipv4([198, 51, 100, 53]),
        destination_port: 53,
        transaction_id: u16::try_from(reference.packet_ordinal()).unwrap_or_default(),
        message_kind: DnsMessageKind::Query,
        opcode: 0,
        response_code: 0,
        effective_response_code: 0,
        flags: DnsFlags::default(),
        declared_qdcount: 1,
        declared_ancount: 0,
        declared_nscount: 0,
        declared_arcount: 0,
        questions: vec![DnsQuestion::new(name, 1, 1)],
        records: Vec::new(),
        edns: None,
        completeness: DnsObservationCompleteness::Complete,
    };
    ProtocolObservation::try_new(
        reference,
        ObservationFlowAssociation::Associated {
            flow,
            direction: FlowDirection::AToB,
        },
        ProtocolObservationData::Dns(dns),
    )
    .ok()
}

fn build_records(data: &[u8]) -> Option<GeneratedRecords> {
    let finding_count = data
        .first()
        .copied()
        .map_or(1, |byte| usize::from(byte) % MAX_FINDINGS + 1);
    let measurement_count = data
        .get(1)
        .copied()
        .map_or(1, |byte| usize::from(byte) % MAX_MEASUREMENTS + 1);
    let reference_count = data
        .get(2)
        .copied()
        .map_or(1, |byte| usize::from(byte) % MAX_REFERENCES_PER_RECORD + 1);
    let raw_text = attacker_text(data, 6);
    let description = EvidenceDescription::try_new(&raw_text)
        .or_else(|_| EvidenceDescription::try_new("rejected attacker evidence text"))
        .ok()?;
    let title = FindingTitle::try_new(&raw_text)
        .or_else(|_| FindingTitle::try_new("Rejected attacker title"))
        .ok()?;
    let summary = FindingSummary::try_new(&raw_text)
        .or_else(|_| FindingSummary::try_new("Rejected attacker summary"))
        .ok()?;
    let rationale = FindingRationale::try_new(&raw_text)
        .or_else(|_| FindingRationale::try_new("Rejected attacker rationale"))
        .ok()?;
    let detector_suffix = data.get(3).copied().unwrap_or_default();
    let detector_id = DetectorId::try_new(format!("phase18.fuzz_{detector_suffix}")).ok()?;

    let entity_count = finding_count.checked_mul(reference_count)?;
    let mut flows = Vec::with_capacity(entity_count);
    let mut observations = Vec::with_capacity(entity_count);
    let mut universe = ReferenceUniverse::default();
    for entity_index in 0..entity_count {
        let ordinal = u64::try_from(entity_index).ok()?;
        let packet = PacketReference::new(ordinal, None, None, 64, 64, false);
        let flow_reference = FlowReference::new(ordinal);
        let observation_reference = ObservationReference::new(ordinal, ProtocolKind::Dns, 0);
        universe.packets.insert(ordinal.to_string());
        universe.flows.insert(flow_reference.to_string());
        universe
            .observations
            .insert(observation_reference.to_string());
        flows.push(flow(flow_reference, packet)?);
        observations.push(observation(observation_reference, packet, flow_reference)?);
    }

    let mut findings = Vec::with_capacity(finding_count);
    let mut evidence = Vec::with_capacity(finding_count);
    for index in 0..finding_count {
        let reference = u64::try_from(index).ok()?;
        let entity_start = index.checked_mul(reference_count)?;
        let entity_end = entity_start.checked_add(reference_count)?;
        let packet_references: Vec<_> = (entity_start..entity_end)
            .map(|entity_index| {
                let ordinal = u64::try_from(entity_index).ok()?;
                Some(PacketReference::new(ordinal, None, None, 64, 64, false))
            })
            .collect::<Option<Vec<_>>>()?;
        let flow_references: Vec<_> = (entity_start..entity_end)
            .map(|entity_index| Some(FlowReference::new(u64::try_from(entity_index).ok()?)))
            .collect::<Option<Vec<_>>>()?;
        let observation_references: Vec<_> = (entity_start..entity_end)
            .map(|entity_index| {
                Some(ObservationReference::new(
                    u64::try_from(entity_index).ok()?,
                    ProtocolKind::Dns,
                    0,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let mut evidence_builder =
            EvidenceDraftBuilder::new(EvidenceKind::ProtocolObservation, description.clone());
        for packet in &packet_references {
            evidence_builder.add_packet_reference(*packet).ok()?;
        }
        for flow in &flow_references {
            evidence_builder.add_flow_reference(*flow).ok()?;
        }
        for observation in &observation_references {
            evidence_builder.add_observation_reference(*observation).ok()?;
        }
        for measurement_index in 0..measurement_count {
            let key = EvidenceMetricKey::try_new(format!(
                "phase18_metric_{index}_{measurement_index}"
            ))
            .ok()?;
            let measurement = EvidenceMeasurement::try_new(
                key,
                EvidenceValue::Unsigned(u128::from(
                    data.get(index + measurement_index).copied().unwrap_or_default(),
                )),
                EvidenceUnit::Count,
            )
            .ok()?;
            evidence_builder.add_measurement(measurement).ok()?;
        }
        let draft = evidence_builder.build().ok()?;
        let evidence_reference = EvidenceReference::new(reference);
        evidence.push(EvidenceRecord::from_draft(evidence_reference, draft));
        let subject = FindingSubject::try_new(
            packet_references,
            flow_references,
            observation_references,
        )
        .ok()?;
        let evidence_span = usize::from(data.get(4).copied().unwrap_or_default())
            % (index.saturating_add(1).min(3))
            + 1;
        let evidence_references = (index + 1 - evidence_span..=index)
            .map(|evidence_index| {
                Some(EvidenceReference::new(u64::try_from(evidence_index).ok()?))
            })
            .collect::<Option<Vec<_>>>()?;
        let source_span = if index == 0 {
            0
        } else {
            usize::from(data.get(5).copied().unwrap_or_default()) % index.min(2) + 1
        };
        let source_finding_references = (index - source_span..index)
            .map(|source_index| Some(FindingReference::new(u64::try_from(source_index).ok()?)))
            .collect::<Option<Vec<_>>>()?;
        findings.push(
            FindingRecord::try_new(
                FindingReference::new(reference),
                detector_id.clone(),
                DetectorVersion::new(1, 0, u16::from(detector_suffix)),
                subject,
                title.clone(),
                summary.clone(),
                rationale.clone(),
                Severity::Info,
                Confidence::Low,
                evidence_references,
                source_finding_references,
                Vec::new(),
            )
            .ok()?,
        );
    }
    Some(GeneratedRecords {
        findings,
        evidence,
        flows,
        observations,
        universe,
    })
}

fn assert_terminal_safe(bytes: &[u8]) {
    assert!(!bytes.contains(&0x1b));
    assert!(!bytes.contains(&0));
    assert!(!bytes.contains(&b'\r'));
    assert!(
        bytes
            .iter()
            .all(|byte| *byte == b'\n' || *byte >= 0x20)
    );
}

fn parse_envelopes(bytes: &[u8], expected_kind: &str) -> Vec<Value> {
    let mut values = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            invariant_failure("invalid NDJSON envelope");
            return Vec::new();
        };
        values.push(value);
    }
    for value in &values {
        assert_eq!(value["schema_version"].as_str(), Some(REPORT_SCHEMA_VERSION));
        assert_eq!(value["kind"].as_str(), Some(expected_kind));
        assert!(value["record_type"].is_string());
        assert!(value["data"].is_object());
    }
    values
}

fn required_string(value: &Value, context: &str) -> Option<String> {
    let Some(value) = value.as_str() else {
        invariant_failure(context);
        return None;
    };
    Some(value.to_owned())
}

fn reference_vector(record: &Value, field: &str) -> Option<Vec<String>> {
    let Some(values) = record[field].as_array() else {
        invariant_failure("reference field must be an array");
        return None;
    };
    let mut references = Vec::with_capacity(values.len());
    let mut unique = BTreeSet::new();
    for value in values {
        let reference = required_string(value, "reference token must be a string")?;
        assert!(unique.insert(reference.clone()));
        references.push(reference);
    }
    Some(references)
}

fn assert_known(references: &[String], known: &BTreeSet<String>) {
    assert!(references.iter().all(|reference| known.contains(reference)));
}

fn assert_reference_closure(
    findings: &[Value],
    evidence: &[Value],
    universe: &ReferenceUniverse,
) {
    let mut evidence_records = BTreeMap::new();
    for record in evidence {
        let Some(id) = required_string(&record["id"], "evidence id must be a string") else {
            return;
        };
        let Some(packets) = reference_vector(record, "packet_references") else {
            return;
        };
        let Some(flows) = reference_vector(record, "flow_references") else {
            return;
        };
        let Some(observations) = reference_vector(record, "observation_references") else {
            return;
        };
        assert!(!packets.is_empty());
        assert!(!flows.is_empty());
        assert!(!observations.is_empty());
        assert_known(&packets, &universe.packets);
        assert_known(&flows, &universe.flows);
        assert_known(&observations, &universe.observations);
        assert!(
            evidence_records
                .insert(id, (packets, flows, observations))
                .is_none()
        );
    }
    assert_eq!(evidence_records.len(), evidence.len());

    let mut finding_positions = BTreeMap::new();
    for (position, finding) in findings.iter().enumerate() {
        let Some(id) = required_string(&finding["id"], "finding id must be a string") else {
            return;
        };
        assert!(finding_positions.insert(id, position).is_none());
    }
    for (position, finding) in findings.iter().enumerate() {
        let Some(evidence_references) = reference_vector(finding, "evidence_references") else {
            return;
        };
        let Some(source_references) = reference_vector(finding, "source_finding_references") else {
            return;
        };
        assert!(!evidence_references.is_empty());
        assert_eq!(source_references.is_empty(), position == 0);

        let mut prior_position = None;
        for source in &source_references {
            let Some(source_position) = finding_positions.get(source).copied() else {
                invariant_failure("source finding reference must resolve");
                return;
            };
            assert!(source_position < position);
            if let Some(previous) = prior_position {
                assert!(previous < source_position);
            }
            prior_position = Some(source_position);
        }

        let mut evidence_packets = BTreeSet::new();
        let mut evidence_flows = BTreeSet::new();
        let mut evidence_observations = BTreeSet::new();
        for reference in &evidence_references {
            let Some((packets, flows, observations)) = evidence_records.get(reference) else {
                invariant_failure("finding evidence reference must resolve");
                return;
            };
            evidence_packets.extend(packets.iter().cloned());
            evidence_flows.extend(flows.iter().cloned());
            evidence_observations.extend(observations.iter().cloned());
        }

        let Some(subject_packets) = reference_vector(&finding["subject"], "packets") else {
            return;
        };
        let Some(subject_flows) = reference_vector(&finding["subject"], "flows") else {
            return;
        };
        let Some(subject_observations) =
            reference_vector(&finding["subject"], "observations")
        else {
            return;
        };
        assert!(!subject_packets.is_empty());
        assert!(!subject_flows.is_empty());
        assert!(!subject_observations.is_empty());
        assert_known(&subject_packets, &universe.packets);
        assert_known(&subject_flows, &universe.flows);
        assert_known(&subject_observations, &universe.observations);
        assert!(subject_packets.iter().all(|reference| evidence_packets.contains(reference)));
        assert!(subject_flows.iter().all(|reference| evidence_flows.contains(reference)));
        assert!(
            subject_observations
                .iter()
                .all(|reference| evidence_observations.contains(reference))
        );
    }
}

fn assert_analysis_entities(flows: &[Value], observations: &[Value], universe: &ReferenceUniverse) {
    let mut flow_ids = BTreeSet::new();
    for record in flows {
        let Some(id) = required_string(&record["id"], "flow id must be a string") else {
            return;
        };
        assert!(flow_ids.insert(id));
    }
    assert_eq!(&flow_ids, &universe.flows);

    let mut observation_ids = BTreeSet::new();
    for record in observations {
        let Some(id) = required_string(&record["id"], "observation id must be a string") else {
            return;
        };
        let Some(packet) = required_string(
            &record["packet_reference"],
            "observation packet reference must be a string",
        ) else {
            return;
        };
        let Some(flow) = required_string(
            &record["association"]["flow_reference"],
            "observation flow reference must be a string",
        ) else {
            return;
        };
        assert!(universe.packets.contains(&packet));
        assert!(universe.flows.contains(&flow));
        assert!(observation_ids.insert(id));
    }
    assert_eq!(&observation_ids, &universe.observations);
}

fn validate_json_report(bytes: &[u8], expected_kind: &str, universe: &ReferenceUniverse) {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        invariant_failure("invalid report JSON");
        return;
    };
    assert_eq!(value["schema_version"].as_str(), Some(REPORT_SCHEMA_VERSION));
    assert_eq!(value["kind"].as_str(), Some(expected_kind));
    let Some(findings) = value["findings"].as_array() else {
        invariant_failure("missing findings array");
        return;
    };
    let Some(evidence) = value["evidence"].as_array() else {
        invariant_failure("missing evidence array");
        return;
    };
    assert_reference_closure(findings, evidence, universe);
    if expected_kind == "analysis" {
        let Some(flows) = value["flows"].as_array() else {
            invariant_failure("missing analysis flows array");
            return;
        };
        let Some(observations) = value["observations"].as_array() else {
            invariant_failure("missing analysis observations array");
            return;
        };
        assert_analysis_entities(flows, observations, universe);
    }
}

fn validate_ndjson_report(bytes: &[u8], expected_kind: &str, universe: &ReferenceUniverse) {
    let envelopes = parse_envelopes(bytes, expected_kind);
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut flows = Vec::new();
    let mut observations = Vec::new();
    for envelope in &envelopes {
        match envelope["record_type"].as_str() {
            Some("finding") => findings.push(envelope["data"].clone()),
            Some("evidence") => evidence.push(envelope["data"].clone()),
            Some("flow") => flows.push(envelope["data"].clone()),
            Some("observation") => observations.push(envelope["data"].clone()),
            Some("summary") => {}
            _ => {
                invariant_failure("unexpected NDJSON record type");
                return;
            }
        }
    }
    assert_reference_closure(&findings, &evidence, universe);
    if expected_kind == "analysis" {
        assert_analysis_entities(&flows, &observations, universe);
    } else {
        assert!(flows.is_empty());
        assert!(observations.is_empty());
    }
}

fn validate_csv_report(bytes: &[u8]) {
    let mut reader = csv::ReaderBuilder::new().from_reader(bytes);
    let Ok(headers) = reader.headers().cloned() else {
        invariant_failure("invalid CSV header");
        return;
    };
    assert!(!headers.is_empty());
    for record in reader.records() {
        let Ok(record) = record else {
            invariant_failure("invalid CSV record");
            return;
        };
        assert_eq!(record.len(), headers.len());
        for field in &record {
            let trimmed = field.trim_start();
            assert!(!field.starts_with(['=', '+', '-', '@']));
            assert!(!trimmed.starts_with(['=', '+', '-', '@']));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(GeneratedRecords {
        findings,
        evidence,
        flows,
        observations,
        universe,
    }) = build_records(data)
    else {
        return;
    };
    let finding_references: Vec<&FindingRecord> = findings.iter().collect();
    let evidence_references: Vec<&EvidenceRecord> = evidence.iter().collect();

    for format in [
        ReportFormat::Table,
        ReportFormat::Json,
        ReportFormat::Ndjson,
        ReportFormat::Csv,
    ] {
        let mut first = Vec::new();
        let first_result = report_findings(
            format,
            &finding_references,
            &evidence_references,
            None,
            &mut first,
        );
        let mut second = Vec::new();
        let second_result = report_findings(
            format,
            &finding_references,
            &evidence_references,
            None,
            &mut second,
        );
        assert_eq!(first_result.is_ok(), second_result.is_ok());
        assert_eq!(first, second);
        if first_result.is_err() {
            continue;
        }
        assert!(first.len() <= MAX_RENDERED_BYTES);
        match format {
            ReportFormat::Table => assert_terminal_safe(&first),
            ReportFormat::Json => validate_json_report(&first, "findings", &universe),
            ReportFormat::Ndjson => validate_ndjson_report(&first, "findings", &universe),
            ReportFormat::Csv => validate_csv_report(&first),
        }

        for capacity in [first.len().saturating_sub(1), first.len(), first.len().saturating_add(1)] {
            let mut writer = CapacityWriter { remaining: capacity };
            let result = report_findings(
                format,
                &finding_references,
                &evidence_references,
                None,
                &mut writer,
            );
            assert_eq!(result.is_ok(), capacity >= first.len());
        }
    }

    let Some(first_finding) = findings.first() else {
        return;
    };
    let analysis = AnalysisReportDto {
        metadata: ValidationMetadataDto {
            format: first_finding.title().as_str().to_owned(),
            ..ValidationMetadataDto::default()
        },
        summary: AnalysisSummaryDto {
            total_packets: universe.packets.len().to_string(),
            total_flows: flows.len().to_string(),
            total_dns_observations: observations.len().to_string(),
            total_http_observations: "0".to_owned(),
            total_tls_observations: "0".to_owned(),
            total_findings: findings.len().to_string(),
            total_evidence_records: evidence.len().to_string(),
        },
        completion: ReportCompletionDto {
            status: "complete".to_owned(),
            limitations: Vec::new(),
        },
        flows: flows.iter().map(FlowRecordDto::from_domain).collect(),
        observations: observations
            .iter()
            .map(ProtocolObservationDto::from_domain)
            .collect(),
        findings: findings.iter().map(FindingRecordDto::from_domain).collect(),
        evidence: evidence.iter().map(EvidenceRecordDto::from_domain).collect(),
        ..AnalysisReportDto::default()
    };

    for format in [ReportFormat::Table, ReportFormat::Json, ReportFormat::Ndjson] {
        let mut first = Vec::new();
        let first_result =
            report_analysis(format, &analysis, &flows, &finding_references, &mut first);
        let mut second = Vec::new();
        let second_result =
            report_analysis(format, &analysis, &flows, &finding_references, &mut second);
        assert_eq!(first_result.is_ok(), second_result.is_ok());
        assert_eq!(first, second);
        if first_result.is_err() {
            continue;
        }
        assert!(first.len() <= MAX_RENDERED_BYTES);
        match format {
            ReportFormat::Table => assert_terminal_safe(&first),
            ReportFormat::Json => validate_json_report(&first, "analysis", &universe),
            ReportFormat::Ndjson => validate_ndjson_report(&first, "analysis", &universe),
            ReportFormat::Csv => invariant_failure("CSV is excluded from analysis loop"),
        }
    }
    let mut csv = Vec::new();
    assert!(
        report_analysis(
            ReportFormat::Csv,
            &analysis,
            &flows,
            &finding_references,
            &mut csv,
        )
        .is_err()
    );
});
