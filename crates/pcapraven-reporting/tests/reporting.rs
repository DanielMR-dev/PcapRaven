//! Integration and boundary tests for the PcapRaven reporting architecture.

use pcapraven_domain::{
    Confidence, DnsFlags, DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness,
    DnsQuestion, DnsRdataMetadata, DnsResourceRecord, DnsSection, DnsTransport, EvidenceComparison,
    EvidenceDescription, EvidenceDraftBuilder, EvidenceKind, EvidenceMeasurement,
    EvidenceMetricKey, EvidenceRatio, EvidenceRecord, EvidenceUnit, EvidenceValue, FindingDraft,
    FindingRationale, FindingRecord, FindingSubject, FindingSummary, FindingTitle, FlowDuration,
    FlowEndReason, FlowEndpoint, FlowInterArrivalMetrics, FlowKey, FlowRecord, FlowReference,
    FlowTemporalMetrics, FlowTemporalUnavailableReason, FlowTemporalValue, FlowTimestampCoverage,
    FlowTrafficCounters, FlowTrafficStatistics, IpAddress, MitreAttackCatalogVersion,
    MitreAttackDomain, MitreAttackId, MitreAttackObjectVersion, MitreAttackRelationship,
    MitreMapping, MitreMappingDeclaration, MitreMappingProvenance, MitreMappingRationale,
    MitreTactic, PacketReference, PacketTimestamp, Severity, TransportProtocol,
};
use pcapraven_reporting::{
    AnalysisReportDto, AnalysisSummaryDto, EvidenceRecordDto, FindingRecordDto, FlowRecordDto,
    REPORT_SCHEMA_VERSION, ReportError, ReportFormat, ReportKind, ValidationCompletionDto,
    ValidationMetadataDto, ValidationSummaryDto, report_analysis, report_dns, report_findings,
    report_flows, report_validation, sanitize_csv_cell,
};
use proptest::prelude::*;

fn make_synthetic_flow() -> FlowRecord {
    let ep_a = FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 10]), 54321);
    let ep_b = FlowEndpoint::new(IpAddress::Ipv4([93, 184, 216, 34]), 80);
    let key = FlowKey::new(TransportProtocol::Tcp, ep_a, ep_b);
    let reference = FlowReference::new(0);
    let pkt = PacketReference::new(0, None, None, 128, 128, false);

    let traffic = FlowTrafficStatistics::new(
        FlowTrafficCounters::new(10, 1500, 1500, 0),
        FlowTrafficCounters::new(6, 900, 900, 0),
        FlowTrafficCounters::new(4, 600, 600, 0),
        FlowTrafficCounters::empty(),
    );

    let dur = FlowDuration::from_fraction(15, 2).unwrap(); // 7.5s
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Available(dur),
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

fn make_synthetic_dns_obs() -> DnsObservation {
    let pkt_ref = PacketReference::new(0, None, None, 128, 128, false);
    let name = DnsName::from_labels(vec![b"example".to_vec(), b"com".to_vec()]).unwrap();
    let q = DnsQuestion::new(name.clone(), 1, 1);
    let rr = DnsResourceRecord {
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
        source_port: 54321,
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
        questions: vec![q],
        records: vec![rr],
        edns: None,
        completeness: DnsObservationCompleteness::Complete,
    }
}

fn make_synthetic_finding() -> (FindingRecord, EvidenceRecord) {
    let flow = make_synthetic_flow();
    let sub = FindingSubject::try_new(
        vec![PacketReference::new(0, None, None, 128, 128, false)],
        vec![flow.reference],
        Vec::new(),
    )
    .unwrap();

    let title = FindingTitle::try_new("Possible DNS Tunneling Activity").unwrap();
    let summary = FindingSummary::try_new("High volume of suspicious subdomains").unwrap();
    let rationale = FindingRationale::try_new("Observed high query name diversity").unwrap();
    let desc = EvidenceDescription::try_new("Query label diversity ratio exceeded").unwrap();
    let mkey = EvidenceMetricKey::try_new("label_octet_diversity_ratio").unwrap();
    let ratio = EvidenceRatio::from_fraction(85, 100).unwrap();
    let thresh = EvidenceRatio::from_fraction(75, 100).unwrap();

    let meas = EvidenceMeasurement::try_with_threshold(
        mkey,
        EvidenceValue::Ratio(ratio),
        EvidenceValue::Ratio(thresh),
        EvidenceComparison::GreaterThan,
        EvidenceUnit::Ratio,
    )
    .unwrap();

    let mut draft_builder = EvidenceDraftBuilder::new(EvidenceKind::RatioComparison, desc);
    draft_builder.add_measurement(meas).unwrap();
    draft_builder.add_flow_reference(flow.reference).unwrap();
    let evi_draft = draft_builder.build().unwrap();

    let evi_rec = EvidenceRecord::from_draft(
        pcapraven_domain::EvidenceReference::new(0),
        evi_draft.clone(),
    );

    let draft = FindingDraft::try_new(
        sub,
        title,
        summary,
        rationale,
        Severity::High,
        Confidence::Medium,
        vec![evi_draft],
    )
    .unwrap();

    let mitre_id = MitreAttackId::try_new("T1071.004").unwrap();
    let mitre_decl = MitreMappingDeclaration::try_new(
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
        &mitre_decl,
        MitreMappingProvenance::DetectorDeclared {
            detector_id: pcapraven_domain::DetectorId::try_new("dns.possible_tunneling").unwrap(),
            detector_version: pcapraven_domain::DetectorVersion::new(1, 1, 1),
        },
    );

    let finding = FindingRecord::try_new(
        pcapraven_domain::FindingReference::new(0),
        pcapraven_domain::DetectorId::try_new("dns.possible_tunneling").unwrap(),
        pcapraven_domain::DetectorVersion::new(1, 1, 1),
        draft.subject().clone(),
        draft.title().clone(),
        draft.summary().clone(),
        draft.rationale().clone(),
        draft.severity(),
        draft.confidence(),
        vec![evi_rec.reference()],
        Vec::new(),
        vec![mitre_mapping],
    )
    .unwrap();

    (finding, evi_rec)
}

#[test]
fn test_schema_version_anchor() {
    assert_eq!(REPORT_SCHEMA_VERSION, "v1.0");
}

#[test]
fn test_validation_report_all_formats() {
    let metadata = ValidationMetadataDto {
        format: "pcap".to_string(),
        byte_order: "little_endian".to_string(),
        version_major: Some(2),
        version_minor: Some(4),
        linktype: Some(1),
        snaplen: Some(65535),
        timestamp_resolution: Some("10^6 units/s (1000000 Hz)".to_string()),
        section_count: None,
        interface_count: None,
        usable_interfaces: None,
        unusable_interfaces: None,
    };
    let summary = ValidationSummaryDto {
        records_emitted: "42".to_string(),
        total_diagnostics: "0".to_string(),
        had_diagnostics: false,
    };
    let completion = ValidationCompletionDto {
        status: "complete".to_string(),
        is_complete: true,
        terminal_error: None,
    };

    // Table
    let mut table_out = Vec::new();
    report_validation(
        ReportFormat::Table,
        &metadata,
        &summary,
        &completion,
        &[],
        &mut table_out,
    )
    .unwrap();
    let table_str = String::from_utf8(table_out).unwrap();
    assert!(table_str.contains("Format"));
    assert!(table_str.contains("pcap"));

    // JSON
    let mut json_out = Vec::new();
    report_validation(
        ReportFormat::Json,
        &metadata,
        &summary,
        &completion,
        &[],
        &mut json_out,
    )
    .unwrap();
    let json_str = String::from_utf8(json_out).unwrap();
    assert!(json_str.contains("\"schema_version\": \"v1.0\""));
    assert!(json_str.contains("\"kind\": \"validation\""));

    // NDJSON
    let mut ndjson_out = Vec::new();
    report_validation(
        ReportFormat::Ndjson,
        &metadata,
        &summary,
        &completion,
        &[],
        &mut ndjson_out,
    )
    .unwrap();
    let ndjson_str = String::from_utf8(ndjson_out).unwrap();
    assert!(ndjson_str.contains("\"schema_version\":\"v1.0\""));

    // CSV
    let mut csv_out = Vec::new();
    report_validation(
        ReportFormat::Csv,
        &metadata,
        &summary,
        &completion,
        &[],
        &mut csv_out,
    )
    .unwrap();
    let csv_str = String::from_utf8(csv_out).unwrap();
    assert!(csv_str.contains("property,value"));
}

#[test]
fn test_flows_report_all_formats() {
    let flow = make_synthetic_flow();
    let flows = vec![flow];

    // Table
    let mut table_out = Vec::new();
    report_flows(ReportFormat::Table, &flows, &mut table_out).unwrap();
    let table_str = String::from_utf8(table_out).unwrap();
    assert!(table_str.contains("ID     PROTO"));
    assert!(table_str.contains("192.168.1.10:54321"));

    // JSON
    let mut json_out = Vec::new();
    report_flows(ReportFormat::Json, &flows, &mut json_out).unwrap();
    let json_str = String::from_utf8(json_out).unwrap();
    assert!(json_str.contains("\"schema_version\": \"v1.0\""));
    assert!(json_str.contains("\"total_flows\": \"1\""));

    // NDJSON
    let mut ndjson_out = Vec::new();
    report_flows(ReportFormat::Ndjson, &flows, &mut ndjson_out).unwrap();
    let ndjson_str = String::from_utf8(ndjson_out).unwrap();
    let lines: Vec<&str> = ndjson_str.lines().collect();
    assert_eq!(lines.len(), 2); // header + 1 flow

    // CSV
    let mut csv_out = Vec::new();
    report_flows(ReportFormat::Csv, &flows, &mut csv_out).unwrap();
    let csv_str = String::from_utf8(csv_out).unwrap();
    assert!(csv_str.contains("endpoint_a,endpoint_b"));
    assert!(csv_str.contains("93.184.216.34:80,192.168.1.10:54321"));
}

#[test]
fn test_dns_report_all_formats() {
    let obs = make_synthetic_dns_obs();
    let observations = vec![obs];

    // Table
    let mut table_out = Vec::new();
    report_dns(ReportFormat::Table, &observations, &mut table_out).unwrap();
    let table_str = String::from_utf8(table_out).unwrap();
    assert!(table_str.contains("PKT    XPORT"));
    assert!(table_str.contains("example.com"));

    // JSON
    let mut json_out = Vec::new();
    report_dns(ReportFormat::Json, &observations, &mut json_out).unwrap();
    let json_str = String::from_utf8(json_out).unwrap();
    assert!(json_str.contains("\"schema_version\": \"v1.0\""));
    assert!(json_str.contains("\"total_observations\": \"1\""));

    // NDJSON
    let mut ndjson_out = Vec::new();
    report_dns(ReportFormat::Ndjson, &observations, &mut ndjson_out).unwrap();
    let ndjson_str = String::from_utf8(ndjson_out).unwrap();
    let lines: Vec<&str> = ndjson_str.lines().collect();
    assert_eq!(lines.len(), 2); // header + 1 observation

    // CSV
    let mut csv_out = Vec::new();
    report_dns(ReportFormat::Csv, &observations, &mut csv_out).unwrap();
    let csv_str = String::from_utf8(csv_out).unwrap();
    assert!(csv_str.contains("packet_ordinal,transport"));
    assert!(csv_str.contains("example.com"));
}

fn make_synthetic_http_obs() -> pcapraven_domain::HttpObservation {
    let pkt_ref = PacketReference::new(0, None, None, 128, 128, false);
    pcapraven_domain::HttpObservation {
        packet: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        source_ip: IpAddress::Ipv4([192, 168, 1, 10]),
        source_port: 54321,
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

fn make_synthetic_tls_obs() -> pcapraven_domain::TlsObservation {
    let pkt_ref = PacketReference::new(0, None, None, 128, 128, false);
    pcapraven_domain::TlsObservation {
        packet: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        source_ip: IpAddress::Ipv4([192, 168, 1, 10]),
        source_port: 54321,
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

#[test]
fn test_http_report_all_formats() {
    let obs = make_synthetic_http_obs();
    let observations = vec![obs];

    // Table
    let mut table_out = Vec::new();
    pcapraven_reporting::report_http(ReportFormat::Table, &observations, &mut table_out).unwrap();
    let table_str = String::from_utf8(table_out).unwrap();
    assert!(table_str.contains("PKT    KIND"));
    assert!(table_str.contains("example.com"));

    // JSON
    let mut json_out = Vec::new();
    pcapraven_reporting::report_http(ReportFormat::Json, &observations, &mut json_out).unwrap();
    let json_str = String::from_utf8(json_out).unwrap();
    assert!(json_str.contains("\"kind\": \"http\""));
    assert!(json_str.contains("\"total_observations\": \"1\""));

    // NDJSON
    let mut ndjson_out = Vec::new();
    pcapraven_reporting::report_http(ReportFormat::Ndjson, &observations, &mut ndjson_out).unwrap();
    let ndjson_str = String::from_utf8(ndjson_out).unwrap();
    let lines: Vec<&str> = ndjson_str.lines().collect();
    assert_eq!(lines.len(), 2);

    // CSV
    let mut csv_out = Vec::new();
    pcapraven_reporting::report_http(ReportFormat::Csv, &observations, &mut csv_out).unwrap();
    let csv_str = String::from_utf8(csv_out).unwrap();
    assert!(csv_str.contains("packet_ordinal,transport"));
    assert!(csv_str.contains("example.com"));
}

#[test]
fn test_tls_report_all_formats() {
    let obs = make_synthetic_tls_obs();
    let observations = vec![obs];

    // Table
    let mut table_out = Vec::new();
    pcapraven_reporting::report_tls(ReportFormat::Table, &observations, &mut table_out).unwrap();
    let table_str = String::from_utf8(table_out).unwrap();
    assert!(table_str.contains("PKT    KIND"));
    assert!(table_str.contains("example.com"));

    // JSON
    let mut json_out = Vec::new();
    pcapraven_reporting::report_tls(ReportFormat::Json, &observations, &mut json_out).unwrap();
    let json_str = String::from_utf8(json_out).unwrap();
    assert!(json_str.contains("\"kind\": \"tls\""));
    assert!(json_str.contains("\"total_observations\": \"1\""));

    // NDJSON
    let mut ndjson_out = Vec::new();
    pcapraven_reporting::report_tls(ReportFormat::Ndjson, &observations, &mut ndjson_out).unwrap();
    let ndjson_str = String::from_utf8(ndjson_out).unwrap();
    let lines: Vec<&str> = ndjson_str.lines().collect();
    assert_eq!(lines.len(), 2);

    // CSV
    let mut csv_out = Vec::new();
    pcapraven_reporting::report_tls(ReportFormat::Csv, &observations, &mut csv_out).unwrap();
    let csv_str = String::from_utf8(csv_out).unwrap();
    assert!(csv_str.contains("packet_ordinal,source_ip"));
    assert!(csv_str.contains("example.com"));
}

#[test]
fn test_findings_report_all_formats() {
    let (finding, evi) = make_synthetic_finding();
    let findings = vec![&finding];
    let evidence = vec![&evi];

    // Table
    let mut table_out = Vec::new();
    report_findings(
        ReportFormat::Table,
        &findings,
        &evidence,
        None,
        &mut table_out,
    )
    .unwrap();
    let table_str = String::from_utf8(table_out).unwrap();
    assert!(table_str.contains("Possible DNS Tunneling Activity"));
    assert!(table_str.contains("T1071.004"));

    // JSON
    let mut json_out = Vec::new();
    report_findings(
        ReportFormat::Json,
        &findings,
        &evidence,
        None,
        &mut json_out,
    )
    .unwrap();
    let json_str = String::from_utf8(json_out).unwrap();
    assert!(json_str.contains("\"schema_version\": \"v1.0\""));
    assert!(json_str.contains("\"technique_id\": \"T1071.004\""));

    // NDJSON
    let mut ndjson_out = Vec::new();
    report_findings(
        ReportFormat::Ndjson,
        &findings,
        &evidence,
        None,
        &mut ndjson_out,
    )
    .unwrap();
    let ndjson_str = String::from_utf8(ndjson_out).unwrap();
    let lines: Vec<&str> = ndjson_str.lines().collect();
    assert_eq!(lines.len(), 3); // summary + 1 finding + 1 evidence

    // CSV
    let mut csv_out = Vec::new();
    report_findings(ReportFormat::Csv, &findings, &evidence, None, &mut csv_out).unwrap();
    let csv_str = String::from_utf8(csv_out).unwrap();
    assert!(csv_str.contains("id,ordinal,detector_id"));
    assert!(csv_str.contains("T1071.004:TA0011"));
}

#[test]
fn test_analysis_report_formats_and_csv_rejection() {
    let (finding, evi) = make_synthetic_finding();
    let flow = make_synthetic_flow();
    let flows = vec![flow];
    let findings = vec![&finding];

    let mut report = AnalysisReportDto::default();
    report.metadata.format = "pcap".to_string();
    report.summary = AnalysisSummaryDto {
        total_packets: "100".to_string(),
        total_flows: "1".to_string(),
        total_dns_observations: "0".to_string(),
        total_http_observations: "0".to_string(),
        total_tls_observations: "0".to_string(),
        total_findings: "1".to_string(),
        total_evidence_records: "1".to_string(),
    };
    report.completion.status = "complete".to_string();
    report.flows = vec![FlowRecordDto::from_domain(&flows[0])];
    report.findings = vec![FindingRecordDto::from_domain(&finding)];
    report.evidence = vec![EvidenceRecordDto::from_domain(&evi)];

    // Table
    let mut table_out = Vec::new();
    report_analysis(
        ReportFormat::Table,
        &report,
        &flows,
        &findings,
        &mut table_out,
    )
    .unwrap();
    let table_str = String::from_utf8(table_out).unwrap();
    assert!(table_str.contains("PCAPRAVEN ANALYSIS REPORT"));

    // JSON
    let mut json_out = Vec::new();
    report_analysis(
        ReportFormat::Json,
        &report,
        &flows,
        &findings,
        &mut json_out,
    )
    .unwrap();
    let json_str = String::from_utf8(json_out).unwrap();
    assert!(json_str.contains("\"kind\": \"analysis\""));

    // NDJSON
    let mut ndjson_out = Vec::new();
    report_analysis(
        ReportFormat::Ndjson,
        &report,
        &flows,
        &findings,
        &mut ndjson_out,
    )
    .unwrap();
    let ndjson_str = String::from_utf8(ndjson_out).unwrap();
    assert!(ndjson_str.contains("\"kind\":\"analysis\""));

    // CSV MUST BE REJECTED!
    let mut csv_out = Vec::new();
    let err =
        report_analysis(ReportFormat::Csv, &report, &flows, &findings, &mut csv_out).unwrap_err();
    match err {
        ReportError::UnsupportedFormat { format, kind, .. } => {
            assert_eq!(format, ReportFormat::Csv);
            assert_eq!(kind, ReportKind::Analysis);
        }
        other => panic!("expected UnsupportedFormat error, got {other:?}"),
    }
}

#[test]
fn test_csv_formula_injection_defense() {
    assert_eq!(sanitize_csv_cell("=1+1"), "'=1+1");
    assert_eq!(sanitize_csv_cell("+cmd"), "'+cmd");
    assert_eq!(sanitize_csv_cell("-calc"), "'-calc");
    assert_eq!(sanitize_csv_cell("@SUM"), "'@SUM");
    assert_eq!(sanitize_csv_cell("\t=test"), "'\t=test");
    assert_eq!(sanitize_csv_cell("\r=test"), "'\r=test");
    assert_eq!(sanitize_csv_cell("\n=test"), "'\n=test");
    assert_eq!(sanitize_csv_cell("  =test"), "'  =test");
    assert_eq!(sanitize_csv_cell("\tSAFE"), "'\tSAFE");
    assert_eq!(sanitize_csv_cell("\rSAFE"), "'\rSAFE");
    assert_eq!(sanitize_csv_cell("\nSAFE"), "'\nSAFE");
    assert_eq!(sanitize_csv_cell("normal"), "normal");
}

proptest! {
    #[test]
    fn prop_csv_sanitizer_never_allows_unquoted_formula(s in "\\PC*") {
        let sanitized = sanitize_csv_cell(&s);
        let raw_trigger = s.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']);
        let trimmed_trigger = s.trim_start().starts_with(['=', '+', '-', '@']);
        if raw_trigger || trimmed_trigger {
            prop_assert!(sanitized.starts_with('\''));
        } else {
            prop_assert_eq!(&sanitized, &s);
        }
    }
}
