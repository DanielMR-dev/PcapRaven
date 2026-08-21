//! Tabular CSV reporter with formula injection defense.

use std::io::Write;

use crate::csv_escape::sanitize_csv_cell;
use crate::dto::dns::DnsReportDto;
use crate::dto::findings::FindingsReportDto;
use crate::dto::flows::FlowsReportDto;
use crate::dto::http::HttpReportDto;
use crate::dto::tls::TlsReportDto;
use crate::dto::validation::ValidationReportDto;
use crate::error::ReportError;
use crate::format::{ReportFormat, ReportKind};

fn build_csv_writer<W: Write>(w: W) -> csv::Writer<W> {
    csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(w)
}

/// Renders a validation report as a 2-column key/value CSV table.
pub fn render_validation_csv(
    report: &ValidationReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let mut writer = build_csv_writer(w);
    writer
        .write_record(["property", "value"])
        .map_err(|e| ReportError::Serialization(e.to_string()))?;

    let rows: [(&str, String); 8] = [
        ("schema_version", sanitize_csv_cell(report.schema_version)),
        ("format", sanitize_csv_cell(&report.metadata.format)),
        ("completion", sanitize_csv_cell(&report.completion.status)),
        (
            "records_emitted",
            sanitize_csv_cell(&report.summary.records_emitted),
        ),
        (
            "total_diagnostics",
            sanitize_csv_cell(&report.summary.total_diagnostics),
        ),
        (
            "version",
            if let (Some(maj), Some(min)) =
                (report.metadata.version_major, report.metadata.version_minor)
            {
                format!("{maj}.{min}")
            } else {
                "-".to_string()
            },
        ),
        (
            "linktype",
            report
                .metadata
                .linktype
                .map(|l| l.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "snaplen",
            report
                .metadata
                .snaplen
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
    ];

    for (k, v) in rows {
        writer
            .write_record([sanitize_csv_cell(k), v])
            .map_err(|e| ReportError::Serialization(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    Ok(())
}

/// Renders a flows report as a CSV table with formula injection defense.
pub fn render_flows_csv(report: &FlowsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let mut writer = build_csv_writer(w);
    writer
        .write_record([
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
        ])
        .map_err(|e| ReportError::Serialization(e.to_string()))?;

    for f in &report.flows {
        let dur_num = f
            .temporal
            .duration
            .as_ref()
            .map(|d| d.numerator.clone())
            .unwrap_or_else(|| "-".to_string());
        let dur_den = f
            .temporal
            .duration
            .as_ref()
            .map(|d| d.denominator.clone())
            .unwrap_or_else(|| "-".to_string());
        let dur_disp = f
            .temporal
            .duration
            .as_ref()
            .map(|d| d.display.as_str())
            .unwrap_or_else(|| f.temporal.unavailable_reason.as_deref().unwrap_or("-"));

        writer
            .write_record([
                sanitize_csv_cell(&f.id),
                sanitize_csv_cell(&f.ordinal),
                sanitize_csv_cell(&f.protocol),
                sanitize_csv_cell(&f.endpoint_a),
                sanitize_csv_cell(&f.endpoint_b),
                sanitize_csv_cell(&f.traffic.total.packet_count),
                sanitize_csv_cell(&f.traffic.a_to_b.packet_count),
                sanitize_csv_cell(&f.traffic.b_to_a.packet_count),
                sanitize_csv_cell(&f.traffic.same_endpoint.packet_count),
                sanitize_csv_cell(&f.traffic.total.captured_bytes),
                sanitize_csv_cell(&f.traffic.a_to_b.captured_bytes),
                sanitize_csv_cell(&f.traffic.b_to_a.captured_bytes),
                sanitize_csv_cell(&f.traffic.total.wire_bytes),
                sanitize_csv_cell(&f.traffic.a_to_b.wire_bytes),
                sanitize_csv_cell(&f.traffic.b_to_a.wire_bytes),
                dur_num,
                dur_den,
                sanitize_csv_cell(dur_disp),
                sanitize_csv_cell(&f.end_reason),
            ])
            .map_err(|e| ReportError::Serialization(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    Ok(())
}

/// Renders a DNS report as a CSV table with formula injection defense.
pub fn render_dns_csv(report: &DnsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let mut writer = build_csv_writer(w);
    writer
        .write_record([
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
        ])
        .map_err(|e| ReportError::Serialization(e.to_string()))?;

    for obs in &report.observations {
        let (qname, qtype, qclass) = if let Some(q) = obs.questions.first() {
            (&q.name, q.qtype_name.as_str(), q.qclass.to_string())
        } else {
            (&"-".to_string(), "-", "-".to_string())
        };

        writer
            .write_record([
                sanitize_csv_cell(&obs.packet_ordinal),
                sanitize_csv_cell(&obs.transport),
                sanitize_csv_cell(&obs.source_ip),
                obs.source_port.to_string(),
                sanitize_csv_cell(&obs.destination_ip),
                obs.destination_port.to_string(),
                obs.transaction_id.to_string(),
                sanitize_csv_cell(&obs.message_kind),
                obs.opcode.to_string(),
                obs.authoritative_answer.to_string(),
                obs.truncation.to_string(),
                obs.recursion_desired.to_string(),
                obs.recursion_available.to_string(),
                obs.response_code.to_string(),
                sanitize_csv_cell(qname),
                sanitize_csv_cell(qtype),
                qclass,
                obs.answers.len().to_string(),
                obs.edns.is_some().to_string(),
                sanitize_csv_cell(&obs.completeness),
            ])
            .map_err(|e| ReportError::Serialization(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    Ok(())
}

/// Renders an HTTP report as a CSV table with formula injection defense.
pub fn render_http_csv(report: &HttpReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let mut writer = build_csv_writer(w);
    writer
        .write_record([
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
        ])
        .map_err(|e| ReportError::Serialization(e.to_string()))?;

    for obs in &report.observations {
        let method = obs
            .request
            .as_ref()
            .map(|r| r.method.as_str())
            .unwrap_or("-");
        let target = obs
            .request
            .as_ref()
            .map(|r| r.target.as_str())
            .unwrap_or("-");
        let status = obs
            .response
            .as_ref()
            .map(|r| r.status_code.to_string())
            .unwrap_or_else(|| "-".to_string());

        writer
            .write_record([
                sanitize_csv_cell(&obs.packet_ordinal),
                sanitize_csv_cell(obs.transport),
                sanitize_csv_cell(&obs.source_ip),
                obs.source_port.to_string(),
                sanitize_csv_cell(&obs.destination_ip),
                obs.destination_port.to_string(),
                sanitize_csv_cell(&obs.message_kind),
                sanitize_csv_cell(&obs.version),
                sanitize_csv_cell(method),
                sanitize_csv_cell(target),
                status,
                sanitize_csv_cell(obs.headers.host.as_deref().unwrap_or("-")),
                sanitize_csv_cell(obs.headers.content_type.as_deref().unwrap_or("-")),
                sanitize_csv_cell(&obs.headers.content_length),
                sanitize_csv_cell(obs.headers.transfer_encoding.as_deref().unwrap_or("-")),
                sanitize_csv_cell(obs.headers.server.as_deref().unwrap_or("-")),
                sanitize_csv_cell(obs.headers.user_agent.as_deref().unwrap_or("-")),
                obs.headers
                    .sensitive_headers
                    .authorization_present
                    .to_string(),
                obs.headers.sensitive_headers.cookie_present.to_string(),
                obs.headers.sensitive_headers.set_cookie_present.to_string(),
                obs.headers
                    .sensitive_headers
                    .proxy_authorization_present
                    .to_string(),
                sanitize_csv_cell(&obs.completeness),
            ])
            .map_err(|e| ReportError::Serialization(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    Ok(())
}

/// Renders a TLS report as a CSV table with formula injection defense.
pub fn render_tls_csv(report: &TlsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let mut writer = build_csv_writer(w);
    writer
        .write_record([
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
        ])
        .map_err(|e| ReportError::Serialization(e.to_string()))?;

    for obs in &report.observations {
        let (client_ver, server_ver, sel_ver, cipher, sni, alpn, ciphers_cnt, exts_cnt) =
            if let Some(ch) = &obs.client_hello {
                (
                    ch.client_version.as_str(),
                    "-",
                    "-",
                    "-".to_string(),
                    ch.server_name.as_deref().unwrap_or("-"),
                    ch.alpn_protocols.join(";"),
                    ch.cipher_suites.len().to_string(),
                    ch.extensions.len().to_string(),
                )
            } else if let Some(sh) = &obs.server_hello {
                (
                    "-",
                    sh.server_version.as_str(),
                    sh.selected_version.as_deref().unwrap_or("-"),
                    sh.selected_cipher_suite.clone(),
                    "-",
                    sh.selected_alpn.as_deref().unwrap_or("-").to_string(),
                    "-".to_string(),
                    sh.extensions.len().to_string(),
                )
            } else {
                (
                    "-",
                    "-",
                    "-",
                    "-".to_string(),
                    "-",
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                )
            };

        writer
            .write_record([
                sanitize_csv_cell(&obs.packet_ordinal),
                sanitize_csv_cell(&obs.source_ip),
                obs.source_port.to_string(),
                sanitize_csv_cell(&obs.destination_ip),
                obs.destination_port.to_string(),
                sanitize_csv_cell(&obs.record_version),
                sanitize_csv_cell(&obs.handshake_kind),
                sanitize_csv_cell(client_ver),
                sanitize_csv_cell(server_ver),
                sanitize_csv_cell(sel_ver),
                sanitize_csv_cell(&cipher),
                sanitize_csv_cell(sni),
                sanitize_csv_cell(&alpn),
                ciphers_cnt,
                exts_cnt,
                sanitize_csv_cell(&obs.completeness),
            ])
            .map_err(|e| ReportError::Serialization(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    Ok(())
}

/// Renders a findings report as a CSV table with formula injection defense.
pub fn render_findings_csv(
    report: &FindingsReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let mut writer = build_csv_writer(w);
    writer
        .write_record([
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
        ])
        .map_err(|e| ReportError::Serialization(e.to_string()))?;

    for f in &report.findings {
        let pkts_str = f
            .subject
            .packets
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(";");
        let flows_str = f.subject.flows.join(";");
        let obss_str = f.subject.observations.join(";");
        let evi_str = f.evidence_references.join(";");
        let src_str = f.source_finding_references.join(";");
        let mitre_str = f
            .mitre_mappings
            .iter()
            .map(|m| format!("{}:{}", m.technique_id, m.tactic_id))
            .collect::<Vec<_>>()
            .join(";");

        writer
            .write_record([
                sanitize_csv_cell(&f.id),
                sanitize_csv_cell(&f.ordinal),
                sanitize_csv_cell(&f.detector_id),
                sanitize_csv_cell(&f.detector_version),
                sanitize_csv_cell(&f.title),
                sanitize_csv_cell(&f.summary),
                sanitize_csv_cell(&f.rationale),
                sanitize_csv_cell(&f.severity),
                sanitize_csv_cell(&f.confidence),
                sanitize_csv_cell(&pkts_str),
                sanitize_csv_cell(&flows_str),
                sanitize_csv_cell(&obss_str),
                sanitize_csv_cell(&evi_str),
                sanitize_csv_cell(&src_str),
                sanitize_csv_cell(&mitre_str),
            ])
            .map_err(|e| ReportError::Serialization(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    Ok(())
}

/// Rejects CSV formatting for multi-section hierarchical Analysis reports.
pub fn render_analysis_csv(
    _report: &crate::dto::analysis::AnalysisReportDto,
    _w: &mut impl Write,
) -> Result<(), ReportError> {
    Err(ReportError::UnsupportedFormat {
        format: ReportFormat::Csv,
        kind: ReportKind::Analysis,
        rationale: "hierarchical multi-section analysis report cannot be represented as a single flat CSV table; use table, json, or ndjson",
    })
}
