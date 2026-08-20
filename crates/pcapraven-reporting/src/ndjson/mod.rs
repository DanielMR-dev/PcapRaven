//! Newline-delimited JSON (NDJSON) streaming reporter.

use std::io::Write;

use serde::Serialize;

use crate::dto::analysis::AnalysisReportDto;
use crate::dto::dns::DnsReportDto;
use crate::dto::findings::FindingsReportDto;
use crate::dto::flows::FlowsReportDto;
use crate::dto::http::HttpReportDto;
use crate::dto::tls::TlsReportDto;
use crate::dto::validation::ValidationReportDto;
use crate::error::ReportError;
use crate::format::REPORT_SCHEMA_VERSION;

#[derive(Serialize)]
struct NdjsonHeaderDto {
    schema_version: &'static str,
    record_type: &'static str,
    kind: &'static str,
    total_records: usize,
}

fn write_ndjson_line<T: Serialize>(w: &mut impl Write, record: &T) -> Result<(), ReportError> {
    let line =
        serde_json::to_string(record).map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Renders a validation report as NDJSON.
pub fn render_validation_ndjson(
    report: &ValidationReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    write_ndjson_line(w, report)
}

/// Renders a flows report as streaming NDJSON records.
pub fn render_flows_ndjson(report: &FlowsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let header = NdjsonHeaderDto {
        schema_version: REPORT_SCHEMA_VERSION,
        record_type: "header",
        kind: "flows",
        total_records: report.total_flows,
    };
    write_ndjson_line(w, &header)?;

    for flow in &report.flows {
        write_ndjson_line(w, flow)?;
    }
    Ok(())
}

/// Renders a DNS report as streaming NDJSON records.
pub fn render_dns_ndjson(report: &DnsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let header = NdjsonHeaderDto {
        schema_version: REPORT_SCHEMA_VERSION,
        record_type: "header",
        kind: "dns",
        total_records: report.total_observations,
    };
    write_ndjson_line(w, &header)?;

    for obs in &report.observations {
        write_ndjson_line(w, obs)?;
    }
    Ok(())
}

/// Renders an HTTP report as streaming NDJSON records.
pub fn render_http_ndjson(report: &HttpReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let header = NdjsonHeaderDto {
        schema_version: REPORT_SCHEMA_VERSION,
        record_type: "header",
        kind: "http",
        total_records: report.total_observations,
    };
    write_ndjson_line(w, &header)?;

    for obs in &report.observations {
        write_ndjson_line(w, obs)?;
    }
    Ok(())
}

/// Renders a TLS report as streaming NDJSON records.
pub fn render_tls_ndjson(report: &TlsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let header = NdjsonHeaderDto {
        schema_version: REPORT_SCHEMA_VERSION,
        record_type: "header",
        kind: "tls",
        total_records: report.total_observations,
    };
    write_ndjson_line(w, &header)?;

    for obs in &report.observations {
        write_ndjson_line(w, obs)?;
    }
    Ok(())
}

/// Renders a findings report as streaming NDJSON records.
pub fn render_findings_ndjson(
    report: &FindingsReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let header = NdjsonHeaderDto {
        schema_version: REPORT_SCHEMA_VERSION,
        record_type: "header",
        kind: "findings",
        total_records: report.total_findings,
    };
    write_ndjson_line(w, &header)?;

    for finding in &report.findings {
        write_ndjson_line(w, finding)?;
    }
    for evi in &report.evidence {
        write_ndjson_line(w, evi)?;
    }
    Ok(())
}

/// Renders a unified analysis report as streaming NDJSON records.
pub fn render_analysis_ndjson(
    report: &AnalysisReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let header = NdjsonHeaderDto {
        schema_version: REPORT_SCHEMA_VERSION,
        record_type: "header",
        kind: "analysis",
        total_records: report.summary.total_packets as usize,
    };
    write_ndjson_line(w, &header)?;
    write_ndjson_line(w, &report.metadata)?;
    write_ndjson_line(w, &report.summary)?;

    for flow in &report.flows {
        write_ndjson_line(w, flow)?;
    }
    for obs in &report.dns {
        write_ndjson_line(w, obs)?;
    }
    for obs in &report.http {
        write_ndjson_line(w, obs)?;
    }
    for obs in &report.tls {
        write_ndjson_line(w, obs)?;
    }
    for finding in &report.findings {
        write_ndjson_line(w, finding)?;
    }
    for evi in &report.evidence {
        write_ndjson_line(w, evi)?;
    }
    write_ndjson_line(w, &report.completion)?;
    Ok(())
}
