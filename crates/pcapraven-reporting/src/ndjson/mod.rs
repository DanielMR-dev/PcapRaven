//! Newline-delimited JSON (NDJSON) streaming reporter.

use std::io::Write;

use serde::Serialize;

use crate::dto::analysis::{AnalysisReportDto, AnalysisSummaryDto, ReportCompletionDto};
use crate::dto::dns::DnsReportDto;
use crate::dto::findings::{FindingFilterDto, FindingsReportDto};
use crate::dto::flows::FlowsReportDto;
use crate::dto::http::HttpReportDto;
use crate::dto::tls::TlsReportDto;
use crate::dto::validation::{
    ValidationCompletionDto, ValidationMetadataDto, ValidationReportDto, ValidationSummaryDto,
};
use crate::error::ReportError;
use crate::format::REPORT_SCHEMA_VERSION;

#[derive(Serialize)]
struct NdjsonLineEnvelope<'a, T: Serialize> {
    schema_version: &'static str,
    kind: &'static str,
    record_type: &'static str,
    data: &'a T,
}

fn write_ndjson_line<T: Serialize>(w: &mut impl Write, record: &T) -> Result<(), ReportError> {
    let line =
        serde_json::to_string(record).map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

#[derive(Serialize)]
struct ValidationSummaryData<'a> {
    source_path: Option<&'a str>,
    metadata: &'a ValidationMetadataDto,
    summary: &'a ValidationSummaryDto,
    completion: &'a ValidationCompletionDto,
}

/// Renders a validation report as streaming NDJSON records.
pub fn render_validation_ndjson(
    report: &ValidationReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let summary_payload = ValidationSummaryData {
        source_path: report.source_path.as_deref(),
        metadata: &report.metadata,
        summary: &report.summary,
        completion: &report.completion,
    };
    let header = NdjsonLineEnvelope {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "validation",
        record_type: "summary",
        data: &summary_payload,
    };
    write_ndjson_line(w, &header)?;

    for diag in &report.diagnostics {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "validation",
            record_type: "diagnostic",
            data: diag,
        };
        write_ndjson_line(w, &line)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct FlowsSummaryData {
    total_flows: String,
}

/// Renders a flows report as streaming NDJSON records.
pub fn render_flows_ndjson(report: &FlowsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let summary_payload = FlowsSummaryData {
        total_flows: report.total_flows.clone(),
    };
    let header = NdjsonLineEnvelope {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "flows",
        record_type: "summary",
        data: &summary_payload,
    };
    write_ndjson_line(w, &header)?;

    for flow in &report.flows {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "flows",
            record_type: "flow",
            data: flow,
        };
        write_ndjson_line(w, &line)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct DnsSummaryData {
    total_observations: String,
}

/// Renders a DNS report as streaming NDJSON records.
pub fn render_dns_ndjson(report: &DnsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let summary_payload = DnsSummaryData {
        total_observations: report.total_observations.clone(),
    };
    let header = NdjsonLineEnvelope {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "dns",
        record_type: "summary",
        data: &summary_payload,
    };
    write_ndjson_line(w, &header)?;

    for obs in &report.observations {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "dns",
            record_type: "dns",
            data: obs,
        };
        write_ndjson_line(w, &line)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct HttpSummaryData {
    total_observations: String,
}

/// Renders an HTTP report as streaming NDJSON records.
pub fn render_http_ndjson(report: &HttpReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let summary_payload = HttpSummaryData {
        total_observations: report.total_observations.clone(),
    };
    let header = NdjsonLineEnvelope {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "http",
        record_type: "summary",
        data: &summary_payload,
    };
    write_ndjson_line(w, &header)?;

    for obs in &report.observations {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "http",
            record_type: "http",
            data: obs,
        };
        write_ndjson_line(w, &line)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct TlsSummaryData {
    total_observations: String,
}

/// Renders a TLS report as streaming NDJSON records.
pub fn render_tls_ndjson(report: &TlsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let summary_payload = TlsSummaryData {
        total_observations: report.total_observations.clone(),
    };
    let header = NdjsonLineEnvelope {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "tls",
        record_type: "summary",
        data: &summary_payload,
    };
    write_ndjson_line(w, &header)?;

    for obs in &report.observations {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "tls",
            record_type: "tls",
            data: obs,
        };
        write_ndjson_line(w, &line)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct FindingsSummaryData<'a> {
    total_findings: String,
    total_evidence_records: String,
    filter: Option<&'a FindingFilterDto>,
}

/// Renders a findings report as streaming NDJSON records.
pub fn render_findings_ndjson(
    report: &FindingsReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let summary_payload = FindingsSummaryData {
        total_findings: report.total_findings.clone(),
        total_evidence_records: report.total_evidence_records.clone(),
        filter: report.filter.as_ref(),
    };
    let header = NdjsonLineEnvelope {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "findings",
        record_type: "summary",
        data: &summary_payload,
    };
    write_ndjson_line(w, &header)?;

    for finding in &report.findings {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "findings",
            record_type: "finding",
            data: finding,
        };
        write_ndjson_line(w, &line)?;
    }
    for evi in &report.evidence {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "findings",
            record_type: "evidence",
            data: evi,
        };
        write_ndjson_line(w, &line)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct AnalysisSummaryData<'a> {
    metadata: &'a ValidationMetadataDto,
    summary: &'a AnalysisSummaryDto,
    completion: &'a ReportCompletionDto,
    filter: Option<&'a FindingFilterDto>,
}

/// Renders a unified analysis report as streaming NDJSON records.
pub fn render_analysis_ndjson(
    report: &AnalysisReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let summary_payload = AnalysisSummaryData {
        metadata: &report.metadata,
        summary: &report.summary,
        completion: &report.completion,
        filter: report.filter.as_ref(),
    };
    let header = NdjsonLineEnvelope {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: "analysis",
        record_type: "summary",
        data: &summary_payload,
    };
    write_ndjson_line(w, &header)?;

    for flow in &report.flows {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "analysis",
            record_type: "flow",
            data: flow,
        };
        write_ndjson_line(w, &line)?;
    }
    for obs in &report.observations {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "analysis",
            record_type: "observation",
            data: obs,
        };
        write_ndjson_line(w, &line)?;
    }
    for evi in &report.evidence {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "analysis",
            record_type: "evidence",
            data: evi,
        };
        write_ndjson_line(w, &line)?;
    }
    for finding in &report.findings {
        let line = NdjsonLineEnvelope {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "analysis",
            record_type: "finding",
            data: finding,
        };
        write_ndjson_line(w, &line)?;
    }
    Ok(())
}
