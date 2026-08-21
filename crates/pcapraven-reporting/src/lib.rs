//! Deterministic reporting architecture for PcapRaven.
//!
//! Provides pure presentation and serialization across human-readable ASCII tables,
//! canonical JSON envelopes, newline-delimited JSON (NDJSON) streaming records,
//! and sanitized CSV tables with formula injection protection.

pub mod csv;
pub mod csv_escape;
pub mod dto;
pub mod error;
pub mod format;
pub mod json;
pub mod ndjson;
pub mod table;

pub use csv_escape::sanitize_csv_cell;
pub use dto::*;
pub use error::ReportError;
pub use format::{REPORT_SCHEMA_VERSION, ReportFormat, ReportKind};

use pcapraven_domain::{
    DnsObservation, EvidenceRecord, FindingRecord, FlowRecord, HttpObservation, TlsObservation,
};
use std::io::Write;

/// Dispatches a capture validation report to the requested format.
///
/// # Errors
/// Returns [`ReportError`] on I/O or serialization failures.
pub fn report_validation(
    format: ReportFormat,
    metadata: &ValidationMetadataDto,
    summary: &ValidationSummaryDto,
    completion: &ValidationCompletionDto,
    diagnostics: &[ValidationDiagnosticDto],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let dto = ValidationReportDto {
        schema_version: REPORT_SCHEMA_VERSION,
        kind: ReportKind::Validation.as_str(),
        source_path: None,
        metadata: metadata.clone(),
        summary: summary.clone(),
        diagnostics: diagnostics.to_vec(),
        completion: completion.clone(),
    };

    match format {
        ReportFormat::Table => table::render_validation_table(metadata, summary, completion, w),
        ReportFormat::Json => json::render_validation_json(&dto, w),
        ReportFormat::Ndjson => ndjson::render_validation_ndjson(&dto, w),
        ReportFormat::Csv => csv::render_validation_csv(&dto, w),
    }
}

/// Dispatches a network flows report to the requested format.
///
/// # Errors
/// Returns [`ReportError`] on I/O or serialization failures.
pub fn report_flows(
    format: ReportFormat,
    flows: &[FlowRecord],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    match format {
        ReportFormat::Table => table::render_flows_table(flows, w),
        ReportFormat::Json => {
            let dto = FlowsReportDto::from_domain_flows(flows);
            json::render_flows_json(&dto, w)
        }
        ReportFormat::Ndjson => {
            let dto = FlowsReportDto::from_domain_flows(flows);
            ndjson::render_flows_ndjson(&dto, w)
        }
        ReportFormat::Csv => {
            let dto = FlowsReportDto::from_domain_flows(flows);
            csv::render_flows_csv(&dto, w)
        }
    }
}

/// Dispatches a DNS observation report to the requested format.
///
/// # Errors
/// Returns [`ReportError`] on I/O or serialization failures.
pub fn report_dns(
    format: ReportFormat,
    observations: &[DnsObservation],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    match format {
        ReportFormat::Table => table::render_dns_table(observations, w),
        ReportFormat::Json => {
            let dto = DnsReportDto::from_domain_observations(observations);
            json::render_dns_json(&dto, w)
        }
        ReportFormat::Ndjson => {
            let dto = DnsReportDto::from_domain_observations(observations);
            ndjson::render_dns_ndjson(&dto, w)
        }
        ReportFormat::Csv => {
            let dto = DnsReportDto::from_domain_observations(observations);
            csv::render_dns_csv(&dto, w)
        }
    }
}

/// Dispatches an HTTP observation report to the requested format.
///
/// # Errors
/// Returns [`ReportError`] on I/O or serialization failures.
pub fn report_http(
    format: ReportFormat,
    observations: &[HttpObservation],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    match format {
        ReportFormat::Table => table::render_http_table(observations, w),
        ReportFormat::Json => {
            let dto = HttpReportDto::from_domain_observations(observations);
            json::render_http_json(&dto, w)
        }
        ReportFormat::Ndjson => {
            let dto = HttpReportDto::from_domain_observations(observations);
            ndjson::render_http_ndjson(&dto, w)
        }
        ReportFormat::Csv => {
            let dto = HttpReportDto::from_domain_observations(observations);
            csv::render_http_csv(&dto, w)
        }
    }
}

/// Dispatches a TLS observation report to the requested format.
///
/// # Errors
/// Returns [`ReportError`] on I/O or serialization failures.
pub fn report_tls(
    format: ReportFormat,
    observations: &[TlsObservation],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    match format {
        ReportFormat::Table => table::render_tls_table(observations, w),
        ReportFormat::Json => {
            let dto = TlsReportDto::from_domain_observations(observations);
            json::render_tls_json(&dto, w)
        }
        ReportFormat::Ndjson => {
            let dto = TlsReportDto::from_domain_observations(observations);
            ndjson::render_tls_ndjson(&dto, w)
        }
        ReportFormat::Csv => {
            let dto = TlsReportDto::from_domain_observations(observations);
            csv::render_tls_csv(&dto, w)
        }
    }
}

/// Dispatches an analytical findings report to the requested format.
///
/// # Errors
/// Returns [`ReportError`] on I/O or serialization failures.
pub fn report_findings(
    format: ReportFormat,
    findings: &[&FindingRecord],
    evidence: &[&EvidenceRecord],
    filter: Option<FindingFilterDto>,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    match format {
        ReportFormat::Table => table::render_findings_table(findings, w),
        ReportFormat::Json => {
            let dto = FindingsReportDto::from_domain_findings(findings, evidence, filter);
            json::render_findings_json(&dto, w)
        }
        ReportFormat::Ndjson => {
            let dto = FindingsReportDto::from_domain_findings(findings, evidence, filter);
            ndjson::render_findings_ndjson(&dto, w)
        }
        ReportFormat::Csv => {
            let dto = FindingsReportDto::from_domain_findings(findings, evidence, filter);
            csv::render_findings_csv(&dto, w)
        }
    }
}

/// Dispatches a unified multi-layer analysis report to the requested format.
///
/// # Errors
/// Returns [`ReportError`] on I/O or serialization failures.
/// Note: [`ReportFormat::Csv`] is rejected with [`ReportError::UnsupportedFormat`].
pub fn report_analysis(
    format: ReportFormat,
    report: &AnalysisReportDto,
    flows: &[FlowRecord],
    findings: &[&FindingRecord],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    match format {
        ReportFormat::Table => table::render_analysis_table(
            &report.metadata,
            &report.summary,
            &report.completion,
            flows,
            findings,
            w,
        ),
        ReportFormat::Json => json::render_analysis_json(report, w),
        ReportFormat::Ndjson => ndjson::render_analysis_ndjson(report, w),
        ReportFormat::Csv => csv::render_analysis_csv(report, w),
    }
}
