//! Canonical indented JSON envelope reporter.

use std::io::Write;

use crate::dto::analysis::AnalysisReportDto;
use crate::dto::dns::DnsReportDto;
use crate::dto::findings::FindingsReportDto;
use crate::dto::flows::FlowsReportDto;
use crate::dto::http::HttpReportDto;
use crate::dto::tls::TlsReportDto;
use crate::dto::validation::ValidationReportDto;
use crate::error::ReportError;

/// Renders a validation report as pretty-printed canonical JSON.
pub fn render_validation_json(
    report: &ValidationReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let s = serde_json::to_string_pretty(report)
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Renders a flows report as pretty-printed canonical JSON.
pub fn render_flows_json(report: &FlowsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let s = serde_json::to_string_pretty(report)
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Renders a DNS report as pretty-printed canonical JSON.
pub fn render_dns_json(report: &DnsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let s = serde_json::to_string_pretty(report)
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Renders an HTTP report as pretty-printed canonical JSON.
pub fn render_http_json(report: &HttpReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let s = serde_json::to_string_pretty(report)
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Renders a TLS report as pretty-printed canonical JSON.
pub fn render_tls_json(report: &TlsReportDto, w: &mut impl Write) -> Result<(), ReportError> {
    let s = serde_json::to_string_pretty(report)
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Renders a findings report as pretty-printed canonical JSON.
pub fn render_findings_json(
    report: &FindingsReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let s = serde_json::to_string_pretty(report)
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Renders a unified analysis report as pretty-printed canonical JSON.
pub fn render_analysis_json(
    report: &AnalysisReportDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    let s = serde_json::to_string_pretty(report)
        .map_err(|e| ReportError::Serialization(e.to_string()))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}
