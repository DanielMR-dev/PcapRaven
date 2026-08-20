//! Serializable DTOs for unified multi-layer capture analysis reports.

use serde::Serialize;

use super::dns::DnsObservationDto;
use super::findings::{EvidenceRecordDto, FindingRecordDto};
use super::flows::FlowRecordDto;
use super::http::HttpObservationDto;
use super::tls::TlsObservationDto;
use super::validation::{ValidationCompletionDto, ValidationMetadataDto};
use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for a unified analysis report in JSON.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReportDto {
    /// Schema version anchor ("v1.0").
    pub schema_version: &'static str,
    /// Report kind identifier ("analysis").
    pub kind: &'static str,
    /// Capture container metadata.
    pub metadata: ValidationMetadataDto,
    /// High-level analysis summary counters.
    pub summary: AnalysisSummaryDto,
    /// Overall completion state.
    pub completion: ValidationCompletionDto,
    /// Reconstructed network flows.
    pub flows: Vec<FlowRecordDto>,
    /// Normalized DNS observations.
    pub dns: Vec<DnsObservationDto>,
    /// Normalized HTTP observations.
    pub http: Vec<HttpObservationDto>,
    /// Normalized TLS observations.
    pub tls: Vec<TlsObservationDto>,
    /// Analytical threat-hunting security findings.
    pub findings: Vec<FindingRecordDto>,
    /// Supporting structured evidence records.
    pub evidence: Vec<EvidenceRecordDto>,
}

impl Default for AnalysisReportDto {
    fn default() -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "analysis",
            metadata: ValidationMetadataDto::default(),
            summary: AnalysisSummaryDto::default(),
            completion: ValidationCompletionDto::default(),
            flows: Vec::new(),
            dns: Vec::new(),
            http: Vec::new(),
            tls: Vec::new(),
            findings: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

/// Analysis summary counters.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalysisSummaryDto {
    /// Total packet records emitted by the capture reader.
    pub total_packets: u64,
    /// Total reconstructed network flows.
    pub total_flows: usize,
    /// Total normalized DNS observations.
    pub total_dns_observations: usize,
    /// Total normalized HTTP observations.
    pub total_http_observations: usize,
    /// Total normalized TLS observations.
    pub total_tls_observations: usize,
    /// Total analytical findings produced.
    pub total_findings: usize,
    /// Total structured evidence records produced.
    pub total_evidence_records: usize,
}
