//! Serializable DTOs for unified multi-layer capture analysis reports.

use pcapraven_domain::{
    FlowDirection, ObservationFlowAssociation, ProtocolObservation, ProtocolObservationData,
};
use serde::Serialize;

use super::dns::DnsObservationDto;
use super::findings::{EvidenceRecordDto, FindingFilterDto, FindingRecordDto};
use super::flows::FlowRecordDto;
use super::http::HttpObservationDto;
use super::tls::TlsObservationDto;
use super::validation::ValidationMetadataDto;
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
    /// Overall completion state and structured limitations.
    pub completion: ReportCompletionDto,
    /// Active finding filter configuration if filtered.
    pub filter: Option<FindingFilterDto>,
    /// Reconstructed network flows.
    pub flows: Vec<FlowRecordDto>,
    /// Unified protocol observations in canonical reference order.
    pub observations: Vec<ProtocolObservationDto>,
    /// Supporting structured evidence records.
    pub evidence: Vec<EvidenceRecordDto>,
    /// Analytical threat-hunting security findings.
    pub findings: Vec<FindingRecordDto>,
}

impl Default for AnalysisReportDto {
    fn default() -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "analysis",
            metadata: ValidationMetadataDto::default(),
            summary: AnalysisSummaryDto::default(),
            completion: ReportCompletionDto::default(),
            filter: None,
            flows: Vec::new(),
            observations: Vec::new(),
            evidence: Vec::new(),
            findings: Vec::new(),
        }
    }
}

/// Whole-analysis completion state and structured limitations.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReportCompletionDto {
    /// Status string: "complete", "partial", or "failed".
    pub status: String,
    /// Finite limitation tokens encountered during processing.
    pub limitations: Vec<String>,
}

/// Analysis summary counters with wide decimal string representations.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalysisSummaryDto {
    /// Total packet records emitted by the capture reader.
    pub total_packets: String,
    /// Total reconstructed network flows.
    pub total_flows: String,
    /// Total normalized DNS observations.
    pub total_dns_observations: String,
    /// Total normalized HTTP observations.
    pub total_http_observations: String,
    /// Total normalized TLS observations.
    pub total_tls_observations: String,
    /// Total analytical findings produced.
    pub total_findings: String,
    /// Total structured evidence records produced.
    pub total_evidence_records: String,
}

/// A unified protocol observation record preserving observation identity and flow association facts.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolObservationDto {
    /// Monotonic observation reference string (e.g. "obs:0:dns:0").
    pub id: String,
    /// Protocol family name ("dns", "http", "tls").
    pub protocol: String,
    /// Packet record ordinal as a decimal string.
    pub packet_reference: String,
    /// Completeness status ("complete" or "partial").
    pub completeness: String,
    /// Flow association facts.
    pub association: ObservationFlowAssociationDto,
    /// Typed protocol data payload.
    pub data: ProtocolObservationDataDto,
}

impl ProtocolObservationDto {
    /// Converts a domain [`ProtocolObservation`] into a serializable DTO.
    #[must_use]
    pub fn from_domain(obs: &ProtocolObservation) -> Self {
        let (proto_str, dns_dto, http_dto, tls_dto) = match obs.data() {
            ProtocolObservationData::Dns(d) => {
                ("dns", Some(DnsObservationDto::from_domain(d)), None, None)
            }
            ProtocolObservationData::Http(h) => {
                ("http", None, Some(HttpObservationDto::from_domain(h)), None)
            }
            ProtocolObservationData::Tls(t) => {
                ("tls", None, None, Some(TlsObservationDto::from_domain(t)))
            }
        };

        Self {
            id: obs.reference().to_string(),
            protocol: proto_str.to_string(),
            packet_reference: obs.packet_reference().capture_record_ordinal().to_string(),
            completeness: if obs.completeness().is_complete() {
                "complete".to_string()
            } else {
                "partial".to_string()
            },
            association: ObservationFlowAssociationDto::from_domain(obs.flow_association()),
            data: ProtocolObservationDataDto {
                dns: dns_dto,
                http: http_dto,
                tls: tls_dto,
            },
        }
    }
}

/// Structured flow association facts for a protocol observation.
#[derive(Debug, Clone, Serialize)]
pub struct ObservationFlowAssociationDto {
    /// Association state ("associated", "excluded", "unassociated").
    pub status: String,
    /// Flow reference string if associated.
    pub flow_reference: Option<String>,
    /// Direction relative to endpoint A ("a_to_b", "b_to_a", "same_endpoint") if associated.
    pub direction: Option<String>,
    /// Exclusion reason if excluded.
    pub exclusion_reason: Option<String>,
}

impl ObservationFlowAssociationDto {
    /// Converts domain [`ObservationFlowAssociation`] into a DTO.
    #[must_use]
    pub fn from_domain(assoc: &ObservationFlowAssociation) -> Self {
        match assoc {
            ObservationFlowAssociation::Associated { flow, direction } => {
                let dir_str = match direction {
                    FlowDirection::AToB => "a_to_b",
                    FlowDirection::BToA => "b_to_a",
                    FlowDirection::SameEndpoint => "same_endpoint",
                };
                Self {
                    status: "associated".to_string(),
                    flow_reference: Some(flow.to_string()),
                    direction: Some(dir_str.to_string()),
                    exclusion_reason: None,
                }
            }
            ObservationFlowAssociation::Excluded(reason) => Self {
                status: "excluded".to_string(),
                flow_reference: None,
                direction: None,
                exclusion_reason: Some(reason.as_str().to_string()),
            },
            ObservationFlowAssociation::Unassociated => Self {
                status: "unassociated".to_string(),
                flow_reference: None,
                direction: None,
                exclusion_reason: None,
            },
        }
    }
}

/// Typed observation payload container.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolObservationDataDto {
    /// DNS observation metadata if DNS.
    pub dns: Option<DnsObservationDto>,
    /// HTTP observation metadata if HTTP.
    pub http: Option<HttpObservationDto>,
    /// TLS observation metadata if TLS.
    pub tls: Option<TlsObservationDto>,
}
