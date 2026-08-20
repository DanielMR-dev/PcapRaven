//! Serializable DTOs for analytical security findings and MITRE ATT&CK mappings.

use pcapraven_domain::{
    EvidenceMeasurement, EvidenceRatio, EvidenceRecord, EvidenceValue, FindingRecord,
    FindingSubject, MitreMapping,
};
use serde::Serialize;

use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for a findings report in JSON.
#[derive(Debug, Clone, Serialize)]
pub struct FindingsReportDto {
    /// Schema version anchor ("v1.0").
    pub schema_version: &'static str,
    /// Report kind identifier ("findings").
    pub kind: &'static str,
    /// Total count of matching findings.
    pub total_findings: usize,
    /// List of finding records.
    pub findings: Vec<FindingRecordDto>,
    /// Supporting evidence records if included.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceRecordDto>,
}

impl FindingsReportDto {
    /// Constructs a findings report DTO from slices of domain finding and evidence records.
    #[must_use]
    pub fn from_domain_findings(findings: &[&FindingRecord], evidence: &[EvidenceRecord]) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "findings",
            total_findings: findings.len(),
            findings: findings
                .iter()
                .map(|f| FindingRecordDto::from_domain(f))
                .collect(),
            evidence: evidence
                .iter()
                .map(EvidenceRecordDto::from_domain)
                .collect(),
        }
    }
}

/// A canonical analytical finding record.
#[derive(Debug, Clone, Serialize)]
pub struct FindingRecordDto {
    /// Finding reference string (e.g. "find:0").
    pub id: String,
    /// Ordinal index within detection run.
    pub ordinal: u64,
    /// Namespaced detector identifier.
    pub detector_id: String,
    /// Semantic version of detector analytical logic.
    pub detector_version: String,
    /// Concise finding title.
    pub title: String,
    /// High-level summary of the finding.
    pub summary: String,
    /// Technical rationale explaining why the finding was produced.
    pub rationale: String,
    /// Potential security impact ("info", "low", "medium", "high", "critical").
    pub severity: String,
    /// Analytical confidence rating ("low", "medium", "high").
    pub confidence: String,
    /// Supporting traffic entities.
    pub subject: FindingSubjectDto,
    /// Supporting evidence references ("evi:0").
    pub evidence_references: Vec<String>,
    /// Source finding references for correlated findings.
    pub source_finding_references: Vec<String>,
    /// Canonical MITRE ATT&CK mappings.
    pub mitre_mappings: Vec<MitreMappingDto>,
}

impl FindingRecordDto {
    /// Converts a domain [`FindingRecord`] into a serializable DTO.
    #[must_use]
    pub fn from_domain(f: &FindingRecord) -> Self {
        Self {
            id: f.reference().to_string(),
            ordinal: f.reference().id(),
            detector_id: f.detector_id().to_string(),
            detector_version: f.detector_version().to_string(),
            title: f.title().to_string(),
            summary: f.summary().to_string(),
            rationale: f.rationale().to_string(),
            severity: f.severity().to_string(),
            confidence: f.confidence().to_string(),
            subject: FindingSubjectDto::from_domain(f.subject()),
            evidence_references: f
                .evidence_references()
                .iter()
                .map(|e| e.to_string())
                .collect(),
            source_finding_references: f
                .source_finding_references()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            mitre_mappings: f
                .mitre_mappings()
                .iter()
                .map(MitreMappingDto::from_domain)
                .collect(),
        }
    }
}

/// Entities involved in a security finding.
#[derive(Debug, Clone, Serialize)]
pub struct FindingSubjectDto {
    /// Packet references involved in the finding.
    pub packets: Vec<u64>,
    /// Flow references involved in the finding.
    pub flows: Vec<String>,
    /// Observation references involved in the finding.
    pub observations: Vec<String>,
}

impl FindingSubjectDto {
    /// Converts domain [`FindingSubject`] into a DTO.
    #[must_use]
    pub fn from_domain(subject: &FindingSubject) -> Self {
        Self {
            packets: subject
                .packet_references()
                .iter()
                .map(|p| p.capture_record_ordinal())
                .collect(),
            flows: subject
                .flow_references()
                .iter()
                .map(|f| f.to_string())
                .collect(),
            observations: subject
                .observation_references()
                .iter()
                .map(|o| o.to_string())
                .collect(),
        }
    }
}

/// MITRE ATT&CK technique mapping record.
#[derive(Debug, Clone, Serialize)]
pub struct MitreMappingDto {
    /// MITRE ATT&CK domain ("Enterprise").
    pub domain: String,
    /// Knowledge base catalog version ("19.2").
    pub catalog_version: String,
    /// Technique or sub-technique identifier (e.g. "T1071.004").
    pub technique_id: String,
    /// Human-readable technique name.
    pub technique_name: String,
    /// Technique object version (e.g. "1.4").
    pub technique_version: String,
    /// MITRE tactic identifier (e.g. "TA0011").
    pub tactic_id: String,
    /// MITRE tactic name (e.g. "CommandAndControl").
    pub tactic: String,
    /// Mapping relationship ("Analytical").
    pub relationship: String,
    /// Analytical rationale for mapping technique.
    pub rationale: String,
    /// Component provenance stamping origin.
    pub provenance: String,
}

impl MitreMappingDto {
    /// Converts a domain [`MitreMapping`] into a DTO.
    #[must_use]
    pub fn from_domain(m: &MitreMapping) -> Self {
        Self {
            domain: m.domain().to_string(),
            catalog_version: m.catalog_version().to_string(),
            technique_id: m.technique_id().to_string(),
            technique_name: m.technique_name().to_string(),
            technique_version: m.technique_version().to_string(),
            tactic_id: m.tactic().tactic_id().to_string(),
            tactic: m.tactic().to_string(),
            relationship: m.relationship().to_string(),
            rationale: m.rationale().to_string(),
            provenance: m.provenance().to_string(),
        }
    }
}

/// A structured evidence record supporting one or more findings.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceRecordDto {
    /// Evidence reference string (e.g. "evi:0").
    pub id: String,
    /// Evidence kind.
    pub kind: String,
    /// Factual description.
    pub description: String,
    /// Structured factual measurements.
    pub measurements: Vec<EvidenceMeasurementDto>,
    /// Explicit analysis limitations.
    pub limitations: Vec<String>,
}

impl EvidenceRecordDto {
    /// Converts a domain [`EvidenceRecord`] into a DTO.
    #[must_use]
    pub fn from_domain(e: &EvidenceRecord) -> Self {
        Self {
            id: e.reference().to_string(),
            kind: e.kind().as_str().to_string(),
            description: e.description().to_string(),
            measurements: e
                .measurements()
                .iter()
                .map(EvidenceMeasurementDto::from_domain)
                .collect(),
            limitations: e
                .limitations()
                .iter()
                .map(|l| l.as_str().to_string())
                .collect(),
        }
    }
}

/// A single structured factual measurement.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceMeasurementDto {
    /// Metric key string.
    pub metric_key: String,
    /// Observed value.
    pub observed_value: EvidenceValueDto,
    /// Reference threshold value if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<EvidenceValueDto>,
    /// Comparison operator if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<String>,
    /// Measurement unit string.
    pub unit: String,
}

impl EvidenceMeasurementDto {
    /// Converts a domain [`EvidenceMeasurement`] into a DTO.
    #[must_use]
    pub fn from_domain(m: &EvidenceMeasurement) -> Self {
        Self {
            metric_key: m.key().to_string(),
            observed_value: EvidenceValueDto::from_domain(m.observed_value()),
            threshold: m.threshold_value().map(EvidenceValueDto::from_domain),
            comparison: m.comparison().map(|c| c.as_str().to_string()),
            unit: m.unit().as_str().to_string(),
        }
    }
}

/// Typed evidence value representation with full numerical fidelity.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum EvidenceValueDto {
    /// Signed integer value.
    Integer(i128),
    /// Unsigned integer value.
    Unsigned(u128),
    /// Exact rational ratio (reduced fraction).
    Ratio(RatioDto),
    /// Boolean flag.
    Boolean(bool),
    /// Duration in seconds and nanoseconds.
    Duration(crate::dto::flows::DurationDto),
}

impl EvidenceValueDto {
    /// Converts a domain [`EvidenceValue`] into a DTO.
    #[must_use]
    pub fn from_domain(v: &EvidenceValue) -> Self {
        match v {
            EvidenceValue::Integer(i) => Self::Integer(*i),
            EvidenceValue::Unsigned(u) => Self::Unsigned(*u),
            EvidenceValue::Ratio(r) => Self::Ratio(RatioDto::from_domain(r)),
            EvidenceValue::Boolean(b) => Self::Boolean(*b),
            EvidenceValue::Duration(d) => {
                Self::Duration(crate::dto::flows::DurationDto::from_domain(d))
            }
        }
    }
}

/// Exact rational ratio representation.
#[derive(Debug, Clone, Serialize)]
pub struct RatioDto {
    /// Numerator.
    pub numerator: u128,
    /// Denominator (always >= 1).
    pub denominator: u128,
    /// Exact rational string representation ("num/den").
    pub string_representation: String,
}

impl RatioDto {
    /// Converts domain [`EvidenceRatio`] into a DTO.
    #[must_use]
    pub fn from_domain(r: &EvidenceRatio) -> Self {
        Self {
            numerator: r.numerator(),
            denominator: r.denominator(),
            string_representation: r.to_string(),
        }
    }
}
