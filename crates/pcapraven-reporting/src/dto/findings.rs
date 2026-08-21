//! Serializable DTOs for analytical security findings and MITRE ATT&CK mappings.

use pcapraven_domain::{
    Confidence, EvidenceMeasurement, EvidenceRatio, EvidenceRecord, EvidenceValue, FindingRecord,
    FindingSubject, MitreMapping, MitreMappingProvenance, Severity,
};
use serde::Serialize;

use crate::dto::flows::DurationDto;
use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for a findings report in JSON.
#[derive(Debug, Clone, Serialize)]
pub struct FindingsReportDto {
    /// Schema version anchor ("v1.0").
    pub schema_version: &'static str,
    /// Report kind identifier ("findings").
    pub kind: &'static str,
    /// Total count of matching findings (string decimal).
    pub total_findings: String,
    /// Total count of matching evidence records (string decimal).
    pub total_evidence_records: String,
    /// Active finding filter configuration if filtered.
    pub filter: Option<FindingFilterDto>,
    /// List of finding records.
    pub findings: Vec<FindingRecordDto>,
    /// Supporting evidence records.
    pub evidence: Vec<EvidenceRecordDto>,
}

impl FindingsReportDto {
    /// Constructs a findings report DTO from slices of domain finding and evidence records.
    #[must_use]
    pub fn from_domain_findings(
        findings: &[&FindingRecord],
        evidence: &[&EvidenceRecord],
        filter: Option<FindingFilterDto>,
    ) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "findings",
            total_findings: findings.len().to_string(),
            total_evidence_records: evidence.len().to_string(),
            filter,
            findings: findings
                .iter()
                .map(|f| FindingRecordDto::from_domain(f))
                .collect(),
            evidence: evidence
                .iter()
                .map(|e| EvidenceRecordDto::from_domain(e))
                .collect(),
        }
    }
}

/// Filter settings applied to finding reports.
#[derive(Debug, Clone, Serialize)]
pub struct FindingFilterDto {
    /// Minimum severity filter ("low", "medium", "high", "critical").
    pub min_severity: Option<String>,
    /// Minimum confidence rating filter ("low", "medium", "high").
    pub min_confidence: Option<String>,
    /// Exact detector ID filter.
    pub detector_id: Option<String>,
    /// MITRE ATT&CK technique or sub-technique ID filter.
    pub mitre_attack_id: Option<String>,
}

/// A canonical analytical finding record.
#[derive(Debug, Clone, Serialize)]
pub struct FindingRecordDto {
    /// Finding reference string (e.g. "find:0").
    pub id: String,
    /// Ordinal index within detection run as a decimal string.
    pub ordinal: String,
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
        let sev_str = match f.severity() {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };

        let conf_str = match f.confidence() {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        };

        Self {
            id: f.reference().to_string(),
            ordinal: f.reference().id().to_string(),
            detector_id: f.detector_id().to_string(),
            detector_version: f.detector_version().to_string(),
            title: f.title().to_string(),
            summary: f.summary().to_string(),
            rationale: f.rationale().to_string(),
            severity: sev_str.to_string(),
            confidence: conf_str.to_string(),
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
    /// Packet references involved in the finding as decimal string ordinals.
    pub packets: Vec<String>,
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
                .map(|p| p.capture_record_ordinal().to_string())
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

/// Structured provenance stamping for a MITRE ATT&CK mapping.
#[derive(Debug, Clone, Serialize)]
pub struct MitreMappingProvenanceDto {
    /// Originating component kind ("detector" or "correlator").
    pub kind: String,
    /// Originating component identifier.
    pub component_id: String,
    /// Originating component version.
    pub component_version: String,
}

/// MITRE ATT&CK technique mapping record.
#[derive(Debug, Clone, Serialize)]
pub struct MitreMappingDto {
    /// MITRE ATT&CK domain ("enterprise").
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
    /// MITRE tactic name ("command_and_control", "initial_access", etc.).
    pub tactic: String,
    /// Mapping relationship ("analytical").
    pub relationship: String,
    /// Analytical rationale for mapping technique.
    pub rationale: String,
    /// Structured component provenance stamping origin.
    pub provenance: MitreMappingProvenanceDto,
}

impl MitreMappingDto {
    /// Converts a domain [`MitreMapping`] into a DTO.
    #[must_use]
    pub fn from_domain(m: &MitreMapping) -> Self {
        let domain_str = match m.domain() {
            pcapraven_domain::MitreAttackDomain::Enterprise => "enterprise",
        };

        let tactic_str = match m.tactic() {
            pcapraven_domain::MitreTactic::InitialAccess => "initial_access",
            pcapraven_domain::MitreTactic::Execution => "execution",
            pcapraven_domain::MitreTactic::Persistence => "persistence",
            pcapraven_domain::MitreTactic::PrivilegeEscalation => "privilege_escalation",
            pcapraven_domain::MitreTactic::DefenseEvasion => "defense_evasion",
            pcapraven_domain::MitreTactic::CredentialAccess => "credential_access",
            pcapraven_domain::MitreTactic::Discovery => "discovery",
            pcapraven_domain::MitreTactic::LateralMovement => "lateral_movement",
            pcapraven_domain::MitreTactic::Collection => "collection",
            pcapraven_domain::MitreTactic::CommandAndControl => "command_and_control",
            pcapraven_domain::MitreTactic::Exfiltration => "exfiltration",
            pcapraven_domain::MitreTactic::Impact => "impact",
        };

        let relationship_str = match m.relationship() {
            pcapraven_domain::MitreAttackRelationship::Analytical => "analytical",
        };

        let provenance_dto = match m.provenance() {
            MitreMappingProvenance::DetectorDeclared {
                detector_id,
                detector_version,
            } => MitreMappingProvenanceDto {
                kind: "detector".to_string(),
                component_id: detector_id.to_string(),
                component_version: detector_version.to_string(),
            },
            MitreMappingProvenance::CorrelatorDeclared {
                correlator_id,
                correlator_version,
            } => MitreMappingProvenanceDto {
                kind: "correlator".to_string(),
                component_id: correlator_id.to_string(),
                component_version: correlator_version.to_string(),
            },
        };

        Self {
            domain: domain_str.to_string(),
            catalog_version: m.catalog_version().to_string(),
            technique_id: m.technique_id().to_string(),
            technique_name: m.technique_name().to_string(),
            technique_version: m.technique_version().to_string(),
            tactic_id: m.tactic().tactic_id().to_string(),
            tactic: tactic_str.to_string(),
            relationship: relationship_str.to_string(),
            rationale: m.rationale().to_string(),
            provenance: provenance_dto,
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
    /// Packet references involved in the evidence (as decimal string ordinals).
    pub packet_references: Vec<String>,
    /// Flow references involved in the evidence.
    pub flow_references: Vec<String>,
    /// Observation references involved in the evidence.
    pub observation_references: Vec<String>,
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
            packet_references: e
                .packet_references()
                .iter()
                .map(|p| p.capture_record_ordinal().to_string())
                .collect(),
            flow_references: e.flow_references().iter().map(|f| f.to_string()).collect(),
            observation_references: e
                .observation_references()
                .iter()
                .map(|o| o.to_string())
                .collect(),
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
    pub threshold: Option<EvidenceValueDto>,
    /// Comparison operator if applicable.
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
    /// Signed integer value as a base-10 string.
    Integer(String),
    /// Unsigned integer value as a base-10 string.
    Unsigned(String),
    /// Exact rational ratio (reduced fraction).
    Ratio(RatioDto),
    /// Boolean flag.
    Boolean(bool),
    /// Duration in seconds and nanoseconds.
    Duration(DurationDto),
}

impl EvidenceValueDto {
    /// Converts a domain [`EvidenceValue`] into a DTO.
    #[must_use]
    pub fn from_domain(v: &EvidenceValue) -> Self {
        match v {
            EvidenceValue::Integer(i) => Self::Integer(i.to_string()),
            EvidenceValue::Unsigned(u) => Self::Unsigned(u.to_string()),
            EvidenceValue::Ratio(r) => Self::Ratio(RatioDto::from_domain(r)),
            EvidenceValue::Boolean(b) => Self::Boolean(*b),
            EvidenceValue::Duration(d) => Self::Duration(DurationDto::from_domain(d)),
        }
    }
}

/// Exact rational ratio representation.
#[derive(Debug, Clone, Serialize)]
pub struct RatioDto {
    /// Numerator as a base-10 string.
    pub numerator: String,
    /// Denominator as a base-10 string (always >= 1).
    pub denominator: String,
    /// Exact rational string representation ("num/den").
    pub string_representation: String,
}

impl RatioDto {
    /// Converts domain [`EvidenceRatio`] into a DTO.
    #[must_use]
    pub fn from_domain(r: &EvidenceRatio) -> Self {
        Self {
            numerator: r.numerator().to_string(),
            denominator: r.denominator().to_string(),
            string_representation: r.to_string(),
        }
    }
}
