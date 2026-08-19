//! Deterministic finding filtering model and evaluation.
//!
//! Provides inclusive AND filtering over canonical finding records by minimum severity,
//! minimum confidence, detector identifier, and MITRE ATT&CK technique identifier.

use pcapraven_domain::{Confidence, DetectorId, FindingRecord, MitreAttackId, Severity};

/// Deterministic filter criteria for analytical findings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FindingFilter {
    min_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    detector_id: Option<DetectorId>,
    mitre_attack_id: Option<MitreAttackId>,
}

impl FindingFilter {
    /// Creates a new empty finding filter matching all findings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_severity: None,
            min_confidence: None,
            detector_id: None,
            mitre_attack_id: None,
        }
    }

    /// Sets the minimum severity threshold.
    #[must_use]
    pub const fn with_min_severity(mut self, min_severity: Option<Severity>) -> Self {
        self.min_severity = min_severity;
        self
    }

    /// Sets the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min_confidence: Option<Confidence>) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Sets the detector identifier filter.
    #[must_use]
    pub fn with_detector_id(mut self, detector_id: Option<DetectorId>) -> Self {
        self.detector_id = detector_id;
        self
    }

    /// Sets the MITRE ATT&CK technique filter.
    #[must_use]
    pub fn with_mitre_attack_id(mut self, mitre_attack_id: Option<MitreAttackId>) -> Self {
        self.mitre_attack_id = mitre_attack_id;
        self
    }

    /// Returns the minimum severity filter, if set.
    #[must_use]
    pub const fn min_severity(&self) -> Option<Severity> {
        self.min_severity
    }

    /// Returns the minimum confidence filter, if set.
    #[must_use]
    pub const fn min_confidence(&self) -> Option<Confidence> {
        self.min_confidence
    }

    /// Returns the detector ID filter, if set.
    #[must_use]
    pub fn detector_id(&self) -> Option<&DetectorId> {
        self.detector_id.as_ref()
    }

    /// Returns the MITRE ATT&CK ID filter, if set.
    #[must_use]
    pub fn mitre_attack_id(&self) -> Option<&MitreAttackId> {
        self.mitre_attack_id.as_ref()
    }

    /// Evaluates whether a single finding record satisfies all active filter criteria.
    #[must_use]
    pub fn matches(&self, finding: &FindingRecord) -> bool {
        if let Some(min_sev) = self.min_severity {
            if finding.severity() < min_sev {
                return false;
            }
        }

        if let Some(min_conf) = self.min_confidence {
            if finding.confidence() < min_conf {
                return false;
            }
        }

        if let Some(ref det_id) = self.detector_id {
            if finding.detector_id() != det_id {
                return false;
            }
        }

        if let Some(ref mitre_id) = self.mitre_attack_id {
            if !finding
                .mitre_mappings()
                .iter()
                .any(|m| m.technique_id() == mitre_id)
            {
                return false;
            }
        }

        true
    }

    /// Applies this filter to a slice of finding records, returning matching borrowed records in original canonical order.
    #[must_use]
    pub fn filter_findings<'a>(&self, findings: &'a [FindingRecord]) -> Vec<&'a FindingRecord> {
        findings.iter().filter(|f| self.matches(f)).collect()
    }
}
