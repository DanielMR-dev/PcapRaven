//! Detector trait, metadata contracts, and incomplete data policies.

use crate::config::DetectorParameters;
use crate::engine::DetectionInput;
use crate::error::{DetectorConfigError, DetectorExecutionError, DetectorRegistryError};
use core::fmt;
use pcapraven_domain::{
    DetectorId, DetectorVersion, FindingDraft, FindingSummary, FindingTitle,
    HARD_MAX_MITRE_MAPPINGS_PER_FINDING, MitreMappingDeclaration,
};

/// Policy declared by a detector regarding execution over incomplete/partial traffic analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IncompleteDataPolicy {
    /// Skip evaluation entirely when input traffic analysis is partial.
    Skip,
    /// Allow evaluation on partial input, provided any emitted findings include supporting limitations.
    AllowWithLimitations,
}

impl IncompleteDataPolicy {
    /// Returns the static label for this policy.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Skip => "Skip",
            Self::AllowWithLimitations => "AllowWithLimitations",
        }
    }
}

impl fmt::Display for IncompleteDataPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Immutable metadata identifying a detector and its behavioral contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorMetadata {
    id: DetectorId,
    version: DetectorVersion,
    title: FindingTitle,
    purpose: FindingSummary,
    incomplete_data_policy: IncompleteDataPolicy,
    mitre_mapping_declarations: Vec<MitreMappingDeclaration>,
}

impl DetectorMetadata {
    /// Creates and validates new detector metadata.
    pub fn try_new(
        id: DetectorId,
        version: DetectorVersion,
        title: FindingTitle,
        purpose: FindingSummary,
        incomplete_data_policy: IncompleteDataPolicy,
        mitre_mapping_declarations: Vec<MitreMappingDeclaration>,
    ) -> Result<Self, DetectorRegistryError> {
        if mitre_mapping_declarations.len() > HARD_MAX_MITRE_MAPPINGS_PER_FINDING {
            return Err(DetectorRegistryError::InvalidMitreMappingDeclarations {
                component_id: id,
                reason: "MITRE ATT&CK mapping declarations count exceeds maximum limit",
            });
        }

        for window in mitre_mapping_declarations.windows(2) {
            let prev = window[0].technique_id();
            let curr = window[1].technique_id();
            if curr == prev {
                return Err(DetectorRegistryError::InvalidMitreMappingDeclarations {
                    component_id: id,
                    reason: "duplicate MITRE ATT&CK mapping declaration technique ID",
                });
            }
            if curr < prev {
                return Err(DetectorRegistryError::InvalidMitreMappingDeclarations {
                    component_id: id,
                    reason: "MITRE ATT&CK mapping declarations must be strictly sorted by technique ID",
                });
            }
        }

        Ok(Self {
            id,
            version,
            title,
            purpose,
            incomplete_data_policy,
            mitre_mapping_declarations,
        })
    }

    /// Creates new detector metadata without MITRE mapping declarations.
    #[must_use]
    pub const fn new(
        id: DetectorId,
        version: DetectorVersion,
        title: FindingTitle,
        purpose: FindingSummary,
        incomplete_data_policy: IncompleteDataPolicy,
    ) -> Self {
        Self {
            id,
            version,
            title,
            purpose,
            incomplete_data_policy,
            mitre_mapping_declarations: Vec::new(),
        }
    }

    /// Returns the unique detector identifier.
    #[must_use]
    pub const fn id(&self) -> &DetectorId {
        &self.id
    }

    /// Returns the detector version.
    #[must_use]
    pub const fn version(&self) -> DetectorVersion {
        self.version
    }

    /// Returns the detector display title.
    #[must_use]
    pub const fn title(&self) -> &FindingTitle {
        &self.title
    }

    /// Returns the detector purpose summary.
    #[must_use]
    pub const fn purpose(&self) -> &FindingSummary {
        &self.purpose
    }

    /// Returns the detector incomplete data policy.
    #[must_use]
    pub const fn incomplete_data_policy(&self) -> IncompleteDataPolicy {
        self.incomplete_data_policy
    }

    /// Returns the slice of declared MITRE mapping declarations.
    #[must_use]
    pub fn mitre_mapping_declarations(&self) -> &[MitreMappingDeclaration] {
        &self.mitre_mapping_declarations
    }
}

/// Bounded, engine-controlled sink for collecting finding drafts during detector evaluation.
///
/// Prevents detectors from unbounded allocation and strictly checks remaining finding
/// and evidence capacity budgets on every push using checked arithmetic.
#[derive(Debug)]
pub struct DetectorDraftSink {
    findings: Vec<FindingDraft>,
    max_findings: usize,
    max_evidence_records: usize,
    current_evidence_records: usize,
}

impl DetectorDraftSink {
    /// Creates a new bounded draft sink with the specified remaining finding and evidence capacities.
    #[must_use]
    pub fn new(max_findings: usize, max_evidence_records: usize) -> Self {
        Self {
            findings: Vec::with_capacity(max_findings.min(64)),
            max_findings,
            max_evidence_records,
            current_evidence_records: 0,
        }
    }

    /// Pushes a finding draft into the sink, checking remaining finding and evidence budgets.
    ///
    /// Returns a structured [`DetectorExecutionError::ResourceLimitExceeded`] if adding this draft
    /// would exceed either remaining budget.
    pub fn push(&mut self, draft: FindingDraft) -> Result<(), DetectorExecutionError> {
        if self.findings.len() >= self.max_findings {
            return Err(DetectorExecutionError::resource_limit(
                "detector draft finding budget exceeded",
            ));
        }

        let draft_evidence_count = draft.evidence().len();
        let new_evidence_count = self
            .current_evidence_records
            .checked_add(draft_evidence_count)
            .ok_or_else(|| {
                DetectorExecutionError::resource_limit("detector evidence counter overflow")
            })?;

        if new_evidence_count > self.max_evidence_records {
            return Err(DetectorExecutionError::resource_limit(
                "detector draft evidence budget exceeded",
            ));
        }

        self.current_evidence_records = new_evidence_count;
        self.findings.push(draft);
        Ok(())
    }

    /// Returns the number of finding drafts currently in the sink.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Returns `true` if the sink contains zero finding drafts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns the cumulative number of evidence records in all accepted finding drafts.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.current_evidence_records
    }

    /// Returns a slice of the finding drafts currently held in the sink.
    #[must_use]
    pub fn drafts(&self) -> &[FindingDraft] {
        &self.findings
    }

    /// Consumes the sink and returns the collected finding drafts.
    #[must_use]
    pub fn into_drafts(self) -> Vec<FindingDraft> {
        self.findings
    }

    /// Clears all findings and resets the evidence count (used for transactional discard).
    pub fn clear(&mut self) {
        self.findings.clear();
        self.current_evidence_records = 0;
    }
}

/// Pure, offline analytical detector evaluation contract.
///
/// Implementations must be pure functions of borrowed domain inputs and configuration parameters,
/// producing zero network, filesystem, or process side effects.
pub trait Detector: Send + Sync {
    /// Returns immutable metadata describing the detector.
    fn metadata(&self) -> &DetectorMetadata;

    /// Validates configuration parameters prior to execution.
    fn validate_parameters(
        &self,
        parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError>;

    /// Evaluates normalized domain input facts against validated parameters, emitting finding drafts into `output`.
    fn evaluate(
        &self,
        input: &DetectionInput<'_>,
        parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError>;
}
