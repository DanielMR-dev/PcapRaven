//! Cross-detector finding correlation architecture and multi-signal C2 heuristics.
//!
//! Evaluates relationships across primary detector findings (e.g. periodic beaconing combined
//! with high-diversity DNS tunneling on the same flow) to produce correlated findings.
//! Correlated findings reuse existing evidence records without generating new evidence records.

use crate::error::{DetectorExecutionError, DetectorRegistryError};
use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, EvidenceRecord, EvidenceReference, FindingRationale,
    FindingRecord, FindingReference, FindingSubject, FindingSummary, FindingTitle,
    FindingValidationError, Severity,
};

/// Metadata describing a finding correlator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatorMetadata {
    id: DetectorId,
    version: DetectorVersion,
    description: String,
}

impl CorrelatorMetadata {
    /// Creates new correlator metadata.
    #[must_use]
    pub fn new(id: DetectorId, version: DetectorVersion, description: impl Into<String>) -> Self {
        Self {
            id,
            version,
            description: description.into(),
        }
    }

    /// Returns the correlator identifier.
    #[must_use]
    pub const fn id(&self) -> &DetectorId {
        &self.id
    }

    /// Returns the correlator version.
    #[must_use]
    pub const fn version(&self) -> DetectorVersion {
        self.version
    }

    /// Returns the human-readable description of the correlator.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Draft correlated finding emitted by a correlator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationDraft {
    subject: FindingSubject,
    title: FindingTitle,
    summary: FindingSummary,
    rationale: FindingRationale,
    severity: Severity,
    confidence: Confidence,
    evidence_references: Vec<EvidenceReference>,
    source_finding_references: Vec<FindingReference>,
}

impl CorrelationDraft {
    /// Default maximum source finding references (64).
    pub const DEFAULT_MAX_SOURCE_FINDING_REFERENCES: usize = 64;
    /// Hard maximum source finding references (256).
    pub const HARD_MAX_SOURCE_FINDING_REFERENCES: usize = 256;

    /// Creates and validates a new correlation draft.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        subject: FindingSubject,
        title: FindingTitle,
        summary: FindingSummary,
        rationale: FindingRationale,
        severity: Severity,
        confidence: Confidence,
        evidence_references: Vec<EvidenceReference>,
        source_finding_references: Vec<FindingReference>,
    ) -> Result<Self, FindingValidationError> {
        if evidence_references.is_empty() {
            return Err(FindingValidationError::FindingWithoutEvidence);
        }
        if source_finding_references.len() < 2 {
            return Err(FindingValidationError::EmptyFindingSubject);
        }
        if source_finding_references.len() > Self::HARD_MAX_SOURCE_FINDING_REFERENCES {
            return Err(FindingValidationError::SourceFindingReferencesExceeded {
                count: source_finding_references.len(),
                max: Self::HARD_MAX_SOURCE_FINDING_REFERENCES,
            });
        }

        // Validate evidence references are strictly sorted without duplicates
        for window in evidence_references.windows(2) {
            let prev = window[0].id();
            let curr = window[1].id();
            if curr == prev {
                return Err(FindingValidationError::DuplicateEvidenceReference(
                    window[1],
                ));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderEvidenceReference {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        // Validate source finding references are strictly sorted without duplicates
        for window in source_finding_references.windows(2) {
            let prev = window[0].id();
            let curr = window[1].id();
            if curr == prev {
                return Err(FindingValidationError::DuplicateSourceFindingReference(
                    window[1],
                ));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderSourceFindingReference {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        Ok(Self {
            subject,
            title,
            summary,
            rationale,
            severity,
            confidence,
            evidence_references,
            source_finding_references,
        })
    }

    /// Returns the finding subject.
    #[must_use]
    pub const fn subject(&self) -> &FindingSubject {
        &self.subject
    }

    /// Returns the finding title.
    #[must_use]
    pub const fn title(&self) -> &FindingTitle {
        &self.title
    }

    /// Returns the finding summary.
    #[must_use]
    pub const fn summary(&self) -> &FindingSummary {
        &self.summary
    }

    /// Returns the finding rationale.
    #[must_use]
    pub const fn rationale(&self) -> &FindingRationale {
        &self.rationale
    }

    /// Returns the severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the supporting evidence references.
    #[must_use]
    pub fn evidence_references(&self) -> &[EvidenceReference] {
        &self.evidence_references
    }

    /// Returns the source finding references.
    #[must_use]
    pub fn source_finding_references(&self) -> &[FindingReference] {
        &self.source_finding_references
    }
}

/// Bounded output sink for correlation drafts.
#[derive(Debug)]
pub struct CorrelationDraftSink {
    max_findings: usize,
    drafts: Vec<CorrelationDraft>,
}

impl CorrelationDraftSink {
    /// Creates a new correlation draft sink with a finite finding capacity.
    #[must_use]
    pub fn new(max_findings: usize) -> Self {
        Self {
            max_findings,
            drafts: Vec::new(),
        }
    }

    /// Appends a correlation draft, returning an error if capacity is reached.
    pub fn push(&mut self, draft: CorrelationDraft) -> Result<(), DetectorExecutionError> {
        if self.drafts.len() >= self.max_findings {
            return Err(DetectorExecutionError::resource_limit(
                "correlation draft sink finding capacity exceeded",
            ));
        }
        self.drafts.push(draft);
        Ok(())
    }

    /// Returns the number of drafts in the sink.
    #[must_use]
    pub fn len(&self) -> usize {
        self.drafts.len()
    }

    /// Returns `true` if the sink contains no drafts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.drafts.is_empty()
    }

    /// Consumes the sink, returning all accumulated drafts.
    #[must_use]
    pub fn into_drafts(self) -> Vec<CorrelationDraft> {
        self.drafts
    }
}

/// Trait implemented by post-evaluation cross-detector correlation heuristics.
pub trait FindingCorrelator: Send + Sync {
    /// Returns the static metadata for this correlator.
    fn metadata(&self) -> &CorrelatorMetadata;

    /// Evaluates primary findings and evidence, emitting correlated finding drafts.
    fn correlate(
        &self,
        primary_findings: &[FindingRecord],
        evidence_pool: &[EvidenceRecord],
        output: &mut CorrelationDraftSink,
    ) -> Result<(), DetectorExecutionError>;
}

/// Deterministic, bounded registry for finding correlators.
pub struct CorrelationRegistry {
    correlators: Vec<Box<dyn FindingCorrelator>>,
    max_registered_correlators: usize,
}

impl Default for CorrelationRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl CorrelationRegistry {
    /// Default maximum registered correlators (64).
    pub const DEFAULT_MAX_REGISTERED_CORRELATORS: usize = 64;
    /// Hard maximum registered correlators (256).
    pub const HARD_MAX_REGISTERED_CORRELATORS: usize = 256;

    /// Creates a new correlation registry with configured maximum capacity.
    pub fn new(max_registered_correlators: usize) -> Result<Self, DetectorRegistryError> {
        if max_registered_correlators == 0 {
            return Err(DetectorRegistryError::ZeroRegistryCapacity);
        }
        if max_registered_correlators > Self::HARD_MAX_REGISTERED_CORRELATORS {
            return Err(DetectorRegistryError::RegistryCapacityAboveHardMaximum {
                attempted: max_registered_correlators,
                max: Self::HARD_MAX_REGISTERED_CORRELATORS,
            });
        }
        Ok(Self {
            correlators: Vec::new(),
            max_registered_correlators,
        })
    }

    /// Creates an empty registry with default capacity.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            correlators: Vec::new(),
            max_registered_correlators: Self::DEFAULT_MAX_REGISTERED_CORRELATORS,
        }
    }

    /// Registers a new correlator, maintaining canonical sorted order by `DetectorId`.
    pub fn register(
        &mut self,
        correlator: Box<dyn FindingCorrelator>,
    ) -> Result<(), DetectorRegistryError> {
        let id = correlator.metadata().id();

        if self.correlators.iter().any(|c| c.metadata().id() == id) {
            return Err(DetectorRegistryError::DuplicateDetectorId(id.clone()));
        }

        if self.correlators.len() >= self.max_registered_correlators {
            return Err(DetectorRegistryError::RegistryCapacityExceeded {
                count: self.correlators.len() + 1,
                max: self.max_registered_correlators,
            });
        }

        let insert_idx = self
            .correlators
            .binary_search_by(|c| c.metadata().id().cmp(id))
            .unwrap_or_else(|idx| idx);

        self.correlators.insert(insert_idx, correlator);
        Ok(())
    }

    /// Returns the number of registered correlators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.correlators.len()
    }

    /// Returns `true` if no correlators are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.correlators.is_empty()
    }

    /// Returns an iterator over registered correlators in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn FindingCorrelator> {
        self.correlators.iter().map(|b| b.as_ref())
    }

    /// Looks up a correlator by identifier.
    #[must_use]
    pub fn get(&self, id: &DetectorId) -> Option<&dyn FindingCorrelator> {
        self.correlators
            .binary_search_by(|c| c.metadata().id().cmp(id))
            .ok()
            .map(|idx| self.correlators[idx].as_ref())
    }
}

/// Possible C2 Multi-Signal Correlator (`behavior.possible_c2_multi_signal`).
///
/// Correlates periodic beaconing detection with high-diversity DNS tunneling detection
/// occurring on the same flow, producing a medium-severity finding without asserting
/// confirmed malware presence.
#[derive(Debug, Clone)]
pub struct PossibleC2MultiSignalCorrelator {
    metadata: CorrelatorMetadata,
}

impl Default for PossibleC2MultiSignalCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl PossibleC2MultiSignalCorrelator {
    /// Stable namespaced correlator identifier.
    pub const CORRELATOR_ID: &'static str = "behavior.possible_c2_multi_signal";
    /// Correlator logic version.
    pub const CORRELATOR_VERSION: DetectorVersion = DetectorVersion::new(1, 0, 0);

    /// Creates a new possible C2 multi-signal correlator.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("valid static correlator metadata")
    }

    /// Fallible constructor returning `Result` if metadata validation fails.
    pub fn try_new() -> Result<Self, FindingValidationError> {
        let id = DetectorId::try_new(Self::CORRELATOR_ID)?;
        let metadata = CorrelatorMetadata::new(
            id,
            Self::CORRELATOR_VERSION,
            "Correlates periodic beaconing and DNS tunneling signals on the same flow",
        );
        Ok(Self { metadata })
    }
}

impl FindingCorrelator for PossibleC2MultiSignalCorrelator {
    fn metadata(&self) -> &CorrelatorMetadata {
        &self.metadata
    }

    fn correlate(
        &self,
        primary_findings: &[FindingRecord],
        _evidence_pool: &[EvidenceRecord],
        output: &mut CorrelationDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let beaconing_findings: Vec<&FindingRecord> = primary_findings
            .iter()
            .filter(|f| f.detector_id().as_str() == "behavior.periodic_beaconing")
            .collect();

        let tunneling_findings: Vec<&FindingRecord> = primary_findings
            .iter()
            .filter(|f| f.detector_id().as_str() == "dns.possible_tunneling")
            .collect();

        for beaconing in &beaconing_findings {
            for tunneling in &tunneling_findings {
                // Find shared flow references
                let has_shared_flow = beaconing
                    .subject()
                    .flow_references()
                    .iter()
                    .any(|f| tunneling.subject().flow_references().contains(f));

                if !has_shared_flow {
                    continue;
                }

                // Combine and deduplicate source finding references
                let mut source_findings = vec![beaconing.reference(), tunneling.reference()];
                source_findings.sort_by_key(|f| f.id());
                source_findings.dedup_by_key(|f| f.id());

                // Combine and deduplicate evidence references
                let mut evidence_refs = Vec::new();
                evidence_refs.extend_from_slice(beaconing.evidence_references());
                evidence_refs.extend_from_slice(tunneling.evidence_references());
                evidence_refs.sort_by_key(|e| e.id());
                evidence_refs.dedup_by_key(|e| e.id());

                // Combine and deduplicate subjects
                let mut packet_refs = Vec::new();
                packet_refs.extend_from_slice(beaconing.subject().packet_references());
                packet_refs.extend_from_slice(tunneling.subject().packet_references());
                packet_refs.sort_by_key(|p| p.capture_record_ordinal());
                packet_refs.dedup_by_key(|p| p.capture_record_ordinal());

                let mut flow_refs = Vec::new();
                flow_refs.extend_from_slice(beaconing.subject().flow_references());
                flow_refs.extend_from_slice(tunneling.subject().flow_references());
                flow_refs.sort_by_key(|f| f.ordinal());
                flow_refs.dedup_by_key(|f| f.ordinal());

                let mut obs_refs = Vec::new();
                obs_refs.extend_from_slice(beaconing.subject().observation_references());
                obs_refs.extend_from_slice(tunneling.subject().observation_references());
                obs_refs.sort();
                obs_refs.dedup();

                let subject =
                    FindingSubject::try_new(packet_refs, flow_refs, obs_refs).map_err(|e| {
                        DetectorExecutionError::internal_error(format!("subject error: {e}"))
                    })?;

                let title = FindingTitle::try_new("Possible multi-signal C2-like behavior")
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!("title error: {e}"))
                    })?;

                let summary = FindingSummary::try_new(
                    "The same flow independently matched periodic communication and possible DNS tunneling heuristics.",
                )
                .map_err(|e| DetectorExecutionError::internal_error(format!("summary error: {e}")))?;

                let rationale = FindingRationale::try_new(
                    "Two independent detector signals (periodic beaconing and possible DNS tunneling) co-occur on the same network flow. While this multi-signal correlation increases investigative relevance, it does not establish confirmed malware, command-and-control, or data exfiltration. Benign alternatives include periodic DNS telemetry, monitoring software, generated scheduled lookups, service discovery, heartbeat mechanisms, security software, or automated infrastructure management.",
                )
                .map_err(|e| DetectorExecutionError::internal_error(format!("rationale error: {e}")))?;

                let draft = CorrelationDraft::try_new(
                    subject,
                    title,
                    summary,
                    rationale,
                    Severity::Medium,
                    Confidence::Medium,
                    evidence_refs,
                    source_findings,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("correlation draft error: {e}"))
                })?;

                output.push(draft)?;
            }
        }

        Ok(())
    }
}
