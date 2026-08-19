//! Cross-detector finding correlation architecture and multi-signal C2 heuristics.
//!
//! Evaluates relationships across primary detector findings (e.g. periodic beaconing combined
//! with high-diversity DNS tunneling on the same flow) to produce correlated findings.
//! Correlated findings reuse existing evidence records without generating new evidence records.

use crate::error::{DetectorExecutionError, DetectorRegistryError};
use core::fmt;
use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, EvidenceRecord, EvidenceReference, FindingRationale,
    FindingRecord, FindingReference, FindingSubject, FindingSummary, FindingTitle,
    FindingValidationError, FlowReference, HARD_MAX_MITRE_MAPPINGS_PER_FINDING, MitreAttackId,
    MitreMapping, MitreMappingProvenance, MitreMappingRationale, MitreTactic, Severity,
};
use std::collections::BTreeMap;

/// Maximum byte length for a correlator description (512 bytes).
pub const MAX_CORRELATOR_DESCRIPTION_LENGTH: usize = 512;

/// Validated, terminal-safe description of a correlator heuristic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrelatorDescription {
    text: String,
}

impl CorrelatorDescription {
    /// Creates and validates a new correlator description.
    pub fn try_new(text: impl AsRef<str>) -> Result<Self, FindingValidationError> {
        let raw = text.as_ref();
        if raw.is_empty() {
            return Err(FindingValidationError::EmptyFindingSummary);
        }
        if raw.len() > MAX_CORRELATOR_DESCRIPTION_LENGTH {
            return Err(FindingValidationError::FindingSummaryTooLong {
                length: raw.len(),
                max: MAX_CORRELATOR_DESCRIPTION_LENGTH,
            });
        }
        for c in raw.chars() {
            if c.is_control() {
                return Err(FindingValidationError::FindingSummaryControlCharacter {
                    byte: c as u32 as u8,
                });
            }
        }
        Ok(Self {
            text: raw.to_string(),
        })
    }

    /// Returns the description as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for CorrelatorDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Metadata describing a finding correlator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatorMetadata {
    id: DetectorId,
    version: DetectorVersion,
    description: CorrelatorDescription,
    required_primary_detector_ids: Vec<DetectorId>,
}

impl CorrelatorMetadata {
    /// Hard maximum required primary detector IDs (16).
    pub const HARD_MAX_REQUIRED_PRIMARY_DETECTOR_IDS: usize = 16;

    /// Creates and validates new correlator metadata.
    pub fn try_new(
        id: DetectorId,
        version: DetectorVersion,
        description: CorrelatorDescription,
        required_primary_detector_ids: Vec<DetectorId>,
    ) -> Result<Self, DetectorRegistryError> {
        if required_primary_detector_ids.len() > Self::HARD_MAX_REQUIRED_PRIMARY_DETECTOR_IDS {
            return Err(DetectorRegistryError::InvalidRequiredPrimaryDetectorIds {
                correlator_id: id,
                reason: "required primary detector count exceeds hard maximum limit",
            });
        }

        // Validate strictly sorted, duplicate-free required primary detector IDs
        for window in required_primary_detector_ids.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            if curr == prev {
                return Err(DetectorRegistryError::InvalidRequiredPrimaryDetectorIds {
                    correlator_id: id,
                    reason: "duplicate required primary detector ID declared",
                });
            }
            if curr < prev {
                return Err(DetectorRegistryError::InvalidRequiredPrimaryDetectorIds {
                    correlator_id: id,
                    reason: "required primary detector IDs must be strictly sorted",
                });
            }
        }

        Ok(Self {
            id,
            version,
            description,
            required_primary_detector_ids,
        })
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
        self.description.as_str()
    }

    /// Returns the slice of required primary detector IDs.
    #[must_use]
    pub fn required_primary_detector_ids(&self) -> &[DetectorId] {
        &self.required_primary_detector_ids
    }
}

/// Draft finding emitted by a correlator referencing primary findings and existing evidence.
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
    mitre_mappings: Vec<MitreMapping>,
}

impl CorrelationDraft {
    /// Default maximum correlation evidence references per finding (128).
    pub const DEFAULT_MAX_CORRELATION_EVIDENCE_REFERENCES: usize = 128;
    /// Hard maximum correlation evidence references per finding (4,096).
    pub const HARD_MAX_CORRELATION_EVIDENCE_REFERENCES: usize = 4_096;
    /// Hard maximum source finding references per finding (256).
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
        mitre_mappings: Vec<MitreMapping>,
    ) -> Result<Self, FindingValidationError> {
        if evidence_references.is_empty() {
            return Err(FindingValidationError::FindingWithoutEvidence);
        }
        if evidence_references.len() > Self::HARD_MAX_CORRELATION_EVIDENCE_REFERENCES {
            return Err(FindingValidationError::EvidenceReferencesExceeded {
                count: evidence_references.len(),
                max: Self::HARD_MAX_CORRELATION_EVIDENCE_REFERENCES,
            });
        }
        if source_finding_references.len() < 2 {
            return Err(
                FindingValidationError::InsufficientSourceFindingReferences {
                    count: source_finding_references.len(),
                    minimum: 2,
                },
            );
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

        if mitre_mappings.len() > HARD_MAX_MITRE_MAPPINGS_PER_FINDING {
            return Err(FindingValidationError::MitreMappingsExceeded {
                count: mitre_mappings.len(),
                max: HARD_MAX_MITRE_MAPPINGS_PER_FINDING,
            });
        }

        for window in mitre_mappings.windows(2) {
            let prev = window[0].technique_id();
            let curr = window[1].technique_id();
            if curr == prev {
                return Err(FindingValidationError::DuplicateMitreMapping(curr.clone()));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderMitreMapping {
                    previous: prev.to_string(),
                    attempted: curr.to_string(),
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
            mitre_mappings,
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

    /// Returns the ordered slice of source finding references.
    #[must_use]
    pub fn source_finding_references(&self) -> &[FindingReference] {
        &self.source_finding_references
    }

    /// Returns the ordered slice of MITRE ATT&CK mappings.
    #[must_use]
    pub fn mitre_mappings(&self) -> &[MitreMapping] {
        &self.mitre_mappings
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
    /// Default maximum registered correlators (16).
    pub const DEFAULT_MAX_REGISTERED_CORRELATORS: usize = 16;
    /// Hard maximum registered correlators (64).
    pub const HARD_MAX_REGISTERED_CORRELATORS: usize = 64;

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
    /// Correlator logic version for Phase 15 mapping semantics.
    pub const CORRELATOR_VERSION: DetectorVersion = DetectorVersion::new(1, 1, 0);

    /// Creates a new possible C2 multi-signal correlator.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("valid static correlator metadata")
    }

    /// Fallible constructor returning `Result` if metadata validation fails.
    pub fn try_new() -> Result<Self, DetectorRegistryError> {
        let id = DetectorId::try_new(Self::CORRELATOR_ID).map_err(|_| {
            DetectorRegistryError::InvalidRequiredPrimaryDetectorIds {
                correlator_id: DetectorId::try_new("behavior.possible_c2_multi_signal")
                    .unwrap_or_else(|_| unreachable!()),
                reason: "invalid correlator ID",
            }
        })?;
        let description = CorrelatorDescription::try_new(
            "Correlates periodic beaconing and DNS tunneling signals on the same flow",
        )
        .map_err(
            |_| DetectorRegistryError::InvalidRequiredPrimaryDetectorIds {
                correlator_id: id.clone(),
                reason: "invalid correlator description",
            },
        )?;
        let req1 = DetectorId::try_new("behavior.periodic_beaconing").map_err(|_| {
            DetectorRegistryError::InvalidRequiredPrimaryDetectorIds {
                correlator_id: id.clone(),
                reason: "invalid required primary detector ID",
            }
        })?;
        let req2 = DetectorId::try_new("dns.possible_tunneling").map_err(|_| {
            DetectorRegistryError::InvalidRequiredPrimaryDetectorIds {
                correlator_id: id.clone(),
                reason: "invalid required primary detector ID",
            }
        })?;
        let mut required_primary_detector_ids = vec![req1, req2];
        required_primary_detector_ids.sort();
        required_primary_detector_ids.dedup();

        let metadata = CorrelatorMetadata::try_new(
            id,
            Self::CORRELATOR_VERSION,
            description,
            required_primary_detector_ids,
        )?;
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
        // Bounded O(P log P) indexing of primary findings by FlowReference
        let mut periodic_by_flow: BTreeMap<FlowReference, &FindingRecord> = BTreeMap::new();
        let mut tunneling_by_flow: BTreeMap<FlowReference, &FindingRecord> = BTreeMap::new();

        for finding in primary_findings {
            if finding.detector_id().as_str() == "behavior.periodic_beaconing" {
                if let [flow_ref] = finding.subject().flow_references() {
                    periodic_by_flow.insert(*flow_ref, finding);
                }
            } else if finding.detector_id().as_str() == "dns.possible_tunneling" {
                if let [flow_ref] = finding.subject().flow_references() {
                    tunneling_by_flow.insert(*flow_ref, finding);
                }
            }
        }

        for (flow_ref, beaconing) in &periodic_by_flow {
            if let Some(tunneling) = tunneling_by_flow.get(flow_ref) {
                // Exactly two source findings
                let mut source_findings = vec![beaconing.reference(), tunneling.reference()];
                source_findings.sort_by_key(|f| f.id());
                source_findings.dedup_by_key(|f| f.id());

                // Exact deduplicated union of source evidence references
                let mut evidence_refs = Vec::new();
                evidence_refs.extend_from_slice(beaconing.evidence_references());
                evidence_refs.extend_from_slice(tunneling.evidence_references());
                evidence_refs.sort_by_key(|e| e.id());
                evidence_refs.dedup_by_key(|e| e.id());

                // Target subject: exactly the single shared flow reference, zero packet/observation references
                let subject = FindingSubject::try_new(Vec::new(), vec![*flow_ref], Vec::new())
                    .map_err(|e| {
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

                let mitre_id = MitreAttackId::try_new("T1071.004").map_err(|e| {
                    DetectorExecutionError::internal_error(format!("mitre id error: {e}"))
                })?;
                let mitre_rationale = MitreMappingRationale::try_new(
                    "The correlator matched co-occurring periodic beaconing and possible DNS tunneling heuristics on the same flow, increasing investigative relevance for command-and-control channel analysis. This mapping reflects heuristic alignment with ATT&CK T1071.004 without asserting confirmed adversary presence.",
                ).map_err(|e| DetectorExecutionError::internal_error(format!("mitre rationale error: {e}")))?;
                let mitre_provenance = MitreMappingProvenance::CorrelatorDeclared {
                    correlator_id: self.metadata().id().clone(),
                    correlator_version: self.metadata().version(),
                };
                let mitre_mapping = MitreMapping::try_new(
                    mitre_id,
                    "Application Layer Protocol: DNS",
                    MitreTactic::CommandAndControl,
                    mitre_rationale,
                    mitre_provenance,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("mitre mapping error: {e}"))
                })?;

                let draft = CorrelationDraft::try_new(
                    subject,
                    title,
                    summary,
                    rationale,
                    Severity::Medium,
                    Confidence::Medium,
                    evidence_refs,
                    source_findings,
                    vec![mitre_mapping],
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
