//! Detection execution engine, immutable inputs, preflight configuration, and deterministic outcome generation.

use crate::config::{DetectorConfig, DetectorConfigurations};
use crate::detector::IncompleteDataPolicy;
use crate::error::{DetectionEngineError, DetectionOutputError, DetectorExecutionError};
use crate::registry::DetectorRegistry;
use core::fmt;
use pcapraven_domain::{
    DetectorId, DetectorVersion, EvidenceRecord, EvidenceRecordBuilder, EvidenceReference,
    FindingDraft, FindingRecord, FindingReference, FlowRecord, ProtocolObservation,
};

/// Completeness status of the domain facts provided to the detection engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectionInputCompleteness {
    /// Complete traffic analysis without truncation or budget exhaustion.
    Complete,
    /// Partial traffic analysis due to capture truncation, frame exclusions, or resource bounds.
    Partial,
}

impl DetectionInputCompleteness {
    /// Returns `true` if input analysis is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Returns `true` if input analysis is partial.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        matches!(self, Self::Partial)
    }
}

impl fmt::Display for DetectionInputCompleteness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete => f.write_str("Complete"),
            Self::Partial => f.write_str("Partial"),
        }
    }
}

/// Analysis limitation affecting the completeness of detection input data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectionInputLimitation {
    /// Capture container or record bytes were truncated.
    CaptureTruncated,
    /// Configured packet analysis budget was reached.
    PacketCountBudgetReached,
    /// Configured flow capacity was reached.
    FlowBudgetReached,
    /// Configured observation capacity was reached.
    ObservationBudgetReached,
}

impl fmt::Display for DetectionInputLimitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureTruncated => f.write_str("CaptureTruncated"),
            Self::PacketCountBudgetReached => f.write_str("PacketCountBudgetReached"),
            Self::FlowBudgetReached => f.write_str("FlowBudgetReached"),
            Self::ObservationBudgetReached => f.write_str("ObservationBudgetReached"),
        }
    }
}

/// Borrowed, immutable normalized domain input for detection.
///
/// Contains only normalized facts; never exposes raw packet bytes or parser state.
#[derive(Debug, Clone)]
pub struct DetectionInput<'a> {
    flows: &'a [FlowRecord],
    observations: &'a [ProtocolObservation],
    completeness: DetectionInputCompleteness,
    limitations: &'a [DetectionInputLimitation],
}

impl<'a> DetectionInput<'a> {
    /// Creates a new borrowed detection input structure.
    #[must_use]
    pub const fn new(
        flows: &'a [FlowRecord],
        observations: &'a [ProtocolObservation],
        completeness: DetectionInputCompleteness,
        limitations: &'a [DetectionInputLimitation],
    ) -> Self {
        Self {
            flows,
            observations,
            completeness,
            limitations,
        }
    }

    /// Returns the slice of reconstructed flows.
    #[must_use]
    pub const fn flows(&self) -> &'a [FlowRecord] {
        self.flows
    }

    /// Returns the slice of normalized protocol observations.
    #[must_use]
    pub const fn observations(&self) -> &'a [ProtocolObservation] {
        self.observations
    }

    /// Returns the completeness state of the input analysis.
    #[must_use]
    pub const fn completeness(&self) -> DetectionInputCompleteness {
        self.completeness
    }

    /// Returns the slice of input analysis limitations.
    #[must_use]
    pub const fn limitations(&self) -> &'a [DetectionInputLimitation] {
        self.limitations
    }
}

/// Finite resource bounds governing detection engine execution and output generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionLimits {
    /// Maximum allowed registered detectors.
    pub max_registered_detectors: usize,
    /// Maximum allowed parameters per detector.
    pub max_parameters_per_detector: usize,
    /// Maximum total findings produced in one detection run.
    pub max_total_findings: usize,
    /// Maximum total evidence records produced in one detection run.
    pub max_total_evidence_records: usize,
    /// Maximum diagnostic messages collected during execution.
    pub max_execution_diagnostics: usize,
}

impl DetectionLimits {
    /// Default maximum total findings (10,000).
    pub const DEFAULT_MAX_TOTAL_FINDINGS: usize = 10_000;
    /// Hard maximum cap on total findings (100,000).
    pub const HARD_MAX_TOTAL_FINDINGS: usize = 100_000;

    /// Default maximum total evidence records (50,000).
    pub const DEFAULT_MAX_TOTAL_EVIDENCE: usize = 50_000;
    /// Hard maximum cap on total evidence records (500,000).
    pub const HARD_MAX_TOTAL_EVIDENCE: usize = 500_000;

    /// Default maximum execution diagnostics (256).
    pub const DEFAULT_MAX_DIAGNOSTICS: usize = 256;
    /// Hard maximum cap on execution diagnostics (4,096).
    pub const HARD_MAX_DIAGNOSTICS: usize = 4_096;

    /// Creates default detection limits.
    #[must_use]
    pub const fn default_limits() -> Self {
        Self {
            max_registered_detectors: DetectorRegistry::DEFAULT_MAX_REGISTERED_DETECTORS,
            max_parameters_per_detector: 32,
            max_total_findings: Self::DEFAULT_MAX_TOTAL_FINDINGS,
            max_total_evidence_records: Self::DEFAULT_MAX_TOTAL_EVIDENCE,
            max_execution_diagnostics: Self::DEFAULT_MAX_DIAGNOSTICS,
        }
    }
}

impl Default for DetectionLimits {
    fn default() -> Self {
        Self::default_limits()
    }
}

/// Execution status recorded for an individual detector during a detection run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorExecutionStatus {
    /// Detector executed successfully.
    Executed,
    /// Detector was disabled by configuration.
    Disabled,
    /// Detector was skipped due to incomplete input and a Skip policy.
    SkippedIncompleteData,
    /// Detector evaluation failed with an execution error.
    Failed {
        /// Failure message.
        reason: String,
    },
    /// Detector output was rejected due to engine resource limits.
    ResourceLimited,
}

impl fmt::Display for DetectorExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executed => f.write_str("Executed"),
            Self::Disabled => f.write_str("Disabled"),
            Self::SkippedIncompleteData => f.write_str("SkippedIncompleteData"),
            Self::Failed { reason } => write!(f, "Failed({reason})"),
            Self::ResourceLimited => f.write_str("ResourceLimited"),
        }
    }
}

/// Individual detector execution record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorExecutionRecord {
    /// Detector identifier.
    pub detector_id: DetectorId,
    /// Detector version.
    pub detector_version: DetectorVersion,
    /// Execution status.
    pub status: DetectorExecutionStatus,
}

/// Deterministic outcome produced by a detection run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionRunOutcome {
    /// Overall run completion state.
    pub completion: DetectionInputCompleteness,
    /// Execution status record for each registered detector.
    pub detector_executions: Vec<DetectorExecutionRecord>,
    /// Canonical, deterministic findings.
    pub findings: Vec<FindingRecord>,
    /// Canonical, deterministic evidence records.
    pub evidence: Vec<EvidenceRecord>,
    /// Execution diagnostics.
    pub diagnostics: Vec<String>,
}

/// Evaluates all registered detectors over normalized domain input facts.
///
/// Preflights all detector configurations before any detector is evaluated.
/// Executes detectors in canonical [`DetectorId`] order, enforcing incomplete data policies,
/// referential integrity, duplicate finding rejection, and resource bounds.
pub fn execute_detection(
    registry: &DetectorRegistry,
    input: &DetectionInput<'_>,
    configurations: &DetectorConfigurations,
    limits: &DetectionLimits,
) -> Result<DetectionRunOutcome, DetectionEngineError> {
    let default_cfg = DetectorConfig::enabled();

    // STEP 1: Whole-configuration preflight validation.
    // If ANY detector configuration is invalid, fail before evaluating ANY detector.
    for detector in registry.iter() {
        let meta = detector.metadata();
        let cfg = configurations.get(meta.id()).unwrap_or(&default_cfg);
        if cfg.enabled {
            detector.validate_parameters(&cfg.parameters)?;
        }
    }

    // STEP 2: Deterministic execution in DetectorId order.
    let mut overall_completion = input.completeness();
    let mut execution_records = Vec::with_capacity(registry.len());
    let mut accepted_drafts: Vec<FindingDraft> = Vec::new();
    let mut diagnostics = Vec::new();

    for detector in registry.iter() {
        let meta = detector.metadata();
        let cfg = configurations.get(meta.id()).unwrap_or(&default_cfg);

        if !cfg.enabled {
            execution_records.push(DetectorExecutionRecord {
                detector_id: meta.id().clone(),
                detector_version: meta.version(),
                status: DetectorExecutionStatus::Disabled,
            });
            continue;
        }

        if input.completeness() == DetectionInputCompleteness::Partial
            && meta.incomplete_data_policy() == IncompleteDataPolicy::Skip
        {
            execution_records.push(DetectorExecutionRecord {
                detector_id: meta.id().clone(),
                detector_version: meta.version(),
                status: DetectorExecutionStatus::SkippedIncompleteData,
            });
            continue;
        }

        match detector.evaluate(input, &cfg.parameters) {
            Err(err) => {
                overall_completion = DetectionInputCompleteness::Partial;
                let reason = match &err {
                    DetectorExecutionError::InternalError(msg) => msg.clone(),
                    DetectorExecutionError::ResourceLimitExceeded(msg) => msg.clone(),
                };
                if diagnostics.len() < limits.max_execution_diagnostics {
                    diagnostics.push(format!("detector '{}' failed: {reason}", meta.id()));
                }
                execution_records.push(DetectorExecutionRecord {
                    detector_id: meta.id().clone(),
                    detector_version: meta.version(),
                    status: DetectorExecutionStatus::Failed { reason },
                });
            }
            Ok(drafts) => {
                // Validate incomplete data policy for AllowWithLimitations
                if input.completeness() == DetectionInputCompleteness::Partial
                    && meta.incomplete_data_policy() == IncompleteDataPolicy::AllowWithLimitations
                {
                    for draft in &drafts {
                        let has_limitation = draft
                            .evidence
                            .iter()
                            .any(|evi| !evi.limitations().is_empty());
                        if !has_limitation {
                            return Err(DetectionEngineError::Output(
                                DetectionOutputError::IncompleteDataPolicyViolation {
                                    detector_id: meta.id().clone(),
                                    reason: "finding emitted on partial input without supporting limitation evidence",
                                },
                            ));
                        }
                    }
                }

                // Validate finding draft requirements: every finding requires evidence
                for draft in &drafts {
                    if draft.evidence.is_empty() {
                        return Err(DetectionEngineError::Output(
                            DetectionOutputError::FindingWithoutEvidence,
                        ));
                    }
                }

                // Check duplicate finding key collision within this detector or across drafts
                for i in 0..drafts.len() {
                    for j in (i + 1)..drafts.len() {
                        if drafts[i].detector_id == drafts[j].detector_id
                            && drafts[i].subject == drafts[j].subject
                        {
                            return Err(DetectionEngineError::Output(
                                DetectionOutputError::DuplicateFindingIdentity {
                                    detector_id: drafts[i].detector_id.clone(),
                                },
                            ));
                        }
                    }
                }

                // Validate referential integrity of subject and evidence against DetectionInput
                for draft in &drafts {
                    for flow_ref in draft.subject.flow_references() {
                        if !input.flows.iter().any(|f| f.reference == *flow_ref) {
                            return Err(DetectionEngineError::Output(
                                DetectionOutputError::ReferentialIntegrityError(format!(
                                    "finding subject references unknown flow {}",
                                    flow_ref
                                )),
                            ));
                        }
                    }
                    for obs_ref in draft.subject.observation_references() {
                        if !input.observations.iter().any(|o| o.reference() == *obs_ref) {
                            return Err(DetectionEngineError::Output(
                                DetectionOutputError::ReferentialIntegrityError(format!(
                                    "finding subject references unknown observation {}",
                                    obs_ref
                                )),
                            ));
                        }
                    }
                }

                // Check total output resource limits
                if accepted_drafts.len() + drafts.len() > limits.max_total_findings {
                    overall_completion = DetectionInputCompleteness::Partial;
                    if diagnostics.len() < limits.max_execution_diagnostics {
                        diagnostics.push(format!(
                            "maximum finding limit ({}) reached, rejecting output from detector '{}'",
                            limits.max_total_findings,
                            meta.id()
                        ));
                    }
                    execution_records.push(DetectorExecutionRecord {
                        detector_id: meta.id().clone(),
                        detector_version: meta.version(),
                        status: DetectorExecutionStatus::ResourceLimited,
                    });
                    continue;
                }

                accepted_drafts.extend(drafts);
                execution_records.push(DetectorExecutionRecord {
                    detector_id: meta.id().clone(),
                    detector_version: meta.version(),
                    status: DetectorExecutionStatus::Executed,
                });
            }
        }
    }

    // STEP 3: Canonical assignment and determinism.
    // Sort accepted drafts deterministically by:
    // 1. DetectorId
    // 2. FindingSubject
    // 3. Title
    accepted_drafts.sort_by(|a, b| {
        a.detector_id
            .cmp(&b.detector_id)
            .then_with(|| a.subject.cmp(&b.subject))
            .then_with(|| a.title.as_str().cmp(b.title.as_str()))
    });

    let mut canonical_evidence: Vec<EvidenceRecord> = Vec::new();
    let mut canonical_findings: Vec<FindingRecord> = Vec::with_capacity(accepted_drafts.len());

    for (finding_idx, draft) in accepted_drafts.into_iter().enumerate() {
        let mut finding_evidence_refs = Vec::with_capacity(draft.evidence.len());

        for evidence_record in draft.evidence {
            if canonical_evidence.len() >= limits.max_total_evidence_records {
                overall_completion = DetectionInputCompleteness::Partial;
                if diagnostics.len() < limits.max_execution_diagnostics {
                    diagnostics.push(format!(
                        "maximum evidence records limit ({}) reached",
                        limits.max_total_evidence_records
                    ));
                }
                break;
            }

            let evi_ref = EvidenceReference::new(canonical_evidence.len() as u64);
            finding_evidence_refs.push(evi_ref);

            // Construct canonical evidence record with engine-assigned EvidenceReference
            let mut builder = EvidenceRecordBuilder::new(
                evi_ref,
                evidence_record.kind(),
                evidence_record.description().clone(),
            );
            builder = builder.with_schema_version(evidence_record.schema_version());

            for pkt in evidence_record.packet_references() {
                let _ = builder.add_packet_reference(*pkt);
            }
            for flow in evidence_record.flow_references() {
                let _ = builder.add_flow_reference(*flow);
            }
            for obs in evidence_record.observation_references() {
                let _ = builder.add_observation_reference(*obs);
            }
            for m in evidence_record.measurements() {
                let _ = builder.add_measurement(m.clone());
            }
            for lim in evidence_record.limitations() {
                let _ = builder.add_limitation(*lim);
            }

            if let Ok(built_evidence) = builder.build() {
                canonical_evidence.push(built_evidence);
            }
        }

        if finding_evidence_refs.is_empty() {
            continue;
        }

        let finding_ref = FindingReference::new(finding_idx as u64);
        if let Ok(finding) = FindingRecord::try_new(
            finding_ref,
            draft.detector_id,
            draft.detector_version,
            draft.subject,
            draft.title,
            draft.summary,
            draft.rationale,
            draft.severity,
            draft.confidence,
            finding_evidence_refs,
        ) {
            canonical_findings.push(finding);
        }
    }

    Ok(DetectionRunOutcome {
        completion: overall_completion,
        detector_executions: execution_records,
        findings: canonical_findings,
        evidence: canonical_evidence,
        diagnostics,
    })
}
