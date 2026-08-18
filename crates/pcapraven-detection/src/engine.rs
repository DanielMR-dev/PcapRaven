//! Detection execution engine, immutable inputs, preflight configuration, and deterministic outcome generation.

use crate::config::{DetectorConfig, DetectorConfigurations};
use crate::detector::{DetectorDraftSink, IncompleteDataPolicy};
use crate::error::{
    DetectionEngineError, DetectionInputError, DetectionLimitsValidationError,
    DetectionOutputError, DetectorConfigError, DetectorExecutionError,
};
use crate::registry::DetectorRegistry;
use core::fmt;
use pcapraven_domain::{
    DetectorId, DetectorVersion, EvidenceLimitation, EvidenceRecord, EvidenceReference,
    FindingRecord, FindingReference, FlowRecord, ProtocolObservation,
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

impl DetectionInputLimitation {
    /// Maps this detection input limitation to the corresponding domain evidence limitation.
    #[must_use]
    pub const fn to_evidence_limitation(&self) -> EvidenceLimitation {
        match self {
            Self::CaptureTruncated => EvidenceLimitation::CaptureTruncated,
            Self::PacketCountBudgetReached => EvidenceLimitation::PacketCountBudgetReached,
            Self::FlowBudgetReached => EvidenceLimitation::FlowBudgetReached,
            Self::ObservationBudgetReached => EvidenceLimitation::ObservationBudgetReached,
        }
    }
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
    /// Creates and validates a new borrowed detection input structure.
    pub fn try_new(
        flows: &'a [FlowRecord],
        observations: &'a [ProtocolObservation],
        completeness: DetectionInputCompleteness,
        limitations: &'a [DetectionInputLimitation],
    ) -> Result<Self, DetectionInputError> {
        // Validate strictly increasing, duplicate-free flows
        for window in flows.windows(2) {
            let prev = window[0].reference.ordinal();
            let curr = window[1].reference.ordinal();
            if curr == prev {
                return Err(DetectionInputError::DuplicateFlow(window[1].reference));
            }
            if curr < prev {
                return Err(DetectionInputError::OutOfOrderFlow {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        // Validate strictly increasing, duplicate-free observations
        for window in observations.windows(2) {
            let prev = window[0].reference();
            let curr = window[1].reference();
            if curr == prev {
                return Err(DetectionInputError::DuplicateObservation(curr));
            }
            if curr < prev {
                return Err(DetectionInputError::OutOfOrderObservation {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        // Validate strictly sorted, duplicate-free limitations
        for window in limitations.windows(2) {
            let prev = window[0];
            let curr = window[1];
            if curr == prev {
                return Err(DetectionInputError::DuplicateLimitation(curr));
            }
            if curr < prev {
                return Err(DetectionInputError::OutOfOrderLimitation {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        // Validate consistency between completeness and limitations
        if completeness == DetectionInputCompleteness::Complete && !limitations.is_empty() {
            return Err(DetectionInputError::CompleteInputWithLimitations);
        }
        if completeness == DetectionInputCompleteness::Partial && limitations.is_empty() {
            return Err(DetectionInputError::PartialInputWithoutLimitations);
        }

        Ok(Self {
            flows,
            observations,
            completeness,
            limitations,
        })
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
    max_registered_detectors: usize,
    max_parameters_per_detector: usize,
    max_total_findings: usize,
    max_total_evidence_records: usize,
    max_execution_diagnostics: usize,
}

impl DetectionLimits {
    /// Default maximum registered detectors (64).
    pub const DEFAULT_MAX_REGISTERED_DETECTORS: usize =
        DetectorRegistry::DEFAULT_MAX_REGISTERED_DETECTORS;
    /// Hard maximum cap on registered detectors (256).
    pub const HARD_MAX_REGISTERED_DETECTORS: usize =
        DetectorRegistry::HARD_MAX_REGISTERED_DETECTORS;

    /// Default maximum parameters per detector (32).
    pub const DEFAULT_MAX_PARAMETERS_PER_DETECTOR: usize = 32;
    /// Hard maximum cap on parameters per detector (256).
    pub const HARD_MAX_PARAMETERS_PER_DETECTOR: usize = 256;

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

    /// Creates and validates new detection limits.
    pub fn try_new(
        max_registered_detectors: usize,
        max_parameters_per_detector: usize,
        max_total_findings: usize,
        max_total_evidence_records: usize,
        max_execution_diagnostics: usize,
    ) -> Result<Self, DetectionLimitsValidationError> {
        if max_registered_detectors == 0 {
            return Err(DetectionLimitsValidationError::ZeroLimit(
                "max_registered_detectors",
            ));
        }
        if max_registered_detectors > Self::HARD_MAX_REGISTERED_DETECTORS {
            return Err(DetectionLimitsValidationError::LimitAboveHardMaximum {
                limit_name: "max_registered_detectors",
                attempted: max_registered_detectors,
                max: Self::HARD_MAX_REGISTERED_DETECTORS,
            });
        }

        if max_parameters_per_detector == 0 {
            return Err(DetectionLimitsValidationError::ZeroLimit(
                "max_parameters_per_detector",
            ));
        }
        if max_parameters_per_detector > Self::HARD_MAX_PARAMETERS_PER_DETECTOR {
            return Err(DetectionLimitsValidationError::LimitAboveHardMaximum {
                limit_name: "max_parameters_per_detector",
                attempted: max_parameters_per_detector,
                max: Self::HARD_MAX_PARAMETERS_PER_DETECTOR,
            });
        }

        if max_total_findings == 0 {
            return Err(DetectionLimitsValidationError::ZeroLimit(
                "max_total_findings",
            ));
        }
        if max_total_findings > Self::HARD_MAX_TOTAL_FINDINGS {
            return Err(DetectionLimitsValidationError::LimitAboveHardMaximum {
                limit_name: "max_total_findings",
                attempted: max_total_findings,
                max: Self::HARD_MAX_TOTAL_FINDINGS,
            });
        }

        if max_total_evidence_records == 0 {
            return Err(DetectionLimitsValidationError::ZeroLimit(
                "max_total_evidence_records",
            ));
        }
        if max_total_evidence_records > Self::HARD_MAX_TOTAL_EVIDENCE {
            return Err(DetectionLimitsValidationError::LimitAboveHardMaximum {
                limit_name: "max_total_evidence_records",
                attempted: max_total_evidence_records,
                max: Self::HARD_MAX_TOTAL_EVIDENCE,
            });
        }

        if max_execution_diagnostics == 0 {
            return Err(DetectionLimitsValidationError::ZeroLimit(
                "max_execution_diagnostics",
            ));
        }
        if max_execution_diagnostics > Self::HARD_MAX_DIAGNOSTICS {
            return Err(DetectionLimitsValidationError::LimitAboveHardMaximum {
                limit_name: "max_execution_diagnostics",
                attempted: max_execution_diagnostics,
                max: Self::HARD_MAX_DIAGNOSTICS,
            });
        }

        Ok(Self {
            max_registered_detectors,
            max_parameters_per_detector,
            max_total_findings,
            max_total_evidence_records,
            max_execution_diagnostics,
        })
    }

    /// Returns a builder for configuring [`DetectionLimits`].
    #[must_use]
    pub fn builder() -> DetectionLimitsBuilder {
        DetectionLimitsBuilder::new()
    }

    /// Creates default detection limits.
    #[must_use]
    pub const fn default_limits() -> Self {
        Self {
            max_registered_detectors: Self::DEFAULT_MAX_REGISTERED_DETECTORS,
            max_parameters_per_detector: Self::DEFAULT_MAX_PARAMETERS_PER_DETECTOR,
            max_total_findings: Self::DEFAULT_MAX_TOTAL_FINDINGS,
            max_total_evidence_records: Self::DEFAULT_MAX_TOTAL_EVIDENCE,
            max_execution_diagnostics: Self::DEFAULT_MAX_DIAGNOSTICS,
        }
    }

    /// Returns the maximum allowed registered detectors.
    #[must_use]
    pub const fn max_registered_detectors(&self) -> usize {
        self.max_registered_detectors
    }

    /// Returns the maximum allowed parameters per detector.
    #[must_use]
    pub const fn max_parameters_per_detector(&self) -> usize {
        self.max_parameters_per_detector
    }

    /// Returns the maximum total findings per run.
    #[must_use]
    pub const fn max_total_findings(&self) -> usize {
        self.max_total_findings
    }

    /// Returns the maximum total evidence records per run.
    #[must_use]
    pub const fn max_total_evidence_records(&self) -> usize {
        self.max_total_evidence_records
    }

    /// Returns the maximum diagnostic messages collected per run.
    #[must_use]
    pub const fn max_execution_diagnostics(&self) -> usize {
        self.max_execution_diagnostics
    }
}

impl Default for DetectionLimits {
    fn default() -> Self {
        Self::default_limits()
    }
}

/// Builder for constructing validated [`DetectionLimits`] instances.
#[derive(Debug, Clone)]
pub struct DetectionLimitsBuilder {
    max_registered_detectors: usize,
    max_parameters_per_detector: usize,
    max_total_findings: usize,
    max_total_evidence_records: usize,
    max_execution_diagnostics: usize,
}

impl DetectionLimitsBuilder {
    /// Creates a builder initialized with default limits.
    #[must_use]
    pub fn new() -> Self {
        let defaults = DetectionLimits::default_limits();
        Self {
            max_registered_detectors: defaults.max_registered_detectors,
            max_parameters_per_detector: defaults.max_parameters_per_detector,
            max_total_findings: defaults.max_total_findings,
            max_total_evidence_records: defaults.max_total_evidence_records,
            max_execution_diagnostics: defaults.max_execution_diagnostics,
        }
    }

    /// Sets the maximum registered detectors limit.
    #[must_use]
    pub fn max_registered_detectors(mut self, limit: usize) -> Self {
        self.max_registered_detectors = limit;
        self
    }

    /// Sets the maximum parameters per detector limit.
    #[must_use]
    pub fn max_parameters_per_detector(mut self, limit: usize) -> Self {
        self.max_parameters_per_detector = limit;
        self
    }

    /// Sets the maximum total findings limit.
    #[must_use]
    pub fn max_total_findings(mut self, limit: usize) -> Self {
        self.max_total_findings = limit;
        self
    }

    /// Sets the maximum total evidence records limit.
    #[must_use]
    pub fn max_total_evidence_records(mut self, limit: usize) -> Self {
        self.max_total_evidence_records = limit;
        self
    }

    /// Sets the maximum execution diagnostics limit.
    #[must_use]
    pub fn max_execution_diagnostics(mut self, limit: usize) -> Self {
        self.max_execution_diagnostics = limit;
        self
    }

    /// Builds and validates the [`DetectionLimits`].
    pub fn build(self) -> Result<DetectionLimits, DetectionLimitsValidationError> {
        DetectionLimits::try_new(
            self.max_registered_detectors,
            self.max_parameters_per_detector,
            self.max_total_findings,
            self.max_total_evidence_records,
            self.max_execution_diagnostics,
        )
    }
}

impl Default for DetectionLimitsBuilder {
    fn default() -> Self {
        Self::new()
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
/// referential integrity, duplicate finding rejection, transactional output acceptance, and resource bounds.
pub fn execute_detection(
    registry: &DetectorRegistry,
    input: &DetectionInput<'_>,
    configurations: &DetectorConfigurations,
    limits: &DetectionLimits,
) -> Result<DetectionRunOutcome, DetectionEngineError> {
    let default_cfg = DetectorConfig::enabled();

    // Check registry size against limits
    if registry.len() > limits.max_registered_detectors() {
        return Err(DetectionEngineError::ResourceLimit {
            resource: "registered_detectors",
            capacity: limits.max_registered_detectors(),
        });
    }

    // STEP 1: Whole-configuration preflight validation.
    // Ensure all configured detector IDs exist in the registry.
    for (detector_id, config) in configurations.iter() {
        if registry.get(detector_id).is_none() {
            return Err(DetectionEngineError::Config(
                DetectorConfigError::UnregisteredDetector(detector_id.clone()),
            ));
        }
        if config.parameters.len() > limits.max_parameters_per_detector() {
            return Err(DetectionEngineError::Config(
                DetectorConfigError::ParametersExceeded {
                    count: config.parameters.len(),
                    max: limits.max_parameters_per_detector(),
                },
            ));
        }
    }

    // Validate parameters for all registered detectors.
    for detector in registry.iter() {
        let meta = detector.metadata();
        let cfg = configurations.get(meta.id()).unwrap_or(&default_cfg);
        if cfg.parameters.len() > limits.max_parameters_per_detector() {
            return Err(DetectionEngineError::Config(
                DetectorConfigError::ParametersExceeded {
                    count: cfg.parameters.len(),
                    max: limits.max_parameters_per_detector(),
                },
            ));
        }
        if cfg.enabled {
            detector.validate_parameters(&cfg.parameters)?;
        }
    }

    // STEP 2: Deterministic execution in canonical DetectorId order.
    let mut overall_completion = input.completeness();
    let mut execution_records = Vec::with_capacity(registry.len());
    let mut accepted_findings: Vec<FindingRecord> = Vec::new();
    let mut accepted_evidence: Vec<EvidenceRecord> = Vec::new();
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

        let remaining_findings = limits
            .max_total_findings()
            .saturating_sub(accepted_findings.len());
        let remaining_evidence = limits
            .max_total_evidence_records()
            .saturating_sub(accepted_evidence.len());
        let mut sink = DetectorDraftSink::new(remaining_findings, remaining_evidence);

        match detector.evaluate(input, &cfg.parameters, &mut sink) {
            Err(DetectorExecutionError::ResourceLimitExceeded(msg)) => {
                overall_completion = DetectionInputCompleteness::Partial;
                if diagnostics.len() < limits.max_execution_diagnostics() {
                    diagnostics.push(format!(
                        "output budget exceeded, rejecting output from detector '{}': {msg}",
                        meta.id()
                    ));
                }
                execution_records.push(DetectorExecutionRecord {
                    detector_id: meta.id().clone(),
                    detector_version: meta.version(),
                    status: DetectorExecutionStatus::ResourceLimited,
                });
            }
            Err(DetectorExecutionError::InternalError(msg)) => {
                overall_completion = DetectionInputCompleteness::Partial;
                if diagnostics.len() < limits.max_execution_diagnostics() {
                    diagnostics.push(format!("detector '{}' failed: {msg}", meta.id()));
                }
                execution_records.push(DetectorExecutionRecord {
                    detector_id: meta.id().clone(),
                    detector_version: meta.version(),
                    status: DetectorExecutionStatus::Failed { reason: msg },
                });
            }
            Ok(()) => {
                let mut drafts = sink.into_drafts();
                if drafts.is_empty() {
                    execution_records.push(DetectorExecutionRecord {
                        detector_id: meta.id().clone(),
                        detector_version: meta.version(),
                        status: DetectorExecutionStatus::Executed,
                    });
                    continue;
                }

                // Canonicalize detector draft order within this detector before identity assignment
                drafts.sort_by(|a, b| {
                    a.subject()
                        .cmp(b.subject())
                        .then_with(|| a.title().cmp(b.title()))
                });

                // Validate incomplete data policy for AllowWithLimitations
                if input.completeness() == DetectionInputCompleteness::Partial
                    && meta.incomplete_data_policy() == IncompleteDataPolicy::AllowWithLimitations
                {
                    for draft in &drafts {
                        for input_lim in input.limitations() {
                            let mapped = input_lim.to_evidence_limitation();
                            let has_limitation = draft
                                .evidence()
                                .iter()
                                .any(|evi| evi.limitations().contains(&mapped));
                            if !has_limitation {
                                return Err(DetectionEngineError::Output(
                                    DetectionOutputError::IncompleteDataPolicyViolation {
                                        detector_id: meta.id().clone(),
                                        reason: "finding emitted on partial input without required input limitation evidence",
                                    },
                                ));
                            }
                        }
                    }
                }

                // Validate referential integrity of subject and evidence against DetectionInput
                for draft in &drafts {
                    // Subject flow references
                    for flow_ref in draft.subject().flow_references() {
                        if !input.flows().iter().any(|f| f.reference == *flow_ref) {
                            return Err(DetectionEngineError::Output(
                                DetectionOutputError::ReferentialIntegrityError(format!(
                                    "finding subject references unknown flow {flow_ref}"
                                )),
                            ));
                        }
                    }
                    // Subject observation references
                    for obs_ref in draft.subject().observation_references() {
                        if !input
                            .observations()
                            .iter()
                            .any(|o| o.reference() == *obs_ref)
                        {
                            return Err(DetectionEngineError::Output(
                                DetectionOutputError::ReferentialIntegrityError(format!(
                                    "finding subject references unknown observation {obs_ref}"
                                )),
                            ));
                        }
                    }
                    // Subject packet references
                    for pkt_ref in draft.subject().packet_references() {
                        let is_valid_pkt = input
                            .flows()
                            .iter()
                            .any(|f| f.first_packet == *pkt_ref || f.last_packet == *pkt_ref)
                            || input
                                .observations()
                                .iter()
                                .any(|o| *o.packet_reference() == *pkt_ref);
                        if !is_valid_pkt {
                            return Err(DetectionEngineError::Output(
                                DetectionOutputError::ReferentialIntegrityError(format!(
                                    "finding subject references unknown packet {pkt_ref:?}"
                                )),
                            ));
                        }
                    }

                    // Evidence references
                    for evi in draft.evidence() {
                        for flow_ref in evi.flow_references() {
                            if !input.flows().iter().any(|f| f.reference == *flow_ref) {
                                return Err(DetectionEngineError::Output(
                                    DetectionOutputError::ReferentialIntegrityError(format!(
                                        "evidence references unknown flow {flow_ref}"
                                    )),
                                ));
                            }
                        }
                        for obs_ref in evi.observation_references() {
                            if !input
                                .observations()
                                .iter()
                                .any(|o| o.reference() == *obs_ref)
                            {
                                return Err(DetectionEngineError::Output(
                                    DetectionOutputError::ReferentialIntegrityError(format!(
                                        "evidence references unknown observation {obs_ref}"
                                    )),
                                ));
                            }
                        }
                        for pkt_ref in evi.packet_references() {
                            let is_valid_pkt =
                                input.flows().iter().any(|f| {
                                    f.first_packet == *pkt_ref || f.last_packet == *pkt_ref
                                }) || input
                                    .observations()
                                    .iter()
                                    .any(|o| *o.packet_reference() == *pkt_ref);
                            if !is_valid_pkt {
                                return Err(DetectionEngineError::Output(
                                    DetectionOutputError::ReferentialIntegrityError(format!(
                                        "evidence references unknown packet {pkt_ref:?}"
                                    )),
                                ));
                            }
                        }
                    }
                }

                // Check duplicate finding key collision within sorted drafts
                for window in drafts.windows(2) {
                    if window[0].subject() == window[1].subject() {
                        return Err(DetectionEngineError::Output(
                            DetectionOutputError::DuplicateFindingIdentity {
                                detector_id: meta.id().clone(),
                            },
                        ));
                    }
                }

                // Check duplicate finding key collision against accepted findings
                for draft in &drafts {
                    if accepted_findings
                        .iter()
                        .any(|f| f.detector_id() == meta.id() && f.subject() == draft.subject())
                    {
                        return Err(DetectionEngineError::Output(
                            DetectionOutputError::DuplicateFindingIdentity {
                                detector_id: meta.id().clone(),
                            },
                        ));
                    }
                }

                // Check transactional output budgets with checked arithmetic
                let new_findings_count = drafts.len();
                let new_evidence_count = drafts
                    .iter()
                    .try_fold(0usize, |acc, d| acc.checked_add(d.evidence().len()))
                    .ok_or_else(|| DetectionEngineError::ResourceLimit {
                        resource: "evidence_count_overflow",
                        capacity: limits.max_total_evidence_records(),
                    })?;

                let fits_findings = accepted_findings
                    .len()
                    .checked_add(new_findings_count)
                    .is_some_and(|total| total <= limits.max_total_findings());

                let fits_evidence = accepted_evidence
                    .len()
                    .checked_add(new_evidence_count)
                    .is_some_and(|total| total <= limits.max_total_evidence_records());

                if !fits_findings || !fits_evidence {
                    overall_completion = DetectionInputCompleteness::Partial;
                    if diagnostics.len() < limits.max_execution_diagnostics() {
                        diagnostics.push(format!(
                            "output budget exceeded, rejecting output from detector '{}'",
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

                // Convert drafts transactionally in a temporary batch before committing
                let mut temp_findings = Vec::with_capacity(drafts.len());
                let mut temp_evidence = Vec::with_capacity(new_evidence_count);

                for draft in drafts {
                    let mut finding_evi_refs = Vec::with_capacity(draft.evidence().len());
                    let subject = draft.subject().clone();
                    let title = draft.title().clone();
                    let summary = draft.summary().clone();
                    let rationale = draft.rationale().clone();
                    let severity = draft.severity();
                    let confidence = draft.confidence();

                    for evi_draft in draft.into_evidence() {
                        let base_evi_len = accepted_evidence
                            .len()
                            .checked_add(temp_evidence.len())
                            .ok_or_else(|| DetectionEngineError::ResourceLimit {
                                resource: "evidence_index_overflow",
                                capacity: limits.max_total_evidence_records(),
                            })?;
                        let next_evi_idx = base_evi_len as u64;
                        let evi_ref = EvidenceReference::new(next_evi_idx);
                        let record = EvidenceRecord::from_draft(evi_ref, evi_draft);
                        temp_evidence.push(record);
                        finding_evi_refs.push(evi_ref);
                    }

                    let base_find_len = accepted_findings
                        .len()
                        .checked_add(temp_findings.len())
                        .ok_or_else(|| DetectionEngineError::ResourceLimit {
                            resource: "finding_index_overflow",
                            capacity: limits.max_total_findings(),
                        })?;
                    let next_find_idx = base_find_len as u64;
                    let finding_ref = FindingReference::new(next_find_idx);
                    let finding = FindingRecord::try_new(
                        finding_ref,
                        meta.id().clone(),
                        meta.version(),
                        subject,
                        title,
                        summary,
                        rationale,
                        severity,
                        confidence,
                        finding_evi_refs,
                    )
                    .map_err(DetectionOutputError::from)?;
                    temp_findings.push(finding);
                }

                accepted_evidence.extend(temp_evidence);
                accepted_findings.extend(temp_findings);

                execution_records.push(DetectorExecutionRecord {
                    detector_id: meta.id().clone(),
                    detector_version: meta.version(),
                    status: DetectorExecutionStatus::Executed,
                });
            }
        }
    }

    Ok(DetectionRunOutcome {
        completion: overall_completion,
        detector_executions: execution_records,
        findings: accepted_findings,
        evidence: accepted_evidence,
        diagnostics,
    })
}
