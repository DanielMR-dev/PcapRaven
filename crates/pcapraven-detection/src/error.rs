//! Error types for detector registration, configuration, evaluation, and engine execution.

use crate::engine::DetectionInputLimitation;
use core::fmt;
use pcapraven_domain::{
    DetectorId, EvidenceReference, EvidenceValidationError, FindingValidationError, FlowReference,
    ObservationReference,
};

/// Errors occurring during detector configuration validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorConfigError {
    /// Parameter key must not be empty.
    EmptyParameterKey,
    /// Parameter key exceeds maximum byte length.
    ParameterKeyTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Parameter key contains an invalid character.
    InvalidParameterKeyCharacter {
        /// Invalid character.
        character: char,
    },
    /// Duplicate parameter key in parameter collection.
    DuplicateParameterKey(String),
    /// Parameter keys must be strictly increasing.
    OutOfOrderParameterKey {
        /// Previous parameter key.
        previous: String,
        /// Attempted parameter key.
        attempted: String,
    },
    /// Number of parameters exceeds configured maximum.
    ParametersExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Total detector configurations count exceeds maximum.
    ConfigurationsExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Detector encountered an unknown configuration parameter.
    UnknownParameter(String),
    /// Required detector configuration parameter is missing.
    MissingRequiredParameter(String),
    /// Parameter value has an unexpected type.
    InvalidParameterType {
        /// Parameter key.
        key: String,
        /// Expected type name.
        expected: &'static str,
    },
    /// Parameter value is semantically invalid or out of acceptable range.
    ParameterValueOutOfRange {
        /// Parameter key.
        key: String,
        /// Description of the range violation.
        reason: &'static str,
    },
    /// Configuration provided for an unregistered detector ID.
    UnregisteredDetector(DetectorId),
}

impl fmt::Display for DetectorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyParameterKey => f.write_str("detector parameter key cannot be empty"),
            Self::ParameterKeyTooLong { length, max } => write!(
                f,
                "detector parameter key length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::InvalidParameterKeyCharacter { character } => write!(
                f,
                "detector parameter key contains invalid character '{character}'"
            ),
            Self::DuplicateParameterKey(key) => {
                write!(f, "duplicate detector parameter key: {key}")
            }
            Self::OutOfOrderParameterKey {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order detector parameter key: attempted '{attempted}' after '{previous}'"
            ),
            Self::ParametersExceeded { count, max } => write!(
                f,
                "detector parameters count ({count}) exceeds maximum ({max})"
            ),
            Self::ConfigurationsExceeded { count, max } => write!(
                f,
                "detector configurations count ({count}) exceeds maximum ({max})"
            ),
            Self::UnknownParameter(key) => {
                write!(f, "unknown detector parameter: {key}")
            }
            Self::MissingRequiredParameter(key) => {
                write!(f, "missing required detector parameter: {key}")
            }
            Self::InvalidParameterType { key, expected } => {
                write!(f, "parameter '{key}' has invalid type, expected {expected}")
            }
            Self::ParameterValueOutOfRange { key, reason } => {
                write!(f, "parameter '{key}' value out of range: {reason}")
            }
            Self::UnregisteredDetector(id) => {
                write!(f, "configuration provided for unregistered detector '{id}'")
            }
        }
    }
}

impl std::error::Error for DetectorConfigError {}

/// Errors occurring during detector registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorRegistryError {
    /// Built-in component metadata failed its static validation boundary.
    InvalidStaticMetadata {
        /// Name of the built-in component whose metadata was invalid.
        component: &'static str,
    },
    /// Registry capacity must be greater than zero.
    ZeroRegistryCapacity,
    /// Registry capacity exceeds hard maximum.
    RegistryCapacityAboveHardMaximum {
        /// Attempted capacity.
        attempted: usize,
        /// Maximum allowed capacity.
        max: usize,
    },
    /// A detector with the same DetectorId was already registered.
    DuplicateDetectorId(DetectorId),
    /// A detector identifier is registered in both detector and correlator registries.
    CrossRegistryDetectorIdCollision(DetectorId),
    /// Correlator requires a primary detector that is not registered.
    MissingRequiredPrimaryDetector {
        /// Correlator identifier.
        correlator_id: DetectorId,
        /// Required primary detector identifier.
        required_detector_id: DetectorId,
    },
    /// Correlator declares invalid required primary detector IDs.
    InvalidRequiredPrimaryDetectorIds {
        /// Correlator identifier.
        correlator_id: DetectorId,
        /// Description of validation failure.
        reason: &'static str,
    },
    /// Component declares invalid MITRE ATT&CK mapping declarations.
    InvalidMitreMappingDeclarations {
        /// Component identifier.
        component_id: DetectorId,
        /// Description of validation failure.
        reason: &'static str,
    },
    /// Registered detector count exceeds registry capacity.
    RegistryCapacityExceeded {
        /// Current count.
        count: usize,
        /// Maximum capacity.
        max: usize,
    },
    /// Requested detector was not found in registry.
    DetectorNotFound(DetectorId),
}

impl fmt::Display for DetectorRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStaticMetadata { component } => {
                write!(
                    f,
                    "built-in component '{component}' has invalid static metadata"
                )
            }
            Self::ZeroRegistryCapacity => {
                f.write_str("detector registry capacity must be greater than zero")
            }
            Self::RegistryCapacityAboveHardMaximum { attempted, max } => write!(
                f,
                "detector registry capacity ({attempted}) exceeds hard maximum ({max})"
            ),
            Self::DuplicateDetectorId(id) => {
                write!(f, "duplicate detector registration with ID '{id}'")
            }
            Self::CrossRegistryDetectorIdCollision(id) => {
                write!(
                    f,
                    "detector identifier '{id}' is registered in both detector and correlation registries"
                )
            }
            Self::MissingRequiredPrimaryDetector {
                correlator_id,
                required_detector_id,
            } => write!(
                f,
                "correlator '{correlator_id}' requires unregistered primary detector '{required_detector_id}'"
            ),
            Self::InvalidRequiredPrimaryDetectorIds {
                correlator_id,
                reason,
            } => write!(
                f,
                "correlator '{correlator_id}' declares invalid required primary detector IDs: {reason}"
            ),
            Self::InvalidMitreMappingDeclarations {
                component_id,
                reason,
            } => write!(
                f,
                "component '{component_id}' declares invalid MITRE ATT&CK mapping declarations: {reason}"
            ),
            Self::RegistryCapacityExceeded { count, max } => {
                write!(f, "detector registry capacity exceeded ({count} > {max})")
            }
            Self::DetectorNotFound(id) => {
                write!(f, "detector '{id}' not found in registry")
            }
        }
    }
}

impl std::error::Error for DetectorRegistryError {}

/// Errors occurring during detection limits validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionLimitsValidationError {
    /// A configured detection limit must be greater than zero.
    ZeroLimit(&'static str),
    /// A configured detection limit exceeds its hard maximum.
    LimitAboveHardMaximum {
        /// Limit name.
        limit_name: &'static str,
        /// Attempted value.
        attempted: usize,
        /// Maximum allowed value.
        max: usize,
    },
}

impl fmt::Display for DetectionLimitsValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit(name) => {
                write!(f, "detection limit '{name}' must be greater than zero")
            }
            Self::LimitAboveHardMaximum {
                limit_name,
                attempted,
                max,
            } => write!(
                f,
                "detection limit '{limit_name}' value ({attempted}) exceeds hard maximum ({max})"
            ),
        }
    }
}

impl std::error::Error for DetectionLimitsValidationError {}

/// Errors occurring during validation of borrowed detection input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionInputError {
    /// Duplicate flow record reference in detection input.
    DuplicateFlow(FlowReference),
    /// Flow record references must be strictly increasing.
    OutOfOrderFlow {
        /// Previous flow ordinal.
        previous: u64,
        /// Attempted flow ordinal.
        attempted: u64,
    },
    /// Duplicate protocol observation reference in detection input.
    DuplicateObservation(ObservationReference),
    /// Protocol observation references must be strictly increasing.
    OutOfOrderObservation {
        /// Previous observation reference.
        previous: ObservationReference,
        /// Attempted observation reference.
        attempted: ObservationReference,
    },
    /// Duplicate input limitation in detection input.
    DuplicateLimitation(DetectionInputLimitation),
    /// Input limitations must be strictly sorted.
    OutOfOrderLimitation {
        /// Previous limitation.
        previous: DetectionInputLimitation,
        /// Attempted limitation.
        attempted: DetectionInputLimitation,
    },
    /// Complete detection input cannot have analysis limitations.
    CompleteInputWithLimitations,
    /// Partial detection input must specify at least one analysis limitation.
    PartialInputWithoutLimitations,
}

impl fmt::Display for DetectionInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFlow(flow) => {
                write!(f, "duplicate flow reference in detection input: {flow}")
            }
            Self::OutOfOrderFlow {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order flow reference in detection input: attempted flow:{attempted} after flow:{previous}"
            ),
            Self::DuplicateObservation(obs) => {
                write!(
                    f,
                    "duplicate observation reference in detection input: {obs}"
                )
            }
            Self::OutOfOrderObservation {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order observation reference in detection input: attempted {attempted} after {previous}"
            ),
            Self::DuplicateLimitation(lim) => {
                write!(f, "duplicate limitation in detection input: {lim}")
            }
            Self::OutOfOrderLimitation {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order limitation in detection input: attempted {attempted} after {previous}"
            ),
            Self::CompleteInputWithLimitations => {
                f.write_str("complete detection input must not specify analysis limitations")
            }
            Self::PartialInputWithoutLimitations => {
                f.write_str("partial detection input must specify at least one analysis limitation")
            }
        }
    }
}

impl std::error::Error for DetectionInputError {}

/// Maximum byte length for dynamic detector error strings (512 bytes).
pub const MAX_DETECTOR_ERROR_MESSAGE_LENGTH: usize = 512;

/// Errors occurring during internal detector evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorExecutionError {
    /// Internal execution failure within the detector.
    InternalError(String),
    /// Detector exceeded its internal resource budget.
    ResourceLimitExceeded(String),
}

impl DetectorExecutionError {
    /// Creates a validated internal error with bounded length and no prohibited control characters.
    #[must_use]
    pub fn internal_error(message: impl AsRef<str>) -> Self {
        Self::InternalError(Self::sanitize_message(message.as_ref()))
    }

    /// Creates a validated resource limit error with bounded length and no prohibited control characters.
    #[must_use]
    pub fn resource_limit(message: impl AsRef<str>) -> Self {
        Self::ResourceLimitExceeded(Self::sanitize_message(message.as_ref()))
    }

    fn sanitize_message(raw: &str) -> String {
        let mut clean = String::with_capacity(raw.len().min(MAX_DETECTOR_ERROR_MESSAGE_LENGTH));
        for c in raw.chars() {
            let ch = if c.is_control() { ' ' } else { c };
            let ch_len = ch.len_utf8();
            if clean.len().saturating_add(ch_len) > MAX_DETECTOR_ERROR_MESSAGE_LENGTH {
                break;
            }
            clean.push(ch);
        }
        if clean.is_empty() {
            "unspecified error".to_string()
        } else {
            clean
        }
    }
}

impl fmt::Display for DetectorExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InternalError(msg) => write!(f, "detector execution failed: {msg}"),
            Self::ResourceLimitExceeded(msg) => {
                write!(f, "detector resource limit exceeded: {msg}")
            }
        }
    }
}

impl std::error::Error for DetectorExecutionError {}

/// Errors validating detector-emitted findings and evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionOutputError {
    /// Duplicate finding identity emitted by the same detector for the same subject.
    DuplicateFindingIdentity {
        /// Originating detector identifier.
        detector_id: DetectorId,
    },
    /// Finding emitted without any supporting evidence.
    FindingWithoutEvidence,
    /// Evidence reference does not resolve to an accepted evidence record.
    DanglingEvidenceReference(EvidenceReference),
    /// Subject references a flow or observation not present in the detection input.
    ReferentialIntegrityError(String),
    /// Domain validation error on finding structure.
    FindingValidationError(FindingValidationError),
    /// Domain validation error on evidence structure.
    EvidenceValidationError(EvidenceValidationError),
    /// Domain validation error on MITRE structure.
    MitreAttackValidationError(pcapraven_domain::MitreAttackValidationError),
    /// Detector with AllowWithLimitations emitted finding without limitation evidence on partial input.
    IncompleteDataPolicyViolation {
        /// Detector ID.
        detector_id: DetectorId,
        /// Violation description.
        reason: &'static str,
    },
    /// Correlator emitted a source finding reference that is invalid or does not exist in primary snapshot.
    InvalidSourceFindingReference {
        /// Correlator ID.
        correlator_id: DetectorId,
        /// Referenced finding reference.
        finding_reference: pcapraven_domain::FindingReference,
        /// Reason for failure.
        reason: &'static str,
    },
    /// Correlator emitted an evidence reference not owned by declared source findings.
    UnownedCorrelationEvidenceReference {
        /// Correlator ID.
        correlator_id: DetectorId,
        /// Offending evidence reference.
        evidence_reference: EvidenceReference,
    },
    /// Correlator emitted a subject reference not owned by declared source findings.
    UnownedCorrelationSubjectReference {
        /// Correlator ID.
        correlator_id: DetectorId,
        /// Description of subject provenance failure.
        reason: &'static str,
    },
    /// Correlator source finding count violates requirements.
    InvalidCorrelationSourceCardinality {
        /// Correlator ID.
        correlator_id: DetectorId,
        /// Actual count.
        count: usize,
        /// Expected count.
        expected: usize,
    },
    /// Total output resource limit exceeded.
    OutputLimitExceeded {
        /// Resource name.
        resource: &'static str,
        /// Limit reached.
        limit: usize,
    },
}

impl fmt::Display for DetectionOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFindingIdentity { detector_id } => write!(
                f,
                "duplicate finding identity emitted by detector '{detector_id}' for identical subject"
            ),
            Self::FindingWithoutEvidence => {
                f.write_str("detector emitted finding without supporting evidence")
            }
            Self::DanglingEvidenceReference(evi) => {
                write!(f, "dangling evidence reference: {evi}")
            }
            Self::ReferentialIntegrityError(msg) => {
                write!(f, "referential integrity violation: {msg}")
            }
            Self::FindingValidationError(err) => write!(f, "finding validation error: {err}"),
            Self::EvidenceValidationError(err) => write!(f, "evidence validation error: {err}"),
            Self::MitreAttackValidationError(err) => {
                write!(f, "MITRE ATT&CK validation error: {err}")
            }
            Self::IncompleteDataPolicyViolation {
                detector_id,
                reason,
            } => write!(
                f,
                "detector '{detector_id}' incomplete data policy violation: {reason}"
            ),
            Self::InvalidSourceFindingReference {
                correlator_id,
                finding_reference,
                reason,
            } => write!(
                f,
                "correlator '{correlator_id}' invalid source finding reference {finding_reference}: {reason}"
            ),
            Self::UnownedCorrelationEvidenceReference {
                correlator_id,
                evidence_reference,
            } => write!(
                f,
                "correlator '{correlator_id}' emitted evidence {evidence_reference} not owned by declared source findings"
            ),
            Self::UnownedCorrelationSubjectReference {
                correlator_id,
                reason,
            } => write!(
                f,
                "correlator '{correlator_id}' emitted subject outside source finding provenance: {reason}"
            ),
            Self::InvalidCorrelationSourceCardinality {
                correlator_id,
                count,
                expected,
            } => write!(
                f,
                "correlator '{correlator_id}' source count ({count}) does not match expected ({expected})"
            ),
            Self::OutputLimitExceeded { resource, limit } => write!(
                f,
                "detection output limit for {resource} ({limit}) exceeded"
            ),
        }
    }
}

impl std::error::Error for DetectionOutputError {}

impl From<FindingValidationError> for DetectionOutputError {
    fn from(err: FindingValidationError) -> Self {
        Self::FindingValidationError(err)
    }
}

impl From<EvidenceValidationError> for DetectionOutputError {
    fn from(err: EvidenceValidationError) -> Self {
        Self::EvidenceValidationError(err)
    }
}

impl From<pcapraven_domain::MitreAttackValidationError> for DetectionOutputError {
    fn from(err: pcapraven_domain::MitreAttackValidationError) -> Self {
        Self::MitreAttackValidationError(err)
    }
}

/// Unified error returned by the detection engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionEngineError {
    /// Configuration validation error prior to execution.
    Config(DetectorConfigError),
    /// Registry error.
    Registry(DetectorRegistryError),
    /// Limits validation error.
    InvalidLimits(DetectionLimitsValidationError),
    /// Input validation error.
    Input(DetectionInputError),
    /// Detector output validation error.
    Output(DetectionOutputError),
    /// System resource limit reached.
    ResourceLimit {
        /// Resource name.
        resource: &'static str,
        /// Limit.
        capacity: usize,
    },
}

impl fmt::Display for DetectionEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "configuration error: {err}"),
            Self::Registry(err) => write!(f, "registry error: {err}"),
            Self::InvalidLimits(err) => write!(f, "limits error: {err}"),
            Self::Input(err) => write!(f, "input error: {err}"),
            Self::Output(err) => write!(f, "output error: {err}"),
            Self::ResourceLimit { resource, capacity } => write!(
                f,
                "detection resource limit for {resource} ({capacity}) reached"
            ),
        }
    }
}

impl std::error::Error for DetectionEngineError {}

impl From<DetectorConfigError> for DetectionEngineError {
    fn from(err: DetectorConfigError) -> Self {
        Self::Config(err)
    }
}

impl From<DetectorRegistryError> for DetectionEngineError {
    fn from(err: DetectorRegistryError) -> Self {
        Self::Registry(err)
    }
}

impl From<DetectionLimitsValidationError> for DetectionEngineError {
    fn from(err: DetectionLimitsValidationError) -> Self {
        Self::InvalidLimits(err)
    }
}

impl From<DetectionInputError> for DetectionEngineError {
    fn from(err: DetectionInputError) -> Self {
        Self::Input(err)
    }
}

impl From<DetectionOutputError> for DetectionEngineError {
    fn from(err: DetectionOutputError) -> Self {
        Self::Output(err)
    }
}
