//! Error types for detector registration, configuration, evaluation, and engine execution.

use core::fmt;
use pcapraven_domain::{
    DetectorId, EvidenceReference, EvidenceValidationError, FindingValidationError,
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
    /// A detector with the same DetectorId was already registered.
    DuplicateDetectorId(DetectorId),
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
            Self::DuplicateDetectorId(id) => {
                write!(f, "duplicate detector registration with ID '{id}'")
            }
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

/// Errors occurring during internal detector evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorExecutionError {
    /// Internal execution failure within the detector.
    InternalError(String),
    /// Detector exceeded its internal resource budget.
    ResourceLimitExceeded(String),
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
    /// Detector with AllowWithLimitations emitted finding without limitation evidence on partial input.
    IncompleteDataPolicyViolation {
        /// Detector ID.
        detector_id: DetectorId,
        /// Violation description.
        reason: &'static str,
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
            Self::IncompleteDataPolicyViolation {
                detector_id,
                reason,
            } => write!(
                f,
                "detector '{detector_id}' incomplete data policy violation: {reason}"
            ),
            Self::OutputLimitExceeded { resource, limit } => write!(
                f,
                "detection output limit for {resource} ({limit}) exceeded"
            ),
        }
    }
}

impl std::error::Error for DetectionOutputError {}

/// Unified error returned by the detection engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionEngineError {
    /// Configuration validation error prior to execution.
    Config(DetectorConfigError),
    /// Registry error.
    Registry(DetectorRegistryError),
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

impl From<DetectionOutputError> for DetectionEngineError {
    fn from(err: DetectionOutputError) -> Self {
        Self::Output(err)
    }
}
