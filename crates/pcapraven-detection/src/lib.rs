//! Detection engine architecture for PcapRaven.
//!
//! Provides deterministic detector registration, whole-configuration preflight validation,
//! immutable borrowed detection inputs, incomplete-data policies, and canonical finding/evidence
//! identity assignment without floating-point numbers or raw packet payload copies.

pub mod config;
pub mod detector;
pub mod engine;
pub mod error;
pub mod registry;

pub use config::{
    DetectorConfig, DetectorConfigurations, DetectorParameter, DetectorParameterKey,
    DetectorParameterValue, DetectorParameters, DetectorParametersBuilder,
    MAX_PARAMETER_KEY_LENGTH,
};
pub use detector::{Detector, DetectorMetadata, IncompleteDataPolicy};
pub use engine::{
    DetectionInput, DetectionInputCompleteness, DetectionInputLimitation, DetectionLimits,
    DetectionRunOutcome, DetectorExecutionRecord, DetectorExecutionStatus, execute_detection,
};
pub use error::{
    DetectionEngineError, DetectionOutputError, DetectorConfigError, DetectorExecutionError,
    DetectorRegistryError,
};
pub use registry::DetectorRegistry;
