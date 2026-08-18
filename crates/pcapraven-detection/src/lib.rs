//! Detection engine architecture for PcapRaven.
//!
//! Provides deterministic detector registration, whole-configuration preflight validation,
//! immutable borrowed detection inputs, incomplete-data policies, and canonical finding/evidence
//! identity assignment without floating-point numbers or raw packet payload copies.

pub mod config;
pub mod detector;
pub mod dns_anomaly;
pub mod engine;
pub mod error;
pub mod periodic_beaconing;
pub mod registry;

pub use config::{
    DetectorConfig, DetectorConfigurations, DetectorParameter, DetectorParameterKey,
    DetectorParameterValue, DetectorParameters, DetectorParametersBuilder,
    MAX_PARAMETER_KEY_LENGTH,
};
pub use detector::{Detector, DetectorDraftSink, DetectorMetadata, IncompleteDataPolicy};
pub use dns_anomaly::{
    DnsLongQueryNameDetector, DnsPossibleTunnelingDetector, label_octet_diversity_ratio,
};
pub use engine::{
    DetectionInput, DetectionInputCompleteness, DetectionInputLimitation, DetectionLimits,
    DetectionLimitsBuilder, DetectionRunOutcome, DetectorExecutionRecord, DetectorExecutionStatus,
    execute_detection,
};
pub use error::{
    DetectionEngineError, DetectionInputError, DetectionLimitsValidationError,
    DetectionOutputError, DetectorConfigError, DetectorExecutionError, DetectorRegistryError,
    MAX_DETECTOR_ERROR_MESSAGE_LENGTH,
};
pub use periodic_beaconing::PeriodicBeaconingDetector;
pub use registry::DetectorRegistry;
