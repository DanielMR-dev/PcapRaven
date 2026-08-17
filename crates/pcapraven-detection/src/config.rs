//! Bounded, typed configuration and parameter models for detectors.

use crate::error::DetectorConfigError;
use core::fmt;
use pcapraven_domain::{DetectorId, EvidenceRatio, FlowDuration};

/// Maximum allowed byte length for a detector parameter key (64 bytes).
pub const MAX_PARAMETER_KEY_LENGTH: usize = 64;

/// Validated, bounded key identifying a detector configuration parameter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorParameterKey {
    key: String,
}

impl DetectorParameterKey {
    /// Creates and validates a new detector parameter key.
    pub fn try_new(key: impl AsRef<str>) -> Result<Self, DetectorConfigError> {
        let raw = key.as_ref();
        if raw.is_empty() {
            return Err(DetectorConfigError::EmptyParameterKey);
        }
        if raw.len() > MAX_PARAMETER_KEY_LENGTH {
            return Err(DetectorConfigError::ParameterKeyTooLong {
                length: raw.len(),
                max: MAX_PARAMETER_KEY_LENGTH,
            });
        }

        let bytes = raw.as_bytes();
        let first = bytes[0];
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(DetectorConfigError::InvalidParameterKeyCharacter {
                character: first as char,
            });
        }

        for &b in &bytes[1..] {
            if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'.' && b != b'_' && b != b'-'
            {
                return Err(DetectorConfigError::InvalidParameterKeyCharacter {
                    character: b as char,
                });
            }
        }

        Ok(Self {
            key: raw.to_string(),
        })
    }

    /// Returns the parameter key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for DetectorParameterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key)
    }
}

/// Strictly typed parameter value without floating-point numbers or arbitrary strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectorParameterValue {
    /// Boolean flag.
    Boolean(bool),
    /// Unsigned 128-bit integer.
    Unsigned(u128),
    /// Signed 128-bit integer.
    Signed(i128),
    /// Exact rational ratio.
    Ratio(EvidenceRatio),
    /// Exact rational temporal duration.
    Duration(FlowDuration),
}

impl fmt::Display for DetectorParameterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Unsigned(u) => write!(f, "{u}"),
            Self::Signed(s) => write!(f, "{s}"),
            Self::Ratio(r) => write!(f, "{r}"),
            Self::Duration(d) => write!(f, "{d}"),
        }
    }
}

/// An individual key-value parameter pair for detector configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DetectorParameter {
    /// Parameter identifier key.
    pub key: DetectorParameterKey,
    /// Parameter value.
    pub value: DetectorParameterValue,
}

impl DetectorParameter {
    /// Creates a new parameter pair.
    #[must_use]
    pub const fn new(key: DetectorParameterKey, value: DetectorParameterValue) -> Self {
        Self { key, value }
    }
}

/// Builder for constructing validated, strictly sorted [`DetectorParameters`].
#[derive(Debug, Clone, Default)]
pub struct DetectorParametersBuilder {
    parameters: Vec<DetectorParameter>,
}

impl DetectorParametersBuilder {
    /// Creates a new empty parameters builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a parameter, ensuring unique keys, capacity limits, and strict ordering.
    pub fn add(
        &mut self,
        key: DetectorParameterKey,
        value: DetectorParameterValue,
    ) -> Result<&mut Self, DetectorConfigError> {
        if self.parameters.len() >= DetectorParameters::HARD_MAX_PARAMETERS {
            return Err(DetectorConfigError::ParametersExceeded {
                count: self.parameters.len() + 1,
                max: DetectorParameters::HARD_MAX_PARAMETERS,
            });
        }
        if let Some(last) = self.parameters.last() {
            if last.key == key {
                return Err(DetectorConfigError::DuplicateParameterKey(
                    key.as_str().to_string(),
                ));
            }
            if key < last.key {
                return Err(DetectorConfigError::OutOfOrderParameterKey {
                    previous: last.key.as_str().to_string(),
                    attempted: key.as_str().to_string(),
                });
            }
        }
        self.parameters.push(DetectorParameter::new(key, value));
        Ok(self)
    }

    /// Builds the validated [`DetectorParameters`] collection.
    pub fn build(self) -> Result<DetectorParameters, DetectorConfigError> {
        Ok(DetectorParameters {
            parameters: self.parameters,
        })
    }
}

/// Bounded, deterministic collection of detector configuration parameters.
///
/// Storage is strictly ordered by [`DetectorParameterKey`] with no duplicate keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetectorParameters {
    parameters: Vec<DetectorParameter>,
}

impl DetectorParameters {
    /// Default maximum parameters per detector (32).
    pub const DEFAULT_MAX_PARAMETERS: usize = 32;
    /// Hard maximum parameters per detector (256).
    pub const HARD_MAX_PARAMETERS: usize = 256;

    /// Creates an empty parameters collection.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            parameters: Vec::new(),
        }
    }

    /// Returns a new parameters builder.
    #[must_use]
    pub fn builder() -> DetectorParametersBuilder {
        DetectorParametersBuilder::new()
    }

    /// Creates parameters from a vector, validating strict order and uniqueness.
    pub fn try_new(parameters: Vec<DetectorParameter>) -> Result<Self, DetectorConfigError> {
        if parameters.len() > Self::HARD_MAX_PARAMETERS {
            return Err(DetectorConfigError::ParametersExceeded {
                count: parameters.len(),
                max: Self::HARD_MAX_PARAMETERS,
            });
        }
        for window in parameters.windows(2) {
            if window[0].key == window[1].key {
                return Err(DetectorConfigError::DuplicateParameterKey(
                    window[1].key.as_str().to_string(),
                ));
            }
            if window[1].key < window[0].key {
                return Err(DetectorConfigError::OutOfOrderParameterKey {
                    previous: window[0].key.as_str().to_string(),
                    attempted: window[1].key.as_str().to_string(),
                });
            }
        }
        Ok(Self { parameters })
    }

    /// Looks up a parameter value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&DetectorParameterValue> {
        self.parameters
            .iter()
            .find(|p| p.key.as_str() == key)
            .map(|p| &p.value)
    }

    /// Looks up a boolean parameter value by key.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key) {
            Some(DetectorParameterValue::Boolean(b)) => Some(*b),
            _ => None,
        }
    }

    /// Looks up an unsigned integer parameter value by key.
    #[must_use]
    pub fn get_unsigned(&self, key: &str) -> Option<u128> {
        match self.get(key) {
            Some(DetectorParameterValue::Unsigned(u)) => Some(*u),
            _ => None,
        }
    }

    /// Looks up a signed integer parameter value by key.
    #[must_use]
    pub fn get_signed(&self, key: &str) -> Option<i128> {
        match self.get(key) {
            Some(DetectorParameterValue::Signed(s)) => Some(*s),
            _ => None,
        }
    }

    /// Looks up an exact rational ratio parameter value by key.
    #[must_use]
    pub fn get_ratio(&self, key: &str) -> Option<EvidenceRatio> {
        match self.get(key) {
            Some(DetectorParameterValue::Ratio(r)) => Some(*r),
            _ => None,
        }
    }

    /// Looks up an exact temporal duration parameter value by key.
    #[must_use]
    pub fn get_duration(&self, key: &str) -> Option<FlowDuration> {
        match self.get(key) {
            Some(DetectorParameterValue::Duration(d)) => Some(*d),
            _ => None,
        }
    }

    /// Returns the number of parameters in the collection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parameters.len()
    }

    /// Returns `true` if the parameters collection is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parameters.is_empty()
    }

    /// Returns an iterator over the parameters.
    pub fn iter(&self) -> core::slice::Iter<'_, DetectorParameter> {
        self.parameters.iter()
    }

    /// Returns a slice of the parameter pairs.
    #[must_use]
    pub fn as_slice(&self) -> &[DetectorParameter] {
        &self.parameters
    }
}

/// Execution configuration for a single registered detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorConfig {
    /// Whether the detector is enabled for evaluation.
    pub enabled: bool,
    /// Parameter settings for the detector.
    pub parameters: DetectorParameters,
}

impl DetectorConfig {
    /// Creates a enabled detector configuration with default/empty parameters.
    #[must_use]
    pub const fn enabled() -> Self {
        Self {
            enabled: true,
            parameters: DetectorParameters::empty(),
        }
    }

    /// Creates a disabled detector configuration.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            parameters: DetectorParameters::empty(),
        }
    }

    /// Creates a detector configuration with explicit enablement and parameters.
    #[must_use]
    pub const fn new(enabled: bool, parameters: DetectorParameters) -> Self {
        Self {
            enabled,
            parameters,
        }
    }
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self::enabled()
    }
}

/// Map of detector configurations keyed by [`DetectorId`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectorConfigurations {
    configs: Vec<(DetectorId, DetectorConfig)>,
}

impl DetectorConfigurations {
    /// Creates an empty configurations set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces configuration for a detector.
    pub fn insert(&mut self, detector_id: DetectorId, config: DetectorConfig) {
        if let Some(existing) = self.configs.iter_mut().find(|(id, _)| *id == detector_id) {
            existing.1 = config;
        } else {
            self.configs.push((detector_id, config));
            self.configs.sort_by(|a, b| a.0.cmp(&b.0));
        }
    }

    /// Gets configuration for a detector, or returns None.
    #[must_use]
    pub fn get(&self, detector_id: &DetectorId) -> Option<&DetectorConfig> {
        self.configs
            .iter()
            .find(|(id, _)| id == detector_id)
            .map(|(_, config)| config)
    }
}
