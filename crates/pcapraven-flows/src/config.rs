//! Configuration and resource limits for deterministic flow reconstruction.

use core::fmt;

/// Maximum allowed value for simultaneously tracked active flow keys (1,000,000).
pub const MAX_ALLOWED_TRACKED_FLOWS: usize = 1_000_000;
/// Maximum allowed value for total flow instances created in one run (10,000,000).
pub const MAX_ALLOWED_FLOW_INSTANCES: usize = 10_000_000;
/// Maximum allowed idle timeout value in seconds (30 days = 2,592,000 seconds).
pub const MAX_ALLOWED_TIMEOUT_SECONDS: u32 = 86_400 * 30;

/// Error returned when configuring invalid flow reconstruction limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowConfigError {
    /// A configuration value was zero where a positive value is required.
    ZeroValue {
        /// Name of the parameter that failed validation.
        parameter: &'static str,
    },
    /// A configuration value exceeded the maximum allowed hard safety cap.
    ExceedsHardCap {
        /// Name of the parameter that failed validation.
        parameter: &'static str,
        /// Provided value.
        value: usize,
        /// Maximum allowed value.
        max: usize,
    },
}

impl fmt::Display for FlowConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroValue { parameter } => {
                write!(
                    f,
                    "flow configuration parameter {} must be non-zero",
                    parameter
                )
            }
            Self::ExceedsHardCap {
                parameter,
                value,
                max,
            } => {
                write!(
                    f,
                    "flow configuration parameter {} value {} exceeds maximum allowed {}",
                    parameter, value, max
                )
            }
        }
    }
}

impl std::error::Error for FlowConfigError {}

/// Finite configuration governing bidirectional flow reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowReconstructionConfig {
    /// Inactivity threshold in seconds to close an idle TCP flow (default: 300s).
    pub tcp_idle_timeout_seconds: u32,
    /// Inactivity threshold in seconds to close an idle UDP flow (default: 60s).
    pub udp_idle_timeout_seconds: u32,
    /// Maximum number of distinct active flow keys simultaneously tracked (default: 65,536).
    pub maximum_tracked_flows: usize,
    /// Maximum total flow instances created across the entire reconstruction (default: 1,000,000).
    pub maximum_flow_instances: usize,
}

impl Default for FlowReconstructionConfig {
    fn default() -> Self {
        Self {
            tcp_idle_timeout_seconds: 300,
            udp_idle_timeout_seconds: 60,
            maximum_tracked_flows: 65_536,
            maximum_flow_instances: 1_000_000,
        }
    }
}

impl FlowReconstructionConfig {
    /// Creates a builder initialized with default flow reconstruction settings.
    #[must_use]
    pub fn builder() -> FlowReconstructionConfigBuilder {
        FlowReconstructionConfigBuilder::default()
    }

    /// Validates configuration parameters against non-zero requirements and hard safety caps.
    pub fn validate(&self) -> Result<(), FlowConfigError> {
        if self.tcp_idle_timeout_seconds == 0 {
            return Err(FlowConfigError::ZeroValue {
                parameter: "tcp_idle_timeout_seconds",
            });
        }
        if self.tcp_idle_timeout_seconds > MAX_ALLOWED_TIMEOUT_SECONDS {
            return Err(FlowConfigError::ExceedsHardCap {
                parameter: "tcp_idle_timeout_seconds",
                value: self.tcp_idle_timeout_seconds as usize,
                max: MAX_ALLOWED_TIMEOUT_SECONDS as usize,
            });
        }
        if self.udp_idle_timeout_seconds == 0 {
            return Err(FlowConfigError::ZeroValue {
                parameter: "udp_idle_timeout_seconds",
            });
        }
        if self.udp_idle_timeout_seconds > MAX_ALLOWED_TIMEOUT_SECONDS {
            return Err(FlowConfigError::ExceedsHardCap {
                parameter: "udp_idle_timeout_seconds",
                value: self.udp_idle_timeout_seconds as usize,
                max: MAX_ALLOWED_TIMEOUT_SECONDS as usize,
            });
        }
        if self.maximum_tracked_flows == 0 {
            return Err(FlowConfigError::ZeroValue {
                parameter: "maximum_tracked_flows",
            });
        }
        if self.maximum_tracked_flows > MAX_ALLOWED_TRACKED_FLOWS {
            return Err(FlowConfigError::ExceedsHardCap {
                parameter: "maximum_tracked_flows",
                value: self.maximum_tracked_flows,
                max: MAX_ALLOWED_TRACKED_FLOWS,
            });
        }
        if self.maximum_flow_instances == 0 {
            return Err(FlowConfigError::ZeroValue {
                parameter: "maximum_flow_instances",
            });
        }
        if self.maximum_flow_instances > MAX_ALLOWED_FLOW_INSTANCES {
            return Err(FlowConfigError::ExceedsHardCap {
                parameter: "maximum_flow_instances",
                value: self.maximum_flow_instances,
                max: MAX_ALLOWED_FLOW_INSTANCES,
            });
        }
        Ok(())
    }
}

/// Builder for constructing a validated [`FlowReconstructionConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowReconstructionConfigBuilder {
    config: FlowReconstructionConfig,
}

impl FlowReconstructionConfigBuilder {
    /// Sets the TCP idle timeout in seconds.
    #[must_use]
    pub const fn tcp_idle_timeout_seconds(mut self, seconds: u32) -> Self {
        self.config.tcp_idle_timeout_seconds = seconds;
        self
    }

    /// Sets the UDP idle timeout in seconds.
    #[must_use]
    pub const fn udp_idle_timeout_seconds(mut self, seconds: u32) -> Self {
        self.config.udp_idle_timeout_seconds = seconds;
        self
    }

    /// Sets the maximum number of simultaneously tracked active flow keys.
    #[must_use]
    pub const fn maximum_tracked_flows(mut self, count: usize) -> Self {
        self.config.maximum_tracked_flows = count;
        self
    }

    /// Sets the maximum total flow instances created across reconstruction.
    #[must_use]
    pub const fn maximum_flow_instances(mut self, count: usize) -> Self {
        self.config.maximum_flow_instances = count;
        self
    }

    /// Validates and constructs the [`FlowReconstructionConfig`].
    pub fn build(self) -> Result<FlowReconstructionConfig, FlowConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}
