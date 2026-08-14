//! Configurable resource limits for packet normalization.

use core::fmt;

/// Maximum allowed value for retained transport application payload bytes (64 MiB).
pub const MAX_ALLOWED_RETAINED_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
/// Maximum allowed value for diagnostics per packet (1,024).
pub const MAX_ALLOWED_DIAGNOSTICS_PER_PACKET: usize = 1024;
/// Maximum allowed value for IPv6 extension headers traversed per packet (64).
pub const MAX_ALLOWED_IPV6_EXTENSION_HEADERS: u8 = 64;
/// Maximum allowed value for IPv6 extension header bytes processed per packet (64 KiB).
pub const MAX_ALLOWED_IPV6_EXTENSION_BYTES: usize = 64 * 1024;

/// Error returned when configuring invalid normalization limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationLimitError {
    /// Limit value exceeds the maximum safe hard cap.
    ExceedsHardCap {
        /// Name of the limit that failed validation.
        limit: &'static str,
        /// Provided value.
        value: usize,
        /// Maximum allowed value.
        max: usize,
    },
}

impl fmt::Display for NormalizationLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsHardCap { limit, value, max } => {
                write!(
                    f,
                    "normalization limit {} value {} exceeds maximum allowed {}",
                    limit, value, max
                )
            }
        }
    }
}

impl std::error::Error for NormalizationLimitError {}

/// Finite resource limits governing packet normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizationLimits {
    /// Maximum bytes of application payload retained after the transport header (default: 4 KiB).
    pub maximum_retained_payload_bytes: usize,
    /// Maximum number of diagnostics emitted for a single packet (default: 16).
    pub maximum_diagnostics_per_packet: usize,
    /// Maximum number of IPv6 extension headers traversed (default: 8).
    pub maximum_ipv6_extension_headers: u8,
    /// Maximum total bytes of IPv6 extension headers processed (default: 2 KiB).
    pub maximum_ipv6_extension_bytes: usize,
}

impl Default for NormalizationLimits {
    fn default() -> Self {
        Self {
            maximum_retained_payload_bytes: 4096,
            maximum_diagnostics_per_packet: 16,
            maximum_ipv6_extension_headers: 8,
            maximum_ipv6_extension_bytes: 2048,
        }
    }
}

impl NormalizationLimits {
    /// Create a builder initialized with default limits.
    #[must_use]
    pub fn builder() -> NormalizationLimitsBuilder {
        NormalizationLimitsBuilder::default()
    }

    /// Validate the limit values against their respective hard caps.
    pub fn validate(&self) -> Result<(), NormalizationLimitError> {
        if self.maximum_retained_payload_bytes > MAX_ALLOWED_RETAINED_PAYLOAD_BYTES {
            return Err(NormalizationLimitError::ExceedsHardCap {
                limit: "maximum_retained_payload_bytes",
                value: self.maximum_retained_payload_bytes,
                max: MAX_ALLOWED_RETAINED_PAYLOAD_BYTES,
            });
        }
        if self.maximum_diagnostics_per_packet > MAX_ALLOWED_DIAGNOSTICS_PER_PACKET {
            return Err(NormalizationLimitError::ExceedsHardCap {
                limit: "maximum_diagnostics_per_packet",
                value: self.maximum_diagnostics_per_packet,
                max: MAX_ALLOWED_DIAGNOSTICS_PER_PACKET,
            });
        }
        if self.maximum_ipv6_extension_headers > MAX_ALLOWED_IPV6_EXTENSION_HEADERS {
            return Err(NormalizationLimitError::ExceedsHardCap {
                limit: "maximum_ipv6_extension_headers",
                value: usize::from(self.maximum_ipv6_extension_headers),
                max: usize::from(MAX_ALLOWED_IPV6_EXTENSION_HEADERS),
            });
        }
        if self.maximum_ipv6_extension_bytes > MAX_ALLOWED_IPV6_EXTENSION_BYTES {
            return Err(NormalizationLimitError::ExceedsHardCap {
                limit: "maximum_ipv6_extension_bytes",
                value: self.maximum_ipv6_extension_bytes,
                max: MAX_ALLOWED_IPV6_EXTENSION_BYTES,
            });
        }
        Ok(())
    }
}

/// Builder for constructing [`NormalizationLimits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NormalizationLimitsBuilder {
    limits: NormalizationLimits,
}

impl NormalizationLimitsBuilder {
    /// Sets the maximum retained transport application payload bytes.
    #[must_use]
    pub const fn maximum_retained_payload_bytes(mut self, bytes: usize) -> Self {
        self.limits.maximum_retained_payload_bytes = bytes;
        self
    }

    /// Sets the maximum number of diagnostics recorded per packet.
    #[must_use]
    pub const fn maximum_diagnostics_per_packet(mut self, count: usize) -> Self {
        self.limits.maximum_diagnostics_per_packet = count;
        self
    }

    /// Sets the maximum number of IPv6 extension headers traversed per packet.
    #[must_use]
    pub const fn maximum_ipv6_extension_headers(mut self, count: u8) -> Self {
        self.limits.maximum_ipv6_extension_headers = count;
        self
    }

    /// Sets the maximum total bytes of IPv6 extension headers processed per packet.
    #[must_use]
    pub const fn maximum_ipv6_extension_bytes(mut self, bytes: usize) -> Self {
        self.limits.maximum_ipv6_extension_bytes = bytes;
        self
    }

    /// Validates and builds the [`NormalizationLimits`].
    pub fn build(self) -> Result<NormalizationLimits, NormalizationLimitError> {
        self.limits.validate()?;
        Ok(self.limits)
    }
}
