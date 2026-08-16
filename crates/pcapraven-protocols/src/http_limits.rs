//! Validated finite resource limits for HTTP/1.x wire-format and header parsing.

use core::fmt;

/// Hard upper bound on maximum start-line length in bytes.
pub const MAX_ALLOWED_HTTP_START_LINE_BYTES: usize = 32_768; // 32 KiB

/// Hard upper bound on maximum individual header line length in bytes.
pub const MAX_ALLOWED_HTTP_HEADER_LINE_BYTES: usize = 32_768; // 32 KiB

/// Hard upper bound on maximum aggregate header section length in bytes (including trailing CRLF CRLF).
pub const MAX_ALLOWED_HTTP_HEADER_SECTION_BYTES: usize = 65_535; // 64 KiB - 1

/// Hard upper bound on maximum header fields parsed per message.
pub const MAX_ALLOWED_HTTP_HEADER_FIELDS: usize = 1_024;

/// Hard upper bound on maximum method length in bytes.
pub const MAX_ALLOWED_HTTP_METHOD_BYTES: usize = 256;

/// Hard upper bound on maximum request-target length in bytes.
pub const MAX_ALLOWED_HTTP_REQUEST_TARGET_BYTES: usize = 32_768; // 32 KiB

/// Hard upper bound on maximum selected field value length in bytes.
pub const MAX_ALLOWED_HTTP_SELECTED_FIELD_VALUE_BYTES: usize = 32_768; // 32 KiB

/// Hard upper bound on diagnostics retained per packet.
pub const MAX_ALLOWED_HTTP_DIAGNOSTICS_PER_PACKET: usize = 256;

/// Error returned when HTTP parser limit configuration violates safety invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpLimitError {
    /// A configured value is zero where a positive value is required.
    ZeroValue {
        /// Name of the limit field.
        field: &'static str,
    },
    /// A configured value exceeds the compile-time hard upper bound.
    ExceedsHardCap {
        /// Name of the limit field.
        field: &'static str,
        /// Configured value.
        value: usize,
        /// Maximum allowed limit.
        limit: usize,
    },
}

impl fmt::Display for HttpLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroValue { field } => {
                write!(f, "HTTP limit {field} must be greater than zero")
            }
            Self::ExceedsHardCap {
                field,
                value,
                limit,
            } => {
                write!(
                    f,
                    "HTTP limit {field} ({value}) exceeds maximum allowed cap of {limit}"
                )
            }
        }
    }
}

/// Validated finite configuration governing bounded HTTP/1.x header parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpLimits {
    /// Maximum bytes allowed for the request/status start-line.
    pub maximum_start_line_bytes: usize,
    /// Maximum bytes allowed for any single header field line.
    pub maximum_header_line_bytes: usize,
    /// Maximum bytes allowed for the complete header section.
    pub maximum_header_section_bytes: usize,
    /// Maximum number of header fields parsed per message.
    pub maximum_header_fields: usize,
    /// Maximum bytes allowed for the HTTP request method token.
    pub maximum_method_bytes: usize,
    /// Maximum bytes allowed for the HTTP request-target.
    pub maximum_request_target_bytes: usize,
    /// Maximum bytes allowed for any individual retained selected header value.
    pub maximum_selected_field_value_bytes: usize,
    /// Maximum diagnostics collected per packet.
    pub maximum_diagnostics_per_packet: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            maximum_start_line_bytes: 8_192,
            maximum_header_line_bytes: 8_192,
            maximum_header_section_bytes: 32_768,
            maximum_header_fields: 100,
            maximum_method_bytes: 32,
            maximum_request_target_bytes: 8_192,
            maximum_selected_field_value_bytes: 4_096,
            maximum_diagnostics_per_packet: 16,
        }
    }
}

impl HttpLimits {
    /// Creates a new builder for configuring HTTP parser limits.
    #[must_use]
    pub const fn builder() -> HttpLimitsBuilder {
        HttpLimitsBuilder::new()
    }
}

/// Builder for constructing validated [`HttpLimits`] instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimitsBuilder {
    limits: HttpLimits,
}

impl Default for HttpLimitsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpLimitsBuilder {
    /// Creates a new builder initialized with default conservative limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: HttpLimits {
                maximum_start_line_bytes: 8_192,
                maximum_header_line_bytes: 8_192,
                maximum_header_section_bytes: 32_768,
                maximum_header_fields: 100,
                maximum_method_bytes: 32,
                maximum_request_target_bytes: 8_192,
                maximum_selected_field_value_bytes: 4_096,
                maximum_diagnostics_per_packet: 16,
            },
        }
    }

    /// Sets the maximum start-line bytes limit.
    #[must_use]
    pub const fn maximum_start_line_bytes(mut self, value: usize) -> Self {
        self.limits.maximum_start_line_bytes = value;
        self
    }

    /// Sets the maximum header line bytes limit.
    #[must_use]
    pub const fn maximum_header_line_bytes(mut self, value: usize) -> Self {
        self.limits.maximum_header_line_bytes = value;
        self
    }

    /// Sets the maximum header section bytes limit.
    #[must_use]
    pub const fn maximum_header_section_bytes(mut self, value: usize) -> Self {
        self.limits.maximum_header_section_bytes = value;
        self
    }

    /// Sets the maximum header fields limit.
    #[must_use]
    pub const fn maximum_header_fields(mut self, value: usize) -> Self {
        self.limits.maximum_header_fields = value;
        self
    }

    /// Sets the maximum method bytes limit.
    #[must_use]
    pub const fn maximum_method_bytes(mut self, value: usize) -> Self {
        self.limits.maximum_method_bytes = value;
        self
    }

    /// Sets the maximum request-target bytes limit.
    #[must_use]
    pub const fn maximum_request_target_bytes(mut self, value: usize) -> Self {
        self.limits.maximum_request_target_bytes = value;
        self
    }

    /// Sets the maximum selected field value bytes limit.
    #[must_use]
    pub const fn maximum_selected_field_value_bytes(mut self, value: usize) -> Self {
        self.limits.maximum_selected_field_value_bytes = value;
        self
    }

    /// Sets the maximum diagnostics per packet limit.
    #[must_use]
    pub const fn maximum_diagnostics_per_packet(mut self, value: usize) -> Self {
        self.limits.maximum_diagnostics_per_packet = value;
        self
    }

    /// Validates all configured limits against their safety invariants and hard caps.
    ///
    /// # Errors
    /// Returns [`HttpLimitError`] if any limit is zero or exceeds its hard cap.
    pub const fn build(self) -> Result<HttpLimits, HttpLimitError> {
        if self.limits.maximum_start_line_bytes == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_start_line_bytes",
            });
        }
        if self.limits.maximum_start_line_bytes > MAX_ALLOWED_HTTP_START_LINE_BYTES {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_start_line_bytes",
                value: self.limits.maximum_start_line_bytes,
                limit: MAX_ALLOWED_HTTP_START_LINE_BYTES,
            });
        }

        if self.limits.maximum_header_line_bytes == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_header_line_bytes",
            });
        }
        if self.limits.maximum_header_line_bytes > MAX_ALLOWED_HTTP_HEADER_LINE_BYTES {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_header_line_bytes",
                value: self.limits.maximum_header_line_bytes,
                limit: MAX_ALLOWED_HTTP_HEADER_LINE_BYTES,
            });
        }

        if self.limits.maximum_header_section_bytes == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_header_section_bytes",
            });
        }
        if self.limits.maximum_header_section_bytes > MAX_ALLOWED_HTTP_HEADER_SECTION_BYTES {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_header_section_bytes",
                value: self.limits.maximum_header_section_bytes,
                limit: MAX_ALLOWED_HTTP_HEADER_SECTION_BYTES,
            });
        }

        if self.limits.maximum_header_fields == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_header_fields",
            });
        }
        if self.limits.maximum_header_fields > MAX_ALLOWED_HTTP_HEADER_FIELDS {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_header_fields",
                value: self.limits.maximum_header_fields,
                limit: MAX_ALLOWED_HTTP_HEADER_FIELDS,
            });
        }

        if self.limits.maximum_method_bytes == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_method_bytes",
            });
        }
        if self.limits.maximum_method_bytes > MAX_ALLOWED_HTTP_METHOD_BYTES {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_method_bytes",
                value: self.limits.maximum_method_bytes,
                limit: MAX_ALLOWED_HTTP_METHOD_BYTES,
            });
        }

        if self.limits.maximum_request_target_bytes == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_request_target_bytes",
            });
        }
        if self.limits.maximum_request_target_bytes > MAX_ALLOWED_HTTP_REQUEST_TARGET_BYTES {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_request_target_bytes",
                value: self.limits.maximum_request_target_bytes,
                limit: MAX_ALLOWED_HTTP_REQUEST_TARGET_BYTES,
            });
        }

        if self.limits.maximum_selected_field_value_bytes == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_selected_field_value_bytes",
            });
        }
        if self.limits.maximum_selected_field_value_bytes
            > MAX_ALLOWED_HTTP_SELECTED_FIELD_VALUE_BYTES
        {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_selected_field_value_bytes",
                value: self.limits.maximum_selected_field_value_bytes,
                limit: MAX_ALLOWED_HTTP_SELECTED_FIELD_VALUE_BYTES,
            });
        }

        if self.limits.maximum_diagnostics_per_packet == 0 {
            return Err(HttpLimitError::ZeroValue {
                field: "maximum_diagnostics_per_packet",
            });
        }
        if self.limits.maximum_diagnostics_per_packet > MAX_ALLOWED_HTTP_DIAGNOSTICS_PER_PACKET {
            return Err(HttpLimitError::ExceedsHardCap {
                field: "maximum_diagnostics_per_packet",
                value: self.limits.maximum_diagnostics_per_packet,
                limit: MAX_ALLOWED_HTTP_DIAGNOSTICS_PER_PACKET,
            });
        }

        Ok(self.limits)
    }
}
