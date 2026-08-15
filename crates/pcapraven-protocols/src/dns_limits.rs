//! Validated finite resource limits for DNS wire-format parsing.

use core::fmt;

/// Hard upper bound on maximum messages parsed per packet (TCP framing).
pub const MAX_ALLOWED_DNS_MESSAGES_PER_PACKET: usize = 64;

/// Hard upper bound on maximum question records parsed per DNS message.
pub const MAX_ALLOWED_DNS_QUESTIONS_PER_MESSAGE: usize = 4096;

/// Hard upper bound on maximum resource records parsed per DNS message.
pub const MAX_ALLOWED_DNS_RESOURCE_RECORDS_PER_MESSAGE: usize = 4096;

/// Hard upper bound on compression pointer hops per name decompression.
pub const MAX_ALLOWED_DNS_NAME_POINTER_HOPS: usize = 128;

/// Hard upper bound on EDNS(0) option TLVs parsed per message.
pub const MAX_ALLOWED_DNS_EDNS_OPTIONS_PER_MESSAGE: usize = 256;

/// Hard upper bound on diagnostics retained per packet.
pub const MAX_ALLOWED_DNS_DIAGNOSTICS_PER_PACKET: usize = 256;

/// Hard upper bound on aggregate retained domain name bytes per message.
pub const MAX_ALLOWED_DNS_TOTAL_NAME_BYTES_PER_MESSAGE: usize = 1_048_576; // 1 MiB

/// Error returned when DNS parser limit configuration violates safety invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsLimitError {
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

impl fmt::Display for DnsLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroValue { field } => {
                write!(f, "DNS limit {field} must be greater than zero")
            }
            Self::ExceedsHardCap {
                field,
                value,
                limit,
            } => {
                write!(
                    f,
                    "DNS limit {field} ({value}) exceeds maximum allowed cap of {limit}"
                )
            }
        }
    }
}

/// Validated finite configuration governing bounded DNS wire-format parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsLimits {
    /// Maximum number of framed DNS messages processed per packet.
    pub maximum_messages_per_packet: usize,
    /// Maximum questions parsed per DNS message.
    pub maximum_questions_per_message: usize,
    /// Maximum resource records parsed per DNS message.
    pub maximum_resource_records_per_message: usize,
    /// Maximum compression pointer hops followed per domain name.
    pub maximum_name_pointer_hops: usize,
    /// Maximum EDNS option TLVs decoded per message.
    pub maximum_edns_options_per_message: usize,
    /// Maximum diagnostics collected per packet.
    pub maximum_diagnostics_per_packet: usize,
    /// Maximum aggregate name wire bytes retained per message.
    pub maximum_total_retained_name_bytes_per_message: usize,
}

impl Default for DnsLimits {
    fn default() -> Self {
        Self {
            maximum_messages_per_packet: 8,
            maximum_questions_per_message: 64,
            maximum_resource_records_per_message: 256,
            maximum_name_pointer_hops: 32,
            maximum_edns_options_per_message: 32,
            maximum_diagnostics_per_packet: 16,
            maximum_total_retained_name_bytes_per_message: 65_536, // 64 KiB
        }
    }
}

impl DnsLimits {
    /// Creates a new builder for configuring DNS parser limits.
    #[must_use]
    pub const fn builder() -> DnsLimitsBuilder {
        DnsLimitsBuilder::new()
    }
}

/// Builder for constructing validated [`DnsLimits`] instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsLimitsBuilder {
    limits: DnsLimits,
}

impl Default for DnsLimitsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsLimitsBuilder {
    /// Creates a new builder initialized with default conservative limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: DnsLimits {
                maximum_messages_per_packet: 8,
                maximum_questions_per_message: 64,
                maximum_resource_records_per_message: 256,
                maximum_name_pointer_hops: 32,
                maximum_edns_options_per_message: 32,
                maximum_diagnostics_per_packet: 16,
                maximum_total_retained_name_bytes_per_message: 65_536,
            },
        }
    }

    /// Sets the maximum messages per packet limit.
    #[must_use]
    pub const fn maximum_messages_per_packet(mut self, value: usize) -> Self {
        self.limits.maximum_messages_per_packet = value;
        self
    }

    /// Sets the maximum questions per message limit.
    #[must_use]
    pub const fn maximum_questions_per_message(mut self, value: usize) -> Self {
        self.limits.maximum_questions_per_message = value;
        self
    }

    /// Sets the maximum resource records per message limit.
    #[must_use]
    pub const fn maximum_resource_records_per_message(mut self, value: usize) -> Self {
        self.limits.maximum_resource_records_per_message = value;
        self
    }

    /// Sets the maximum name pointer hops limit.
    #[must_use]
    pub const fn maximum_name_pointer_hops(mut self, value: usize) -> Self {
        self.limits.maximum_name_pointer_hops = value;
        self
    }

    /// Sets the maximum EDNS options per message limit.
    #[must_use]
    pub const fn maximum_edns_options_per_message(mut self, value: usize) -> Self {
        self.limits.maximum_edns_options_per_message = value;
        self
    }

    /// Sets the maximum diagnostics per packet limit.
    #[must_use]
    pub const fn maximum_diagnostics_per_packet(mut self, value: usize) -> Self {
        self.limits.maximum_diagnostics_per_packet = value;
        self
    }

    /// Sets the maximum total retained name bytes per message limit.
    #[must_use]
    pub const fn maximum_total_retained_name_bytes_per_message(mut self, value: usize) -> Self {
        self.limits.maximum_total_retained_name_bytes_per_message = value;
        self
    }

    /// Validates all configured limits against their safety invariants and hard caps.
    ///
    /// # Errors
    /// Returns [`DnsLimitError`] if any limit is zero or exceeds its hard cap.
    pub const fn build(self) -> Result<DnsLimits, DnsLimitError> {
        if self.limits.maximum_messages_per_packet == 0 {
            return Err(DnsLimitError::ZeroValue {
                field: "maximum_messages_per_packet",
            });
        }
        if self.limits.maximum_messages_per_packet > MAX_ALLOWED_DNS_MESSAGES_PER_PACKET {
            return Err(DnsLimitError::ExceedsHardCap {
                field: "maximum_messages_per_packet",
                value: self.limits.maximum_messages_per_packet,
                limit: MAX_ALLOWED_DNS_MESSAGES_PER_PACKET,
            });
        }

        if self.limits.maximum_questions_per_message == 0 {
            return Err(DnsLimitError::ZeroValue {
                field: "maximum_questions_per_message",
            });
        }
        if self.limits.maximum_questions_per_message > MAX_ALLOWED_DNS_QUESTIONS_PER_MESSAGE {
            return Err(DnsLimitError::ExceedsHardCap {
                field: "maximum_questions_per_message",
                value: self.limits.maximum_questions_per_message,
                limit: MAX_ALLOWED_DNS_QUESTIONS_PER_MESSAGE,
            });
        }

        if self.limits.maximum_resource_records_per_message == 0 {
            return Err(DnsLimitError::ZeroValue {
                field: "maximum_resource_records_per_message",
            });
        }
        if self.limits.maximum_resource_records_per_message
            > MAX_ALLOWED_DNS_RESOURCE_RECORDS_PER_MESSAGE
        {
            return Err(DnsLimitError::ExceedsHardCap {
                field: "maximum_resource_records_per_message",
                value: self.limits.maximum_resource_records_per_message,
                limit: MAX_ALLOWED_DNS_RESOURCE_RECORDS_PER_MESSAGE,
            });
        }

        if self.limits.maximum_name_pointer_hops == 0 {
            return Err(DnsLimitError::ZeroValue {
                field: "maximum_name_pointer_hops",
            });
        }
        if self.limits.maximum_name_pointer_hops > MAX_ALLOWED_DNS_NAME_POINTER_HOPS {
            return Err(DnsLimitError::ExceedsHardCap {
                field: "maximum_name_pointer_hops",
                value: self.limits.maximum_name_pointer_hops,
                limit: MAX_ALLOWED_DNS_NAME_POINTER_HOPS,
            });
        }

        if self.limits.maximum_edns_options_per_message == 0 {
            return Err(DnsLimitError::ZeroValue {
                field: "maximum_edns_options_per_message",
            });
        }
        if self.limits.maximum_edns_options_per_message > MAX_ALLOWED_DNS_EDNS_OPTIONS_PER_MESSAGE {
            return Err(DnsLimitError::ExceedsHardCap {
                field: "maximum_edns_options_per_message",
                value: self.limits.maximum_edns_options_per_message,
                limit: MAX_ALLOWED_DNS_EDNS_OPTIONS_PER_MESSAGE,
            });
        }

        if self.limits.maximum_diagnostics_per_packet == 0 {
            return Err(DnsLimitError::ZeroValue {
                field: "maximum_diagnostics_per_packet",
            });
        }
        if self.limits.maximum_diagnostics_per_packet > MAX_ALLOWED_DNS_DIAGNOSTICS_PER_PACKET {
            return Err(DnsLimitError::ExceedsHardCap {
                field: "maximum_diagnostics_per_packet",
                value: self.limits.maximum_diagnostics_per_packet,
                limit: MAX_ALLOWED_DNS_DIAGNOSTICS_PER_PACKET,
            });
        }

        if self.limits.maximum_total_retained_name_bytes_per_message == 0 {
            return Err(DnsLimitError::ZeroValue {
                field: "maximum_total_retained_name_bytes_per_message",
            });
        }
        if self.limits.maximum_total_retained_name_bytes_per_message
            > MAX_ALLOWED_DNS_TOTAL_NAME_BYTES_PER_MESSAGE
        {
            return Err(DnsLimitError::ExceedsHardCap {
                field: "maximum_total_retained_name_bytes_per_message",
                value: self.limits.maximum_total_retained_name_bytes_per_message,
                limit: MAX_ALLOWED_DNS_TOTAL_NAME_BYTES_PER_MESSAGE,
            });
        }

        Ok(self.limits)
    }
}
