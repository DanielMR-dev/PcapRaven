//! Finite resource limits and configuration for TLS protocol analysis.

use std::error::Error;
use std::fmt;

/// Maximum allowed record fragment size for visible plaintext TLS records (RFC 9846 2^14 bytes).
pub const MAX_TLS_PLAINTEXT_FRAGMENT_BYTES: usize = 16_384;

/// Maximum allowed record fragment size for opaque/ciphertext TLS records (16 KiB + 2 KiB overhead).
pub const MAX_TLS_OPAQUE_RECORD_FRAGMENT_BYTES: usize = 18_432;

/// Hard caps for TLS parser limits.
pub const HARD_MAX_RECORDS_PER_PACKET: usize = 256;
pub const HARD_MAX_HANDSHAKE_MESSAGES_PER_PACKET: usize = 256;
pub const HARD_MAX_HANDSHAKE_MESSAGE_BYTES: usize = 1_048_576;
pub const HARD_MAX_CIPHER_SUITES_PER_CLIENT_HELLO: usize = 4_096;
pub const HARD_MAX_EXTENSIONS_PER_HELLO: usize = 1_024;
pub const HARD_MAX_SUPPORTED_VERSIONS: usize = 127;
pub const HARD_MAX_SUPPORTED_GROUPS: usize = 4_096;
pub const HARD_MAX_SIGNATURE_ALGORITHMS: usize = 4_096;
pub const HARD_MAX_ALPN_PROTOCOLS: usize = 255;
pub const HARD_MAX_TOTAL_ALPN_BYTES: usize = 65_535;
pub const HARD_MAX_SERVER_NAME_BYTES: usize = 4_096;
pub const HARD_MAX_KEY_SHARE_ENTRIES: usize = 1_024;
pub const HARD_MAX_DIAGNOSTICS_PER_PACKET: usize = 256;

/// Default limit values.
pub const DEFAULT_MAX_RECORDS_PER_PACKET: usize = 32;
pub const DEFAULT_MAX_HANDSHAKE_MESSAGES_PER_PACKET: usize = 32;
pub const DEFAULT_MAX_HANDSHAKE_MESSAGE_BYTES: usize = 131_072;
pub const DEFAULT_MAX_CIPHER_SUITES_PER_CLIENT_HELLO: usize = 256;
pub const DEFAULT_MAX_EXTENSIONS_PER_HELLO: usize = 128;
pub const DEFAULT_MAX_SUPPORTED_VERSIONS: usize = 32;
pub const DEFAULT_MAX_SUPPORTED_GROUPS: usize = 256;
pub const DEFAULT_MAX_SIGNATURE_ALGORITHMS: usize = 256;
pub const DEFAULT_MAX_ALPN_PROTOCOLS: usize = 32;
pub const DEFAULT_MAX_TOTAL_ALPN_BYTES: usize = 4_096;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_KEY_SHARE_ENTRIES: usize = 64;
pub const DEFAULT_MAX_DIAGNOSTICS_PER_PACKET: usize = 16;

/// Validated finite resource limits for TLS protocol analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLimits {
    pub maximum_records_per_packet: usize,
    pub maximum_handshake_messages_per_packet: usize,
    pub maximum_handshake_message_bytes: usize,
    pub maximum_cipher_suites_per_client_hello: usize,
    pub maximum_extensions_per_hello: usize,
    pub maximum_supported_versions: usize,
    pub maximum_supported_groups: usize,
    pub maximum_signature_algorithms: usize,
    pub maximum_alpn_protocols: usize,
    pub maximum_total_alpn_bytes: usize,
    pub maximum_server_name_bytes: usize,
    pub maximum_key_share_entries: usize,
    pub maximum_diagnostics_per_packet: usize,
}

impl Default for TlsLimits {
    fn default() -> Self {
        Self {
            maximum_records_per_packet: DEFAULT_MAX_RECORDS_PER_PACKET,
            maximum_handshake_messages_per_packet: DEFAULT_MAX_HANDSHAKE_MESSAGES_PER_PACKET,
            maximum_handshake_message_bytes: DEFAULT_MAX_HANDSHAKE_MESSAGE_BYTES,
            maximum_cipher_suites_per_client_hello: DEFAULT_MAX_CIPHER_SUITES_PER_CLIENT_HELLO,
            maximum_extensions_per_hello: DEFAULT_MAX_EXTENSIONS_PER_HELLO,
            maximum_supported_versions: DEFAULT_MAX_SUPPORTED_VERSIONS,
            maximum_supported_groups: DEFAULT_MAX_SUPPORTED_GROUPS,
            maximum_signature_algorithms: DEFAULT_MAX_SIGNATURE_ALGORITHMS,
            maximum_alpn_protocols: DEFAULT_MAX_ALPN_PROTOCOLS,
            maximum_total_alpn_bytes: DEFAULT_MAX_TOTAL_ALPN_BYTES,
            maximum_server_name_bytes: DEFAULT_MAX_SERVER_NAME_BYTES,
            maximum_key_share_entries: DEFAULT_MAX_KEY_SHARE_ENTRIES,
            maximum_diagnostics_per_packet: DEFAULT_MAX_DIAGNOSTICS_PER_PACKET,
        }
    }
}

/// Error produced when configuring invalid `TlsLimits`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLimitError {
    message: String,
}

impl TlsLimitError {
    #[must_use]
    pub const fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for TlsLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid TLS limit: {}", self.message)
    }
}

impl Error for TlsLimitError {}

/// Builder for constructing validated [`TlsLimits`].
#[derive(Debug, Clone)]
pub struct TlsLimitsBuilder {
    limits: TlsLimits,
}

impl Default for TlsLimitsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsLimitsBuilder {
    /// Creates a new builder initialized with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: TlsLimits::default(),
        }
    }

    /// Sets the maximum TLS records parsed per packet.
    #[must_use]
    pub fn maximum_records_per_packet(mut self, limit: usize) -> Self {
        self.limits.maximum_records_per_packet = limit;
        self
    }

    /// Sets the maximum handshake messages parsed per packet.
    #[must_use]
    pub fn maximum_handshake_messages_per_packet(mut self, limit: usize) -> Self {
        self.limits.maximum_handshake_messages_per_packet = limit;
        self
    }

    /// Sets the maximum bytes allocated for a single assembled handshake message.
    #[must_use]
    pub fn maximum_handshake_message_bytes(mut self, limit: usize) -> Self {
        self.limits.maximum_handshake_message_bytes = limit;
        self
    }

    /// Sets the maximum cipher suites retained per ClientHello.
    #[must_use]
    pub fn maximum_cipher_suites_per_client_hello(mut self, limit: usize) -> Self {
        self.limits.maximum_cipher_suites_per_client_hello = limit;
        self
    }

    /// Sets the maximum extensions parsed per Hello message.
    #[must_use]
    pub fn maximum_extensions_per_hello(mut self, limit: usize) -> Self {
        self.limits.maximum_extensions_per_hello = limit;
        self
    }

    /// Sets the maximum supported versions retained.
    #[must_use]
    pub fn maximum_supported_versions(mut self, limit: usize) -> Self {
        self.limits.maximum_supported_versions = limit;
        self
    }

    /// Sets the maximum supported groups retained.
    #[must_use]
    pub fn maximum_supported_groups(mut self, limit: usize) -> Self {
        self.limits.maximum_supported_groups = limit;
        self
    }

    /// Sets the maximum signature algorithms retained.
    #[must_use]
    pub fn maximum_signature_algorithms(mut self, limit: usize) -> Self {
        self.limits.maximum_signature_algorithms = limit;
        self
    }

    /// Sets the maximum ALPN protocols retained.
    #[must_use]
    pub fn maximum_alpn_protocols(mut self, limit: usize) -> Self {
        self.limits.maximum_alpn_protocols = limit;
        self
    }

    /// Sets the maximum total ALPN bytes retained.
    #[must_use]
    pub fn maximum_total_alpn_bytes(mut self, limit: usize) -> Self {
        self.limits.maximum_total_alpn_bytes = limit;
        self
    }

    /// Sets the maximum server name (SNI) bytes retained.
    #[must_use]
    pub fn maximum_server_name_bytes(mut self, limit: usize) -> Self {
        self.limits.maximum_server_name_bytes = limit;
        self
    }

    /// Sets the maximum key share entries parsed.
    #[must_use]
    pub fn maximum_key_share_entries(mut self, limit: usize) -> Self {
        self.limits.maximum_key_share_entries = limit;
        self
    }

    /// Sets the maximum diagnostics emitted per packet.
    #[must_use]
    pub fn maximum_diagnostics_per_packet(mut self, limit: usize) -> Self {
        self.limits.maximum_diagnostics_per_packet = limit;
        self
    }

    /// Validates and constructs the [`TlsLimits`].
    ///
    /// # Errors
    /// Returns [`TlsLimitError`] if any limit is zero or exceeds its hard cap.
    pub fn build(self) -> Result<TlsLimits, TlsLimitError> {
        let l = &self.limits;
        if l.maximum_records_per_packet == 0
            || l.maximum_records_per_packet > HARD_MAX_RECORDS_PER_PACKET
        {
            return Err(TlsLimitError::new(format!(
                "maximum_records_per_packet must be 1..={HARD_MAX_RECORDS_PER_PACKET} (got {})",
                l.maximum_records_per_packet
            )));
        }
        if l.maximum_handshake_messages_per_packet == 0
            || l.maximum_handshake_messages_per_packet > HARD_MAX_HANDSHAKE_MESSAGES_PER_PACKET
        {
            return Err(TlsLimitError::new(format!(
                "maximum_handshake_messages_per_packet must be 1..={HARD_MAX_HANDSHAKE_MESSAGES_PER_PACKET} (got {})",
                l.maximum_handshake_messages_per_packet
            )));
        }
        if l.maximum_handshake_message_bytes == 0
            || l.maximum_handshake_message_bytes > HARD_MAX_HANDSHAKE_MESSAGE_BYTES
        {
            return Err(TlsLimitError::new(format!(
                "maximum_handshake_message_bytes must be 1..={HARD_MAX_HANDSHAKE_MESSAGE_BYTES} (got {})",
                l.maximum_handshake_message_bytes
            )));
        }
        if l.maximum_cipher_suites_per_client_hello == 0
            || l.maximum_cipher_suites_per_client_hello > HARD_MAX_CIPHER_SUITES_PER_CLIENT_HELLO
        {
            return Err(TlsLimitError::new(format!(
                "maximum_cipher_suites_per_client_hello must be 1..={HARD_MAX_CIPHER_SUITES_PER_CLIENT_HELLO} (got {})",
                l.maximum_cipher_suites_per_client_hello
            )));
        }
        if l.maximum_extensions_per_hello == 0
            || l.maximum_extensions_per_hello > HARD_MAX_EXTENSIONS_PER_HELLO
        {
            return Err(TlsLimitError::new(format!(
                "maximum_extensions_per_hello must be 1..={HARD_MAX_EXTENSIONS_PER_HELLO} (got {})",
                l.maximum_extensions_per_hello
            )));
        }
        if l.maximum_supported_versions == 0
            || l.maximum_supported_versions > HARD_MAX_SUPPORTED_VERSIONS
        {
            return Err(TlsLimitError::new(format!(
                "maximum_supported_versions must be 1..={HARD_MAX_SUPPORTED_VERSIONS} (got {})",
                l.maximum_supported_versions
            )));
        }
        if l.maximum_supported_groups == 0 || l.maximum_supported_groups > HARD_MAX_SUPPORTED_GROUPS
        {
            return Err(TlsLimitError::new(format!(
                "maximum_supported_groups must be 1..={HARD_MAX_SUPPORTED_GROUPS} (got {})",
                l.maximum_supported_groups
            )));
        }
        if l.maximum_signature_algorithms == 0
            || l.maximum_signature_algorithms > HARD_MAX_SIGNATURE_ALGORITHMS
        {
            return Err(TlsLimitError::new(format!(
                "maximum_signature_algorithms must be 1..={HARD_MAX_SIGNATURE_ALGORITHMS} (got {})",
                l.maximum_signature_algorithms
            )));
        }
        if l.maximum_alpn_protocols == 0 || l.maximum_alpn_protocols > HARD_MAX_ALPN_PROTOCOLS {
            return Err(TlsLimitError::new(format!(
                "maximum_alpn_protocols must be 1..={HARD_MAX_ALPN_PROTOCOLS} (got {})",
                l.maximum_alpn_protocols
            )));
        }
        if l.maximum_total_alpn_bytes == 0 || l.maximum_total_alpn_bytes > HARD_MAX_TOTAL_ALPN_BYTES
        {
            return Err(TlsLimitError::new(format!(
                "maximum_total_alpn_bytes must be 1..={HARD_MAX_TOTAL_ALPN_BYTES} (got {})",
                l.maximum_total_alpn_bytes
            )));
        }
        if l.maximum_server_name_bytes == 0
            || l.maximum_server_name_bytes > HARD_MAX_SERVER_NAME_BYTES
        {
            return Err(TlsLimitError::new(format!(
                "maximum_server_name_bytes must be 1..={HARD_MAX_SERVER_NAME_BYTES} (got {})",
                l.maximum_server_name_bytes
            )));
        }
        if l.maximum_key_share_entries == 0
            || l.maximum_key_share_entries > HARD_MAX_KEY_SHARE_ENTRIES
        {
            return Err(TlsLimitError::new(format!(
                "maximum_key_share_entries must be 1..={HARD_MAX_KEY_SHARE_ENTRIES} (got {})",
                l.maximum_key_share_entries
            )));
        }
        if l.maximum_diagnostics_per_packet == 0
            || l.maximum_diagnostics_per_packet > HARD_MAX_DIAGNOSTICS_PER_PACKET
        {
            return Err(TlsLimitError::new(format!(
                "maximum_diagnostics_per_packet must be 1..={HARD_MAX_DIAGNOSTICS_PER_PACKET} (got {})",
                l.maximum_diagnostics_per_packet
            )));
        }

        Ok(self.limits)
    }
}
