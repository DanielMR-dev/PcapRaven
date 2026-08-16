//! Normalized domain models and types for TLS handshake metadata analysis.
//!
//! Provides capture-independent representations of visible TLS 1.2 and TLS 1.3
//! handshake messages (`ClientHello`, `ServerHello`, `HelloRetryRequest`) extracted
//! passively from packet payloads without decryption or secret retention.

use crate::packet::{IpAddress, PacketReference, PacketTimestamp};
use std::fmt;

/// TLS version representation preserving standard wire codes and unrecognized variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// SSL 3.0 (0x0300) - Unsupported historical version.
    Ssl30,
    /// TLS 1.0 (0x0301) - Unsupported deprecated version (RFC 8996).
    Tls10,
    /// TLS 1.1 (0x0302) - Unsupported deprecated version (RFC 8996).
    Tls11,
    /// TLS 1.2 (0x0303) - Supported wire protocol (RFC 5246 historical reference / RFC 9846).
    Tls12,
    /// TLS 1.3 (0x0304) - Supported current standard (RFC 9846).
    Tls13,
    /// Unknown or custom version code.
    Unknown(u16),
}

impl TlsVersion {
    /// Parses a 16-bit wire version code into a `TlsVersion`.
    #[must_use]
    pub const fn from_wire(code: u16) -> Self {
        match code {
            0x0300 => Self::Ssl30,
            0x0301 => Self::Tls10,
            0x0302 => Self::Tls11,
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            other => Self::Unknown(other),
        }
    }

    /// Converts the `TlsVersion` into its 16-bit wire representation.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::Ssl30 => 0x0300,
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
            Self::Unknown(code) => code,
        }
    }

    /// Returns a static string representation of the TLS version.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssl30 => "SSLv3",
            Self::Tls10 => "TLS 1.0",
            Self::Tls11 => "TLS 1.1",
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(code) => write!(f, "Unknown(0x{code:04x})"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// TLS record layer content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsRecordContentType {
    /// ChangeCipherSpec (20)
    ChangeCipherSpec,
    /// Alert (21)
    Alert,
    /// Handshake (22)
    Handshake,
    /// ApplicationData (23)
    ApplicationData,
    /// Other / unrecognized content type.
    Other(u8),
}

impl TlsRecordContentType {
    /// Parses an 8-bit wire content type into `TlsRecordContentType`.
    #[must_use]
    pub const fn from_wire(code: u8) -> Self {
        match code {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            other => Self::Other(other),
        }
    }

    /// Converts the content type into its 8-bit wire representation.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
            Self::Other(code) => code,
        }
    }

    /// Returns a static string representation of the content type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChangeCipherSpec => "ChangeCipherSpec",
            Self::Alert => "Alert",
            Self::Handshake => "Handshake",
            Self::ApplicationData => "ApplicationData",
            Self::Other(_) => "Other",
        }
    }
}

impl fmt::Display for TlsRecordContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(code) => write!(f, "Other({code})"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Handshake message kind classified from visible plaintext messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsHandshakeKind {
    /// ClientHello (type 1).
    ClientHello,
    /// ServerHello (type 2).
    ServerHello,
    /// HelloRetryRequest (ServerHello with fixed RFC 9846 SHA-256 sentinel random).
    HelloRetryRequest,
    /// Other handshake type code.
    Other(u8),
}

impl TlsHandshakeKind {
    /// Returns a static string representation of the handshake kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientHello => "ClientHello",
            Self::ServerHello => "ServerHello",
            Self::HelloRetryRequest => "HelloRetryRequest",
            Self::Other(_) => "Other",
        }
    }
}

impl fmt::Display for TlsHandshakeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(code) => write!(f, "Other({code})"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Raw byte string representation preserving wire bytes without assuming UTF-8.
///
/// Bounded construction and size limits are enforced by upstream protocol parsers
/// and configuration budgets before domain instantiation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsByteString {
    bytes: Vec<u8>,
}

impl TlsByteString {
    /// Creates a new `TlsByteString` from raw bytes.
    ///
    /// Upstream callers must ensure byte buffers conform to applicable protocol limits.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the slice of raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the number of bytes in this byte string.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the byte string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns a terminal-safe escaped string representation.
    ///
    /// Printable ASCII characters (0x20..=0x7E, except `\`) are preserved literally.
    /// The backslash `\` is escaped as `\\`. All other bytes are formatted as `\xHH`.
    #[must_use]
    pub fn display_escaped(&self) -> String {
        let mut out = String::with_capacity(self.bytes.len());
        for &b in &self.bytes {
            match b {
                b'\\' => out.push_str("\\\\"),
                0x20..=0x7E => out.push(b as char),
                _ => {
                    use std::fmt::Write;
                    let _ = write!(out, "\\x{b:02x}");
                }
            }
        }
        out
    }
}

impl fmt::Display for TlsByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_escaped())
    }
}

/// Factual summary of an observed TLS extension header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsExtensionMetadata {
    /// 16-bit extension type code.
    pub extension_type: u16,
    /// Declared 16-bit extension payload length.
    pub declared_length: u16,
}

/// Factual metadata extracted from a visible `ClientHello` handshake message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloMetadata {
    /// Legacy client version field (e.g. 0x0303 for TLS 1.2+).
    pub legacy_version: TlsVersion,
    /// Declared legacy session ID length in bytes (session ID bytes are NOT retained).
    pub session_id_length: u8,
    /// Bounded list of offered cipher suite numeric identifiers in wire order.
    pub cipher_suites: Vec<u16>,
    /// Bounded list of offered compression method identifiers.
    pub compression_methods: Vec<u8>,
    /// Server Name Indication (SNI) host name value, if present.
    pub server_name: Option<TlsByteString>,
    /// Bounded list of offered protocol versions from the `supported_versions` extension (43).
    pub supported_versions: Vec<TlsVersion>,
    /// Bounded list of supported elliptic curve / Diffie-Hellman group IDs (extension 10).
    pub supported_groups: Vec<u16>,
    /// Bounded list of supported signature algorithm scheme IDs (extension 13).
    pub signature_algorithms: Vec<u16>,
    /// Bounded list of offered Application-Layer Protocol Negotiation (ALPN) identifiers (extension 16).
    pub alpn_protocols: Vec<TlsByteString>,
    /// Bounded list of KeyShare group IDs offered by the client (extension 51; key bytes NOT retained).
    pub key_share_groups: Vec<u16>,
    /// `true` if the `pre_shared_key` extension (41) was present (identities/binders NOT retained).
    pub has_pre_shared_key: bool,
    /// `true` if the `early_data` extension (42) was present.
    pub has_early_data: bool,
    /// Bounded list of all extension type/length headers observed in the ClientHello.
    pub extensions: Vec<TlsExtensionMetadata>,
}

/// Factual metadata extracted from a visible `ServerHello` or `HelloRetryRequest` handshake message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerHelloMetadata {
    /// Legacy server version field.
    pub legacy_version: TlsVersion,
    /// Declared legacy session ID echo length in bytes (bytes NOT retained).
    pub session_id_echo_length: u8,
    /// Selected 16-bit cipher suite identifier.
    pub cipher_suite: u16,
    /// Selected legacy compression method identifier.
    pub compression_method: u8,
    /// Selected TLS version (from `supported_versions` extension 43 in TLS 1.3, or `legacy_version` in TLS 1.2).
    pub selected_version: Option<TlsVersion>,
    /// Selected key-share group ID (from `key_share` extension 51; key bytes NOT retained).
    pub selected_group: Option<u16>,
    /// Selected ALPN protocol identifier (only visible in plaintext in TLS 1.2; never fabricated for TLS 1.3).
    pub selected_alpn: Option<TlsByteString>,
    /// `true` if the `pre_shared_key` extension (41) was present.
    pub has_pre_shared_key: bool,
    /// `true` if the `early_data` extension (42) was present.
    pub has_early_data: bool,
    /// Bounded list of all extension type/length headers observed in the ServerHello.
    pub extensions: Vec<TlsExtensionMetadata>,
}

/// Completeness state of an extracted TLS observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsObservationCompleteness {
    /// The visible handshake message and its extensions were completely parsed within limits.
    Complete,
    /// Processing was truncated due to capture limits, bounds exhaustion, or protocol errors.
    Partial,
}

impl TlsObservationCompleteness {
    /// Returns `true` if the observation is complete.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Factual normalized TLS observation produced from a single packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsObservation {
    /// Provenance reference to the enclosing capture record.
    pub packet: PacketReference,
    /// Packet timestamp.
    pub timestamp: PacketTimestamp,
    /// Source IP address.
    pub source_ip: IpAddress,
    /// Source transport port.
    pub source_port: u16,
    /// Destination IP address.
    pub destination_ip: IpAddress,
    /// Destination transport port.
    pub destination_port: u16,
    /// Outer TLS record layer version.
    pub record_version: TlsVersion,
    /// Handshake message classification.
    pub handshake_kind: TlsHandshakeKind,
    /// ClientHello metadata, if this observation represents a ClientHello.
    pub client_hello: Option<TlsClientHelloMetadata>,
    /// ServerHello / HelloRetryRequest metadata, if this observation represents a ServerHello.
    pub server_hello: Option<TlsServerHelloMetadata>,
    /// Declared outer record length in bytes.
    pub declared_record_bytes: u16,
    /// Declared 24-bit handshake message length in bytes.
    pub declared_handshake_bytes: u32,
    /// Completeness assessment.
    pub completeness: TlsObservationCompleteness,
}

/// Structural category of a TLS parser diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsDiagnosticKind {
    /// Malformed wire format or violated TLS framing/grammar.
    Malformed,
    /// Unsupported TLS version, extension, or protocol feature.
    Unsupported,
    /// Exceeded a configured finite parser resource bound.
    ResourceLimit,
    /// Handshake data truncated by packet capture boundary.
    Truncated,
}

impl TlsDiagnosticKind {
    /// Returns a static string label for the diagnostic kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::Unsupported => "Unsupported",
            Self::ResourceLimit => "ResourceLimit",
            Self::Truncated => "Truncated",
        }
    }
}

impl fmt::Display for TlsDiagnosticKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bounded factual diagnostic emitted during TLS protocol parsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsDiagnostic {
    /// Diagnostic classification kind.
    pub kind: TlsDiagnosticKind,
    /// Bounded diagnostic explanation.
    pub message: String,
}

impl TlsDiagnostic {
    /// Creates a new `TlsDiagnostic`.
    #[must_use]
    pub const fn new(kind: TlsDiagnosticKind, message: String) -> Self {
        Self { kind, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_conversions() {
        assert_eq!(TlsVersion::from_wire(0x0303), TlsVersion::Tls12);
        assert_eq!(TlsVersion::from_wire(0x0304), TlsVersion::Tls13);
        assert_eq!(TlsVersion::from_wire(0x0301), TlsVersion::Tls10);
        assert_eq!(TlsVersion::from_wire(0x0302), TlsVersion::Tls11);
        assert_eq!(TlsVersion::from_wire(0x0300), TlsVersion::Ssl30);
        assert_eq!(TlsVersion::from_wire(0x0999), TlsVersion::Unknown(0x0999));
        assert_eq!(TlsVersion::Tls12.to_wire(), 0x0303);
        assert_eq!(TlsVersion::Tls13.to_wire(), 0x0304);
        assert_eq!(TlsVersion::Unknown(0x1234).to_wire(), 0x1234);
    }

    #[test]
    fn test_tls_record_content_type() {
        assert_eq!(
            TlsRecordContentType::from_wire(22),
            TlsRecordContentType::Handshake
        );
        assert_eq!(
            TlsRecordContentType::from_wire(23),
            TlsRecordContentType::ApplicationData
        );
        assert_eq!(
            TlsRecordContentType::from_wire(20),
            TlsRecordContentType::ChangeCipherSpec
        );
        assert_eq!(
            TlsRecordContentType::from_wire(21),
            TlsRecordContentType::Alert
        );
        assert_eq!(
            TlsRecordContentType::from_wire(99),
            TlsRecordContentType::Other(99)
        );
        assert_eq!(TlsRecordContentType::Handshake.to_wire(), 22);
    }

    #[test]
    fn test_byte_string_terminal_escaping() {
        let bs = TlsByteString::new(b"example.com".to_vec());
        assert_eq!(bs.display_escaped(), "example.com");

        let bs_control = TlsByteString::new(b"evil\x00host\x1b[31m\\".to_vec());
        assert_eq!(bs_control.display_escaped(), "evil\\x00host\\x1b[31m\\\\");
    }
}
