//! Serializable DTOs for normalized TLS handshake observation reports.

use pcapraven_domain::{
    TlsClientHelloMetadata, TlsExtensionMetadata, TlsHandshakeKind, TlsObservation,
    TlsServerHelloMetadata,
};
use serde::Serialize;

use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for a TLS report in JSON.
#[derive(Debug, Clone, Serialize)]
pub struct TlsReportDto {
    /// Schema version anchor ("v1.0").
    pub schema_version: &'static str,
    /// Report kind identifier ("tls").
    pub kind: &'static str,
    /// Total count of TLS observations as a decimal string.
    pub total_observations: String,
    /// List of normalized TLS observations.
    pub observations: Vec<TlsObservationDto>,
}

impl TlsReportDto {
    /// Constructs a new DTO from a slice of domain TLS observations.
    #[must_use]
    pub fn from_domain_observations(observations: &[TlsObservation]) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "tls",
            total_observations: observations.len().to_string(),
            observations: observations
                .iter()
                .map(TlsObservationDto::from_domain)
                .collect(),
        }
    }
}

/// A normalized TLS 1.2 / TLS 1.3 handshake observation record.
#[derive(Debug, Clone, Serialize)]
pub struct TlsObservationDto {
    /// Zero-based packet ordinal in capture file as a decimal string.
    pub packet_ordinal: String,
    /// Source IP address string.
    pub source_ip: String,
    /// Source TCP port number.
    pub source_port: u16,
    /// Destination IP address string.
    pub destination_ip: String,
    /// Destination TCP port number.
    pub destination_port: u16,
    /// TLS record layer version string (e.g. "TLS 1.0", "TLS 1.2").
    pub record_version: String,
    /// Handshake message kind ("client_hello", "server_hello", "hello_retry_request", "other").
    pub handshake_kind: String,
    /// ClientHello handshake metadata if present.
    pub client_hello: Option<TlsClientHelloDto>,
    /// ServerHello handshake metadata if present.
    pub server_hello: Option<TlsServerHelloDto>,
    /// Completeness status ("complete" or "partial").
    pub completeness: String,
}

impl TlsObservationDto {
    /// Converts a domain [`TlsObservation`] into a serializable DTO.
    #[must_use]
    pub fn from_domain(obs: &TlsObservation) -> Self {
        let kind_str = match obs.handshake_kind {
            TlsHandshakeKind::ClientHello => "client_hello",
            TlsHandshakeKind::ServerHello => "server_hello",
            TlsHandshakeKind::HelloRetryRequest => "hello_retry_request",
            TlsHandshakeKind::Other(_) => "other",
        };

        Self {
            packet_ordinal: obs.packet.capture_record_ordinal.to_string(),
            source_ip: obs.source_ip.to_string(),
            source_port: obs.source_port,
            destination_ip: obs.destination_ip.to_string(),
            destination_port: obs.destination_port,
            record_version: obs.record_version.as_str().to_string(),
            handshake_kind: kind_str.to_string(),
            client_hello: obs
                .client_hello
                .as_ref()
                .map(TlsClientHelloDto::from_domain),
            server_hello: obs
                .server_hello
                .as_ref()
                .map(TlsServerHelloDto::from_domain),
            completeness: if obs.completeness.is_complete() {
                "complete".to_string()
            } else {
                "partial".to_string()
            },
        }
    }
}

/// TLS ClientHello metadata.
#[derive(Debug, Clone, Serialize)]
pub struct TlsClientHelloDto {
    /// Client declared legacy protocol version string (e.g. "TLS 1.2").
    pub client_version: String,
    /// Server Name Indication (SNI) hostname if present.
    pub server_name: Option<String>,
    /// Supported versions announced via supported_versions extension.
    pub supported_versions: Vec<String>,
    /// Application Layer Protocol Negotiation (ALPN) protocol names.
    pub alpn_protocols: Vec<String>,
    /// Advertised 16-bit cipher suite codes (formatted as hex strings "0x1301").
    pub cipher_suites: Vec<String>,
    /// Extensions present in the ClientHello.
    pub extensions: Vec<TlsExtensionDto>,
}

impl TlsClientHelloDto {
    /// Converts domain ClientHello metadata into a DTO.
    #[must_use]
    pub fn from_domain(ch: &TlsClientHelloMetadata) -> Self {
        Self {
            client_version: ch.legacy_version.as_str().to_string(),
            server_name: ch.server_name.as_ref().map(|s| s.display_escaped()),
            supported_versions: ch
                .supported_versions
                .iter()
                .map(|v| v.as_str().to_string())
                .collect(),
            alpn_protocols: ch
                .alpn_protocols
                .iter()
                .map(|a| a.display_escaped())
                .collect(),
            cipher_suites: ch
                .cipher_suites
                .iter()
                .map(|cs| format!("0x{cs:04x}"))
                .collect(),
            extensions: ch
                .extensions
                .iter()
                .map(TlsExtensionDto::from_domain)
                .collect(),
        }
    }
}

/// TLS ServerHello metadata.
#[derive(Debug, Clone, Serialize)]
pub struct TlsServerHelloDto {
    /// Server declared legacy protocol version string (e.g. "TLS 1.2").
    pub server_version: String,
    /// Negotiated protocol version (from supported_versions extension if TLS 1.3).
    pub selected_version: Option<String>,
    /// Selected 16-bit cipher suite code (formatted as hex "0x1301").
    pub selected_cipher_suite: String,
    /// Negotiated ALPN protocol name if present.
    pub selected_alpn: Option<String>,
    /// Extensions present in the ServerHello.
    pub extensions: Vec<TlsExtensionDto>,
}

impl TlsServerHelloDto {
    /// Converts domain ServerHello metadata into a DTO.
    #[must_use]
    pub fn from_domain(sh: &TlsServerHelloMetadata) -> Self {
        Self {
            server_version: sh.legacy_version.as_str().to_string(),
            selected_version: sh.selected_version.map(|v| v.as_str().to_string()),
            selected_cipher_suite: format!("0x{:04x}", sh.cipher_suite),
            selected_alpn: sh.selected_alpn.as_ref().map(|a| a.display_escaped()),
            extensions: sh
                .extensions
                .iter()
                .map(TlsExtensionDto::from_domain)
                .collect(),
        }
    }
}

/// Metadata for an individual TLS extension.
#[derive(Debug, Clone, Serialize)]
pub struct TlsExtensionDto {
    /// 16-bit extension type code.
    pub extension_type: u16,
    /// Declared byte length of extension data.
    pub length: u16,
}

impl TlsExtensionDto {
    /// Converts domain extension metadata into a DTO.
    #[must_use]
    pub fn from_domain(ext: &TlsExtensionMetadata) -> Self {
        Self {
            extension_type: ext.extension_type,
            length: ext.declared_length,
        }
    }
}
