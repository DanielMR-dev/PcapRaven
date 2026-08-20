//! Serializable DTOs for normalized HTTP/1.x observation reports.

use pcapraven_domain::{
    HttpContentLengthState, HttpObservation, HttpRequestMetadata, HttpResponseMetadata,
    HttpSelectedHeaders,
};
use serde::Serialize;

use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for an HTTP report in JSON.
#[derive(Debug, Clone, Serialize)]
pub struct HttpReportDto {
    /// Schema version anchor ("v1.0").
    pub schema_version: &'static str,
    /// Report kind identifier ("http").
    pub kind: &'static str,
    /// Total count of HTTP observations.
    pub total_observations: usize,
    /// List of normalized HTTP observations.
    pub observations: Vec<HttpObservationDto>,
}

impl HttpReportDto {
    /// Constructs a new DTO from a slice of domain HTTP observations.
    #[must_use]
    pub fn from_domain_observations(observations: &[HttpObservation]) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "http",
            total_observations: observations.len(),
            observations: observations
                .iter()
                .map(HttpObservationDto::from_domain)
                .collect(),
        }
    }
}

/// A normalized HTTP/1.x message observation record.
#[derive(Debug, Clone, Serialize)]
pub struct HttpObservationDto {
    /// Zero-based packet ordinal in capture file.
    pub packet_ordinal: u64,
    /// Transport protocol ("TCP").
    pub transport: &'static str,
    /// Source IP address string.
    pub source_ip: String,
    /// Source TCP port number.
    pub source_port: u16,
    /// Destination IP address string.
    pub destination_ip: String,
    /// Destination TCP port number.
    pub destination_port: u16,
    /// Message kind ("Request" or "Response").
    pub message_kind: String,
    /// HTTP protocol version string ("HTTP/1.0", "HTTP/1.1", etc.).
    pub version: String,
    /// Request line metadata if this message is an HTTP request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpRequestDto>,
    /// Response line metadata if this message is an HTTP response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpResponseDto>,
    /// Selected headers and privacy flags.
    pub headers: HttpHeadersDto,
    /// Completeness status ("complete" or "partial").
    pub completeness: String,
}

impl HttpObservationDto {
    /// Converts a domain [`HttpObservation`] into a serializable DTO.
    #[must_use]
    pub fn from_domain(obs: &HttpObservation) -> Self {
        Self {
            packet_ordinal: obs.packet.capture_record_ordinal,
            transport: "TCP",
            source_ip: obs.source_ip.to_string(),
            source_port: obs.source_port,
            destination_ip: obs.destination_ip.to_string(),
            destination_port: obs.destination_port,
            message_kind: obs.message_kind.as_str().to_string(),
            version: obs.version.as_str().to_string(),
            request: obs.request.as_ref().map(HttpRequestDto::from_domain),
            response: obs.response.as_ref().map(HttpResponseDto::from_domain),
            headers: HttpHeadersDto::from_domain(&obs.headers),
            completeness: if obs.completeness.is_complete() {
                "complete".to_string()
            } else {
                "partial".to_string()
            },
        }
    }
}

/// HTTP request line metadata.
#[derive(Debug, Clone, Serialize)]
pub struct HttpRequestDto {
    /// HTTP method string (e.g. "GET", "POST").
    pub method: String,
    /// Request target URL / path (terminal-safe escaped).
    pub target: String,
}

impl HttpRequestDto {
    /// Converts domain request metadata into a DTO.
    #[must_use]
    pub fn from_domain(req: &HttpRequestMetadata) -> Self {
        Self {
            method: req.method.display_escaped(),
            target: req.target.display_escaped(),
        }
    }
}

/// HTTP response status line metadata.
#[derive(Debug, Clone, Serialize)]
pub struct HttpResponseDto {
    /// HTTP 3-digit status code (e.g. 200, 404).
    pub status_code: u16,
}

impl HttpResponseDto {
    /// Converts domain response metadata into a DTO.
    #[must_use]
    pub fn from_domain(resp: &HttpResponseMetadata) -> Self {
        Self {
            status_code: resp.status_code,
        }
    }
}

/// Selected HTTP headers and privacy presence flags.
#[derive(Debug, Clone, Serialize)]
pub struct HttpHeadersDto {
    /// Host header value if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Content-Type header value if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Content-Length state ("none", "invalid", or byte length string).
    pub content_length: String,
    /// Transfer-Encoding header value if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_encoding: Option<String>,
    /// Server header value if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// User-Agent header value if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Privacy flags indicating presence of sensitive credentials/tokens.
    pub sensitive_headers: HttpSensitiveHeadersDto,
}

impl HttpHeadersDto {
    /// Converts domain headers metadata into a DTO.
    #[must_use]
    pub fn from_domain(h: &HttpSelectedHeaders) -> Self {
        let cl_str = match &h.content_length {
            HttpContentLengthState::Present(v) => format!("{v}"),
            HttpContentLengthState::Invalid => "invalid".to_string(),
            HttpContentLengthState::NotPresent => "not_present".to_string(),
        };

        Self {
            host: h.host.as_ref().map(|v| v.display_escaped()),
            content_type: h.content_type.as_ref().map(|v| v.display_escaped()),
            content_length: cl_str,
            transfer_encoding: h.transfer_encoding.as_ref().map(|v| v.display_escaped()),
            server: h.server.as_ref().map(|v| v.display_escaped()),
            user_agent: h.user_agent.as_ref().map(|v| v.display_escaped()),
            sensitive_headers: HttpSensitiveHeadersDto {
                authorization_present: h.has_authorization,
                cookie_present: h.has_cookie,
                set_cookie_present: h.has_set_cookie,
                proxy_authorization_present: h.has_proxy_authorization,
            },
        }
    }
}

/// Privacy presence flags for sensitive headers (values are never retained).
#[derive(Debug, Clone, Serialize)]
pub struct HttpSensitiveHeadersDto {
    /// `Authorization` header present.
    pub authorization_present: bool,
    /// `Cookie` header present.
    pub cookie_present: bool,
    /// `Set-Cookie` header present.
    pub set_cookie_present: bool,
    /// `Proxy-Authorization` header present.
    pub proxy_authorization_present: bool,
}
