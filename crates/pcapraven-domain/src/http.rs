//! Capture-independent normalized HTTP/1.x observation models and contracts.
//!
//! This module defines domain types representing factual HTTP/1.x requests,
//! responses, selected headers, framing metadata, and diagnostics extracted
//! from packet streams.

use crate::packet::{IpAddress, PacketReference, PacketTimestamp};
use core::fmt;

/// Factual HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/1.0 (RFC 1945).
    Http10,
    /// HTTP/1.1 (RFC 9112).
    Http11,
}

impl HttpVersion {
    /// Returns the static string representation of this HTTP version.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Factual HTTP message kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMessageKind {
    /// HTTP request message.
    Request,
    /// HTTP response message.
    Response,
}

impl HttpMessageKind {
    /// Returns the static string representation of this message kind.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Response => "Response",
        }
    }
}

impl fmt::Display for HttpMessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Raw byte string representation preserving wire bytes without assuming UTF-8.
///
/// Bounded construction and size limits are enforced by upstream protocol parsers
/// and configuration budgets before domain instantiation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HttpByteString {
    bytes: Vec<u8>,
}

impl HttpByteString {
    /// Creates a new `HttpByteString` from raw bytes.
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

    /// Returns the number of bytes in this string.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if this byte string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Renders a deterministic terminal-safe string representation.
    ///
    /// Printable ASCII characters (0x20..=0x7E, except `\`) are rendered directly.
    /// Control characters, non-ASCII octets, and backslashes are escaped in `\xHH`
    /// or `\\` notation to prevent ANSI escape sequence injection into terminal output.
    #[must_use]
    pub fn display_escaped(&self) -> String {
        let mut output = String::new();
        for &b in &self.bytes {
            match b {
                b'\\' => output.push_str("\\\\"),
                0x20..=0x7E => output.push(b as char),
                _ => {
                    use core::fmt::Write;
                    let _ = write!(output, "\\x{:02x}", b);
                }
            }
        }
        output
    }
}

impl fmt::Display for HttpByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_escaped())
    }
}

impl From<Vec<u8>> for HttpByteString {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for HttpByteString {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

impl From<&str> for HttpByteString {
    fn from(s: &str) -> Self {
        Self {
            bytes: s.as_bytes().to_vec(),
        }
    }
}

/// Normalized HTTP request start-line metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpRequestMetadata {
    /// Bounded raw request method (e.g. `GET`, `POST`).
    pub method: HttpByteString,
    /// Bounded raw request target (URI path / query).
    pub target: HttpByteString,
}

/// Normalized HTTP response status-line metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpResponseMetadata {
    /// 3-digit numeric HTTP status code (e.g. 200, 404).
    pub status_code: u16,
}

/// Content-Length header decoding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HttpContentLengthState {
    /// Content-Length header was not present in the message.
    #[default]
    NotPresent,
    /// Successfully parsed single or consistent non-conflicting decimal Content-Length.
    Present(u64),
    /// Conflicting, negative, unparseable, or overflowing Content-Length values.
    Invalid,
}

impl HttpContentLengthState {
    /// Returns the decimal value if present and valid.
    #[must_use]
    pub const fn value(&self) -> Option<u64> {
        match *self {
            Self::Present(v) => Some(v),
            Self::NotPresent | Self::Invalid => None,
        }
    }
}

/// Selected retained HTTP header fields and sensitive header presence flags.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HttpSelectedHeaders {
    /// Value of `Host` header if present.
    pub host: Option<HttpByteString>,
    /// Value of `User-Agent` header if present.
    pub user_agent: Option<HttpByteString>,
    /// Value of `Server` header if present.
    pub server: Option<HttpByteString>,
    /// Value of `Content-Type` header if present.
    pub content_type: Option<HttpByteString>,
    /// Parsed Content-Length state.
    pub content_length: HttpContentLengthState,
    /// Value of `Transfer-Encoding` header if present.
    pub transfer_encoding: Option<HttpByteString>,
    /// Value of `Connection` header if present.
    pub connection: Option<HttpByteString>,
    /// Value of `Upgrade` header if present.
    pub upgrade: Option<HttpByteString>,
    /// Flag indicating whether `Authorization` was present (values are never retained).
    pub has_authorization: bool,
    /// Flag indicating whether `Proxy-Authorization` was present (values are never retained).
    pub has_proxy_authorization: bool,
    /// Flag indicating whether `Cookie` was present (values are never retained).
    pub has_cookie: bool,
    /// Flag indicating whether `Set-Cookie` was present (values are never retained).
    pub has_set_cookie: bool,
}

/// Normalized HTTP framing and connection metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HttpFramingMetadata {
    /// Decoded Content-Length state.
    pub content_length: HttpContentLengthState,
    /// Whether Transfer-Encoding indicates chunked framing.
    pub is_chunked: bool,
    /// Whether Connection/Upgrade indicates a protocol upgrade.
    pub is_upgrade: bool,
    /// Whether Connection indicates connection closure (`close`).
    pub is_close: bool,
    /// Whether Connection indicates keep-alive.
    pub is_keep_alive: bool,
    /// Whether both Transfer-Encoding and Content-Length headers were present.
    pub has_conflicting_framing: bool,
}

/// Completeness status of a normalized HTTP observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpObservationCompleteness {
    /// Header section was fully and completely parsed up to `\r\n\r\n`.
    Complete,
    /// Header section was partially parsed up to a truncation or limit boundary.
    Partial {
        /// Safe fixed explanation for partial completeness.
        reason: &'static str,
    },
}

impl HttpObservationCompleteness {
    /// Returns `true` if this observation is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// A normalized, capture-independent factual HTTP/1.x observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpObservation {
    /// Reference to the source capture record.
    pub packet: PacketReference,
    /// Timestamp of the source packet.
    pub timestamp: PacketTimestamp,
    /// Observed source IP address.
    pub source_ip: IpAddress,
    /// Observed source transport port.
    pub source_port: u16,
    /// Observed destination IP address.
    pub destination_ip: IpAddress,
    /// Observed destination transport port.
    pub destination_port: u16,
    /// Decoded HTTP version.
    pub version: HttpVersion,
    /// Message kind (Request or Response).
    pub message_kind: HttpMessageKind,
    /// Request-specific metadata if this is a request.
    pub request: Option<HttpRequestMetadata>,
    /// Response-specific metadata if this is a response.
    pub response: Option<HttpResponseMetadata>,
    /// Retained selected header values and sensitive header flags.
    pub headers: HttpSelectedHeaders,
    /// Framing and connection lifecycle metadata.
    pub framing: HttpFramingMetadata,
    /// Total number of header fields parsed in the message.
    pub declared_field_count: usize,
    /// Total bytes in the start-line and header section (including terminating CRLF CRLF).
    pub header_section_bytes: usize,
    /// Explicit completeness status.
    pub completeness: HttpObservationCompleteness,
}

/// Category of an HTTP parser diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpDiagnosticKind {
    /// Malformed wire structure or invalid field format.
    Malformed,
    /// Truncated payload before a required header field or section ended.
    Incomplete,
    /// Recognized structure outside the supported subset (e.g. HTTP/2 or obs-fold).
    Unsupported,
    /// A configured finite parser limit was reached.
    ResourceLimit,
    /// An internal invariant failed.
    Internal,
}

/// Bounded diagnostic emitted during HTTP parsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpDiagnostic {
    /// Diagnostic classification.
    pub kind: HttpDiagnosticKind,
    /// Safe, static message template.
    pub message: &'static str,
    /// Byte offset within the transport payload.
    pub offset: usize,
}
