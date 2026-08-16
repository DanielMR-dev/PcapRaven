//! Bounded HTTP/1.x wire-format parser and candidate classification.
//!
//! Parses normalized IPv4/IPv6 TCP packets on cleartext port 80 into structured,
//! capture-independent [`HttpObservation`] records and bounded diagnostics.

use crate::http_limits::HttpLimits;
use pcapraven_domain::{
    HttpByteString, HttpContentLengthState, HttpDiagnostic, HttpDiagnosticKind,
    HttpFramingMetadata, HttpMessageKind, HttpObservation, HttpObservationCompleteness,
    HttpRequestMetadata, HttpResponseMetadata, HttpSelectedHeaders, HttpVersion, IpAddress,
    NormalizedPacket, PacketReference, PacketTimestamp, TransportLayer,
};

/// High-level disposition of HTTP processing for a single packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpPacketDisposition {
    /// Packet is not an HTTP candidate (not cleartext TCP port 80).
    NotHttpCandidate,
    /// Candidate TCP packet on port 80 containing zero payload or non-start midstream data.
    CandidateWithoutMessage,
    /// Successfully parsed a complete HTTP/1.x header observation.
    Parsed,
    /// One or more HTTP messages had incomplete framing, truncation, malformed structure, or hit limits.
    Partial,
}

/// Result of parsing HTTP messages from a single normalized packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPacketOutcome {
    /// High-level packet classification.
    pub disposition: HttpPacketDisposition,
    /// Decoded HTTP observations (0 or 1 per packet start).
    pub observations: Vec<HttpObservation>,
    /// Bounded diagnostic events collected during parsing.
    pub diagnostics: Vec<HttpDiagnostic>,
}

/// Parses HTTP/1.x message headers from a normalized packet using configured resource limits.
#[must_use]
pub fn parse_http_packet(packet: &NormalizedPacket, limits: &HttpLimits) -> HttpPacketOutcome {
    let transport = match &packet.transport_layer {
        Some(TransportLayer::Tcp(tcp)) => tcp,
        _ => {
            return HttpPacketOutcome {
                disposition: HttpPacketDisposition::NotHttpCandidate,
                observations: Vec::new(),
                diagnostics: Vec::new(),
            };
        }
    };

    if transport.source_port != 80 && transport.destination_port != 80 {
        return HttpPacketOutcome {
            disposition: HttpPacketDisposition::NotHttpCandidate,
            observations: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let payload = match &packet.payload {
        Some(p) => p.as_slice(),
        None => &[],
    };

    if payload.is_empty() {
        return HttpPacketOutcome {
            disposition: HttpPacketDisposition::CandidateWithoutMessage,
            observations: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let (source_ip, destination_ip) = match &packet.network_layer {
        Some(net) => (net.source_ip(), net.destination_ip()),
        None => {
            let mut diagnostics = Vec::new();
            if limits.maximum_diagnostics_per_packet > 0 {
                diagnostics.push(HttpDiagnostic {
                    kind: HttpDiagnosticKind::Malformed,
                    message: "missing network layer in normalized packet candidate",
                    offset: 0,
                });
            }
            return HttpPacketOutcome {
                disposition: HttpPacketDisposition::Partial,
                observations: Vec::new(),
                diagnostics,
            };
        }
    };

    // Check if the payload starts with an HTTP/2 connection preface
    if payload.starts_with(b"PRI * HTTP/2.0\r\n") {
        let mut diagnostics = Vec::new();
        if limits.maximum_diagnostics_per_packet > 0 {
            diagnostics.push(HttpDiagnostic {
                kind: HttpDiagnosticKind::Unsupported,
                message: "HTTP/2 connection preface is unsupported in Phase 8",
                offset: 0,
            });
        }
        return HttpPacketOutcome {
            disposition: HttpPacketDisposition::Partial,
            observations: Vec::new(),
            diagnostics,
        };
    }

    // Heuristic check: does the payload establish an HTTP start-line?
    // Responses start with "HTTP/"
    // Requests start with a token followed by SP and a target starting with "/" or "*" or "http"
    if !looks_like_http_start_line(payload) {
        return HttpPacketOutcome {
            disposition: HttpPacketDisposition::CandidateWithoutMessage,
            observations: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let mut parser = HttpMessageParser {
        packet_ref: packet.reference,
        timestamp: packet.timestamp,
        source_ip,
        source_port: transport.source_port,
        destination_ip,
        destination_port: transport.destination_port,
        limits,
        diagnostics: Vec::new(),
        had_partial: false,
    };

    let observation = parser.parse_message(payload);

    let disposition = if parser.had_partial {
        HttpPacketDisposition::Partial
    } else if observation.is_some() {
        HttpPacketDisposition::Parsed
    } else {
        HttpPacketDisposition::CandidateWithoutMessage
    };

    let mut observations = Vec::new();
    if let Some(obs) = observation {
        observations.push(obs);
    }

    HttpPacketOutcome {
        disposition,
        observations,
        diagnostics: parser.diagnostics,
    }
}

fn looks_like_http_start_line(data: &[u8]) -> bool {
    if data.starts_with(b"HTTP/") {
        return true;
    }

    // Check for standard or custom request methods: [A-Z]{1..32} followed by SP
    let mut i = 0usize;
    while i < data.len() && i < 32 {
        let b = data[i];
        if b == b' ' {
            // Need at least 1 character method and space followed by target character
            return i > 0
                && i + 1 < data.len()
                && (data[i + 1] == b'/' || data[i + 1] == b'*' || is_token_char(data[i + 1]));
        }
        if !is_token_char(b) {
            return false;
        }
        i = i.saturating_add(1);
    }
    false
}

const fn is_token_char(b: u8) -> bool {
    matches!(
        b,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

struct HttpMessageParser<'a> {
    packet_ref: PacketReference,
    timestamp: PacketTimestamp,
    source_ip: IpAddress,
    source_port: u16,
    destination_ip: IpAddress,
    destination_port: u16,
    limits: &'a HttpLimits,
    diagnostics: Vec<HttpDiagnostic>,
    had_partial: bool,
}

impl<'a> HttpMessageParser<'a> {
    fn emit_diagnostic(&mut self, kind: HttpDiagnosticKind, message: &'static str, offset: usize) {
        if self.diagnostics.len() < self.limits.maximum_diagnostics_per_packet {
            self.diagnostics.push(HttpDiagnostic {
                kind,
                message,
                offset,
            });
        }
    }

    fn parse_message(&mut self, payload: &[u8]) -> Option<HttpObservation> {
        let mut offset = 0usize;
        let mut is_partial = false;
        let mut partial_reason = "";

        // 1. Parse start-line up to CRLF
        let start_line_crlf = match find_crlf(payload, offset) {
            Ok(Some(idx)) => idx,
            Ok(None) => {
                self.emit_diagnostic(
                    HttpDiagnosticKind::Incomplete,
                    "truncated HTTP start-line (missing CRLF)",
                    offset,
                );
                self.had_partial = true;
                return None;
            }
            Err(e) => {
                self.emit_diagnostic(e.kind, e.message, e.offset);
                self.had_partial = true;
                return None;
            }
        };

        let start_line_len = start_line_crlf.saturating_sub(offset);
        if start_line_len > self.limits.maximum_start_line_bytes {
            self.emit_diagnostic(
                HttpDiagnosticKind::ResourceLimit,
                "HTTP start-line exceeds configured maximum bytes limit",
                offset,
            );
            self.had_partial = true;
            return None;
        }

        let start_line_bytes = &payload[offset..start_line_crlf];
        offset = start_line_crlf.saturating_add(2); // skip \r\n

        let (version, message_kind, request_meta, response_meta) =
            match self.parse_start_line(start_line_bytes) {
                Ok(res) => res,
                Err(e) => {
                    self.emit_diagnostic(e.kind, e.message, e.offset);
                    self.had_partial = true;
                    return None;
                }
            };

        // 2. Parse field lines until empty line (CRLF)
        let mut field_count = 0usize;
        let mut selected_headers = HttpSelectedHeaders::default();
        let mut transfer_encoding_present = false;
        let mut is_chunked = false;
        let mut is_upgrade = false;
        let mut is_close = false;
        let mut is_keep_alive = false;

        loop {
            if offset >= payload.len() {
                self.emit_diagnostic(
                    HttpDiagnosticKind::Incomplete,
                    "truncated HTTP header section (missing terminal CRLF CRLF)",
                    offset,
                );
                is_partial = true;
                partial_reason = "truncated HTTP header section";
                break;
            }

            // Check for empty line marking end of headers
            if payload[offset..].starts_with(b"\r\n") {
                offset = offset.saturating_add(2);
                break;
            }

            // Check limits before reading next line
            if field_count >= self.limits.maximum_header_fields {
                self.emit_diagnostic(
                    HttpDiagnosticKind::ResourceLimit,
                    "reached maximum HTTP header fields limit",
                    offset,
                );
                is_partial = true;
                partial_reason = "exceeded maximum header fields limit";
                break;
            }

            if offset > self.limits.maximum_header_section_bytes {
                self.emit_diagnostic(
                    HttpDiagnosticKind::ResourceLimit,
                    "exceeded maximum HTTP header section bytes limit",
                    offset,
                );
                is_partial = true;
                partial_reason = "exceeded maximum header section bytes limit";
                break;
            }

            // Check for line folding (obs-fold)
            if payload[offset] == b' ' || payload[offset] == b'\t' {
                self.emit_diagnostic(
                    HttpDiagnosticKind::Unsupported,
                    "HTTP line folding (obs-fold) is unsupported",
                    offset,
                );
                is_partial = true;
                partial_reason = "unsupported line folding (obs-fold)";
                break;
            }

            let line_crlf = match find_crlf(payload, offset) {
                Ok(Some(idx)) => idx,
                Ok(None) => {
                    self.emit_diagnostic(
                        HttpDiagnosticKind::Incomplete,
                        "truncated HTTP header field line (missing CRLF)",
                        offset,
                    );
                    is_partial = true;
                    partial_reason = "truncated header line";
                    break;
                }
                Err(e) => {
                    self.emit_diagnostic(e.kind, e.message, e.offset);
                    is_partial = true;
                    partial_reason = e.message;
                    break;
                }
            };

            let line_len = line_crlf.saturating_sub(offset);
            if line_len > self.limits.maximum_header_line_bytes {
                self.emit_diagnostic(
                    HttpDiagnosticKind::ResourceLimit,
                    "HTTP header line exceeds configured maximum bytes limit",
                    offset,
                );
                is_partial = true;
                partial_reason = "header line exceeds byte limit";
                break;
            }

            let line_bytes = &payload[offset..line_crlf];
            offset = line_crlf.saturating_add(2); // skip \r\n
            field_count = field_count.saturating_add(1);

            // Parse field name and field value
            let colon_pos = match line_bytes.iter().position(|&b| b == b':') {
                Some(p) => p,
                None => {
                    self.emit_diagnostic(
                        HttpDiagnosticKind::Malformed,
                        "header line missing colon separator",
                        offset.saturating_sub(line_len).saturating_sub(2),
                    );
                    is_partial = true;
                    partial_reason = "header missing colon separator";
                    break;
                }
            };

            let name_bytes = &line_bytes[..colon_pos];
            if name_bytes.is_empty() || !name_bytes.iter().all(|&b| is_token_char(b)) {
                self.emit_diagnostic(
                    HttpDiagnosticKind::Malformed,
                    "invalid characters or whitespace in HTTP header field name",
                    offset.saturating_sub(line_len).saturating_sub(2),
                );
                is_partial = true;
                partial_reason = "invalid header field name";
                break;
            }

            let raw_value = &line_bytes[colon_pos + 1..];
            let value_trimmed = trim_ows(raw_value);

            // Validate value bytes (VCHAR, SP, HTAB, obs-text)
            if !is_valid_field_value(value_trimmed) {
                self.emit_diagnostic(
                    HttpDiagnosticKind::Malformed,
                    "invalid control characters in HTTP header field value",
                    offset.saturating_sub(line_len).saturating_sub(2),
                );
                is_partial = true;
                partial_reason = "invalid control characters in header value";
                break;
            }

            // Process selected headers
            if name_bytes.eq_ignore_ascii_case(b"host") {
                if selected_headers.host.is_some()
                    && matches!(message_kind, HttpMessageKind::Request)
                {
                    self.emit_diagnostic(
                        HttpDiagnosticKind::Malformed,
                        "duplicate Host header in HTTP request",
                        offset.saturating_sub(line_len).saturating_sub(2),
                    );
                    is_partial = true;
                    partial_reason = "duplicate Host header";
                } else {
                    let val_len = value_trimmed
                        .len()
                        .min(self.limits.maximum_selected_field_value_bytes);
                    selected_headers.host =
                        Some(HttpByteString::new(value_trimmed[..val_len].to_vec()));
                }
            } else if name_bytes.eq_ignore_ascii_case(b"user-agent") {
                let val_len = value_trimmed
                    .len()
                    .min(self.limits.maximum_selected_field_value_bytes);
                selected_headers.user_agent =
                    Some(HttpByteString::new(value_trimmed[..val_len].to_vec()));
            } else if name_bytes.eq_ignore_ascii_case(b"server") {
                let val_len = value_trimmed
                    .len()
                    .min(self.limits.maximum_selected_field_value_bytes);
                selected_headers.server =
                    Some(HttpByteString::new(value_trimmed[..val_len].to_vec()));
            } else if name_bytes.eq_ignore_ascii_case(b"content-type") {
                let val_len = value_trimmed
                    .len()
                    .min(self.limits.maximum_selected_field_value_bytes);
                selected_headers.content_type =
                    Some(HttpByteString::new(value_trimmed[..val_len].to_vec()));
            } else if name_bytes.eq_ignore_ascii_case(b"content-length") {
                match parse_content_length(value_trimmed) {
                    Ok(len) => {
                        match selected_headers.content_length {
                            HttpContentLengthState::NotPresent => {
                                selected_headers.content_length =
                                    HttpContentLengthState::Present(len);
                            }
                            HttpContentLengthState::Present(existing) if existing == len => {
                                // Duplicate identical values allowed per RFC 9110 Section 8.6
                            }
                            _ => {
                                selected_headers.content_length = HttpContentLengthState::Invalid;
                                self.emit_diagnostic(
                                    HttpDiagnosticKind::Malformed,
                                    "conflicting or invalid Content-Length header values",
                                    offset.saturating_sub(line_len).saturating_sub(2),
                                );
                                is_partial = true;
                                partial_reason = "conflicting Content-Length header";
                            }
                        }
                    }
                    Err(_) => {
                        selected_headers.content_length = HttpContentLengthState::Invalid;
                        self.emit_diagnostic(
                            HttpDiagnosticKind::Malformed,
                            "malformed Content-Length integer value",
                            offset.saturating_sub(line_len).saturating_sub(2),
                        );
                        is_partial = true;
                        partial_reason = "malformed Content-Length integer value";
                    }
                }
            } else if name_bytes.eq_ignore_ascii_case(b"transfer-encoding") {
                transfer_encoding_present = true;
                if matches!(version, HttpVersion::Http10) {
                    self.emit_diagnostic(
                        HttpDiagnosticKind::Unsupported,
                        "Transfer-Encoding is unsupported in HTTP/1.0",
                        offset.saturating_sub(line_len).saturating_sub(2),
                    );
                    is_partial = true;
                    partial_reason = "Transfer-Encoding in HTTP/1.0";
                }
                if contains_token_case_insensitive(value_trimmed, b"chunked") {
                    is_chunked = true;
                }
                let val_len = value_trimmed
                    .len()
                    .min(self.limits.maximum_selected_field_value_bytes);
                selected_headers.transfer_encoding =
                    Some(HttpByteString::new(value_trimmed[..val_len].to_vec()));
            } else if name_bytes.eq_ignore_ascii_case(b"connection") {
                if contains_token_case_insensitive(value_trimmed, b"close") {
                    is_close = true;
                }
                if contains_token_case_insensitive(value_trimmed, b"keep-alive") {
                    is_keep_alive = true;
                }
                if contains_token_case_insensitive(value_trimmed, b"upgrade") {
                    is_upgrade = true;
                }
                let val_len = value_trimmed
                    .len()
                    .min(self.limits.maximum_selected_field_value_bytes);
                selected_headers.connection =
                    Some(HttpByteString::new(value_trimmed[..val_len].to_vec()));
            } else if name_bytes.eq_ignore_ascii_case(b"upgrade") {
                is_upgrade = true;
                let val_len = value_trimmed
                    .len()
                    .min(self.limits.maximum_selected_field_value_bytes);
                selected_headers.upgrade =
                    Some(HttpByteString::new(value_trimmed[..val_len].to_vec()));
            } else if name_bytes.eq_ignore_ascii_case(b"authorization") {
                selected_headers.has_authorization = true;
            } else if name_bytes.eq_ignore_ascii_case(b"proxy-authorization") {
                selected_headers.has_proxy_authorization = true;
            } else if name_bytes.eq_ignore_ascii_case(b"cookie") {
                selected_headers.has_cookie = true;
            } else if name_bytes.eq_ignore_ascii_case(b"set-cookie") {
                selected_headers.has_set_cookie = true;
            }
        }

        // Post-validation: Host header in HTTP/1.1 requests
        if !is_partial
            && matches!(message_kind, HttpMessageKind::Request)
            && matches!(version, HttpVersion::Http11)
            && selected_headers.host.is_none()
        {
            self.emit_diagnostic(
                HttpDiagnosticKind::Malformed,
                "missing mandatory Host header in HTTP/1.1 request",
                0,
            );
            is_partial = true;
            partial_reason = "missing mandatory Host header in HTTP/1.1 request";
        }

        // Post-validation: Conflicting Transfer-Encoding and Content-Length
        let has_conflicting_framing = transfer_encoding_present
            && matches!(
                selected_headers.content_length,
                HttpContentLengthState::Present(_)
            );
        if !is_partial && has_conflicting_framing {
            self.emit_diagnostic(
                HttpDiagnosticKind::Malformed,
                "conflicting Transfer-Encoding and Content-Length headers",
                0,
            );
            is_partial = true;
            partial_reason = "conflicting Transfer-Encoding and Content-Length";
        }

        let framing = HttpFramingMetadata {
            content_length: selected_headers.content_length,
            is_chunked,
            is_upgrade,
            is_close,
            is_keep_alive,
            has_conflicting_framing,
        };

        if is_partial {
            self.had_partial = true;
        }

        let completeness = if is_partial {
            HttpObservationCompleteness::Partial {
                reason: partial_reason,
            }
        } else {
            HttpObservationCompleteness::Complete
        };

        let header_section_bytes = offset;

        Some(HttpObservation {
            packet: self.packet_ref,
            timestamp: self.timestamp,
            source_ip: self.source_ip,
            source_port: self.source_port,
            destination_ip: self.destination_ip,
            destination_port: self.destination_port,
            version,
            message_kind,
            request: request_meta,
            response: response_meta,
            headers: selected_headers,
            framing,
            declared_field_count: field_count,
            header_section_bytes,
            completeness,
        })
    }

    fn parse_start_line(
        &self,
        line: &[u8],
    ) -> Result<
        (
            HttpVersion,
            HttpMessageKind,
            Option<HttpRequestMetadata>,
            Option<HttpResponseMetadata>,
        ),
        HttpInternalError,
    > {
        if line.starts_with(b"HTTP/") {
            // Response: HTTP-version SP status-code SP [reason-phrase]
            let sp1 = line.iter().position(|&b| b == b' ').ok_or_else(|| {
                HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "malformed HTTP status-line (missing first space)",
                    0,
                )
            })?;

            let version_bytes = &line[..sp1];
            let version = match version_bytes {
                b"HTTP/1.0" => HttpVersion::Http10,
                b"HTTP/1.1" => HttpVersion::Http11,
                _ => {
                    return Err(HttpInternalError::new(
                        HttpDiagnosticKind::Unsupported,
                        "unsupported HTTP response version",
                        0,
                    ));
                }
            };

            let rem = &line[sp1 + 1..];
            if rem.is_empty() {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "malformed HTTP status-line (empty status code)",
                    sp1 + 1,
                ));
            }

            // Status code is exactly 3 decimal digits
            let status_code_bytes = if rem.len() >= 3 && (rem.len() == 3 || rem[3] == b' ') {
                &rem[..3]
            } else {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "HTTP status code must be exactly 3 digits",
                    sp1 + 1,
                ));
            };

            if !status_code_bytes.iter().all(|&b| b.is_ascii_digit()) {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "HTTP status code contains non-digit characters",
                    sp1 + 1,
                ));
            }

            let d0 = (status_code_bytes[0] - b'0') as u16;
            let d1 = (status_code_bytes[1] - b'0') as u16;
            let d2 = (status_code_bytes[2] - b'0') as u16;
            let status_code = d0 * 100 + d1 * 10 + d2;

            if !(100..=999).contains(&status_code) {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "HTTP status code outside 100..=999 range",
                    sp1 + 1,
                ));
            }

            Ok((
                version,
                HttpMessageKind::Response,
                None,
                Some(HttpResponseMetadata { status_code }),
            ))
        } else {
            // Request: method SP request-target SP HTTP-version
            let sp1 = line.iter().position(|&b| b == b' ').ok_or_else(|| {
                HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "malformed HTTP request-line (missing first space)",
                    0,
                )
            })?;

            let method_bytes = &line[..sp1];
            if method_bytes.is_empty() || !method_bytes.iter().all(|&b| is_token_char(b)) {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "invalid characters in HTTP request method",
                    0,
                ));
            }
            if method_bytes.len() > self.limits.maximum_method_bytes {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::ResourceLimit,
                    "HTTP request method exceeds maximum method bytes limit",
                    0,
                ));
            }

            let rem = &line[sp1 + 1..];
            let sp2 = rem.iter().position(|&b| b == b' ').ok_or_else(|| {
                HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "malformed HTTP request-line (missing second space)",
                    sp1 + 1,
                )
            })?;

            let target_bytes = &rem[..sp2];
            if target_bytes.is_empty() || target_bytes.iter().any(|&b| b <= 0x20 || b == 0x7F) {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "invalid characters or whitespace in HTTP request-target",
                    sp1 + 1,
                ));
            }
            if target_bytes.len() > self.limits.maximum_request_target_bytes {
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::ResourceLimit,
                    "HTTP request-target exceeds maximum target bytes limit",
                    sp1 + 1,
                ));
            }

            let version_bytes = &rem[sp2 + 1..];
            let version = match version_bytes {
                b"HTTP/1.0" => HttpVersion::Http10,
                b"HTTP/1.1" => HttpVersion::Http11,
                _ => {
                    return Err(HttpInternalError::new(
                        HttpDiagnosticKind::Unsupported,
                        "unsupported HTTP request version",
                        sp1 + 1 + sp2 + 1,
                    ));
                }
            };

            let req_meta = HttpRequestMetadata {
                method: HttpByteString::new(method_bytes.to_vec()),
                target: HttpByteString::new(target_bytes.to_vec()),
            };

            Ok((version, HttpMessageKind::Request, Some(req_meta), None))
        }
    }
}

struct HttpInternalError {
    kind: HttpDiagnosticKind,
    message: &'static str,
    offset: usize,
}

impl HttpInternalError {
    const fn new(kind: HttpDiagnosticKind, message: &'static str, offset: usize) -> Self {
        Self {
            kind,
            message,
            offset,
        }
    }
}

fn find_crlf(data: &[u8], start: usize) -> Result<Option<usize>, HttpInternalError> {
    let mut i = start;
    while i < data.len() {
        if data[i] == b'\r' {
            if i + 1 < data.len() {
                if data[i + 1] == b'\n' {
                    return Ok(Some(i));
                }
                return Err(HttpInternalError::new(
                    HttpDiagnosticKind::Malformed,
                    "bare CR character without following LF in HTTP message",
                    i,
                ));
            }
            return Ok(None); // truncated at bare CR at end of available payload
        }
        if data[i] == b'\n' {
            return Err(HttpInternalError::new(
                HttpDiagnosticKind::Malformed,
                "bare LF character without preceding CR in HTTP message",
                i,
            ));
        }
        i = i.saturating_add(1);
    }
    Ok(None)
}

fn trim_ows(mut data: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = data.split_first() {
        if first == b' ' || first == b'\t' {
            data = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = data.split_last() {
        if last == b' ' || last == b'\t' {
            data = rest;
        } else {
            break;
        }
    }
    data
}

fn is_valid_field_value(data: &[u8]) -> bool {
    for &b in data {
        // VCHAR (0x21..=0x7E), SP (0x20), HTAB (0x09), obs-text (0x80..=0xFF)
        if (b < 0x20 && b != 0x09) || b == 0x7F {
            return false;
        }
    }
    true
}

fn parse_content_length(data: &[u8]) -> Result<u64, ()> {
    if data.is_empty() {
        return Err(());
    }
    let mut val = 0u64;
    for &b in data {
        if !b.is_ascii_digit() {
            return Err(());
        }
        let digit = (b - b'0') as u64;
        val = val
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(())?;
    }
    Ok(val)
}

fn contains_token_case_insensitive(data: &[u8], token: &[u8]) -> bool {
    for chunk in data.split(|&b| b == b',' || b == b' ' || b == b'\t' || b == b';') {
        let trimmed = trim_ows(chunk);
        if trimmed.eq_ignore_ascii_case(token) {
            return true;
        }
    }
    false
}
