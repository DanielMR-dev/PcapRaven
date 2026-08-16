//! Bounded TLS 1.2 / TLS 1.3 handshake metadata parser and candidate classifier.
//!
//! Enforces strict finite resource bounds, privacy invariants (no randoms, session IDs,
//! key share bytes, PSK secrets, or certificate DER retained), and safe packet-local
//! record parsing for TCP port 443 traffic.

use crate::tls_limits::{
    MAX_TLS_OPAQUE_RECORD_FRAGMENT_BYTES, MAX_TLS_PLAINTEXT_FRAGMENT_BYTES, TlsLimits,
};
use pcapraven_domain::{
    IpAddress, NetworkLayer, NormalizedPacket, PacketCompleteness, PacketReference,
    PacketTimestamp, PacketTruncationReason, TlsByteString, TlsClientHelloMetadata, TlsDiagnostic,
    TlsDiagnosticKind, TlsExtensionMetadata, TlsHandshakeKind, TlsObservation,
    TlsObservationCompleteness, TlsRecordContentType, TlsServerHelloMetadata, TlsVersion,
    TransportLayer,
};

/// 32-byte HelloRetryRequest random sentinel defined by RFC 9846 Section 4.1.3:
/// `CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C`
const HRR_RANDOM_SENTINEL: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// High-level disposition of TLS processing for a single packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsPacketDisposition {
    /// Packet is not on TCP port 443.
    NotTlsCandidate,
    /// Packet is on TCP port 443 but contains no recognisable TLS record header.
    CandidateWithoutRecord,
    /// Successfully parsed one or more complete TLS handshake observations.
    Parsed,
    /// TLS candidate processing was partial, truncated, or exceeded bounds.
    Partial,
}

/// Overall outcome of parsing a normalized packet for TLS handshake observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPacketOutcome {
    /// Processing disposition.
    pub disposition: TlsPacketDisposition,
    /// Extracted factual observations.
    pub observations: Vec<TlsObservation>,
    /// Bounded diagnostic collection.
    pub diagnostics: Vec<TlsDiagnostic>,
}

struct TlsParserContext<'a> {
    packet_ref: PacketReference,
    timestamp: PacketTimestamp,
    src_ip: IpAddress,
    src_port: u16,
    dst_ip: IpAddress,
    dst_port: u16,
    limits: &'a TlsLimits,
    diagnostics: Vec<TlsDiagnostic>,
    observations: Vec<TlsObservation>,
    is_partial: bool,
}

impl<'a> TlsParserContext<'a> {
    fn emit_diagnostic(&mut self, kind: TlsDiagnosticKind, message: String) {
        if self.diagnostics.len() < self.limits.maximum_diagnostics_per_packet {
            self.diagnostics.push(TlsDiagnostic::new(kind, message));
        }
    }
}

#[derive(Default)]
struct ParsedClientHelloExtensions {
    server_name: Option<TlsByteString>,
    supported_versions: Vec<TlsVersion>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn_protocols: Vec<TlsByteString>,
    key_share_groups: Vec<u16>,
    has_pre_shared_key: bool,
    has_early_data: bool,
    extensions: Vec<TlsExtensionMetadata>,
}

#[derive(Default)]
struct ParsedServerHelloExtensions {
    selected_version: Option<TlsVersion>,
    selected_group: Option<u16>,
    selected_alpn: Option<TlsByteString>,
    has_pre_shared_key: bool,
    has_early_data: bool,
    extensions: Vec<TlsExtensionMetadata>,
}

/// Parses a [`NormalizedPacket`] for visible TLS 1.2 / TLS 1.3 handshake metadata.
///
/// Returns a [`TlsPacketOutcome`] containing any extracted factual [`TlsObservation`]
/// records and bounded diagnostics.
#[must_use]
pub fn parse_tls_packet(packet: &NormalizedPacket, limits: &TlsLimits) -> TlsPacketOutcome {
    let tcp = match packet.transport_layer {
        Some(TransportLayer::Tcp(ref t)) => t,
        _ => {
            return TlsPacketOutcome {
                disposition: TlsPacketDisposition::NotTlsCandidate,
                observations: Vec::new(),
                diagnostics: Vec::new(),
            };
        }
    };

    if tcp.source_port != 443 && tcp.destination_port != 443 {
        return TlsPacketOutcome {
            disposition: TlsPacketDisposition::NotTlsCandidate,
            observations: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let payload = match packet.payload {
        Some(ref p) if !p.is_empty() => p.as_slice(),
        _ => {
            return TlsPacketOutcome {
                disposition: TlsPacketDisposition::CandidateWithoutRecord,
                observations: Vec::new(),
                diagnostics: Vec::new(),
            };
        }
    };

    let (src_ip, dst_ip) = match packet.network_layer {
        Some(NetworkLayer::Ipv4(ref ip)) => {
            (IpAddress::Ipv4(ip.source), IpAddress::Ipv4(ip.destination))
        }
        Some(NetworkLayer::Ipv6(ref ip)) => {
            (IpAddress::Ipv6(ip.source), IpAddress::Ipv6(ip.destination))
        }
        None => {
            return TlsPacketOutcome {
                disposition: TlsPacketDisposition::Partial,
                observations: Vec::new(),
                diagnostics: vec![TlsDiagnostic::new(
                    TlsDiagnosticKind::Malformed,
                    "TCP packet is missing network layer addresses".to_string(),
                )],
            };
        }
    };

    // Quick structural check: must have at least 5 bytes and look like a TLS record
    if payload.len() < 5 {
        let is_tls_prefix = !payload.is_empty()
            && matches!(payload[0], 20..=23)
            && (payload.len() < 2 || payload[1] == 0x03);
        return if is_tls_prefix {
            TlsPacketOutcome {
                disposition: TlsPacketDisposition::Partial,
                observations: Vec::new(),
                diagnostics: vec![TlsDiagnostic::new(
                    TlsDiagnosticKind::Truncated,
                    "TLS record header truncated by capture boundary".to_string(),
                )],
            }
        } else {
            TlsPacketOutcome {
                disposition: TlsPacketDisposition::CandidateWithoutRecord,
                observations: Vec::new(),
                diagnostics: Vec::new(),
            }
        };
    }

    let first_content_type = payload[0];
    let first_version_major = payload[1];
    if !(20..=23).contains(&first_content_type) || first_version_major != 0x03 {
        return TlsPacketOutcome {
            disposition: TlsPacketDisposition::CandidateWithoutRecord,
            observations: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let mut ctx = TlsParserContext {
        packet_ref: packet.reference,
        timestamp: packet.timestamp,
        src_ip,
        src_port: tcp.source_port,
        dst_ip,
        dst_port: tcp.destination_port,
        limits,
        diagnostics: Vec::new(),
        observations: Vec::new(),
        is_partial: false,
    };

    if !packet.completeness.is_complete() {
        if let PacketCompleteness::Partial { reason } = packet.completeness {
            if reason != PacketTruncationReason::PayloadBudgetExceeded {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Truncated,
                    format!("underlying packet capture was truncated: {reason:?}"),
                );
            }
        }
    }

    parse_records(payload, &mut ctx);

    let disposition = if !ctx.observations.is_empty() {
        if ctx.is_partial
            || ctx
                .observations
                .iter()
                .any(|o| !o.completeness.is_complete())
        {
            TlsPacketDisposition::Partial
        } else {
            TlsPacketDisposition::Parsed
        }
    } else if ctx.is_partial || !ctx.diagnostics.is_empty() {
        TlsPacketDisposition::Partial
    } else {
        TlsPacketDisposition::CandidateWithoutRecord
    };

    TlsPacketOutcome {
        disposition,
        observations: ctx.observations,
        diagnostics: ctx.diagnostics,
    }
}

fn parse_records(payload: &[u8], ctx: &mut TlsParserContext<'_>) {
    let mut offset = 0usize;
    let mut records_parsed = 0usize;

    // Buffer for packet-local multi-record handshake assembly
    let mut pending_handshake: Option<(TlsVersion, u16, Vec<u8>)> = None;

    while offset < payload.len() {
        if records_parsed >= ctx.limits.maximum_records_per_packet {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::ResourceLimit,
                format!(
                    "maximum records per packet limit ({}) reached",
                    ctx.limits.maximum_records_per_packet
                ),
            );
            break;
        }

        if payload.len().saturating_sub(offset) < 5 {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Truncated,
                "trailing bytes truncated before complete 5-byte TLS record header".to_string(),
            );
            break;
        }

        let content_type = TlsRecordContentType::from_wire(payload[offset]);
        let raw_version = u16::from_be_bytes([payload[offset + 1], payload[offset + 2]]);
        let record_version = TlsVersion::from_wire(raw_version);
        let record_length = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;

        let record_body_start = offset.saturating_add(5);
        let record_end = match record_body_start.checked_add(record_length) {
            Some(end) => end,
            None => {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Malformed,
                    "TLS record length arithmetic overflow".to_string(),
                );
                break;
            }
        };

        if record_end > payload.len() {
            ctx.is_partial = true;
            if record_length > MAX_TLS_OPAQUE_RECORD_FRAGMENT_BYTES {
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::ResourceLimit,
                    format!(
                        "TLS record length ({record_length} bytes) exceeds maximum fragment limit ({MAX_TLS_OPAQUE_RECORD_FRAGMENT_BYTES} bytes)"
                    ),
                );
            } else {
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Truncated,
                    format!(
                        "TLS record body truncated by packet boundary (expected {record_length} bytes, available {})",
                        payload.len().saturating_sub(record_body_start)
                    ),
                );
            }
            break;
        }

        let record_body = &payload[record_body_start..record_end];
        records_parsed = records_parsed.saturating_add(1);

        if content_type == TlsRecordContentType::Handshake {
            if record_length > MAX_TLS_PLAINTEXT_FRAGMENT_BYTES {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::ResourceLimit,
                    format!(
                        "plaintext handshake record fragment ({record_length} bytes) exceeds 16384-byte protocol limit"
                    ),
                );
                break;
            }

            if let Some((init_ver, init_rec_len, ref mut buf)) = pending_handshake {
                // Continue packet-local assembly of adjacent Handshake record
                let available_budget = ctx
                    .limits
                    .maximum_handshake_message_bytes
                    .saturating_sub(buf.len());
                if record_body.len() > available_budget {
                    ctx.is_partial = true;
                    ctx.emit_diagnostic(
                        TlsDiagnosticKind::ResourceLimit,
                        format!(
                            "assembled handshake message exceeds limit of {} bytes",
                            ctx.limits.maximum_handshake_message_bytes
                        ),
                    );
                    pending_handshake = None;
                    break;
                }
                buf.extend_from_slice(record_body);
                if process_handshake_buffer(init_ver, init_rec_len, buf, ctx) {
                    pending_handshake = None;
                }
            } else {
                let mut buf = record_body.to_vec();
                let initial_rec_len = u16::try_from(record_length).unwrap_or(u16::MAX);
                if !process_handshake_buffer(record_version, initial_rec_len, &mut buf, ctx) {
                    // Message is incomplete in this record, keep pending for subsequent records in the same packet
                    pending_handshake = Some((record_version, initial_rec_len, buf));
                }
            }
        } else {
            // Non-handshake record encountered: terminate any pending handshake assembly
            if pending_handshake.is_some() {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Malformed,
                    "interleaved non-handshake record encountered during fragmented handshake assembly".to_string(),
                );
                pending_handshake = None;
            }
        }

        offset = record_end;
    }

    if pending_handshake.is_some() {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Truncated,
            "fragmented handshake message incomplete within packet payload".to_string(),
        );
    }
}

/// Attempts to parse complete handshake messages from `buf`.
/// Returns `true` if all data in `buf` was completely consumed or encountered a terminal condition.
/// Returns `false` if `buf` ends with a partially present handshake message that needs more bytes.
fn process_handshake_buffer(
    record_version: TlsVersion,
    record_length: u16,
    buf: &mut [u8],
    ctx: &mut TlsParserContext<'_>,
) -> bool {
    let mut offset = 0usize;
    let mut messages_parsed = 0usize;

    while offset < buf.len() {
        if messages_parsed >= ctx.limits.maximum_handshake_messages_per_packet {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::ResourceLimit,
                format!(
                    "maximum handshake messages per packet limit ({}) reached",
                    ctx.limits.maximum_handshake_messages_per_packet
                ),
            );
            return true;
        }

        if buf.len().saturating_sub(offset) < 4 {
            // Incomplete handshake header: need more record data
            return false;
        }

        let msg_type = buf[offset];
        let msg_length = (u32::from(buf[offset + 1]) << 16)
            | (u32::from(buf[offset + 2]) << 8)
            | u32::from(buf[offset + 3]);

        let msg_usize = match usize::try_from(msg_length) {
            Ok(u) => u,
            Err(_) => {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::ResourceLimit,
                    "handshake message length exceeds addressable bounds".to_string(),
                );
                return true;
            }
        };

        if msg_usize > ctx.limits.maximum_handshake_message_bytes {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::ResourceLimit,
                format!(
                    "declared handshake message length ({msg_usize} bytes) exceeds limit ({})",
                    ctx.limits.maximum_handshake_message_bytes
                ),
            );
            return true;
        }

        let msg_body_start = offset.saturating_add(4);
        let msg_end = match msg_body_start.checked_add(msg_usize) {
            Some(end) => end,
            None => {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Malformed,
                    "handshake message length arithmetic overflow".to_string(),
                );
                return true;
            }
        };

        if msg_end > buf.len() {
            // Need more data from subsequent record in this packet
            return false;
        }

        let body = &buf[msg_body_start..msg_end];
        messages_parsed = messages_parsed.saturating_add(1);

        match msg_type {
            1 => {
                // ClientHello
                parse_client_hello(record_version, record_length, msg_length, body, ctx);
            }
            2 => {
                // ServerHello / HelloRetryRequest
                parse_server_hello(record_version, record_length, msg_length, body, ctx);
            }
            _ => {
                // Other handshake type: skip safely
            }
        }

        offset = msg_end;
    }

    true
}

fn parse_client_hello(
    record_version: TlsVersion,
    record_length: u16,
    msg_length: u32,
    body: &[u8],
    ctx: &mut TlsParserContext<'_>,
) {
    // ClientHello structure:
    // legacy_version (2 bytes)
    // random (32 bytes) -> NOT RETAINED
    // session_id_length (1 byte)
    // session_id (0..32 bytes) -> NOT RETAINED
    // cipher_suites_length (2 bytes)
    // cipher_suites (2..2^16-2 bytes)
    // compression_methods_length (1 byte)
    // compression_methods (1..2^8-1 bytes)
    // extensions_length (2 bytes) [optional]
    // extensions (0..2^16-1 bytes)
    if body.len() < 35 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Malformed,
            format!(
                "ClientHello body too short ({}) for minimum header (35 bytes)",
                body.len()
            ),
        );
        return;
    }

    let legacy_version = TlsVersion::from_wire(u16::from_be_bytes([body[0], body[1]]));
    // body[2..34] is random: NEVER RETAINED
    let session_id_len = body[34];
    if session_id_len > 32 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Malformed,
            format!("ClientHello session ID length ({session_id_len}) exceeds 32 bytes"),
        );
        return;
    }

    let mut cursor = match 35usize.checked_add(session_id_len as usize) {
        Some(c) => c,
        None => {
            ctx.is_partial = true;
            return;
        }
    };

    if body.len().saturating_sub(cursor) < 2 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Truncated,
            "ClientHello truncated before cipher suites length".to_string(),
        );
        return;
    }

    let cipher_suites_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor = cursor.saturating_add(2);

    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Malformed,
            format!("invalid ClientHello cipher suites length ({cipher_suites_len})"),
        );
        return;
    }

    if body.len().saturating_sub(cursor) < cipher_suites_len {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Truncated,
            "ClientHello truncated inside cipher suites list".to_string(),
        );
        return;
    }

    let cipher_suites_slice = &body[cursor..cursor + cipher_suites_len];
    cursor = cursor.saturating_add(cipher_suites_len);

    let num_ciphers = cipher_suites_len / 2;
    let mut cipher_suites =
        Vec::with_capacity(num_ciphers.min(ctx.limits.maximum_cipher_suites_per_client_hello));
    for chunk in cipher_suites_slice.chunks_exact(2) {
        if cipher_suites.len() < ctx.limits.maximum_cipher_suites_per_client_hello {
            cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        } else {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::ResourceLimit,
                format!(
                    "ClientHello cipher suites count exceeds limit of {}",
                    ctx.limits.maximum_cipher_suites_per_client_hello
                ),
            );
            break;
        }
    }

    if body.len().saturating_sub(cursor) < 1 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Truncated,
            "ClientHello truncated before compression methods length".to_string(),
        );
        return;
    }

    let compression_len = body[cursor] as usize;
    cursor = cursor.saturating_add(1);

    if compression_len == 0 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Malformed,
            "ClientHello compression methods length is zero".to_string(),
        );
        return;
    }

    if body.len().saturating_sub(cursor) < compression_len {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Truncated,
            "ClientHello truncated inside compression methods list".to_string(),
        );
        return;
    }

    let compression_methods = body[cursor..cursor + compression_len].to_vec();
    cursor = cursor.saturating_add(compression_len);

    let mut parsed_exts = ParsedClientHelloExtensions::default();

    if cursor < body.len() {
        if body.len().saturating_sub(cursor) < 2 {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Truncated,
                "ClientHello truncated before extensions length".to_string(),
            );
        } else {
            let extensions_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
            cursor = cursor.saturating_add(2);

            if body.len().saturating_sub(cursor) != extensions_len {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Malformed,
                    format!(
                        "ClientHello extensions length mismatch (declared {extensions_len}, available {})",
                        body.len().saturating_sub(cursor)
                    ),
                );
            } else {
                let ext_slice = &body[cursor..cursor + extensions_len];
                parse_client_hello_extensions(ext_slice, &mut parsed_exts, ctx);
            }
        }
    }

    let obs = TlsObservation {
        packet: ctx.packet_ref,
        timestamp: ctx.timestamp,
        source_ip: ctx.src_ip,
        source_port: ctx.src_port,
        destination_ip: ctx.dst_ip,
        destination_port: ctx.dst_port,
        record_version,
        handshake_kind: TlsHandshakeKind::ClientHello,
        client_hello: Some(TlsClientHelloMetadata {
            legacy_version,
            session_id_length: session_id_len,
            cipher_suites,
            compression_methods,
            server_name: parsed_exts.server_name,
            supported_versions: parsed_exts.supported_versions,
            supported_groups: parsed_exts.supported_groups,
            signature_algorithms: parsed_exts.signature_algorithms,
            alpn_protocols: parsed_exts.alpn_protocols,
            key_share_groups: parsed_exts.key_share_groups,
            has_pre_shared_key: parsed_exts.has_pre_shared_key,
            has_early_data: parsed_exts.has_early_data,
            extensions: parsed_exts.extensions,
        }),
        server_hello: None,
        declared_record_bytes: record_length,
        declared_handshake_bytes: msg_length,
        completeness: if ctx.is_partial {
            TlsObservationCompleteness::Partial
        } else {
            TlsObservationCompleteness::Complete
        },
    };

    ctx.observations.push(obs);
}

fn parse_client_hello_extensions(
    ext_slice: &[u8],
    parsed: &mut ParsedClientHelloExtensions,
    ctx: &mut TlsParserContext<'_>,
) {
    let mut offset = 0usize;
    let mut seen_types = Vec::new();

    while offset < ext_slice.len() {
        if parsed.extensions.len() >= ctx.limits.maximum_extensions_per_hello {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::ResourceLimit,
                format!(
                    "maximum extensions per hello limit ({}) reached",
                    ctx.limits.maximum_extensions_per_hello
                ),
            );
            break;
        }

        if ext_slice.len().saturating_sub(offset) < 4 {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Truncated,
                "ClientHello extensions truncated before 4-byte extension header".to_string(),
            );
            break;
        }

        let ext_type = u16::from_be_bytes([ext_slice[offset], ext_slice[offset + 1]]);
        let ext_len = u16::from_be_bytes([ext_slice[offset + 2], ext_slice[offset + 3]]);
        let ext_len_usize = ext_len as usize;
        offset = offset.saturating_add(4);

        if ext_slice.len().saturating_sub(offset) < ext_len_usize {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Truncated,
                format!(
                    "ClientHello extension 0x{ext_type:04x} truncated (declared {ext_len} bytes)"
                ),
            );
            break;
        }

        let ext_data = &ext_slice[offset..offset + ext_len_usize];
        offset = offset.saturating_add(ext_len_usize);

        if seen_types.contains(&ext_type) {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Malformed,
                format!("duplicate extension type 0x{ext_type:04x} in ClientHello"),
            );
        } else {
            seen_types.push(ext_type);
        }

        parsed.extensions.push(TlsExtensionMetadata {
            extension_type: ext_type,
            declared_length: ext_len,
        });

        match ext_type {
            0 => {
                // Server Name Indication (RFC 6066)
                if ext_data.len() < 2 {
                    ctx.is_partial = true;
                    ctx.emit_diagnostic(
                        TlsDiagnosticKind::Malformed,
                        "SNI extension too short for list length".to_string(),
                    );
                } else {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    if ext_data.len().saturating_sub(2) != list_len || list_len < 3 {
                        ctx.is_partial = true;
                        ctx.emit_diagnostic(
                            TlsDiagnosticKind::Malformed,
                            "SNI extension list length mismatch".to_string(),
                        );
                    } else {
                        let name_type = ext_data[2];
                        if name_type == 0 {
                            // host_name
                            if ext_data.len() < 5 {
                                ctx.is_partial = true;
                                ctx.emit_diagnostic(
                                    TlsDiagnosticKind::Malformed,
                                    "SNI host_name entry truncated".to_string(),
                                );
                            } else {
                                let name_len =
                                    u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                                if ext_data.len().saturating_sub(5) < name_len || name_len == 0 {
                                    ctx.is_partial = true;
                                    ctx.emit_diagnostic(
                                        TlsDiagnosticKind::Malformed,
                                        "invalid SNI host_name length".to_string(),
                                    );
                                } else if name_len > ctx.limits.maximum_server_name_bytes {
                                    ctx.is_partial = true;
                                    ctx.emit_diagnostic(
                                        TlsDiagnosticKind::ResourceLimit,
                                        format!(
                                            "SNI host_name ({name_len} bytes) exceeds limit of {}",
                                            ctx.limits.maximum_server_name_bytes
                                        ),
                                    );
                                } else {
                                    parsed.server_name = Some(TlsByteString::new(
                                        ext_data[5..5 + name_len].to_vec(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            43 => {
                // Supported Versions (RFC 9846 / RFC 8446)
                if ext_data.is_empty() {
                    ctx.is_partial = true;
                    ctx.emit_diagnostic(
                        TlsDiagnosticKind::Malformed,
                        "supported_versions extension empty".to_string(),
                    );
                } else {
                    let list_len = ext_data[0] as usize;
                    if ext_data.len().saturating_sub(1) != list_len
                        || list_len % 2 != 0
                        || list_len == 0
                    {
                        ctx.is_partial = true;
                        ctx.emit_diagnostic(
                            TlsDiagnosticKind::Malformed,
                            "supported_versions extension list length mismatch".to_string(),
                        );
                    } else {
                        for chunk in ext_data[1..1 + list_len].chunks_exact(2) {
                            if parsed.supported_versions.len()
                                < ctx.limits.maximum_supported_versions
                            {
                                let ver_code = u16::from_be_bytes([chunk[0], chunk[1]]);
                                parsed
                                    .supported_versions
                                    .push(TlsVersion::from_wire(ver_code));
                            } else {
                                ctx.is_partial = true;
                                ctx.emit_diagnostic(
                                    TlsDiagnosticKind::ResourceLimit,
                                    format!(
                                        "supported_versions count exceeds limit of {}",
                                        ctx.limits.maximum_supported_versions
                                    ),
                                );
                                break;
                            }
                        }
                    }
                }
            }
            10 => {
                // Supported Groups (RFC 8422 / RFC 9846)
                if ext_data.len() < 2 {
                    ctx.is_partial = true;
                } else {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    if ext_data.len().saturating_sub(2) != list_len || list_len % 2 != 0 {
                        ctx.is_partial = true;
                    } else {
                        for chunk in ext_data[2..2 + list_len].chunks_exact(2) {
                            if parsed.supported_groups.len() < ctx.limits.maximum_supported_groups {
                                parsed
                                    .supported_groups
                                    .push(u16::from_be_bytes([chunk[0], chunk[1]]));
                            } else {
                                ctx.is_partial = true;
                                break;
                            }
                        }
                    }
                }
            }
            13 => {
                // Signature Algorithms (RFC 5246 / RFC 9846)
                if ext_data.len() < 2 {
                    ctx.is_partial = true;
                } else {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    if ext_data.len().saturating_sub(2) != list_len || list_len % 2 != 0 {
                        ctx.is_partial = true;
                    } else {
                        for chunk in ext_data[2..2 + list_len].chunks_exact(2) {
                            if parsed.signature_algorithms.len()
                                < ctx.limits.maximum_signature_algorithms
                            {
                                parsed
                                    .signature_algorithms
                                    .push(u16::from_be_bytes([chunk[0], chunk[1]]));
                            } else {
                                ctx.is_partial = true;
                                break;
                            }
                        }
                    }
                }
            }
            16 => {
                // ALPN (RFC 7301)
                if ext_data.len() < 2 {
                    ctx.is_partial = true;
                } else {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    if ext_data.len().saturating_sub(2) != list_len {
                        ctx.is_partial = true;
                    } else {
                        let mut p_cursor = 2usize;
                        let mut total_alpn_bytes = 0usize;
                        while p_cursor < ext_data.len() {
                            let p_len = ext_data[p_cursor] as usize;
                            p_cursor = p_cursor.saturating_add(1);
                            if ext_data.len().saturating_sub(p_cursor) < p_len || p_len == 0 {
                                ctx.is_partial = true;
                                break;
                            }
                            if parsed.alpn_protocols.len() < ctx.limits.maximum_alpn_protocols
                                && total_alpn_bytes.saturating_add(p_len)
                                    <= ctx.limits.maximum_total_alpn_bytes
                            {
                                total_alpn_bytes = total_alpn_bytes.saturating_add(p_len);
                                parsed.alpn_protocols.push(TlsByteString::new(
                                    ext_data[p_cursor..p_cursor + p_len].to_vec(),
                                ));
                            } else {
                                ctx.is_partial = true;
                            }
                            p_cursor = p_cursor.saturating_add(p_len);
                        }
                    }
                }
            }
            51 => {
                // Key Share (RFC 9846)
                if ext_data.len() < 2 {
                    ctx.is_partial = true;
                } else {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    if ext_data.len().saturating_sub(2) != list_len {
                        ctx.is_partial = true;
                    } else {
                        let mut ks_cursor = 2usize;
                        while ks_cursor < ext_data.len() {
                            if ext_data.len().saturating_sub(ks_cursor) < 4 {
                                ctx.is_partial = true;
                                break;
                            }
                            let group =
                                u16::from_be_bytes([ext_data[ks_cursor], ext_data[ks_cursor + 1]]);
                            let key_len = u16::from_be_bytes([
                                ext_data[ks_cursor + 2],
                                ext_data[ks_cursor + 3],
                            ]) as usize;
                            ks_cursor = ks_cursor.saturating_add(4);
                            if ext_data.len().saturating_sub(ks_cursor) < key_len {
                                ctx.is_partial = true;
                                break;
                            }
                            // Retain group ID only, NEVER RETAIN KEY EXCHANGE BYTES!
                            if parsed.key_share_groups.len() < ctx.limits.maximum_key_share_entries
                            {
                                parsed.key_share_groups.push(group);
                            }
                            ks_cursor = ks_cursor.saturating_add(key_len);
                        }
                    }
                }
            }
            41 => {
                // Pre-Shared Key (RFC 9846) -> flag only, NEVER RETAIN IDENTITIES OR BINDERS
                parsed.has_pre_shared_key = true;
            }
            42 => {
                // Early Data (RFC 9846)
                parsed.has_early_data = true;
            }
            _ => {
                // Other extensions: safely skipped
            }
        }
    }
}

fn parse_server_hello(
    record_version: TlsVersion,
    record_length: u16,
    msg_length: u32,
    body: &[u8],
    ctx: &mut TlsParserContext<'_>,
) {
    // ServerHello structure:
    // legacy_version (2 bytes)
    // random (32 bytes) -> checked for HRR sentinel, NOT RETAINED
    // session_id_echo_length (1 byte)
    // session_id_echo (0..32 bytes) -> NOT RETAINED
    // cipher_suite (2 bytes)
    // compression_method (1 byte)
    // extensions_length (2 bytes) [optional]
    // extensions (0..2^16-1 bytes)
    if body.len() < 38 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Malformed,
            format!(
                "ServerHello body too short ({}) for minimum header (38 bytes)",
                body.len()
            ),
        );
        return;
    }

    let legacy_version = TlsVersion::from_wire(u16::from_be_bytes([body[0], body[1]]));
    let random_slice = &body[2..34];
    let is_hrr = random_slice == HRR_RANDOM_SENTINEL;
    let handshake_kind = if is_hrr {
        TlsHandshakeKind::HelloRetryRequest
    } else {
        TlsHandshakeKind::ServerHello
    };

    let session_id_echo_len = body[34];
    if session_id_echo_len > 32 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Malformed,
            format!("ServerHello session ID echo length ({session_id_echo_len}) exceeds 32 bytes"),
        );
        return;
    }

    let mut cursor = match 35usize.checked_add(session_id_echo_len as usize) {
        Some(c) => c,
        None => {
            ctx.is_partial = true;
            return;
        }
    };

    if body.len().saturating_sub(cursor) < 3 {
        ctx.is_partial = true;
        ctx.emit_diagnostic(
            TlsDiagnosticKind::Truncated,
            "ServerHello truncated before cipher suite and compression".to_string(),
        );
        return;
    }

    let cipher_suite = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
    let compression_method = body[cursor + 2];
    cursor = cursor.saturating_add(3);

    let mut parsed_exts = ParsedServerHelloExtensions::default();

    if cursor < body.len() {
        if body.len().saturating_sub(cursor) < 2 {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Truncated,
                "ServerHello truncated before extensions length".to_string(),
            );
        } else {
            let extensions_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
            cursor = cursor.saturating_add(2);

            if body.len().saturating_sub(cursor) != extensions_len {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Malformed,
                    format!(
                        "ServerHello extensions length mismatch (declared {extensions_len}, available {})",
                        body.len().saturating_sub(cursor)
                    ),
                );
            } else {
                let ext_slice = &body[cursor..cursor + extensions_len];
                parse_server_hello_extensions(is_hrr, ext_slice, &mut parsed_exts, ctx);
            }
        }
    }

    // Version determination for ServerHello
    let final_version = if let Some(v) = parsed_exts.selected_version {
        v
    } else {
        match legacy_version {
            TlsVersion::Tls12 => TlsVersion::Tls12,
            TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Ssl30 => {
                ctx.is_partial = true;
                ctx.emit_diagnostic(
                    TlsDiagnosticKind::Unsupported,
                    format!("{legacy_version} negotiation is outside Phase 9 supported subset (TLS 1.2 / TLS 1.3)"),
                );
                legacy_version
            }
            other => other,
        }
    };

    let obs = TlsObservation {
        packet: ctx.packet_ref,
        timestamp: ctx.timestamp,
        source_ip: ctx.src_ip,
        source_port: ctx.src_port,
        destination_ip: ctx.dst_ip,
        destination_port: ctx.dst_port,
        record_version,
        handshake_kind,
        client_hello: None,
        server_hello: Some(TlsServerHelloMetadata {
            legacy_version,
            session_id_echo_length: session_id_echo_len,
            cipher_suite,
            compression_method,
            selected_version: Some(final_version),
            selected_group: parsed_exts.selected_group,
            selected_alpn: parsed_exts.selected_alpn,
            has_pre_shared_key: parsed_exts.has_pre_shared_key,
            has_early_data: parsed_exts.has_early_data,
            extensions: parsed_exts.extensions,
        }),
        declared_record_bytes: record_length,
        declared_handshake_bytes: msg_length,
        completeness: if ctx.is_partial {
            TlsObservationCompleteness::Partial
        } else {
            TlsObservationCompleteness::Complete
        },
    };

    ctx.observations.push(obs);
}

fn parse_server_hello_extensions(
    is_hrr: bool,
    ext_slice: &[u8],
    parsed: &mut ParsedServerHelloExtensions,
    ctx: &mut TlsParserContext<'_>,
) {
    let mut offset = 0usize;
    let mut seen_types = Vec::new();

    while offset < ext_slice.len() {
        if parsed.extensions.len() >= ctx.limits.maximum_extensions_per_hello {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::ResourceLimit,
                format!(
                    "maximum extensions per hello limit ({}) reached",
                    ctx.limits.maximum_extensions_per_hello
                ),
            );
            break;
        }

        if ext_slice.len().saturating_sub(offset) < 4 {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Truncated,
                "ServerHello extensions truncated before 4-byte extension header".to_string(),
            );
            break;
        }

        let ext_type = u16::from_be_bytes([ext_slice[offset], ext_slice[offset + 1]]);
        let ext_len = u16::from_be_bytes([ext_slice[offset + 2], ext_slice[offset + 3]]);
        let ext_len_usize = ext_len as usize;
        offset = offset.saturating_add(4);

        if ext_slice.len().saturating_sub(offset) < ext_len_usize {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Truncated,
                format!(
                    "ServerHello extension 0x{ext_type:04x} truncated (declared {ext_len} bytes)"
                ),
            );
            break;
        }

        let ext_data = &ext_slice[offset..offset + ext_len_usize];
        offset = offset.saturating_add(ext_len_usize);

        if seen_types.contains(&ext_type) {
            ctx.is_partial = true;
            ctx.emit_diagnostic(
                TlsDiagnosticKind::Malformed,
                format!("duplicate extension type 0x{ext_type:04x} in ServerHello"),
            );
        } else {
            seen_types.push(ext_type);
        }

        parsed.extensions.push(TlsExtensionMetadata {
            extension_type: ext_type,
            declared_length: ext_len,
        });

        match ext_type {
            43 => {
                // Supported Versions (RFC 9846) in ServerHello contains a single selected u16 version
                if ext_data.len() != 2 {
                    ctx.is_partial = true;
                    ctx.emit_diagnostic(
                        TlsDiagnosticKind::Malformed,
                        format!(
                            "ServerHello supported_versions extension length is {} (expected 2)",
                            ext_data.len()
                        ),
                    );
                } else {
                    let ver_code = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                    parsed.selected_version = Some(TlsVersion::from_wire(ver_code));
                }
            }
            51 => {
                // Key Share (RFC 9846)
                if is_hrr {
                    // In HelloRetryRequest, key_share is just the selected named group (2 bytes)
                    if ext_data.len() != 2 {
                        ctx.is_partial = true;
                    } else {
                        parsed.selected_group =
                            Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                    }
                } else {
                    // In ServerHello, key_share is KeyShareEntry (group u16 + key_exchange vector)
                    if ext_data.len() < 4 {
                        ctx.is_partial = true;
                    } else {
                        let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                        let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                        if ext_data.len().saturating_sub(4) != key_len {
                            ctx.is_partial = true;
                        } else {
                            // Retain group ID only! NEVER RETAIN KEY EXCHANGE BYTES.
                            parsed.selected_group = Some(group);
                        }
                    }
                }
            }
            16 => {
                // ALPN in TLS 1.2 ServerHello
                if ext_data.len() < 3 {
                    ctx.is_partial = true;
                } else {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    if ext_data.len().saturating_sub(2) == list_len {
                        let proto_len = ext_data[2] as usize;
                        if ext_data.len().saturating_sub(3) == proto_len && proto_len > 0 {
                            parsed.selected_alpn =
                                Some(TlsByteString::new(ext_data[3..3 + proto_len].to_vec()));
                        }
                    }
                }
            }
            41 => {
                parsed.has_pre_shared_key = true;
            }
            42 => {
                parsed.has_early_data = true;
            }
            _ => {}
        }
    }
}
