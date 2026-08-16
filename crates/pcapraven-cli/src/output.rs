//! Factual human inspection output rendering for stdout.

use pcapraven_domain::{FlowRecord, FlowTemporalValue, TransportProtocol};
use pcapraven_pcap::{
    ByteOrder, CaptureCompletion, CaptureFormat, CaptureReadOutcome, CaptureTimestampResolution,
};
use std::io::{self, Write};

/// Renders the capture validation summary to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_validate_summary(
    outcome: &CaptureReadOutcome,
    records_emitted: u64,
    w: &mut impl Write,
) -> io::Result<()> {
    writeln!(w, "Capture")?;

    let format_str = match outcome.metadata.format {
        CaptureFormat::LegacyPcap => {
            if let Some(ref legacy) = outcome.metadata.legacy {
                match legacy.byte_order {
                    ByteOrder::Little => "PCAP (little-endian)",
                    ByteOrder::Big => "PCAP (big-endian)",
                }
            } else {
                "PCAP"
            }
        }
        CaptureFormat::PcapNg => {
            if let Some(first_sec) = outcome.metadata.sections.first() {
                match first_sec.byte_order {
                    ByteOrder::Little => "PCAPNG (little-endian)",
                    ByteOrder::Big => "PCAPNG (big-endian)",
                }
            } else {
                "PCAPNG"
            }
        }
        CaptureFormat::Unknown => "Unknown",
    };
    writeln!(w, "{:<14}{}", "Format", format_str)?;

    let completion_str = match outcome.completion {
        CaptureCompletion::Complete => "complete",
        CaptureCompletion::Partial { .. } => "partial",
        CaptureCompletion::FailedBeforeUsefulRecords { .. } => "failed",
    };
    writeln!(w, "{:<14}{}", "Completion", completion_str)?;
    writeln!(w, "{:<14}{}", "Records", records_emitted)?;
    writeln!(w, "{:<14}{}", "Diagnostics", outcome.diagnostics.len())?;

    if let Some(ref legacy) = outcome.metadata.legacy {
        writeln!(
            w,
            "{:<14}{}.{}",
            "Version", legacy.version_major, legacy.version_minor
        )?;
        writeln!(w, "{:<14}{}", "Linktype", legacy.linktype)?;
        writeln!(w, "{:<14}{}", "Snaplen", legacy.snaplen)?;
        let res_str = format_resolution(legacy.timestamp_resolution);
        writeln!(w, "{:<14}{}", "TimestampRes", res_str)?;
    } else if !outcome.metadata.sections.is_empty() {
        writeln!(w, "{:<14}{}", "Sections", outcome.metadata.sections.len())?;
        let mut total_interfaces = 0usize;
        let mut usable_interfaces = 0usize;
        let mut unusable_interfaces = 0usize;
        for sec in &outcome.metadata.sections {
            total_interfaces = total_interfaces.saturating_add(sec.interfaces.len());
            for iface in &sec.interfaces {
                if iface.is_valid() {
                    usable_interfaces = usable_interfaces.saturating_add(1);
                } else {
                    unusable_interfaces = unusable_interfaces.saturating_add(1);
                }
            }
        }
        writeln!(
            w,
            "{:<14}{} (usable: {}, unusable: {})",
            "Interfaces", total_interfaces, usable_interfaces, unusable_interfaces
        )?;
    }

    Ok(())
}

fn format_resolution(res: CaptureTimestampResolution) -> String {
    match res {
        CaptureTimestampResolution::Decimal {
            exponent,
            units_per_second,
        } => {
            format!("10^{exponent} units/s ({units_per_second} Hz)")
        }
        CaptureTimestampResolution::Binary {
            exponent,
            units_per_second,
        } => {
            format!("2^{exponent} units/s ({units_per_second} Hz)")
        }
    }
}

/// Renders the flow table column header to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_flow_table_header(w: &mut impl Write) -> io::Result<()> {
    writeln!(
        w,
        "{:<6} {:<5} {:<21} {:<21} {:>6} {:>6} {:>6} {:>6} {:>10} {:>10} {:<10} {:<16}",
        "ID",
        "PROTO",
        "ENDPOINT_A",
        "ENDPOINT_B",
        "PKTS",
        "A>B",
        "B>A",
        "SELF",
        "CAP_BYTES",
        "WIRE_BYTES",
        "DURATION",
        "END"
    )
}

/// Renders a single factual flow record row to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_flow_row(flow: &FlowRecord, w: &mut impl Write) -> io::Result<()> {
    let proto = match flow.key.protocol() {
        TransportProtocol::Tcp => "TCP",
        TransportProtocol::Udp => "UDP",
    };
    let ep_a = format!("{}", flow.key.endpoint_a());
    let ep_b = format!("{}", flow.key.endpoint_b());
    let duration_str = match &flow.temporal.duration {
        FlowTemporalValue::Available(d) => format!("{d}"),
        FlowTemporalValue::Unavailable(reason) => format!("N/A({reason})"),
    };

    writeln!(
        w,
        "{:<6} {:<5} {:<21} {:<21} {:>6} {:>6} {:>6} {:>6} {:>10} {:>10} {:<10} {:<16}",
        flow.reference.ordinal(),
        proto,
        ep_a,
        ep_b,
        flow.traffic.total.packet_count,
        flow.traffic.a_to_b.packet_count,
        flow.traffic.b_to_a.packet_count,
        flow.traffic.same_endpoint.packet_count,
        flow.traffic.total.captured_bytes,
        flow.traffic.total.wire_bytes,
        duration_str,
        flow.end_reason.as_str(),
    )
}

/// Renders the DNS inspection table column header to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_dns_table_header(w: &mut impl Write) -> io::Result<()> {
    writeln!(
        w,
        "{:<6} {:<5} {:<21} {:<21} {:>5} {:<8} {:>6} {:>5} {:>3} {:>3} {:>3} {:>3} {:<30} {:<6} {:<4}",
        "PKT",
        "XPORT",
        "SRC",
        "DST",
        "ID",
        "KIND",
        "OPCODE",
        "RCODE",
        "QD",
        "AN",
        "NS",
        "AR",
        "QNAME",
        "QTYPE",
        "EDNS"
    )
}

/// Renders a single factual DNS observation row to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_dns_row(
    obs: &pcapraven_domain::DnsObservation,
    w: &mut impl Write,
) -> io::Result<()> {
    let src = format!("{}:{}", obs.source_ip, obs.source_port);
    let dst = format!("{}:{}", obs.destination_ip, obs.destination_port);
    let kind = obs.message_kind.as_str();

    let (qname, qtype) = if let Some(first_q) = obs.questions.first() {
        let name_str = if obs.questions.len() > 1 {
            format!(
                "{}(+{})",
                first_q.name.display_escaped(),
                obs.questions.len().saturating_sub(1)
            )
        } else {
            first_q.name.display_escaped()
        };
        let type_str = pcapraven_domain::DnsQuestion::qtype_name(first_q.qtype);
        (name_str, type_str)
    } else {
        ("-".to_string(), "-")
    };

    let edns_str = if obs.edns.is_some() { "yes" } else { "no" };

    writeln!(
        w,
        "{:<6} {:<5} {:<21} {:<21} {:>5} {:<8} {:>6} {:>5} {:>3} {:>3} {:>3} {:>3} {:<30} {:<6} {:<4}",
        obs.packet.capture_record_ordinal,
        obs.transport.as_str(),
        src,
        dst,
        obs.transaction_id,
        kind,
        obs.opcode,
        obs.effective_response_code,
        obs.declared_qdcount,
        obs.declared_ancount,
        obs.declared_nscount,
        obs.declared_arcount,
        qname,
        qtype,
        edns_str,
    )
}

/// Renders the HTTP inspection table column header to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_http_table_header(w: &mut impl Write) -> io::Result<()> {
    writeln!(
        w,
        "{:<6} {:<8} {:<21} {:<21} {:<8} {:<8} {:>6} {:<24} {:<20} {:<20} {:>10} {:<10}",
        "PKT",
        "KIND",
        "SRC",
        "DST",
        "VER",
        "METHOD",
        "STATUS",
        "TARGET",
        "HOST",
        "CONTENT-TYPE",
        "CL",
        "TE"
    )
}

/// Renders a single factual HTTP observation row to the provided writer.
///
/// Truncates an already terminal-safe escaped string to a maximum display width,
/// ensuring we never slice in the middle of a `\xHH` or `\\` escape sequence.
#[must_use]
pub fn truncate_escaped_presentation(escaped: &str, max_width: usize) -> String {
    if escaped.len() <= max_width {
        return escaped.to_string();
    }
    if max_width <= 3 {
        return "...".chars().take(max_width).collect();
    }

    let budget = max_width.saturating_sub(3);
    let bytes = escaped.as_bytes();
    let mut i = 0usize;
    let mut last_safe = 0usize;

    while i < bytes.len() {
        let token_len = if bytes[i] == b'\\' {
            if i + 3 < bytes.len() && bytes[i + 1] == b'x' {
                4
            } else if i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                2
            } else {
                1
            }
        } else {
            1
        };

        if i.saturating_add(token_len) <= budget {
            i = i.saturating_add(token_len);
            last_safe = i;
        } else {
            break;
        }
    }

    let mut res = escaped[..last_safe].to_string();
    res.push_str("...");
    res
}

/// Renders a single factual HTTP observation row to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_http_row(
    obs: &pcapraven_domain::HttpObservation,
    w: &mut impl Write,
) -> io::Result<()> {
    let src = format!("{}:{}", obs.source_ip, obs.source_port);
    let dst = format!("{}:{}", obs.destination_ip, obs.destination_port);
    let kind = obs.message_kind.as_str();
    let ver = obs.version.as_str();

    let method = match &obs.request {
        Some(req) => truncate_escaped_presentation(&req.method.display_escaped(), 8),
        None => "-".to_string(),
    };

    let target = match &obs.request {
        Some(req) => truncate_escaped_presentation(&req.target.display_escaped(), 24),
        None => "-".to_string(),
    };

    let status = match &obs.response {
        Some(resp) => format!("{}", resp.status_code),
        None => "-".to_string(),
    };

    let host = match &obs.headers.host {
        Some(h) => truncate_escaped_presentation(&h.display_escaped(), 20),
        None => "-".to_string(),
    };

    let content_type = match &obs.headers.content_type {
        Some(ct) => truncate_escaped_presentation(&ct.display_escaped(), 20),
        None => "-".to_string(),
    };

    let cl = match &obs.headers.content_length {
        pcapraven_domain::HttpContentLengthState::Present(v) => format!("{v}"),
        pcapraven_domain::HttpContentLengthState::Invalid => "invalid".to_string(),
        pcapraven_domain::HttpContentLengthState::NotPresent => "-".to_string(),
    };

    let te = match &obs.headers.transfer_encoding {
        Some(t) => truncate_escaped_presentation(&t.display_escaped(), 10),
        None => "-".to_string(),
    };

    writeln!(
        w,
        "{:<6} {:<8} {:<21} {:<21} {:<8} {:<8} {:>6} {:<24} {:<20} {:<20} {:>10} {:<10}",
        obs.packet.capture_record_ordinal,
        kind,
        src,
        dst,
        ver,
        method,
        status,
        target,
        host,
        content_type,
        cl,
        te,
    )
}

/// Renders the TLS inspection table column header to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_tls_table_header(w: &mut impl Write) -> io::Result<()> {
    writeln!(
        w,
        "{:<6} {:<17} {:<21} {:<21} {:<8} {:<8} {:<8} {:<24} {:<12} {:>7} {:>4}",
        "PKT",
        "KIND",
        "SRC",
        "DST",
        "REC_VER",
        "TLS_VER",
        "CIPHER",
        "SNI",
        "ALPN",
        "CIPHERS",
        "EXTS"
    )
}

/// Renders a single factual TLS observation row to the provided writer.
///
/// # Errors
/// Returns an [`io::Error`] if writing to `w` fails.
pub fn render_tls_row(
    obs: &pcapraven_domain::TlsObservation,
    w: &mut impl Write,
) -> io::Result<()> {
    let src = format!("{}:{}", obs.source_ip, obs.source_port);
    let dst = format!("{}:{}", obs.destination_ip, obs.destination_port);
    let kind = obs.handshake_kind.as_str();
    let rec_ver = obs.record_version.as_str();

    let (tls_ver, cipher, sni, alpn, ciphers_count, exts_count) = if let Some(ref ch) =
        obs.client_hello
    {
        let sni_str = match &ch.server_name {
            Some(s) => truncate_escaped_presentation(&s.display_escaped(), 24),
            None => "-".to_string(),
        };
        let alpn_str = if ch.alpn_protocols.is_empty() {
            "-".to_string()
        } else if ch.alpn_protocols.len() == 1 {
            truncate_escaped_presentation(&ch.alpn_protocols[0].display_escaped(), 12)
        } else {
            let first = truncate_escaped_presentation(&ch.alpn_protocols[0].display_escaped(), 6);
            format!("{}(+{})", first, ch.alpn_protocols.len().saturating_sub(1))
        };
        (
            "-".to_string(),
            "-".to_string(),
            sni_str,
            alpn_str,
            format!("{}", ch.cipher_suites.len()),
            format!("{}", ch.extensions.len()),
        )
    } else if let Some(ref sh) = obs.server_hello {
        let ver_str = sh
            .selected_version
            .map(|v| v.as_str().to_string())
            .unwrap_or_else(|| "-".to_string());
        let cipher_str = format!("0x{:04x}", sh.cipher_suite);
        let alpn_str = match &sh.selected_alpn {
            Some(a) => truncate_escaped_presentation(&a.display_escaped(), 12),
            None => "-".to_string(),
        };
        (
            ver_str,
            cipher_str,
            "-".to_string(),
            alpn_str,
            "-".to_string(),
            format!("{}", sh.extensions.len()),
        )
    } else {
        (
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        )
    };

    writeln!(
        w,
        "{:<6} {:<17} {:<21} {:<21} {:<8} {:<8} {:<8} {:<24} {:<12} {:>7} {:>4}",
        obs.packet.capture_record_ordinal,
        kind,
        src,
        dst,
        rec_ver,
        tls_ver,
        cipher,
        sni,
        alpn,
        ciphers_count,
        exts_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcapraven_domain::{
        FlowDuration, FlowEndReason, FlowEndpoint, FlowInterArrivalMetrics, FlowKey, FlowRecord,
        FlowReference, FlowTemporalMetrics, FlowTemporalUnavailableReason, FlowTemporalValue,
        FlowTimestampCoverage, FlowTrafficCounters, FlowTrafficStatistics, IpAddress,
        PacketReference, PacketTimestamp, TransportProtocol,
    };
    use pcapraven_pcap::{CaptureCompletion, CaptureFormat, CaptureMetadata, CaptureReadOutcome};
    use std::io::{self, Write};

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
        }
    }

    #[test]
    fn test_render_validate_summary_propagates_writer_error() {
        let outcome = CaptureReadOutcome {
            metadata: CaptureMetadata {
                format: CaptureFormat::Unknown,
                legacy: None,
                sections: Vec::new(),
            },
            records: Vec::new(),
            diagnostics: Vec::new(),
            completion: CaptureCompletion::Complete,
        };
        let mut writer = FailingWriter;
        assert!(render_validate_summary(&outcome, 0, &mut writer).is_err());
    }

    #[test]
    fn test_render_flow_table_header_propagates_writer_error() {
        let mut writer = FailingWriter;
        assert!(render_flow_table_header(&mut writer).is_err());
    }

    #[test]
    fn test_render_flow_row_propagates_writer_error() {
        let key = FlowKey::new(
            TransportProtocol::Udp,
            FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 1]), 1000),
            FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 2]), 2000),
        );
        let counters = FlowTrafficCounters::default();
        let pkt_ref = PacketReference::new(0, None, None, 64, 64, false);
        let unavail =
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
        let inter_arrival =
            FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
        let flow = FlowRecord {
            key,
            reference: FlowReference::new(0),
            first_packet: pkt_ref,
            last_packet: pkt_ref,
            traffic: FlowTrafficStatistics {
                total: counters,
                a_to_b: counters,
                b_to_a: counters,
                same_endpoint: counters,
            },
            temporal: FlowTemporalMetrics {
                first_packet_timestamp: PacketTimestamp::Unavailable,
                last_packet_timestamp: PacketTimestamp::Unavailable,
                duration: FlowTemporalValue::Available(FlowDuration::from_fraction(0, 1).unwrap()),
                coverage: FlowTimestampCoverage::default(),
                overall_inter_arrival: inter_arrival.clone(),
                a_to_b_inter_arrival: inter_arrival.clone(),
                b_to_a_inter_arrival: inter_arrival.clone(),
                same_endpoint_inter_arrival: inter_arrival,
            },
            end_reason: FlowEndReason::EndOfInput,
        };
        let mut writer = FailingWriter;
        assert!(render_flow_row(&flow, &mut writer).is_err());
    }

    #[test]
    fn test_render_dns_table_header_propagates_writer_error() {
        let mut writer = FailingWriter;
        assert!(render_dns_table_header(&mut writer).is_err());
    }

    #[test]
    fn test_render_dns_row_propagates_writer_error() {
        use pcapraven_domain::{
            DnsFlags, DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness,
            DnsQuestion, DnsTransport,
        };

        let obs = DnsObservation {
            packet: PacketReference::new(0, None, None, 64, 64, false),
            timestamp: PacketTimestamp::Unavailable,
            transport: DnsTransport::Udp,
            source_ip: IpAddress::Ipv4([10, 0, 0, 1]),
            source_port: 53535,
            destination_ip: IpAddress::Ipv4([8, 8, 8, 8]),
            destination_port: 53,
            transaction_id: 0x1234,
            message_kind: DnsMessageKind::Query,
            opcode: 0,
            response_code: 0,
            effective_response_code: 0,
            flags: DnsFlags::default(),
            declared_qdcount: 1,
            declared_ancount: 0,
            declared_nscount: 0,
            declared_arcount: 0,
            questions: vec![DnsQuestion::new(DnsName::root(), 1, 1)],
            records: Vec::new(),
            edns: None,
            completeness: DnsObservationCompleteness::Complete,
        };

        let mut writer = FailingWriter;
        assert!(render_dns_row(&obs, &mut writer).is_err());
    }

    #[test]
    fn test_render_http_table_header_propagates_writer_error() {
        let mut writer = FailingWriter;
        assert!(render_http_table_header(&mut writer).is_err());
    }

    #[test]
    fn test_render_http_row_propagates_writer_error() {
        use pcapraven_domain::{
            HttpByteString, HttpContentLengthState, HttpFramingMetadata, HttpMessageKind,
            HttpObservation, HttpObservationCompleteness, HttpRequestMetadata, HttpSelectedHeaders,
            HttpVersion,
        };

        let obs = HttpObservation {
            packet: PacketReference::new(0, None, None, 64, 64, false),
            timestamp: PacketTimestamp::Unavailable,
            source_ip: IpAddress::Ipv4([192, 168, 1, 100]),
            source_port: 54321,
            destination_ip: IpAddress::Ipv4([93, 184, 216, 34]),
            destination_port: 80,
            version: HttpVersion::Http11,
            message_kind: HttpMessageKind::Request,
            request: Some(HttpRequestMetadata {
                method: HttpByteString::new(b"GET".to_vec()),
                target: HttpByteString::new(b"/index.html".to_vec()),
            }),
            response: None,
            headers: HttpSelectedHeaders {
                host: Some(HttpByteString::new(b"example.com".to_vec())),
                content_length: HttpContentLengthState::NotPresent,
                ..Default::default()
            },
            framing: HttpFramingMetadata::default(),
            declared_field_count: 1,
            header_section_bytes: 50,
            completeness: HttpObservationCompleteness::Complete,
        };

        let mut writer = FailingWriter;
        assert!(render_http_row(&obs, &mut writer).is_err());
    }

    #[test]
    fn test_truncate_escaped_presentation() {
        assert_eq!(truncate_escaped_presentation("hello", 10), "hello");
        assert_eq!(truncate_escaped_presentation("hello world", 8), "hello...");
        assert_eq!(
            truncate_escaped_presentation("hello\\x00world", 10),
            "hello..."
        );
        assert_eq!(
            truncate_escaped_presentation("hello\\\\world", 9),
            "hello..."
        );
        assert_eq!(truncate_escaped_presentation("abc", 2), "..");
    }
}
