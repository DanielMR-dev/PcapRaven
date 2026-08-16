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
        Some(req) => req.method.display_escaped(),
        None => "-".to_string(),
    };

    let target = match &obs.request {
        Some(req) => req.target.display_escaped(),
        None => "-".to_string(),
    };

    let status = match &obs.response {
        Some(resp) => format!("{}", resp.status_code),
        None => "-".to_string(),
    };

    let host = match &obs.headers.host {
        Some(h) => h.display_escaped(),
        None => "-".to_string(),
    };

    let content_type = match &obs.headers.content_type {
        Some(ct) => ct.display_escaped(),
        None => "-".to_string(),
    };

    let cl = match &obs.headers.content_length {
        pcapraven_domain::HttpContentLengthState::Present(v) => format!("{v}"),
        pcapraven_domain::HttpContentLengthState::Invalid => "invalid".to_string(),
        pcapraven_domain::HttpContentLengthState::NotPresent => "-".to_string(),
    };

    let te = match &obs.headers.transfer_encoding {
        Some(t) => t.display_escaped(),
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
}
