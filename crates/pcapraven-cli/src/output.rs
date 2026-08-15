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
