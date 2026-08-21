//! Deterministic, fixed-column human-readable ASCII table reporter.

use pcapraven_domain::{
    DnsObservation, DnsQuestion, FlowRecord, FlowTemporalValue, HttpContentLengthState,
    HttpObservation, TlsObservation, TransportProtocol,
};
use std::io::Write;

use crate::dto::validation::{
    ValidationCompletionDto, ValidationMetadataDto, ValidationSummaryDto,
};
use crate::error::ReportError;

/// Truncates an already terminal-safe escaped string to a maximum display width.
#[must_use]
pub fn truncate_escaped(escaped: &str, max_width: usize) -> String {
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

/// Renders capture container validation summary as a human-readable table.
pub fn render_validation_table(
    metadata: &ValidationMetadataDto,
    summary: &ValidationSummaryDto,
    completion: &ValidationCompletionDto,
    w: &mut impl Write,
) -> Result<(), ReportError> {
    writeln!(w, "Capture")?;
    writeln!(w, "{:<14}{}", "Format", metadata.format)?;
    writeln!(w, "{:<14}{}", "Completion", completion.status)?;
    writeln!(w, "{:<14}{}", "Records", summary.records_emitted)?;
    writeln!(w, "{:<14}{}", "Diagnostics", summary.total_diagnostics)?;

    if let (Some(maj), Some(min)) = (metadata.version_major, metadata.version_minor) {
        writeln!(w, "{:<14}{}.{}", "Version", maj, min)?;
    }
    if let Some(linktype) = metadata.linktype {
        writeln!(w, "{:<14}{}", "Linktype", linktype)?;
    }
    if let Some(snaplen) = metadata.snaplen {
        writeln!(w, "{:<14}{}", "Snaplen", snaplen)?;
    }
    if let Some(ref res) = metadata.timestamp_resolution {
        writeln!(w, "{:<14}{}", "TimestampRes", res)?;
    }
    if let Some(sections) = &metadata.section_count {
        writeln!(w, "{:<14}{}", "Sections", sections)?;
    }
    if let (Some(total_ifaces), Some(usable), Some(unusable)) = (
        &metadata.interface_count,
        &metadata.usable_interfaces,
        &metadata.unusable_interfaces,
    ) {
        writeln!(
            w,
            "{:<14}{} (usable: {}, unusable: {})",
            "Interfaces", total_ifaces, usable, unusable
        )?;
    }

    Ok(())
}

/// Renders the network flows table header.
pub fn render_flows_table_header(w: &mut impl Write) -> Result<(), ReportError> {
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
    )?;
    Ok(())
}

/// Renders a single network flow record row.
pub fn render_flow_row(flow: &FlowRecord, w: &mut impl Write) -> Result<(), ReportError> {
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
    )?;
    Ok(())
}

/// Renders the complete network flows table.
pub fn render_flows_table(flows: &[FlowRecord], w: &mut impl Write) -> Result<(), ReportError> {
    render_flows_table_header(w)?;
    for flow in flows {
        render_flow_row(flow, w)?;
    }
    Ok(())
}

/// Renders the DNS table header.
pub fn render_dns_table_header(w: &mut impl Write) -> Result<(), ReportError> {
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
    )?;
    Ok(())
}

/// Renders a single DNS observation row.
pub fn render_dns_row(obs: &DnsObservation, w: &mut impl Write) -> Result<(), ReportError> {
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
        let type_str = DnsQuestion::qtype_name(first_q.qtype);
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
    )?;
    Ok(())
}

/// Renders the complete DNS table.
pub fn render_dns_table(
    observations: &[DnsObservation],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    render_dns_table_header(w)?;
    for obs in observations {
        render_dns_row(obs, w)?;
    }
    Ok(())
}

/// Renders the HTTP table header.
pub fn render_http_table_header(w: &mut impl Write) -> Result<(), ReportError> {
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
    )?;
    Ok(())
}

/// Renders a single HTTP observation row.
pub fn render_http_row(obs: &HttpObservation, w: &mut impl Write) -> Result<(), ReportError> {
    let src = format!("{}:{}", obs.source_ip, obs.source_port);
    let dst = format!("{}:{}", obs.destination_ip, obs.destination_port);
    let kind = obs.message_kind.as_str();
    let ver = obs.version.as_str();

    let method = match &obs.request {
        Some(req) => truncate_escaped(&req.method.display_escaped(), 8),
        None => "-".to_string(),
    };

    let target = match &obs.request {
        Some(req) => truncate_escaped(&req.target.display_escaped(), 24),
        None => "-".to_string(),
    };

    let status = match &obs.response {
        Some(resp) => format!("{}", resp.status_code),
        None => "-".to_string(),
    };

    let host = match &obs.headers.host {
        Some(h) => truncate_escaped(&h.display_escaped(), 20),
        None => "-".to_string(),
    };

    let content_type = match &obs.headers.content_type {
        Some(ct) => truncate_escaped(&ct.display_escaped(), 20),
        None => "-".to_string(),
    };

    let cl = match &obs.headers.content_length {
        HttpContentLengthState::Present(v) => format!("{v}"),
        HttpContentLengthState::Invalid => "invalid".to_string(),
        HttpContentLengthState::NotPresent => "-".to_string(),
    };

    let te = match &obs.headers.transfer_encoding {
        Some(t) => truncate_escaped(&t.display_escaped(), 10),
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
    )?;
    Ok(())
}

/// Renders the complete HTTP table.
pub fn render_http_table(
    observations: &[HttpObservation],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    render_http_table_header(w)?;
    for obs in observations {
        render_http_row(obs, w)?;
    }
    Ok(())
}

/// Renders the TLS table header.
pub fn render_tls_table_header(w: &mut impl Write) -> Result<(), ReportError> {
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
    )?;
    Ok(())
}

/// Renders a single TLS observation row.
pub fn render_tls_row(obs: &TlsObservation, w: &mut impl Write) -> Result<(), ReportError> {
    let src = format!("{}:{}", obs.source_ip, obs.source_port);
    let dst = format!("{}:{}", obs.destination_ip, obs.destination_port);
    let kind = obs.handshake_kind.as_str();
    let rec_ver = obs.record_version.as_str();

    let (tls_ver, cipher, sni, alpn, ciphers_count, exts_count) =
        if let Some(ref ch) = obs.client_hello {
            let sni_str = match &ch.server_name {
                Some(s) => truncate_escaped(&s.display_escaped(), 24),
                None => "-".to_string(),
            };
            let alpn_str = if ch.alpn_protocols.is_empty() {
                "-".to_string()
            } else if ch.alpn_protocols.len() == 1 {
                truncate_escaped(&ch.alpn_protocols[0].display_escaped(), 12)
            } else {
                let first = truncate_escaped(&ch.alpn_protocols[0].display_escaped(), 6);
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
                Some(a) => truncate_escaped(&a.display_escaped(), 12),
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
    )?;
    Ok(())
}

/// Renders the complete TLS table.
pub fn render_tls_table(
    observations: &[TlsObservation],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    render_tls_table_header(w)?;
    for obs in observations {
        render_tls_row(obs, w)?;
    }
    Ok(())
}

/// Renders analytical security findings as human-readable inspection cards.
pub fn render_findings_table(
    findings: &[&pcapraven_domain::FindingRecord],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    if findings.is_empty() {
        writeln!(w, "No findings matched the requested criteria.")?;
        return Ok(());
    }

    writeln!(w, "Findings ({})", findings.len())?;
    writeln!(w, "{}", "=".repeat(80))?;

    for (idx, finding) in findings.iter().enumerate() {
        if idx > 0 {
            writeln!(w, "{}", "-".repeat(80))?;
        }

        writeln!(
            w,
            "[{}] {} ({}, {})",
            finding.reference(),
            finding.title(),
            finding.severity(),
            finding.confidence()
        )?;
        writeln!(
            w,
            "  Detector:     {}@{}",
            finding.detector_id(),
            finding.detector_version()
        )?;
        writeln!(w, "  Summary:      {}", finding.summary())?;
        writeln!(w, "  Rationale:    {}", finding.rationale())?;

        // Subject
        let mut subject_parts = Vec::new();
        let flows = finding.subject().flow_references();
        if !flows.is_empty() {
            let flow_strs: Vec<String> = flows.iter().map(|f| f.to_string()).collect();
            subject_parts.push(format!("flows=[{}]", flow_strs.join(", ")));
        }
        let pkts = finding.subject().packet_references();
        if !pkts.is_empty() {
            let pkt_strs: Vec<String> = pkts
                .iter()
                .map(|p| format!("pkt:{}", p.capture_record_ordinal()))
                .collect();
            subject_parts.push(format!("packets=[{}]", pkt_strs.join(", ")));
        }
        let obss = finding.subject().observation_references();
        if !obss.is_empty() {
            let obs_strs: Vec<String> = obss.iter().map(|o| o.to_string()).collect();
            subject_parts.push(format!("observations=[{}]", obs_strs.join(", ")));
        }
        writeln!(w, "  Subject:      {}", subject_parts.join("; "))?;

        // Evidence References
        let evi_strs: Vec<String> = finding
            .evidence_references()
            .iter()
            .map(|e| e.to_string())
            .collect();
        writeln!(w, "  Evidence:     {}", evi_strs.join(", "))?;

        // Source Finding References (for correlated findings)
        if !finding.source_finding_references().is_empty() {
            let src_strs: Vec<String> = finding
                .source_finding_references()
                .iter()
                .map(|s| s.to_string())
                .collect();
            writeln!(w, "  Sources:      {}", src_strs.join(", "))?;
        }

        // MITRE ATT&CK Mappings
        if !finding.mitre_mappings().is_empty() {
            writeln!(w, "  MITRE ATT&CK:")?;
            for m in finding.mitre_mappings() {
                writeln!(
                    w,
                    "    - {} ({}) [{} ({})] via {}",
                    m.technique_id(),
                    m.technique_name(),
                    m.tactic().tactic_id(),
                    m.tactic(),
                    m.provenance()
                )?;
                writeln!(w, "      Rationale: {}", m.rationale())?;
            }
        }
    }

    Ok(())
}

/// Renders a unified multi-layer analysis table report.
pub fn render_analysis_table(
    metadata: &ValidationMetadataDto,
    summary: &crate::dto::analysis::AnalysisSummaryDto,
    completion: &crate::dto::analysis::ReportCompletionDto,
    flows: &[FlowRecord],
    findings: &[&pcapraven_domain::FindingRecord],
    w: &mut impl Write,
) -> Result<(), ReportError> {
    writeln!(w, "=== PCAPRAVEN ANALYSIS REPORT ===")?;
    writeln!(w)?;
    writeln!(w, "Capture Summary:")?;
    writeln!(w, "  Format:             {}", metadata.format)?;
    writeln!(w, "  Completion:         {}", completion.status)?;
    if !completion.limitations.is_empty() {
        writeln!(
            w,
            "  Limitations:        {}",
            completion.limitations.join(", ")
        )?;
    }
    writeln!(w, "  Total Packets:      {}", summary.total_packets)?;
    writeln!(w, "  Total Flows:        {}", summary.total_flows)?;
    writeln!(
        w,
        "  DNS Observations:   {}",
        summary.total_dns_observations
    )?;
    writeln!(
        w,
        "  HTTP Observations:  {}",
        summary.total_http_observations
    )?;
    writeln!(
        w,
        "  TLS Observations:   {}",
        summary.total_tls_observations
    )?;
    writeln!(w, "  Total Findings:     {}", summary.total_findings)?;
    writeln!(w)?;

    if !flows.is_empty() {
        writeln!(w, "Reconstructed Flows ({}):", flows.len())?;
        writeln!(w, "{}", "-".repeat(80))?;
        render_flows_table(flows, w)?;
        writeln!(w)?;
    }

    writeln!(w, "Analytical Findings ({}):", findings.len())?;
    writeln!(w, "{}", "-".repeat(80))?;
    render_findings_table(findings, w)?;

    Ok(())
}
