//! CLI application orchestration for validation and flow inspection.

use crate::args::{CliArgs, DnsArgs, FlowsArgs, HttpArgs, Subcommand, ValidateArgs};
use crate::diagnostics::{DEFAULT_DIAGNOSTIC_BUDGET, DiagnosticEmitter};
use crate::output;
use pcapraven_domain::{FlowRecord, FlowTemporalUnavailableReason};
use pcapraven_flows::{FlowDisposition, FlowReconstructionConfig, FlowReconstructor};
use pcapraven_pcap::{CaptureCompletion, CaptureReader, ReaderLimits};
use pcapraven_protocols::{
    DnsLimits, DnsPacketDisposition, HttpLimits, HttpPacketDisposition, NormalizationLimits,
    normalize_packet, parse_dns_packet, parse_http_packet,
};
use std::fs::File;
use std::io;
use std::process::ExitCode;

/// Evaluates whether a completed [`FlowRecord`] suffered any temporal metric limitation
/// beyond normal single-sample initialization.
fn has_temporal_degradation(flow: &FlowRecord) -> bool {
    let is_degraded = |reason: Option<FlowTemporalUnavailableReason>| -> bool {
        match reason {
            Some(FlowTemporalUnavailableReason::InsufficientSamples) | None => false,
            Some(_) => true,
        }
    };

    is_degraded(flow.temporal.duration.unavailable_reason())
        || is_degraded(
            flow.temporal
                .overall_inter_arrival
                .minimum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .overall_inter_arrival
                .maximum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .overall_inter_arrival
                .mean_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .overall_inter_arrival
                .mean_absolute_successive_interval_delta
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .a_to_b_inter_arrival
                .minimum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .a_to_b_inter_arrival
                .maximum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .a_to_b_inter_arrival
                .mean_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .a_to_b_inter_arrival
                .mean_absolute_successive_interval_delta
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .b_to_a_inter_arrival
                .minimum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .b_to_a_inter_arrival
                .maximum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .b_to_a_inter_arrival
                .mean_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .b_to_a_inter_arrival
                .mean_absolute_successive_interval_delta
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .same_endpoint_inter_arrival
                .minimum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .same_endpoint_inter_arrival
                .maximum_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .same_endpoint_inter_arrival
                .mean_interval
                .unavailable_reason(),
        )
        || is_degraded(
            flow.temporal
                .same_endpoint_inter_arrival
                .mean_absolute_successive_interval_delta
                .unavailable_reason(),
        )
}

/// Main application dispatcher converting [`CliArgs`] into a process [`ExitCode`].
#[must_use]
pub fn run(args: CliArgs) -> ExitCode {
    let status_code = match args.command {
        Subcommand::Validate(v_args) => run_validate(v_args, args.quiet),
        Subcommand::Flows(f_args) => run_flows(f_args, args.quiet),
        Subcommand::Dns(d_args) => run_dns(d_args, args.quiet),
        Subcommand::Http(h_args) => run_http(h_args, args.quiet),
    };
    ExitCode::from(status_code)
}

fn run_validate(args: ValidateArgs, quiet: bool) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let limits = if let Some(max_rec) = args.max_records {
        let max_usize = match usize::try_from(max_rec) {
            Ok(v) => v,
            Err(_) => {
                let _ = DiagnosticEmitter::emit_fatal_error(
                    "max-records value exceeds memory addressable bounds",
                );
                return 2;
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!("invalid reader limits: {e}"));
                return 2;
            }
        }
    } else {
        ReaderLimits::default()
    };

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            let _ =
                DiagnosticEmitter::emit_fatal_error(&format!("failed to open capture file: {e}"));
            return 1;
        }
    };

    let mut reader = match CaptureReader::new(file, limits) {
        Ok(r) => r,
        Err(e) => {
            let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                "failed to initialize capture reader: {e}"
            ));
            return 1;
        }
    };

    let mut records_emitted = 0u64;
    let mut had_stream_error = false;

    loop {
        match reader.next_record() {
            Ok(Some(_)) => {
                records_emitted = records_emitted.saturating_add(1);
            }
            Ok(None) => break,
            Err(e) => {
                had_stream_error = true;
                let _ = diag_emitter.emit_diagnostic(&format!("capture reader error: {e}"));
                break;
            }
        }
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        let _ = diag_emitter.emit_capture_diagnostic(diag);
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    match outcome.completion {
        CaptureCompletion::FailedBeforeUsefulRecords { ref terminal_error } => {
            let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                "capture validation failed before useful records: {terminal_error}"
            ));
            1
        }
        CaptureCompletion::Complete if !had_stream_error => {
            let mut stdout = io::stdout().lock();
            if let Err(e) = output::render_validate_summary(&outcome, records_emitted, &mut stdout)
            {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                    "failed to write validation output: {e}"
                ));
                return 1;
            }
            0
        }
        _ => {
            let mut stdout = io::stdout().lock();
            if let Err(e) = output::render_validate_summary(&outcome, records_emitted, &mut stdout)
            {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                    "failed to write validation output: {e}"
                ));
                return 1;
            }
            3
        }
    }
}

fn run_flows(args: FlowsArgs, quiet: bool) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let reader_limits = if let Some(max_rec) = args.max_records {
        let max_usize = match usize::try_from(max_rec) {
            Ok(v) => v,
            Err(_) => {
                let _ = DiagnosticEmitter::emit_fatal_error(
                    "max-records value exceeds memory addressable bounds",
                );
                return 2;
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!("invalid reader limits: {e}"));
                return 2;
            }
        }
    } else {
        ReaderLimits::default()
    };

    let mut flow_builder = FlowReconstructionConfig::builder();
    if let Some(mf) = args.max_flows {
        flow_builder = flow_builder.maximum_tracked_flows(mf);
    }
    if let Some(mfi) = args.max_flow_instances {
        flow_builder = flow_builder.maximum_flow_instances(mfi);
    }
    if let Some(tcp_to) = args.tcp_idle_timeout {
        flow_builder = flow_builder.tcp_idle_timeout_seconds(tcp_to);
    }
    if let Some(udp_to) = args.udp_idle_timeout {
        flow_builder = flow_builder.udp_idle_timeout_seconds(udp_to);
    }

    let flow_config = match flow_builder.build() {
        Ok(c) => c,
        Err(e) => {
            let _ =
                DiagnosticEmitter::emit_fatal_error(&format!("invalid flow configuration: {e}"));
            return 2;
        }
    };

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            let _ =
                DiagnosticEmitter::emit_fatal_error(&format!("failed to open capture file: {e}"));
            return 1;
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                "failed to initialize capture reader: {e}"
            ));
            return 1;
        }
    };

    let mut reconstructor = match FlowReconstructor::new(flow_config) {
        Ok(r) => r,
        Err(e) => {
            let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                "failed to initialize flow reconstructor: {e}"
            ));
            return 1;
        }
    };

    let mut stdout = io::stdout().lock();
    let mut table_header_rendered = false;
    let mut useful_result_produced = false;
    let mut had_exclusion = false;
    let mut had_temporal_degradation = false;
    let mut had_stream_error = false;
    let mut total_records_processed = 0u64;

    loop {
        let record_opt = match reader.next_record() {
            Ok(opt) => opt,
            Err(e) => {
                had_stream_error = true;
                let _ = diag_emitter.emit_diagnostic(&format!("capture reader error: {e}"));
                break;
            }
        };

        let record = match record_opt {
            Some(r) => r,
            None => break,
        };
        total_records_processed = total_records_processed.saturating_add(1);

        let norm_input = record.as_normalization_input();
        let norm_limits = NormalizationLimits::default();
        let norm_outcome = normalize_packet(&norm_input, &norm_limits);
        for d in &norm_outcome.diagnostics {
            let _ = diag_emitter.emit_diagnostic(&format!(
                "normalization diagnostic on packet {}: {}",
                record.ordinal, d.message
            ));
        }

        match reconstructor.observe(&norm_outcome.packet) {
            Ok(step) => {
                if let FlowDisposition::Excluded(reason) = step.disposition {
                    had_exclusion = true;
                    let _ = diag_emitter.emit_diagnostic(&format!(
                        "packet {} excluded from flow reconstruction: {reason:?}",
                        record.ordinal
                    ));
                }
                for closed in step.closed_flows {
                    if !table_header_rendered {
                        if let Err(e) = output::render_flow_table_header(&mut stdout) {
                            let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                                "failed to write flow table header: {e}"
                            ));
                            return 1;
                        }
                        table_header_rendered = true;
                    }
                    if has_temporal_degradation(&closed) {
                        had_temporal_degradation = true;
                    }
                    if let Err(e) = output::render_flow_row(&closed, &mut stdout) {
                        let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                            "failed to write flow row: {e}"
                        ));
                        return 1;
                    }
                    useful_result_produced = true;
                }
            }
            Err(e) => {
                had_stream_error = true;
                let _ = diag_emitter.emit_diagnostic(&format!(
                    "flow reconstruction error on packet {}: {e}",
                    record.ordinal
                ));
                break;
            }
        }
    }

    let remaining_flows = if had_stream_error {
        reconstructor.finish_partial()
    } else {
        reconstructor.finish()
    };

    for flow in remaining_flows {
        if !table_header_rendered {
            if let Err(e) = output::render_flow_table_header(&mut stdout) {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                    "failed to write flow table header: {e}"
                ));
                return 1;
            }
            table_header_rendered = true;
        }
        if has_temporal_degradation(&flow) {
            had_temporal_degradation = true;
        }
        if let Err(e) = output::render_flow_row(&flow, &mut stdout) {
            let _ = DiagnosticEmitter::emit_fatal_error(&format!("failed to write flow row: {e}"));
            return 1;
        }
        useful_result_produced = true;
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        let _ = diag_emitter.emit_capture_diagnostic(diag);
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if !useful_result_produced {
        if total_records_processed == 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_flow_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write flow table header: {e}"
                    ));
                    return 1;
                }
            }
            return 0;
        }
        if had_exclusion && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_flow_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write flow table header: {e}"
                    ));
                    return 1;
                }
            }
            return 3;
        }
        let _ =
            DiagnosticEmitter::emit_fatal_error("flow reconstruction produced no useful results");
        return 1;
    }

    if had_stream_error || had_exclusion || had_temporal_degradation || !outcome.is_complete() {
        3
    } else {
        0
    }
}

fn run_dns(args: DnsArgs, quiet: bool) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let reader_limits = if let Some(max_rec) = args.max_records {
        let max_usize = match usize::try_from(max_rec) {
            Ok(v) => v,
            Err(_) => {
                let _ = DiagnosticEmitter::emit_fatal_error(
                    "max-records value exceeds memory addressable bounds",
                );
                return 2;
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!("invalid reader limits: {e}"));
                return 2;
            }
        }
    } else {
        ReaderLimits::default()
    };

    let norm_limits = match NormalizationLimits::builder()
        .maximum_retained_payload_bytes(65_535)
        .build()
    {
        Ok(l) => l,
        Err(e) => {
            let _ =
                DiagnosticEmitter::emit_fatal_error(&format!("invalid normalization limits: {e}"));
            return 2;
        }
    };

    let dns_limits = DnsLimits::default();

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            let _ =
                DiagnosticEmitter::emit_fatal_error(&format!("failed to open capture file: {e}"));
            return 1;
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                "failed to initialize capture reader: {e}"
            ));
            return 1;
        }
    };

    let mut stdout = io::stdout().lock();
    let mut table_header_rendered = false;
    let mut useful_result_produced = false;
    let mut had_partial_dns = false;
    let mut had_stream_error = false;
    let mut total_records_processed = 0u64;

    loop {
        let record_opt = match reader.next_record() {
            Ok(opt) => opt,
            Err(e) => {
                had_stream_error = true;
                let _ = diag_emitter.emit_diagnostic(&format!("capture reader error: {e}"));
                break;
            }
        };

        let record = match record_opt {
            Some(r) => r,
            None => break,
        };
        total_records_processed = total_records_processed.saturating_add(1);

        let norm_input = record.as_normalization_input();
        let norm_outcome = normalize_packet(&norm_input, &norm_limits);
        for d in &norm_outcome.diagnostics {
            let _ = diag_emitter.emit_diagnostic(&format!(
                "normalization diagnostic on packet {}: {}",
                record.ordinal, d.message
            ));
        }

        let dns_outcome = parse_dns_packet(&norm_outcome.packet, &dns_limits);
        for d in &dns_outcome.diagnostics {
            let _ = diag_emitter.emit_diagnostic(&format!(
                "DNS diagnostic on packet {}: {}",
                record.ordinal, d.message
            ));
        }

        if !matches!(
            dns_outcome.disposition,
            DnsPacketDisposition::NotDnsCandidate
        ) && !norm_outcome.packet.completeness.is_complete()
        {
            had_partial_dns = true;
        }

        if matches!(dns_outcome.disposition, DnsPacketDisposition::Partial) {
            had_partial_dns = true;
        }

        for obs in &dns_outcome.observations {
            if !obs.completeness.is_complete() {
                had_partial_dns = true;
            }
            if !table_header_rendered {
                if let Err(e) = output::render_dns_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write DNS table header: {e}"
                    ));
                    return 1;
                }
                table_header_rendered = true;
            }
            if let Err(e) = output::render_dns_row(obs, &mut stdout) {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                    "failed to write DNS observation row: {e}"
                ));
                return 1;
            }
            useful_result_produced = true;
        }
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        let _ = diag_emitter.emit_capture_diagnostic(diag);
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if !useful_result_produced {
        if total_records_processed == 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_dns_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write DNS table header: {e}"
                    ));
                    return 1;
                }
            }
            return 0;
        }
        if total_records_processed > 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_dns_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write DNS table header: {e}"
                    ));
                    return 1;
                }
            }
            if had_partial_dns {
                return 3;
            }
            return 0;
        }
        let _ = DiagnosticEmitter::emit_fatal_error("DNS inspection produced no useful results");
        return 1;
    }

    if had_stream_error || had_partial_dns || !outcome.is_complete() {
        3
    } else {
        0
    }
}

fn run_http(args: HttpArgs, quiet: bool) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let reader_limits = if let Some(max_rec) = args.max_records {
        let max_usize = match usize::try_from(max_rec) {
            Ok(v) => v,
            Err(_) => {
                let _ = DiagnosticEmitter::emit_fatal_error(
                    "max-records value exceeds memory addressable bounds",
                );
                return 2;
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!("invalid reader limits: {e}"));
                return 2;
            }
        }
    } else {
        ReaderLimits::default()
    };

    let norm_limits = match NormalizationLimits::builder()
        .maximum_retained_payload_bytes(65_535)
        .build()
    {
        Ok(l) => l,
        Err(e) => {
            let _ =
                DiagnosticEmitter::emit_fatal_error(&format!("invalid normalization limits: {e}"));
            return 2;
        }
    };

    let http_limits = HttpLimits::default();

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            let _ =
                DiagnosticEmitter::emit_fatal_error(&format!("failed to open capture file: {e}"));
            return 1;
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                "failed to initialize capture reader: {e}"
            ));
            return 1;
        }
    };

    let mut stdout = io::stdout().lock();
    let mut table_header_rendered = false;
    let mut useful_result_produced = false;
    let mut had_partial_http = false;
    let mut had_stream_error = false;
    let mut total_records_processed = 0u64;

    loop {
        let record_opt = match reader.next_record() {
            Ok(opt) => opt,
            Err(e) => {
                had_stream_error = true;
                let _ = diag_emitter.emit_diagnostic(&format!("capture reader error: {e}"));
                break;
            }
        };

        let record = match record_opt {
            Some(r) => r,
            None => break,
        };
        total_records_processed = total_records_processed.saturating_add(1);

        let norm_input = record.as_normalization_input();
        let norm_outcome = normalize_packet(&norm_input, &norm_limits);
        for d in &norm_outcome.diagnostics {
            let _ = diag_emitter.emit_diagnostic(&format!(
                "normalization diagnostic on packet {}: {}",
                record.ordinal, d.message
            ));
        }

        let http_outcome = parse_http_packet(&norm_outcome.packet, &http_limits);
        for d in &http_outcome.diagnostics {
            let _ = diag_emitter.emit_diagnostic(&format!(
                "HTTP diagnostic on packet {}: {}",
                record.ordinal, d.message
            ));
        }

        if !matches!(
            http_outcome.disposition,
            HttpPacketDisposition::NotHttpCandidate
        ) && !norm_outcome.packet.completeness.is_complete()
        {
            had_partial_http = true;
        }

        if matches!(http_outcome.disposition, HttpPacketDisposition::Partial) {
            had_partial_http = true;
        }

        for obs in &http_outcome.observations {
            if !obs.completeness.is_complete() {
                had_partial_http = true;
            }
            if !table_header_rendered {
                if let Err(e) = output::render_http_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write HTTP table header: {e}"
                    ));
                    return 1;
                }
                table_header_rendered = true;
            }
            if let Err(e) = output::render_http_row(obs, &mut stdout) {
                let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                    "failed to write HTTP observation row: {e}"
                ));
                return 1;
            }
            useful_result_produced = true;
        }
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        let _ = diag_emitter.emit_capture_diagnostic(diag);
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if !useful_result_produced {
        if total_records_processed == 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_http_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write HTTP table header: {e}"
                    ));
                    return 1;
                }
            }
            return 0;
        }
        if total_records_processed > 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_http_table_header(&mut stdout) {
                    let _ = DiagnosticEmitter::emit_fatal_error(&format!(
                        "failed to write HTTP table header: {e}"
                    ));
                    return 1;
                }
            }
            if had_partial_http {
                return 3;
            }
            return 0;
        }
        let _ = DiagnosticEmitter::emit_fatal_error("HTTP inspection produced no useful results");
        return 1;
    }

    if had_stream_error || had_partial_http || !outcome.is_complete() {
        3
    } else {
        0
    }
}
