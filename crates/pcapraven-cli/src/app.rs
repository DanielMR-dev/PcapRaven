//! CLI application orchestration for validation, flow, DNS, and HTTP inspection.

use crate::args::{
    CliArgs, DnsArgs, FindingsArgs, FlowsArgs, HttpArgs, Subcommand, TlsArgs, ValidateArgs,
};
use crate::diagnostics::{DEFAULT_DIAGNOSTIC_BUDGET, DiagnosticEmitter};
use crate::output;
use pcapraven_detection::{
    CorrelationRegistry, DetectionInput, DetectionInputCompleteness, DetectionInputLimitation,
    DetectionLimits, DetectorConfigurations, DetectorRegistry, DnsLongQueryNameDetector,
    DnsPossibleTunnelingDetector, FindingFilter, PeriodicBeaconingDetector,
    PossibleC2MultiSignalCorrelator, RepeatedLowVolumeFlowDetector,
    execute_detection_with_correlators,
};
use pcapraven_domain::{
    FlowRecord, FlowTemporalUnavailableReason, ObservationFlowAssociation, ObservationReference,
    ProtocolKind, ProtocolObservation, ProtocolObservationCollection, ProtocolObservationData,
};
use pcapraven_flows::{FlowDisposition, FlowReconstructionConfig, FlowReconstructor};
use pcapraven_pcap::{CaptureCompletion, CaptureReader, ReaderLimits};
use pcapraven_protocols::{
    DnsLimits, DnsPacketDisposition, HttpLimits, HttpPacketDisposition, NormalizationLimits,
    TlsLimits, TlsPacketDisposition, normalize_packet, parse_dns_packet, parse_http_packet,
    parse_tls_packet,
};
use std::fs::File;
use std::io;
use std::process::ExitCode;

fn emit_config_error(message: &str) -> u8 {
    if DiagnosticEmitter::emit_fatal_error(message).is_err() {
        1
    } else {
        2
    }
}

fn emit_fatal_error(message: &str) -> u8 {
    let _ = DiagnosticEmitter::emit_fatal_error(message);
    1
}

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
        Subcommand::Tls(t_args) => run_tls(t_args, args.quiet),
        Subcommand::Findings(f_args) => run_findings(f_args, args.quiet),
    };
    ExitCode::from(status_code)
}

fn run_validate(args: ValidateArgs, quiet: bool) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let limits = if let Some(max_rec) = args.max_records {
        let max_usize = match usize::try_from(max_rec) {
            Ok(v) => v,
            Err(_) => {
                return emit_config_error("max-records value exceeds memory addressable bounds");
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                return emit_config_error(&format!("invalid reader limits: {e}"));
            }
        }
    } else {
        ReaderLimits::default()
    };

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            return emit_fatal_error(&format!("failed to open capture file: {e}"));
        }
    };

    let mut reader = match CaptureReader::new(file, limits) {
        Ok(r) => r,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize capture reader: {e}"));
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
                if diag_emitter
                    .emit_diagnostic(&format!("capture reader error: {e}"))
                    .is_err()
                {
                    return 1;
                }
                break;
            }
        }
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        if diag_emitter.emit_capture_diagnostic(diag).is_err() {
            return 1;
        }
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    match outcome.completion {
        CaptureCompletion::FailedBeforeUsefulRecords { ref terminal_error } => emit_fatal_error(
            &format!("capture validation failed before useful records: {terminal_error}"),
        ),
        CaptureCompletion::Complete if !had_stream_error => {
            let mut stdout = io::stdout().lock();
            if let Err(e) = output::render_validate_summary(&outcome, records_emitted, &mut stdout)
            {
                return emit_fatal_error(&format!("failed to write validation output: {e}"));
            }
            0
        }
        _ => {
            let mut stdout = io::stdout().lock();
            if let Err(e) = output::render_validate_summary(&outcome, records_emitted, &mut stdout)
            {
                return emit_fatal_error(&format!("failed to write validation output: {e}"));
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
                return emit_config_error("max-records value exceeds memory addressable bounds");
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                return emit_config_error(&format!("invalid reader limits: {e}"));
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
            return emit_config_error(&format!("invalid flow configuration: {e}"));
        }
    };

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            return emit_fatal_error(&format!("failed to open capture file: {e}"));
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize capture reader: {e}"));
        }
    };

    let mut reconstructor = match FlowReconstructor::new(flow_config) {
        Ok(r) => r,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize flow reconstructor: {e}"));
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
                if diag_emitter
                    .emit_diagnostic(&format!("capture reader error: {e}"))
                    .is_err()
                {
                    return 1;
                }
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
            if diag_emitter
                .emit_diagnostic(&format!(
                    "normalization diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }

        match reconstructor.observe(&norm_outcome.packet) {
            Ok(step) => {
                if let FlowDisposition::Excluded(reason) = step.disposition {
                    had_exclusion = true;
                    if diag_emitter
                        .emit_diagnostic(&format!(
                            "packet {} excluded from flow reconstruction: {reason:?}",
                            record.ordinal
                        ))
                        .is_err()
                    {
                        return 1;
                    }
                }
                for closed in step.closed_flows {
                    if !table_header_rendered {
                        if let Err(e) = output::render_flow_table_header(&mut stdout) {
                            return emit_fatal_error(&format!(
                                "failed to write flow table header: {e}"
                            ));
                        }
                        table_header_rendered = true;
                    }
                    if has_temporal_degradation(&closed) {
                        had_temporal_degradation = true;
                    }
                    if let Err(e) = output::render_flow_row(&closed, &mut stdout) {
                        return emit_fatal_error(&format!("failed to write flow row: {e}"));
                    }
                    useful_result_produced = true;
                }
            }
            Err(e) => {
                had_stream_error = true;
                if diag_emitter
                    .emit_diagnostic(&format!(
                        "flow reconstruction error on packet {}: {e}",
                        record.ordinal
                    ))
                    .is_err()
                {
                    return 1;
                }
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
                return emit_fatal_error(&format!("failed to write flow table header: {e}"));
            }
            table_header_rendered = true;
        }
        if has_temporal_degradation(&flow) {
            had_temporal_degradation = true;
        }
        if let Err(e) = output::render_flow_row(&flow, &mut stdout) {
            return emit_fatal_error(&format!("failed to write flow row: {e}"));
        }
        useful_result_produced = true;
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        if diag_emitter.emit_capture_diagnostic(diag).is_err() {
            return 1;
        }
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if !useful_result_produced {
        if total_records_processed == 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_flow_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write flow table header: {e}"));
                }
            }
            return 0;
        }
        if had_exclusion && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_flow_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write flow table header: {e}"));
                }
            }
            return 3;
        }
        return emit_fatal_error("flow reconstruction produced no useful results");
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
                return emit_config_error("max-records value exceeds memory addressable bounds");
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                return emit_config_error(&format!("invalid reader limits: {e}"));
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
            return emit_config_error(&format!("invalid normalization limits: {e}"));
        }
    };

    let dns_limits = DnsLimits::default();

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            return emit_fatal_error(&format!("failed to open capture file: {e}"));
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize capture reader: {e}"));
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
                if diag_emitter
                    .emit_diagnostic(&format!("capture reader error: {e}"))
                    .is_err()
                {
                    return 1;
                }
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
            if diag_emitter
                .emit_diagnostic(&format!(
                    "normalization diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }

        let dns_outcome = parse_dns_packet(&norm_outcome.packet, &dns_limits);
        for d in &dns_outcome.diagnostics {
            if diag_emitter
                .emit_diagnostic(&format!(
                    "DNS diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
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
                    return emit_fatal_error(&format!("failed to write DNS table header: {e}"));
                }
                table_header_rendered = true;
            }
            if let Err(e) = output::render_dns_row(obs, &mut stdout) {
                return emit_fatal_error(&format!("failed to write DNS observation row: {e}"));
            }
            useful_result_produced = true;
        }
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        if diag_emitter.emit_capture_diagnostic(diag).is_err() {
            return 1;
        }
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if !useful_result_produced {
        if total_records_processed == 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_dns_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write DNS table header: {e}"));
                }
            }
            return 0;
        }
        if total_records_processed > 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_dns_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write DNS table header: {e}"));
                }
            }
            if had_partial_dns {
                return 3;
            }
            return 0;
        }
        return emit_fatal_error("DNS inspection produced no useful results");
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
                return emit_config_error("max-records value exceeds memory addressable bounds");
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                return emit_config_error(&format!("invalid reader limits: {e}"));
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
            return emit_config_error(&format!("invalid normalization limits: {e}"));
        }
    };

    let http_limits = HttpLimits::default();

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            return emit_fatal_error(&format!("failed to open capture file: {e}"));
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize capture reader: {e}"));
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
                if diag_emitter
                    .emit_diagnostic(&format!("capture reader error: {e}"))
                    .is_err()
                {
                    return 1;
                }
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
            if diag_emitter
                .emit_diagnostic(&format!(
                    "normalization diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }

        let http_outcome = parse_http_packet(&norm_outcome.packet, &http_limits);
        for d in &http_outcome.diagnostics {
            if diag_emitter
                .emit_diagnostic(&format!(
                    "HTTP diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
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
                    return emit_fatal_error(&format!("failed to write HTTP table header: {e}"));
                }
                table_header_rendered = true;
            }
            if let Err(e) = output::render_http_row(obs, &mut stdout) {
                return emit_fatal_error(&format!("failed to write HTTP observation row: {e}"));
            }
            useful_result_produced = true;
        }
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        if diag_emitter.emit_capture_diagnostic(diag).is_err() {
            return 1;
        }
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if !useful_result_produced {
        if total_records_processed == 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_http_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write HTTP table header: {e}"));
                }
            }
            return 0;
        }
        if total_records_processed > 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_http_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write HTTP table header: {e}"));
                }
            }
            if had_partial_http {
                return 3;
            }
            return 0;
        }
        return emit_fatal_error("HTTP inspection produced no useful results");
    }

    if had_stream_error || had_partial_http || !outcome.is_complete() {
        3
    } else {
        0
    }
}

fn run_tls(args: TlsArgs, quiet: bool) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let reader_limits = if let Some(max_rec) = args.max_records {
        let max_usize = match usize::try_from(max_rec) {
            Ok(v) => v,
            Err(_) => {
                return emit_config_error("max-records value exceeds memory addressable bounds");
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                return emit_config_error(&format!("invalid reader limits: {e}"));
            }
        }
    } else {
        ReaderLimits::default()
    };

    let norm_limits = match NormalizationLimits::builder()
        .maximum_retained_payload_bytes(262_144)
        .build()
    {
        Ok(l) => l,
        Err(e) => {
            return emit_config_error(&format!("invalid normalization limits: {e}"));
        }
    };

    let tls_limits = TlsLimits::default();

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            return emit_fatal_error(&format!("failed to open capture file: {e}"));
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize capture reader: {e}"));
        }
    };

    let mut stdout = io::stdout().lock();
    let mut table_header_rendered = false;
    let mut useful_result_produced = false;
    let mut had_partial_tls = false;
    let mut had_stream_error = false;
    let mut total_records_processed = 0u64;

    loop {
        let record_opt = match reader.next_record() {
            Ok(opt) => opt,
            Err(e) => {
                had_stream_error = true;
                if diag_emitter
                    .emit_diagnostic(&format!("capture reader error: {e}"))
                    .is_err()
                {
                    return 1;
                }
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
            if diag_emitter
                .emit_diagnostic(&format!(
                    "normalization diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }

        let tls_outcome = parse_tls_packet(&norm_outcome.packet, &tls_limits);
        for d in &tls_outcome.diagnostics {
            if diag_emitter
                .emit_diagnostic(&format!(
                    "TLS diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }

        if matches!(tls_outcome.disposition, TlsPacketDisposition::Partial) {
            had_partial_tls = true;
        }

        for obs in &tls_outcome.observations {
            if !obs.completeness.is_complete() {
                had_partial_tls = true;
            }
            if !table_header_rendered {
                if let Err(e) = output::render_tls_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write TLS table header: {e}"));
                }
                table_header_rendered = true;
            }
            if let Err(e) = output::render_tls_row(obs, &mut stdout) {
                return emit_fatal_error(&format!("failed to write TLS observation row: {e}"));
            }
            useful_result_produced = true;
        }
    }

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        if diag_emitter.emit_capture_diagnostic(diag).is_err() {
            return 1;
        }
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if !useful_result_produced {
        if total_records_processed == 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_tls_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write TLS table header: {e}"));
                }
            }
            return 0;
        }
        if total_records_processed > 0 && !had_stream_error && outcome.is_complete() {
            if !table_header_rendered {
                if let Err(e) = output::render_tls_table_header(&mut stdout) {
                    return emit_fatal_error(&format!("failed to write TLS table header: {e}"));
                }
            }
            if had_partial_tls {
                return 3;
            }
            return 0;
        }
        return emit_fatal_error("TLS inspection produced no useful results");
    }

    if had_stream_error || had_partial_tls || !outcome.is_complete() {
        3
    } else {
        0
    }
}

fn run_findings(args: FindingsArgs, quiet: bool) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let reader_limits = if let Some(max_rec) = args.max_records {
        let max_usize = match usize::try_from(max_rec) {
            Ok(v) => v,
            Err(_) => {
                return emit_config_error("max-records value exceeds memory addressable bounds");
            }
        };
        match ReaderLimits::builder().maximum_records(max_usize).build() {
            Ok(l) => l,
            Err(e) => {
                return emit_config_error(&format!("invalid reader limits: {e}"));
            }
        }
    } else {
        ReaderLimits::default()
    };

    let file = match File::open(&args.capture_path) {
        Ok(f) => f,
        Err(e) => {
            return emit_fatal_error(&format!("failed to open capture file: {e}"));
        }
    };

    let mut reader = match CaptureReader::new(file, reader_limits) {
        Ok(r) => r,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize capture reader: {e}"));
        }
    };

    let norm_limits = NormalizationLimits::default();
    let dns_limits = DnsLimits::default();
    let http_limits = HttpLimits::default();
    let tls_limits = TlsLimits::default();

    let flow_config = FlowReconstructionConfig::default();
    let mut flow_reconstructor = match FlowReconstructor::new(flow_config) {
        Ok(fr) => fr,
        Err(e) => {
            return emit_config_error(&format!("failed to initialize flow reconstructor: {e}"));
        }
    };

    let mut obs_collection = match ProtocolObservationCollection::new(
        ProtocolObservationCollection::DEFAULT_MAX_OBSERVATIONS,
    ) {
        Ok(c) => c,
        Err(e) => {
            return emit_fatal_error(&format!("failed to initialize observation collection: {e}"));
        }
    };

    let mut all_flows = Vec::new();
    let mut had_stream_error = false;
    let mut had_partial_data = false;
    let mut total_records_processed: u64 = 0;

    loop {
        let record_opt = match reader.next_record() {
            Ok(opt) => opt,
            Err(e) => {
                had_stream_error = true;
                if diag_emitter
                    .emit_diagnostic(&format!("capture reader stream error: {e}"))
                    .is_err()
                {
                    return 1;
                }
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
            if diag_emitter
                .emit_diagnostic(&format!(
                    "normalization diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }

        let flow_step = match flow_reconstructor.observe(&norm_outcome.packet) {
            Ok(s) => s,
            Err(e) => {
                had_stream_error = true;
                if diag_emitter
                    .emit_diagnostic(&format!(
                        "flow reconstruction error on packet {}: {e}",
                        record.ordinal
                    ))
                    .is_err()
                {
                    return 1;
                }
                break;
            }
        };

        all_flows.extend(flow_step.closed_flows);

        let flow_association = match flow_step.disposition {
            FlowDisposition::Associated(assoc) => {
                ObservationFlowAssociation::from_flow_packet_association(
                    &norm_outcome.packet.reference,
                    &assoc,
                )
                .unwrap_or(ObservationFlowAssociation::Unassociated)
            }
            FlowDisposition::Excluded(reason) => ObservationFlowAssociation::Excluded(reason),
        };

        let dns_outcome = parse_dns_packet(&norm_outcome.packet, &dns_limits);
        for d in &dns_outcome.diagnostics {
            if diag_emitter
                .emit_diagnostic(&format!(
                    "DNS diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }
        for (idx, obs) in dns_outcome.observations.into_iter().enumerate() {
            if !obs.completeness.is_complete() {
                had_partial_data = true;
            }
            let obs_ref = ObservationReference::new(record.ordinal, ProtocolKind::Dns, idx as u32);
            if let Ok(protocol_obs) = ProtocolObservation::try_new(
                obs_ref,
                flow_association,
                ProtocolObservationData::Dns(obs),
            ) {
                if let Err(e) = obs_collection.push(protocol_obs) {
                    if diag_emitter
                        .emit_diagnostic(&format!("observation collection error: {e}"))
                        .is_err()
                    {
                        return 1;
                    }
                }
            }
        }

        let http_outcome = parse_http_packet(&norm_outcome.packet, &http_limits);
        for d in &http_outcome.diagnostics {
            if diag_emitter
                .emit_diagnostic(&format!(
                    "HTTP diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }
        for (idx, obs) in http_outcome.observations.into_iter().enumerate() {
            if !obs.completeness.is_complete() {
                had_partial_data = true;
            }
            let obs_ref = ObservationReference::new(record.ordinal, ProtocolKind::Http, idx as u32);
            if let Ok(protocol_obs) = ProtocolObservation::try_new(
                obs_ref,
                flow_association,
                ProtocolObservationData::Http(obs),
            ) {
                if let Err(e) = obs_collection.push(protocol_obs) {
                    if diag_emitter
                        .emit_diagnostic(&format!("observation collection error: {e}"))
                        .is_err()
                    {
                        return 1;
                    }
                }
            }
        }

        let tls_outcome = parse_tls_packet(&norm_outcome.packet, &tls_limits);
        for d in &tls_outcome.diagnostics {
            if diag_emitter
                .emit_diagnostic(&format!(
                    "TLS diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ))
                .is_err()
            {
                return 1;
            }
        }
        for (idx, obs) in tls_outcome.observations.into_iter().enumerate() {
            if !obs.completeness.is_complete() {
                had_partial_data = true;
            }
            let obs_ref = ObservationReference::new(record.ordinal, ProtocolKind::Tls, idx as u32);
            if let Ok(protocol_obs) = ProtocolObservation::try_new(
                obs_ref,
                flow_association,
                ProtocolObservationData::Tls(obs),
            ) {
                if let Err(e) = obs_collection.push(protocol_obs) {
                    if diag_emitter
                        .emit_diagnostic(&format!("observation collection error: {e}"))
                        .is_err()
                    {
                        return 1;
                    }
                }
            }
        }
    }

    let remaining_flows = if had_stream_error {
        flow_reconstructor.finish_partial()
    } else {
        flow_reconstructor.finish()
    };
    all_flows.extend(remaining_flows);

    let outcome = reader.into_outcome();
    for diag in &outcome.diagnostics {
        if diag_emitter.emit_capture_diagnostic(diag).is_err() {
            return 1;
        }
    }
    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    let mut detector_registry =
        match DetectorRegistry::new(DetectorRegistry::DEFAULT_MAX_REGISTERED_DETECTORS) {
            Ok(r) => r,
            Err(e) => {
                return emit_fatal_error(&format!("failed to initialize detector registry: {e}"));
            }
        };

    if let Err(e) = detector_registry.register(Box::new(PeriodicBeaconingDetector::new())) {
        return emit_fatal_error(&format!(
            "failed to register periodic beaconing detector: {e}"
        ));
    }
    if let Err(e) = detector_registry.register(Box::new(DnsLongQueryNameDetector::new())) {
        return emit_fatal_error(&format!(
            "failed to register DNS long query name detector: {e}"
        ));
    }
    if let Err(e) = detector_registry.register(Box::new(DnsPossibleTunnelingDetector::new())) {
        return emit_fatal_error(&format!(
            "failed to register DNS possible tunneling detector: {e}"
        ));
    }
    if let Err(e) = detector_registry.register(Box::new(RepeatedLowVolumeFlowDetector::new())) {
        return emit_fatal_error(&format!(
            "failed to register repeated low-volume flow detector: {e}"
        ));
    }

    let mut correlation_registry = CorrelationRegistry::empty();

    if let Err(e) = correlation_registry.register(Box::new(PossibleC2MultiSignalCorrelator::new()))
    {
        return emit_fatal_error(&format!("failed to register possible C2 correlator: {e}"));
    }

    let mut limitations = Vec::new();
    if had_stream_error || had_partial_data || !outcome.is_complete() {
        limitations.push(DetectionInputLimitation::CaptureTruncated);
    }

    let completeness = if limitations.is_empty() {
        DetectionInputCompleteness::Complete
    } else {
        DetectionInputCompleteness::Partial
    };

    let detection_input = match DetectionInput::try_new(
        &all_flows,
        obs_collection.observations(),
        completeness,
        &limitations,
    ) {
        Ok(i) => i,
        Err(e) => {
            return emit_fatal_error(&format!("failed to build detection input: {e}"));
        }
    };

    let detection_limits = DetectionLimits::default();
    let detection_configs = DetectorConfigurations::default();

    let detection_outcome = match execute_detection_with_correlators(
        &detector_registry,
        &correlation_registry,
        &detection_input,
        &detection_configs,
        &detection_limits,
    ) {
        Ok(o) => o,
        Err(e) => {
            return emit_fatal_error(&format!("detection execution failed: {e}"));
        }
    };

    let filter = FindingFilter::new()
        .with_min_severity(args.min_severity)
        .with_min_confidence(args.min_confidence)
        .with_detector_id(args.detector_id)
        .with_mitre_attack_id(args.mitre_id);

    let filtered_findings = filter.filter_findings(&detection_outcome.findings);

    let mut stdout = io::stdout().lock();
    if let Err(e) = output::render_findings(&filtered_findings, &mut stdout) {
        return emit_fatal_error(&format!("failed to render findings: {e}"));
    }

    if had_stream_error || had_partial_data || !outcome.is_complete() {
        3
    } else {
        0
    }
}
