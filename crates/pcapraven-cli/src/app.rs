//! CLI application orchestration for validation, flow, DNS, HTTP, TLS, findings, and analysis inspection.

use crate::analysis::{AnalysisError, AnalysisOptions, AnalysisResult, run_analysis};
use crate::args::{
    AnalyzeArgs, CliArgs, DnsArgs, FindingsArgs, FlowsArgs, HttpArgs, Subcommand, TlsArgs,
    ValidateArgs,
};
use crate::diagnostics::{DEFAULT_DIAGNOSTIC_BUDGET, DiagnosticEmitter};
use pcapraven_detection::FindingFilter;
use pcapraven_domain::{
    Confidence, DetectorId, EvidenceRecord, FindingRecord, MitreAttackId, ProtocolObservation,
    ProtocolObservationData, Severity,
};
use pcapraven_pcap::{
    ByteOrder, CaptureCompletion, CaptureFormat, CaptureReadOutcome, CaptureReader,
    CaptureTimestampResolution, ReaderLimits,
};
use pcapraven_reporting::{
    AnalysisReportDto, AnalysisSummaryDto, EvidenceRecordDto, FindingFilterDto, FindingRecordDto,
    FlowRecordDto, ProtocolObservationDto, ReportCompletionDto, ReportError, ReportFormat,
    ValidationCompletionDto, ValidationDiagnosticDto, ValidationMetadataDto, ValidationSummaryDto,
    report_analysis, report_dns, report_findings, report_flows, report_http, report_tls,
    report_validation,
};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
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

fn render_and_flush<W, F>(writer: &mut W, render: F) -> Result<(), ReportError>
where
    W: Write,
    F: FnOnce(&mut dyn Write) -> Result<(), ReportError>,
{
    render(writer)?;
    writer.flush().map_err(ReportError::Io)
}

/// Executes a reporting closure against the requested output sink (safe atomic file or stdout).
fn with_output_sink<F>(output_path: Option<&Path>, f: F) -> Result<(), u8>
where
    F: FnOnce(&mut dyn Write) -> Result<(), ReportError>,
{
    match output_path {
        Some(path) => {
            let file = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(f) => f,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(emit_config_error(&format!(
                        "output file already exists: {}",
                        path.display()
                    )));
                }
                Err(err) => {
                    return Err(emit_fatal_error(&format!(
                        "failed to create output file '{}': {err}",
                        path.display()
                    )));
                }
            };
            let mut writer = std::io::BufWriter::new(file);
            let write_res = render_and_flush(&mut writer, f);
            if let Err(e) = write_res {
                drop(writer);
                let _ = std::fs::remove_file(path);
                return match e {
                    ReportError::UnsupportedFormat { rationale, .. } => {
                        Err(emit_config_error(rationale))
                    }
                    other => Err(emit_fatal_error(&format!(
                        "failed to render report: {other}"
                    ))),
                };
            }
            Ok(())
        }
        None => {
            let mut stdout = io::stdout().lock();
            let write_res = render_and_flush(&mut stdout, f);
            if let Err(e) = write_res {
                return match e {
                    ReportError::UnsupportedFormat { rationale, .. } => {
                        Err(emit_config_error(rationale))
                    }
                    other => Err(emit_fatal_error(&format!(
                        "failed to render report: {other}"
                    ))),
                };
            }
            Ok(())
        }
    }
}

/// Converts a [`CaptureReadOutcome`] into validation DTO components.
fn convert_validation_outcome(
    outcome: &CaptureReadOutcome,
    records_emitted: u64,
) -> (
    ValidationMetadataDto,
    ValidationSummaryDto,
    ValidationCompletionDto,
    Vec<ValidationDiagnosticDto>,
) {
    let mut meta = ValidationMetadataDto::default();
    match outcome.metadata.format {
        CaptureFormat::LegacyPcap => {
            meta.format = "pcap".to_string();
            if let Some(ref legacy) = outcome.metadata.legacy {
                meta.byte_order = match legacy.byte_order {
                    ByteOrder::Little => "little_endian".to_string(),
                    ByteOrder::Big => "big_endian".to_string(),
                };
                meta.version_major = Some(legacy.version_major);
                meta.version_minor = Some(legacy.version_minor);
                meta.linktype = Some(legacy.linktype);
                meta.snaplen = Some(legacy.snaplen);
                meta.timestamp_resolution = match legacy.timestamp_resolution {
                    CaptureTimestampResolution::Decimal {
                        exponent,
                        units_per_second,
                    } => Some(format!("10^{exponent} units/s ({units_per_second} Hz)")),
                    CaptureTimestampResolution::Binary {
                        exponent,
                        units_per_second,
                    } => Some(format!("2^{exponent} units/s ({units_per_second} Hz)")),
                };
            } else {
                meta.byte_order = "unknown".to_string();
            }
        }
        CaptureFormat::PcapNg => {
            meta.format = "pcapng".to_string();
            meta.section_count = Some(outcome.metadata.sections.len().to_string());
            let mut total_ifaces = 0usize;
            let mut usable_ifaces = 0usize;
            let mut unusable_ifaces = 0usize;
            for sec in &outcome.metadata.sections {
                total_ifaces = total_ifaces.saturating_add(sec.interfaces.len());
                for iface in &sec.interfaces {
                    if iface.is_valid() {
                        usable_ifaces = usable_ifaces.saturating_add(1);
                    } else {
                        unusable_ifaces = unusable_ifaces.saturating_add(1);
                    }
                }
            }
            meta.interface_count = Some(total_ifaces.to_string());
            meta.usable_interfaces = Some(usable_ifaces.to_string());
            meta.unusable_interfaces = Some(unusable_ifaces.to_string());

            if let Some(first_sec) = outcome.metadata.sections.first() {
                meta.byte_order = match first_sec.byte_order {
                    ByteOrder::Little => "little_endian".to_string(),
                    ByteOrder::Big => "big_endian".to_string(),
                };
                meta.version_major = Some(first_sec.version_major);
                meta.version_minor = Some(first_sec.version_minor);
            } else {
                meta.byte_order = "unknown".to_string();
            }
        }
        CaptureFormat::Unknown => {
            meta.format = "unknown".to_string();
            meta.byte_order = "unknown".to_string();
        }
    }

    let summary = ValidationSummaryDto {
        records_emitted: records_emitted.to_string(),
        total_diagnostics: outcome.diagnostics.len().to_string(),
        had_diagnostics: !outcome.diagnostics.is_empty(),
    };

    let (status, is_complete, terminal_error) = match &outcome.completion {
        CaptureCompletion::Complete => ("complete".to_string(), true, None),
        CaptureCompletion::Partial { terminal_error } => (
            "partial".to_string(),
            false,
            terminal_error.as_ref().map(ToString::to_string),
        ),
        CaptureCompletion::FailedBeforeUsefulRecords { terminal_error } => (
            "failed".to_string(),
            false,
            Some(terminal_error.to_string()),
        ),
    };

    let completion = ValidationCompletionDto {
        status,
        is_complete,
        terminal_error,
    };

    let diagnostics = outcome
        .diagnostics
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let stage_str = match d.stage {
                pcapraven_pcap::CaptureDiagnosticStage::Format => "format",
                pcapraven_pcap::CaptureDiagnosticStage::Header => "header",
                pcapraven_pcap::CaptureDiagnosticStage::Block => "block",
                pcapraven_pcap::CaptureDiagnosticStage::Interface => "interface",
                pcapraven_pcap::CaptureDiagnosticStage::Packet => "packet",
                pcapraven_pcap::CaptureDiagnosticStage::Reader => "reader",
            };
            let kind_str = match d.kind {
                pcapraven_pcap::CaptureDiagnosticKind::Unsupported => "unsupported",
                pcapraven_pcap::CaptureDiagnosticKind::Malformed => "malformed",
                pcapraven_pcap::CaptureDiagnosticKind::Incomplete => "incomplete",
                pcapraven_pcap::CaptureDiagnosticKind::InvalidReference => "invalid_reference",
                pcapraven_pcap::CaptureDiagnosticKind::ResourceLimit => "resource_limit",
                pcapraven_pcap::CaptureDiagnosticKind::Io => "io",
                pcapraven_pcap::CaptureDiagnosticKind::Internal => "internal",
            };
            ValidationDiagnosticDto {
                index: i.to_string(),
                stage: stage_str.to_string(),
                kind: kind_str.to_string(),
                message: d.message.to_string(),
                byte_offset: Some(d.location.offset.to_string()),
            }
        })
        .collect();

    (meta, summary, completion, diagnostics)
}

fn execute_analysis(options: AnalysisOptions, quiet: bool) -> Result<AnalysisResult, u8> {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);
    let result = match run_analysis(&options, &mut diag_emitter) {
        Ok(r) => r,
        Err(AnalysisError::Config(msg)) => return Err(emit_config_error(&msg)),
        Err(AnalysisError::Fatal(msg)) => return Err(emit_fatal_error(&msg)),
    };

    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return Err(1);
    }

    Ok(result)
}

fn build_finding_filter_dto(
    min_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    detector_id: Option<&DetectorId>,
    mitre_id: Option<&MitreAttackId>,
) -> Option<FindingFilterDto> {
    if min_severity.is_some()
        || min_confidence.is_some()
        || detector_id.is_some()
        || mitre_id.is_some()
    {
        Some(FindingFilterDto {
            min_severity: min_severity.map(|s| s.as_str().to_string()),
            min_confidence: min_confidence.map(|c| c.as_str().to_string()),
            detector_id: detector_id.map(ToString::to_string),
            mitre_attack_id: mitre_id.map(ToString::to_string),
        })
    } else {
        None
    }
}

fn filter_findings_and_evidence<'a>(
    findings: &'a [FindingRecord],
    evidence: &'a [EvidenceRecord],
    min_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    detector_id: Option<&DetectorId>,
    mitre_id: Option<&MitreAttackId>,
) -> (Vec<&'a FindingRecord>, Vec<&'a EvidenceRecord>) {
    let filter = FindingFilter::new()
        .with_min_severity(min_severity)
        .with_min_confidence(min_confidence)
        .with_detector_id(detector_id.cloned())
        .with_mitre_attack_id(mitre_id.cloned());

    let filtered_findings = filter.filter_findings(findings);
    let needed_evidence_refs: BTreeSet<_> = filtered_findings
        .iter()
        .flat_map(|f| f.evidence_references().iter().copied())
        .collect();
    let filtered_evidence = evidence
        .iter()
        .filter(|e| needed_evidence_refs.contains(&e.reference()))
        .collect();

    (filtered_findings, filtered_evidence)
}

fn project_protocol_observations<T, F>(
    observations: &[ProtocolObservation],
    mut project: F,
) -> Vec<T>
where
    F: FnMut(&ProtocolObservationData) -> Option<T>,
{
    let mut projected = Vec::new();
    for observation in observations {
        if let Some(value) = project(observation.data()) {
            projected.push(value);
        }
    }
    projected
}

/// Main application dispatcher converting [`CliArgs`] into a process [`ExitCode`].
#[must_use]
pub fn run(args: CliArgs) -> ExitCode {
    let status_code = match args.command {
        Subcommand::Validate(v_args) => {
            run_validate(v_args, args.quiet, args.format, args.output.as_deref())
        }
        Subcommand::Flows(f_args) => {
            run_flows(f_args, args.quiet, args.format, args.output.as_deref())
        }
        Subcommand::Dns(d_args) => run_dns(d_args, args.quiet, args.format, args.output.as_deref()),
        Subcommand::Http(h_args) => {
            run_http(h_args, args.quiet, args.format, args.output.as_deref())
        }
        Subcommand::Tls(t_args) => run_tls(t_args, args.quiet, args.format, args.output.as_deref()),
        Subcommand::Findings(f_args) => {
            run_findings(f_args, args.quiet, args.format, args.output.as_deref())
        }
        Subcommand::Analyze(a_args) => {
            run_analyze(a_args, args.quiet, args.format, args.output.as_deref())
        }
    };
    ExitCode::from(status_code)
}

fn run_validate(
    args: ValidateArgs,
    quiet: bool,
    format: ReportFormat,
    output_path: Option<&Path>,
) -> u8 {
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

    let (meta, summary, completion, diags) = convert_validation_outcome(&outcome, records_emitted);

    match outcome.completion {
        CaptureCompletion::FailedBeforeUsefulRecords { ref terminal_error } => emit_fatal_error(
            &format!("capture validation failed before useful records: {terminal_error}"),
        ),
        _ => {
            if let Err(code) = with_output_sink(output_path, |mut w| {
                report_validation(format, &meta, &summary, &completion, &diags, &mut w)
            }) {
                return code;
            }

            if outcome.is_complete() && !had_stream_error {
                0
            } else {
                3
            }
        }
    }
}

fn run_flows(args: FlowsArgs, quiet: bool, format: ReportFormat, output_path: Option<&Path>) -> u8 {
    let analysis_options = AnalysisOptions {
        capture_path: args.capture_path,
        max_records: args.max_records,
        max_flows: args.max_flows,
        max_flow_instances: args.max_flow_instances,
        max_observations: None,
        tcp_idle_timeout: args.tcp_idle_timeout,
        udp_idle_timeout: args.udp_idle_timeout,
        parse_dns: false,
        parse_http: false,
        parse_tls: false,
        run_detectors: false,
    };

    let result = match execute_analysis(analysis_options, quiet) {
        Ok(r) => r,
        Err(code) => return code,
    };

    if let Err(code) = with_output_sink(output_path, |mut w| {
        report_flows(format, &result.flows, &mut w)
    }) {
        return code;
    }

    result.exit_code()
}

fn run_dns(args: DnsArgs, quiet: bool, format: ReportFormat, output_path: Option<&Path>) -> u8 {
    let analysis_options = AnalysisOptions {
        capture_path: args.capture_path,
        max_records: args.max_records,
        max_flows: None,
        max_flow_instances: None,
        max_observations: None,
        tcp_idle_timeout: None,
        udp_idle_timeout: None,
        parse_dns: true,
        parse_http: false,
        parse_tls: false,
        run_detectors: false,
    };

    let result = match execute_analysis(analysis_options, quiet) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let dns_obs = project_protocol_observations(&result.observations, |data| match data {
        ProtocolObservationData::Dns(d) => Some(d.clone()),
        ProtocolObservationData::Http(_) | ProtocolObservationData::Tls(_) => None,
    });

    if let Err(code) = with_output_sink(output_path, |mut w| report_dns(format, &dns_obs, &mut w)) {
        return code;
    }

    result.exit_code()
}

fn run_http(args: HttpArgs, quiet: bool, format: ReportFormat, output_path: Option<&Path>) -> u8 {
    let analysis_options = AnalysisOptions {
        capture_path: args.capture_path,
        max_records: args.max_records,
        max_flows: None,
        max_flow_instances: None,
        max_observations: None,
        tcp_idle_timeout: None,
        udp_idle_timeout: None,
        parse_dns: false,
        parse_http: true,
        parse_tls: false,
        run_detectors: false,
    };

    let result = match execute_analysis(analysis_options, quiet) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let http_obs = project_protocol_observations(&result.observations, |data| match data {
        ProtocolObservationData::Dns(_) | ProtocolObservationData::Tls(_) => None,
        ProtocolObservationData::Http(h) => Some(h.clone()),
    });

    if let Err(code) = with_output_sink(output_path, |mut w| report_http(format, &http_obs, &mut w))
    {
        return code;
    }

    result.exit_code()
}

fn run_tls(args: TlsArgs, quiet: bool, format: ReportFormat, output_path: Option<&Path>) -> u8 {
    let analysis_options = AnalysisOptions {
        capture_path: args.capture_path,
        max_records: args.max_records,
        max_flows: None,
        max_flow_instances: None,
        max_observations: None,
        tcp_idle_timeout: None,
        udp_idle_timeout: None,
        parse_dns: false,
        parse_http: false,
        parse_tls: true,
        run_detectors: false,
    };

    let result = match execute_analysis(analysis_options, quiet) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let tls_obs = project_protocol_observations(&result.observations, |data| match data {
        ProtocolObservationData::Dns(_) | ProtocolObservationData::Http(_) => None,
        ProtocolObservationData::Tls(t) => Some(t.clone()),
    });

    if let Err(code) = with_output_sink(output_path, |mut w| report_tls(format, &tls_obs, &mut w)) {
        return code;
    }

    result.exit_code()
}

fn run_findings(
    args: FindingsArgs,
    quiet: bool,
    format: ReportFormat,
    output_path: Option<&Path>,
) -> u8 {
    let filter_dto = build_finding_filter_dto(
        args.min_severity,
        args.min_confidence,
        args.detector_id.as_ref(),
        args.mitre_id.as_ref(),
    );

    let analysis_options = AnalysisOptions {
        capture_path: args.capture_path,
        max_records: args.max_records,
        max_flows: args.max_flows,
        max_flow_instances: args.max_flow_instances,
        max_observations: args.max_observations,
        tcp_idle_timeout: args.tcp_idle_timeout,
        udp_idle_timeout: args.udp_idle_timeout,
        parse_dns: true,
        parse_http: true,
        parse_tls: true,
        run_detectors: true,
    };

    let result = match execute_analysis(analysis_options, quiet) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let (filtered_findings, filtered_evidence) = filter_findings_and_evidence(
        &result.detection_outcome.findings,
        &result.detection_outcome.evidence,
        args.min_severity,
        args.min_confidence,
        args.detector_id.as_ref(),
        args.mitre_id.as_ref(),
    );

    if let Err(code) = with_output_sink(output_path, |mut w| {
        report_findings(
            format,
            &filtered_findings,
            &filtered_evidence,
            filter_dto,
            &mut w,
        )
    }) {
        return code;
    }

    result.exit_code()
}

fn run_analyze(
    args: AnalyzeArgs,
    quiet: bool,
    format: ReportFormat,
    output_path: Option<&Path>,
) -> u8 {
    if format == ReportFormat::Csv {
        return emit_config_error(
            "hierarchical multi-section analysis report cannot be represented as a single flat CSV table; use table, json, or ndjson",
        );
    }

    let filter_dto = build_finding_filter_dto(
        args.min_severity,
        args.min_confidence,
        args.detector_id.as_ref(),
        args.mitre_id.as_ref(),
    );

    let analysis_options = AnalysisOptions {
        capture_path: args.capture_path,
        max_records: args.max_records,
        max_flows: args.max_flows,
        max_flow_instances: args.max_flow_instances,
        max_observations: args.max_observations,
        tcp_idle_timeout: args.tcp_idle_timeout,
        udp_idle_timeout: args.udp_idle_timeout,
        parse_dns: true,
        parse_http: true,
        parse_tls: true,
        run_detectors: true,
    };

    let result = match execute_analysis(analysis_options, quiet) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let (filtered_findings, filtered_evidence) = filter_findings_and_evidence(
        &result.detection_outcome.findings,
        &result.detection_outcome.evidence,
        args.min_severity,
        args.min_confidence,
        args.detector_id.as_ref(),
        args.mitre_id.as_ref(),
    );

    let (meta, _, _, _) =
        convert_validation_outcome(&result.reader_outcome, result.total_records_processed);

    let completion_dto = ReportCompletionDto {
        status: if result.is_partial() {
            "partial".to_string()
        } else {
            "complete".to_string()
        },
        limitations: result
            .detection_input_limitations
            .iter()
            .map(|l| match l {
                pcapraven_detection::DetectionInputLimitation::CaptureTruncated => {
                    "capture_truncated".to_string()
                }
                pcapraven_detection::DetectionInputLimitation::PacketCountBudgetReached => {
                    "packet_count_budget_reached".to_string()
                }
                pcapraven_detection::DetectionInputLimitation::FlowBudgetReached => {
                    "flow_budget_reached".to_string()
                }
                pcapraven_detection::DetectionInputLimitation::ObservationBudgetReached => {
                    "observation_budget_reached".to_string()
                }
            })
            .collect(),
    };

    let summary = AnalysisSummaryDto {
        total_packets: result.total_records_processed.to_string(),
        total_flows: result.flows.len().to_string(),
        total_dns_observations: result
            .observations
            .iter()
            .filter(|o| o.protocol_kind() == pcapraven_domain::ProtocolKind::Dns)
            .count()
            .to_string(),
        total_http_observations: result
            .observations
            .iter()
            .filter(|o| o.protocol_kind() == pcapraven_domain::ProtocolKind::Http)
            .count()
            .to_string(),
        total_tls_observations: result
            .observations
            .iter()
            .filter(|o| o.protocol_kind() == pcapraven_domain::ProtocolKind::Tls)
            .count()
            .to_string(),
        total_findings: filtered_findings.len().to_string(),
        total_evidence_records: filtered_evidence.len().to_string(),
    };

    let analysis_dto = AnalysisReportDto {
        schema_version: pcapraven_reporting::REPORT_SCHEMA_VERSION,
        kind: pcapraven_reporting::ReportKind::Analysis.as_str(),
        metadata: meta,
        summary,
        completion: completion_dto,
        filter: filter_dto,
        flows: result
            .flows
            .iter()
            .map(FlowRecordDto::from_domain)
            .collect(),
        observations: result
            .observations
            .iter()
            .map(ProtocolObservationDto::from_domain)
            .collect(),
        findings: filtered_findings
            .iter()
            .map(|f| FindingRecordDto::from_domain(f))
            .collect(),
        evidence: filtered_evidence
            .iter()
            .map(|e| EvidenceRecordDto::from_domain(e))
            .collect(),
    };

    if let Err(code) = with_output_sink(output_path, |mut w| {
        report_analysis(
            format,
            &analysis_dto,
            &result.flows,
            &filtered_findings,
            &mut w,
        )
    }) {
        return code;
    }

    result.exit_code()
}

#[cfg(test)]
mod output_tests {
    use super::{convert_validation_outcome, render_and_flush, with_output_sink};
    use pcapraven_pcap::{
        CaptureCompletion, CaptureDiagnostic, CaptureDiagnosticKind, CaptureDiagnosticStage,
        CaptureFormat, CaptureLocation, CaptureMetadata, CaptureReadOutcome,
    };
    use pcapraven_reporting::ReportError;
    use std::io::{self, Write};

    struct ControlledWriter {
        fail_write: bool,
        fail_flush: bool,
    }

    struct BoundaryWriter {
        remaining: usize,
        flushed: bool,
    }

    impl Write for BoundaryWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "synthetic boundary write failure",
                ));
            }
            let written = self.remaining.min(bytes.len());
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }

    impl Write for ControlledWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "synthetic write failure",
                ))
            } else {
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("synthetic flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn output_writer_and_flush_failures_are_returned() {
        let mut write_failure = ControlledWriter {
            fail_write: true,
            fail_flush: false,
        };
        let write_result = render_and_flush(&mut write_failure, |writer| {
            writer.write_all(b"result").map_err(ReportError::Io)
        });
        assert!(matches!(write_result, Err(ReportError::Io(_))));

        let mut flush_failure = ControlledWriter {
            fail_write: false,
            fail_flush: true,
        };
        let flush_result = render_and_flush(&mut flush_failure, |writer| {
            writer.write_all(b"result").map_err(ReportError::Io)
        });
        assert!(matches!(flush_result, Err(ReportError::Io(_))));
    }

    #[test]
    fn phase18_output_write_capacity_covers_n_minus_1_n_n_plus_1() {
        const OUTPUT_BYTES: &[u8] = b"result";
        for capacity in [
            OUTPUT_BYTES.len() - 1,
            OUTPUT_BYTES.len(),
            OUTPUT_BYTES.len() + 1,
        ] {
            let mut writer = BoundaryWriter {
                remaining: capacity,
                flushed: false,
            };
            let result = render_and_flush(&mut writer, |output| {
                output.write_all(OUTPUT_BYTES).map_err(ReportError::Io)
            });
            assert_eq!(result.is_ok(), capacity >= OUTPUT_BYTES.len());
            assert_eq!(writer.flushed, capacity >= OUTPUT_BYTES.len());
        }
    }

    #[test]
    fn phase18_new_output_file_is_removed_after_reporting_failure() {
        let path = std::env::temp_dir().join(format!(
            "pcapraven_phase18_cleanup_{}_{}.tmp",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&path);
        let result = with_output_sink(Some(&path), |output| {
            output.write_all(b"partial").map_err(ReportError::Io)?;
            Err(ReportError::Io(io::Error::other(
                "synthetic report failure after write",
            )))
        });
        assert_eq!(result, Err(1));
        assert!(!path.exists());
    }

    #[test]
    fn validation_conversion_maps_every_diagnostic_stage_and_kind() {
        let stages = [
            (CaptureDiagnosticStage::Format, "format"),
            (CaptureDiagnosticStage::Header, "header"),
            (CaptureDiagnosticStage::Block, "block"),
            (CaptureDiagnosticStage::Interface, "interface"),
            (CaptureDiagnosticStage::Packet, "packet"),
            (CaptureDiagnosticStage::Reader, "reader"),
        ];
        let kinds = [
            (CaptureDiagnosticKind::Unsupported, "unsupported"),
            (CaptureDiagnosticKind::Malformed, "malformed"),
            (CaptureDiagnosticKind::Incomplete, "incomplete"),
            (CaptureDiagnosticKind::InvalidReference, "invalid_reference"),
            (CaptureDiagnosticKind::ResourceLimit, "resource_limit"),
            (CaptureDiagnosticKind::Io, "io"),
            (CaptureDiagnosticKind::Internal, "internal"),
        ];

        let mut diagnostics = Vec::new();
        let mut expected_tokens = Vec::new();
        for &(stage, stage_token) in &stages {
            for &(kind, kind_token) in &kinds {
                let offset = diagnostics.len() as u64;
                diagnostics.push(CaptureDiagnostic {
                    kind,
                    stage,
                    message: "synthetic diagnostic",
                    location: CaptureLocation {
                        offset,
                        section_ordinal: None,
                        interface_ordinal: None,
                        block_type: None,
                        packet_ordinal: None,
                    },
                    recovered: true,
                });
                expected_tokens.push((stage_token, kind_token));
            }
        }

        let outcome = CaptureReadOutcome {
            metadata: CaptureMetadata {
                format: CaptureFormat::Unknown,
                legacy: None,
                sections: Vec::new(),
            },
            records: Vec::new(),
            diagnostics,
            completion: CaptureCompletion::Complete,
        };

        let (_, summary, completion, emitted) = convert_validation_outcome(&outcome, 0);

        assert_eq!(summary.total_diagnostics, "42");
        assert!(summary.had_diagnostics);
        assert_eq!(completion.status, "complete");
        assert!(completion.is_complete);
        assert_eq!(emitted.len(), expected_tokens.len());
        for (index, (expected_stage, expected_kind)) in expected_tokens.iter().enumerate() {
            assert_eq!(emitted[index].index, index.to_string());
            assert_eq!(emitted[index].stage, *expected_stage);
            assert_eq!(emitted[index].kind, *expected_kind);
            assert_eq!(emitted[index].byte_offset, Some(index.to_string()));
        }
    }
}
