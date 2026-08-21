//! CLI application orchestration for validation, flow, DNS, HTTP, TLS, findings, and analysis inspection.

use crate::analysis::{AnalysisError, AnalysisOptions, run_analysis};
use crate::args::{
    AnalyzeArgs, CliArgs, DnsArgs, FindingsArgs, FlowsArgs, HttpArgs, Subcommand, TlsArgs,
    ValidateArgs,
};
use crate::diagnostics::{DEFAULT_DIAGNOSTIC_BUDGET, DiagnosticEmitter};
use pcapraven_detection::FindingFilter;
use pcapraven_domain::ProtocolObservationData;
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
            let write_res = f(&mut writer).and_then(|()| writer.flush().map_err(ReportError::Io));
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
            let write_res = f(&mut stdout).and_then(|()| stdout.flush().map_err(ReportError::Io));
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
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

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

    let result = match run_analysis(&analysis_options, &mut diag_emitter) {
        Ok(r) => r,
        Err(AnalysisError::Config(msg)) => return emit_config_error(&msg),
        Err(AnalysisError::Fatal(msg)) => return emit_fatal_error(&msg),
    };

    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    if let Err(code) = with_output_sink(output_path, |mut w| {
        report_flows(format, &result.flows, &mut w)
    }) {
        return code;
    }

    result.exit_code()
}

fn run_dns(args: DnsArgs, quiet: bool, format: ReportFormat, output_path: Option<&Path>) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

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

    let result = match run_analysis(&analysis_options, &mut diag_emitter) {
        Ok(r) => r,
        Err(AnalysisError::Config(msg)) => return emit_config_error(&msg),
        Err(AnalysisError::Fatal(msg)) => return emit_fatal_error(&msg),
    };

    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    let mut dns_obs = Vec::new();
    for obs in &result.observations {
        if let ProtocolObservationData::Dns(d) = obs.data() {
            dns_obs.push(d.clone());
        }
    }

    if let Err(code) = with_output_sink(output_path, |mut w| report_dns(format, &dns_obs, &mut w)) {
        return code;
    }

    result.exit_code()
}

fn run_http(args: HttpArgs, quiet: bool, format: ReportFormat, output_path: Option<&Path>) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

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

    let result = match run_analysis(&analysis_options, &mut diag_emitter) {
        Ok(r) => r,
        Err(AnalysisError::Config(msg)) => return emit_config_error(&msg),
        Err(AnalysisError::Fatal(msg)) => return emit_fatal_error(&msg),
    };

    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    let mut http_obs = Vec::new();
    for obs in &result.observations {
        if let ProtocolObservationData::Http(h) = obs.data() {
            http_obs.push(h.clone());
        }
    }

    if let Err(code) = with_output_sink(output_path, |mut w| report_http(format, &http_obs, &mut w))
    {
        return code;
    }

    result.exit_code()
}

fn run_tls(args: TlsArgs, quiet: bool, format: ReportFormat, output_path: Option<&Path>) -> u8 {
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

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

    let result = match run_analysis(&analysis_options, &mut diag_emitter) {
        Ok(r) => r,
        Err(AnalysisError::Config(msg)) => return emit_config_error(&msg),
        Err(AnalysisError::Fatal(msg)) => return emit_fatal_error(&msg),
    };

    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    let mut tls_obs = Vec::new();
    for obs in &result.observations {
        if let ProtocolObservationData::Tls(t) = obs.data() {
            tls_obs.push(t.clone());
        }
    }

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
    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let filter_dto = if args.min_severity.is_some()
        || args.min_confidence.is_some()
        || args.detector_id.is_some()
        || args.mitre_id.is_some()
    {
        Some(FindingFilterDto {
            min_severity: args.min_severity.map(|s| s.as_str().to_string()),
            min_confidence: args.min_confidence.map(|c| c.as_str().to_string()),
            detector_id: args.detector_id.as_ref().map(|d| d.to_string()),
            mitre_attack_id: args.mitre_id.as_ref().map(|m| m.to_string()),
        })
    } else {
        None
    };

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

    let result = match run_analysis(&analysis_options, &mut diag_emitter) {
        Ok(r) => r,
        Err(AnalysisError::Config(msg)) => return emit_config_error(&msg),
        Err(AnalysisError::Fatal(msg)) => return emit_fatal_error(&msg),
    };

    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    let filter = FindingFilter::new()
        .with_min_severity(args.min_severity)
        .with_min_confidence(args.min_confidence)
        .with_detector_id(args.detector_id)
        .with_mitre_attack_id(args.mitre_id);

    let filtered_findings = filter.filter_findings(&result.detection_outcome.findings);

    let needed_evidence_refs: BTreeSet<_> = filtered_findings
        .iter()
        .flat_map(|f| f.evidence_references().iter().copied())
        .collect();
    let filtered_evidence: Vec<&pcapraven_domain::EvidenceRecord> = result
        .detection_outcome
        .evidence
        .iter()
        .filter(|e| needed_evidence_refs.contains(&e.reference()))
        .collect();

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

    let mut diag_emitter = DiagnosticEmitter::new(quiet, DEFAULT_DIAGNOSTIC_BUDGET);

    let filter_dto = if args.min_severity.is_some()
        || args.min_confidence.is_some()
        || args.detector_id.is_some()
        || args.mitre_id.is_some()
    {
        Some(FindingFilterDto {
            min_severity: args.min_severity.map(|s| s.as_str().to_string()),
            min_confidence: args.min_confidence.map(|c| c.as_str().to_string()),
            detector_id: args.detector_id.as_ref().map(|d| d.to_string()),
            mitre_attack_id: args.mitre_id.as_ref().map(|m| m.to_string()),
        })
    } else {
        None
    };

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

    let result = match run_analysis(&analysis_options, &mut diag_emitter) {
        Ok(r) => r,
        Err(AnalysisError::Config(msg)) => return emit_config_error(&msg),
        Err(AnalysisError::Fatal(msg)) => return emit_fatal_error(&msg),
    };

    if diag_emitter.finish().is_err() || diag_emitter.had_io_error() {
        return 1;
    }

    let filter = FindingFilter::new()
        .with_min_severity(args.min_severity)
        .with_min_confidence(args.min_confidence)
        .with_detector_id(args.detector_id)
        .with_mitre_attack_id(args.mitre_id);

    let filtered_findings = filter.filter_findings(&result.detection_outcome.findings);

    let (meta, _, _, _) =
        convert_validation_outcome(&result.reader_outcome, result.total_records_processed);

    let needed_evidence_refs: BTreeSet<_> = filtered_findings
        .iter()
        .flat_map(|f| f.evidence_references().iter().copied())
        .collect();
    let filtered_evidence: Vec<&pcapraven_domain::EvidenceRecord> = result
        .detection_outcome
        .evidence
        .iter()
        .filter(|e| needed_evidence_refs.contains(&e.reference()))
        .collect();

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
