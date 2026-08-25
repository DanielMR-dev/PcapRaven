use pcapraven_detection::{
    CorrelationRegistry, DetectionInput, DetectionInputCompleteness, DetectionInputLimitation,
    DetectionLimits, DetectionRunOutcome, DetectorConfigurations, DetectorRegistry,
    DnsLongQueryNameDetector, DnsPossibleTunnelingDetector, PeriodicBeaconingDetector,
    PossibleC2MultiSignalCorrelator, RepeatedLowVolumeFlowDetector,
    execute_detection_with_correlators,
};
use pcapraven_domain::{
    FlowRecord, ObservationFlowAssociation, ObservationReference, ProtocolKind,
    ProtocolObservation, ProtocolObservationCollection, ProtocolObservationCollectionError,
    ProtocolObservationData,
};
use pcapraven_flows::{FlowDisposition, FlowReconstructionConfigBuilder, FlowReconstructor};
use pcapraven_pcap::{
    CaptureCompletion, CaptureDiagnosticKind, CaptureReadOutcome, CaptureReader,
    CaptureReaderErrorKind, ReaderLimit, ReaderLimits,
};
use pcapraven_protocols::{
    DnsLimits, HttpLimits, NormalizationLimits, TlsLimits, normalize_packet, parse_dns_packet,
    parse_http_packet, parse_tls_packet,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::diagnostics::DiagnosticEmitter;

/// Options controlling the shared capture analysis pipeline.
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Path to the capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
    /// Maximum simultaneous active flows to track.
    pub max_flows: Option<usize>,
    /// Maximum total flow instances across analysis.
    pub max_flow_instances: Option<usize>,
    /// Maximum protocol observations to retain.
    pub max_observations: Option<usize>,
    /// TCP flow idle timeout in seconds.
    pub tcp_idle_timeout: Option<u32>,
    /// UDP flow idle timeout in seconds.
    pub udp_idle_timeout: Option<u32>,
    /// Whether to parse DNS packets.
    pub parse_dns: bool,
    /// Whether to parse HTTP/1.x packets.
    pub parse_http: bool,
    /// Whether to parse TLS packets.
    pub parse_tls: bool,
    /// Whether to execute detection algorithms and correlators.
    pub run_detectors: bool,
}

/// Errors arising during analysis initialization or fatal execution.
#[derive(Debug)]
pub enum AnalysisError {
    /// Configuration or argument validation error.
    Config(String),
    /// Unrecoverable fatal error (e.g. file open error, engine init failure).
    Fatal(String),
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "{msg}"),
            Self::Fatal(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AnalysisError {}

/// Full outcome of the shared capture analysis pipeline.
pub struct AnalysisResult {
    /// Outcome metadata from the capture container reader.
    pub reader_outcome: CaptureReadOutcome,
    /// Total capture records processed.
    pub total_records_processed: u64,
    /// Reconstructed network flows, canonically sorted by `FlowReference.ordinal()`.
    pub flows: Vec<FlowRecord>,
    /// Unified protocol observations.
    pub observations: Vec<ProtocolObservation>,
    /// Completeness of the detection input.
    pub detection_input_completeness: DetectionInputCompleteness,
    /// Specific limitations recorded on detection input.
    pub detection_input_limitations: Vec<DetectionInputLimitation>,
    /// Execution outcome from the detection engine.
    pub detection_outcome: DetectionRunOutcome,
    /// Whether any capture reader or stream error occurred.
    pub had_stream_error: bool,
    /// Whether any partial parsing or limitation occurred.
    pub had_partial_data: bool,
}

impl AnalysisResult {
    /// Returns `true` if the analysis run was partial or encountered any degradation.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.had_stream_error
            || self.had_partial_data
            || !self.reader_outcome.is_complete()
            || self.detection_outcome.completion == DetectionInputCompleteness::Partial
            || self.detection_input_completeness == DetectionInputCompleteness::Partial
    }

    /// Computes the CLI exit code (0 for complete success, 3 for partial analysis).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.is_partial() { 3 } else { 0 }
    }
}

fn emit_diagnostic<W: Write>(
    emitter: &mut DiagnosticEmitter<W>,
    message: &str,
) -> Result<(), AnalysisError> {
    emitter.emit_diagnostic(message).map_err(|_| {
        AnalysisError::Fatal("failed to emit analysis diagnostic to stderr".to_string())
    })
}

fn handle_observation_push<W: Write>(
    collection: &mut ProtocolObservationCollection,
    observation: ProtocolObservation,
    budget_exhausted: &mut bool,
    had_partial_data: &mut bool,
    emitter: &mut DiagnosticEmitter<W>,
) -> Result<(), AnalysisError> {
    match collection.push(observation) {
        Ok(()) => Ok(()),
        Err(error @ ProtocolObservationCollectionError::ResourceLimit { .. }) => {
            *budget_exhausted = true;
            *had_partial_data = true;
            emit_diagnostic(
                emitter,
                &format!("observation collection budget exhausted: {error}"),
            )
        }
        Err(
            error @ (ProtocolObservationCollectionError::DuplicateReference(_)
            | ProtocolObservationCollectionError::OutOfOrderReference { .. }),
        ) => Err(AnalysisError::Fatal(format!(
            "protocol observation ordering invariant failed: {error}"
        ))),
        Err(
            error @ (ProtocolObservationCollectionError::ZeroCapacity
            | ProtocolObservationCollectionError::CapacityAboveHardMaximum { .. }),
        ) => Err(AnalysisError::Fatal(format!(
            "initialized observation collection rejected an insertion: {error}"
        ))),
    }
}

struct ObservationIngestion<'a, W: Write> {
    packet_ordinal: u64,
    protocol: ProtocolKind,
    protocol_label: &'static str,
    flow_association: ObservationFlowAssociation,
    collection: &'a mut ProtocolObservationCollection,
    budget_exhausted: &'a mut bool,
    had_partial_data: &'a mut bool,
    emitter: &'a mut DiagnosticEmitter<W>,
}

fn ingest_observations<W, O, I, C, D>(
    observations: I,
    context: ObservationIngestion<'_, W>,
    is_complete: C,
    into_data: D,
) -> Result<(), AnalysisError>
where
    W: Write,
    I: IntoIterator<Item = O>,
    C: Fn(&O) -> bool,
    D: Fn(O) -> ProtocolObservationData,
{
    for (idx, obs) in observations.into_iter().enumerate() {
        if !is_complete(&obs) {
            *context.had_partial_data = true;
        }
        let sub_idx = match u32::try_from(idx) {
            Ok(si) => si,
            Err(_) => {
                *context.had_partial_data = true;
                emit_diagnostic(
                    &mut *context.emitter,
                    &format!(
                        "{} observation index overflow on packet {}",
                        context.protocol_label, context.packet_ordinal
                    ),
                )?;
                continue;
            }
        };
        let obs_ref = ObservationReference::new(context.packet_ordinal, context.protocol, sub_idx);
        match ProtocolObservation::try_new(obs_ref, context.flow_association, into_data(obs)) {
            Ok(protocol_obs) => {
                if !*context.budget_exhausted {
                    handle_observation_push(
                        &mut *context.collection,
                        protocol_obs,
                        &mut *context.budget_exhausted,
                        &mut *context.had_partial_data,
                        &mut *context.emitter,
                    )?;
                }
            }
            Err(e) => {
                return Err(AnalysisError::Fatal(format!(
                    "{} observation construction failed on packet {}: {e}",
                    context.protocol_label, context.packet_ordinal
                )));
            }
        }
    }
    Ok(())
}

fn terminal_reader_error(
    outcome: &CaptureReadOutcome,
) -> Option<&pcapraven_pcap::CaptureReaderError> {
    match &outcome.completion {
        CaptureCompletion::Complete => None,
        CaptureCompletion::Partial { terminal_error } => terminal_error.as_ref(),
        CaptureCompletion::FailedBeforeUsefulRecords { terminal_error } => Some(terminal_error),
    }
}

fn outcome_is_physically_truncated(outcome: &CaptureReadOutcome) -> bool {
    terminal_reader_error(outcome)
        .is_some_and(|error| error.kind() == CaptureReaderErrorKind::Incomplete)
        || outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == CaptureDiagnosticKind::Incomplete)
}

fn outcome_reached_record_budget(outcome: &CaptureReadOutcome) -> bool {
    matches!(
        terminal_reader_error(outcome),
        Some(pcapraven_pcap::CaptureReaderError::ResourceLimit {
            limit: ReaderLimit::MaximumRecords,
            ..
        })
    )
}

fn build_builtin_registries() -> Result<(DetectorRegistry, CorrelationRegistry), AnalysisError> {
    let mut det_registry = DetectorRegistry::default();
    let beaconing = PeriodicBeaconingDetector::try_new().map_err(|e| {
        AnalysisError::Fatal(format!("invalid built-in beaconing detector metadata: {e}"))
    })?;
    if let Err(e) = det_registry.register(Box::new(beaconing)) {
        return Err(AnalysisError::Fatal(format!(
            "failed to register beaconing detector: {e}"
        )));
    }
    let dns_tunneling = DnsPossibleTunnelingDetector::try_new().map_err(|e| {
        AnalysisError::Fatal(format!(
            "invalid built-in DNS tunneling detector metadata: {e}"
        ))
    })?;
    if let Err(e) = det_registry.register(Box::new(dns_tunneling)) {
        return Err(AnalysisError::Fatal(format!(
            "failed to register DNS tunneling detector: {e}"
        )));
    }
    let dns_long_query = DnsLongQueryNameDetector::try_new().map_err(|e| {
        AnalysisError::Fatal(format!(
            "invalid built-in DNS long query detector metadata: {e}"
        ))
    })?;
    if let Err(e) = det_registry.register(Box::new(dns_long_query)) {
        return Err(AnalysisError::Fatal(format!(
            "failed to register DNS long query detector: {e}"
        )));
    }
    let low_volume = RepeatedLowVolumeFlowDetector::try_new().map_err(|e| {
        AnalysisError::Fatal(format!(
            "invalid built-in low-volume detector metadata: {e}"
        ))
    })?;
    if let Err(e) = det_registry.register(Box::new(low_volume)) {
        return Err(AnalysisError::Fatal(format!(
            "failed to register low-volume flow detector: {e}"
        )));
    }

    let mut corr_registry = CorrelationRegistry::default();
    let c2_correlator = PossibleC2MultiSignalCorrelator::try_new()
        .map_err(|e| AnalysisError::Fatal(format!("invalid built-in correlator metadata: {e}")))?;
    if let Err(e) = corr_registry.register(Box::new(c2_correlator)) {
        return Err(AnalysisError::Fatal(format!(
            "failed to register C2 multi-signal correlator: {e}"
        )));
    }

    Ok((det_registry, corr_registry))
}

/// Executes the shared capture analysis pipeline.
///
/// # Errors
/// Returns [`AnalysisError`] on configuration or fatal initialization/execution errors.
pub fn run_analysis<W: Write>(
    options: &AnalysisOptions,
    diag_emitter: &mut DiagnosticEmitter<W>,
) -> Result<AnalysisResult, AnalysisError> {
    // 1. Validate reader limits
    let reader_limits = if let Some(max_rec) = options.max_records {
        let max_usize = usize::try_from(max_rec).map_err(|_| {
            AnalysisError::Config("max-records value exceeds memory addressable bounds".to_string())
        })?;
        ReaderLimits::builder()
            .maximum_records(max_usize)
            .build()
            .map_err(|e| AnalysisError::Config(format!("invalid reader limits: {e}")))?
    } else {
        ReaderLimits::default()
    };

    // 2. Validate flow reconstruction configuration
    let mut flow_cfg_builder = FlowReconstructionConfigBuilder::default();
    if let Some(mf) = options.max_flows {
        flow_cfg_builder = flow_cfg_builder.maximum_tracked_flows(mf);
    }
    if let Some(mfi) = options.max_flow_instances {
        flow_cfg_builder = flow_cfg_builder.maximum_flow_instances(mfi);
    }
    if let Some(t) = options.tcp_idle_timeout {
        flow_cfg_builder = flow_cfg_builder.tcp_idle_timeout_seconds(t);
    }
    if let Some(u) = options.udp_idle_timeout {
        flow_cfg_builder = flow_cfg_builder.udp_idle_timeout_seconds(u);
    }
    let flow_config = flow_cfg_builder
        .build()
        .map_err(|e| AnalysisError::Config(format!("invalid flow configuration: {e}")))?;

    // 3. Initialize flow reconstructor
    let mut flow_reconstructor = FlowReconstructor::new(flow_config).map_err(|e| {
        AnalysisError::Config(format!("failed to initialize flow reconstructor: {e}"))
    })?;

    // 4. Validate observation collection
    let max_obs = options
        .max_observations
        .unwrap_or(ProtocolObservationCollection::DEFAULT_MAX_OBSERVATIONS);
    let mut obs_collection = ProtocolObservationCollection::new(max_obs)
        .map_err(|e| AnalysisError::Config(format!("invalid observation collection limit: {e}")))?;

    // 5. Open capture file and initialize capture reader
    let file = File::open(&options.capture_path)
        .map_err(|e| AnalysisError::Fatal(format!("failed to open capture file: {e}")))?;

    let mut reader = CaptureReader::new(file, reader_limits)
        .map_err(|e| AnalysisError::Fatal(format!("failed to initialize capture reader: {e}")))?;

    let norm_limits = NormalizationLimits::default();
    let dns_limits = DnsLimits::default();
    let http_limits = HttpLimits::default();
    let tls_limits = TlsLimits::default();

    let mut all_flows = Vec::new();
    let mut had_stream_error = false;
    let mut had_partial_data = false;
    let mut total_records_processed: u64 = 0;
    let mut observation_budget_exhausted = false;
    let mut had_flow_budget_exhaustion = false;

    loop {
        let record_opt = match reader.next_record() {
            Ok(opt) => opt,
            Err(e) => {
                had_stream_error = true;
                emit_diagnostic(diag_emitter, &format!("capture reader stream error: {e}"))?;
                break;
            }
        };

        let record = match record_opt {
            Some(r) => r,
            None => break,
        };
        total_records_processed = total_records_processed.checked_add(1).ok_or_else(|| {
            AnalysisError::Fatal(
                "capture record counter exceeded supported resource bounds".to_string(),
            )
        })?;

        let norm_input = record.as_normalization_input();
        let norm_outcome = normalize_packet(&norm_input, &norm_limits);
        if !norm_outcome.diagnostics.is_empty() {
            had_partial_data = true;
        }
        for d in &norm_outcome.diagnostics {
            emit_diagnostic(
                diag_emitter,
                &format!(
                    "normalization diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ),
            )?;
        }

        let flow_step = match flow_reconstructor.observe(&norm_outcome.packet) {
            Ok(s) => s,
            Err(e) => {
                had_stream_error = true;
                if matches!(&e, pcapraven_flows::FlowError::ResourceLimit { .. }) {
                    had_flow_budget_exhaustion = true;
                }
                emit_diagnostic(
                    diag_emitter,
                    &format!(
                        "flow reconstruction error on packet {}: {e}",
                        record.ordinal
                    ),
                )?;
                break;
            }
        };

        all_flows.extend(flow_step.closed_flows);

        let flow_association = match &flow_step.disposition {
            FlowDisposition::Associated(assoc) => {
                match ObservationFlowAssociation::from_flow_packet_association(
                    &norm_outcome.packet.reference,
                    assoc,
                ) {
                    Ok(fa) => fa,
                    Err(e) => {
                        return Err(AnalysisError::Fatal(format!(
                            "fatal flow-observation association invariant failure on packet {}: {e}",
                            record.ordinal
                        )));
                    }
                }
            }
            FlowDisposition::Excluded(reason) => ObservationFlowAssociation::Excluded(*reason),
        };

        // DNS parsing
        if options.parse_dns {
            let dns_outcome = parse_dns_packet(&norm_outcome.packet, &dns_limits);
            if !dns_outcome.diagnostics.is_empty() {
                had_partial_data = true;
            }
            for d in &dns_outcome.diagnostics {
                emit_diagnostic(
                    diag_emitter,
                    &format!("DNS diagnostic on packet {}: {}", record.ordinal, d.message),
                )?;
            }
            ingest_observations(
                dns_outcome.observations,
                ObservationIngestion {
                    packet_ordinal: record.ordinal,
                    protocol: ProtocolKind::Dns,
                    protocol_label: "DNS",
                    flow_association,
                    collection: &mut obs_collection,
                    budget_exhausted: &mut observation_budget_exhausted,
                    had_partial_data: &mut had_partial_data,
                    emitter: diag_emitter,
                },
                |obs| obs.completeness.is_complete(),
                ProtocolObservationData::Dns,
            )?;
        }

        // HTTP parsing
        if options.parse_http {
            let http_outcome = parse_http_packet(&norm_outcome.packet, &http_limits);
            if !http_outcome.diagnostics.is_empty() {
                had_partial_data = true;
            }
            for d in &http_outcome.diagnostics {
                emit_diagnostic(
                    diag_emitter,
                    &format!(
                        "HTTP diagnostic on packet {}: {}",
                        record.ordinal, d.message
                    ),
                )?;
            }
            ingest_observations(
                http_outcome.observations,
                ObservationIngestion {
                    packet_ordinal: record.ordinal,
                    protocol: ProtocolKind::Http,
                    protocol_label: "HTTP",
                    flow_association,
                    collection: &mut obs_collection,
                    budget_exhausted: &mut observation_budget_exhausted,
                    had_partial_data: &mut had_partial_data,
                    emitter: diag_emitter,
                },
                |obs| obs.completeness.is_complete(),
                ProtocolObservationData::Http,
            )?;
        }

        // TLS parsing
        if options.parse_tls {
            let tls_outcome = parse_tls_packet(&norm_outcome.packet, &tls_limits);
            if !tls_outcome.diagnostics.is_empty() {
                had_partial_data = true;
            }
            for d in &tls_outcome.diagnostics {
                emit_diagnostic(
                    diag_emitter,
                    &format!("TLS diagnostic on packet {}: {}", record.ordinal, d.message),
                )?;
            }
            ingest_observations(
                tls_outcome.observations,
                ObservationIngestion {
                    packet_ordinal: record.ordinal,
                    protocol: ProtocolKind::Tls,
                    protocol_label: "TLS",
                    flow_association,
                    collection: &mut obs_collection,
                    budget_exhausted: &mut observation_budget_exhausted,
                    had_partial_data: &mut had_partial_data,
                    emitter: diag_emitter,
                },
                |obs| obs.completeness.is_complete(),
                ProtocolObservationData::Tls,
            )?;
        }
    }

    let reader_outcome = reader.into_outcome();
    for diag in &reader_outcome.diagnostics {
        diag_emitter.emit_capture_diagnostic(diag).map_err(|_| {
            AnalysisError::Fatal("failed to emit capture diagnostic to stderr".to_string())
        })?;
    }

    if let CaptureCompletion::FailedBeforeUsefulRecords { terminal_error } =
        &reader_outcome.completion
    {
        return Err(AnalysisError::Fatal(format!(
            "capture analysis failed before useful records: {terminal_error}"
        )));
    }

    // Flush remaining flows
    let remaining_flows = if had_stream_error || !reader_outcome.is_complete() {
        flow_reconstructor.finish_partial()
    } else {
        flow_reconstructor.finish()
    };
    all_flows.extend(remaining_flows);

    // Sort flows canonically by reference ordinal
    all_flows.sort_by_key(|f| f.reference.ordinal());

    let mut detection_limitations = Vec::new();
    if outcome_is_physically_truncated(&reader_outcome) {
        detection_limitations.push(DetectionInputLimitation::CaptureTruncated);
    }
    if outcome_reached_record_budget(&reader_outcome) {
        detection_limitations.push(DetectionInputLimitation::PacketCountBudgetReached);
    }
    if observation_budget_exhausted {
        detection_limitations.push(DetectionInputLimitation::ObservationBudgetReached);
    }
    if had_flow_budget_exhaustion {
        detection_limitations.push(DetectionInputLimitation::FlowBudgetReached);
    }

    let input_completeness = if detection_limitations.is_empty() {
        DetectionInputCompleteness::Complete
    } else {
        DetectionInputCompleteness::Partial
    };

    let detection_outcome = if options.run_detectors {
        let detection_input = match DetectionInput::try_new(
            &all_flows,
            obs_collection.observations(),
            input_completeness,
            &detection_limitations,
        ) {
            Ok(inp) => inp,
            Err(e) => {
                return Err(AnalysisError::Fatal(format!(
                    "failed to construct detection input: {e}"
                )));
            }
        };

        let (det_registry, corr_registry) = build_builtin_registries()?;

        let det_configs = DetectorConfigurations::default();
        let det_limits = DetectionLimits::default();

        match execute_detection_with_correlators(
            &det_registry,
            &corr_registry,
            &detection_input,
            &det_configs,
            &det_limits,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(AnalysisError::Fatal(format!(
                    "detection execution failed: {e}"
                )));
            }
        }
    } else {
        DetectionRunOutcome {
            completion: DetectionInputCompleteness::Complete,
            detector_executions: Vec::new(),
            correlator_executions: Vec::new(),
            findings: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
        }
    };

    Ok(AnalysisResult {
        reader_outcome,
        total_records_processed,
        flows: all_flows,
        observations: obs_collection.into_vec(),
        detection_input_completeness: input_completeness,
        detection_input_limitations: detection_limitations,
        detection_outcome,
        had_stream_error,
        had_partial_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic failure",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailAfterOneWrite {
        completed_line: bool,
    }

    impl Write for FailAfterOneWrite {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.completed_line {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic failure",
                ));
            }
            self.completed_line = buffer.contains(&b'\n');
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn options_for(relative_capture: &str) -> AnalysisOptions {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("CLI crate is below workspace root")
            .to_path_buf();
        AnalysisOptions {
            capture_path: root.join("tests/fixtures/pcaps").join(relative_capture),
            max_records: None,
            max_flows: None,
            max_flow_instances: None,
            max_observations: None,
            tcp_idle_timeout: None,
            udp_idle_timeout: None,
            parse_dns: false,
            parse_http: true,
            parse_tls: false,
            run_detectors: false,
        }
    }

    #[test]
    fn diagnostic_write_failure_is_a_fatal_analysis_error() {
        let options = options_for("edge_cases/local_http_partial_with_dns_detection.pcap");
        let mut emitter = DiagnosticEmitter::with_writer(FailingWriter, false, 100);
        assert!(matches!(
            run_analysis(&options, &mut emitter),
            Err(AnalysisError::Fatal(_))
        ));
    }

    #[test]
    fn capture_diagnostic_write_failure_is_a_fatal_analysis_error() {
        let options = options_for("malformed/useful_then_truncated_record.pcap");
        let writer = FailAfterOneWrite {
            completed_line: false,
        };
        let mut emitter = DiagnosticEmitter::with_writer(writer, false, 100);
        assert!(matches!(
            run_analysis(&options, &mut emitter),
            Err(AnalysisError::Fatal(_))
        ));
    }
}
