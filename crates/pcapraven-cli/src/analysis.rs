use pcapraven_detection::{
    CorrelationRegistry, DetectionInput, DetectionInputCompleteness, DetectionInputLimitation,
    DetectionLimits, DetectionRunOutcome, DetectorConfigurations, DetectorRegistry,
    DnsLongQueryNameDetector, DnsPossibleTunnelingDetector, PeriodicBeaconingDetector,
    PossibleC2MultiSignalCorrelator, RepeatedLowVolumeFlowDetector,
    execute_detection_with_correlators,
};
use pcapraven_domain::{
    FlowRecord, ObservationFlowAssociation, ObservationReference, ProtocolKind,
    ProtocolObservation, ProtocolObservationCollection, ProtocolObservationData,
};
use pcapraven_flows::{FlowDisposition, FlowReconstructionConfigBuilder, FlowReconstructor};
use pcapraven_pcap::{CaptureReadOutcome, CaptureReader, ReaderLimits};
use pcapraven_protocols::{
    DnsLimits, HttpLimits, NormalizationLimits, TlsLimits, normalize_packet, parse_dns_packet,
    parse_http_packet, parse_tls_packet,
};
use std::fs::File;
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
#[allow(dead_code)]
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

/// Executes the shared capture analysis pipeline.
///
/// # Errors
/// Returns [`AnalysisError`] on configuration or fatal initialization/execution errors.
pub fn run_analysis(
    options: &AnalysisOptions,
    diag_emitter: &mut DiagnosticEmitter,
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
    let mut obs_collection = ProtocolObservationCollection::new(max_obs).map_err(|e| {
        AnalysisError::Fatal(format!("failed to initialize observation collection: {e}"))
    })?;

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
                let _ = diag_emitter.emit_diagnostic(&format!("capture reader stream error: {e}"));
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
        if !norm_outcome.diagnostics.is_empty() {
            had_partial_data = true;
        }
        for d in &norm_outcome.diagnostics {
            let _ = diag_emitter.emit_diagnostic(&format!(
                "normalization diagnostic on packet {}: {}",
                record.ordinal, d.message
            ));
        }

        let flow_step = match flow_reconstructor.observe(&norm_outcome.packet) {
            Ok(s) => s,
            Err(e) => {
                had_stream_error = true;
                let err_str = e.to_string();
                if err_str.contains("budget") || err_str.contains("capacity") {
                    had_flow_budget_exhaustion = true;
                }
                let _ = diag_emitter.emit_diagnostic(&format!(
                    "flow reconstruction error on packet {}: {e}",
                    record.ordinal
                ));
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
                        had_partial_data = true;
                        let _ = diag_emitter.emit_diagnostic(&format!(
                            "failed to map flow association on packet {}: {e}",
                            record.ordinal
                        ));
                        ObservationFlowAssociation::Unassociated
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
                let _ = diag_emitter.emit_diagnostic(&format!(
                    "DNS diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ));
            }
            for (idx, obs) in dns_outcome.observations.into_iter().enumerate() {
                if !obs.completeness.is_complete() {
                    had_partial_data = true;
                }
                let sub_idx = match u32::try_from(idx) {
                    Ok(si) => si,
                    Err(_) => {
                        had_partial_data = true;
                        let _ = diag_emitter.emit_diagnostic(&format!(
                            "DNS observation index overflow on packet {}",
                            record.ordinal
                        ));
                        continue;
                    }
                };
                let obs_ref = ObservationReference::new(record.ordinal, ProtocolKind::Dns, sub_idx);
                match ProtocolObservation::try_new(
                    obs_ref,
                    flow_association,
                    ProtocolObservationData::Dns(obs),
                ) {
                    Ok(protocol_obs) => {
                        if !observation_budget_exhausted {
                            if let Err(e) = obs_collection.push(protocol_obs) {
                                observation_budget_exhausted = true;
                                had_partial_data = true;
                                let _ = diag_emitter.emit_diagnostic(&format!(
                                    "observation collection budget exhausted: {e}"
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        had_partial_data = true;
                        let _ = diag_emitter.emit_diagnostic(&format!(
                            "DNS observation construction failed on packet {}: {e}",
                            record.ordinal
                        ));
                    }
                }
            }
        }

        // HTTP parsing
        if options.parse_http {
            let http_outcome = parse_http_packet(&norm_outcome.packet, &http_limits);
            if !http_outcome.diagnostics.is_empty() {
                had_partial_data = true;
            }
            for d in &http_outcome.diagnostics {
                let _ = diag_emitter.emit_diagnostic(&format!(
                    "HTTP diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ));
            }
            for (idx, obs) in http_outcome.observations.into_iter().enumerate() {
                if !obs.completeness.is_complete() {
                    had_partial_data = true;
                }
                let sub_idx = match u32::try_from(idx) {
                    Ok(si) => si,
                    Err(_) => {
                        had_partial_data = true;
                        let _ = diag_emitter.emit_diagnostic(&format!(
                            "HTTP observation index overflow on packet {}",
                            record.ordinal
                        ));
                        continue;
                    }
                };
                let obs_ref =
                    ObservationReference::new(record.ordinal, ProtocolKind::Http, sub_idx);
                match ProtocolObservation::try_new(
                    obs_ref,
                    flow_association,
                    ProtocolObservationData::Http(obs),
                ) {
                    Ok(protocol_obs) => {
                        if !observation_budget_exhausted {
                            if let Err(e) = obs_collection.push(protocol_obs) {
                                observation_budget_exhausted = true;
                                had_partial_data = true;
                                let _ = diag_emitter.emit_diagnostic(&format!(
                                    "observation collection budget exhausted: {e}"
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        had_partial_data = true;
                        let _ = diag_emitter.emit_diagnostic(&format!(
                            "HTTP observation construction failed on packet {}: {e}",
                            record.ordinal
                        ));
                    }
                }
            }
        }

        // TLS parsing
        if options.parse_tls {
            let tls_outcome = parse_tls_packet(&norm_outcome.packet, &tls_limits);
            if !tls_outcome.diagnostics.is_empty() {
                had_partial_data = true;
            }
            for d in &tls_outcome.diagnostics {
                let _ = diag_emitter.emit_diagnostic(&format!(
                    "TLS diagnostic on packet {}: {}",
                    record.ordinal, d.message
                ));
            }
            for (idx, obs) in tls_outcome.observations.into_iter().enumerate() {
                if !obs.completeness.is_complete() {
                    had_partial_data = true;
                }
                let sub_idx = match u32::try_from(idx) {
                    Ok(si) => si,
                    Err(_) => {
                        had_partial_data = true;
                        let _ = diag_emitter.emit_diagnostic(&format!(
                            "TLS observation index overflow on packet {}",
                            record.ordinal
                        ));
                        continue;
                    }
                };
                let obs_ref = ObservationReference::new(record.ordinal, ProtocolKind::Tls, sub_idx);
                match ProtocolObservation::try_new(
                    obs_ref,
                    flow_association,
                    ProtocolObservationData::Tls(obs),
                ) {
                    Ok(protocol_obs) => {
                        if !observation_budget_exhausted {
                            if let Err(e) = obs_collection.push(protocol_obs) {
                                observation_budget_exhausted = true;
                                had_partial_data = true;
                                let _ = diag_emitter.emit_diagnostic(&format!(
                                    "observation collection budget exhausted: {e}"
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        had_partial_data = true;
                        let _ = diag_emitter.emit_diagnostic(&format!(
                            "TLS observation construction failed on packet {}: {e}",
                            record.ordinal
                        ));
                    }
                }
            }
        }
    }

    let reader_outcome = reader.into_outcome();
    for diag in &reader_outcome.diagnostics {
        let _ = diag_emitter.emit_capture_diagnostic(diag);
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
    if !reader_outcome.is_complete() {
        detection_limitations.push(DetectionInputLimitation::CaptureTruncated);
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

        let mut det_registry = DetectorRegistry::default();
        if let Err(e) = det_registry.register(Box::new(PeriodicBeaconingDetector::new())) {
            return Err(AnalysisError::Fatal(format!(
                "failed to register beaconing detector: {e}"
            )));
        }
        if let Err(e) = det_registry.register(Box::new(DnsPossibleTunnelingDetector::new())) {
            return Err(AnalysisError::Fatal(format!(
                "failed to register DNS tunneling detector: {e}"
            )));
        }
        if let Err(e) = det_registry.register(Box::new(DnsLongQueryNameDetector::new())) {
            return Err(AnalysisError::Fatal(format!(
                "failed to register DNS long query detector: {e}"
            )));
        }
        if let Err(e) = det_registry.register(Box::new(RepeatedLowVolumeFlowDetector::new())) {
            return Err(AnalysisError::Fatal(format!(
                "failed to register low-volume flow detector: {e}"
            )));
        }

        let mut corr_registry = CorrelationRegistry::default();
        if let Err(e) = corr_registry.register(Box::new(PossibleC2MultiSignalCorrelator::new())) {
            return Err(AnalysisError::Fatal(format!(
                "failed to register C2 multi-signal correlator: {e}"
            )));
        }

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
