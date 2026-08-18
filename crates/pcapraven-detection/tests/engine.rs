//! Integration tests for detection engine architecture, registry, configuration, and determinism.

use pcapraven_detection::*;
use pcapraven_domain::*;

/// Test-only stub detector that emits zero findings.
struct NoMatchStubDetector {
    metadata: DetectorMetadata,
}

impl NoMatchStubDetector {
    fn new(id_str: &str) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("No Match Stub").unwrap(),
                FindingSummary::try_new("Emits zero findings").unwrap(),
                IncompleteDataPolicy::Skip,
            ),
        }
    }
}

impl Detector for NoMatchStubDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        _parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        Ok(())
    }

    fn evaluate(
        &self,
        _input: &DetectionInput<'_>,
        _parameters: &DetectorParameters,
        _output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        Ok(())
    }
}

/// Test-only stub detector that emits exactly one finding with one supporting evidence.
struct OneFindingStubDetector {
    metadata: DetectorMetadata,
    flow_ord: u64,
}

impl OneFindingStubDetector {
    fn new(id_str: &str, flow_ord: u64) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("One Finding Stub").unwrap(),
                FindingSummary::try_new("Emits one finding").unwrap(),
                IncompleteDataPolicy::Skip,
            ),
            flow_ord,
        }
    }
}

impl Detector for OneFindingStubDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        _parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        Ok(())
    }

    fn evaluate(
        &self,
        _input: &DetectionInput<'_>,
        _parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let subject = FindingSubject::try_new(
            Vec::new(),
            vec![FlowReference::new(self.flow_ord)],
            Vec::new(),
        )
        .unwrap();

        let mut evi_builder = EvidenceDraft::builder(
            EvidenceKind::FlowMeasurement,
            EvidenceDescription::try_new("Supporting flow traffic evidence").unwrap(),
        );
        evi_builder
            .add_flow_reference(FlowReference::new(self.flow_ord))
            .unwrap();
        evi_builder
            .add_measurement(
                EvidenceMeasurement::try_new(
                    EvidenceMetricKey::try_new("flow_ordinal").unwrap(),
                    EvidenceValue::Unsigned(self.flow_ord as u128),
                    EvidenceUnit::Count,
                )
                .unwrap(),
            )
            .unwrap();

        let evi = evi_builder.build().unwrap();

        let draft = FindingDraft::try_new(
            subject,
            FindingTitle::try_new("Detected Stub Finding").unwrap(),
            FindingSummary::try_new("Synthetic stub finding description").unwrap(),
            FindingRationale::try_new("Triggered by test stub logic").unwrap(),
            Severity::Low,
            Confidence::High,
            vec![evi],
        )
        .unwrap();

        output.push(draft)?;
        Ok(())
    }
}

/// Test-only stub detector that emits multi-finding output with multi-evidence.
struct MultiFindingStubDetector {
    metadata: DetectorMetadata,
    count: usize,
    evidence_per_finding: usize,
    reverse_order: bool,
}

impl MultiFindingStubDetector {
    fn new(id_str: &str, count: usize, evidence_per_finding: usize) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("Multi Finding Stub").unwrap(),
                FindingSummary::try_new("Emits multiple findings").unwrap(),
                IncompleteDataPolicy::Skip,
            ),
            count,
            evidence_per_finding,
            reverse_order: false,
        }
    }

    fn new_reversed(id_str: &str, count: usize, evidence_per_finding: usize) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("Multi Finding Stub").unwrap(),
                FindingSummary::try_new("Emits multiple findings").unwrap(),
                IncompleteDataPolicy::Skip,
            ),
            count,
            evidence_per_finding,
            reverse_order: true,
        }
    }
}

impl Detector for MultiFindingStubDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        _parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        Ok(())
    }

    fn evaluate(
        &self,
        _input: &DetectionInput<'_>,
        _parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let indices: Vec<usize> = if self.reverse_order {
            (0..self.count).rev().collect()
        } else {
            (0..self.count).collect()
        };

        for i in indices {
            let flow_ref = FlowReference::new(i as u64);
            let subject = FindingSubject::try_new(Vec::new(), vec![flow_ref], Vec::new()).unwrap();

            let mut evidence = Vec::with_capacity(self.evidence_per_finding);
            for e in 0..self.evidence_per_finding {
                let mut evi_builder = EvidenceDraft::builder(
                    EvidenceKind::FlowMeasurement,
                    EvidenceDescription::try_new(format!("Evidence {e} for finding {i}")).unwrap(),
                );
                evi_builder.add_flow_reference(flow_ref).unwrap();
                evi_builder
                    .add_measurement(
                        EvidenceMeasurement::try_new(
                            EvidenceMetricKey::try_new(format!("metric_{e}")).unwrap(),
                            EvidenceValue::Unsigned(e as u128),
                            EvidenceUnit::Count,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                evidence.push(evi_builder.build().unwrap());
            }

            let draft = FindingDraft::try_new(
                subject,
                FindingTitle::try_new(format!("Finding {i}")).unwrap(),
                FindingSummary::try_new(format!("Summary {i}")).unwrap(),
                FindingRationale::try_new(format!("Rationale {i}")).unwrap(),
                Severity::Low,
                Confidence::Medium,
                evidence,
            )
            .unwrap();

            output.push(draft)?;
        }
        Ok(())
    }
}

/// Test-only stub detector that validates configuration parameters.
struct ParameterValidationStubDetector {
    metadata: DetectorMetadata,
}

impl ParameterValidationStubDetector {
    fn new(id_str: &str) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("Parameter Validation Stub").unwrap(),
                FindingSummary::try_new("Validates threshold parameters").unwrap(),
                IncompleteDataPolicy::Skip,
            ),
        }
    }
}

impl Detector for ParameterValidationStubDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        let min_samples = parameters.get_unsigned("min_samples").ok_or_else(|| {
            DetectorConfigError::MissingRequiredParameter("min_samples".to_string())
        })?;
        if min_samples == 0 {
            return Err(DetectorConfigError::ParameterValueOutOfRange {
                key: "min_samples".to_string(),
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }

    fn evaluate(
        &self,
        _input: &DetectionInput<'_>,
        _parameters: &DetectorParameters,
        _output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        Ok(())
    }
}

/// Test-only stub detector that always returns an internal execution error.
struct FailingStubDetector {
    metadata: DetectorMetadata,
}

impl FailingStubDetector {
    fn new(id_str: &str) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("Failing Stub").unwrap(),
                FindingSummary::try_new("Fails evaluation").unwrap(),
                IncompleteDataPolicy::Skip,
            ),
        }
    }
}

impl Detector for FailingStubDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        _parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        Ok(())
    }

    fn evaluate(
        &self,
        _input: &DetectionInput<'_>,
        _parameters: &DetectorParameters,
        _output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        Err(DetectorExecutionError::internal_error(
            "simulated detector execution error",
        ))
    }
}

/// Test-only stub detector declaring `AllowWithLimitations` policy.
struct IncompleteInputStubDetector {
    metadata: DetectorMetadata,
    include_limitations: bool,
}

impl IncompleteInputStubDetector {
    fn new(id_str: &str, include_limitations: bool) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("Incomplete Input Stub").unwrap(),
                FindingSummary::try_new("Runs on partial input").unwrap(),
                IncompleteDataPolicy::AllowWithLimitations,
            ),
            include_limitations,
        }
    }
}

impl Detector for IncompleteInputStubDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        _parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        Ok(())
    }

    fn evaluate(
        &self,
        _input: &DetectionInput<'_>,
        _parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let subject =
            FindingSubject::try_new(Vec::new(), vec![FlowReference::new(0)], Vec::new()).unwrap();

        let mut evi_builder = EvidenceDraft::builder(
            EvidenceKind::ProtocolFact,
            EvidenceDescription::try_new("Partial analysis evidence").unwrap(),
        );
        evi_builder
            .add_flow_reference(FlowReference::new(0))
            .unwrap();
        if self.include_limitations {
            evi_builder
                .add_limitation(EvidenceLimitation::CaptureTruncated)
                .unwrap();
        }

        let evi = evi_builder.build().unwrap();

        let draft = FindingDraft::try_new(
            subject,
            FindingTitle::try_new("Partial Data Finding").unwrap(),
            FindingSummary::try_new("Found with limitations").unwrap(),
            FindingRationale::try_new("Rationale under partial data").unwrap(),
            Severity::Medium,
            Confidence::Low,
            vec![evi],
        )
        .unwrap();

        output.push(draft)?;
        Ok(())
    }
}

fn create_synthetic_flow(ordinal: u64) -> FlowRecord {
    let key = FlowKey::new(
        TransportProtocol::Tcp,
        FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 1]), 10000),
        FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 2]), 80),
    );
    let pkt = PacketReference::new(ordinal, None, None, 100, 100, false);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let inter_arrival = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        unavail,
        FlowTimestampCoverage::default(),
        inter_arrival.clone(),
        inter_arrival.clone(),
        inter_arrival.clone(),
        inter_arrival,
    );

    FlowRecord::new(
        FlowReference::new(ordinal),
        key,
        pkt,
        pkt,
        FlowEndReason::EndOfInput,
        FlowTrafficStatistics::new(
            FlowTrafficCounters::new(10, 1000, 1000, 0),
            FlowTrafficCounters::new(5, 500, 500, 0),
            FlowTrafficCounters::new(5, 500, 500, 0),
            FlowTrafficCounters::new(0, 0, 0, 0),
        ),
        temporal,
    )
}

#[test]
fn test_detector_id_validation() {
    assert!(DetectorId::try_new("test.synthetic.detector").is_ok());
    assert!(DetectorId::try_new("company.product.sub_module-1").is_ok());

    // Empty rejected
    assert_eq!(
        DetectorId::try_new("").unwrap_err(),
        FindingValidationError::EmptyDetectorId
    );

    // Single segment (no namespace dot) rejected
    assert_eq!(
        DetectorId::try_new("detector").unwrap_err(),
        FindingValidationError::InvalidDetectorIdNamespace
    );

    // Uppercase rejected
    assert_eq!(
        DetectorId::try_new("Test.Detector").unwrap_err(),
        FindingValidationError::InvalidDetectorIdCharacter { character: 'T' }
    );

    // Max length 96 accepted, 97 rejected
    let long_valid = format!("test.{}", "a".repeat(91));
    assert_eq!(long_valid.len(), 96);
    assert!(DetectorId::try_new(&long_valid).is_ok());

    let too_long = format!("test.{}", "a".repeat(92));
    assert!(DetectorId::try_new(&too_long).is_err());
}

#[test]
fn test_detector_version() {
    let v1 = DetectorVersion::new(1, 2, 3);
    assert_eq!(v1.major, 1);
    assert_eq!(v1.minor, 2);
    assert_eq!(v1.patch, 3);
    assert_eq!(v1.to_string(), "v1.2.3");

    let v_max = DetectorVersion::new(u16::MAX, u16::MAX, u16::MAX);
    assert_eq!(
        v_max.to_string(),
        format!("v{}.{}.{}", u16::MAX, u16::MAX, u16::MAX)
    );
}

#[test]
fn test_detection_limits_validation() {
    // Default is valid
    let def = DetectionLimits::default();
    assert_eq!(def.max_registered_detectors(), 64);
    assert_eq!(def.max_parameters_per_detector(), 32);
    assert_eq!(def.max_total_findings(), 10_000);
    assert_eq!(def.max_total_evidence_records(), 50_000);
    assert_eq!(def.max_execution_diagnostics(), 256);

    // Exact hard maximums accepted
    let hard = DetectionLimits::try_new(256, 256, 100_000, 500_000, 4_096).unwrap();
    assert_eq!(hard.max_registered_detectors(), 256);
    assert_eq!(hard.max_parameters_per_detector(), 256);
    assert_eq!(hard.max_total_findings(), 100_000);
    assert_eq!(hard.max_total_evidence_records(), 500_000);
    assert_eq!(hard.max_execution_diagnostics(), 4_096);

    // Hard maximum + 1 rejected
    assert!(DetectionLimits::try_new(257, 32, 10_000, 50_000, 256).is_err());
    assert!(DetectionLimits::try_new(64, 257, 10_000, 50_000, 256).is_err());
    assert!(DetectionLimits::try_new(64, 32, 100_001, 50_000, 256).is_err());
    assert!(DetectionLimits::try_new(64, 32, 10_000, 500_001, 256).is_err());
    assert!(DetectionLimits::try_new(64, 32, 10_000, 50_000, 4_097).is_err());

    // Zero limit rejected
    assert_eq!(
        DetectionLimits::try_new(0, 32, 10_000, 50_000, 256).unwrap_err(),
        DetectionLimitsValidationError::ZeroLimit("max_registered_detectors")
    );
    assert_eq!(
        DetectionLimits::try_new(64, 0, 10_000, 50_000, 256).unwrap_err(),
        DetectionLimitsValidationError::ZeroLimit("max_parameters_per_detector")
    );
    assert_eq!(
        DetectionLimits::try_new(64, 32, 0, 50_000, 256).unwrap_err(),
        DetectionLimitsValidationError::ZeroLimit("max_total_findings")
    );
    assert_eq!(
        DetectionLimits::try_new(64, 32, 10_000, 0, 256).unwrap_err(),
        DetectionLimitsValidationError::ZeroLimit("max_total_evidence_records")
    );
    assert_eq!(
        DetectionLimits::try_new(64, 32, 10_000, 50_000, 0).unwrap_err(),
        DetectionLimitsValidationError::ZeroLimit("max_execution_diagnostics")
    );

    // Builder methods
    let b = DetectionLimits::builder()
        .max_registered_detectors(10)
        .max_parameters_per_detector(5)
        .max_total_findings(100)
        .max_total_evidence_records(500)
        .max_execution_diagnostics(20)
        .build()
        .unwrap();
    assert_eq!(b.max_registered_detectors(), 10);
    assert_eq!(b.max_parameters_per_detector(), 5);
}

#[test]
fn test_detector_registry_validation_and_ordering() {
    // Zero capacity rejected
    assert_eq!(
        DetectorRegistry::new(0).unwrap_err(),
        DetectorRegistryError::ZeroRegistryCapacity
    );

    // Hard maximum 256 accepted, 257 rejected
    assert!(DetectorRegistry::new(256).is_ok());
    assert_eq!(
        DetectorRegistry::new(257).unwrap_err(),
        DetectorRegistryError::RegistryCapacityAboveHardMaximum {
            attempted: 257,
            max: 256
        }
    );

    let mut registry = DetectorRegistry::default();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);

    let d_b = NoMatchStubDetector::new("test.b_detector");
    let d_a = NoMatchStubDetector::new("test.a_detector");
    let d_c = NoMatchStubDetector::new("test.c_detector");

    // Register in reverse order: b, a, c
    registry.register(Box::new(d_b)).unwrap();
    registry.register(Box::new(d_a)).unwrap();
    registry.register(Box::new(d_c)).unwrap();

    assert_eq!(registry.len(), 3);

    // Iteration must be deterministically sorted by DetectorId (a, b, c)
    let ids: Vec<String> = registry
        .iter()
        .map(|d| d.metadata().id().to_string())
        .collect();
    assert_eq!(
        ids,
        vec!["test.a_detector", "test.b_detector", "test.c_detector"]
    );

    // Duplicate registration rejected
    let dup = NoMatchStubDetector::new("test.a_detector");
    assert_eq!(
        registry.register(Box::new(dup)).unwrap_err(),
        DetectorRegistryError::DuplicateDetectorId(DetectorId::try_new("test.a_detector").unwrap())
    );
}

#[test]
fn test_detector_configurations_bounds_and_unknown_rejection() {
    let mut configs = DetectorConfigurations::new();
    assert!(configs.is_empty());
    assert_eq!(configs.len(), 0);

    // Insert 256 configurations successfully
    for i in 0..256 {
        let id = DetectorId::try_new(format!("test.detector_{i:03}")).unwrap();
        configs.insert(id, DetectorConfig::enabled()).unwrap();
    }
    assert_eq!(configs.len(), 256);

    // 257th insertion rejected
    let extra_id = DetectorId::try_new("test.detector_extra").unwrap();
    assert_eq!(
        configs
            .insert(extra_id, DetectorConfig::enabled())
            .unwrap_err(),
        DetectorConfigError::ConfigurationsExceeded {
            count: 257,
            max: 256
        }
    );

    // Replacing existing entry does not increase count and succeeds
    let existing_id = DetectorId::try_new("test.detector_000").unwrap();
    assert!(
        configs
            .insert(existing_id, DetectorConfig::disabled())
            .is_ok()
    );
    assert_eq!(configs.len(), 256);

    // Preflight rejects unregistered detector configurations before evaluating anything
    let mut small_configs = DetectorConfigurations::new();
    let unreg_id = DetectorId::try_new("test.unregistered_detector").unwrap();
    small_configs
        .insert(unreg_id.clone(), DetectorConfig::enabled())
        .unwrap();

    let registry = DetectorRegistry::default();
    let flows = vec![create_synthetic_flow(0)];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let limits = DetectionLimits::default();

    let err = execute_detection(&registry, &input, &small_configs, &limits).unwrap_err();
    assert_eq!(
        err,
        DetectionEngineError::Config(DetectorConfigError::UnregisteredDetector(unreg_id))
    );
}

#[test]
fn test_detection_input_validation() {
    let flows = vec![create_synthetic_flow(0), create_synthetic_flow(1)];
    let limits = [DetectionInputLimitation::CaptureTruncated];

    // Complete input with no limitations is valid
    assert!(
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).is_ok()
    );

    // Partial input with limitations is valid
    assert!(
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Partial, &limits).is_ok()
    );

    // Complete input with limitations is rejected
    assert_eq!(
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &limits)
            .unwrap_err(),
        DetectionInputError::CompleteInputWithLimitations
    );

    // Partial input without limitations is rejected
    assert_eq!(
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Partial, &[]).unwrap_err(),
        DetectionInputError::PartialInputWithoutLimitations
    );

    // Duplicate flow ordinal is rejected
    let dup_flows = vec![create_synthetic_flow(0), create_synthetic_flow(0)];
    assert_eq!(
        DetectionInput::try_new(&dup_flows, &[], DetectionInputCompleteness::Complete, &[])
            .unwrap_err(),
        DetectionInputError::DuplicateFlow(FlowReference::new(0))
    );

    // Out-of-order flow ordinal is rejected
    let ooo_flows = vec![create_synthetic_flow(2), create_synthetic_flow(1)];
    assert_eq!(
        DetectionInput::try_new(&ooo_flows, &[], DetectionInputCompleteness::Complete, &[])
            .unwrap_err(),
        DetectionInputError::OutOfOrderFlow {
            previous: 2,
            attempted: 1
        }
    );
}

#[test]
fn test_parameter_collection_and_builder() {
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("a_bool").unwrap(),
            DetectorParameterValue::Boolean(true),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("b_uint").unwrap(),
            DetectorParameterValue::Unsigned(42),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("c_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(3, 4).unwrap()),
        )
        .unwrap();

    // Duplicate key rejected
    assert_eq!(
        builder
            .add(
                DetectorParameterKey::try_new("c_ratio").unwrap(),
                DetectorParameterValue::Unsigned(10),
            )
            .unwrap_err(),
        DetectorConfigError::DuplicateParameterKey("c_ratio".to_string())
    );

    // Out of order key rejected
    assert_eq!(
        builder
            .add(
                DetectorParameterKey::try_new("a_first").unwrap(),
                DetectorParameterValue::Unsigned(10),
            )
            .unwrap_err(),
        DetectorConfigError::OutOfOrderParameterKey {
            previous: "c_ratio".to_string(),
            attempted: "a_first".to_string(),
        }
    );

    let params = builder.build().unwrap();
    assert_eq!(params.len(), 3);
    assert_eq!(params.get_bool("a_bool"), Some(true));
    assert_eq!(params.get_unsigned("b_uint"), Some(42));
    assert_eq!(
        params.get_ratio("c_ratio"),
        Some(EvidenceRatio::from_fraction(3, 4).unwrap())
    );
    assert_eq!(params.get("unknown"), None);
}

#[test]
fn test_whole_configuration_preflight_transactionality() {
    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.a_detector", 0)))
        .unwrap();
    registry
        .register(Box::new(ParameterValidationStubDetector::new(
            "test.b_detector",
        )))
        .unwrap();

    let flows = vec![create_synthetic_flow(0)];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let limits = DetectionLimits::default();

    // Configuration with invalid parameter for detector B (min_samples == 0)
    let mut configs = DetectorConfigurations::new();
    let mut bad_params = DetectorParameters::builder();
    bad_params
        .add(
            DetectorParameterKey::try_new("min_samples").unwrap(),
            DetectorParameterValue::Unsigned(0),
        )
        .unwrap();
    configs
        .insert(
            DetectorId::try_new("test.b_detector").unwrap(),
            DetectorConfig::new(true, bad_params.build().unwrap()),
        )
        .unwrap();

    // Execution must fail preflight BEFORE evaluating detector A!
    let err = execute_detection(&registry, &input, &configs, &limits).unwrap_err();
    assert_eq!(
        err,
        DetectionEngineError::Config(DetectorConfigError::ParameterValueOutOfRange {
            key: "min_samples".to_string(),
            reason: "must be greater than zero",
        })
    );
}

#[test]
fn test_disabled_detector_behavior() {
    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.a_detector", 0)))
        .unwrap();

    let flows = vec![create_synthetic_flow(0)];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let limits = DetectionLimits::default();

    let mut configs = DetectorConfigurations::new();
    configs
        .insert(
            DetectorId::try_new("test.a_detector").unwrap(),
            DetectorConfig::disabled(),
        )
        .unwrap();

    let outcome = execute_detection(&registry, &input, &configs, &limits).unwrap();
    assert_eq!(outcome.findings.len(), 0);
    assert_eq!(outcome.evidence.len(), 0);
    assert_eq!(outcome.detector_executions.len(), 1);
    assert_eq!(
        outcome.detector_executions[0].status,
        DetectorExecutionStatus::Disabled
    );
}

#[test]
fn test_incomplete_data_skip_and_allow_policies() {
    let mut registry = DetectorRegistry::default();
    // Detector 1 has Skip policy
    registry
        .register(Box::new(OneFindingStubDetector::new(
            "test.skip_detector",
            0,
        )))
        .unwrap();
    // Detector 2 has AllowWithLimitations policy
    registry
        .register(Box::new(IncompleteInputStubDetector::new(
            "test.allow_detector",
            true,
        )))
        .unwrap();

    let flows = vec![create_synthetic_flow(0)];
    let partial_input = DetectionInput::try_new(
        &flows,
        &[],
        DetectionInputCompleteness::Partial,
        &[DetectionInputLimitation::CaptureTruncated],
    )
    .unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let outcome = execute_detection(&registry, &partial_input, &configs, &limits).unwrap();
    assert_eq!(outcome.completion, DetectionInputCompleteness::Partial);
    assert_eq!(outcome.detector_executions.len(), 2);

    // Skip detector was skipped
    assert_eq!(
        outcome.detector_executions[1].status,
        DetectorExecutionStatus::SkippedIncompleteData
    );

    // Allow detector was executed and finding produced
    assert_eq!(
        outcome.detector_executions[0].status,
        DetectorExecutionStatus::Executed
    );
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.evidence.len(), 1);
    assert_eq!(outcome.evidence[0].limitations().len(), 1);
}

#[test]
fn test_incomplete_data_policy_violation_rejected() {
    let mut registry = DetectorRegistry::default();
    // AllowWithLimitations detector emitting finding WITHOUT limitations on partial input
    registry
        .register(Box::new(IncompleteInputStubDetector::new(
            "test.bad_allow_detector",
            false,
        )))
        .unwrap();

    let flows = vec![create_synthetic_flow(0)];
    let partial_input = DetectionInput::try_new(
        &flows,
        &[],
        DetectionInputCompleteness::Partial,
        &[DetectionInputLimitation::CaptureTruncated],
    )
    .unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let err = execute_detection(&registry, &partial_input, &configs, &limits).unwrap_err();
    assert_eq!(
        err,
        DetectionEngineError::Output(DetectionOutputError::IncompleteDataPolicyViolation {
            detector_id: DetectorId::try_new("test.bad_allow_detector").unwrap(),
            reason: "finding emitted on partial input without required input limitation evidence",
        })
    );
}

#[test]
fn test_detector_execution_error_isolation() {
    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.a_detector", 0)))
        .unwrap();
    registry
        .register(Box::new(FailingStubDetector::new("test.b_failing")))
        .unwrap();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.c_detector", 1)))
        .unwrap();

    let flows = vec![create_synthetic_flow(0), create_synthetic_flow(1)];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let outcome = execute_detection(&registry, &input, &configs, &limits).unwrap();
    // Overall run became Partial due to detector failure
    assert_eq!(outcome.completion, DetectionInputCompleteness::Partial);
    assert_eq!(outcome.detector_executions.len(), 3);
    assert_eq!(
        outcome.detector_executions[0].status,
        DetectorExecutionStatus::Executed
    );
    assert_eq!(
        outcome.detector_executions[1].status,
        DetectorExecutionStatus::Failed {
            reason: "simulated detector execution error".to_string()
        }
    );
    assert_eq!(
        outcome.detector_executions[2].status,
        DetectorExecutionStatus::Executed
    );

    // Findings from A and C are preserved
    assert_eq!(outcome.findings.len(), 2);
    assert_eq!(
        outcome.findings[0].detector_id().as_str(),
        "test.a_detector"
    );
    assert_eq!(
        outcome.findings[1].detector_id().as_str(),
        "test.c_detector"
    );
}

#[test]
fn test_finding_and_evidence_deterministic_identity_and_ordering() {
    let mut reg1 = DetectorRegistry::default();
    reg1.register(Box::new(OneFindingStubDetector::new("test.b_detector", 1)))
        .unwrap();
    reg1.register(Box::new(OneFindingStubDetector::new("test.a_detector", 0)))
        .unwrap();

    let mut reg2 = DetectorRegistry::default();
    reg2.register(Box::new(OneFindingStubDetector::new("test.a_detector", 0)))
        .unwrap();
    reg2.register(Box::new(OneFindingStubDetector::new("test.b_detector", 1)))
        .unwrap();

    let flows = vec![create_synthetic_flow(0), create_synthetic_flow(1)];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let outcome1 = execute_detection(&reg1, &input, &configs, &limits).unwrap();
    let outcome2 = execute_detection(&reg2, &input, &configs, &limits).unwrap();

    // Exact bit-for-bit equivalence regardless of registration order
    assert_eq!(outcome1.findings.len(), 2);
    assert_eq!(outcome2.findings.len(), 2);

    assert_eq!(outcome1.findings[0].reference(), FindingReference::new(0));
    assert_eq!(
        outcome1.findings[0].detector_id().as_str(),
        "test.a_detector"
    );
    assert_eq!(outcome1.findings[1].reference(), FindingReference::new(1));
    assert_eq!(
        outcome1.findings[1].detector_id().as_str(),
        "test.b_detector"
    );

    assert_eq!(outcome1.evidence[0].reference(), EvidenceReference::new(0));
    assert_eq!(outcome1.evidence[1].reference(), EvidenceReference::new(1));

    assert_eq!(outcome1.findings, outcome2.findings);
    assert_eq!(outcome1.evidence, outcome2.evidence);
}

#[test]
fn test_referential_integrity_unknown_flow_rejected() {
    let mut registry = DetectorRegistry::default();
    // Detector referencing flow 99 which does NOT exist in input
    registry
        .register(Box::new(OneFindingStubDetector::new("test.dangling", 99)))
        .unwrap();

    let flows = vec![create_synthetic_flow(0)];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let err = execute_detection(&registry, &input, &configs, &limits).unwrap_err();
    assert!(matches!(
        err,
        DetectionEngineError::Output(DetectionOutputError::ReferentialIntegrityError(_))
    ));
}

#[test]
fn test_finding_record_strict_evidence_reference_order() {
    let finding_ref = FindingReference::new(0);
    let detector_id = DetectorId::try_new("test.detector").unwrap();
    let version = DetectorVersion::new(1, 0, 0);
    let subject =
        FindingSubject::try_new(Vec::new(), vec![FlowReference::new(0)], Vec::new()).unwrap();
    let title = FindingTitle::try_new("Title").unwrap();
    let summary = FindingSummary::try_new("Summary").unwrap();
    let rationale = FindingRationale::try_new("Rationale").unwrap();

    // Strictly increasing accepted
    let valid_refs = vec![EvidenceReference::new(0), EvidenceReference::new(1)];
    assert!(
        FindingRecord::try_new(
            finding_ref,
            detector_id.clone(),
            version,
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Low,
            Confidence::Medium,
            valid_refs
        )
        .is_ok()
    );

    // Duplicate evidence ref rejected
    let dup_refs = vec![EvidenceReference::new(1), EvidenceReference::new(1)];
    assert_eq!(
        FindingRecord::try_new(
            finding_ref,
            detector_id.clone(),
            version,
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Low,
            Confidence::Medium,
            dup_refs
        )
        .unwrap_err(),
        FindingValidationError::DuplicateEvidenceReference(EvidenceReference::new(1))
    );

    // Descending evidence ref rejected
    let desc_refs = vec![EvidenceReference::new(2), EvidenceReference::new(1)];
    assert_eq!(
        FindingRecord::try_new(
            finding_ref,
            detector_id,
            version,
            subject,
            title,
            summary,
            rationale,
            Severity::Low,
            Confidence::Medium,
            desc_refs
        )
        .unwrap_err(),
        FindingValidationError::OutOfOrderEvidenceReference {
            previous: 2,
            attempted: 1
        }
    );
}

#[test]
fn test_transactional_output_acceptance_and_resource_bounds() {
    let mut registry = DetectorRegistry::default();
    // Detector 1 emits 2 findings (2 evidence)
    registry
        .register(Box::new(MultiFindingStubDetector::new(
            "test.detector_a",
            2,
            1,
        )))
        .unwrap();
    // Detector 2 emits 3 findings (3 evidence) - will exceed finding limit of 4
    registry
        .register(Box::new(MultiFindingStubDetector::new(
            "test.detector_b",
            3,
            1,
        )))
        .unwrap();
    // Detector 3 emits 1 finding (1 evidence) - will fit remaining budget (2 + 1 = 3 <= 4)
    registry
        .register(Box::new(OneFindingStubDetector::new("test.detector_c", 0)))
        .unwrap();

    let flows = vec![
        create_synthetic_flow(0),
        create_synthetic_flow(1),
        create_synthetic_flow(2),
    ];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::builder()
        .max_total_findings(4)
        .max_total_evidence_records(10)
        .build()
        .unwrap();

    let outcome = execute_detection(&registry, &input, &configs, &limits).unwrap();
    assert_eq!(outcome.completion, DetectionInputCompleteness::Partial);
    assert_eq!(outcome.detector_executions.len(), 3);
    assert_eq!(
        outcome.detector_executions[0].status,
        DetectorExecutionStatus::Executed
    );
    // Detector B rejected transactionally (none of its findings or evidence were partially accepted)
    assert_eq!(
        outcome.detector_executions[1].status,
        DetectorExecutionStatus::ResourceLimited
    );
    // Detector C accepted
    assert_eq!(
        outcome.detector_executions[2].status,
        DetectorExecutionStatus::Executed
    );

    // Findings are contiguous: find:0, find:1 from A, and find:2 from C!
    assert_eq!(outcome.findings.len(), 3);
    assert_eq!(outcome.findings[0].reference(), FindingReference::new(0));
    assert_eq!(
        outcome.findings[0].detector_id().as_str(),
        "test.detector_a"
    );
    assert_eq!(outcome.findings[1].reference(), FindingReference::new(1));
    assert_eq!(
        outcome.findings[1].detector_id().as_str(),
        "test.detector_a"
    );
    assert_eq!(outcome.findings[2].reference(), FindingReference::new(2));
    assert_eq!(
        outcome.findings[2].detector_id().as_str(),
        "test.detector_c"
    );

    // Evidence records are contiguous: evi:0, evi:1 from A, and evi:2 from C!
    assert_eq!(outcome.evidence.len(), 3);
    assert_eq!(outcome.evidence[0].reference(), EvidenceReference::new(0));
    assert_eq!(outcome.evidence[1].reference(), EvidenceReference::new(1));
    assert_eq!(outcome.evidence[2].reference(), EvidenceReference::new(2));
}

#[test]
fn test_finding_text_validations() {
    assert!(FindingTitle::try_new("Valid Title").is_ok());
    assert_eq!(
        FindingTitle::try_new("").unwrap_err(),
        FindingValidationError::EmptyFindingTitle
    );
    assert_eq!(
        FindingTitle::try_new("Title with \x00 null").unwrap_err(),
        FindingValidationError::FindingTitleControlCharacter { byte: 0 }
    );

    assert!(FindingSummary::try_new("Valid Summary").is_ok());
    assert_eq!(
        FindingSummary::try_new("").unwrap_err(),
        FindingValidationError::EmptyFindingSummary
    );
    assert_eq!(
        FindingSummary::try_new("Summary with \x1b esc").unwrap_err(),
        FindingValidationError::FindingSummaryControlCharacter { byte: 27 }
    );

    assert!(FindingRationale::try_new("Valid Rationale").is_ok());
    assert_eq!(
        FindingRationale::try_new("").unwrap_err(),
        FindingValidationError::EmptyFindingRationale
    );
}

#[test]
fn test_finding_subject_validations() {
    // Empty subject rejected
    assert_eq!(
        FindingSubject::try_new(Vec::new(), Vec::new(), Vec::new()).unwrap_err(),
        FindingValidationError::EmptyFindingSubject
    );

    let pkt1 = PacketReference::new(1, None, None, 100, 100, false);
    let pkt2 = PacketReference::new(2, None, None, 100, 100, false);

    // Duplicate packet rejected
    assert_eq!(
        FindingSubject::try_new(vec![pkt1, pkt1], Vec::new(), Vec::new()).unwrap_err(),
        FindingValidationError::DuplicateSubjectPacketReference(pkt1)
    );

    // Out of order packet rejected
    assert_eq!(
        FindingSubject::try_new(vec![pkt2, pkt1], Vec::new(), Vec::new()).unwrap_err(),
        FindingValidationError::OutOfOrderSubjectPacketReference {
            previous: 2,
            attempted: 1
        }
    );

    // Valid subject accepted
    let subj = FindingSubject::try_new(vec![pkt1, pkt2], Vec::new(), Vec::new()).unwrap();
    assert_eq!(subj.packet_references().len(), 2);
}

#[test]
fn test_canonical_draft_sorting_invariance() {
    let mut reg_forward = DetectorRegistry::default();
    reg_forward
        .register(Box::new(MultiFindingStubDetector::new(
            "test.detector",
            3,
            2,
        )))
        .unwrap();

    let mut reg_reversed = DetectorRegistry::default();
    reg_reversed
        .register(Box::new(MultiFindingStubDetector::new_reversed(
            "test.detector",
            3,
            2,
        )))
        .unwrap();

    let flows = vec![
        create_synthetic_flow(0),
        create_synthetic_flow(1),
        create_synthetic_flow(2),
    ];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let outcome_forward = execute_detection(&reg_forward, &input, &configs, &limits).unwrap();
    let outcome_reversed = execute_detection(&reg_reversed, &input, &configs, &limits).unwrap();

    assert_eq!(outcome_forward.findings, outcome_reversed.findings);
    assert_eq!(outcome_forward.evidence, outcome_reversed.evidence);
}

#[test]
fn test_detector_draft_sink_capacity_enforcement() {
    // Sink with max 2 findings, max 3 evidence
    let mut sink = DetectorDraftSink::new(2, 3);
    assert_eq!(sink.len(), 0);
    assert_eq!(sink.evidence_count(), 0);
    assert!(sink.is_empty());

    let subject0 =
        FindingSubject::try_new(Vec::new(), vec![FlowReference::new(0)], Vec::new()).unwrap();
    let subject1 =
        FindingSubject::try_new(Vec::new(), vec![FlowReference::new(1)], Vec::new()).unwrap();
    let subject2 =
        FindingSubject::try_new(Vec::new(), vec![FlowReference::new(2)], Vec::new()).unwrap();

    let mut evi_builder = EvidenceDraft::builder(
        EvidenceKind::FlowMeasurement,
        EvidenceDescription::try_new("evidence").unwrap(),
    );
    evi_builder
        .add_flow_reference(FlowReference::new(0))
        .unwrap();
    let evi1 = evi_builder.build().unwrap();

    let draft0 = FindingDraft::try_new(
        subject0,
        FindingTitle::try_new("title").unwrap(),
        FindingSummary::try_new("summary").unwrap(),
        FindingRationale::try_new("rationale").unwrap(),
        Severity::Low,
        Confidence::Medium,
        vec![evi1.clone(), evi1.clone()],
    )
    .unwrap();

    // Push 1 draft with 2 evidence -> total 1 finding, 2 evidence (fits)
    assert!(sink.push(draft0).is_ok());
    assert_eq!(sink.len(), 1);
    assert_eq!(sink.evidence_count(), 2);

    let draft1_overflow_evidence = FindingDraft::try_new(
        subject1.clone(),
        FindingTitle::try_new("title").unwrap(),
        FindingSummary::try_new("summary").unwrap(),
        FindingRationale::try_new("rationale").unwrap(),
        Severity::Low,
        Confidence::Medium,
        vec![evi1.clone(), evi1.clone()],
    )
    .unwrap();

    // Push second draft with 2 evidence -> 2+2 = 4 > 3 evidence max -> rejected
    let err = sink.push(draft1_overflow_evidence).unwrap_err();
    assert_eq!(
        err,
        DetectorExecutionError::resource_limit("detector draft evidence budget exceeded")
    );
    assert_eq!(sink.len(), 1);
    assert_eq!(sink.evidence_count(), 2);

    let draft1_fitting = FindingDraft::try_new(
        subject1,
        FindingTitle::try_new("title").unwrap(),
        FindingSummary::try_new("summary").unwrap(),
        FindingRationale::try_new("rationale").unwrap(),
        Severity::Low,
        Confidence::Medium,
        vec![evi1.clone()],
    )
    .unwrap();

    // Push second draft with 1 evidence -> 2+1 = 3 <= 3 evidence max -> accepted
    assert!(sink.push(draft1_fitting).is_ok());
    assert_eq!(sink.len(), 2);
    assert_eq!(sink.evidence_count(), 3);

    let draft2_overflow_findings = FindingDraft::try_new(
        subject2,
        FindingTitle::try_new("title").unwrap(),
        FindingSummary::try_new("summary").unwrap(),
        FindingRationale::try_new("rationale").unwrap(),
        Severity::Low,
        Confidence::Medium,
        vec![evi1],
    )
    .unwrap();

    // Push third draft -> 3 > 2 findings max -> rejected
    let err2 = sink.push(draft2_overflow_findings).unwrap_err();
    assert_eq!(
        err2,
        DetectorExecutionError::resource_limit("detector draft finding budget exceeded")
    );
    assert_eq!(sink.len(), 2);
}

#[test]
fn test_detector_error_sanitizer_bounds_and_unicode_controls() {
    // 1. Empty message returns "unspecified error"
    let err_empty = DetectorExecutionError::internal_error("");
    assert_eq!(
        err_empty,
        DetectorExecutionError::InternalError("unspecified error".to_string())
    );

    // 2. Control characters (NUL, ESC, CR, LF, non-ASCII controls) replaced with ' '
    let raw_controls = "Error\x00with\x1bcontrol\r\nand\u{0080}unicode\u{009F}controls";
    let err_controls = DetectorExecutionError::internal_error(raw_controls);
    if let DetectorExecutionError::InternalError(clean) = err_controls {
        assert!(!clean.contains('\x00'));
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\n'));
        assert!(!clean.contains('\u{0080}'));
        assert!(!clean.contains('\u{009F}'));
        assert_eq!(clean, "Error with control  and unicode controls");
    } else {
        panic!("unexpected error variant");
    }

    // 3. 511 ASCII chars + 2-byte char -> 2-byte char cannot fit in 512, so length is exactly 511 bytes
    let msg_511_plus_2 = format!("{}é", "a".repeat(511));
    let err_511 = DetectorExecutionError::internal_error(&msg_511_plus_2);
    if let DetectorExecutionError::InternalError(clean) = err_511 {
        assert_eq!(clean.len(), 511);
        assert_eq!(clean, "a".repeat(511));
    } else {
        panic!("unexpected error variant");
    }

    // 4. 510 ASCII chars + 2-byte char -> exactly 512 bytes
    let msg_510_plus_2 = format!("{}é", "a".repeat(510));
    let err_510 = DetectorExecutionError::internal_error(&msg_510_plus_2);
    if let DetectorExecutionError::InternalError(clean) = err_510 {
        assert_eq!(clean.len(), 512);
        assert!(clean.ends_with('é'));
    } else {
        panic!("unexpected error variant");
    }

    // 5. Multibyte Unicode near limit (3-byte characters)
    let msg_multibyte = "€".repeat(200); // 200 * 3 = 600 bytes
    let err_multibyte = DetectorExecutionError::resource_limit(&msg_multibyte);
    if let DetectorExecutionError::ResourceLimitExceeded(clean) = err_multibyte {
        assert!(clean.len() <= MAX_DETECTOR_ERROR_MESSAGE_LENGTH);
        assert_eq!(clean.len(), 510); // 170 * 3 = 510 bytes (171st would be 513 > 512)
    } else {
        panic!("unexpected error variant");
    }
}
