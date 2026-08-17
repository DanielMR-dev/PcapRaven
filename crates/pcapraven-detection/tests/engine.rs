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
    ) -> Result<Vec<FindingDraft>, DetectorExecutionError> {
        Ok(Vec::new())
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
    ) -> Result<Vec<FindingDraft>, DetectorExecutionError> {
        let subject = FindingSubject::try_new(
            Vec::new(),
            vec![FlowReference::new(self.flow_ord)],
            Vec::new(),
        )
        .unwrap();

        let mut evi_builder = EvidenceRecord::builder(
            EvidenceReference::new(0),
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

        Ok(vec![FindingDraft {
            detector_id: self.metadata.id().clone(),
            detector_version: self.metadata.version(),
            subject,
            title: FindingTitle::try_new("Detected Stub Finding").unwrap(),
            summary: FindingSummary::try_new("Synthetic stub finding description").unwrap(),
            rationale: FindingRationale::try_new("Triggered by test stub logic").unwrap(),
            severity: Severity::Low,
            confidence: Confidence::High,
            evidence: vec![evi],
        }])
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
    ) -> Result<Vec<FindingDraft>, DetectorExecutionError> {
        Ok(Vec::new())
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
    ) -> Result<Vec<FindingDraft>, DetectorExecutionError> {
        Err(DetectorExecutionError::InternalError(
            "simulated detector execution error".to_string(),
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
    ) -> Result<Vec<FindingDraft>, DetectorExecutionError> {
        let subject =
            FindingSubject::try_new(Vec::new(), vec![FlowReference::new(0)], Vec::new()).unwrap();

        let mut evi_builder = EvidenceRecord::builder(
            EvidenceReference::new(0),
            EvidenceKind::ProtocolFact,
            EvidenceDescription::try_new("Partial analysis evidence").unwrap(),
        );
        evi_builder
            .add_flow_reference(FlowReference::new(0))
            .unwrap();
        if self.include_limitations {
            evi_builder
                .add_limitation(EvidenceLimitation::TruncatedPayload)
                .unwrap();
        }

        let evi = evi_builder.build().unwrap();

        Ok(vec![FindingDraft {
            detector_id: self.metadata.id().clone(),
            detector_version: self.metadata.version(),
            subject,
            title: FindingTitle::try_new("Partial Data Finding").unwrap(),
            summary: FindingSummary::try_new("Found with limitations").unwrap(),
            rationale: FindingRationale::try_new("Rationale under partial data").unwrap(),
            severity: Severity::Medium,
            confidence: Confidence::Low,
            evidence: vec![evi],
        }])
    }
}

fn create_synthetic_flow(ordinal: u64) -> FlowRecord {
    let key = FlowKey::new(
        TransportProtocol::Tcp,
        FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 1]), 10000),
        FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 2]), 80),
    );
    let pkt = PacketReference::new(0, None, None, 100, 100, false);
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
fn test_registry_ordering_and_duplicate_rejection() {
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
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
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
    configs.insert(
        DetectorId::try_new("test.b_detector").unwrap(),
        DetectorConfig::new(true, bad_params.build().unwrap()),
    );

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
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
    let limits = DetectionLimits::default();

    let mut configs = DetectorConfigurations::new();
    configs.insert(
        DetectorId::try_new("test.a_detector").unwrap(),
        DetectorConfig::disabled(),
    );

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
    let partial_input = DetectionInput::new(
        &flows,
        &[],
        DetectionInputCompleteness::Partial,
        &[DetectionInputLimitation::CaptureTruncated],
    );
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
    let partial_input = DetectionInput::new(
        &flows,
        &[],
        DetectionInputCompleteness::Partial,
        &[DetectionInputLimitation::CaptureTruncated],
    );
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let err = execute_detection(&registry, &partial_input, &configs, &limits).unwrap_err();
    assert_eq!(
        err,
        DetectionEngineError::Output(DetectionOutputError::IncompleteDataPolicyViolation {
            detector_id: DetectorId::try_new("test.bad_allow_detector").unwrap(),
            reason: "finding emitted on partial input without supporting limitation evidence",
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
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
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
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
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
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let err = execute_detection(&registry, &input, &configs, &limits).unwrap_err();
    assert!(matches!(
        err,
        DetectionEngineError::Output(DetectionOutputError::ReferentialIntegrityError(_))
    ));
}

/// Test stub that emits two duplicate finding drafts with identical subject.
struct DuplicateDraftsStubDetector {
    metadata: DetectorMetadata,
}

impl DuplicateDraftsStubDetector {
    fn new(id_str: &str) -> Self {
        Self {
            metadata: DetectorMetadata::new(
                DetectorId::try_new(id_str).unwrap(),
                DetectorVersion::new(1, 0, 0),
                FindingTitle::try_new("Duplicate Drafts Stub").unwrap(),
                FindingSummary::try_new("Emits duplicate drafts").unwrap(),
                IncompleteDataPolicy::Skip,
            ),
        }
    }
}

impl Detector for DuplicateDraftsStubDetector {
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
    ) -> Result<Vec<FindingDraft>, DetectorExecutionError> {
        let subject =
            FindingSubject::try_new(Vec::new(), vec![FlowReference::new(0)], Vec::new()).unwrap();

        let mut evi_builder = EvidenceRecord::builder(
            EvidenceReference::new(0),
            EvidenceKind::FlowMeasurement,
            EvidenceDescription::try_new("Supporting evidence").unwrap(),
        );
        evi_builder
            .add_flow_reference(FlowReference::new(0))
            .unwrap();
        evi_builder
            .add_measurement(
                EvidenceMeasurement::try_new(
                    EvidenceMetricKey::try_new("metric_a").unwrap(),
                    EvidenceValue::Unsigned(1),
                    EvidenceUnit::Count,
                )
                .unwrap(),
            )
            .unwrap();
        let evi = evi_builder.build().unwrap();

        let draft1 = FindingDraft {
            detector_id: self.metadata.id().clone(),
            detector_version: self.metadata.version(),
            subject: subject.clone(),
            title: FindingTitle::try_new("Finding 1").unwrap(),
            summary: FindingSummary::try_new("Summary 1").unwrap(),
            rationale: FindingRationale::try_new("Rationale 1").unwrap(),
            severity: Severity::Low,
            confidence: Confidence::Low,
            evidence: vec![evi.clone()],
        };

        let draft2 = FindingDraft {
            detector_id: self.metadata.id().clone(),
            detector_version: self.metadata.version(),
            subject,
            title: FindingTitle::try_new("Finding 2").unwrap(),
            summary: FindingSummary::try_new("Summary 2").unwrap(),
            rationale: FindingRationale::try_new("Rationale 2").unwrap(),
            severity: Severity::Low,
            confidence: Confidence::Low,
            evidence: vec![evi],
        };

        Ok(vec![draft1, draft2])
    }
}

#[test]
fn test_duplicate_finding_identity_rejected() {
    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(DuplicateDraftsStubDetector::new(
            "test.dup_detector",
        )))
        .unwrap();

    let flows = vec![create_synthetic_flow(0)];
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let err = execute_detection(&registry, &input, &configs, &limits).unwrap_err();
    assert_eq!(
        err,
        DetectionEngineError::Output(DetectionOutputError::DuplicateFindingIdentity {
            detector_id: DetectorId::try_new("test.dup_detector").unwrap(),
        })
    );
}

#[test]
fn test_different_detectors_same_subject_accepted() {
    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.detector_a", 0)))
        .unwrap();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.detector_b", 0)))
        .unwrap();

    let flows = vec![create_synthetic_flow(0)];
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let outcome = execute_detection(&registry, &input, &configs, &limits).unwrap();
    assert_eq!(outcome.findings.len(), 2);
    assert_eq!(
        outcome.findings[0].detector_id().as_str(),
        "test.detector_a"
    );
    assert_eq!(
        outcome.findings[1].detector_id().as_str(),
        "test.detector_b"
    );
    assert_eq!(outcome.findings[0].subject(), outcome.findings[1].subject());
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
fn test_findings_resource_limit_truncation() {
    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.detector_1", 0)))
        .unwrap();
    registry
        .register(Box::new(OneFindingStubDetector::new("test.detector_2", 1)))
        .unwrap();

    let flows = vec![create_synthetic_flow(0), create_synthetic_flow(1)];
    let input = DetectionInput::new(&flows, &[], DetectionInputCompleteness::Complete, &[]);
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits {
        max_total_findings: 1,
        ..DetectionLimits::default()
    };

    let outcome = execute_detection(&registry, &input, &configs, &limits).unwrap();
    assert_eq!(outcome.completion, DetectionInputCompleteness::Partial);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(
        outcome.detector_executions[0].status,
        DetectorExecutionStatus::Executed
    );
    assert_eq!(
        outcome.detector_executions[1].status,
        DetectorExecutionStatus::ResourceLimited
    );
}
