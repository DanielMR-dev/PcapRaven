//! Integration tests for Cross-Detector Finding Correlation and Possible C2 Multi-Signal heuristic.

use pcapraven_detection::correlation::{
    CorrelationDraft, CorrelationRegistry, CorrelatorDescription, CorrelatorMetadata,
    PossibleC2MultiSignalCorrelator,
};
use pcapraven_detection::detector::{
    Detector, DetectorDraftSink, DetectorMetadata, IncompleteDataPolicy,
};
use pcapraven_detection::dns_anomaly::{DnsLongQueryNameDetector, DnsPossibleTunnelingDetector};
use pcapraven_detection::periodic_beaconing::PeriodicBeaconingDetector;
use pcapraven_detection::*;
use pcapraven_domain::*;

fn sample_packet(ordinal: u64) -> PacketReference {
    PacketReference::new(ordinal, None, None, 64, 64, false)
}

fn create_beaconing_tunneling_flow(ordinal: u64) -> FlowRecord {
    let key = FlowKey::new(
        TransportProtocol::Udp,
        FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 100]), 53000),
        FlowEndpoint::new(IpAddress::Ipv4([198, 51, 100, 1]), 53),
    );
    let pkt = sample_packet(ordinal);
    let traffic = FlowTrafficStatistics::new(
        FlowTrafficCounters::new(30, 2000, 2000, 0),
        FlowTrafficCounters::new(15, 1000, 1000, 0),
        FlowTrafficCounters::new(15, 1000, 1000, 0),
        FlowTrafficCounters::new(0, 0, 0, 0),
    );
    // Periodic beaconing metrics: 15 samples, 0 discontinuities, 10s interval, 0 jitter
    let periodic_metrics = FlowInterArrivalMetrics::new(
        15,
        0,
        FlowTemporalValue::Available(FlowDuration::from_secs(10)),
        FlowTemporalValue::Available(FlowDuration::from_secs(10)),
        FlowTemporalValue::Available(FlowDuration::from_secs(10)),
        14,
        FlowTemporalValue::Available(FlowDuration::ZERO),
    );
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let empty_metrics = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Available(FlowDuration::from_secs(150)),
        FlowTimestampCoverage::default(),
        empty_metrics.clone(),
        periodic_metrics.clone(),
        periodic_metrics,
        empty_metrics,
    );
    FlowRecord::new(
        FlowReference::new(ordinal),
        key,
        pkt,
        pkt,
        FlowEndReason::EndOfInput,
        traffic,
        temporal,
    )
}

fn create_dns_query_obs(
    obs_ordinal: u64,
    pkt_ordinal: u64,
    flow_ref: FlowReference,
    labels: Vec<Vec<u8>>,
) -> ProtocolObservation {
    let name = DnsName::from_labels(labels).expect("valid dns name");
    let question = DnsQuestion::new(name, 1, 1);
    let flags = DnsFlags {
        qr: false, // Query
        ..Default::default()
    };
    let pkt = sample_packet(pkt_ordinal);

    let dns_obs = DnsObservation {
        packet: pkt,
        timestamp: PacketTimestamp::Unavailable,
        transport: DnsTransport::Udp,
        source_ip: IpAddress::Ipv4([192, 168, 1, 100]),
        source_port: 53000,
        destination_ip: IpAddress::Ipv4([198, 51, 100, 1]),
        destination_port: 53,
        transaction_id: 1234,
        message_kind: DnsMessageKind::Query,
        opcode: 0,
        response_code: 0,
        effective_response_code: 0,
        flags,
        declared_qdcount: 1,
        declared_ancount: 0,
        declared_nscount: 0,
        declared_arcount: 0,
        questions: vec![question],
        records: Vec::new(),
        edns: None,
        completeness: DnsObservationCompleteness::Complete,
    };

    let flow_assoc = ObservationFlowAssociation::Associated {
        flow: flow_ref,
        direction: FlowDirection::AToB,
    };

    ProtocolObservation::new(
        ObservationReference::new(pkt_ordinal, ProtocolKind::Dns, obs_ordinal as u32),
        flow_assoc,
        ProtocolObservationData::Dns(dns_obs),
    )
}

#[test]
fn test_possible_c2_multi_signal_matching() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);

    // Create 10 DNS queries with high diversity QNAMEs on flow 1
    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow_ref,
            vec![label1, label2, label3, label4],
        ));
    }

    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    // Verify 2 primary findings + 1 correlated finding = 3 total findings
    assert_eq!(outcome.findings.len(), 3);
    let primary_beaconing = outcome
        .findings
        .iter()
        .find(|f| f.detector_id().as_str() == "behavior.periodic_beaconing")
        .unwrap();
    let primary_tunneling = outcome
        .findings
        .iter()
        .find(|f| f.detector_id().as_str() == "dns.possible_tunneling")
        .unwrap();
    let correlated = outcome
        .findings
        .iter()
        .find(|f| f.detector_id().as_str() == "behavior.possible_c2_multi_signal")
        .unwrap();

    // Verify correlated finding properties
    assert_eq!(correlated.severity(), Severity::Medium);
    assert_eq!(correlated.confidence(), Confidence::Medium);
    assert_eq!(correlated.source_finding_references().len(), 2);
    assert_eq!(
        correlated.source_finding_references()[0],
        primary_beaconing.reference()
    );
    assert_eq!(
        correlated.source_finding_references()[1],
        primary_tunneling.reference()
    );

    // Subject has exactly the single flow reference and no packet/observation references
    assert_eq!(correlated.subject().flow_references(), &[flow_ref]);
    assert!(correlated.subject().packet_references().is_empty());
    assert!(correlated.subject().observation_references().is_empty());

    // Verify zero new evidence records created during correlation
    let total_primary_evidence = primary_beaconing.evidence_references().len()
        + primary_tunneling.evidence_references().len();
    assert_eq!(outcome.evidence.len(), total_primary_evidence);
    assert!(
        correlated
            .evidence_references()
            .iter()
            .all(|r| outcome.evidence.iter().any(|e| e.reference() == *r))
    );

    // Correlator execution record status
    assert_eq!(outcome.correlator_executions.len(), 1);
    assert_eq!(
        outcome.correlator_executions[0].status,
        CorrelatorExecutionStatus::Executed
    );
}

#[test]
fn test_possible_c2_multi_signal_partial_signal_no_match() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);

    // Only 1 DNS query (insufficient for tunneling)
    let observations = vec![create_dns_query_obs(
        1,
        1,
        flow_ref,
        vec![b"abc".to_vec(), b"example".to_vec(), b"com".to_vec()],
    )];

    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    // Beaconing matches (1 finding), Tunneling does not (0 findings) -> 0 correlated findings
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(
        outcome.findings[0].detector_id().as_str(),
        "behavior.periodic_beaconing"
    );
    assert_eq!(outcome.correlator_executions.len(), 1);
    assert_eq!(
        outcome.correlator_executions[0].status,
        CorrelatorExecutionStatus::Executed
    );
}

#[test]
fn test_possible_c2_long_query_name_not_used_as_second_signal() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);

    // Only 1 long query name -> triggers dns.long_query_name, but NOT dns.possible_tunneling
    let label1: Vec<u8> = (0..60).map(|j| b'a' + (j % 26) as u8).collect();
    let label2: Vec<u8> = (0..60).map(|j| b'A' + (j % 26) as u8).collect();
    let label3: Vec<u8> = (0..60).map(|j| b'0' + (j % 10) as u8).collect();
    let label4 = b"com".to_vec();
    let observations = vec![create_dns_query_obs(
        1,
        1,
        flow_ref,
        vec![label1, label2, label3, label4],
    )];

    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsLongQueryNameDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    // Should have periodic_beaconing and dns.long_query_name, but NO correlated C2 finding
    assert!(
        outcome
            .findings
            .iter()
            .any(|f| f.detector_id().as_str() == "behavior.periodic_beaconing")
    );
    assert!(
        outcome
            .findings
            .iter()
            .any(|f| f.detector_id().as_str() == "dns.long_query_name")
    );
    assert!(
        !outcome
            .findings
            .iter()
            .any(|f| f.detector_id().as_str() == "behavior.possible_c2_multi_signal")
    );
}

#[test]
fn test_possible_c2_different_flows_no_correlation() {
    let flow1 = create_beaconing_tunneling_flow(1);
    let flow2 = create_beaconing_tunneling_flow(2);

    // DNS queries on flow 2 (tunneling), periodic beaconing on flow 1
    let flow2_ref = FlowReference::new(2);
    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow2_ref,
            vec![label1, label2, label3, label4],
        ));
    }

    let flows = vec![flow1, flow2];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    // Since flow 1 and flow 2 are different, they do not correlate together
    // Flow 1 has beaconing (no tunneling), Flow 2 has tunneling (and beaconing since both flows were created identical)
    // On flow 2, it matches both -> exactly 1 correlation on flow 2
    let c2_findings: Vec<_> = outcome
        .findings
        .iter()
        .filter(|f| f.detector_id().as_str() == "behavior.possible_c2_multi_signal")
        .collect();
    assert_eq!(c2_findings.len(), 1);
    assert_eq!(c2_findings[0].subject().flow_references(), &[flow2_ref]);
}

#[test]
fn test_preflight_missing_required_primary_detector() {
    let mut detector_registry = DetectorRegistry::default();
    // Only register beaconing, omit tunneling
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let input =
        DetectionInput::try_new(&[], &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let err = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap_err();

    assert!(matches!(
        err,
        DetectionEngineError::Registry(
            DetectorRegistryError::MissingRequiredPrimaryDetector { .. }
        )
    ));
}

#[test]
fn test_preflight_cross_registry_id_collision() {
    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    // Create a mock detector with the same ID as a correlator
    struct CollidingDetector {
        meta: DetectorMetadata,
    }
    impl Detector for CollidingDetector {
        fn metadata(&self) -> &DetectorMetadata {
            &self.meta
        }
        fn validate_parameters(&self, _p: &DetectorParameters) -> Result<(), DetectorConfigError> {
            Ok(())
        }
        fn evaluate(
            &self,
            _i: &DetectionInput,
            _p: &DetectorParameters,
            _o: &mut DetectorDraftSink,
        ) -> Result<(), DetectorExecutionError> {
            Ok(())
        }
    }

    let col_id = DetectorId::try_new("behavior.possible_c2_multi_signal").unwrap();
    let col_title = FindingTitle::try_new("Title").unwrap();
    let col_summary = FindingSummary::try_new("Purpose").unwrap();
    let col_meta = DetectorMetadata::new(
        col_id,
        DetectorVersion::new(1, 0, 0),
        col_title,
        col_summary,
        IncompleteDataPolicy::Skip,
    );
    detector_registry
        .register(Box::new(CollidingDetector { meta: col_meta }))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let input =
        DetectionInput::try_new(&[], &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let err = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap_err();

    assert!(matches!(
        err,
        DetectionEngineError::Registry(DetectorRegistryError::CrossRegistryDetectorIdCollision(_))
    ));
}

#[test]
fn test_correlator_skipped_on_disabled_required_source() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);

    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow_ref,
            vec![label1, label2, label3],
        ));
    }

    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    // Disable dns.possible_tunneling
    let mut configs = DetectorConfigurations::default();
    configs
        .insert(
            DetectorId::try_new("dns.possible_tunneling").unwrap(),
            DetectorConfig::disabled(),
        )
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &configs,
        &DetectionLimits::default(),
    )
    .unwrap();

    // Correlator must be SkippedUnavailableSources and emit 0 findings
    assert_eq!(outcome.correlator_executions.len(), 1);
    assert_eq!(
        outcome.correlator_executions[0].status,
        CorrelatorExecutionStatus::SkippedUnavailableSources
    );
    assert!(
        !outcome
            .findings
            .iter()
            .any(|f| f.detector_id().as_str() == "behavior.possible_c2_multi_signal")
    );
}

#[test]
fn test_correlator_skipped_on_partial_primary_input() {
    let flow = create_beaconing_tunneling_flow(1);

    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &[],
        DetectionInputCompleteness::Partial,
        &[DetectionInputLimitation::CaptureTruncated],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    assert_eq!(outcome.completion, DetectionInputCompleteness::Partial);
    assert_eq!(outcome.correlator_executions.len(), 1);
    assert_eq!(
        outcome.correlator_executions[0].status,
        CorrelatorExecutionStatus::SkippedIncompleteData
    );
    assert!(outcome.findings.is_empty());
}

#[test]
fn test_correlation_registry_ordering_and_bounds() {
    let mut registry = CorrelationRegistry::new(2).unwrap();
    assert_eq!(registry.len(), 0);
    assert!(registry.is_empty());

    let corr = PossibleC2MultiSignalCorrelator::new();
    registry.register(Box::new(corr.clone())).unwrap();
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());

    // Duplicate registration rejected
    let err = registry.register(Box::new(corr)).unwrap_err();
    assert!(matches!(err, DetectorRegistryError::DuplicateDetectorId(_)));

    // Capacity limit
    assert!(CorrelationRegistry::new(0).is_err());
    assert!(CorrelationRegistry::new(65).is_err());
}

#[test]
fn test_correlator_metadata_validation() {
    let id = DetectorId::try_new("test.correlator").unwrap();
    let version = DetectorVersion::new(1, 0, 0);
    let desc = CorrelatorDescription::try_new("Valid description").unwrap();

    // Valid metadata
    let req1 = DetectorId::try_new("test.primary_a").unwrap();
    let req2 = DetectorId::try_new("test.primary_b").unwrap();
    assert!(
        CorrelatorMetadata::try_new(
            id.clone(),
            version,
            desc.clone(),
            vec![req1.clone(), req2.clone()]
        )
        .is_ok()
    );

    // Out of order required primary IDs
    assert!(
        CorrelatorMetadata::try_new(
            id.clone(),
            version,
            desc.clone(),
            vec![req2.clone(), req1.clone()]
        )
        .is_err()
    );

    // Duplicate required primary IDs
    assert!(
        CorrelatorMetadata::try_new(
            id.clone(),
            version,
            desc.clone(),
            vec![req1.clone(), req1.clone()]
        )
        .is_err()
    );

    // Description validation
    assert!(CorrelatorDescription::try_new("").is_err());
    assert!(CorrelatorDescription::try_new("a".repeat(513)).is_err());
    assert!(CorrelatorDescription::try_new("invalid\x00ctrl").is_err());
}

#[test]
fn test_correlation_draft_validation() {
    let flow_ref = FlowReference::new(1);
    let subject = FindingSubject::try_new(Vec::new(), vec![flow_ref], Vec::new()).unwrap();
    let title = FindingTitle::try_new("Test Title").unwrap();
    let summary = FindingSummary::try_new("Test Summary").unwrap();
    let rationale = FindingRationale::try_new("Test Rationale").unwrap();
    let evi1 = EvidenceReference::new(1);
    let evi2 = EvidenceReference::new(2);
    let find1 = FindingReference::new(1);
    let find2 = FindingReference::new(2);

    // Valid draft
    assert!(
        CorrelationDraft::try_new(
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Medium,
            Confidence::Medium,
            vec![evi1, evi2],
            vec![find1, find2],
            Vec::new(),
        )
        .is_ok()
    );

    // Empty evidence
    assert!(
        CorrelationDraft::try_new(
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Medium,
            Confidence::Medium,
            Vec::new(),
            vec![find1, find2],
            Vec::new(),
        )
        .is_err()
    );

    // Less than 2 source findings
    assert!(
        CorrelationDraft::try_new(
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Medium,
            Confidence::Medium,
            vec![evi1],
            vec![find1],
            Vec::new(),
        )
        .is_err()
    );

    // Duplicate evidence
    assert!(
        CorrelationDraft::try_new(
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Medium,
            Confidence::Medium,
            vec![evi1, evi1],
            vec![find1, find2],
            Vec::new(),
        )
        .is_err()
    );

    // Out of order evidence
    assert!(
        CorrelationDraft::try_new(
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Medium,
            Confidence::Medium,
            vec![evi2, evi1],
            vec![find1, find2],
            Vec::new(),
        )
        .is_err()
    );

    // Duplicate source finding
    assert!(
        CorrelationDraft::try_new(
            subject.clone(),
            title.clone(),
            summary.clone(),
            rationale.clone(),
            Severity::Medium,
            Confidence::Medium,
            vec![evi1],
            vec![find1, find1],
            Vec::new(),
        )
        .is_err()
    );

    // Out of order source finding
    assert!(
        CorrelationDraft::try_new(
            subject,
            title,
            summary,
            rationale,
            Severity::Medium,
            Confidence::Medium,
            vec![evi1],
            vec![find2, find1],
            Vec::new(),
        )
        .is_err()
    );
}

#[test]
fn test_complexity_large_synthetic_primary_finding_set() {
    // Verify O(P log P) scaling without quadratic slowdown
    let mut flows = Vec::new();
    let mut observations = Vec::new();

    // 50 flows with periodic beaconing only, 50 flows with DNS tunneling only, 1 shared flow
    for i in 1..=50 {
        flows.push(create_beaconing_tunneling_flow(i));
    }

    let shared_flow_ref = FlowReference::new(1);
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            shared_flow_ref,
            vec![label1, label2, label3, label4],
        ));
    }

    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    // 50 periodic findings + 1 tunneling finding = 51 primary findings
    // Exactly 1 correlated finding on shared flow 1
    let c2_findings: Vec<_> = outcome
        .findings
        .iter()
        .filter(|f| f.detector_id().as_str() == "behavior.possible_c2_multi_signal")
        .collect();
    assert_eq!(c2_findings.len(), 1);
    assert_eq!(
        c2_findings[0].subject().flow_references(),
        &[shared_flow_ref]
    );
}

struct MockProvenanceCorrelator {
    meta: CorrelatorMetadata,
    mode: ProvenanceViolationMode,
}

enum ProvenanceViolationMode {
    BadSourceRef,
    UnownedEvidenceRef,
    UnownedSubjectRef,
    DuplicateIdentity,
}

impl FindingCorrelator for MockProvenanceCorrelator {
    fn metadata(&self) -> &CorrelatorMetadata {
        &self.meta
    }

    fn correlate(
        &self,
        primary_findings: &[FindingRecord],
        _evidence_pool: &[EvidenceRecord],
        output: &mut pcapraven_detection::correlation::CorrelationDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let b = primary_findings
            .iter()
            .find(|f| f.detector_id().as_str() == "behavior.periodic_beaconing")
            .unwrap();
        let t = primary_findings
            .iter()
            .find(|f| f.detector_id().as_str() == "dns.possible_tunneling")
            .unwrap();

        match self.mode {
            ProvenanceViolationMode::BadSourceRef => {
                let draft = CorrelationDraft::try_new(
                    b.subject().clone(),
                    FindingTitle::try_new("Bad Source").unwrap(),
                    FindingSummary::try_new("Summary").unwrap(),
                    FindingRationale::try_new("Rationale").unwrap(),
                    Severity::Medium,
                    Confidence::Medium,
                    vec![b.evidence_references()[0]],
                    vec![FindingReference::new(998), FindingReference::new(999)],
                    Vec::new(),
                )
                .unwrap();
                output.push(draft)?;
            }
            ProvenanceViolationMode::UnownedEvidenceRef => {
                let draft = CorrelationDraft::try_new(
                    b.subject().clone(),
                    FindingTitle::try_new("Unowned Evidence").unwrap(),
                    FindingSummary::try_new("Summary").unwrap(),
                    FindingRationale::try_new("Rationale").unwrap(),
                    Severity::Medium,
                    Confidence::Medium,
                    vec![EvidenceReference::new(999)],
                    vec![b.reference(), t.reference()],
                    Vec::new(),
                )
                .unwrap();
                output.push(draft)?;
            }
            ProvenanceViolationMode::UnownedSubjectRef => {
                let unowned_subject =
                    FindingSubject::try_new(Vec::new(), vec![FlowReference::new(999)], Vec::new())
                        .unwrap();
                let draft = CorrelationDraft::try_new(
                    unowned_subject,
                    FindingTitle::try_new("Unowned Subject").unwrap(),
                    FindingSummary::try_new("Summary").unwrap(),
                    FindingRationale::try_new("Rationale").unwrap(),
                    Severity::Medium,
                    Confidence::Medium,
                    vec![b.evidence_references()[0]],
                    vec![b.reference(), t.reference()],
                    Vec::new(),
                )
                .unwrap();
                output.push(draft)?;
            }
            ProvenanceViolationMode::DuplicateIdentity => {
                let draft1 = CorrelationDraft::try_new(
                    b.subject().clone(),
                    FindingTitle::try_new("Title 1").unwrap(),
                    FindingSummary::try_new("Summary").unwrap(),
                    FindingRationale::try_new("Rationale").unwrap(),
                    Severity::Medium,
                    Confidence::Medium,
                    vec![b.evidence_references()[0]],
                    vec![b.reference(), t.reference()],
                    Vec::new(),
                )
                .unwrap();
                let draft2 = CorrelationDraft::try_new(
                    b.subject().clone(),
                    FindingTitle::try_new("Title 2").unwrap(),
                    FindingSummary::try_new("Summary").unwrap(),
                    FindingRationale::try_new("Rationale").unwrap(),
                    Severity::Medium,
                    Confidence::Medium,
                    vec![b.evidence_references()[0]],
                    vec![b.reference(), t.reference()],
                    Vec::new(),
                )
                .unwrap();
                output.push(draft1)?;
                output.push(draft2)?;
            }
        }
        Ok(())
    }
}

fn create_mock_provenance_correlator(
    id_str: &'static str,
    mode: ProvenanceViolationMode,
) -> MockProvenanceCorrelator {
    let id = DetectorId::try_new(id_str).unwrap();
    let version = DetectorVersion::new(1, 0, 0);
    let desc = CorrelatorDescription::try_new("Mock provenance test correlator").unwrap();
    let req1 = DetectorId::try_new("behavior.periodic_beaconing").unwrap();
    let req2 = DetectorId::try_new("dns.possible_tunneling").unwrap();
    let meta = CorrelatorMetadata::try_new(id, version, desc, vec![req1, req2]).unwrap();
    MockProvenanceCorrelator { meta, mode }
}

#[test]
fn test_provenance_violation_bad_source_finding_ref_rejected() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);
    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow_ref,
            vec![label1, label2, label3, label4],
        ));
    }
    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(create_mock_provenance_correlator(
            "behavior.mock_bad_src",
            ProvenanceViolationMode::BadSourceRef,
        )))
        .unwrap();

    let err = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DetectionEngineError::Output(DetectionOutputError::InvalidSourceFindingReference { .. })
    ));
}

#[test]
fn test_provenance_violation_unowned_evidence_ref_rejected() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);
    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow_ref,
            vec![label1, label2, label3, label4],
        ));
    }
    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(create_mock_provenance_correlator(
            "behavior.mock_bad_evi",
            ProvenanceViolationMode::UnownedEvidenceRef,
        )))
        .unwrap();

    let err = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DetectionEngineError::Output(
            DetectionOutputError::UnownedCorrelationEvidenceReference { .. }
        )
    ));
}

#[test]
fn test_provenance_violation_unowned_subject_ref_rejected() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);
    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow_ref,
            vec![label1, label2, label3, label4],
        ));
    }
    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(create_mock_provenance_correlator(
            "behavior.mock_bad_subj",
            ProvenanceViolationMode::UnownedSubjectRef,
        )))
        .unwrap();

    let err = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DetectionEngineError::Output(
            DetectionOutputError::UnownedCorrelationSubjectReference { .. }
        )
    ));
}

#[test]
fn test_correlator_duplicate_identity_rejected() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);
    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow_ref,
            vec![label1, label2, label3, label4],
        ));
    }
    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(create_mock_provenance_correlator(
            "behavior.mock_dup",
            ProvenanceViolationMode::DuplicateIdentity,
        )))
        .unwrap();

    let err = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DetectionEngineError::Output(DetectionOutputError::DuplicateFindingIdentity { .. })
    ));
}

#[test]
fn test_correlator_budget_exceeded_resource_limited() {
    let flow_ref = FlowReference::new(1);
    let flow = create_beaconing_tunneling_flow(1);
    let mut observations = Vec::new();
    for i in 1..=10 {
        let label1: Vec<u8> = (0..45).map(|j| b'a' + ((i + j) % 26) as u8).collect();
        let label2: Vec<u8> = (0..45).map(|j| b'A' + ((i + j) % 26) as u8).collect();
        let label3: Vec<u8> = (0..45).map(|j| b'0' + ((i + j) % 10) as u8).collect();
        let label4 = b"com".to_vec();
        observations.push(create_dns_query_obs(
            i,
            i,
            flow_ref,
            vec![label1, label2, label3, label4],
        ));
    }
    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut detector_registry = DetectorRegistry::default();
    detector_registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();
    detector_registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let mut correlator_registry = CorrelationRegistry::default();
    correlator_registry
        .register(Box::new(PossibleC2MultiSignalCorrelator::new()))
        .unwrap();

    // Primary findings = 2. Set max_total_findings = 2, so correlated finding exceeds budget.
    let limits = DetectionLimitsBuilder::default()
        .max_total_findings(2)
        .build()
        .unwrap();

    let outcome = execute_detection_with_correlators(
        &detector_registry,
        &correlator_registry,
        &input,
        &DetectorConfigurations::default(),
        &limits,
    )
    .unwrap();

    assert_eq!(outcome.completion, DetectionInputCompleteness::Partial);
    assert_eq!(outcome.findings.len(), 2);
    assert_eq!(outcome.correlator_executions.len(), 1);
    assert_eq!(
        outcome.correlator_executions[0].status,
        CorrelatorExecutionStatus::ResourceLimited
    );
}
