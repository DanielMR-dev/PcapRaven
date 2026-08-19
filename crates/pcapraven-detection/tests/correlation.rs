//! Integration tests for Cross-Detector Finding Correlation and Possible C2 Multi-Signal heuristic.

use pcapraven_detection::correlation::{CorrelationRegistry, PossibleC2MultiSignalCorrelator};
use pcapraven_detection::dns_anomaly::DnsPossibleTunnelingDetector;
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
    assert!(CorrelationRegistry::new(257).is_err());
}
