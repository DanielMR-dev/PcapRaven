use pcapraven_detection::{
    ConnectionPeerKey, DetectionInput, DetectionInputCompleteness, DetectionInputLimitation,
    DetectionLimits, Detector, DetectorConfigurations, DetectorParameterKey,
    DetectorParameterValue, DetectorParameters, DetectorRegistry, RepeatedLowVolumeFlowDetector,
    execute_detection,
};
use pcapraven_domain::{
    Confidence, EvidenceComparison, EvidenceKind, EvidenceRatio, EvidenceValue, FlowDuration,
    FlowEndReason, FlowEndpoint, FlowInterArrivalMetrics, FlowKey, FlowRecord, FlowReference,
    FlowTemporalMetrics, FlowTemporalUnavailableReason, FlowTemporalValue, FlowTimestampCoverage,
    FlowTrafficCounters, FlowTrafficStatistics, IpAddress, PacketReference, PacketTimestamp,
    Severity, TransportProtocol,
};

fn sample_packet(ordinal: u64) -> PacketReference {
    PacketReference::new(ordinal, None, None, 64, 64, false)
}

#[allow(clippy::too_many_arguments)]
fn create_test_flow(
    ordinal: u64,
    ip_a: [u8; 4],
    port_a: u16,
    ip_b: [u8; 4],
    port_b: u16,
    protocol: TransportProtocol,
    wire_bytes: u64,
    packets: u64,
    duration: FlowDuration,
    end_reason: FlowEndReason,
    same_endpoint_packets: u64,
    has_dirty_timestamps: bool,
) -> FlowRecord {
    let key = FlowKey::new(
        protocol,
        FlowEndpoint::new(IpAddress::Ipv4(ip_a), port_a),
        FlowEndpoint::new(IpAddress::Ipv4(ip_b), port_b),
    );
    let pkt = sample_packet(ordinal);
    let traffic = FlowTrafficStatistics::new(
        FlowTrafficCounters::new(packets, wire_bytes, wire_bytes, 0),
        FlowTrafficCounters::new(packets / 2, wire_bytes / 2, wire_bytes / 2, 0),
        FlowTrafficCounters::new(
            packets - packets / 2,
            wire_bytes - wire_bytes / 2,
            wire_bytes - wire_bytes / 2,
            0,
        ),
        FlowTrafficCounters::new(same_endpoint_packets, 0, 0, 0),
    );
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let empty_metrics = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let coverage = if has_dirty_timestamps {
        FlowTimestampCoverage::new(0, 1, 0, 0)
    } else {
        FlowTimestampCoverage::default()
    };

    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Available(duration),
        coverage,
        empty_metrics.clone(),
        empty_metrics.clone(),
        empty_metrics.clone(),
        empty_metrics,
    );
    FlowRecord::new(
        FlowReference::new(ordinal),
        key,
        pkt,
        pkt,
        end_reason,
        traffic,
        temporal,
    )
}

#[test]
fn test_connection_peer_key_normalization() {
    let ip1 = IpAddress::Ipv4([192, 168, 1, 100]);
    let ip2 = IpAddress::Ipv4([10, 0, 0, 1]);

    let key1 = ConnectionPeerKey::new(TransportProtocol::Tcp, ip1, ip2);
    let key2 = ConnectionPeerKey::new(TransportProtocol::Tcp, ip2, ip1);

    assert_eq!(key1, key2);
    assert_eq!(key1.peer_a(), ip2);
    assert_eq!(key1.peer_b(), ip1);
    assert_eq!(key1.transport(), TransportProtocol::Tcp);
}

#[test]
fn test_repeated_low_volume_flows_matching() {
    let mut flows = Vec::new();
    for i in 1..=6 {
        flows.push(create_test_flow(
            i,
            [192, 168, 1, 10],
            40000 + i as u16,
            [198, 51, 100, 1],
            443,
            TransportProtocol::Tcp,
            200,
            4,
            FlowDuration::from_secs(5),
            FlowEndReason::EndOfInput,
            0,
            false,
        ));
    }

    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(RepeatedLowVolumeFlowDetector::new()))
        .unwrap();

    let outcome = execute_detection(
        &registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    assert_eq!(outcome.findings.len(), 1);
    let finding = &outcome.findings[0];
    assert_eq!(
        finding.detector_id().as_str(),
        "behavior.repeated_low_volume_flows"
    );
    assert_eq!(finding.severity(), Severity::Low);
    assert_eq!(finding.confidence(), Confidence::Medium);
    assert_eq!(finding.subject().flow_references().len(), 2);
    assert_eq!(
        finding.subject().flow_references()[0],
        FlowReference::new(1)
    );
    assert_eq!(
        finding.subject().flow_references()[1],
        FlowReference::new(6)
    );
    assert_eq!(finding.evidence_references().len(), 1);

    let evidence = &outcome.evidence[0];
    assert_eq!(evidence.kind(), EvidenceKind::RatioComparison);
    assert_eq!(evidence.measurements().len(), 6);

    // 1. candidate_flow_count
    assert_eq!(
        evidence.measurements()[0].key().as_str(),
        "candidate_flow_count"
    );
    assert_eq!(
        evidence.measurements()[0].observed_value(),
        &EvidenceValue::Unsigned(6)
    );

    // 2. candidate_flow_ratio
    assert_eq!(
        evidence.measurements()[1].key().as_str(),
        "candidate_flow_ratio"
    );
    assert_eq!(
        evidence.measurements()[1].observed_value(),
        &EvidenceValue::Ratio(EvidenceRatio::ONE)
    );
    assert_eq!(
        evidence.measurements()[1].threshold_value(),
        Some(&EvidenceValue::Ratio(
            EvidenceRatio::from_fraction(3, 4).unwrap()
        ))
    );
    assert_eq!(
        evidence.measurements()[1].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    // 3. eligible_flow_instance_count
    assert_eq!(
        evidence.measurements()[2].key().as_str(),
        "eligible_flow_instance_count"
    );
    assert_eq!(
        evidence.measurements()[2].observed_value(),
        &EvidenceValue::Unsigned(6)
    );

    // 4. maximum_candidate_duration
    assert_eq!(
        evidence.measurements()[3].key().as_str(),
        "maximum_candidate_duration"
    );
    assert_eq!(
        evidence.measurements()[3].observed_value(),
        &EvidenceValue::Duration(FlowDuration::from_secs(5))
    );

    // 5. maximum_candidate_packet_count
    assert_eq!(
        evidence.measurements()[4].key().as_str(),
        "maximum_candidate_packet_count"
    );
    assert_eq!(
        evidence.measurements()[4].observed_value(),
        &EvidenceValue::Unsigned(4)
    );

    // 6. maximum_candidate_wire_bytes
    assert_eq!(
        evidence.measurements()[5].key().as_str(),
        "maximum_candidate_wire_bytes"
    );
    assert_eq!(
        evidence.measurements()[5].observed_value(),
        &EvidenceValue::Unsigned(200)
    );
}

#[test]
fn test_repeated_low_volume_flows_insufficient_instances() {
    let mut flows = Vec::new();
    for i in 1..=5 {
        flows.push(create_test_flow(
            i,
            [192, 168, 1, 10],
            40000 + i as u16,
            [198, 51, 100, 1],
            443,
            TransportProtocol::Tcp,
            200,
            4,
            FlowDuration::from_secs(5),
            FlowEndReason::EndOfInput,
            0,
            false,
        ));
    }

    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(RepeatedLowVolumeFlowDetector::new()))
        .unwrap();

    let outcome = execute_detection(
        &registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    assert_eq!(outcome.findings.len(), 0);
}

#[test]
fn test_repeated_low_volume_flows_ratio_boundary() {
    let mut flows = Vec::new();
    // 6 eligible flows: 4 candidate (200 bytes), 2 non-candidate (50000 bytes) -> ratio 4/6 = 2/3 < 3/4
    for i in 1..=4 {
        flows.push(create_test_flow(
            i,
            [192, 168, 1, 10],
            40000 + i as u16,
            [198, 51, 100, 1],
            443,
            TransportProtocol::Tcp,
            200,
            4,
            FlowDuration::from_secs(5),
            FlowEndReason::EndOfInput,
            0,
            false,
        ));
    }
    for i in 5..=6 {
        flows.push(create_test_flow(
            i,
            [192, 168, 1, 10],
            40000 + i as u16,
            [198, 51, 100, 1],
            443,
            TransportProtocol::Tcp,
            50000,
            4,
            FlowDuration::from_secs(5),
            FlowEndReason::EndOfInput,
            0,
            false,
        ));
    }

    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(RepeatedLowVolumeFlowDetector::new()))
        .unwrap();

    let outcome = execute_detection(
        &registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    assert_eq!(outcome.findings.len(), 0);

    // Add 2 more candidate flows -> 6 candidate / 8 eligible = 6/8 = 3/4 >= 3/4 -> MATCH!
    for i in 7..=8 {
        flows.push(create_test_flow(
            i,
            [192, 168, 1, 10],
            40000 + i as u16,
            [198, 51, 100, 1],
            443,
            TransportProtocol::Tcp,
            200,
            4,
            FlowDuration::from_secs(5),
            FlowEndReason::EndOfInput,
            0,
            false,
        ));
    }

    let input2 =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let outcome2 = execute_detection(
        &registry,
        &input2,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    assert_eq!(outcome2.findings.len(), 1);
}

#[test]
fn test_repeated_low_volume_flows_exclusions() {
    let mut flows = Vec::new();
    for i in 1..=5 {
        flows.push(create_test_flow(
            i,
            [192, 168, 1, 10],
            40000 + i as u16,
            [198, 51, 100, 1],
            443,
            TransportProtocol::Tcp,
            200,
            4,
            FlowDuration::from_secs(5),
            FlowEndReason::EndOfInput,
            0,
            false,
        ));
    }
    // Flow with AnalysisStopped -> excluded
    flows.push(create_test_flow(
        6,
        [192, 168, 1, 10],
        40006,
        [198, 51, 100, 1],
        443,
        TransportProtocol::Tcp,
        200,
        4,
        FlowDuration::from_secs(5),
        FlowEndReason::AnalysisStopped,
        0,
        false,
    ));
    // Flow with same_endpoint -> excluded
    flows.push(create_test_flow(
        7,
        [192, 168, 1, 10],
        40007,
        [198, 51, 100, 1],
        443,
        TransportProtocol::Tcp,
        200,
        4,
        FlowDuration::from_secs(5),
        FlowEndReason::EndOfInput,
        1,
        false,
    ));
    // Flow with dirty timestamps -> excluded
    flows.push(create_test_flow(
        8,
        [192, 168, 1, 10],
        40008,
        [198, 51, 100, 1],
        443,
        TransportProtocol::Tcp,
        200,
        4,
        FlowDuration::from_secs(5),
        FlowEndReason::EndOfInput,
        0,
        true,
    ));

    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(RepeatedLowVolumeFlowDetector::new()))
        .unwrap();

    let outcome = execute_detection(
        &registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    // Only 5 eligible flows -> 0 findings
    assert_eq!(outcome.findings.len(), 0);
}

#[test]
fn test_repeated_low_volume_flows_incomplete_data_skipped() {
    let mut flows = Vec::new();
    for i in 1..=10 {
        flows.push(create_test_flow(
            i,
            [192, 168, 1, 10],
            40000 + i as u16,
            [198, 51, 100, 1],
            443,
            TransportProtocol::Tcp,
            200,
            4,
            FlowDuration::from_secs(5),
            FlowEndReason::EndOfInput,
            0,
            false,
        ));
    }

    let input = DetectionInput::try_new(
        &flows,
        &[],
        DetectionInputCompleteness::Partial,
        &[DetectionInputLimitation::CaptureTruncated],
    )
    .unwrap();

    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(RepeatedLowVolumeFlowDetector::new()))
        .unwrap();

    let outcome = execute_detection(
        &registry,
        &input,
        &DetectorConfigurations::default(),
        &DetectionLimits::default(),
    )
    .unwrap();

    assert_eq!(outcome.findings.len(), 0);
}

#[test]
fn test_repeated_low_volume_flow_parameter_validation() {
    let detector = RepeatedLowVolumeFlowDetector::new();

    // Valid parameters (keys in strict alphabetical order)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_flow_duration").unwrap(),
            DetectorParameterValue::Duration(FlowDuration::from_secs(30)),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_packets_per_flow").unwrap(),
            DetectorParameterValue::Unsigned(30),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_tracked_peer_groups").unwrap(),
            DetectorParameterValue::Unsigned(1000),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_wire_bytes_per_flow").unwrap(),
            DetectorParameterValue::Unsigned(16384),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("minimum_candidate_flow_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(1, 2).unwrap()),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("minimum_eligible_flow_instances").unwrap(),
            DetectorParameterValue::Unsigned(10),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_ok());

    // Invalid minimum_eligible_flow_instances (1 < 2)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("minimum_eligible_flow_instances").unwrap(),
            DetectorParameterValue::Unsigned(1),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());

    // Invalid minimum_candidate_flow_ratio (0)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("minimum_candidate_flow_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::ZERO),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());

    // Invalid maximum_packets_per_flow (0)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_packets_per_flow").unwrap(),
            DetectorParameterValue::Unsigned(0),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());

    // Invalid maximum_wire_bytes_per_flow (0)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_wire_bytes_per_flow").unwrap(),
            DetectorParameterValue::Unsigned(0),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());

    // Invalid maximum_flow_duration (0)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_flow_duration").unwrap(),
            DetectorParameterValue::Duration(FlowDuration::ZERO),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());

    // Invalid maximum_tracked_peer_groups (0)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_tracked_peer_groups").unwrap(),
            DetectorParameterValue::Unsigned(0),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());

    // Invalid maximum_tracked_peer_groups (> 1_000_000)
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_tracked_peer_groups").unwrap(),
            DetectorParameterValue::Unsigned(1_000_001),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());

    // Unknown parameter
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("unknown_param").unwrap(),
            DetectorParameterValue::Unsigned(100),
        )
        .unwrap();
    let params = builder.build().unwrap();
    assert!(detector.validate_parameters(&params).is_err());
}
