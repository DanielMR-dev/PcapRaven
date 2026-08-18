use pcapraven_detection::{
    DetectionInput, DetectionInputCompleteness, DetectionLimits, Detector, DetectorConfigurations,
    DetectorDraftSink, DetectorParameterKey, DetectorParameterValue, DetectorParameters,
    DnsLongQueryNameDetector, DnsPossibleTunnelingDetector, execute_detection,
};
use pcapraven_domain::{
    Confidence, DnsFlags, DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness,
    DnsQuestion, DnsTransport, EvidenceComparison, EvidenceKind, EvidenceRatio, EvidenceValue,
    FlowDirection, FlowEndReason, FlowEndpoint, FlowInterArrivalMetrics, FlowKey, FlowRecord,
    FlowReference, FlowTemporalMetrics, FlowTemporalUnavailableReason, FlowTemporalValue,
    FlowTimestampCoverage, FlowTrafficStatistics, IpAddress, ObservationFlowAssociation,
    ObservationReference, PacketReference, PacketTimestamp, ProtocolKind, ProtocolObservation,
    ProtocolObservationData, Severity, TransportProtocol,
};

fn create_synthetic_dns_obs(
    obs_ordinal: u64,
    pkt_ordinal: u64,
    flow_ref: Option<FlowReference>,
    is_query: bool,
    labels: Vec<Vec<u8>>,
) -> ProtocolObservation {
    let name = DnsName::from_labels(labels).expect("valid dns name");
    let question = DnsQuestion::new(name, 1, 1);
    let flags = DnsFlags {
        qr: !is_query,
        ..Default::default()
    };
    let pkt = PacketReference::new(pkt_ordinal, None, None, 100, 100, false);

    let dns_obs = DnsObservation {
        packet: pkt,
        timestamp: PacketTimestamp::Unavailable,
        transport: DnsTransport::Udp,
        source_ip: IpAddress::Ipv4([10, 0, 0, 1]),
        source_port: 5353,
        destination_ip: IpAddress::Ipv4([10, 0, 0, 2]),
        destination_port: 53,
        transaction_id: 1234,
        message_kind: if is_query {
            DnsMessageKind::Query
        } else {
            DnsMessageKind::Response
        },
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

    let flow_assoc = match flow_ref {
        Some(f) => ObservationFlowAssociation::Associated {
            flow: f,
            direction: FlowDirection::AToB,
        },
        None => ObservationFlowAssociation::Unassociated,
    };

    ProtocolObservation::new(
        ObservationReference::new(pkt_ordinal, ProtocolKind::Dns, obs_ordinal as u32),
        flow_assoc,
        ProtocolObservationData::Dns(dns_obs),
    )
}

fn create_synthetic_flow(ordinal: u64) -> FlowRecord {
    let key = FlowKey::new(
        TransportProtocol::Udp,
        FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 1]), 5353),
        FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 2]), 53),
    );
    let pkt = PacketReference::new(0, None, None, 100, 100, false);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let empty_metrics = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        unavail,
        FlowTimestampCoverage {
            available_timestamps: 0,
            unavailable_timestamps: 0,
            invalid_timestamps: 0,
            non_monotonic_transitions: 0,
        },
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
        FlowEndReason::EndOfInput,
        FlowTrafficStatistics::empty(),
        temporal,
    )
}

#[test]
fn test_label_octet_diversity_ratio_pure_logic() {
    // 1. Empty label -> ZERO
    assert_eq!(
        pcapraven_detection::label_octet_diversity_ratio(&[]),
        EvidenceRatio::ZERO
    );

    // 2. Monomorphic label: all identical octets -> 1 / len
    let mono = b"aaaaaa";
    assert_eq!(
        pcapraven_detection::label_octet_diversity_ratio(mono),
        EvidenceRatio::from_fraction(1, 6).unwrap()
    );

    // 3. Polymorphic label: all distinct octets -> 1 / 1
    let poly = b"abcdef";
    assert_eq!(
        pcapraven_detection::label_octet_diversity_ratio(poly),
        EvidenceRatio::from_fraction(1, 1).unwrap()
    );

    // 4. Mixed repeating: 6 distinct out of 8 octets -> 6/8 = 3/4
    let mixed = b"a1b2c3a1";
    assert_eq!(
        pcapraven_detection::label_octet_diversity_ratio(mixed),
        EvidenceRatio::from_fraction(3, 4).unwrap()
    );

    // 5. Full 256 byte array -> 256/256 = 1/1
    let all_256: Vec<u8> = (0..=255).collect();
    assert_eq!(
        pcapraven_detection::label_octet_diversity_ratio(&all_256),
        EvidenceRatio::ONE
    );
}

#[test]
fn test_dns_long_query_name_parameter_validation() {
    let detector = DnsLongQueryNameDetector::new();

    // Default empty params -> valid
    assert!(
        detector
            .validate_parameters(&DetectorParameters::empty())
            .is_ok()
    );

    // Valid bounds (strictly sorted: minimum_label_length < minimum_label_octet_diversity_ratio < minimum_qname_wire_length)
    let mut b1 = DetectorParameters::builder();
    b1.add(
        DetectorParameterKey::try_new("minimum_label_length").unwrap(),
        DetectorParameterValue::Unsigned(63),
    )
    .unwrap();
    b1.add(
        DetectorParameterKey::try_new("minimum_label_octet_diversity_ratio").unwrap(),
        DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(1, 2).unwrap()),
    )
    .unwrap();
    b1.add(
        DetectorParameterKey::try_new("minimum_qname_wire_length").unwrap(),
        DetectorParameterValue::Unsigned(1),
    )
    .unwrap();
    assert!(detector.validate_parameters(&b1.build().unwrap()).is_ok());

    // Invalid minimum_qname_wire_length: 0
    let mut b_zero_name = DetectorParameters::builder();
    b_zero_name
        .add(
            DetectorParameterKey::try_new("minimum_qname_wire_length").unwrap(),
            DetectorParameterValue::Unsigned(0),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_zero_name.build().unwrap())
            .is_err()
    );

    // Invalid minimum_qname_wire_length: > 255
    let mut b_over_name = DetectorParameters::builder();
    b_over_name
        .add(
            DetectorParameterKey::try_new("minimum_qname_wire_length").unwrap(),
            DetectorParameterValue::Unsigned(256),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_over_name.build().unwrap())
            .is_err()
    );

    // Invalid minimum_label_length: 0
    let mut b_zero_label = DetectorParameters::builder();
    b_zero_label
        .add(
            DetectorParameterKey::try_new("minimum_label_length").unwrap(),
            DetectorParameterValue::Unsigned(0),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_zero_label.build().unwrap())
            .is_err()
    );

    // Invalid minimum_label_length: > 63
    let mut b_over_label = DetectorParameters::builder();
    b_over_label
        .add(
            DetectorParameterKey::try_new("minimum_label_length").unwrap(),
            DetectorParameterValue::Unsigned(64),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_over_label.build().unwrap())
            .is_err()
    );

    // Invalid minimum_label_octet_diversity_ratio: > 1
    let mut b_over_div = DetectorParameters::builder();
    b_over_div
        .add(
            DetectorParameterKey::try_new("minimum_label_octet_diversity_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(2, 1).unwrap()),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_over_div.build().unwrap())
            .is_err()
    );

    // Invalid type (Ratio instead of Unsigned)
    let mut b_type = DetectorParameters::builder();
    b_type
        .add(
            DetectorParameterKey::try_new("minimum_qname_wire_length").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::ONE),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_type.build().unwrap())
            .is_err()
    );

    // Unknown parameter
    let mut b_unknown = DetectorParameters::builder();
    b_unknown
        .add(
            DetectorParameterKey::try_new("unknown_param").unwrap(),
            DetectorParameterValue::Unsigned(10),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_unknown.build().unwrap())
            .is_err()
    );
}

#[test]
fn test_dns_long_query_name_detection_matching() {
    let detector = DnsLongQueryNameDetector::new();
    let flow = create_synthetic_flow(0);

    // 1. Short normal query: "example.com" -> no finding
    let obs_normal = create_synthetic_dns_obs(
        0,
        0,
        Some(flow.reference),
        true,
        vec![b"example".to_vec(), b"com".to_vec()],
    );

    // 2. High-diversity, long query matching all thresholds (QNAME >= 120, max_label >= 40, diversity >= 1/3)
    // 3 labels of 45 characters with high diversity -> wire length ~138 octets >= 120
    let label45_1: Vec<u8> = (0..45).map(|i| b'a' + (i % 26)).collect();
    let label45_2: Vec<u8> = (0..45).map(|i| b'A' + (i % 26)).collect();
    let label45_3: Vec<u8> = (0..45).map(|i| b'0' + (i % 10)).collect();
    let obs_matching = create_synthetic_dns_obs(
        1,
        1,
        Some(flow.reference),
        true,
        vec![label45_1, label45_2, label45_3, b"net".to_vec()],
    );

    // 3. Response message -> MUST NOT match (QR = 1)
    let label45_resp: Vec<u8> = (0..45).map(|i| b'z' - (i % 26)).collect();
    let obs_resp = create_synthetic_dns_obs(
        2,
        2,
        Some(flow.reference),
        false,
        vec![
            label45_resp.clone(),
            label45_resp.clone(),
            label45_resp,
            b"com".to_vec(),
        ],
    );

    let observations = vec![obs_normal, obs_matching, obs_resp];
    let flows = vec![flow];
    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .expect("evaluation succeeds");

    // Exactly 1 finding: obs_matching
    assert_eq!(sink.len(), 1);
    let findings = sink.into_drafts();

    assert_eq!(findings[0].severity(), Severity::Info);
    assert_eq!(findings[0].confidence(), Confidence::Medium);
    assert_eq!(
        findings[0].title().as_str(),
        "Unusually long DNS query name"
    );
    assert_eq!(findings[0].evidence().len(), 1);
    let evi = &findings[0].evidence()[0];
    assert_eq!(evi.kind(), EvidenceKind::ProtocolObservation);
    assert_eq!(evi.measurements().len(), 5);

    // 5 ordered metric keys:
    // 1. matching_question_count
    assert_eq!(
        evi.measurements()[0].key().as_str(),
        "matching_question_count"
    );
    assert_eq!(
        evi.measurements()[0].observed_value(),
        &EvidenceValue::Unsigned(1)
    );

    // 2. maximum_label_length
    assert_eq!(evi.measurements()[1].key().as_str(), "maximum_label_length");
    assert_eq!(
        evi.measurements()[1].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    // 3. maximum_label_octet_diversity_ratio
    assert_eq!(
        evi.measurements()[2].key().as_str(),
        "maximum_label_octet_diversity_ratio"
    );
    assert_eq!(
        evi.measurements()[2].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    // 4. maximum_qname_wire_length
    assert_eq!(
        evi.measurements()[3].key().as_str(),
        "maximum_qname_wire_length"
    );
    assert_eq!(
        evi.measurements()[3].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    // 5. question_count
    assert_eq!(evi.measurements()[4].key().as_str(), "question_count");
    assert_eq!(
        evi.measurements()[4].observed_value(),
        &EvidenceValue::Unsigned(1)
    );
}

#[test]
fn test_dns_possible_tunneling_parameter_validation() {
    let detector = DnsPossibleTunnelingDetector::new();

    // Default empty params -> valid
    assert!(
        detector
            .validate_parameters(&DetectorParameters::empty())
            .is_ok()
    );

    // Valid boundary config (strictly sorted)
    let mut b_valid = DetectorParameters::builder();
    b_valid
        .add(
            DetectorParameterKey::try_new("maximum_tracked_dns_flows").unwrap(),
            DetectorParameterValue::Unsigned(16),
        )
        .unwrap();
    b_valid
        .add(
            DetectorParameterKey::try_new("minimum_candidate_query_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(3, 4).unwrap()),
        )
        .unwrap();
    b_valid
        .add(
            DetectorParameterKey::try_new("minimum_label_length").unwrap(),
            DetectorParameterValue::Unsigned(40),
        )
        .unwrap();
    b_valid
        .add(
            DetectorParameterKey::try_new("minimum_label_octet_diversity_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(1, 3).unwrap()),
        )
        .unwrap();
    b_valid
        .add(
            DetectorParameterKey::try_new("minimum_qname_wire_length").unwrap(),
            DetectorParameterValue::Unsigned(120),
        )
        .unwrap();
    b_valid
        .add(
            DetectorParameterKey::try_new("minimum_query_observations").unwrap(),
            DetectorParameterValue::Unsigned(8),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_valid.build().unwrap())
            .is_ok()
    );

    // Invalid minimum_query_observations: 1 (< 2)
    let mut b_under_q = DetectorParameters::builder();
    b_under_q
        .add(
            DetectorParameterKey::try_new("minimum_query_observations").unwrap(),
            DetectorParameterValue::Unsigned(1),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_under_q.build().unwrap())
            .is_err()
    );

    // Invalid minimum_candidate_query_ratio: 0
    let mut b_zero_r = DetectorParameters::builder();
    b_zero_r
        .add(
            DetectorParameterKey::try_new("minimum_candidate_query_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::ZERO),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_zero_r.build().unwrap())
            .is_err()
    );

    // Invalid minimum_candidate_query_ratio: > 1
    let mut b_over_r = DetectorParameters::builder();
    b_over_r
        .add(
            DetectorParameterKey::try_new("minimum_candidate_query_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(2, 1).unwrap()),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_over_r.build().unwrap())
            .is_err()
    );

    // Invalid maximum_tracked_dns_flows: 0
    let mut b_zero_f = DetectorParameters::builder();
    b_zero_f
        .add(
            DetectorParameterKey::try_new("maximum_tracked_dns_flows").unwrap(),
            DetectorParameterValue::Unsigned(0),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_zero_f.build().unwrap())
            .is_err()
    );
}

#[test]
fn test_dns_possible_tunneling_detection_matching() {
    let detector = DnsPossibleTunnelingDetector::new();
    let flow1 = create_synthetic_flow(1);
    let flow2 = create_synthetic_flow(2);

    let mut observations = Vec::new();

    // Flow 1: 8 candidate queries with high diversity and long QNAME (e.g. 3 labels of 45 chars >= 120 total, max_label 45 >= 40, diversity >= 1/3)
    for i in 0..8 {
        let label45_1: Vec<u8> = (0..45)
            .map(|j| b'a' + (((i * 45) + j) % 26) as u8)
            .collect();
        let label45_2: Vec<u8> = (0..45)
            .map(|j| b'A' + (((i * 45) + j) % 26) as u8)
            .collect();
        let label45_3: Vec<u8> = (0..45)
            .map(|j| b'0' + (((i * 45) + j) % 10) as u8)
            .collect();
        observations.push(create_synthetic_dns_obs(
            i as u64,
            i as u64,
            Some(flow1.reference),
            true,
            vec![label45_1, label45_2, label45_3, b"net".to_vec()],
        ));
    }

    // Flow 2: 8 queries with long label (45 chars) but monomorphic low diversity (all 'a' -> diversity 1/45 < 1/3)
    for i in 0..8 {
        let low_div_label: Vec<u8> = vec![b'a'; 45];
        observations.push(create_synthetic_dns_obs(
            10 + i as u64,
            10 + i as u64,
            Some(flow2.reference),
            true,
            vec![
                low_div_label.clone(),
                low_div_label.clone(),
                low_div_label,
                b"test".to_vec(),
            ],
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

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .expect("evaluation succeeds");

    // Only Flow 1 should match! Flow 2 fails diversity threshold.
    assert_eq!(sink.len(), 1);
    let findings = sink.into_drafts();

    assert_eq!(findings[0].severity(), Severity::Low);
    assert_eq!(findings[0].confidence(), Confidence::Medium);
    assert_eq!(
        findings[0].title().as_str(),
        "Possible DNS tunneling pattern"
    );
    assert_eq!(
        findings[0].subject().flow_references(),
        &[FlowReference::new(1)]
    );
    assert_eq!(findings[0].evidence().len(), 1);

    let evi = &findings[0].evidence()[0];
    assert_eq!(evi.kind(), EvidenceKind::RatioComparison);
    assert_eq!(evi.measurements().len(), 6);

    // Verify 6 alphabetical metric keys
    assert_eq!(
        evi.measurements()[0].key().as_str(),
        "candidate_query_count"
    );
    assert_eq!(
        evi.measurements()[0].observed_value(),
        &EvidenceValue::Unsigned(8)
    );

    assert_eq!(
        evi.measurements()[1].key().as_str(),
        "candidate_query_ratio"
    );
    assert_eq!(
        evi.measurements()[1].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    assert_eq!(
        evi.measurements()[2].key().as_str(),
        "dns_query_observation_count"
    );
    assert_eq!(
        evi.measurements()[2].observed_value(),
        &EvidenceValue::Unsigned(8)
    );
    assert_eq!(
        evi.measurements()[2].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    assert_eq!(evi.measurements()[3].key().as_str(), "maximum_label_length");
    assert_eq!(
        evi.measurements()[3].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    assert_eq!(
        evi.measurements()[4].key().as_str(),
        "maximum_label_octet_diversity_ratio"
    );
    assert_eq!(
        evi.measurements()[4].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );

    assert_eq!(
        evi.measurements()[5].key().as_str(),
        "maximum_qname_wire_length"
    );
    assert_eq!(
        evi.measurements()[5].comparison(),
        Some(EvidenceComparison::GreaterThanOrEqual)
    );
}

#[test]
fn test_dns_detectors_integrated_execution_pipeline() {
    let mut registry = pcapraven_detection::DetectorRegistry::new(10).unwrap();
    registry
        .register(Box::new(DnsLongQueryNameDetector::new()))
        .unwrap();
    registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let flow = create_synthetic_flow(0);
    let mut observations = Vec::new();

    // Add 8 high-diversity long queries -> triggers both LongQueryName (on each query) and PossibleTunneling (on the flow)
    for i in 0..8 {
        let label45_1: Vec<u8> = (0..45)
            .map(|j| b'a' + (((i * 45) + j) % 26) as u8)
            .collect();
        let label45_2: Vec<u8> = (0..45)
            .map(|j| b'A' + (((i * 45) + j) % 26) as u8)
            .collect();
        let label45_3: Vec<u8> = (0..45)
            .map(|j| b'0' + (((i * 45) + j) % 10) as u8)
            .collect();
        observations.push(create_synthetic_dns_obs(
            i as u64,
            i as u64,
            Some(flow.reference),
            true,
            vec![label45_1, label45_2, label45_3, b"corp".to_vec()],
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

    let limits = DetectionLimits::default();
    let outcome = execute_detection(&registry, &input, &DetectorConfigurations::new(), &limits)
        .expect("detection engine pipeline executes successfully");

    assert_eq!(outcome.completion, DetectionInputCompleteness::Complete);
    // 8 findings from dns.long_query_name + 1 finding from dns.possible_tunneling = 9 findings
    assert_eq!(outcome.findings.len(), 9);
    assert_eq!(outcome.evidence.len(), 9);

    // Verify deterministic references: find:0 .. find:8, evi:0 .. evi:8
    for (i, f) in outcome.findings.iter().enumerate() {
        assert_eq!(f.reference().id(), i as u64);
    }
    for (i, e) in outcome.evidence.iter().enumerate() {
        assert_eq!(e.reference().id(), i as u64);
    }
}

#[test]
fn test_dns_long_query_name_sink_limits() {
    let detector = DnsLongQueryNameDetector::new();
    let flow = create_synthetic_flow(0);

    let mut observations = Vec::new();
    for i in 0..5 {
        let label45_1: Vec<u8> = (0..45).map(|j| b'a' + (j % 26)).collect();
        let label45_2: Vec<u8> = (0..45).map(|j| b'A' + (j % 26)).collect();
        let label45_3: Vec<u8> = (0..45).map(|j| b'0' + (j % 10)).collect();
        observations.push(create_synthetic_dns_obs(
            i as u64,
            i as u64,
            Some(flow.reference),
            true,
            vec![label45_1, label45_2, label45_3, b"com".to_vec()],
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

    // Capacity 5 -> all fit
    let mut sink_ok = DetectorDraftSink::new(5, 50);
    assert!(
        detector
            .evaluate(&input, &DetectorParameters::empty(), &mut sink_ok)
            .is_ok()
    );
    assert_eq!(sink_ok.len(), 5);

    // Capacity 4 -> fails on 5th with ResourceLimitExceeded
    let mut sink_limited = DetectorDraftSink::new(4, 50);
    let err = detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink_limited)
        .unwrap_err();
    assert!(matches!(
        err,
        pcapraven_detection::DetectorExecutionError::ResourceLimitExceeded { .. }
    ));
}

#[test]
fn test_dns_possible_tunneling_tracked_flows_limit() {
    let detector = DnsPossibleTunnelingDetector::new();

    let mut flows = Vec::new();
    let mut observations = Vec::new();

    // Create 17 flows (each with 1 long high-diversity query)
    for i in 0..17 {
        let flow = create_synthetic_flow(i as u64);
        let label45_1: Vec<u8> = (0..45).map(|j| b'a' + (j % 26)).collect();
        let label45_2: Vec<u8> = (0..45).map(|j| b'A' + (j % 26)).collect();
        let label45_3: Vec<u8> = (0..45).map(|j| b'0' + (j % 10)).collect();
        observations.push(create_synthetic_dns_obs(
            i as u64,
            i as u64,
            Some(flow.reference),
            true,
            vec![label45_1, label45_2, label45_3, b"net".to_vec()],
        ));
        flows.push(flow);
    }

    let input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    // Config with maximum_tracked_dns_flows = 16
    let mut params = DetectorParameters::builder();
    params
        .add(
            DetectorParameterKey::try_new("maximum_tracked_dns_flows").unwrap(),
            DetectorParameterValue::Unsigned(16),
        )
        .unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    let err = detector
        .evaluate(&input, &params.build().unwrap(), &mut sink)
        .unwrap_err();
    assert!(matches!(
        err,
        pcapraven_detection::DetectorExecutionError::ResourceLimitExceeded { .. }
    ));
}

#[test]
fn test_dns_detectors_skip_partial_input_in_engine() {
    let mut registry = pcapraven_detection::DetectorRegistry::new(10).unwrap();
    registry
        .register(Box::new(DnsLongQueryNameDetector::new()))
        .unwrap();
    registry
        .register(Box::new(DnsPossibleTunnelingDetector::new()))
        .unwrap();

    let flow = create_synthetic_flow(0);
    let label45_1: Vec<u8> = (0..45).map(|j| b'a' + (j % 26)).collect();
    let label45_2: Vec<u8> = (0..45).map(|j| b'A' + (j % 26)).collect();
    let label45_3: Vec<u8> = (0..45).map(|j| b'0' + (j % 10)).collect();
    let obs = create_synthetic_dns_obs(
        0,
        0,
        Some(flow.reference),
        true,
        vec![label45_1, label45_2, label45_3, b"test".to_vec()],
    );

    let flows = vec![flow];
    let observations = vec![obs];
    let limitations = vec![pcapraven_detection::DetectionInputLimitation::CaptureTruncated];
    let partial_input = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Partial,
        &limitations,
    )
    .unwrap();

    let limits = DetectionLimits::default();
    let outcome = execute_detection(
        &registry,
        &partial_input,
        &DetectorConfigurations::new(),
        &limits,
    )
    .expect("detection completes");

    assert_eq!(outcome.completion, DetectionInputCompleteness::Partial);
    assert_eq!(outcome.findings.len(), 0);
    assert_eq!(outcome.evidence.len(), 0);
    assert_eq!(outcome.detector_executions.len(), 2);
    assert_eq!(
        outcome.detector_executions[0].status,
        pcapraven_detection::DetectorExecutionStatus::SkippedIncompleteData
    );
    assert_eq!(
        outcome.detector_executions[1].status,
        pcapraven_detection::DetectorExecutionStatus::SkippedIncompleteData
    );
}

#[test]
fn test_dns_possible_tunneling_unassociated_queries_ignored() {
    let detector = DnsPossibleTunnelingDetector::new();
    let mut observations = Vec::new();

    // 10 high-diversity long queries, but all UNASSOCIATED (no flow)
    for i in 0..10 {
        let label45_1: Vec<u8> = (0..45).map(|j| b'a' + (j % 26)).collect();
        let label45_2: Vec<u8> = (0..45).map(|j| b'A' + (j % 26)).collect();
        let label45_3: Vec<u8> = (0..45).map(|j| b'0' + (j % 10)).collect();
        observations.push(create_synthetic_dns_obs(
            i as u64,
            i as u64,
            None,
            true,
            vec![label45_1, label45_2, label45_3, b"net".to_vec()],
        ));
    }

    let input = DetectionInput::try_new(
        &[],
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    assert!(
        detector
            .evaluate(&input, &DetectorParameters::empty(), &mut sink)
            .is_ok()
    );
    assert_eq!(sink.len(), 0);
}
