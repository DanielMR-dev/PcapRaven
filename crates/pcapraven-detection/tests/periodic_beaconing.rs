//! Integration tests for Explainable Periodic Beaconing Detector.

use pcapraven_detection::periodic_beaconing::PeriodicBeaconingDetector;
use pcapraven_detection::*;
use pcapraven_domain::*;

fn create_test_flow_with_protocol(
    ordinal: u64,
    protocol: TransportProtocol,
    a_to_b: FlowInterArrivalMetrics,
    b_to_a: FlowInterArrivalMetrics,
) -> FlowRecord {
    let key = FlowKey::new(
        protocol,
        FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 100]), 45000),
        FlowEndpoint::new(IpAddress::Ipv4([198, 51, 100, 1]), 443),
    );
    let pkt = PacketReference::new(ordinal, None, None, 100, 100, false);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let empty_metrics = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Available(FlowDuration::from_secs(100)),
        FlowTimestampCoverage {
            available_timestamps: 10,
            unavailable_timestamps: 0,
            invalid_timestamps: 0,
            non_monotonic_transitions: 0,
        },
        empty_metrics.clone(),
        a_to_b,
        b_to_a,
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

fn create_test_flow(
    ordinal: u64,
    a_to_b: FlowInterArrivalMetrics,
    b_to_a: FlowInterArrivalMetrics,
) -> FlowRecord {
    create_test_flow_with_protocol(ordinal, TransportProtocol::Tcp, a_to_b, b_to_a)
}

fn create_periodic_metrics(
    samples: u64,
    discontinuities: u64,
    min_secs: u64,
    max_secs: u64,
    mean_secs: u64,
    jitter_num: u128,
    jitter_den: u128,
) -> FlowInterArrivalMetrics {
    FlowInterArrivalMetrics::new(
        samples,
        discontinuities,
        FlowTemporalValue::Available(FlowDuration::from_secs(min_secs)),
        FlowTemporalValue::Available(FlowDuration::from_secs(max_secs)),
        FlowTemporalValue::Available(FlowDuration::from_secs(mean_secs)),
        samples.saturating_sub(1),
        FlowTemporalValue::Available(FlowDuration::from_fraction(jitter_num, jitter_den).unwrap()),
    )
}

#[test]
fn test_periodic_beaconing_metadata_and_defaults() {
    let detector = PeriodicBeaconingDetector::new();
    let meta = detector.metadata();

    assert_eq!(meta.id().as_str(), "behavior.periodic_beaconing");
    assert_eq!(meta.version(), DetectorVersion::new(1, 0, 0));
    assert_eq!(
        meta.title().as_str(),
        "Possible periodic beaconing behavior"
    );
    assert_eq!(meta.incomplete_data_policy(), IncompleteDataPolicy::Skip);

    assert_eq!(
        PeriodicBeaconingDetector::DEFAULT_MINIMUM_INTERVAL_SAMPLES,
        6
    );
    assert_eq!(PeriodicBeaconingDetector::HARD_MIN_INTERVAL_SAMPLES, 3);
    assert_eq!(PeriodicBeaconingDetector::DEFAULT_MIN_MEAN_INTERVAL_SECS, 1);
}

#[test]
fn test_parameter_validation_all_branches() {
    let detector = PeriodicBeaconingDetector::new();

    // Default / empty parameters is valid
    assert!(
        detector
            .validate_parameters(&DetectorParameters::empty())
            .is_ok()
    );

    // Valid custom parameters
    let mut builder = DetectorParameters::builder();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(1, 20).unwrap()),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("maximum_spread_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(1, 5).unwrap()),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("minimum_interval_samples").unwrap(),
            DetectorParameterValue::Unsigned(10),
        )
        .unwrap();
    builder
        .add(
            DetectorParameterKey::try_new("minimum_mean_interval").unwrap(),
            DetectorParameterValue::Duration(FlowDuration::from_secs(5)),
        )
        .unwrap();
    let valid_params = builder.build().unwrap();
    assert!(detector.validate_parameters(&valid_params).is_ok());

    // Unknown parameter rejected
    let mut unk_builder = DetectorParameters::builder();
    unk_builder
        .add(
            DetectorParameterKey::try_new("unknown_param").unwrap(),
            DetectorParameterValue::Boolean(true),
        )
        .unwrap();
    assert_eq!(
        detector
            .validate_parameters(&unk_builder.build().unwrap())
            .unwrap_err(),
        DetectorConfigError::UnknownParameter("unknown_param".to_string())
    );

    // minimum_interval_samples < 3 rejected
    let mut low_samples = DetectorParameters::builder();
    low_samples
        .add(
            DetectorParameterKey::try_new("minimum_interval_samples").unwrap(),
            DetectorParameterValue::Unsigned(2),
        )
        .unwrap();
    assert_eq!(
        detector
            .validate_parameters(&low_samples.build().unwrap())
            .unwrap_err(),
        DetectorConfigError::ParameterValueOutOfRange {
            key: "minimum_interval_samples".to_string(),
            reason: "minimum interval samples must be at least 3",
        }
    );

    // minimum_mean_interval == 0 rejected
    let mut zero_mean = DetectorParameters::builder();
    zero_mean
        .add(
            DetectorParameterKey::try_new("minimum_mean_interval").unwrap(),
            DetectorParameterValue::Duration(FlowDuration::ZERO),
        )
        .unwrap();
    assert_eq!(
        detector
            .validate_parameters(&zero_mean.build().unwrap())
            .unwrap_err(),
        DetectorConfigError::ParameterValueOutOfRange {
            key: "minimum_mean_interval".to_string(),
            reason: "minimum mean interval must be greater than zero",
        }
    );

    // Wrong parameter type rejected
    let mut wrong_type = DetectorParameters::builder();
    wrong_type
        .add(
            DetectorParameterKey::try_new("minimum_interval_samples").unwrap(),
            DetectorParameterValue::Boolean(true),
        )
        .unwrap();
    assert_eq!(
        detector
            .validate_parameters(&wrong_type.build().unwrap())
            .unwrap_err(),
        DetectorConfigError::InvalidParameterType {
            key: "minimum_interval_samples".to_string(),
            expected: "unsigned integer",
        }
    );
}

#[test]
fn test_periodic_beaconing_clean_detection_a_to_b() {
    let detector = PeriodicBeaconingDetector::new();
    // 10 samples, 0 discontinuities, min=10s, max=10s, mean=10s, jitter=0s (perfect period)
    let a_to_b = create_periodic_metrics(10, 0, 10, 10, 10, 0, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    let findings = sink.into_drafts();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(
        finding.subject().flow_references(),
        &[FlowReference::new(0)]
    );
    assert_eq!(
        finding.title().as_str(),
        "Possible periodic beaconing behavior"
    );
    assert_eq!(finding.severity(), Severity::Low);
    assert_eq!(finding.confidence(), Confidence::Medium);
    assert_eq!(finding.evidence().len(), 1);

    let evi = &finding.evidence()[0];
    assert_eq!(evi.kind(), EvidenceKind::TemporalMetric);
    assert_eq!(evi.flow_references(), &[FlowReference::new(0)]);
    assert!(evi.description().as_str().contains("A-to-B"));

    // Check all 9 measurements strictly ordered
    assert_eq!(evi.measurements().len(), 9);
    assert_eq!(evi.measurements()[0].key().as_str(), "discontinuity_count");
    assert_eq!(
        evi.measurements()[0].observed_value(),
        &EvidenceValue::Unsigned(0)
    );
    assert_eq!(
        evi.measurements()[1].key().as_str(),
        "interval_sample_count"
    );
    assert_eq!(
        evi.measurements()[1].observed_value(),
        &EvidenceValue::Unsigned(10)
    );
    assert_eq!(evi.measurements()[2].key().as_str(), "maximum_interval");
    assert_eq!(
        evi.measurements()[3].key().as_str(),
        "mean_absolute_successive_interval_delta"
    );
    assert_eq!(evi.measurements()[4].key().as_str(), "mean_interval");
    assert_eq!(evi.measurements()[5].key().as_str(), "minimum_interval");
    assert_eq!(
        evi.measurements()[6].key().as_str(),
        "relative_jitter_ratio"
    );
    assert_eq!(evi.measurements()[7].key().as_str(), "spread_ratio");
    assert_eq!(
        evi.measurements()[8].key().as_str(),
        "successive_delta_sample_count"
    );
}

#[test]
fn test_periodic_beaconing_clean_detection_b_to_a() {
    let detector = PeriodicBeaconingDetector::new();
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let a_to_b = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let b_to_a = create_periodic_metrics(8, 0, 5, 5, 5, 0, 1);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    let findings = sink.into_drafts();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence().len(), 1);
    assert!(
        findings[0].evidence()[0]
            .description()
            .as_str()
            .contains("B-to-A")
    );
}

#[test]
fn test_periodic_beaconing_both_directions() {
    let detector = PeriodicBeaconingDetector::new();
    let a_to_b = create_periodic_metrics(10, 0, 10, 10, 10, 0, 1);
    let b_to_a = create_periodic_metrics(8, 0, 5, 5, 5, 0, 1);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    let findings = sink.into_drafts();
    assert_eq!(findings.len(), 1);
    // Emits 1 finding with 2 evidence drafts (one for each direction)
    assert_eq!(findings[0].evidence().len(), 2);
    assert!(
        findings[0].evidence()[0]
            .description()
            .as_str()
            .contains("A-to-B")
    );
    assert!(
        findings[0].evidence()[1]
            .description()
            .as_str()
            .contains("B-to-A")
    );
}

#[test]
fn test_discontinuity_rejection() {
    let detector = PeriodicBeaconingDetector::new();
    // 1 discontinuity present -> must not detect
    let a_to_b = create_periodic_metrics(10, 1, 10, 10, 10, 0, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);
}

#[test]
fn test_insufficient_samples_rejection() {
    let detector = PeriodicBeaconingDetector::new();
    // 5 samples is below default 6
    let a_to_b = create_periodic_metrics(5, 0, 10, 10, 10, 0, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);

    // Custom threshold minimum_interval_samples = 4 allows it
    let mut custom = DetectorParameters::builder();
    custom
        .add(
            DetectorParameterKey::try_new("minimum_interval_samples").unwrap(),
            DetectorParameterValue::Unsigned(4),
        )
        .unwrap();
    let mut sink_custom = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &custom.build().unwrap(), &mut sink_custom)
        .unwrap();
    assert_eq!(sink_custom.len(), 1);
}

#[test]
fn test_short_mean_interval_rejection() {
    let detector = PeriodicBeaconingDetector::new();
    // Mean interval = 500ms (1/2 s) is below default 1s
    let a_to_b = FlowInterArrivalMetrics::new(
        10,
        0,
        FlowTemporalValue::Available(FlowDuration::from_fraction(1, 2).unwrap()),
        FlowTemporalValue::Available(FlowDuration::from_fraction(1, 2).unwrap()),
        FlowTemporalValue::Available(FlowDuration::from_fraction(1, 2).unwrap()),
        9,
        FlowTemporalValue::Available(FlowDuration::ZERO),
    );
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);

    // With minimum_mean_interval = 250ms (1/4 s), it is accepted
    let mut custom = DetectorParameters::builder();
    custom
        .add(
            DetectorParameterKey::try_new("minimum_mean_interval").unwrap(),
            DetectorParameterValue::Duration(FlowDuration::from_fraction(1, 4).unwrap()),
        )
        .unwrap();
    let mut sink_custom = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &custom.build().unwrap(), &mut sink_custom)
        .unwrap();
    assert_eq!(sink_custom.len(), 1);
}

#[test]
fn test_jitter_threshold_rejection() {
    let detector = PeriodicBeaconingDetector::new();
    // Mean = 10s. Jitter = 2s. Jitter ratio = 2/10 = 20% > default 10%
    let a_to_b = create_periodic_metrics(10, 0, 9, 11, 10, 2, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);

    // With maximum_jitter_ratio = 25% (1/4), it is accepted
    let mut custom = DetectorParameters::builder();
    custom
        .add(
            DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(1, 4).unwrap()),
        )
        .unwrap();
    let mut sink_custom = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &custom.build().unwrap(), &mut sink_custom)
        .unwrap();
    assert_eq!(sink_custom.len(), 1);
}

#[test]
fn test_spread_threshold_rejection() {
    let detector = PeriodicBeaconingDetector::new();
    // Mean = 10s. Min = 8s, Max = 12s. Spread = 4s. Spread ratio = 4/10 = 40% > default 25%
    // Jitter = 500ms (5%) <= 10%
    let a_to_b = FlowInterArrivalMetrics::new(
        10,
        0,
        FlowTemporalValue::Available(FlowDuration::from_secs(8)),
        FlowTemporalValue::Available(FlowDuration::from_secs(12)),
        FlowTemporalValue::Available(FlowDuration::from_secs(10)),
        9,
        FlowTemporalValue::Available(FlowDuration::from_fraction(1, 2).unwrap()),
    );
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);

    // With maximum_spread_ratio = 50% (1/2), it is accepted
    let mut custom = DetectorParameters::builder();
    custom
        .add(
            DetectorParameterKey::try_new("maximum_spread_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(1, 2).unwrap()),
        )
        .unwrap();
    let mut sink_custom = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &custom.build().unwrap(), &mut sink_custom)
        .unwrap();
    assert_eq!(sink_custom.len(), 1);
}

#[test]
fn test_ratio_bounds_validation_and_rejections() {
    let detector = PeriodicBeaconingDetector::new();

    // 0/1 -> valid
    let mut b0 = DetectorParameters::builder();
    b0.add(
        DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
        DetectorParameterValue::Ratio(EvidenceRatio::ZERO),
    )
    .unwrap();
    b0.add(
        DetectorParameterKey::try_new("maximum_spread_ratio").unwrap(),
        DetectorParameterValue::Ratio(EvidenceRatio::ZERO),
    )
    .unwrap();
    assert!(detector.validate_parameters(&b0.build().unwrap()).is_ok());

    // 1/1 -> valid
    let mut b1 = DetectorParameters::builder();
    b1.add(
        DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
        DetectorParameterValue::Ratio(EvidenceRatio::ONE),
    )
    .unwrap();
    b1.add(
        DetectorParameterKey::try_new("maximum_spread_ratio").unwrap(),
        DetectorParameterValue::Ratio(EvidenceRatio::ONE),
    )
    .unwrap();
    assert!(detector.validate_parameters(&b1.build().unwrap()).is_ok());

    // 100/101 -> valid
    let mut b_frac = DetectorParameters::builder();
    b_frac
        .add(
            DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(100, 101).unwrap()),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_frac.build().unwrap())
            .is_ok()
    );

    // 2/1 -> rejected
    let mut b_over = DetectorParameters::builder();
    b_over
        .add(
            DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(2, 1).unwrap()),
        )
        .unwrap();
    assert_eq!(
        detector
            .validate_parameters(&b_over.build().unwrap())
            .unwrap_err(),
        DetectorConfigError::ParameterValueOutOfRange {
            key: "maximum_jitter_ratio".to_string(),
            reason: "maximum jitter ratio cannot exceed 1.0 (1/1)",
        }
    );

    // 101/100 -> rejected
    let mut b_over2 = DetectorParameters::builder();
    b_over2
        .add(
            DetectorParameterKey::try_new("maximum_spread_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(101, 100).unwrap()),
        )
        .unwrap();
    assert_eq!(
        detector
            .validate_parameters(&b_over2.build().unwrap())
            .unwrap_err(),
        DetectorConfigError::ParameterValueOutOfRange {
            key: "maximum_spread_ratio".to_string(),
            reason: "maximum spread ratio cannot exceed 1.0 (1/1)",
        }
    );

    // u128::MAX / 1 -> rejected
    let mut b_max = DetectorParameters::builder();
    b_max
        .add(
            DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(u128::MAX, 1).unwrap()),
        )
        .unwrap();
    assert!(
        detector
            .validate_parameters(&b_max.build().unwrap())
            .is_err()
    );
}

#[test]
fn test_exact_threshold_equality_and_epsilon_rational() {
    let detector = PeriodicBeaconingDetector::new();
    // Mean = 10s. Jitter = 1s. Jitter ratio = 1/10 (exact default 1/10).
    // Spread = 2.5s (5/2). Spread ratio = (5/2) / 10 = 5/20 = 1/4 (exact default 1/4).
    let a_to_b = FlowInterArrivalMetrics::new(
        10,
        0,
        FlowTemporalValue::Available(FlowDuration::from_fraction(15, 2).unwrap()), // 7.5s
        FlowTemporalValue::Available(FlowDuration::from_secs(10)), // 10s -> spread = 2.5s
        FlowTemporalValue::Available(FlowDuration::from_secs(10)), // 10s
        9,
        FlowTemporalValue::Available(FlowDuration::from_secs(1)), // jitter = 1s -> 1/10
    );
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    // Exact match on default thresholds
    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 1);

    // If maximum_jitter_ratio is slightly below 1/10: 99/1000 (< 1/10) -> non-match
    let mut custom = DetectorParameters::builder();
    custom
        .add(
            DetectorParameterKey::try_new("maximum_jitter_ratio").unwrap(),
            DetectorParameterValue::Ratio(EvidenceRatio::from_fraction(99, 1000).unwrap()),
        )
        .unwrap();
    let mut sink_below = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &custom.build().unwrap(), &mut sink_below)
        .unwrap();
    assert_eq!(sink_below.len(), 0);
}

#[test]
fn test_large_u128_temporal_metrics_no_overflow() {
    let detector = PeriodicBeaconingDetector::new();
    // Huge numerator/denominator fractions in FlowDuration that would overflow direct cross-multiplication
    let num_a = 1_000_000_000_000_000_000u128;
    let den_a = 3_000_000_000_000_000_000u128; // 1/3 s
    let dur_a = FlowDuration::from_fraction(num_a, den_a).unwrap();

    let a_to_b = FlowInterArrivalMetrics::new(
        10,
        0,
        FlowTemporalValue::Available(dur_a),
        FlowTemporalValue::Available(dur_a),
        FlowTemporalValue::Available(dur_a),
        9,
        FlowTemporalValue::Available(FlowDuration::ZERO),
    );
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    // With minimum_mean_interval = 250ms (1/4 s), 1/3s is greater and matches without overflow
    let mut custom = DetectorParameters::builder();
    custom
        .add(
            DetectorParameterKey::try_new("minimum_mean_interval").unwrap(),
            DetectorParameterValue::Duration(FlowDuration::from_fraction(1, 4).unwrap()),
        )
        .unwrap();
    let mut sink = DetectorDraftSink::new(10, 50);
    assert!(
        detector
            .evaluate(&input, &custom.build().unwrap(), &mut sink)
            .is_ok()
    );
    assert_eq!(sink.len(), 1);
}

#[test]
fn test_temporal_coverage_and_end_reason_rejections() {
    let detector = PeriodicBeaconingDetector::new();
    let a_to_b = create_periodic_metrics(10, 0, 10, 10, 10, 0, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    // 1. FlowEndReason::AnalysisStopped -> must not match
    let mut flow_stopped = create_test_flow(0, a_to_b.clone(), b_to_a.clone());
    flow_stopped.end_reason = FlowEndReason::AnalysisStopped;
    let flows_stopped = vec![flow_stopped];
    let input_stopped = DetectionInput::try_new(
        &flows_stopped,
        &[],
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();
    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input_stopped, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);

    // 2. Unavailable timestamp coverage -> must not match
    let mut flow_unavail_cov = create_test_flow(1, a_to_b.clone(), b_to_a.clone());
    flow_unavail_cov.temporal.coverage.unavailable_timestamps = 1;
    let flows_unavail = vec![flow_unavail_cov];
    let input_unavail = DetectionInput::try_new(
        &flows_unavail,
        &[],
        DetectionInputCompleteness::Complete,
        &[],
    )
    .unwrap();
    let mut sink2 = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input_unavail, &DetectorParameters::empty(), &mut sink2)
        .unwrap();
    assert_eq!(sink2.len(), 0);

    // 3. Invalid timestamp coverage -> must not match
    let mut flow_inv_cov = create_test_flow(2, a_to_b.clone(), b_to_a.clone());
    flow_inv_cov.temporal.coverage.invalid_timestamps = 1;
    let flows_inv = vec![flow_inv_cov];
    let input_inv =
        DetectionInput::try_new(&flows_inv, &[], DetectionInputCompleteness::Complete, &[])
            .unwrap();
    let mut sink3 = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input_inv, &DetectorParameters::empty(), &mut sink3)
        .unwrap();
    assert_eq!(sink3.len(), 0);

    // 4. Non-monotonic transitions -> must not match
    let mut flow_non_mono = create_test_flow(3, a_to_b.clone(), b_to_a.clone());
    flow_non_mono.temporal.coverage.non_monotonic_transitions = 1;
    let flows_mono = vec![flow_non_mono];
    let input_mono =
        DetectionInput::try_new(&flows_mono, &[], DetectionInputCompleteness::Complete, &[])
            .unwrap();
    let mut sink4 = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input_mono, &DetectorParameters::empty(), &mut sink4)
        .unwrap();
    assert_eq!(sink4.len(), 0);

    // 5. Unavailable flow duration -> must not match
    let mut flow_dur_unavail = create_test_flow(4, a_to_b, b_to_a);
    flow_dur_unavail.temporal.duration =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::TimestampUnavailable);
    let flows_dur = vec![flow_dur_unavail];
    let input_dur =
        DetectionInput::try_new(&flows_dur, &[], DetectionInputCompleteness::Complete, &[])
            .unwrap();
    let mut sink5 = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input_dur, &DetectorParameters::empty(), &mut sink5)
        .unwrap();
    assert_eq!(sink5.len(), 0);
}

#[test]
fn test_udp_and_tcp_flows_qualify() {
    let detector = PeriodicBeaconingDetector::new();
    let a_to_b = create_periodic_metrics(10, 0, 10, 10, 10, 0, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let tcp_flow =
        create_test_flow_with_protocol(0, TransportProtocol::Tcp, a_to_b.clone(), b_to_a.clone());
    let udp_flow = create_test_flow_with_protocol(1, TransportProtocol::Udp, a_to_b, b_to_a);

    let flows = vec![tcp_flow, udp_flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 2);
}

#[test]
fn test_same_endpoint_series_does_not_match() {
    let detector = PeriodicBeaconingDetector::new();
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let empty_metrics = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let periodic_same = create_periodic_metrics(10, 0, 10, 10, 10, 0, 1);

    let key = FlowKey::new(
        TransportProtocol::Udp,
        FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 100]), 53),
        FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 100]), 53),
    );
    let pkt = PacketReference::new(0, None, None, 100, 100, false);
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Available(FlowDuration::from_secs(100)),
        FlowTimestampCoverage {
            available_timestamps: 10,
            unavailable_timestamps: 0,
            invalid_timestamps: 0,
            non_monotonic_transitions: 0,
        },
        empty_metrics.clone(),
        empty_metrics.clone(),
        empty_metrics,
        periodic_same,
    );

    let flow = FlowRecord::new(
        FlowReference::new(0),
        key,
        pkt,
        pkt,
        FlowEndReason::EndOfInput,
        FlowTrafficStatistics::empty(),
        temporal,
    );

    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);
}

#[test]
fn test_successive_delta_sample_count_requirement() {
    let detector = PeriodicBeaconingDetector::new();
    // 10 interval samples but only 4 successive delta samples (< 10 - 1 = 9)
    let a_to_b = FlowInterArrivalMetrics::new(
        10,
        0,
        FlowTemporalValue::Available(FlowDuration::from_secs(10)),
        FlowTemporalValue::Available(FlowDuration::from_secs(10)),
        FlowTemporalValue::Available(FlowDuration::from_secs(10)),
        4, // deltas < min_samples - 1
        FlowTemporalValue::Available(FlowDuration::ZERO),
    );
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow = create_test_flow(0, a_to_b, b_to_a);
    let flows = vec![flow];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    let mut sink = DetectorDraftSink::new(10, 50);
    detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink)
        .unwrap();
    assert_eq!(sink.len(), 0);
}

#[test]
fn test_sink_capacity_boundary_n_and_n_plus_1() {
    let detector = PeriodicBeaconingDetector::new();
    let a_to_b = create_periodic_metrics(10, 0, 10, 10, 10, 0, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);

    let flow0 = create_test_flow(0, a_to_b.clone(), b_to_a.clone());
    let flow1 = create_test_flow(1, a_to_b, b_to_a);

    let flows = vec![flow0, flow1];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();

    // Exactly capacity 2 findings -> fits
    let mut sink_exact = DetectorDraftSink::new(2, 20);
    assert!(
        detector
            .evaluate(&input, &DetectorParameters::empty(), &mut sink_exact)
            .is_ok()
    );
    assert_eq!(sink_exact.len(), 2);

    // Capacity 1 finding -> pushes first, fails on second with ResourceLimitExceeded
    let mut sink_overflow = DetectorDraftSink::new(1, 20);
    let err = detector
        .evaluate(&input, &DetectorParameters::empty(), &mut sink_overflow)
        .unwrap_err();
    assert_eq!(
        err,
        DetectorExecutionError::resource_limit("detector draft finding budget exceeded")
    );
}

#[test]
fn test_full_engine_integration_periodic_beaconing() {
    let mut registry = DetectorRegistry::default();
    registry
        .register(Box::new(PeriodicBeaconingDetector::new()))
        .unwrap();

    // Flow 0: Periodic
    let f0_a_to_b = create_periodic_metrics(10, 0, 10, 10, 10, 0, 1);
    let unavail =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    let f0_b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let flow0 = create_test_flow(0, f0_a_to_b, f0_b_to_a);

    // Flow 1: Irregular (high jitter)
    let f1_a_to_b = create_periodic_metrics(10, 0, 5, 20, 10, 5, 1);
    let f1_b_to_a = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let flow1 = create_test_flow(1, f1_a_to_b, f1_b_to_a);

    // Flow 2: Periodic in B->A
    let f2_a_to_b = FlowInterArrivalMetrics::new(0, 0, unavail, unavail, unavail, 0, unavail);
    let f2_b_to_a = create_periodic_metrics(8, 0, 30, 30, 30, 0, 1);
    let flow2 = create_test_flow(2, f2_a_to_b, f2_b_to_a);

    let flows = vec![flow0, flow1, flow2];
    let input =
        DetectionInput::try_new(&flows, &[], DetectionInputCompleteness::Complete, &[]).unwrap();
    let configs = DetectorConfigurations::new();
    let limits = DetectionLimits::default();

    let outcome = execute_detection(&registry, &input, &configs, &limits).unwrap();

    assert_eq!(outcome.completion, DetectionInputCompleteness::Complete);
    assert_eq!(outcome.detector_executions.len(), 1);
    assert_eq!(
        outcome.detector_executions[0].status,
        DetectorExecutionStatus::Executed
    );

    // 2 findings produced (for flow 0 and flow 2)
    assert_eq!(outcome.findings.len(), 2);
    assert_eq!(outcome.findings[0].reference(), FindingReference::new(0));
    assert_eq!(
        outcome.findings[0].subject().flow_references(),
        &[FlowReference::new(0)]
    );
    assert_eq!(
        outcome.findings[0].title().as_str(),
        "Possible periodic beaconing behavior"
    );
    assert_eq!(
        outcome.findings[0].detector_id().as_str(),
        "behavior.periodic_beaconing"
    );

    assert_eq!(outcome.findings[1].reference(), FindingReference::new(1));
    assert_eq!(
        outcome.findings[1].subject().flow_references(),
        &[FlowReference::new(2)]
    );
    assert_eq!(
        outcome.findings[1].detector_id().as_str(),
        "behavior.periodic_beaconing"
    );

    // Contiguous evidence records assigned by engine
    assert_eq!(outcome.evidence.len(), 2);
    assert_eq!(outcome.evidence[0].reference(), EvidenceReference::new(0));
    assert_eq!(outcome.evidence[1].reference(), EvidenceReference::new(1));
}
