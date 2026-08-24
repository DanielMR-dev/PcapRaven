#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_detection::{
    CorrelationRegistry, DetectionInput, DetectionInputCompleteness, DetectionLimits,
    DetectorConfigurations, DetectorRegistry, DnsLongQueryNameDetector,
    DnsPossibleTunnelingDetector, PeriodicBeaconingDetector, PossibleC2MultiSignalCorrelator,
    RepeatedLowVolumeFlowDetector, execute_detection_with_correlators,
};
use pcapraven_domain::{
    DnsFlags, DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness, DnsQuestion,
    DnsTransport, EvidenceReference, FlowDirection, FlowDuration, FlowEndReason, FlowEndpoint,
    FlowInterArrivalMetrics, FlowKey, FlowRecord, FlowReference, FlowTemporalMetrics,
    FlowTemporalUnavailableReason, FlowTemporalValue, FlowTimestampCoverage, FlowTrafficCounters,
    FlowTrafficStatistics, IpAddress, ObservationFlowAssociation, ObservationReference,
    PacketReference, PacketTimestamp, ProtocolKind, ProtocolObservation, ProtocolObservationData,
    TransportProtocol,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_FLOWS: usize = 16;
const MAX_OBSERVATIONS: usize = 32;

fn insufficient_inter_arrival() -> FlowInterArrivalMetrics {
    let unavailable =
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples);
    FlowInterArrivalMetrics::new(
        0,
        0,
        unavailable,
        unavailable,
        unavailable,
        0,
        unavailable,
    )
}

fn flow(reference: u64, byte: u8) -> Option<FlowRecord> {
    let source_port = 40_000_u16.checked_add(u16::from(byte))?;
    let key = FlowKey::new(
        TransportProtocol::Udp,
        FlowEndpoint::new(IpAddress::Ipv4([192, 0, 2, 10]), source_port),
        FlowEndpoint::new(IpAddress::Ipv4([198, 51, 100, 53]), 53),
    );
    let packet_count = 10_u64;
    let wire_bytes = packet_count.checked_mul(64)?;
    let counters = FlowTrafficCounters::new(packet_count, wire_bytes, wire_bytes, 0);
    let traffic = FlowTrafficStatistics::new(
        counters,
        counters,
        FlowTrafficCounters::empty(),
        FlowTrafficCounters::empty(),
    );
    let interval_seconds = u64::from(byte % 20).checked_add(1)?;
    let periodic = FlowInterArrivalMetrics::new(
        packet_count.checked_sub(1)?,
        0,
        FlowTemporalValue::Available(FlowDuration::from_secs(interval_seconds)),
        FlowTemporalValue::Available(FlowDuration::from_secs(interval_seconds)),
        FlowTemporalValue::Available(FlowDuration::from_secs(interval_seconds)),
        packet_count.checked_sub(2)?,
        FlowTemporalValue::Available(FlowDuration::ZERO),
    );
    let duration_seconds = interval_seconds.checked_mul(packet_count.checked_sub(1)?)?;
    let temporal = FlowTemporalMetrics::new(
        PacketTimestamp::Unavailable,
        PacketTimestamp::Unavailable,
        FlowTemporalValue::Available(FlowDuration::from_secs(duration_seconds)),
        FlowTimestampCoverage::default(),
        periodic.clone(),
        periodic,
        insufficient_inter_arrival(),
        insufficient_inter_arrival(),
    );
    let first_ordinal = reference.checked_mul(2)?;
    let last_ordinal = first_ordinal.checked_add(1)?;
    Some(FlowRecord::new(
        FlowReference::new(reference),
        key,
        PacketReference::new(first_ordinal, None, None, 64, 64, false),
        PacketReference::new(last_ordinal, None, None, 64, 64, false),
        FlowEndReason::EndOfInput,
        traffic,
        temporal,
    ))
}

fn observation(reference: u64, byte: u8, flow_count: usize) -> Option<ProtocolObservation> {
    if flow_count == 0 {
        return None;
    }
    let labels: Vec<Vec<u8>> = (0_u8..3)
        .map(|label_index| {
            (0_u8..45)
                .map(|offset| b'a'.saturating_add(byte.wrapping_add(label_index).wrapping_add(offset) % 26))
                .collect()
        })
        .chain(std::iter::once(b"example".to_vec()))
        .collect();
    let name = DnsName::from_labels(labels)?;
    let packet_ordinal = 10_000_u64.checked_add(reference)?;
    let packet = PacketReference::new(packet_ordinal, None, None, 256, 256, false);
    let dns = DnsObservation {
        packet,
        timestamp: PacketTimestamp::Unavailable,
        transport: DnsTransport::Udp,
        source_ip: IpAddress::Ipv4([192, 0, 2, 10]),
        source_port: 53_000,
        destination_ip: IpAddress::Ipv4([198, 51, 100, 53]),
        destination_port: 53,
        transaction_id: u16::from(byte),
        message_kind: DnsMessageKind::Query,
        opcode: 0,
        response_code: 0,
        effective_response_code: 0,
        flags: DnsFlags {
            qr: false,
            ..DnsFlags::default()
        },
        declared_qdcount: 1,
        declared_ancount: 0,
        declared_nscount: 0,
        declared_arcount: 0,
        questions: vec![DnsQuestion::new(name, 1, 1)],
        records: Vec::new(),
        edns: None,
        completeness: DnsObservationCompleteness::Complete,
    };
    let flow_index = usize::from(byte) % flow_count;
    let flow_reference = FlowReference::new(u64::try_from(flow_index).ok()?);
    ProtocolObservation::try_new(
        ObservationReference::new(packet_ordinal, ProtocolKind::Dns, 0),
        ObservationFlowAssociation::Associated {
            flow: flow_reference,
            direction: FlowDirection::AToB,
        },
        ProtocolObservationData::Dns(dns),
    )
    .ok()
}

fn assert_outcome_integrity(
    outcome: &pcapraven_detection::DetectionRunOutcome,
    limits: &DetectionLimits,
) {
    assert!(outcome.findings.len() <= limits.max_total_findings());
    assert!(outcome.evidence.len() <= limits.max_total_evidence_records());
    assert!(outcome.diagnostics.len() <= limits.max_execution_diagnostics());
    assert!(
        outcome
            .findings
            .windows(2)
            .all(|window| window[0].reference() < window[1].reference())
    );
    assert!(
        outcome
            .evidence
            .windows(2)
            .all(|window| window[0].reference() < window[1].reference())
    );
    let evidence_references: BTreeSet<EvidenceReference> = outcome
        .evidence
        .iter()
        .map(|evidence| evidence.reference())
        .collect();
    let findings_by_reference: BTreeMap<_, _> = outcome
        .findings
        .iter()
        .map(|finding| (finding.reference(), finding))
        .collect();
    for finding in &outcome.findings {
        assert!(
            finding
                .evidence_references()
                .iter()
                .all(|reference| evidence_references.contains(reference))
        );
        let mut source_evidence = BTreeSet::new();
        for source_reference in finding.source_finding_references() {
            assert!(*source_reference < finding.reference());
            let source = findings_by_reference.get(source_reference);
            assert!(source.is_some());
            let Some(source) = source else {
                return;
            };
            source_evidence.extend(source.evidence_references().iter().copied());
        }
        if !finding.source_finding_references().is_empty() {
            assert!(
                finding
                    .evidence_references()
                    .iter()
                    .all(|reference| source_evidence.contains(reference))
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let flow_count = data
        .first()
        .copied()
        .map_or(0, |byte| usize::from(byte) % (MAX_FLOWS + 1));
    let observation_count = data
        .get(1)
        .copied()
        .map_or(0, |byte| usize::from(byte) % (MAX_OBSERVATIONS + 1));
    let mut source = data.iter().copied().cycle();
    let flows: Vec<_> = (0..flow_count)
        .filter_map(|index| {
            flow(
                u64::try_from(index).ok()?,
                source.next().unwrap_or_default(),
            )
        })
        .collect();
    let observations: Vec<_> = (0..observation_count)
        .filter_map(|index| {
            observation(
                u64::try_from(index).ok()?,
                source.next().unwrap_or_default(),
                flows.len(),
            )
        })
        .collect();
    assert!(flows.len() <= MAX_FLOWS);
    assert!(observations.len() <= MAX_OBSERVATIONS);

    let Ok(mut detectors) = DetectorRegistry::new(8) else {
        return;
    };
    let Some(periodic) = PeriodicBeaconingDetector::try_new().ok() else {
        return;
    };
    let Some(long_query) = DnsLongQueryNameDetector::try_new().ok() else {
        return;
    };
    let Some(tunneling) = DnsPossibleTunnelingDetector::try_new().ok() else {
        return;
    };
    let Some(low_volume) = RepeatedLowVolumeFlowDetector::try_new().ok() else {
        return;
    };
    if detectors.register(Box::new(periodic)).is_err()
        || detectors.register(Box::new(long_query)).is_err()
        || detectors.register(Box::new(tunneling)).is_err()
        || detectors.register(Box::new(low_volume)).is_err()
    {
        return;
    }
    let Ok(mut correlators) = CorrelationRegistry::new(4) else {
        return;
    };
    let Some(correlator) = PossibleC2MultiSignalCorrelator::try_new().ok() else {
        return;
    };
    if correlators.register(Box::new(correlator)).is_err() {
        return;
    }
    let Ok(limits) = DetectionLimits::builder()
        .max_registered_detectors(8)
        .max_parameters_per_detector(16)
        .max_total_findings(32)
        .max_total_evidence_records(64)
        .max_execution_diagnostics(16)
        .build()
    else {
        return;
    };
    let configurations = DetectorConfigurations::default();
    let Ok(input) = DetectionInput::try_new(
        &flows,
        &observations,
        DetectionInputCompleteness::Complete,
        &[],
    ) else {
        return;
    };
    let first = execute_detection_with_correlators(
        &detectors,
        &correlators,
        &input,
        &configurations,
        &limits,
    );
    let second = execute_detection_with_correlators(
        &detectors,
        &correlators,
        &input,
        &configurations,
        &limits,
    );
    assert_eq!(first, second);
    if let Ok(outcome) = &first {
        assert_outcome_integrity(outcome, &limits);
    }
});
