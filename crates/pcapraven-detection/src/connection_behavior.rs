//! Explainable repeated low-volume flow behavior detector and connection peer key.
//!
//! Flags endpoint pairs exhibiting repetitive low-volume flow patterns
//! without asserting malware or confirmed command-and-control.

use crate::config::{DetectorParameterValue, DetectorParameters};
use crate::detector::{Detector, DetectorDraftSink, DetectorMetadata, IncompleteDataPolicy};
use crate::engine::{DetectionInput, DetectionInputCompleteness};
use crate::error::{DetectorConfigError, DetectorExecutionError};
use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, EvidenceComparison, EvidenceDescription,
    EvidenceDraftBuilder, EvidenceKind, EvidenceMeasurement, EvidenceMetricKey, EvidenceRatio,
    EvidenceUnit, EvidenceValue, FindingDraft, FindingRationale, FindingSubject, FindingSummary,
    FindingTitle, FindingValidationError, FlowDuration, FlowEndReason, FlowRecord, FlowReference,
    FlowTemporalValue, IpAddress, PacketReference, Severity, TransportProtocol,
};
use std::collections::BTreeMap;

/// Canonical, port-agnostic endpoint pair identifying communications between two hosts for a transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionPeerKey {
    transport: TransportProtocol,
    peer_a: IpAddress,
    peer_b: IpAddress,
}

impl ConnectionPeerKey {
    /// Creates a new canonical connection peer key, normalizing peer IPs so `peer_a <= peer_b`.
    #[must_use]
    pub fn new(transport: TransportProtocol, ip1: IpAddress, ip2: IpAddress) -> Self {
        let (peer_a, peer_b) = if ip1 <= ip2 { (ip1, ip2) } else { (ip2, ip1) };
        Self {
            transport,
            peer_a,
            peer_b,
        }
    }

    /// Returns the transport protocol.
    #[must_use]
    pub const fn transport(&self) -> TransportProtocol {
        self.transport
    }

    /// Returns the canonical first peer IP.
    #[must_use]
    pub const fn peer_a(&self) -> IpAddress {
        self.peer_a
    }

    /// Returns the canonical second peer IP.
    #[must_use]
    pub const fn peer_b(&self) -> IpAddress {
        self.peer_b
    }
}

#[derive(Debug, Clone)]
struct RepeatedFlowAggregate {
    eligible_flow_instance_count: u64,
    candidate_flow_count: u64,
    maximum_candidate_packet_count: u64,
    maximum_candidate_wire_bytes: u64,
    maximum_candidate_duration: FlowDuration,
    first_candidate_flow: Option<FlowReference>,
    last_candidate_flow: Option<FlowReference>,
    first_packet: Option<PacketReference>,
    last_packet: Option<PacketReference>,
}

impl RepeatedFlowAggregate {
    fn new() -> Self {
        Self {
            eligible_flow_instance_count: 0,
            candidate_flow_count: 0,
            maximum_candidate_packet_count: 0,
            maximum_candidate_wire_bytes: 0,
            maximum_candidate_duration: FlowDuration::ZERO,
            first_candidate_flow: None,
            last_candidate_flow: None,
            first_packet: None,
            last_packet: None,
        }
    }

    fn record_eligible(
        &mut self,
        flow: &FlowRecord,
        duration: FlowDuration,
        is_candidate: bool,
    ) -> Result<(), DetectorExecutionError> {
        self.eligible_flow_instance_count = self
            .eligible_flow_instance_count
            .checked_add(1)
            .ok_or_else(|| {
                DetectorExecutionError::resource_limit("eligible flow count overflow")
            })?;

        if is_candidate {
            self.candidate_flow_count =
                self.candidate_flow_count.checked_add(1).ok_or_else(|| {
                    DetectorExecutionError::resource_limit("candidate flow count overflow")
                })?;

            let wire_bytes = flow.traffic.total.wire_bytes;
            let packet_count = flow.traffic.total.packet_count;

            if wire_bytes > self.maximum_candidate_wire_bytes {
                self.maximum_candidate_wire_bytes = wire_bytes;
            }
            if packet_count > self.maximum_candidate_packet_count {
                self.maximum_candidate_packet_count = packet_count;
            }
            if duration > self.maximum_candidate_duration {
                self.maximum_candidate_duration = duration;
            }

            if self.first_candidate_flow.is_none() {
                self.first_candidate_flow = Some(flow.reference);
                self.first_packet = Some(flow.first_packet);
            }
            self.last_candidate_flow = Some(flow.reference);
            self.last_packet = Some(flow.last_packet);
        }

        Ok(())
    }
}

/// Explainable repeated low-volume flow detector.
///
/// Identifies endpoint pairs that exchange repetitive short, low-volume flows
/// without asserting confirmed malware or command-and-control.
#[derive(Debug, Clone)]
pub struct RepeatedLowVolumeFlowDetector {
    metadata: DetectorMetadata,
}

impl Default for RepeatedLowVolumeFlowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RepeatedLowVolumeFlowDetector {
    /// Stable namespaced detector identifier.
    pub const DETECTOR_ID: &'static str = "behavior.repeated_low_volume_flows";
    /// Detector logic version.
    pub const DETECTOR_VERSION: DetectorVersion = DetectorVersion::new(1, 0, 0);

    /// Default minimum eligible flow instances (6).
    pub const DEFAULT_MINIMUM_ELIGIBLE_FLOW_INSTANCES: u64 = 6;
    /// Default minimum candidate flow ratio (3/4).
    pub const DEFAULT_MINIMUM_CANDIDATE_FLOW_RATIO: EvidenceRatio =
        match EvidenceRatio::from_fraction(3, 4) {
            Some(r) => r,
            None => EvidenceRatio::ZERO,
        };
    /// Default maximum packets per flow (20).
    pub const DEFAULT_MAXIMUM_PACKETS_PER_FLOW: u64 = 20;
    /// Default maximum wire bytes per flow (32,768 bytes).
    pub const DEFAULT_MAXIMUM_WIRE_BYTES_PER_FLOW: u64 = 32_768;
    /// Default maximum flow duration (60 seconds).
    pub const DEFAULT_MAXIMUM_FLOW_DURATION: FlowDuration = FlowDuration::from_secs(60);
    /// Default maximum tracked peer groups (65,536).
    pub const DEFAULT_MAXIMUM_TRACKED_PEER_GROUPS: usize = 65_536;

    /// Valid minimum range for `minimum_eligible_flow_instances` (2..=u64::MAX).
    pub const MIN_MINIMUM_ELIGIBLE_FLOW_INSTANCES: u64 = 2;
    /// Valid range for `maximum_packets_per_flow` (1..=u64::MAX).
    pub const MIN_MAXIMUM_PACKETS_PER_FLOW: u64 = 1;
    /// Valid range for `maximum_wire_bytes_per_flow` (1..=u64::MAX).
    pub const MIN_MAXIMUM_WIRE_BYTES_PER_FLOW: u64 = 1;
    /// Valid range for `maximum_tracked_peer_groups` (1..=1_000_000).
    pub const MIN_MAXIMUM_TRACKED_PEER_GROUPS: usize = 1;
    pub const MAX_MAXIMUM_TRACKED_PEER_GROUPS: usize = 1_000_000;

    /// Creates a new repeated low-volume flow detector.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("valid static detector metadata")
    }

    /// Fallible constructor returning `Result` if metadata validation fails.
    pub fn try_new() -> Result<Self, FindingValidationError> {
        let id = DetectorId::try_new(Self::DETECTOR_ID)?;
        let title = FindingTitle::try_new("Repeated low-volume flow pattern")?;
        let purpose = FindingSummary::try_new(
            "Identifies canonical IP peer pairs exhibiting repeated short, low-volume flows",
        )?;
        let metadata = DetectorMetadata::new(
            id,
            Self::DETECTOR_VERSION,
            title,
            purpose,
            IncompleteDataPolicy::Skip,
        );
        Ok(Self { metadata })
    }
}

impl Detector for RepeatedLowVolumeFlowDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        for param in parameters.iter() {
            let key = param.key.as_str();
            match key {
                "minimum_eligible_flow_instances" => {
                    let val = match param.value {
                        DetectorParameterValue::Unsigned(v) => v,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "unsigned integer",
                            });
                        }
                    };
                    if val < Self::MIN_MINIMUM_ELIGIBLE_FLOW_INSTANCES as u128
                        || val > u64::MAX as u128
                    {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "minimum_eligible_flow_instances must be between 2 and u64::MAX",
                        });
                    }
                }
                "minimum_candidate_flow_ratio" => {
                    let val = match param.value {
                        DetectorParameterValue::Ratio(r) => r,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "ratio",
                            });
                        }
                    };
                    if val.numerator() == 0 || val > EvidenceRatio::ONE {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "minimum_candidate_flow_ratio must be in range 0 < r <= 1",
                        });
                    }
                }
                "maximum_packets_per_flow" => {
                    let val = match param.value {
                        DetectorParameterValue::Unsigned(v) => v,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "unsigned integer",
                            });
                        }
                    };
                    if val < Self::MIN_MAXIMUM_PACKETS_PER_FLOW as u128 || val > u64::MAX as u128 {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "maximum_packets_per_flow must be between 1 and u64::MAX",
                        });
                    }
                }
                "maximum_wire_bytes_per_flow" => {
                    let val = match param.value {
                        DetectorParameterValue::Unsigned(v) => v,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "unsigned integer",
                            });
                        }
                    };
                    if val < Self::MIN_MAXIMUM_WIRE_BYTES_PER_FLOW as u128 || val > u64::MAX as u128
                    {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "maximum_wire_bytes_per_flow must be between 1 and u64::MAX",
                        });
                    }
                }
                "maximum_flow_duration" => {
                    let val = match param.value {
                        DetectorParameterValue::Duration(d) => d,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "duration",
                            });
                        }
                    };
                    if val.numerator() == 0 {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "maximum_flow_duration must be strictly greater than zero",
                        });
                    }
                }
                "maximum_tracked_peer_groups" => {
                    let val = match param.value {
                        DetectorParameterValue::Unsigned(v) => v,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "unsigned integer",
                            });
                        }
                    };
                    if !(Self::MIN_MAXIMUM_TRACKED_PEER_GROUPS as u128
                        ..=Self::MAX_MAXIMUM_TRACKED_PEER_GROUPS as u128)
                        .contains(&val)
                    {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "maximum_tracked_peer_groups must be between 1 and 1000000",
                        });
                    }
                }
                other => {
                    return Err(DetectorConfigError::UnknownParameter(other.to_string()));
                }
            }
        }
        Ok(())
    }

    fn evaluate(
        &self,
        input: &DetectionInput<'_>,
        parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        if input.completeness() == DetectionInputCompleteness::Partial {
            return Ok(());
        }

        let min_eligible_instances = match parameters.get("minimum_eligible_flow_instances") {
            Some(DetectorParameterValue::Unsigned(v)) => u64::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error("invalid minimum_eligible_flow_instances")
            })?,
            _ => Self::DEFAULT_MINIMUM_ELIGIBLE_FLOW_INSTANCES,
        };
        let min_candidate_ratio = match parameters.get("minimum_candidate_flow_ratio") {
            Some(DetectorParameterValue::Ratio(r)) => *r,
            _ => Self::DEFAULT_MINIMUM_CANDIDATE_FLOW_RATIO,
        };
        let max_packets = match parameters.get("maximum_packets_per_flow") {
            Some(DetectorParameterValue::Unsigned(v)) => u64::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error("invalid maximum_packets_per_flow")
            })?,
            _ => Self::DEFAULT_MAXIMUM_PACKETS_PER_FLOW,
        };
        let max_wire_bytes = match parameters.get("maximum_wire_bytes_per_flow") {
            Some(DetectorParameterValue::Unsigned(v)) => u64::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error("invalid maximum_wire_bytes_per_flow")
            })?,
            _ => Self::DEFAULT_MAXIMUM_WIRE_BYTES_PER_FLOW,
        };
        let max_duration = match parameters.get("maximum_flow_duration") {
            Some(DetectorParameterValue::Duration(d)) => *d,
            _ => Self::DEFAULT_MAXIMUM_FLOW_DURATION,
        };
        let max_peer_groups = match parameters.get("maximum_tracked_peer_groups") {
            Some(DetectorParameterValue::Unsigned(v)) => usize::try_from(*v).map_err(|_| {
                DetectorExecutionError::resource_limit(
                    "maximum_tracked_peer_groups exceeds platform pointer width",
                )
            })?,
            _ => Self::DEFAULT_MAXIMUM_TRACKED_PEER_GROUPS,
        };

        let mut peer_aggregates: BTreeMap<ConnectionPeerKey, RepeatedFlowAggregate> =
            BTreeMap::new();

        for flow in input.flows() {
            // Flow eligibility checks:
            // 1. end_reason != AnalysisStopped
            if flow.end_reason == FlowEndReason::AnalysisStopped {
                continue;
            }
            // 2. peer addresses are distinct
            if flow.key.endpoint_a().address() == flow.key.endpoint_b().address() {
                continue;
            }
            // 3. temporal.duration is Available
            let duration = match flow.temporal.duration {
                FlowTemporalValue::Available(d) => d,
                _ => continue,
            };
            // 4. Clean timestamps
            if flow.temporal.coverage.unavailable_timestamps > 0
                || flow.temporal.coverage.invalid_timestamps > 0
                || flow.temporal.coverage.non_monotonic_transitions > 0
            {
                continue;
            }
            // 5. Traffic eligibility
            if flow.traffic.total.truncated_packet_count > 0
                || flow.traffic.total.packet_count == 0
                || flow.traffic.same_endpoint.packet_count > 0
            {
                continue;
            }

            // Candidate low-volume check:
            let is_candidate = flow.traffic.total.packet_count <= max_packets
                && flow.traffic.total.wire_bytes <= max_wire_bytes
                && duration <= max_duration;

            let peer_key = ConnectionPeerKey::new(
                flow.key.protocol(),
                flow.key.endpoint_a().address(),
                flow.key.endpoint_b().address(),
            );

            if let Some(aggregate) = peer_aggregates.get_mut(&peer_key) {
                aggregate.record_eligible(flow, duration, is_candidate)?;
            } else {
                if peer_aggregates.len() >= max_peer_groups {
                    return Err(DetectorExecutionError::resource_limit(
                        "maximum tracked connection peer groups limit reached in repeated low-volume flow detector",
                    ));
                }
                let mut aggregate = RepeatedFlowAggregate::new();
                aggregate.record_eligible(flow, duration, is_candidate)?;
                peer_aggregates.insert(peer_key, aggregate);
            }
        }

        // Emit finding drafts for qualifying peer keys
        for (_peer_key, aggregate) in peer_aggregates {
            if aggregate.eligible_flow_instance_count < min_eligible_instances {
                continue;
            }
            if aggregate.candidate_flow_count == 0 {
                continue;
            }

            let candidate_ratio = EvidenceRatio::from_fraction(
                u128::from(aggregate.candidate_flow_count),
                u128::from(aggregate.eligible_flow_instance_count),
            )
            .ok_or_else(|| {
                DetectorExecutionError::internal_error("invalid candidate ratio fraction")
            })?;

            if candidate_ratio < min_candidate_ratio {
                continue;
            }

            let first_flow = match aggregate.first_candidate_flow {
                Some(f) => f,
                None => continue,
            };
            let last_flow = match aggregate.last_candidate_flow {
                Some(f) => f,
                None => continue,
            };

            let mut flow_refs = if first_flow == last_flow {
                vec![first_flow]
            } else if first_flow < last_flow {
                vec![first_flow, last_flow]
            } else {
                vec![last_flow, first_flow]
            };
            flow_refs.dedup();

            let mut pkts = Vec::new();
            if let Some(p) = aggregate.first_packet {
                pkts.push(p);
            }
            if let Some(p) = aggregate.last_packet {
                pkts.push(p);
            }
            pkts.sort_by_key(|p| p.capture_record_ordinal());
            pkts.dedup_by_key(|p| p.capture_record_ordinal());

            let subject = FindingSubject::try_new(pkts.clone(), flow_refs.clone(), Vec::new())
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("finding subject error: {e}"))
                })?;

            let desc =
                EvidenceDescription::try_new("Repeated low-volume flow aggregate measurements")
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!(
                            "evidence description error: {e}"
                        ))
                    })?;

            let mut evi_builder = EvidenceDraftBuilder::new(EvidenceKind::RatioComparison, desc);
            for pkt in &pkts {
                evi_builder.add_packet_reference(*pkt).map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "evidence packet reference error: {e}"
                    ))
                })?;
            }
            for flow_ref in &flow_refs {
                evi_builder.add_flow_reference(*flow_ref).map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "evidence flow reference error: {e}"
                    ))
                })?;
            }

            // Lexicographic order of metrics:
            // 1. candidate_flow_count
            let k_cfc = EvidenceMetricKey::try_new("candidate_flow_count").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_new(
                        k_cfc,
                        EvidenceValue::Unsigned(u128::from(aggregate.candidate_flow_count)),
                        EvidenceUnit::Count,
                    )
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                    })?,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "measurement builder error: {e}"
                    ))
                })?;

            // 2. candidate_flow_ratio
            let k_cfr = EvidenceMetricKey::try_new("candidate_flow_ratio").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_cfr,
                        EvidenceValue::Ratio(candidate_ratio),
                        EvidenceValue::Ratio(min_candidate_ratio),
                        EvidenceComparison::GreaterThanOrEqual,
                        EvidenceUnit::Ratio,
                    )
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                    })?,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "measurement builder error: {e}"
                    ))
                })?;

            // 3. eligible_flow_instance_count
            let k_efc =
                EvidenceMetricKey::try_new("eligible_flow_instance_count").map_err(|e| {
                    DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_efc,
                        EvidenceValue::Unsigned(u128::from(aggregate.eligible_flow_instance_count)),
                        EvidenceValue::Unsigned(u128::from(min_eligible_instances)),
                        EvidenceComparison::GreaterThanOrEqual,
                        EvidenceUnit::Count,
                    )
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                    })?,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "measurement builder error: {e}"
                    ))
                })?;

            // 4. maximum_candidate_duration
            let k_mcd = EvidenceMetricKey::try_new("maximum_candidate_duration").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_mcd,
                        EvidenceValue::Duration(aggregate.maximum_candidate_duration),
                        EvidenceValue::Duration(max_duration),
                        EvidenceComparison::LessThanOrEqual,
                        EvidenceUnit::Seconds,
                    )
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                    })?,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "measurement builder error: {e}"
                    ))
                })?;

            // 5. maximum_candidate_packet_count
            let k_mcp =
                EvidenceMetricKey::try_new("maximum_candidate_packet_count").map_err(|e| {
                    DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_mcp,
                        EvidenceValue::Unsigned(u128::from(
                            aggregate.maximum_candidate_packet_count,
                        )),
                        EvidenceValue::Unsigned(u128::from(max_packets)),
                        EvidenceComparison::LessThanOrEqual,
                        EvidenceUnit::Packets,
                    )
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                    })?,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "measurement builder error: {e}"
                    ))
                })?;

            // 6. maximum_candidate_wire_bytes
            let k_mcw =
                EvidenceMetricKey::try_new("maximum_candidate_wire_bytes").map_err(|e| {
                    DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_mcw,
                        EvidenceValue::Unsigned(u128::from(aggregate.maximum_candidate_wire_bytes)),
                        EvidenceValue::Unsigned(u128::from(max_wire_bytes)),
                        EvidenceComparison::LessThanOrEqual,
                        EvidenceUnit::Bytes,
                    )
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                    })?,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "measurement builder error: {e}"
                    ))
                })?;

            let evidence_draft = evi_builder.build().map_err(|e| {
                DetectorExecutionError::internal_error(format!("evidence draft build error: {e}"))
            })?;

            let title = FindingTitle::try_new("Repeated low-volume flow pattern").map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding title error: {e}"))
            })?;

            let summary = FindingSummary::try_new(
                "Repeated flow instances between the same canonical IP peer pair are predominantly short and low-volume under configured thresholds.",
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding summary error: {e}"))
            })?;

            let rationale = FindingRationale::try_new(
                "Observed repeated flow instances between the canonical IP peer pair that are short in duration and low in wire bytes and packet count. While repetitive low-volume connections can indicate periodic polling, telemetry, or keepalives, they are also commonly produced by benign services such as health checks, monitoring agents, scheduled polling, API retries, service meshes, load-balancer probes, DNS activity, application heartbeats, or short-lived background tasks.",
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding rationale error: {e}"))
            })?;

            let finding_draft = FindingDraft::try_new(
                subject,
                title,
                summary,
                rationale,
                Severity::Low,
                Confidence::Medium,
                vec![evidence_draft],
                Vec::new(),
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding draft creation error: {e}"))
            })?;

            output.push(finding_draft)?;
        }

        Ok(())
    }
}
