//! Serializable DTOs for network flow reconstruction reports.

use pcapraven_domain::{
    FlowDuration, FlowEndReason, FlowInterArrivalMetrics, FlowRecord, FlowTemporalMetrics,
    FlowTemporalUnavailableReason, FlowTemporalValue, FlowTimestampCoverage, FlowTrafficCounters,
    PacketTimestamp, TransportProtocol,
};
use serde::Serialize;

use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for a network flows report in JSON.
#[derive(Debug, Clone, Serialize)]
pub struct FlowsReportDto {
    /// Schema version anchor ("v1.0").
    pub schema_version: &'static str,
    /// Report kind identifier ("flows").
    pub kind: &'static str,
    /// Total count of flows in report as a decimal string.
    pub total_flows: String,
    /// List of reconstructed flow records in canonical order.
    pub flows: Vec<FlowRecordDto>,
}

impl FlowsReportDto {
    /// Constructs a new DTO from a slice of domain flow records.
    #[must_use]
    pub fn from_domain_flows(flows: &[FlowRecord]) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "flows",
            total_flows: flows.len().to_string(),
            flows: flows.iter().map(FlowRecordDto::from_domain).collect(),
        }
    }
}

/// A reconstructed bidirectional flow record.
#[derive(Debug, Clone, Serialize)]
pub struct FlowRecordDto {
    /// Monotonic flow identifier string (e.g. "flow:0").
    pub id: String,
    /// Ordinal index as a decimal string.
    pub ordinal: String,
    /// Transport protocol ("tcp" or "udp").
    pub protocol: String,
    /// First observed endpoint ("IP:PORT").
    pub endpoint_a: String,
    /// Second observed endpoint ("IP:PORT").
    pub endpoint_b: String,
    /// First packet record ordinal as a decimal string.
    pub first_packet: String,
    /// Last packet record ordinal as a decimal string.
    pub last_packet: String,
    /// Lifecycle end reason ("end_of_input", "idle_timeout", "tcp_reset", "tcp_new_initial_syn", "analysis_stopped").
    pub end_reason: String,
    /// Directional and aggregate traffic metrics.
    pub traffic: FlowTrafficDto,
    /// Exact temporal duration, timestamps, and inter-arrival metrics.
    pub temporal: FlowTemporalDto,
}

impl FlowRecordDto {
    /// Converts a domain [`FlowRecord`] into a serializable DTO.
    #[must_use]
    pub fn from_domain(flow: &FlowRecord) -> Self {
        let proto_str = match flow.key.protocol() {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
        };

        let end_reason_str = match flow.end_reason {
            FlowEndReason::EndOfInput => "end_of_input",
            FlowEndReason::IdleTimeout => "idle_timeout",
            FlowEndReason::TcpReset => "tcp_reset",
            FlowEndReason::TcpNewInitialSyn => "tcp_new_initial_syn",
            FlowEndReason::AnalysisStopped => "analysis_stopped",
        };

        Self {
            id: flow.reference.to_string(),
            ordinal: flow.reference.ordinal().to_string(),
            protocol: proto_str.to_string(),
            endpoint_a: flow.key.endpoint_a().to_string(),
            endpoint_b: flow.key.endpoint_b().to_string(),
            first_packet: flow.first_packet.capture_record_ordinal().to_string(),
            last_packet: flow.last_packet.capture_record_ordinal().to_string(),
            end_reason: end_reason_str.to_string(),
            traffic: FlowTrafficDto::from_domain(&flow.traffic),
            temporal: FlowTemporalDto::from_domain(&flow.temporal),
        }
    }
}

/// Directional packet and byte counters.
#[derive(Debug, Clone, Serialize)]
pub struct FlowDirectionalTrafficDto {
    /// Packet count as a decimal string.
    pub packet_count: String,
    /// Total captured bytes as a decimal string.
    pub captured_bytes: String,
    /// Total on-wire bytes as a decimal string.
    pub wire_bytes: String,
    /// Truncated packet count as a decimal string.
    pub truncated_packet_count: String,
}

impl FlowDirectionalTrafficDto {
    /// Converts domain traffic counters into a DTO.
    #[must_use]
    pub fn from_domain(c: &FlowTrafficCounters) -> Self {
        Self {
            packet_count: c.packet_count.to_string(),
            captured_bytes: c.captured_bytes.to_string(),
            wire_bytes: c.wire_bytes.to_string(),
            truncated_packet_count: c.truncated_packet_count.to_string(),
        }
    }
}

/// Traffic counter metrics for a flow across all directional buckets.
#[derive(Debug, Clone, Serialize)]
pub struct FlowTrafficDto {
    /// Total aggregate traffic across all directions.
    pub total: FlowDirectionalTrafficDto,
    /// Traffic transmitted from endpoint A to endpoint B.
    pub a_to_b: FlowDirectionalTrafficDto,
    /// Traffic transmitted from endpoint B to endpoint A.
    pub b_to_a: FlowDirectionalTrafficDto,
    /// Traffic transmitted where source equals destination endpoint.
    pub same_endpoint: FlowDirectionalTrafficDto,
}

impl FlowTrafficDto {
    /// Converts domain [`pcapraven_domain::FlowTrafficStatistics`] into a DTO.
    #[must_use]
    pub fn from_domain(s: &pcapraven_domain::FlowTrafficStatistics) -> Self {
        Self {
            total: FlowDirectionalTrafficDto::from_domain(&s.total),
            a_to_b: FlowDirectionalTrafficDto::from_domain(&s.a_to_b),
            b_to_a: FlowDirectionalTrafficDto::from_domain(&s.b_to_a),
            same_endpoint: FlowDirectionalTrafficDto::from_domain(&s.same_endpoint),
        }
    }
}

/// Exact timestamp state representation.
#[derive(Debug, Clone, Serialize)]
pub struct PacketTimestampDto {
    /// Whole seconds as a decimal string.
    pub seconds: String,
    /// Fractional time units as a decimal string.
    pub fractional_units: String,
    /// Units per second resolution as a decimal string.
    pub units_per_second: String,
    /// Local signed offset seconds as a decimal string.
    pub offset_seconds: String,
}

impl PacketTimestampDto {
    /// Converts a domain [`PacketTimestamp`] into a DTO.
    #[must_use]
    pub fn from_domain(ts: &PacketTimestamp) -> Option<Self> {
        match ts {
            PacketTimestamp::Available {
                seconds,
                fractional_units,
                resolution,
                offset_seconds,
            } => Some(Self {
                seconds: seconds.to_string(),
                fractional_units: fractional_units.to_string(),
                units_per_second: resolution.units_per_second().to_string(),
                offset_seconds: offset_seconds.to_string(),
            }),
            PacketTimestamp::Unavailable => None,
        }
    }
}

/// Timestamp validity and availability coverage counters.
#[derive(Debug, Clone, Serialize)]
pub struct FlowTimestampCoverageDto {
    /// Available timestamp count.
    pub available_timestamps: String,
    /// Unavailable timestamp count.
    pub unavailable_timestamps: String,
    /// Invalid timestamp count.
    pub invalid_timestamps: String,
    /// Non-monotonic transition count.
    pub non_monotonic_transitions: String,
}

impl FlowTimestampCoverageDto {
    /// Converts domain coverage into a DTO.
    #[must_use]
    pub fn from_domain(c: &FlowTimestampCoverage) -> Self {
        Self {
            available_timestamps: c.available_timestamps.to_string(),
            unavailable_timestamps: c.unavailable_timestamps.to_string(),
            invalid_timestamps: c.invalid_timestamps.to_string(),
            non_monotonic_transitions: c.non_monotonic_transitions.to_string(),
        }
    }
}

/// Exact temporal metrics and inter-arrival statistics for a flow.
#[derive(Debug, Clone, Serialize)]
pub struct FlowTemporalDto {
    /// Availability state ("available" or "unavailable").
    pub status: String,
    /// Reason string if duration is unavailable.
    pub unavailable_reason: Option<String>,
    /// Exact rational duration if available.
    pub duration: Option<DurationDto>,
    /// Timestamp coverage counters.
    pub timestamp_coverage: FlowTimestampCoverageDto,
    /// Timestamp of first observed packet in flow if available.
    pub first_packet_timestamp: Option<PacketTimestampDto>,
    /// Timestamp of last observed packet in flow if available.
    pub last_packet_timestamp: Option<PacketTimestampDto>,
    /// Overall inter-arrival metrics across all packets.
    pub overall_inter_arrival: InterArrivalMetricsDto,
    /// Forward direction (A -> B) inter-arrival statistics.
    pub a_to_b_inter_arrival: InterArrivalMetricsDto,
    /// Reverse direction (B -> A) inter-arrival statistics.
    pub b_to_a_inter_arrival: InterArrivalMetricsDto,
    /// Same-endpoint packet inter-arrival statistics.
    pub same_endpoint_inter_arrival: InterArrivalMetricsDto,
}

impl FlowTemporalDto {
    /// Converts domain flow temporal metrics into a serializable DTO.
    #[must_use]
    pub fn from_domain(temporal: &FlowTemporalMetrics) -> Self {
        let (status, reason, dur) = match &temporal.duration {
            FlowTemporalValue::Available(d) => (
                "available".to_string(),
                None,
                Some(DurationDto::from_domain(d)),
            ),
            FlowTemporalValue::Unavailable(r) => {
                let reason_str = match r {
                    FlowTemporalUnavailableReason::InsufficientSamples => "insufficient_samples",
                    FlowTemporalUnavailableReason::TimestampUnavailable => "timestamp_unavailable",
                    FlowTemporalUnavailableReason::InvalidTimestamp => "invalid_timestamp",
                    FlowTemporalUnavailableReason::NonMonotonicTimestamp => {
                        "non_monotonic_timestamp"
                    }
                    FlowTemporalUnavailableReason::ArithmeticOverflow => "arithmetic_overflow",
                };
                (
                    "unavailable".to_string(),
                    Some(reason_str.to_string()),
                    None,
                )
            }
        };

        Self {
            status,
            unavailable_reason: reason,
            duration: dur,
            timestamp_coverage: FlowTimestampCoverageDto::from_domain(&temporal.coverage),
            first_packet_timestamp: PacketTimestampDto::from_domain(
                &temporal.first_packet_timestamp,
            ),
            last_packet_timestamp: PacketTimestampDto::from_domain(&temporal.last_packet_timestamp),
            overall_inter_arrival: InterArrivalMetricsDto::from_domain(
                &temporal.overall_inter_arrival,
            ),
            a_to_b_inter_arrival: InterArrivalMetricsDto::from_domain(
                &temporal.a_to_b_inter_arrival,
            ),
            b_to_a_inter_arrival: InterArrivalMetricsDto::from_domain(
                &temporal.b_to_a_inter_arrival,
            ),
            same_endpoint_inter_arrival: InterArrivalMetricsDto::from_domain(
                &temporal.same_endpoint_inter_arrival,
            ),
        }
    }
}

/// Inter-arrival interval timing metrics for a directional flow half.
#[derive(Debug, Clone, Serialize)]
pub struct InterArrivalMetricsDto {
    /// Number of valid inter-arrival interval samples observed as decimal string.
    pub interval_sample_count: String,
    /// Number of temporal discontinuities as decimal string.
    pub discontinuity_count: String,
    /// Minimum observed interval if available.
    pub min_interval: Option<DurationDto>,
    /// Maximum observed interval if available.
    pub max_interval: Option<DurationDto>,
    /// Mean observed interval if available.
    pub mean_interval: Option<DurationDto>,
    /// Number of successive delta samples observed as decimal string.
    pub successive_delta_sample_count: String,
    /// Mean absolute successive interval delta if available.
    pub mean_absolute_successive_interval_delta: Option<DurationDto>,
}

impl InterArrivalMetricsDto {
    /// Converts domain inter-arrival metrics into a serializable DTO.
    #[must_use]
    pub fn from_domain(metrics: &FlowInterArrivalMetrics) -> Self {
        Self {
            interval_sample_count: metrics.interval_sample_count.to_string(),
            discontinuity_count: metrics.discontinuity_count.to_string(),
            min_interval: metrics
                .minimum_interval
                .value()
                .map(DurationDto::from_domain),
            max_interval: metrics
                .maximum_interval
                .value()
                .map(DurationDto::from_domain),
            mean_interval: metrics.mean_interval.value().map(DurationDto::from_domain),
            successive_delta_sample_count: metrics.successive_delta_sample_count.to_string(),
            mean_absolute_successive_interval_delta: metrics
                .mean_absolute_successive_interval_delta
                .value()
                .map(DurationDto::from_domain),
        }
    }
}

/// Exact rational duration representation in numerator and denominator.
#[derive(Debug, Clone, Serialize)]
pub struct DurationDto {
    /// Numerator of rational duration as a decimal string.
    pub numerator: String,
    /// Denominator of rational duration (>= 1) as a decimal string.
    pub denominator: String,
    /// Formatted display string (e.g. "0.050000000s" or "5/2s").
    pub display: String,
}

impl DurationDto {
    /// Converts a domain [`FlowDuration`] into a DTO.
    #[must_use]
    pub fn from_domain(d: &FlowDuration) -> Self {
        Self {
            numerator: d.numerator().to_string(),
            denominator: d.denominator().to_string(),
            display: format!("{d}"),
        }
    }
}
