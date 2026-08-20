//! Serializable DTOs for network flow reconstruction reports.

use pcapraven_domain::{
    FlowDuration, FlowInterArrivalMetrics, FlowRecord, FlowTemporalValue, TransportProtocol,
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
    /// Total count of flows in report.
    pub total_flows: usize,
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
            total_flows: flows.len(),
            flows: flows.iter().map(FlowRecordDto::from_domain).collect(),
        }
    }
}

/// A reconstructed bidirectional flow record.
#[derive(Debug, Clone, Serialize)]
pub struct FlowRecordDto {
    /// Monotonic flow identifier string (e.g. "flow:0").
    pub id: String,
    /// Ordinal index.
    pub ordinal: u64,
    /// Transport protocol ("TCP" or "UDP").
    pub protocol: String,
    /// First observed endpoint ("IP:PORT").
    pub endpoint_a: String,
    /// Second observed endpoint ("IP:PORT").
    pub endpoint_b: String,
    /// Traffic packet and byte metrics.
    pub traffic: FlowTrafficDto,
    /// Exact temporal duration and timestamps.
    pub temporal: FlowTemporalDto,
    /// Lifecycle end reason.
    pub end_reason: String,
}

impl FlowRecordDto {
    /// Converts a domain [`FlowRecord`] into a serializable DTO.
    #[must_use]
    pub fn from_domain(flow: &FlowRecord) -> Self {
        let proto_str = match flow.key.protocol() {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
        };

        Self {
            id: flow.reference.to_string(),
            ordinal: flow.reference.ordinal(),
            protocol: proto_str.to_string(),
            endpoint_a: flow.key.endpoint_a().to_string(),
            endpoint_b: flow.key.endpoint_b().to_string(),
            traffic: FlowTrafficDto {
                total_packets: flow.traffic.total.packet_count,
                packets_a_to_b: flow.traffic.a_to_b.packet_count,
                packets_b_to_a: flow.traffic.b_to_a.packet_count,
                packets_same_endpoint: flow.traffic.same_endpoint.packet_count,
                total_captured_bytes: flow.traffic.total.captured_bytes,
                captured_bytes_a_to_b: flow.traffic.a_to_b.captured_bytes,
                captured_bytes_b_to_a: flow.traffic.b_to_a.captured_bytes,
                total_wire_bytes: flow.traffic.total.wire_bytes,
                wire_bytes_a_to_b: flow.traffic.a_to_b.wire_bytes,
                wire_bytes_b_to_a: flow.traffic.b_to_a.wire_bytes,
            },
            temporal: FlowTemporalDto::from_domain(&flow.temporal),
            end_reason: flow.end_reason.as_str().to_string(),
        }
    }
}

/// Traffic counter metrics for a flow.
#[derive(Debug, Clone, Serialize)]
pub struct FlowTrafficDto {
    /// Total packet count across both directions.
    pub total_packets: u64,
    /// Packet count in forward direction (A -> B).
    pub packets_a_to_b: u64,
    /// Packet count in reverse direction (B -> A).
    pub packets_b_to_a: u64,
    /// Packet count where source and destination endpoints matched.
    pub packets_same_endpoint: u64,
    /// Total captured bytes across both directions.
    pub total_captured_bytes: u64,
    /// Captured bytes in forward direction (A -> B).
    pub captured_bytes_a_to_b: u64,
    /// Captured bytes in reverse direction (B -> A).
    pub captured_bytes_b_to_a: u64,
    /// Total on-wire bytes across both directions.
    pub total_wire_bytes: u64,
    /// On-wire bytes in forward direction (A -> B).
    pub wire_bytes_a_to_b: u64,
    /// On-wire bytes in reverse direction (B -> A).
    pub wire_bytes_b_to_a: u64,
}

/// Exact temporal metrics and inter-arrival statistics for a flow.
#[derive(Debug, Clone, Serialize)]
pub struct FlowTemporalDto {
    /// Availability state ("available" or "unavailable").
    pub status: String,
    /// Reason string if duration is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// Exact rational duration if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<DurationDto>,
    /// Forward direction (A -> B) inter-arrival statistics.
    pub inter_arrival_a_to_b: InterArrivalMetricsDto,
    /// Reverse direction (B -> A) inter-arrival statistics.
    pub inter_arrival_b_to_a: InterArrivalMetricsDto,
}

impl FlowTemporalDto {
    /// Converts domain flow temporal metrics into a serializable DTO.
    #[must_use]
    pub fn from_domain(temporal: &pcapraven_domain::FlowTemporalMetrics) -> Self {
        let (status, reason, dur) = match &temporal.duration {
            FlowTemporalValue::Available(d) => (
                "available".to_string(),
                None,
                Some(DurationDto::from_domain(d)),
            ),
            FlowTemporalValue::Unavailable(r) => {
                ("unavailable".to_string(), Some(r.to_string()), None)
            }
        };

        Self {
            status,
            unavailable_reason: reason,
            duration: dur,
            inter_arrival_a_to_b: InterArrivalMetricsDto::from_domain(
                &temporal.a_to_b_inter_arrival,
            ),
            inter_arrival_b_to_a: InterArrivalMetricsDto::from_domain(
                &temporal.b_to_a_inter_arrival,
            ),
        }
    }
}

/// Inter-arrival interval timing metrics for a directional flow half.
#[derive(Debug, Clone, Serialize)]
pub struct InterArrivalMetricsDto {
    /// Number of valid inter-arrival interval samples observed.
    pub interval_sample_count: u64,
    /// Number of temporal discontinuities.
    pub discontinuity_count: u64,
    /// Minimum observed interval if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_interval: Option<DurationDto>,
    /// Maximum observed interval if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_interval: Option<DurationDto>,
    /// Mean observed interval if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_interval: Option<DurationDto>,
    /// Number of successive delta samples observed.
    pub successive_delta_sample_count: u64,
    /// Mean absolute successive interval delta if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_absolute_successive_interval_delta: Option<DurationDto>,
}

impl InterArrivalMetricsDto {
    /// Converts domain inter-arrival metrics into a serializable DTO.
    #[must_use]
    pub fn from_domain(metrics: &FlowInterArrivalMetrics) -> Self {
        Self {
            interval_sample_count: metrics.interval_sample_count,
            discontinuity_count: metrics.discontinuity_count,
            min_interval: metrics
                .minimum_interval
                .value()
                .map(DurationDto::from_domain),
            max_interval: metrics
                .maximum_interval
                .value()
                .map(DurationDto::from_domain),
            mean_interval: metrics.mean_interval.value().map(DurationDto::from_domain),
            successive_delta_sample_count: metrics.successive_delta_sample_count,
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
    /// Numerator of rational duration.
    pub numerator: u128,
    /// Denominator of rational duration (>= 1).
    pub denominator: u128,
    /// Formatted display string (e.g. "0.050000000s" or "5/2s").
    pub display: String,
}

impl DurationDto {
    /// Converts a domain [`FlowDuration`] into a DTO.
    #[must_use]
    pub fn from_domain(d: &FlowDuration) -> Self {
        Self {
            numerator: d.numerator(),
            denominator: d.denominator(),
            display: format!("{d}"),
        }
    }
}
