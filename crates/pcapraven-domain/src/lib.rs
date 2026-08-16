//! Capture-independent domain boundary for PcapRaven.
//!
//! This crate defines normalized packet facts, flow representations, identifiers,
//! and result concepts. It does not perform capture reading, protocol parsing,
//! flow reconstruction algorithms, detection, reporting, or CLI orchestration.

pub mod dns;
pub mod flow;
pub mod flow_metrics;
pub mod http;
pub mod packet;

pub use dns::{
    DnsDiagnostic, DnsDiagnosticKind, DnsEdnsMetadata, DnsEdnsOptionMetadata, DnsFlags,
    DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness, DnsQuestion,
    DnsRdataMetadata, DnsResourceRecord, DnsSection, DnsTransport, MAX_DNS_LABEL_LENGTH,
    MAX_DNS_NAME_WIRE_LENGTH,
};
pub use flow::{
    FlowDirection, FlowEndReason, FlowEndpoint, FlowKey, FlowPacketAssociation, FlowRecord,
    FlowReference, TransportProtocol,
};
pub use flow_metrics::{
    FlowDuration, FlowInterArrivalMetrics, FlowTemporalMetrics, FlowTemporalUnavailableReason,
    FlowTemporalValue, FlowTimestampCoverage, FlowTrafficCounters, FlowTrafficStatistics,
};
pub use http::{
    HttpByteString, HttpContentLengthState, HttpDiagnostic, HttpDiagnosticKind,
    HttpFramingMetadata, HttpMessageKind, HttpObservation, HttpObservationCompleteness,
    HttpRequestMetadata, HttpResponseMetadata, HttpSelectedHeaders, HttpVersion,
};
pub use packet::{
    EthernetMetadata, FragmentationState, IpAddress, Ipv4Metadata, Ipv6Metadata, MacAddress,
    NetworkLayer, NormalizationDiagnostic, NormalizationDiagnosticKind,
    NormalizationDiagnosticLayer, NormalizedPacket, PacketCompleteness, PacketNormalizationInput,
    PacketNormalizationOutcome, PacketReference, PacketTimestamp, PacketTimestampResolution,
    PacketTruncationReason, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
    UnsupportedLayerReason,
};
