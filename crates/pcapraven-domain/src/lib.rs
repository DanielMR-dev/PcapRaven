//! Capture-independent domain boundary for PcapRaven.
//!
//! This crate defines normalized packet facts, flow representations, identifiers,
//! and result concepts. It does not perform capture reading, protocol parsing,
//! flow reconstruction algorithms, detection, reporting, or CLI orchestration.

pub mod dns;
pub mod evidence;
pub mod flow;
pub mod flow_metrics;
pub mod http;
pub mod observation;
pub mod packet;
pub mod tls;

pub use dns::{
    DnsDiagnostic, DnsDiagnosticKind, DnsEdnsMetadata, DnsEdnsOptionMetadata, DnsFlags,
    DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness, DnsQuestion,
    DnsRdataMetadata, DnsResourceRecord, DnsSection, DnsTransport, MAX_DNS_LABEL_LENGTH,
    MAX_DNS_NAME_WIRE_LENGTH,
};
pub use evidence::{
    EvidenceComparison, EvidenceDescription, EvidenceKind, EvidenceLimitation, EvidenceMeasurement,
    EvidenceMetricKey, EvidenceRatio, EvidenceRecord, EvidenceReference, EvidenceUnit,
    EvidenceValue, SchemaVersion,
};
pub use flow::{
    FlowDirection, FlowEndReason, FlowEndpoint, FlowExclusionReason, FlowKey,
    FlowPacketAssociation, FlowRecord, FlowReference, TransportProtocol,
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
pub use observation::{
    ObservationCompleteness, ObservationFlowAssociation, ObservationReference, ProtocolKind,
    ProtocolObservation, ProtocolObservationCollection, ProtocolObservationCollectionError,
    ProtocolObservationData,
};
pub use packet::{
    EthernetMetadata, FragmentationState, IpAddress, Ipv4Metadata, Ipv6Metadata, MacAddress,
    NetworkLayer, NormalizationDiagnostic, NormalizationDiagnosticKind,
    NormalizationDiagnosticLayer, NormalizedPacket, PacketCompleteness, PacketNormalizationInput,
    PacketNormalizationOutcome, PacketReference, PacketTimestamp, PacketTimestampResolution,
    PacketTruncationReason, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
    UnsupportedLayerReason,
};
pub use tls::{
    TlsByteString, TlsClientHelloMetadata, TlsDiagnostic, TlsDiagnosticKind, TlsExtensionMetadata,
    TlsHandshakeKind, TlsObservation, TlsObservationCompleteness, TlsRecordContentType,
    TlsServerHelloMetadata, TlsVersion,
};
