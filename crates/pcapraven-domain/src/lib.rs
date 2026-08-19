//! Capture-independent domain boundary for PcapRaven.
//!
//! This crate defines normalized packet facts, flow representations, identifiers,
//! and result concepts. It does not perform capture reading, protocol parsing,
//! flow reconstruction algorithms, detection, reporting, or CLI orchestration.

pub mod dns;
pub mod evidence;
pub mod finding;
pub mod flow;
pub mod flow_metrics;
pub mod http;
pub mod mitre_attack;
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
    EVIDENCE_SCHEMA_VERSION, EvidenceComparison, EvidenceDescription, EvidenceDraft,
    EvidenceDraftBuilder, EvidenceKind, EvidenceLimitation, EvidenceMeasurement, EvidenceMetricKey,
    EvidenceRatio, EvidenceRecord, EvidenceRecordBuilder, EvidenceReference, EvidenceUnit,
    EvidenceValidationError, EvidenceValue, PROTOCOL_OBSERVATION_SCHEMA_VERSION, SchemaVersion,
};
pub use finding::{
    Confidence, DetectorId, DetectorVersion, FindingDraft, FindingRationale, FindingRecord,
    FindingReference, FindingSubject, FindingSummary, FindingTitle, FindingValidationError,
    MAX_DETECTOR_ID_LENGTH, MAX_FINDING_RATIONALE_LENGTH, MAX_FINDING_SUMMARY_LENGTH,
    MAX_FINDING_TITLE_LENGTH, Severity,
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
pub use mitre_attack::{
    HARD_MAX_MITRE_MAPPINGS_PER_FINDING, MAX_MITRE_ATTACK_ID_LENGTH, MAX_MITRE_RATIONALE_LENGTH,
    MAX_MITRE_TECHNIQUE_NAME_LENGTH, MITRE_ATTACK_VERSION, MitreAttackId, MitreMapping,
    MitreMappingProvenance, MitreMappingRationale, MitreTactic,
};
pub use observation::{
    ObservationCompleteness, ObservationError, ObservationFlowAssociation, ObservationReference,
    ProtocolKind, ProtocolObservation, ProtocolObservationCollection,
    ProtocolObservationCollectionError, ProtocolObservationData,
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
