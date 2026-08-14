//! Capture-independent domain boundary for PcapRaven.
//!
//! This crate defines normalized packet facts, flow representations, identifiers,
//! and result concepts. It does not perform capture reading, protocol parsing,
//! flow reconstruction algorithms, detection, reporting, or CLI orchestration.

pub mod flow;
pub mod packet;

pub use flow::{
    FlowDirection, FlowEndReason, FlowEndpoint, FlowKey, FlowPacketAssociation, FlowRecord,
    FlowReference, TransportProtocol,
};
pub use packet::{
    EthernetMetadata, FragmentationState, IpAddress, Ipv4Metadata, Ipv6Metadata, MacAddress,
    NetworkLayer, NormalizationDiagnostic, NormalizationDiagnosticKind,
    NormalizationDiagnosticLayer, NormalizedPacket, PacketCompleteness, PacketNormalizationInput,
    PacketNormalizationOutcome, PacketReference, PacketTimestamp, PacketTimestampResolution,
    PacketTruncationReason, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
    UnsupportedLayerReason,
};
