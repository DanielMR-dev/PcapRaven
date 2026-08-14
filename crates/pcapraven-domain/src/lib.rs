//! Capture-independent domain boundary for PcapRaven.
//!
//! This crate defines normalized packet facts, identifiers, and result concepts.
//! It does not perform capture reading, protocol parsing, flow reconstruction,
//! detection, reporting, or CLI orchestration.

pub mod packet;

pub use packet::{
    EthernetMetadata, FragmentationState, IpAddress, Ipv4Metadata, Ipv6Metadata, MacAddress,
    NetworkLayer, NormalizationDiagnostic, NormalizationDiagnosticKind,
    NormalizationDiagnosticLayer, NormalizedPacket, PacketCompleteness, PacketNormalizationInput,
    PacketNormalizationOutcome, PacketReference, PacketTimestamp, PacketTimestampResolution,
    PacketTruncationReason, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
    UnsupportedLayerReason,
};
