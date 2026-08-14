//! Capture-independent bidirectional flow models and identity representations.

use crate::packet::{IpAddress, PacketReference};
use core::fmt;

/// Supported transport protocol for flow reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportProtocol {
    /// Transmission Control Protocol (RFC 9293).
    Tcp,
    /// User Datagram Protocol (RFC 768).
    Udp,
}

impl TransportProtocol {
    /// Returns the static name of the transport protocol.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }

    /// Converts a protocol number to a known [`TransportProtocol`].
    #[must_use]
    pub const fn from_u8(protocol: u8) -> Option<Self> {
        match protocol {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }

    /// Returns the standard IP protocol number (6 for TCP, 17 for UDP).
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A transport-layer communication endpoint consisting of an IP address and port.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowEndpoint {
    /// Canonical binary IP address (IPv4 or IPv6).
    pub address: IpAddress,
    /// 16-bit transport port (0..=65535).
    pub port: u16,
}

impl FlowEndpoint {
    /// Creates a new flow endpoint.
    #[must_use]
    pub const fn new(address: IpAddress, port: u16) -> Self {
        Self { address, port }
    }

    /// Returns the IP address of this endpoint.
    #[must_use]
    pub const fn address(&self) -> IpAddress {
        self.address
    }

    /// Returns the transport port of this endpoint.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Debug for FlowEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:{}", self.address, self.port)
    }
}

impl fmt::Display for FlowEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            IpAddress::Ipv4(octets) => write!(
                f,
                "{}.{}.{}.{}:{}",
                octets[0], octets[1], octets[2], octets[3], self.port
            ),
            IpAddress::Ipv6(octets) => write!(
                f,
                "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                u16::from_be_bytes([octets[0], octets[1]]),
                u16::from_be_bytes([octets[2], octets[3]]),
                u16::from_be_bytes([octets[4], octets[5]]),
                u16::from_be_bytes([octets[6], octets[7]]),
                u16::from_be_bytes([octets[8], octets[9]]),
                u16::from_be_bytes([octets[10], octets[11]]),
                u16::from_be_bytes([octets[12], octets[13]]),
                u16::from_be_bytes([octets[14], octets[15]]),
                self.port
            ),
        }
    }
}

/// Canonical bidirectional communication key.
///
/// Endpoints are canonicalized by deterministic total ordering such that
/// `endpoint_a <= endpoint_b` is always guaranteed. Reversing the endpoints
/// of a packet produces an identical [`FlowKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    protocol: TransportProtocol,
    endpoint_a: FlowEndpoint,
    endpoint_b: FlowEndpoint,
}

impl FlowKey {
    /// Creates a canonical bidirectional flow key from a protocol and two endpoints.
    ///
    /// The endpoints are ordered deterministically so that `endpoint_a <= endpoint_b`.
    #[must_use]
    pub fn new(
        protocol: TransportProtocol,
        endpoint1: FlowEndpoint,
        endpoint2: FlowEndpoint,
    ) -> Self {
        let (endpoint_a, endpoint_b) = if endpoint1 <= endpoint2 {
            (endpoint1, endpoint2)
        } else {
            (endpoint2, endpoint1)
        };
        Self {
            protocol,
            endpoint_a,
            endpoint_b,
        }
    }

    /// Returns the transport protocol of this flow key.
    #[must_use]
    pub const fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    /// Returns the first canonical endpoint (`endpoint_a <= endpoint_b`).
    #[must_use]
    pub const fn endpoint_a(&self) -> FlowEndpoint {
        self.endpoint_a
    }

    /// Returns the second canonical endpoint (`endpoint_a <= endpoint_b`).
    #[must_use]
    pub const fn endpoint_b(&self) -> FlowEndpoint {
        self.endpoint_b
    }

    /// Determines the flow direction of an observed packet relative to this canonical key.
    ///
    /// - If `source == destination`, returns [`FlowDirection::SameEndpoint`].
    /// - If `source == endpoint_a && destination == endpoint_b`, returns [`FlowDirection::AToB`].
    /// - If `source == endpoint_b && destination == endpoint_a`, returns [`FlowDirection::BToA`].
    /// - If the endpoints do not match this key, returns `None`.
    #[must_use]
    pub fn direction_of(
        &self,
        source: FlowEndpoint,
        destination: FlowEndpoint,
    ) -> Option<FlowDirection> {
        if source == destination && (source == self.endpoint_a || source == self.endpoint_b) {
            Some(FlowDirection::SameEndpoint)
        } else if source == self.endpoint_a && destination == self.endpoint_b {
            Some(FlowDirection::AToB)
        } else if source == self.endpoint_b && destination == self.endpoint_a {
            Some(FlowDirection::BToA)
        } else {
            None
        }
    }
}

/// Direction of an observed packet relative to canonical [`FlowKey`] endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowDirection {
    /// Traffic observed from `endpoint_a` to `endpoint_b`.
    AToB,
    /// Traffic observed from `endpoint_b` to `endpoint_a`.
    BToA,
    /// Traffic observed where source and destination endpoints are identical.
    SameEndpoint,
}

impl FlowDirection {
    /// Returns `true` if the direction is `AToB`.
    #[must_use]
    pub const fn is_a_to_b(&self) -> bool {
        matches!(self, Self::AToB)
    }

    /// Returns `true` if the direction is `BToA`.
    #[must_use]
    pub const fn is_b_to_a(&self) -> bool {
        matches!(self, Self::BToA)
    }

    /// Returns `true` if the source and destination endpoints are identical.
    #[must_use]
    pub const fn is_same_endpoint(&self) -> bool {
        matches!(self, Self::SameEndpoint)
    }
}

impl fmt::Display for FlowDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AToB => f.write_str("A->B"),
            Self::BToA => f.write_str("B->A"),
            Self::SameEndpoint => f.write_str("SameEndpoint"),
        }
    }
}

/// Capture-local identifier for a distinct flow instance.
///
/// Distinguishes sequential reuse of the same [`FlowKey`] across lifecycle boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FlowReference {
    ordinal: u64,
}

impl FlowReference {
    /// Creates a new flow reference with a zero-based ordinal.
    #[must_use]
    pub const fn new(ordinal: u64) -> Self {
        Self { ordinal }
    }

    /// Returns the zero-based monotonic ordinal of this flow instance.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

impl fmt::Display for FlowReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flow({})", self.ordinal)
    }
}

/// Compact immutable association linking a packet to a reconstructed flow instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowPacketAssociation {
    /// Flow instance reference.
    pub flow: FlowReference,
    /// Packet reference in the capture stream.
    pub packet: PacketReference,
    /// Direction relative to canonical endpoints.
    pub direction: FlowDirection,
}

impl FlowPacketAssociation {
    /// Creates a new flow packet association.
    #[must_use]
    pub const fn new(
        flow: FlowReference,
        packet: PacketReference,
        direction: FlowDirection,
    ) -> Self {
        Self {
            flow,
            packet,
            direction,
        }
    }
}

/// Reason for closing an active flow instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowEndReason {
    /// Capture input ended while flow was active.
    EndOfInput,
    /// Reliable timestamp difference exceeded configured idle timeout.
    IdleTimeout,
    /// A TCP packet with the RST flag set terminated the flow.
    TcpReset,
    /// A new initial TCP SYN packet (SYN=1, ACK=0) was observed after activity.
    TcpNewInitialSyn,
}

impl FlowEndReason {
    /// Returns the static label for this end reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EndOfInput => "EndOfInput",
            Self::IdleTimeout => "IdleTimeout",
            Self::TcpReset => "TcpReset",
            Self::TcpNewInitialSyn => "TcpNewInitialSyn",
        }
    }
}

impl fmt::Display for FlowEndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

use crate::flow_metrics::{FlowTemporalMetrics, FlowTrafficStatistics};

/// Factual record summarizing a completed flow instance, including traffic statistics
/// and exact temporal metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    /// Unique flow instance reference.
    pub reference: FlowReference,
    /// Canonical bidirectional flow key.
    pub key: FlowKey,
    /// Reference to the first observed packet in this flow instance.
    pub first_packet: PacketReference,
    /// Reference to the last observed packet in this flow instance.
    pub last_packet: PacketReference,
    /// Reason the flow instance was closed.
    pub end_reason: FlowEndReason,
    /// Factual traffic counters across total and directional buckets.
    pub traffic: FlowTrafficStatistics,
    /// Exact temporal metrics and inter-arrival series.
    pub temporal: FlowTemporalMetrics,
}

impl FlowRecord {
    /// Creates a new completed flow record.
    #[must_use]
    pub const fn new(
        reference: FlowReference,
        key: FlowKey,
        first_packet: PacketReference,
        last_packet: PacketReference,
        end_reason: FlowEndReason,
        traffic: FlowTrafficStatistics,
        temporal: FlowTemporalMetrics,
    ) -> Self {
        Self {
            reference,
            key,
            first_packet,
            last_packet,
            end_reason,
            traffic,
            temporal,
        }
    }
}
