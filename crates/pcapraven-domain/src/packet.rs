//! Capture-independent packet normalization types and contracts.

use core::fmt;

/// Stable identity reference tying a normalized packet to its source capture record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketReference {
    /// Zero-based sequential emitted record index within the capture stream.
    pub capture_record_ordinal: u64,
    /// Section ordinal if known from the capture container.
    pub section_ordinal: Option<u32>,
    /// Interface ordinal within the section if known from the capture container.
    pub interface_ordinal: Option<u32>,
    /// Number of bytes actually captured and available.
    pub captured_len: u32,
    /// Declared original wire length of the packet.
    pub original_len: u32,
    /// Whether the capture container reported this packet as truncated.
    pub truncated: bool,
}

impl PacketReference {
    /// Create a new packet reference.
    #[must_use]
    pub const fn new(
        capture_record_ordinal: u64,
        section_ordinal: Option<u32>,
        interface_ordinal: Option<u32>,
        captured_len: u32,
        original_len: u32,
        truncated: bool,
    ) -> Self {
        Self {
            capture_record_ordinal,
            section_ordinal,
            interface_ordinal,
            captured_len,
            original_len,
            truncated,
        }
    }
}

/// Capture-independent timestamp resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketTimestampResolution {
    /// Decimal units per second (`10^exponent`).
    Decimal {
        /// Base-10 exponent.
        exponent: u8,
        /// Units per second.
        units_per_second: u64,
    },
    /// Binary units per second (`2^exponent`).
    Binary {
        /// Base-2 exponent.
        exponent: u8,
        /// Units per second.
        units_per_second: u64,
    },
}

/// Capture-independent packet timestamp state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PacketTimestamp {
    /// Timestamp was not recorded or is unavailable.
    #[default]
    Unavailable,
    /// Available timestamp with exact fractional resolution and signed timezone/local offset.
    Available {
        /// Whole seconds since Unix epoch (or section reference).
        seconds: i128,
        /// Fractional time units.
        fractional_units: u64,
        /// Resolution defining how many fractional units equal one second.
        resolution: PacketTimestampResolution,
        /// Signed offset in seconds applied to the timestamp if specified.
        offset_seconds: i64,
    },
}

impl PacketTimestamp {
    /// Check whether a timestamp value is available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

/// Borrowed input representation for normalizing one captured packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketNormalizationInput<'a> {
    /// Capture reference metadata for this packet.
    pub reference: PacketReference,
    /// Packet timestamp state.
    pub timestamp: PacketTimestamp,
    /// Numeric link layer type from capture container (e.g. 1 for Ethernet).
    pub linktype: u32,
    /// Raw captured packet bytes.
    pub data: &'a [u8],
}

impl<'a> PacketNormalizationInput<'a> {
    /// Create a new borrowed packet normalization input.
    #[must_use]
    pub const fn new(
        reference: PacketReference,
        timestamp: PacketTimestamp,
        linktype: u32,
        data: &'a [u8],
    ) -> Self {
        Self {
            reference,
            timestamp,
            linktype,
            data,
        }
    }
}

/// 6-byte IEEE 802 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Create a MAC address from 6 octets.
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Return the 6 octets as an array.
    #[must_use]
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MacAddress({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

/// Canonical binary IP address (IPv4 or IPv6).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpAddress {
    /// IPv4 4-octet address.
    Ipv4([u8; 4]),
    /// IPv6 16-octet address.
    Ipv6([u8; 16]),
}

impl IpAddress {
    /// Check whether the address is IPv4.
    #[must_use]
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, Self::Ipv4(_))
    }

    /// Check whether the address is IPv6.
    #[must_use]
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, Self::Ipv6(_))
    }
}

impl fmt::Debug for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(octets) => write!(
                f,
                "IpAddress({}.{}.{}.{})",
                octets[0], octets[1], octets[2], octets[3]
            ),
            Self::Ipv6(octets) => write!(
                f,
                "IpAddress({:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x})",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                octets[4],
                octets[5],
                octets[6],
                octets[7],
                octets[8],
                octets[9],
                octets[10],
                octets[11],
                octets[12],
                octets[13],
                octets[14],
                octets[15]
            ),
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(octets) => {
                write!(f, "{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            Self::Ipv6(octets) => write!(
                f,
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([octets[0], octets[1]]),
                u16::from_be_bytes([octets[2], octets[3]]),
                u16::from_be_bytes([octets[4], octets[5]]),
                u16::from_be_bytes([octets[6], octets[7]]),
                u16::from_be_bytes([octets[8], octets[9]]),
                u16::from_be_bytes([octets[10], octets[11]]),
                u16::from_be_bytes([octets[12], octets[13]]),
                u16::from_be_bytes([octets[14], octets[15]])
            ),
        }
    }
}

impl From<[u8; 4]> for IpAddress {
    fn from(octets: [u8; 4]) -> Self {
        Self::Ipv4(octets)
    }
}

impl From<[u8; 16]> for IpAddress {
    fn from(octets: [u8; 16]) -> Self {
        Self::Ipv6(octets)
    }
}

impl From<std::net::Ipv4Addr> for IpAddress {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self::Ipv4(addr.octets())
    }
}

impl From<std::net::Ipv6Addr> for IpAddress {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        Self::Ipv6(addr.octets())
    }
}

impl From<std::net::IpAddr> for IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => Self::Ipv4(v4.octets()),
            std::net::IpAddr::V6(v6) => Self::Ipv6(v6.octets()),
        }
    }
}

/// Normalized Ethernet II metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthernetMetadata {
    /// Source MAC address.
    pub source: MacAddress,
    /// Destination MAC address.
    pub destination: MacAddress,
    /// Normalized EtherType field (e.g. 0x0800 for IPv4, 0x86DD for IPv6).
    pub ethertype: u16,
    /// Ethernet header length in bytes (14 for standard Ethernet II).
    pub link_header_length: u8,
}

/// IP packet fragmentation classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FragmentationState {
    /// Not fragmented (offset 0, More Fragments flag false).
    #[default]
    NotFragmented,
    /// Fragmented packet requiring reassembly for transport interpretation.
    Fragmented {
        /// Fragment offset in 8-byte units (IPv4) or bytes (IPv6).
        offset: u16,
        /// Whether more fragments follow.
        more_fragments: bool,
        /// Optional identification tag from IPv4 header or IPv6 Fragment extension.
        identification: Option<u32>,
    },
}

impl FragmentationState {
    /// Check whether the packet is fragmented.
    #[must_use]
    pub const fn is_fragmented(&self) -> bool {
        matches!(self, Self::Fragmented { .. })
    }
}

/// Normalized IPv4 header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Metadata {
    /// IP version (always 4).
    pub version: u8,
    /// Internet Header Length (IHL) in bytes (20..=60).
    pub header_length: u8,
    /// Differentiated Services Code Point (6 bits).
    pub dscp: u8,
    /// Explicit Congestion Notification (2 bits).
    pub ecn: u8,
    /// Declared total length in bytes.
    pub total_length: u16,
    /// Identification field.
    pub identification: u16,
    /// Time To Live.
    pub ttl: u8,
    /// Next protocol number (e.g. 6 for TCP, 17 for UDP).
    pub protocol: u8,
    /// Binary IPv4 source address.
    pub source: [u8; 4],
    /// Binary IPv4 destination address.
    pub destination: [u8; 4],
    /// Fragmentation state.
    pub fragmentation: FragmentationState,
}

/// Normalized IPv6 header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Metadata {
    /// IP version (always 6).
    pub version: u8,
    /// Traffic Class (8 bits).
    pub traffic_class: u8,
    /// Flow Label (20 bits).
    pub flow_label: u32,
    /// Declared payload length in bytes.
    pub payload_length: u16,
    /// Next header in base header.
    pub next_header: u8,
    /// Hop Limit.
    pub hop_limit: u8,
    /// Binary IPv6 source address.
    pub source: [u8; 16],
    /// Binary IPv6 destination address.
    pub destination: [u8; 16],
    /// Number of extension headers traversed.
    pub extension_headers_count: u8,
    /// Total bytes of extension headers traversed.
    pub extension_headers_length: u16,
    /// Effective terminal upper-layer protocol (e.g. 6 for TCP, 17 for UDP).
    pub effective_protocol: u8,
    /// Fragmentation state from IPv6 Fragment extension if present.
    pub fragmentation: FragmentationState,
}

/// Network layer normalized metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkLayer {
    /// Normalized IPv4 header.
    Ipv4(Ipv4Metadata),
    /// Normalized IPv6 header and extension metadata.
    Ipv6(Ipv6Metadata),
}

impl NetworkLayer {
    /// Return the source IP address.
    #[must_use]
    pub const fn source_ip(&self) -> IpAddress {
        match self {
            Self::Ipv4(meta) => IpAddress::Ipv4(meta.source),
            Self::Ipv6(meta) => IpAddress::Ipv6(meta.source),
        }
    }

    /// Return the destination IP address.
    #[must_use]
    pub const fn destination_ip(&self) -> IpAddress {
        match self {
            Self::Ipv4(meta) => IpAddress::Ipv4(meta.destination),
            Self::Ipv6(meta) => IpAddress::Ipv6(meta.destination),
        }
    }

    /// Return the effective upper layer protocol number.
    #[must_use]
    pub const fn effective_protocol(&self) -> u8 {
        match self {
            Self::Ipv4(meta) => meta.protocol,
            Self::Ipv6(meta) => meta.effective_protocol,
        }
    }

    /// Return the fragmentation state.
    #[must_use]
    pub const fn fragmentation(&self) -> FragmentationState {
        match self {
            Self::Ipv4(meta) => meta.fragmentation,
            Self::Ipv6(meta) => meta.fragmentation,
        }
    }
}

/// Decoded TCP header control flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TcpFlags {
    /// ECN Nonce Sum (RFC 3540).
    pub ns: bool,
    /// Congestion Window Reduced.
    pub cwr: bool,
    /// ECN-Echo.
    pub ece: bool,
    /// Urgent Pointer field significant.
    pub urg: bool,
    /// Acknowledgment field significant.
    pub ack: bool,
    /// Push Function.
    pub psh: bool,
    /// Reset the connection.
    pub rst: bool,
    /// Synchronize sequence numbers.
    pub syn: bool,
    /// No more data from sender.
    pub fin: bool,
}

impl TcpFlags {
    /// Create `TcpFlags` from raw 9-bit or 12-bit flag integer representation.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self {
            ns: (bits & 0x0100) != 0,
            cwr: (bits & 0x0080) != 0,
            ece: (bits & 0x0040) != 0,
            urg: (bits & 0x0020) != 0,
            ack: (bits & 0x0010) != 0,
            psh: (bits & 0x0008) != 0,
            rst: (bits & 0x0004) != 0,
            syn: (bits & 0x0002) != 0,
            fin: (bits & 0x0001) != 0,
        }
    }

    /// Return the lower 9 bits representing these flags.
    #[must_use]
    pub const fn raw_bits(&self) -> u16 {
        let mut bits = 0u16;
        if self.ns {
            bits |= 0x0100;
        }
        if self.cwr {
            bits |= 0x0080;
        }
        if self.ece {
            bits |= 0x0040;
        }
        if self.urg {
            bits |= 0x0020;
        }
        if self.ack {
            bits |= 0x0010;
        }
        if self.psh {
            bits |= 0x0008;
        }
        if self.rst {
            bits |= 0x0004;
        }
        if self.syn {
            bits |= 0x0002;
        }
        if self.fin {
            bits |= 0x0001;
        }
        bits
    }
}

/// Normalized TCP header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpMetadata {
    /// Source port (0..=65535).
    pub source_port: u16,
    /// Destination port (0..=65535).
    pub destination_port: u16,
    /// Sequence number.
    pub sequence_number: u32,
    /// Acknowledgment number.
    pub acknowledgement_number: u32,
    /// TCP header length in bytes (20..=60).
    pub data_offset_bytes: u8,
    /// TCP control flags.
    pub flags: TcpFlags,
    /// Flow control window size.
    pub window_size: u16,
    /// Checksum field value recorded in packet.
    pub checksum: u16,
    /// Urgent pointer value.
    pub urgent_pointer: u16,
    /// Options length in bytes (`data_offset_bytes - 20`).
    pub options_length_bytes: u8,
}

/// Normalized UDP header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpMetadata {
    /// Source port (0..=65535).
    pub source_port: u16,
    /// Destination port (0..=65535).
    pub destination_port: u16,
    /// Length field recorded in UDP header (header + payload bytes).
    pub length: u16,
    /// Checksum field value recorded in packet.
    pub checksum: u16,
}

/// Transport layer normalized metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportLayer {
    /// Normalized TCP header metadata.
    Tcp(TcpMetadata),
    /// Normalized UDP header metadata.
    Udp(UdpMetadata),
}

impl TransportLayer {
    /// Return the source port.
    #[must_use]
    pub const fn source_port(&self) -> u16 {
        match self {
            Self::Tcp(meta) => meta.source_port,
            Self::Udp(meta) => meta.source_port,
        }
    }

    /// Return the destination port.
    #[must_use]
    pub const fn destination_port(&self) -> u16 {
        match self {
            Self::Tcp(meta) => meta.destination_port,
            Self::Udp(meta) => meta.destination_port,
        }
    }
}

/// Reason why a packet could only be partially normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketTruncationReason {
    /// Packet was truncated at the capture level (fewer bytes than original).
    CaptureTruncation,
    /// Enclosing layer contained fewer bytes than declared header/payload length.
    DeclaredLengthMismatch,
    /// Captured bytes ended before completing required header.
    HeaderTruncation,
    /// Application payload was truncated to satisfy the configured payload budget.
    PayloadBudgetExceeded,
    /// Packet is fragmented and transport layer was not normalized.
    Fragmented,
}

/// Reason why a packet layer is unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsupportedLayerReason {
    /// Link layer type is not supported (only LINKTYPE_ETHERNET = 1 is supported).
    LinkType(u32),
    /// Network layer EtherType is unsupported (e.g. VLAN, ARP, non-IP).
    EtherType(u16),
    /// Network protocol number is unsupported (e.g. ICMP).
    NetworkProtocol(u8),
    /// Transport protocol is unsupported.
    TransportProtocol(u8),
    /// IPv6 extension header is unsupported.
    Ipv6Extension(u8),
}

/// Completeness status of packet normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketCompleteness {
    /// All supported layers through transport and bounded payload normalized completely.
    Complete,
    /// Packet normalized partially up to a truncation or fragmentation boundary.
    Partial {
        /// Reason for partial normalization.
        reason: PacketTruncationReason,
    },
    /// Packet or an inner layer contains a valid but unsupported protocol.
    Unsupported {
        /// Reason for unsupported status.
        reason: UnsupportedLayerReason,
    },
}

impl PacketCompleteness {
    /// Check whether normalization completed without partial truncation or unsupported layers.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Bounded, normalized packet representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPacket {
    /// Traceable capture reference.
    pub reference: PacketReference,
    /// Capture timestamp.
    pub timestamp: PacketTimestamp,
    /// Normalized Ethernet link layer if supported.
    pub link_layer: Option<EthernetMetadata>,
    /// Normalized IPv4 / IPv6 network layer if supported.
    pub network_layer: Option<NetworkLayer>,
    /// Normalized TCP / UDP transport layer if supported.
    pub transport_layer: Option<TransportLayer>,
    /// Bounded application payload bytes (excluding Ethernet padding and IP/TCP/UDP headers).
    pub payload: Option<Vec<u8>>,
    /// Completeness status of the normalized packet.
    pub completeness: PacketCompleteness,
}

/// Category of normalization diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormalizationDiagnosticKind {
    /// Protocol or encapsulation is valid but not supported by PcapRaven.
    Unsupported,
    /// Header or structure contradicts protocol specifications.
    Malformed,
    /// Input ended before required bytes were available.
    Incomplete,
    /// Configured normalization limits prevented deeper traversal or full payload retention.
    ResourceLimit,
    /// Internal normalization invariant error.
    Internal,
}

/// Protocol layer where a diagnostic originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormalizationDiagnosticLayer {
    /// Link layer (Ethernet).
    Link,
    /// Network layer (IPv4 / IPv6).
    Network,
    /// IPv6 extension header chain.
    Ipv6Extension,
    /// Transport layer (TCP / UDP).
    Transport,
    /// Application payload extraction.
    Payload,
}

/// Structured diagnostic recorded during packet normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NormalizationDiagnostic {
    /// Classification of the issue.
    pub kind: NormalizationDiagnosticKind,
    /// Layer where the diagnostic occurred.
    pub layer: NormalizationDiagnosticLayer,
    /// Static diagnostic description.
    pub message: &'static str,
}

impl NormalizationDiagnostic {
    /// Create a new normalization diagnostic.
    #[must_use]
    pub const fn new(
        kind: NormalizationDiagnosticKind,
        layer: NormalizationDiagnosticLayer,
        message: &'static str,
    ) -> Self {
        Self {
            kind,
            layer,
            message,
        }
    }
}

/// Complete outcome of normalizing a single packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketNormalizationOutcome {
    /// Normalized packet facts.
    pub packet: NormalizedPacket,
    /// Bounded diagnostics collected during normalization.
    pub diagnostics: Vec<NormalizationDiagnostic>,
}

impl PacketNormalizationOutcome {
    /// Create a new packet normalization outcome.
    #[must_use]
    pub const fn new(packet: NormalizedPacket, diagnostics: Vec<NormalizationDiagnostic>) -> Self {
        Self {
            packet,
            diagnostics,
        }
    }
}
