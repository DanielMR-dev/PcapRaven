//! Unified protocol observations across DNS, HTTP, and TLS.
//!
//! Provides common observation identity, explicit flow association, typed protocol
//! observation data, derived completeness states, and bounded deterministic collections.

use crate::dns::DnsObservation;
use crate::flow::{FlowExclusionReason, FlowReference};
use crate::http::HttpObservation;
use crate::packet::PacketReference;
use crate::tls::TlsObservation;
use core::fmt;

/// Supported application protocol family for a normalized observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolKind {
    /// Domain Name System (RFC 1035 / RFC 6891).
    Dns,
    /// Hypertext Transfer Protocol version 1.0 / 1.1 (RFC 9112 / RFC 7230).
    Http,
    /// Transport Layer Security version 1.2 / 1.3 (RFC 5246 / RFC 9846).
    Tls,
}

impl ProtocolKind {
    /// Returns the static string representation of the protocol kind.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Dns => "DNS",
            Self::Http => "HTTP",
            Self::Tls => "TLS",
        }
    }
}

impl fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Monotonically assigned unique identifier for a protocol observation within an analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ObservationReference {
    id: u64,
}

impl ObservationReference {
    /// Creates a new observation reference.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Returns the numeric observation identifier.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }
}

impl fmt::Display for ObservationReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "obs:{}", self.id)
    }
}

/// Unified completeness status for a protocol observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservationCompleteness {
    /// All expected protocol metadata was observed and decoded within configured limits.
    Complete,
    /// Protocol metadata was truncated, exceeded resource bounds, or contained non-fatal malformed elements.
    Partial,
}

impl ObservationCompleteness {
    /// Returns `true` if the observation is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Returns `true` if the observation is partial.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        matches!(self, Self::Partial)
    }

    /// Returns the static label for this completeness state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "Complete",
            Self::Partial => "Partial",
        }
    }
}

impl fmt::Display for ObservationCompleteness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Explicit association between a protocol observation and a reconstructed bidirectional flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservationFlowAssociation {
    /// The observation is associated with a specific reconstructed flow instance.
    Associated(FlowReference),
    /// The observation originated from a packet that was excluded from flow reconstruction.
    Excluded(FlowExclusionReason),
    /// The observation has not been evaluated for flow association.
    Unassociated,
}

impl ObservationFlowAssociation {
    /// Returns `true` if this association is [`Self::Associated`].
    #[must_use]
    pub const fn is_associated(&self) -> bool {
        matches!(self, Self::Associated(_))
    }

    /// Returns `true` if this association is [`Self::Excluded`].
    #[must_use]
    pub const fn is_excluded(&self) -> bool {
        matches!(self, Self::Excluded(_))
    }

    /// Returns `true` if this association is [`Self::Unassociated`].
    #[must_use]
    pub const fn is_unassociated(&self) -> bool {
        matches!(self, Self::Unassociated)
    }

    /// Returns the associated flow reference, if any.
    #[must_use]
    pub const fn flow_reference(&self) -> Option<FlowReference> {
        match self {
            Self::Associated(flow) => Some(*flow),
            Self::Excluded(_) | Self::Unassociated => None,
        }
    }

    /// Returns the exclusion reason, if excluded.
    #[must_use]
    pub const fn exclusion_reason(&self) -> Option<FlowExclusionReason> {
        match self {
            Self::Excluded(reason) => Some(*reason),
            Self::Associated(_) | Self::Unassociated => None,
        }
    }
}

impl fmt::Display for ObservationFlowAssociation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Associated(flow) => write!(f, "Associated({})", flow),
            Self::Excluded(reason) => write!(f, "Excluded({})", reason),
            Self::Unassociated => f.write_str("Unassociated"),
        }
    }
}

/// Typed wrapper encapsulating protocol-specific observation payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolObservationData {
    /// Normalized DNS message observation.
    Dns(DnsObservation),
    /// Normalized cleartext HTTP/1.x message observation.
    Http(HttpObservation),
    /// Normalized visible TLS 1.2 / TLS 1.3 handshake metadata observation.
    Tls(TlsObservation),
}

impl ProtocolObservationData {
    /// Returns the protocol family for this observation data.
    #[must_use]
    pub const fn protocol_kind(&self) -> ProtocolKind {
        match self {
            Self::Dns(_) => ProtocolKind::Dns,
            Self::Http(_) => ProtocolKind::Http,
            Self::Tls(_) => ProtocolKind::Tls,
        }
    }

    /// Computes the unified observation completeness from the underlying protocol observation.
    #[must_use]
    pub fn completeness(&self) -> ObservationCompleteness {
        let is_comp = match self {
            Self::Dns(obs) => obs.completeness.is_complete(),
            Self::Http(obs) => obs.completeness.is_complete(),
            Self::Tls(obs) => obs.completeness.is_complete(),
        };
        if is_comp {
            ObservationCompleteness::Complete
        } else {
            ObservationCompleteness::Partial
        }
    }

    /// Returns `true` if this observation data is DNS.
    #[must_use]
    pub const fn is_dns(&self) -> bool {
        matches!(self, Self::Dns(_))
    }

    /// Returns `true` if this observation data is HTTP.
    #[must_use]
    pub const fn is_http(&self) -> bool {
        matches!(self, Self::Http(_))
    }

    /// Returns `true` if this observation data is TLS.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    /// Returns a reference to the DNS observation, if applicable.
    #[must_use]
    pub const fn as_dns(&self) -> Option<&DnsObservation> {
        match self {
            Self::Dns(obs) => Some(obs),
            Self::Http(_) | Self::Tls(_) => None,
        }
    }

    /// Returns a reference to the HTTP observation, if applicable.
    #[must_use]
    pub const fn as_http(&self) -> Option<&HttpObservation> {
        match self {
            Self::Http(obs) => Some(obs),
            Self::Dns(_) | Self::Tls(_) => None,
        }
    }

    /// Returns a reference to the TLS observation, if applicable.
    #[must_use]
    pub const fn as_tls(&self) -> Option<&TlsObservation> {
        match self {
            Self::Tls(obs) => Some(obs),
            Self::Dns(_) | Self::Http(_) => None,
        }
    }
}

/// Unified, capture-independent protocol observation record.
///
/// Encapsulates stable identity, packet provenance, flow association, completeness,
/// and protocol-specific decoded metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolObservation {
    /// Stable identifier for this observation.
    pub reference: ObservationReference,
    /// Originating capture packet reference.
    pub packet_reference: PacketReference,
    /// Association with a reconstructed bidirectional flow.
    pub flow_association: ObservationFlowAssociation,
    /// Derived or explicit completeness state.
    pub completeness: ObservationCompleteness,
    /// Protocol-specific observation payload.
    pub data: ProtocolObservationData,
}

impl ProtocolObservation {
    /// Creates a new protocol observation, deriving its completeness from the underlying payload.
    #[must_use]
    pub fn new(
        reference: ObservationReference,
        packet_reference: PacketReference,
        flow_association: ObservationFlowAssociation,
        data: ProtocolObservationData,
    ) -> Self {
        let completeness = data.completeness();
        Self {
            reference,
            packet_reference,
            flow_association,
            completeness,
            data,
        }
    }

    /// Creates a new protocol observation with explicit completeness status.
    #[must_use]
    pub const fn with_completeness(
        reference: ObservationReference,
        packet_reference: PacketReference,
        flow_association: ObservationFlowAssociation,
        completeness: ObservationCompleteness,
        data: ProtocolObservationData,
    ) -> Self {
        Self {
            reference,
            packet_reference,
            flow_association,
            completeness,
            data,
        }
    }

    /// Returns the observation reference.
    #[must_use]
    pub const fn reference(&self) -> ObservationReference {
        self.reference
    }

    /// Returns the originating packet reference.
    #[must_use]
    pub const fn packet_reference(&self) -> &PacketReference {
        &self.packet_reference
    }

    /// Returns the flow association.
    #[must_use]
    pub const fn flow_association(&self) -> &ObservationFlowAssociation {
        &self.flow_association
    }

    /// Returns the completeness state.
    #[must_use]
    pub const fn completeness(&self) -> ObservationCompleteness {
        self.completeness
    }

    /// Returns a reference to the observation data.
    #[must_use]
    pub const fn data(&self) -> &ProtocolObservationData {
        &self.data
    }

    /// Returns the protocol kind of this observation.
    #[must_use]
    pub const fn protocol_kind(&self) -> ProtocolKind {
        self.data.protocol_kind()
    }
}

/// Error type when initializing a [`ProtocolObservationCollection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolObservationCollectionError {
    /// Capacity must be greater than zero.
    ZeroCapacity,
}

impl fmt::Display for ProtocolObservationCollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => {
                f.write_str("protocol observation collection capacity must be greater than zero")
            }
        }
    }
}

impl std::error::Error for ProtocolObservationCollectionError {}

/// Bounded, deterministic collection of unified protocol observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolObservationCollection {
    observations: Vec<ProtocolObservation>,
    capacity: usize,
    is_truncated: bool,
}

impl ProtocolObservationCollection {
    /// Creates a new bounded observation collection with the specified non-zero maximum capacity.
    pub fn new(capacity: usize) -> Result<Self, ProtocolObservationCollectionError> {
        if capacity == 0 {
            return Err(ProtocolObservationCollectionError::ZeroCapacity);
        }
        Ok(Self {
            observations: Vec::with_capacity(capacity.min(1024)),
            capacity,
            is_truncated: false,
        })
    }

    /// Pushes an observation into the collection.
    ///
    /// Returns `true` if the observation was accepted.
    /// If capacity has been reached, sets `is_truncated = true` and returns `false`.
    pub fn push(&mut self, observation: ProtocolObservation) -> bool {
        if self.observations.len() < self.capacity {
            self.observations.push(observation);
            true
        } else {
            self.is_truncated = true;
            false
        }
    }

    /// Returns the number of observations currently in the collection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Returns `true` if the collection is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Returns the maximum capacity of the collection.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns `true` if one or more observations were dropped due to reaching capacity.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.is_truncated
    }

    /// Returns a slice over the observations.
    #[must_use]
    pub fn observations(&self) -> &[ProtocolObservation] {
        &self.observations
    }

    /// Returns an iterator over references to the observations.
    pub fn iter(&self) -> core::slice::Iter<'_, ProtocolObservation> {
        self.observations.iter()
    }

    /// Converts the collection into the underlying `Vec<ProtocolObservation>`.
    #[must_use]
    pub fn into_vec(self) -> Vec<ProtocolObservation> {
        self.observations
    }
}

impl<'a> IntoIterator for &'a ProtocolObservationCollection {
    type Item = &'a ProtocolObservation;
    type IntoIter = core::slice::Iter<'a, ProtocolObservation>;

    fn into_iter(self) -> Self::IntoIter {
        self.observations.iter()
    }
}

impl IntoIterator for ProtocolObservationCollection {
    type Item = ProtocolObservation;
    type IntoIter = std::vec::IntoIter<ProtocolObservation>;

    fn into_iter(self) -> Self::IntoIter {
        self.observations.into_iter()
    }
}
