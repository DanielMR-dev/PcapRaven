//! Bounded Ethernet, IPv4, IPv6, TCP, and UDP packet normalization for PcapRaven.
//!
//! This crate normalizes opaque capture-container packet facts into structured,
//! capture-independent domain observations. It does not ingest capture files directly,
//! reconstruct bidirectional flows, parse application protocols (DNS/HTTP/TLS),
//! run detections, or format user reports.

pub mod limits;
pub mod normalizer;

pub use limits::{
    MAX_ALLOWED_DIAGNOSTICS_PER_PACKET, MAX_ALLOWED_IPV6_EXTENSION_BYTES,
    MAX_ALLOWED_IPV6_EXTENSION_HEADERS, MAX_ALLOWED_RETAINED_PAYLOAD_BYTES,
    NormalizationLimitError, NormalizationLimits, NormalizationLimitsBuilder,
};
pub use normalizer::normalize_packet;
