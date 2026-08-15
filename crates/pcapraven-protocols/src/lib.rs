//! Bounded Ethernet, IPv4, IPv6, TCP, and UDP packet normalization for PcapRaven.
//!
//! This crate normalizes opaque capture-container packet facts into structured,
//! capture-independent domain observations. It does not ingest capture files directly,
//! reconstruct bidirectional flows, parse application protocols (DNS/HTTP/TLS),
//! run detections, or format user reports.

pub mod dns;
pub mod dns_limits;
pub mod limits;
pub mod normalizer;

pub use dns::{DnsPacketDisposition, DnsPacketOutcome, parse_dns_packet};
pub use dns_limits::{
    DnsLimitError, DnsLimits, DnsLimitsBuilder, MAX_ALLOWED_DNS_DIAGNOSTICS_PER_PACKET,
    MAX_ALLOWED_DNS_EDNS_OPTIONS_PER_MESSAGE, MAX_ALLOWED_DNS_MESSAGES_PER_PACKET,
    MAX_ALLOWED_DNS_NAME_POINTER_HOPS, MAX_ALLOWED_DNS_QUESTIONS_PER_MESSAGE,
    MAX_ALLOWED_DNS_RESOURCE_RECORDS_PER_MESSAGE, MAX_ALLOWED_DNS_TOTAL_NAME_BYTES_PER_MESSAGE,
};
pub use limits::{
    MAX_ALLOWED_DIAGNOSTICS_PER_PACKET, MAX_ALLOWED_IPV6_EXTENSION_BYTES,
    MAX_ALLOWED_IPV6_EXTENSION_HEADERS, MAX_ALLOWED_RETAINED_PAYLOAD_BYTES,
    NormalizationLimitError, NormalizationLimits, NormalizationLimitsBuilder,
};
pub use normalizer::normalize_packet;
