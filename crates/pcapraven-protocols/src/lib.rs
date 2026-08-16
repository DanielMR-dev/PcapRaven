//! Bounded Ethernet, IPv4, IPv6, TCP, UDP, DNS, and HTTP/1.x protocol analysis for PcapRaven.
//!
//! This crate normalizes opaque capture-container packet facts into structured,
//! capture-independent domain observations and parses application protocols.

pub mod dns;
pub mod dns_limits;
pub mod http;
pub mod http_limits;
pub mod limits;
pub mod normalizer;
pub mod tls;
pub mod tls_limits;

pub use dns::{DnsPacketDisposition, DnsPacketOutcome, parse_dns_packet};
pub use dns_limits::{
    DnsLimitError, DnsLimits, DnsLimitsBuilder, MAX_ALLOWED_DNS_DIAGNOSTICS_PER_PACKET,
    MAX_ALLOWED_DNS_EDNS_OPTIONS_PER_MESSAGE, MAX_ALLOWED_DNS_MESSAGES_PER_PACKET,
    MAX_ALLOWED_DNS_NAME_POINTER_HOPS, MAX_ALLOWED_DNS_QUESTIONS_PER_MESSAGE,
    MAX_ALLOWED_DNS_RESOURCE_RECORDS_PER_MESSAGE, MAX_ALLOWED_DNS_TOTAL_NAME_BYTES_PER_MESSAGE,
};
pub use http::{HttpPacketDisposition, HttpPacketOutcome, parse_http_packet};
pub use http_limits::{
    HttpLimitError, HttpLimits, HttpLimitsBuilder, MAX_ALLOWED_HTTP_DIAGNOSTICS_PER_PACKET,
    MAX_ALLOWED_HTTP_HEADER_FIELDS, MAX_ALLOWED_HTTP_HEADER_LINE_BYTES,
    MAX_ALLOWED_HTTP_HEADER_SECTION_BYTES, MAX_ALLOWED_HTTP_METHOD_BYTES,
    MAX_ALLOWED_HTTP_REQUEST_TARGET_BYTES, MAX_ALLOWED_HTTP_SELECTED_FIELD_VALUE_BYTES,
    MAX_ALLOWED_HTTP_START_LINE_BYTES,
};
pub use limits::{
    MAX_ALLOWED_DIAGNOSTICS_PER_PACKET, MAX_ALLOWED_IPV6_EXTENSION_BYTES,
    MAX_ALLOWED_IPV6_EXTENSION_HEADERS, MAX_ALLOWED_RETAINED_PAYLOAD_BYTES,
    NormalizationLimitError, NormalizationLimits, NormalizationLimitsBuilder,
};
pub use normalizer::normalize_packet;
pub use tls::{TlsPacketDisposition, TlsPacketOutcome, parse_tls_packet};
pub use tls_limits::{
    HARD_MAX_ALPN_PROTOCOLS, HARD_MAX_CIPHER_SUITES_PER_CLIENT_HELLO,
    HARD_MAX_DIAGNOSTICS_PER_PACKET, HARD_MAX_EXTENSIONS_PER_HELLO,
    HARD_MAX_HANDSHAKE_MESSAGE_BYTES, HARD_MAX_HANDSHAKE_MESSAGES_PER_PACKET,
    HARD_MAX_KEY_SHARE_ENTRIES, HARD_MAX_RECORDS_PER_PACKET, HARD_MAX_SERVER_NAME_BYTES,
    HARD_MAX_SIGNATURE_ALGORITHMS, HARD_MAX_SUPPORTED_GROUPS, HARD_MAX_SUPPORTED_VERSIONS,
    HARD_MAX_TOTAL_ALPN_BYTES, MAX_TLS_OPAQUE_RECORD_FRAGMENT_BYTES,
    MAX_TLS_PLAINTEXT_FRAGMENT_BYTES, TlsLimitError, TlsLimits, TlsLimitsBuilder,
};
