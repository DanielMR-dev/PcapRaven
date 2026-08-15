//! Capture-independent normalized DNS observation models and contracts.
//!
//! This module defines domain types representing factual DNS messages, questions,
//! resource records, EDNS(0) metadata, and diagnostics extracted from packet streams.

use crate::packet::{IpAddress, PacketReference, PacketTimestamp};
use core::fmt;

/// Transport layer framing used for a DNS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsTransport {
    /// Standard datagram transport via UDP (port 53).
    Udp,
    /// Length-prefixed stream transport via TCP (port 53).
    Tcp,
}

impl DnsTransport {
    /// Returns the static string representation of this transport.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
        }
    }
}

impl fmt::Display for DnsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Factual DNS message kind determined from the QR flag bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsMessageKind {
    /// DNS Query message (QR = 0).
    Query,
    /// DNS Response message (QR = 1).
    Response,
}

impl DnsMessageKind {
    /// Returns the static string representation of this message kind.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "Query",
            Self::Response => "Response",
        }
    }
}

impl fmt::Display for DnsMessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Decoded DNS header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DnsFlags {
    /// Query (false) or Response (true) bit (QR).
    pub qr: bool,
    /// 4-bit Operation Code (OPCODE).
    pub opcode: u8,
    /// Authoritative Answer bit (AA).
    pub aa: bool,
    /// TrunCation bit (TC).
    pub tc: bool,
    /// Recursion Desired bit (RD).
    pub rd: bool,
    /// Recursion Available bit (RA).
    pub ra: bool,
    /// Authentic Data bit (AD, RFC 4035 / RFC 6840).
    pub ad: bool,
    /// Checking Disabled bit (CD, RFC 4035 / RFC 6840).
    pub cd: bool,
    /// 4-bit Base Response Code (RCODE).
    pub base_rcode: u8,
    /// Raw 16-bit flags field as observed on the wire.
    pub raw: u16,
}

impl DnsFlags {
    /// Decodes a 16-bit raw DNS flags word.
    #[must_use]
    pub const fn from_u16(raw: u16) -> Self {
        let qr = (raw & 0x8000) != 0;
        let opcode = ((raw >> 11) & 0x0F) as u8;
        let aa = (raw & 0x0400) != 0;
        let tc = (raw & 0x0200) != 0;
        let rd = (raw & 0x0100) != 0;
        let ra = (raw & 0x0080) != 0;
        let ad = (raw & 0x0020) != 0;
        let cd = (raw & 0x0010) != 0;
        let base_rcode = (raw & 0x000F) as u8;

        Self {
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            ad,
            cd,
            base_rcode,
            raw,
        }
    }
}

/// Maximum allowed length of an individual DNS label in octets (RFC 1035).
pub const MAX_DNS_LABEL_LENGTH: usize = 63;

/// Maximum allowed wire length of an expanded domain name in octets, including length bytes and root null (RFC 1035).
pub const MAX_DNS_NAME_WIRE_LENGTH: usize = 255;

/// Bounded domain name represented as a sequence of raw wire octet labels.
///
/// Labels preserve raw bytes faithfully without assuming UTF-8.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
}

impl DnsName {
    /// Creates a root domain name (`.`).
    #[must_use]
    pub const fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// Creates a domain name from a validated list of label byte vectors.
    ///
    /// Returns `None` if any label exceeds 63 octets or total expanded wire length exceeds 255 octets.
    #[must_use]
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Option<Self> {
        let mut wire_len = 1usize; // terminating root byte
        for label in &labels {
            if label.is_empty() || label.len() > MAX_DNS_LABEL_LENGTH {
                return None;
            }
            wire_len = wire_len.checked_add(1)?.checked_add(label.len())?;
        }
        if wire_len > MAX_DNS_NAME_WIRE_LENGTH {
            return None;
        }
        Some(Self { labels })
    }

    /// Returns `true` if this name represents the DNS root domain (`.`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Returns the slice of labels constituting this domain name.
    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Computes the expanded wire length of this domain name in octets.
    #[must_use]
    pub fn wire_length(&self) -> usize {
        let mut len = 1usize;
        for label in &self.labels {
            len = len.saturating_add(1).saturating_add(label.len());
        }
        len
    }

    /// Renders a deterministic terminal-safe string representation of the domain name.
    ///
    /// Control characters, non-ASCII octets, dots, and backslashes within labels are
    /// escaped in `\DDD` (3-digit decimal) notation so raw capture bytes cannot inject
    /// ANSI escapes or control sequences into terminal output.
    #[must_use]
    pub fn display_escaped(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }

        let mut output = String::new();
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                output.push('.');
            }
            for &b in label {
                match b {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => {
                        output.push(b as char);
                    }
                    _ => {
                        use core::fmt::Write;
                        let _ = write!(output, "\\{:03}", b);
                    }
                }
            }
        }
        output
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_escaped())
    }
}

/// Normalized DNS question section entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    /// Queried domain name.
    pub name: DnsName,
    /// 16-bit Query Type code (e.g. 1 for A, 28 for AAAA).
    pub qtype: u16,
    /// 16-bit Query Class code (e.g. 1 for IN).
    pub qclass: u16,
}

impl DnsQuestion {
    /// Creates a new DNS question entry.
    #[must_use]
    pub const fn new(name: DnsName, qtype: u16, qclass: u16) -> Self {
        Self {
            name,
            qtype,
            qclass,
        }
    }

    /// Returns a human-friendly uppercase mnemonic for common QTYPE values.
    #[must_use]
    pub const fn qtype_name(qtype: u16) -> &'static str {
        match qtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            41 => "OPT",
            251 => "IXFR",
            252 => "AXFR",
            255 => "ANY",
            _ => "UNKNOWN",
        }
    }
}

/// Resource record section in a DNS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsSection {
    /// Question section.
    Question,
    /// Answer section (ANCOUNT).
    Answer,
    /// Authority section (NSCOUNT).
    Authority,
    /// Additional section (ARCOUNT).
    Additional,
}

impl DnsSection {
    /// Returns the static label for this section.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Question => "Question",
            Self::Answer => "Answer",
            Self::Authority => "Authority",
            Self::Additional => "Additional",
        }
    }
}

/// Decoded metadata for selected DNS resource records.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsRdataMetadata {
    /// IPv4 host address (Type A = 1).
    A([u8; 4]),
    /// IPv6 host address (Type AAAA = 28).
    Aaaa([u8; 16]),
    /// Canonical name pointer (Type CNAME = 5).
    Cname(DnsName),
    /// Authoritative name server (Type NS = 2).
    Ns(DnsName),
    /// Domain name pointer (Type PTR = 12).
    Ptr(DnsName),
    /// Mail exchange (Type MX = 15).
    Mx {
        /// Preference value (lower is higher priority).
        preference: u16,
        /// Mail exchange host name.
        exchange: DnsName,
    },
    /// EDNS(0) OPT pseudo-record metadata (Type OPT = 41).
    Opt(DnsEdnsMetadata),
    /// Unparsed or unsupported RR type, preserving raw length.
    Unknown {
        /// Raw RR type code.
        rtype: u16,
        /// Declared RDATA wire length.
        rdlength: u16,
    },
}

/// Normalized DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsResourceRecord {
    /// Owner name of the resource record.
    pub name: DnsName,
    /// 16-bit RR type code.
    pub rtype: u16,
    /// 16-bit RR class code.
    pub rclass: u16,
    /// 32-bit Time-To-Live in seconds.
    pub ttl: u32,
    /// Declared RDATA wire length in octets.
    pub rdlength: u16,
    /// Parsed RDATA metadata.
    pub rdata: DnsRdataMetadata,
    /// Enclosing DNS message section.
    pub section: DnsSection,
}

/// Metadata for a single EDNS(0) option TLV (RFC 6891).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsEdnsOptionMetadata {
    /// 16-bit Option Code.
    pub code: u16,
    /// 16-bit Option Length in octets.
    pub length: u16,
}

/// Decoded EDNS(0) pseudo-record metadata (RFC 6891).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DnsEdnsMetadata {
    /// Requester's UDP payload size (from CLASS field).
    pub udp_payload_size: u16,
    /// High 8 bits of extended RCODE (from TTL field).
    pub extended_rcode: u8,
    /// EDNS version (from TTL field).
    pub version: u8,
    /// DNSSEC OK bit (DO bit, from TTL field).
    pub dnssec_ok: bool,
    /// Remaining reserved Z bits (from TTL field).
    pub z: u16,
    /// Bounded list of decoded option headers.
    pub options: Vec<DnsEdnsOptionMetadata>,
}

/// Completeness status of a normalized DNS observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsObservationCompleteness {
    /// Message was fully and completely parsed according to declared counts and boundaries.
    Complete,
    /// Message was partially parsed up to a safe structural boundary before an error or limit.
    Partial {
        /// Safe fixed explanation for partial completeness.
        reason: &'static str,
    },
}

impl DnsObservationCompleteness {
    /// Returns `true` if this observation is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// A normalized, capture-independent factual DNS observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    /// Reference to the source capture record.
    pub packet: PacketReference,
    /// Timestamp of the source packet.
    pub timestamp: PacketTimestamp,
    /// Transport layer used (UDP or TCP).
    pub transport: DnsTransport,
    /// Observed source IP address.
    pub source_ip: IpAddress,
    /// Observed source transport port.
    pub source_port: u16,
    /// Observed destination IP address.
    pub destination_ip: IpAddress,
    /// Observed destination transport port.
    pub destination_port: u16,
    /// 16-bit DNS transaction ID.
    pub transaction_id: u16,
    /// Message kind (Query or Response).
    pub message_kind: DnsMessageKind,
    /// 4-bit Opcode.
    pub opcode: u8,
    /// 4-bit Base Response Code.
    pub response_code: u8,
    /// Effective Response Code composed with EDNS extended RCODE when available.
    pub effective_response_code: u16,
    /// Decoded header flags.
    pub flags: DnsFlags,
    /// Declared QDCOUNT (question count).
    pub declared_qdcount: u16,
    /// Declared ANCOUNT (answer count).
    pub declared_ancount: u16,
    /// Declared NSCOUNT (authority count).
    pub declared_nscount: u16,
    /// Declared ARCOUNT (additional count).
    pub declared_arcount: u16,
    /// Bounded parsed questions.
    pub questions: Vec<DnsQuestion>,
    /// Bounded parsed resource records.
    pub records: Vec<DnsResourceRecord>,
    /// Decoded EDNS(0) metadata if a valid OPT record was present.
    pub edns: Option<DnsEdnsMetadata>,
    /// Explicit completeness status.
    pub completeness: DnsObservationCompleteness,
}

/// Category of a DNS parser diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsDiagnosticKind {
    /// Malformed wire structure or invalid field value.
    Malformed,
    /// Truncated payload before a required field or record ended.
    Incomplete,
    /// Recognized structure outside the supported subset.
    Unsupported,
    /// A configured finite parser limit was reached.
    ResourceLimit,
    /// An internal invariant failed.
    Internal,
}

/// Bounded diagnostic emitted during DNS parsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsDiagnostic {
    /// Diagnostic classification.
    pub kind: DnsDiagnosticKind,
    /// Safe, static message template.
    pub message: &'static str,
    /// Byte offset within the transport payload.
    pub offset: usize,
    /// Message index within the packet (0 for UDP, 0-based index for TCP).
    pub message_index: usize,
}
