//! Serializable DTOs for normalized DNS observation reports.

use pcapraven_domain::{DnsObservation, DnsQuestion, DnsResourceRecord};
use serde::Serialize;

use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for a DNS report in JSON.
#[derive(Debug, Clone, Serialize)]
pub struct DnsReportDto {
    /// Schema version anchor ("v1.0").
    pub schema_version: &'static str,
    /// Report kind identifier ("dns").
    pub kind: &'static str,
    /// Total count of DNS observations.
    pub total_observations: usize,
    /// List of normalized DNS observations.
    pub observations: Vec<DnsObservationDto>,
}

impl DnsReportDto {
    /// Constructs a new DTO from a slice of domain DNS observations.
    #[must_use]
    pub fn from_domain_observations(observations: &[DnsObservation]) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "dns",
            total_observations: observations.len(),
            observations: observations
                .iter()
                .map(DnsObservationDto::from_domain)
                .collect(),
        }
    }
}

/// A normalized DNS observation record.
#[derive(Debug, Clone, Serialize)]
pub struct DnsObservationDto {
    /// Zero-based packet ordinal in capture file.
    pub packet_ordinal: u64,
    /// Transport protocol ("UDP" or "TCP").
    pub transport: String,
    /// Source IP address string.
    pub source_ip: String,
    /// Source UDP/TCP port number.
    pub source_port: u16,
    /// Destination IP address string.
    pub destination_ip: String,
    /// Destination UDP/TCP port number.
    pub destination_port: u16,
    /// DNS 16-bit transaction ID.
    pub transaction_id: u16,
    /// Message kind ("query" or "response").
    pub message_kind: String,
    /// DNS 4-bit opcode (0=Standard Query).
    pub opcode: u8,
    /// Authoritative Answer flag.
    pub authoritative_answer: bool,
    /// Truncation flag.
    pub truncation: bool,
    /// Recursion Desired flag.
    pub recursion_desired: bool,
    /// Recursion Available flag.
    pub recursion_available: bool,
    /// Effective Response code (RCODE composed with EDNS).
    pub response_code: u16,
    /// Questions section records.
    pub questions: Vec<DnsQuestionDto>,
    /// Answer resource records.
    pub answers: Vec<DnsResourceRecordDto>,
    /// Authority resource records.
    pub authorities: Vec<DnsResourceRecordDto>,
    /// Additional resource records.
    pub additionals: Vec<DnsResourceRecordDto>,
    /// EDNS(0) metadata if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edns: Option<DnsEdnsDto>,
    /// Completeness status ("complete" or "partial").
    pub completeness: String,
}

impl DnsObservationDto {
    /// Converts a domain [`DnsObservation`] into a serializable DTO.
    #[must_use]
    pub fn from_domain(obs: &DnsObservation) -> Self {
        Self {
            packet_ordinal: obs.packet.capture_record_ordinal,
            transport: obs.transport.as_str().to_string(),
            source_ip: obs.source_ip.to_string(),
            source_port: obs.source_port,
            destination_ip: obs.destination_ip.to_string(),
            destination_port: obs.destination_port,
            transaction_id: obs.transaction_id,
            message_kind: obs.message_kind.as_str().to_string(),
            opcode: obs.opcode,
            authoritative_answer: obs.flags.aa,
            truncation: obs.flags.tc,
            recursion_desired: obs.flags.rd,
            recursion_available: obs.flags.ra,
            response_code: obs.effective_response_code,
            questions: obs
                .questions
                .iter()
                .map(DnsQuestionDto::from_domain)
                .collect(),
            answers: obs
                .records
                .iter()
                .filter(|r| r.section == pcapraven_domain::DnsSection::Answer)
                .map(DnsResourceRecordDto::from_domain)
                .collect(),
            authorities: obs
                .records
                .iter()
                .filter(|r| r.section == pcapraven_domain::DnsSection::Authority)
                .map(DnsResourceRecordDto::from_domain)
                .collect(),
            additionals: obs
                .records
                .iter()
                .filter(|r| r.section == pcapraven_domain::DnsSection::Additional)
                .map(DnsResourceRecordDto::from_domain)
                .collect(),
            edns: obs.edns.as_ref().map(DnsEdnsDto::from_domain),
            completeness: if obs.completeness.is_complete() {
                "complete".to_string()
            } else {
                "partial".to_string()
            },
        }
    }
}

/// A DNS question record.
#[derive(Debug, Clone, Serialize)]
pub struct DnsQuestionDto {
    /// Query domain name (terminal-safe escaped).
    pub name: String,
    /// Query type code (1=A, 28=AAAA, 16=TXT, etc.).
    pub qtype: u16,
    /// Query type mnemonic name ("A", "AAAA", "TXT", or "TYPE###").
    pub qtype_name: String,
    /// Query class code (1=IN).
    pub qclass: u16,
}

impl DnsQuestionDto {
    /// Converts a domain [`DnsQuestion`] into a DTO.
    #[must_use]
    pub fn from_domain(q: &DnsQuestion) -> Self {
        Self {
            name: q.name.display_escaped(),
            qtype: q.qtype,
            qtype_name: DnsQuestion::qtype_name(q.qtype).to_string(),
            qclass: q.qclass,
        }
    }
}

/// A DNS resource record in Answer, Authority, or Additional sections.
#[derive(Debug, Clone, Serialize)]
pub struct DnsResourceRecordDto {
    /// Owner name (terminal-safe escaped).
    pub name: String,
    /// Resource record type code.
    pub rtype: u16,
    /// Resource record class code.
    pub rclass: u16,
    /// Time-to-Live in seconds.
    pub ttl: u32,
    /// Formatted data summary or terminal-safe escaped text.
    pub data: String,
}

impl DnsResourceRecordDto {
    /// Converts a domain [`DnsResourceRecord`] into a DTO.
    #[must_use]
    pub fn from_domain(rr: &DnsResourceRecord) -> Self {
        let data_str = match &rr.rdata {
            pcapraven_domain::DnsRdataMetadata::A(octets) => {
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            pcapraven_domain::DnsRdataMetadata::Aaaa(octets) => {
                std::net::Ipv6Addr::from(*octets).to_string()
            }
            pcapraven_domain::DnsRdataMetadata::Cname(n)
            | pcapraven_domain::DnsRdataMetadata::Ns(n)
            | pcapraven_domain::DnsRdataMetadata::Ptr(n) => n.display_escaped(),
            pcapraven_domain::DnsRdataMetadata::Mx {
                preference,
                exchange,
            } => {
                format!("{} {}", preference, exchange.display_escaped())
            }
            pcapraven_domain::DnsRdataMetadata::Opt(opt) => {
                format!("OPT udp={} do={}", opt.udp_payload_size, opt.dnssec_ok)
            }
            pcapraven_domain::DnsRdataMetadata::Unknown { rtype, rdlength } => {
                format!("TYPE{} ({} bytes)", rtype, rdlength)
            }
        };

        Self {
            name: rr.name.display_escaped(),
            rtype: rr.rtype,
            rclass: rr.rclass,
            ttl: rr.ttl,
            data: data_str,
        }
    }
}

/// EDNS(0) extension metadata.
#[derive(Debug, Clone, Serialize)]
pub struct DnsEdnsDto {
    /// Client UDP payload size buffer capacity.
    pub udp_payload_size: u16,
    /// Extended RCODE upper bits.
    pub extended_rcode: u8,
    /// EDNS version (0).
    pub version: u8,
    /// DNSSEC OK (DO) bit.
    pub dnssec_ok: bool,
    /// Option codes present in the OPT record.
    pub options: Vec<u16>,
}

impl DnsEdnsDto {
    /// Converts domain EDNS metadata into a DTO.
    #[must_use]
    pub fn from_domain(edns: &pcapraven_domain::DnsEdnsMetadata) -> Self {
        Self {
            udp_payload_size: edns.udp_payload_size,
            extended_rcode: edns.extended_rcode,
            version: edns.version,
            dnssec_ok: edns.dnssec_ok,
            options: edns.options.iter().map(|opt| opt.code).collect(),
        }
    }
}
