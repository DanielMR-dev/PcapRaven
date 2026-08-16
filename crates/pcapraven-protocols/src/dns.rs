//! Bounded DNS wire-format parser and candidate classification.
//!
//! Parses normalized IPv4/IPv6 TCP and UDP packets on port 53 into structured,
//! capture-independent [`DnsObservation`] records and bounded diagnostics.

use crate::dns_limits::DnsLimits;
use pcapraven_domain::{
    DnsDiagnostic, DnsDiagnosticKind, DnsEdnsMetadata, DnsEdnsOptionMetadata, DnsFlags,
    DnsMessageKind, DnsName, DnsObservation, DnsObservationCompleteness, DnsQuestion,
    DnsRdataMetadata, DnsResourceRecord, DnsSection, DnsTransport, IpAddress, MAX_DNS_LABEL_LENGTH,
    MAX_DNS_NAME_WIRE_LENGTH, NormalizedPacket, PacketReference, PacketTimestamp, TransportLayer,
    TransportProtocol,
};

/// High-level disposition of DNS processing for a single packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsPacketDisposition {
    /// Packet is not a DNS candidate (not TCP/UDP port 53).
    NotDnsCandidate,
    /// Candidate transport packet (e.g. TCP ACK on port 53) containing zero application payload.
    CandidateWithoutMessage,
    /// Successfully parsed one or more complete DNS observations.
    Parsed,
    /// One or more DNS messages had incomplete framing, truncation, malformed structure, or hit resource limits.
    Partial,
}

/// Result of parsing DNS messages from a single normalized packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacketOutcome {
    /// High-level packet classification.
    pub disposition: DnsPacketDisposition,
    /// Decoded DNS observations (0 or more).
    pub observations: Vec<DnsObservation>,
    /// Bounded diagnostic events collected during parsing.
    pub diagnostics: Vec<DnsDiagnostic>,
}

/// Parses DNS messages from a normalized packet using configured resource limits.
#[must_use]
pub fn parse_dns_packet(packet: &NormalizedPacket, limits: &DnsLimits) -> DnsPacketOutcome {
    let transport = match &packet.transport_layer {
        Some(t) => t,
        None => {
            return DnsPacketOutcome {
                disposition: DnsPacketDisposition::NotDnsCandidate,
                observations: Vec::new(),
                diagnostics: Vec::new(),
            };
        }
    };

    let (proto, src_port, dst_port) = match transport {
        TransportLayer::Udp(udp) => (
            TransportProtocol::Udp,
            udp.source_port,
            udp.destination_port,
        ),
        TransportLayer::Tcp(tcp) => (
            TransportProtocol::Tcp,
            tcp.source_port,
            tcp.destination_port,
        ),
    };

    if src_port != 53 && dst_port != 53 {
        return DnsPacketOutcome {
            disposition: DnsPacketDisposition::NotDnsCandidate,
            observations: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let payload = match &packet.payload {
        Some(p) => p.as_slice(),
        None => &[],
    };

    if payload.is_empty() {
        return DnsPacketOutcome {
            disposition: DnsPacketDisposition::CandidateWithoutMessage,
            observations: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let (source_ip, destination_ip) = match &packet.network_layer {
        Some(net) => (net.source_ip(), net.destination_ip()),
        None => {
            let mut diagnostics = Vec::new();
            if limits.maximum_diagnostics_per_packet > 0 {
                diagnostics.push(DnsDiagnostic {
                    kind: DnsDiagnosticKind::Malformed,
                    message: "missing network layer in normalized packet candidate",
                    offset: 0,
                    message_index: 0,
                });
            }
            return DnsPacketOutcome {
                disposition: DnsPacketDisposition::Partial,
                observations: Vec::new(),
                diagnostics,
            };
        }
    };

    let mut parser = DnsPacketParser {
        packet_ref: packet.reference,
        timestamp: packet.timestamp,
        source_ip,
        source_port: src_port,
        destination_ip,
        destination_port: dst_port,
        limits,
        observations: Vec::new(),
        diagnostics: Vec::new(),
        had_partial: false,
    };

    match proto {
        TransportProtocol::Udp => {
            parser.parse_udp_message(payload);
        }
        TransportProtocol::Tcp => {
            parser.parse_tcp_messages(payload);
        }
    }

    let disposition = if parser.had_partial {
        DnsPacketDisposition::Partial
    } else if parser.observations.is_empty() {
        DnsPacketDisposition::CandidateWithoutMessage
    } else {
        DnsPacketDisposition::Parsed
    };

    DnsPacketOutcome {
        disposition,
        observations: parser.observations,
        diagnostics: parser.diagnostics,
    }
}

struct DnsPacketParser<'a> {
    packet_ref: PacketReference,
    timestamp: PacketTimestamp,
    source_ip: IpAddress,
    source_port: u16,
    destination_ip: IpAddress,
    destination_port: u16,
    limits: &'a DnsLimits,
    observations: Vec<DnsObservation>,
    diagnostics: Vec<DnsDiagnostic>,
    had_partial: bool,
}

impl<'a> DnsPacketParser<'a> {
    fn emit_diagnostic(
        &mut self,
        kind: DnsDiagnosticKind,
        message: &'static str,
        offset: usize,
        message_index: usize,
    ) {
        if self.diagnostics.len() < self.limits.maximum_diagnostics_per_packet {
            self.diagnostics.push(DnsDiagnostic {
                kind,
                message,
                offset,
                message_index,
            });
        }
    }

    fn parse_udp_message(&mut self, payload: &[u8]) {
        let (obs, is_partial) = self.parse_single_dns_message(payload, 0, DnsTransport::Udp);
        if is_partial {
            self.had_partial = true;
        }
        if let Some(o) = obs {
            self.observations.push(o);
        }
    }

    fn parse_tcp_messages(&mut self, payload: &[u8]) {
        let mut offset = 0usize;
        let mut msg_idx = 0usize;

        while offset < payload.len() {
            if msg_idx >= self.limits.maximum_messages_per_packet {
                self.emit_diagnostic(
                    DnsDiagnosticKind::ResourceLimit,
                    "reached maximum DNS messages per packet",
                    offset,
                    msg_idx,
                );
                self.had_partial = true;
                break;
            }

            let remaining = &payload[offset..];
            if remaining.len() < 2 {
                self.emit_diagnostic(
                    DnsDiagnosticKind::Incomplete,
                    "partial DNS/TCP length prefix at end of payload",
                    offset,
                    msg_idx,
                );
                self.had_partial = true;
                break;
            }

            let frame_len = u16::from_be_bytes([remaining[0], remaining[1]]) as usize;
            offset = offset.saturating_add(2);

            if frame_len == 0 {
                self.emit_diagnostic(
                    DnsDiagnosticKind::Incomplete,
                    "zero-length DNS/TCP message frame",
                    offset,
                    msg_idx,
                );
                self.had_partial = true;
                msg_idx = msg_idx.saturating_add(1);
                continue;
            }

            let body_available = payload.len().saturating_sub(offset);
            if body_available < frame_len {
                self.emit_diagnostic(
                    DnsDiagnosticKind::Incomplete,
                    "DNS/TCP message frame truncated (reassembly across packets not supported)",
                    offset,
                    msg_idx,
                );
                self.had_partial = true;
                break;
            }

            let frame_bytes = &payload[offset..offset + frame_len];
            offset = offset.saturating_add(frame_len);

            let (obs, is_partial) =
                self.parse_single_dns_message(frame_bytes, msg_idx, DnsTransport::Tcp);
            if is_partial {
                self.had_partial = true;
            }
            if let Some(o) = obs {
                self.observations.push(o);
            }

            msg_idx = msg_idx.saturating_add(1);
        }
    }

    fn parse_single_dns_message(
        &mut self,
        bytes: &[u8],
        msg_idx: usize,
        transport: DnsTransport,
    ) -> (Option<DnsObservation>, bool) {
        if bytes.len() < 12 {
            self.emit_diagnostic(
                DnsDiagnosticKind::Incomplete,
                "DNS message shorter than 12-byte header",
                0,
                msg_idx,
            );
            return (None, true);
        }

        let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags_raw = u16::from_be_bytes([bytes[2], bytes[3]]);
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);

        let flags = DnsFlags::from_u16(flags_raw);
        let message_kind = if flags.qr {
            DnsMessageKind::Response
        } else {
            DnsMessageKind::Query
        };

        let mut is_partial = false;
        let mut partial_reason = "";

        if qdcount as usize > self.limits.maximum_questions_per_message {
            self.emit_diagnostic(
                DnsDiagnosticKind::ResourceLimit,
                "QDCOUNT exceeds maximum questions limit",
                4,
                msg_idx,
            );
            is_partial = true;
            partial_reason = "QDCOUNT exceeds configured question limit";
        }

        let total_rrs = (ancount as usize)
            .saturating_add(nscount as usize)
            .saturating_add(arcount as usize);
        if total_rrs > self.limits.maximum_resource_records_per_message {
            self.emit_diagnostic(
                DnsDiagnosticKind::ResourceLimit,
                "total RR count exceeds maximum resource records limit",
                6,
                msg_idx,
            );
            is_partial = true;
            partial_reason = "Total RR count exceeds configured resource record limit";
        }

        let mut reader = DnsWireReader::new(bytes, self.limits);
        reader.offset = 12;

        let mut questions = Vec::new();
        if !is_partial {
            for _ in 0..qdcount {
                match reader.parse_question() {
                    Ok(q) => questions.push(q),
                    Err(e) => {
                        self.emit_diagnostic(e.kind, e.message, reader.offset, msg_idx);
                        is_partial = true;
                        partial_reason = e.message;
                        break;
                    }
                }
            }
        }

        let mut records = Vec::new();
        let mut edns = None;

        if !is_partial {
            // ANCOUNT
            for _ in 0..ancount {
                match reader.parse_resource_record(DnsSection::Answer) {
                    Ok(rr) => records.push(rr),
                    Err(e) => {
                        self.emit_diagnostic(e.kind, e.message, reader.offset, msg_idx);
                        is_partial = true;
                        partial_reason = e.message;
                        break;
                    }
                }
            }
        }

        if !is_partial {
            // NSCOUNT
            for _ in 0..nscount {
                match reader.parse_resource_record(DnsSection::Authority) {
                    Ok(rr) => records.push(rr),
                    Err(e) => {
                        self.emit_diagnostic(e.kind, e.message, reader.offset, msg_idx);
                        is_partial = true;
                        partial_reason = e.message;
                        break;
                    }
                }
            }
        }

        if !is_partial {
            // ARCOUNT
            for _ in 0..arcount {
                match reader.parse_resource_record(DnsSection::Additional) {
                    Ok(rr) => {
                        if let DnsRdataMetadata::Opt(ref opt_meta) = rr.rdata {
                            if edns.is_none() {
                                edns = Some(opt_meta.clone());
                            } else {
                                self.emit_diagnostic(
                                    DnsDiagnosticKind::Malformed,
                                    "duplicate EDNS OPT record in message",
                                    reader.offset,
                                    msg_idx,
                                );
                                is_partial = true;
                                partial_reason = "duplicate EDNS OPT record";
                            }
                        }
                        records.push(rr);
                    }
                    Err(e) => {
                        self.emit_diagnostic(e.kind, e.message, reader.offset, msg_idx);
                        is_partial = true;
                        partial_reason = e.message;
                        break;
                    }
                }
            }
        }

        if !is_partial && reader.offset < bytes.len() {
            self.emit_diagnostic(
                DnsDiagnosticKind::Malformed,
                "undeclared trailing bytes after DNS message sections",
                reader.offset,
                msg_idx,
            );
            is_partial = true;
            partial_reason = "undeclared trailing bytes after DNS sections";
        }

        let base_rcode = flags.base_rcode;
        let effective_response_code = if let Some(ref opt) = edns {
            ((opt.extended_rcode as u16) << 4) | (base_rcode as u16)
        } else {
            base_rcode as u16
        };

        let completeness = if is_partial {
            DnsObservationCompleteness::Partial {
                reason: partial_reason,
            }
        } else {
            DnsObservationCompleteness::Complete
        };

        let observation = DnsObservation {
            packet: self.packet_ref,
            timestamp: self.timestamp,
            transport,
            source_ip: self.source_ip,
            source_port: self.source_port,
            destination_ip: self.destination_ip,
            destination_port: self.destination_port,
            transaction_id,
            message_kind,
            opcode: flags.opcode,
            response_code: base_rcode,
            effective_response_code,
            flags,
            declared_qdcount: qdcount,
            declared_ancount: ancount,
            declared_nscount: nscount,
            declared_arcount: arcount,
            questions,
            records,
            edns,
            completeness,
        };

        (Some(observation), is_partial)
    }
}

struct DnsParseError {
    kind: DnsDiagnosticKind,
    message: &'static str,
}

impl DnsParseError {
    const fn new(kind: DnsDiagnosticKind, message: &'static str) -> Self {
        Self { kind, message }
    }
}

struct DnsRrContext<'a> {
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlength: u16,
    rdata_start: usize,
    section: DnsSection,
    owner_name: &'a DnsName,
}

struct DnsWireReader<'a> {
    data: &'a [u8],
    offset: usize,
    limits: &'a DnsLimits,
    retained_name_bytes: usize,
}

impl<'a> DnsWireReader<'a> {
    fn new(data: &'a [u8], limits: &'a DnsLimits) -> Self {
        Self {
            data,
            offset: 0,
            limits,
            retained_name_bytes: 0,
        }
    }

    fn read_u16(&mut self) -> Result<u16, DnsParseError> {
        if self.offset.saturating_add(2) <= self.data.len() {
            let b0 = self.data[self.offset];
            let b1 = self.data[self.offset + 1];
            self.offset = self.offset.saturating_add(2);
            Ok(u16::from_be_bytes([b0, b1]))
        } else {
            Err(DnsParseError::new(
                DnsDiagnosticKind::Incomplete,
                "unexpected end of DNS message while reading 16-bit integer",
            ))
        }
    }

    fn read_u32(&mut self) -> Result<u32, DnsParseError> {
        if self.offset.saturating_add(4) <= self.data.len() {
            let b = [
                self.data[self.offset],
                self.data[self.offset + 1],
                self.data[self.offset + 2],
                self.data[self.offset + 3],
            ];
            self.offset = self.offset.saturating_add(4);
            Ok(u32::from_be_bytes(b))
        } else {
            Err(DnsParseError::new(
                DnsDiagnosticKind::Incomplete,
                "unexpected end of DNS message while reading 32-bit integer",
            ))
        }
    }

    /// Parses a DNS domain name from the current offset, handling compression pointers.
    fn parse_name(&mut self) -> Result<DnsName, DnsParseError> {
        let mut labels = Vec::new();
        let mut hops = 0usize;
        let mut curr_offset = self.offset;
        let mut advanced_reader = false;
        let mut wire_len = 1usize; // terminating root byte

        loop {
            if curr_offset >= self.data.len() {
                return Err(DnsParseError::new(
                    DnsDiagnosticKind::Incomplete,
                    "truncated DNS name",
                ));
            }

            let len_byte = self.data[curr_offset];

            // Root label (0x00)
            if len_byte == 0 {
                if !advanced_reader {
                    self.offset = curr_offset.saturating_add(1);
                }
                break;
            }

            // Compression pointer (11xxxxxx)
            if (len_byte & 0xC0) == 0xC0 {
                if curr_offset.saturating_add(2) > self.data.len() {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Incomplete,
                        "truncated compression pointer",
                    ));
                }

                let ptr_bytes = [self.data[curr_offset], self.data[curr_offset + 1]];
                let target = (u16::from_be_bytes(ptr_bytes) & 0x3FFF) as usize;

                if !advanced_reader {
                    self.offset = curr_offset.saturating_add(2);
                    advanced_reader = true;
                }

                hops = hops.saturating_add(1);
                if hops > self.limits.maximum_name_pointer_hops {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::ResourceLimit,
                        "exceeded maximum name compression pointer hops",
                    ));
                }

                // Backward-pointer policy: target must be strictly less than current pointer location
                if target >= curr_offset {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "compression pointer does not point strictly backward",
                    ));
                }

                curr_offset = target;
                continue;
            }

            // Reserved label prefix (01xxxxxx or 10xxxxxx)
            if (len_byte & 0xC0) != 0 {
                return Err(DnsParseError::new(
                    DnsDiagnosticKind::Unsupported,
                    "unsupported extended label type (01/10 prefix)",
                ));
            }

            // Ordinary label (00xxxxxx)
            let label_len = (len_byte & 0x3F) as usize;
            if label_len > MAX_DNS_LABEL_LENGTH {
                return Err(DnsParseError::new(
                    DnsDiagnosticKind::Malformed,
                    "DNS label exceeds 63 octets",
                ));
            }

            let start = curr_offset.saturating_add(1);
            let end = start.saturating_add(label_len);
            if end > self.data.len() {
                return Err(DnsParseError::new(
                    DnsDiagnosticKind::Incomplete,
                    "truncated DNS label data",
                ));
            }

            let label = self.data[start..end].to_vec();
            wire_len = wire_len
                .checked_add(1)
                .and_then(|l| l.checked_add(label_len))
                .ok_or_else(|| {
                    DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "DNS expanded name wire length overflow",
                    )
                })?;

            if wire_len > MAX_DNS_NAME_WIRE_LENGTH {
                return Err(DnsParseError::new(
                    DnsDiagnosticKind::Malformed,
                    "expanded DNS name exceeds 255 octets",
                ));
            }

            self.retained_name_bytes = self.retained_name_bytes.saturating_add(label_len);
            if self.retained_name_bytes > self.limits.maximum_total_retained_name_bytes_per_message
            {
                return Err(DnsParseError::new(
                    DnsDiagnosticKind::ResourceLimit,
                    "exceeded total retained name bytes limit for message",
                ));
            }

            labels.push(label);
            curr_offset = end;

            if !advanced_reader {
                self.offset = curr_offset;
            }
        }

        DnsName::from_labels(labels).ok_or_else(|| {
            DnsParseError::new(
                DnsDiagnosticKind::Malformed,
                "invalid constructed domain name",
            )
        })
    }

    fn parse_question(&mut self) -> Result<DnsQuestion, DnsParseError> {
        let name = self.parse_name()?;
        let qtype = self.read_u16()?;
        let qclass = self.read_u16()?;
        Ok(DnsQuestion::new(name, qtype, qclass))
    }

    fn parse_resource_record(
        &mut self,
        section: DnsSection,
    ) -> Result<DnsResourceRecord, DnsParseError> {
        let name = self.parse_name()?;
        let rtype = self.read_u16()?;
        let rclass = self.read_u16()?;
        let ttl = self.read_u32()?;
        let rdlength = self.read_u16()?;

        let rdata_start = self.offset;
        let rdata_end = rdata_start.checked_add(rdlength as usize).ok_or_else(|| {
            DnsParseError::new(DnsDiagnosticKind::Malformed, "RDATA length overflow")
        })?;

        if rdata_end > self.data.len() {
            return Err(DnsParseError::new(
                DnsDiagnosticKind::Incomplete,
                "RDATA length exceeds message boundary",
            ));
        }

        let ctx = DnsRrContext {
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata_start,
            section,
            owner_name: &name,
        };
        let rdata = self.decode_rdata(&ctx)?;

        // Ensure reader is positioned exactly after RDATA
        self.offset = rdata_end;

        Ok(DnsResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata,
            section,
        })
    }

    fn decode_rdata(&mut self, ctx: &DnsRrContext<'_>) -> Result<DnsRdataMetadata, DnsParseError> {
        match ctx.rtype {
            // A (1) - IPv4
            1 => {
                if ctx.rdlength != 4 {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "invalid RDLENGTH for A record (must be 4)",
                    ));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&self.data[ctx.rdata_start..ctx.rdata_start + 4]);
                Ok(DnsRdataMetadata::A(ip))
            }
            // AAAA (28) - IPv6
            28 => {
                if ctx.rdlength != 16 {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "invalid RDLENGTH for AAAA record (must be 16)",
                    ));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&self.data[ctx.rdata_start..ctx.rdata_start + 16]);
                Ok(DnsRdataMetadata::Aaaa(ip))
            }
            // NS (2)
            2 => {
                let name = self.parse_name()?;
                if self.offset != ctx.rdata_start + ctx.rdlength as usize {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "NS domain name did not consume exact RDLENGTH bytes",
                    ));
                }
                Ok(DnsRdataMetadata::Ns(name))
            }
            // CNAME (5)
            5 => {
                let name = self.parse_name()?;
                if self.offset != ctx.rdata_start + ctx.rdlength as usize {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "CNAME domain name did not consume exact RDLENGTH bytes",
                    ));
                }
                Ok(DnsRdataMetadata::Cname(name))
            }
            // PTR (12)
            12 => {
                let name = self.parse_name()?;
                if self.offset != ctx.rdata_start + ctx.rdlength as usize {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "PTR domain name did not consume exact RDLENGTH bytes",
                    ));
                }
                Ok(DnsRdataMetadata::Ptr(name))
            }
            // MX (15)
            15 => {
                if ctx.rdlength < 2 {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "MX record RDLENGTH shorter than 2-byte preference",
                    ));
                }
                let preference = self.read_u16()?;
                let exchange = self.parse_name()?;
                if self.offset != ctx.rdata_start + ctx.rdlength as usize {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "MX preference and exchange name did not consume exact RDLENGTH bytes",
                    ));
                }
                Ok(DnsRdataMetadata::Mx {
                    preference,
                    exchange,
                })
            }
            // OPT (41) - EDNS(0)
            41 => {
                if !ctx.owner_name.is_root() {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "OPT record owner name must be root (.)",
                    ));
                }
                if !matches!(ctx.section, DnsSection::Additional) {
                    return Err(DnsParseError::new(
                        DnsDiagnosticKind::Malformed,
                        "OPT record must only appear in Additional section",
                    ));
                }
                let udp_payload_size = ctx.rclass;
                let extended_rcode = (ctx.ttl >> 24) as u8;
                let version = ((ctx.ttl >> 16) & 0xFF) as u8;
                let dnssec_ok = (ctx.ttl & 0x8000) != 0;
                let z = (ctx.ttl & 0x7FFF) as u16;

                let mut opt_offset = ctx.rdata_start;
                let opt_end = ctx.rdata_start + ctx.rdlength as usize;
                let mut options = Vec::new();

                while opt_offset < opt_end {
                    if options.len() >= self.limits.maximum_edns_options_per_message {
                        return Err(DnsParseError::new(
                            DnsDiagnosticKind::ResourceLimit,
                            "exceeded maximum EDNS options per message",
                        ));
                    }
                    if opt_offset.saturating_add(4) > opt_end {
                        return Err(DnsParseError::new(
                            DnsDiagnosticKind::Incomplete,
                            "truncated EDNS option header",
                        ));
                    }
                    let code =
                        u16::from_be_bytes([self.data[opt_offset], self.data[opt_offset + 1]]);
                    let length =
                        u16::from_be_bytes([self.data[opt_offset + 2], self.data[opt_offset + 3]]);
                    opt_offset = opt_offset.saturating_add(4);

                    if opt_offset.saturating_add(length as usize) > opt_end {
                        return Err(DnsParseError::new(
                            DnsDiagnosticKind::Incomplete,
                            "EDNS option length exceeds OPT RDATA boundary",
                        ));
                    }
                    opt_offset = opt_offset.saturating_add(length as usize);
                    options.push(DnsEdnsOptionMetadata { code, length });
                }

                Ok(DnsRdataMetadata::Opt(DnsEdnsMetadata {
                    udp_payload_size,
                    extended_rcode,
                    version,
                    dnssec_ok,
                    z,
                    options,
                }))
            }
            _ => Ok(DnsRdataMetadata::Unknown {
                rtype: ctx.rtype,
                rdlength: ctx.rdlength,
            }),
        }
    }
}
