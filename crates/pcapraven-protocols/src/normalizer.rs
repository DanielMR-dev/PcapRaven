//! Bounded Ethernet, IPv4, IPv6, TCP, and UDP packet normalization.

use crate::limits::NormalizationLimits;
use etherparse::{
    Ethernet2HeaderSlice, Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice, UdpHeaderSlice,
};
use pcapraven_domain::{
    EthernetMetadata, FragmentationState, Ipv4Metadata, Ipv6Metadata, MacAddress, NetworkLayer,
    NormalizationDiagnostic, NormalizationDiagnosticKind, NormalizationDiagnosticLayer,
    NormalizedPacket, PacketCompleteness, PacketNormalizationInput, PacketNormalizationOutcome,
    PacketTruncationReason, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
    UnsupportedLayerReason,
};

/// Normalizes a single captured packet into capture-independent domain facts.
///
/// Normalization parses only the documented subset:
/// - LINKTYPE_ETHERNET = 1
/// - Standard Ethernet II headers
/// - IPv4 with header/total length validation, fragmentation classification, and Ethernet padding exclusion
/// - IPv6 with bounded extension header traversal, fragmentation classification, and padding exclusion
/// - TCP headers with flags, options length, checksum, and bounded application payload
/// - UDP headers with declared length bounds, checksum, and bounded application payload
///
/// Malformed, unsupported, incomplete, or truncated packets produce explicit factual
/// state and bounded diagnostics without panicking or guessing.
#[must_use]
pub fn normalize_packet(
    input: &PacketNormalizationInput<'_>,
    limits: &NormalizationLimits,
) -> PacketNormalizationOutcome {
    let mut collector = DiagnosticCollector::new(limits.maximum_diagnostics_per_packet);

    // 1. Link Layer Validation (only LINKTYPE_ETHERNET = 1 is supported)
    if input.linktype != 1 {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Unsupported,
            NormalizationDiagnosticLayer::Link,
            "capture link type is unsupported; only Ethernet (linktype 1) is supported",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: None,
            network_layer: None,
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Unsupported {
                reason: UnsupportedLayerReason::LinkType(input.linktype),
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.into_vec());
    }

    // 2. Ethernet II Header Normalization
    if input.data.len() < 14 {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Link,
            "captured bytes ended before Ethernet II header was complete",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: None,
            network_layer: None,
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::HeaderTruncation,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.into_vec());
    }

    let eth_slice = match Ethernet2HeaderSlice::from_slice(input.data) {
        Ok(slice) => slice,
        Err(_) => {
            collector.push(NormalizationDiagnostic::new(
                NormalizationDiagnosticKind::Malformed,
                NormalizationDiagnosticLayer::Link,
                "Ethernet II header is malformed",
            ));
            let packet = NormalizedPacket {
                reference: input.reference,
                timestamp: input.timestamp,
                link_layer: None,
                network_layer: None,
                transport_layer: None,
                payload: None,
                completeness: PacketCompleteness::Partial {
                    reason: PacketTruncationReason::HeaderTruncation,
                },
            };
            return PacketNormalizationOutcome::new(packet, collector.into_vec());
        }
    };

    let ethertype = eth_slice.ether_type().0;
    let link_layer = EthernetMetadata {
        source: MacAddress::new(eth_slice.source()),
        destination: MacAddress::new(eth_slice.destination()),
        ethertype,
        link_header_length: 14,
    };

    // Check for IEEE 802.3 length field (<= 1500)
    if ethertype <= 1500 {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Unsupported,
            NormalizationDiagnosticLayer::Link,
            "IEEE 802.3 length framing is unsupported",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: None,
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Unsupported {
                reason: UnsupportedLayerReason::EtherType(ethertype),
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.into_vec());
    }

    // Supported network layer EtherTypes: 0x0800 (IPv4) and 0x86DD (IPv6)
    if ethertype != 0x0800 && ethertype != 0x86dd {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Unsupported,
            NormalizationDiagnosticLayer::Network,
            "network layer EtherType is unsupported",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: None,
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Unsupported {
                reason: UnsupportedLayerReason::EtherType(ethertype),
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.into_vec());
    }

    let ip_data = &input.data[14..];

    // 3. IPv4 or IPv6 Normalization
    if ethertype == 0x0800 {
        normalize_ipv4(input, link_layer, ip_data, limits, &mut collector)
    } else {
        normalize_ipv6(input, link_layer, ip_data, limits, &mut collector)
    }
}

fn normalize_ipv4(
    input: &PacketNormalizationInput<'_>,
    link_layer: EthernetMetadata,
    ip_data: &[u8],
    limits: &NormalizationLimits,
    collector: &mut DiagnosticCollector,
) -> PacketNormalizationOutcome {
    if ip_data.is_empty() {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Network,
            "captured bytes ended before IPv4 header was available",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: None,
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::HeaderTruncation,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    let ip_slice = match Ipv4HeaderSlice::from_slice(ip_data) {
        Ok(slice) => slice,
        Err(_) => {
            if ip_data.len() < 20 {
                collector.push(NormalizationDiagnostic::new(
                    NormalizationDiagnosticKind::Incomplete,
                    NormalizationDiagnosticLayer::Network,
                    "captured bytes ended before minimum 20-byte IPv4 header was complete",
                ));
            } else {
                collector.push(NormalizationDiagnostic::new(
                    NormalizationDiagnosticKind::Malformed,
                    NormalizationDiagnosticLayer::Network,
                    "IPv4 header structure or declared lengths are malformed",
                ));
            }
            let packet = NormalizedPacket {
                reference: input.reference,
                timestamp: input.timestamp,
                link_layer: Some(link_layer),
                network_layer: None,
                transport_layer: None,
                payload: None,
                completeness: PacketCompleteness::Partial {
                    reason: if ip_data.len() < 20 {
                        PacketTruncationReason::HeaderTruncation
                    } else {
                        PacketTruncationReason::DeclaredLengthMismatch
                    },
                },
            };
            return PacketNormalizationOutcome::new(packet, collector.take_vec());
        }
    };

    let header_length = ip_slice.ihl() * 4;
    let total_length = ip_slice.total_len();
    let dscp = ip_slice.slice()[1] >> 2;
    let ecn = ip_slice.slice()[1] & 0x03;
    let identification = ip_slice.identification();
    let ttl = ip_slice.ttl();
    let protocol = ip_slice.protocol().0;
    let source = ip_slice.source();
    let destination = ip_slice.destination();
    let frag_offset = ip_slice.fragments_offset().value();
    let more_fragments = ip_slice.more_fragments();

    let fragmentation = if frag_offset > 0 || more_fragments {
        FragmentationState::Fragmented {
            offset: frag_offset,
            more_fragments,
            identification: Some(u32::from(identification)),
        }
    } else {
        FragmentationState::NotFragmented
    };

    let ipv4_meta = Ipv4Metadata {
        version: 4,
        header_length,
        dscp,
        ecn,
        total_length,
        identification,
        ttl,
        protocol,
        source,
        destination,
        fragmentation,
    };
    let network_layer = NetworkLayer::Ipv4(ipv4_meta);

    // Validate total_length >= header_length
    if total_length < u16::from(header_length) {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Malformed,
            NormalizationDiagnosticLayer::Network,
            "IPv4 total length is smaller than header length",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: Some(network_layer),
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::DeclaredLengthMismatch,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    let mut is_capture_truncated = false;
    let transport_data = if ip_data.len() < usize::from(total_length) {
        is_capture_truncated = true;
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Network,
            "captured packet contains fewer bytes than IPv4 total length declares",
        ));
        // Available payload bytes up to captured length
        if ip_data.len() > usize::from(header_length) {
            &ip_data[usize::from(header_length)..]
        } else {
            &[]
        }
    } else {
        // Exclude trailing Ethernet padding by bounding strictly to total_length
        &ip_data[usize::from(header_length)..usize::from(total_length)]
    };

    // If fragmented, transport interpretation is unsafe without reassembly
    if fragmentation.is_fragmented() {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Unsupported,
            NormalizationDiagnosticLayer::Transport,
            "transport layer normalization omitted for fragmented packet requiring reassembly",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: Some(network_layer),
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::Fragmented,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    normalize_transport(
        input,
        link_layer,
        network_layer,
        protocol,
        transport_data,
        is_capture_truncated,
        limits,
        collector,
    )
}

fn normalize_ipv6(
    input: &PacketNormalizationInput<'_>,
    link_layer: EthernetMetadata,
    ip_data: &[u8],
    limits: &NormalizationLimits,
    collector: &mut DiagnosticCollector,
) -> PacketNormalizationOutcome {
    if ip_data.len() < 40 {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Network,
            "captured bytes ended before 40-byte IPv6 header was complete",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: None,
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::HeaderTruncation,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    let ipv6_slice = match Ipv6HeaderSlice::from_slice(ip_data) {
        Ok(slice) => slice,
        Err(_) => {
            collector.push(NormalizationDiagnostic::new(
                NormalizationDiagnosticKind::Malformed,
                NormalizationDiagnosticLayer::Network,
                "IPv6 header is malformed",
            ));
            let packet = NormalizedPacket {
                reference: input.reference,
                timestamp: input.timestamp,
                link_layer: Some(link_layer),
                network_layer: None,
                transport_layer: None,
                payload: None,
                completeness: PacketCompleteness::Partial {
                    reason: PacketTruncationReason::DeclaredLengthMismatch,
                },
            };
            return PacketNormalizationOutcome::new(packet, collector.take_vec());
        }
    };

    let traffic_class = ipv6_slice.traffic_class();
    let flow_label = ipv6_slice.flow_label().value();
    let payload_length = ipv6_slice.payload_length();
    let next_header = ipv6_slice.next_header().0;
    let hop_limit = ipv6_slice.hop_limit();
    let source = ipv6_slice.source();
    let destination = ipv6_slice.destination();

    let full_ipv6_payload = &ip_data[40..];
    let mut is_capture_truncated = false;
    let ipv6_payload = if full_ipv6_payload.len() < usize::from(payload_length) {
        is_capture_truncated = true;
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Network,
            "captured packet contains fewer bytes than IPv6 payload length declares",
        ));
        full_ipv6_payload
    } else {
        // Exclude Ethernet padding by bounding strictly to payload_length
        &full_ipv6_payload[..usize::from(payload_length)]
    };

    // Traverse IPv6 extension headers
    let (effective_protocol, ext_count, ext_len, fragmentation, transport_slice, ext_error) =
        traverse_ipv6_extensions(next_header, ipv6_payload, limits, collector);

    let ipv6_meta = Ipv6Metadata {
        version: 6,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
        extension_headers_count: ext_count,
        extension_headers_length: ext_len,
        effective_protocol,
        fragmentation,
    };
    let network_layer = NetworkLayer::Ipv6(ipv6_meta);

    if let Some(err) = ext_error {
        let completeness = match err {
            ExtError::ResourceLimit => PacketCompleteness::Partial {
                reason: PacketTruncationReason::PayloadBudgetExceeded,
            },
            ExtError::Unsupported(ext) => PacketCompleteness::Unsupported {
                reason: UnsupportedLayerReason::Ipv6Extension(ext),
            },
            ExtError::Malformed => PacketCompleteness::Partial {
                reason: PacketTruncationReason::DeclaredLengthMismatch,
            },
            ExtError::Fragmented => PacketCompleteness::Partial {
                reason: PacketTruncationReason::Fragmented,
            },
        };
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: Some(network_layer),
            transport_layer: None,
            payload: None,
            completeness,
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    normalize_transport(
        input,
        link_layer,
        network_layer,
        effective_protocol,
        transport_slice,
        is_capture_truncated,
        limits,
        collector,
    )
}

enum ExtError {
    ResourceLimit,
    Unsupported(u8),
    Malformed,
    Fragmented,
}

fn traverse_ipv6_extensions<'a>(
    initial_next_header: u8,
    payload: &'a [u8],
    limits: &NormalizationLimits,
    collector: &mut DiagnosticCollector,
) -> (u8, u8, u16, FragmentationState, &'a [u8], Option<ExtError>) {
    let mut current_protocol = initial_next_header;
    let mut current_slice = payload;
    let mut ext_count = 0u8;
    let mut ext_len = 0usize;
    let mut fragmentation = FragmentationState::NotFragmented;

    loop {
        if !is_ipv6_extension_header(current_protocol) {
            break;
        }

        if ext_count >= limits.maximum_ipv6_extension_headers {
            collector.push(NormalizationDiagnostic::new(
                NormalizationDiagnosticKind::ResourceLimit,
                NormalizationDiagnosticLayer::Ipv6Extension,
                "IPv6 extension header count limit exceeded",
            ));
            return (
                current_protocol,
                ext_count,
                ext_len as u16,
                fragmentation,
                current_slice,
                Some(ExtError::ResourceLimit),
            );
        }

        // Parse extension header boundaries safely
        match current_protocol {
            0 | 43 | 60 | 135 | 139 | 140 => {
                // HopByHop (0), Routing (43), Destination Options (60), Mobility (135), HIP (139), Shim6 (140)
                // RFC 8200: Length is (Hdr Ext Len + 1) * 8 octets. Minimum 8 octets.
                if current_slice.len() < 8 {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::Incomplete,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "captured bytes ended before IPv6 extension header was complete",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::Malformed),
                    );
                }
                let next_proto = current_slice[0];
                let hdr_len = usize::from(current_slice[1])
                    .checked_add(1)
                    .and_then(|v| v.checked_mul(8))
                    .unwrap_or(usize::MAX);
                if current_slice.len() < hdr_len {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::Incomplete,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "captured bytes ended before IPv6 extension header payload was complete",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::Malformed),
                    );
                }
                ext_count = ext_count.saturating_add(1);
                ext_len = ext_len.saturating_add(hdr_len);
                if ext_len > limits.maximum_ipv6_extension_bytes {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::ResourceLimit,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "IPv6 extension header byte budget exceeded",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::ResourceLimit),
                    );
                }
                current_protocol = next_proto;
                current_slice = &current_slice[hdr_len..];
            }
            44 => {
                // Fragment header (RFC 8200): Fixed 8 octets.
                if current_slice.len() < 8 {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::Incomplete,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "captured bytes ended before IPv6 Fragment header was complete",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::Malformed),
                    );
                }
                let next_proto = current_slice[0];
                let frag_raw = u16::from_be_bytes([current_slice[2], current_slice[3]]);
                let offset = frag_raw >> 3;
                let more = (frag_raw & 0x0001) != 0;
                let id = u32::from_be_bytes([
                    current_slice[4],
                    current_slice[5],
                    current_slice[6],
                    current_slice[7],
                ]);
                fragmentation = FragmentationState::Fragmented {
                    offset,
                    more_fragments: more,
                    identification: Some(id),
                };
                ext_count = ext_count.saturating_add(1);
                ext_len = ext_len.saturating_add(8);
                if ext_len > limits.maximum_ipv6_extension_bytes {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::ResourceLimit,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "IPv6 extension header byte budget exceeded",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::ResourceLimit),
                    );
                }
                if offset > 0 || more {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::Unsupported,
                        NormalizationDiagnosticLayer::Transport,
                        "transport layer normalization omitted for fragmented packet requiring reassembly",
                    ));
                    return (
                        next_proto,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        &current_slice[8..],
                        Some(ExtError::Fragmented),
                    );
                }
                current_protocol = next_proto;
                current_slice = &current_slice[8..];
            }
            51 => {
                // Authentication Header (RFC 4302): Length is (Payload Len + 2) * 4 octets. Minimum 8 octets.
                if current_slice.len() < 8 {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::Incomplete,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "captured bytes ended before IPv6 Authentication Header was complete",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::Malformed),
                    );
                }
                let next_proto = current_slice[0];
                let hdr_len = usize::from(current_slice[1])
                    .checked_add(2)
                    .and_then(|v| v.checked_mul(4))
                    .unwrap_or(usize::MAX);
                if current_slice.len() < hdr_len {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::Incomplete,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "captured bytes ended before IPv6 Authentication Header payload was complete",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::Malformed),
                    );
                }
                ext_count = ext_count.saturating_add(1);
                ext_len = ext_len.saturating_add(hdr_len);
                if ext_len > limits.maximum_ipv6_extension_bytes {
                    collector.push(NormalizationDiagnostic::new(
                        NormalizationDiagnosticKind::ResourceLimit,
                        NormalizationDiagnosticLayer::Ipv6Extension,
                        "IPv6 extension header byte budget exceeded",
                    ));
                    return (
                        current_protocol,
                        ext_count,
                        ext_len as u16,
                        fragmentation,
                        current_slice,
                        Some(ExtError::ResourceLimit),
                    );
                }
                current_protocol = next_proto;
                current_slice = &current_slice[hdr_len..];
            }
            other => {
                collector.push(NormalizationDiagnostic::new(
                    NormalizationDiagnosticKind::Unsupported,
                    NormalizationDiagnosticLayer::Ipv6Extension,
                    "unsupported IPv6 extension header",
                ));
                return (
                    other,
                    ext_count,
                    ext_len as u16,
                    fragmentation,
                    current_slice,
                    Some(ExtError::Unsupported(other)),
                );
            }
        }
    }

    (
        current_protocol,
        ext_count,
        ext_len as u16,
        fragmentation,
        current_slice,
        None,
    )
}

const fn is_ipv6_extension_header(protocol: u8) -> bool {
    matches!(
        protocol,
        0   // HopByHop
        | 43  // Routing
        | 44  // Fragment
        | 51  // Authentication Header
        | 60  // Destination Options
        | 135 // Mobility
        | 139 // Host Identity Protocol
        | 140 // Shim6
    )
}

#[allow(clippy::too_many_arguments)]
fn normalize_transport(
    input: &PacketNormalizationInput<'_>,
    link_layer: EthernetMetadata,
    network_layer: NetworkLayer,
    protocol: u8,
    transport_data: &[u8],
    is_capture_truncated: bool,
    limits: &NormalizationLimits,
    collector: &mut DiagnosticCollector,
) -> PacketNormalizationOutcome {
    match protocol {
        6 => normalize_tcp(
            input,
            link_layer,
            network_layer,
            transport_data,
            is_capture_truncated,
            limits,
            collector,
        ),
        17 => normalize_udp(
            input,
            link_layer,
            network_layer,
            transport_data,
            is_capture_truncated,
            limits,
            collector,
        ),
        other => {
            collector.push(NormalizationDiagnostic::new(
                NormalizationDiagnosticKind::Unsupported,
                NormalizationDiagnosticLayer::Transport,
                "transport layer protocol is unsupported",
            ));
            let packet = NormalizedPacket {
                reference: input.reference,
                timestamp: input.timestamp,
                link_layer: Some(link_layer),
                network_layer: Some(network_layer),
                transport_layer: None,
                payload: None,
                completeness: PacketCompleteness::Unsupported {
                    reason: UnsupportedLayerReason::NetworkProtocol(other),
                },
            };
            PacketNormalizationOutcome::new(packet, collector.take_vec())
        }
    }
}

fn normalize_tcp(
    input: &PacketNormalizationInput<'_>,
    link_layer: EthernetMetadata,
    network_layer: NetworkLayer,
    transport_data: &[u8],
    is_capture_truncated: bool,
    limits: &NormalizationLimits,
    collector: &mut DiagnosticCollector,
) -> PacketNormalizationOutcome {
    if transport_data.len() < 20 {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Transport,
            "captured bytes ended before minimum 20-byte TCP header was complete",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: Some(network_layer),
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::HeaderTruncation,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    let tcp_slice = match TcpHeaderSlice::from_slice(transport_data) {
        Ok(slice) => slice,
        Err(_) => {
            collector.push(NormalizationDiagnostic::new(
                NormalizationDiagnosticKind::Malformed,
                NormalizationDiagnosticLayer::Transport,
                "TCP header structure or data offset is malformed",
            ));
            let packet = NormalizedPacket {
                reference: input.reference,
                timestamp: input.timestamp,
                link_layer: Some(link_layer),
                network_layer: Some(network_layer),
                transport_layer: None,
                payload: None,
                completeness: PacketCompleteness::Partial {
                    reason: PacketTruncationReason::DeclaredLengthMismatch,
                },
            };
            return PacketNormalizationOutcome::new(packet, collector.take_vec());
        }
    };

    let data_offset_bytes = tcp_slice.data_offset() * 4;
    if transport_data.len() < usize::from(data_offset_bytes) {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Transport,
            "captured bytes ended before TCP options/header was complete",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: Some(network_layer),
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::HeaderTruncation,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    let flags = TcpFlags {
        ns: tcp_slice.ns(),
        cwr: tcp_slice.cwr(),
        ece: tcp_slice.ece(),
        urg: tcp_slice.urg(),
        ack: tcp_slice.ack(),
        psh: tcp_slice.psh(),
        rst: tcp_slice.rst(),
        syn: tcp_slice.syn(),
        fin: tcp_slice.fin(),
    };

    let tcp_meta = TcpMetadata {
        source_port: tcp_slice.source_port(),
        destination_port: tcp_slice.destination_port(),
        sequence_number: tcp_slice.sequence_number(),
        acknowledgement_number: tcp_slice.acknowledgment_number(),
        data_offset_bytes,
        flags,
        window_size: tcp_slice.window_size(),
        checksum: tcp_slice.checksum(),
        urgent_pointer: tcp_slice.urgent_pointer(),
        options_length_bytes: data_offset_bytes.saturating_sub(20),
    };
    let transport_layer = TransportLayer::Tcp(tcp_meta);

    let raw_payload = &transport_data[usize::from(data_offset_bytes)..];
    let (payload, payload_truncated) = if raw_payload.len() > limits.maximum_retained_payload_bytes
    {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::ResourceLimit,
            NormalizationDiagnosticLayer::Payload,
            "application payload truncated to configured payload retention limit",
        ));
        (
            Some(raw_payload[..limits.maximum_retained_payload_bytes].to_vec()),
            true,
        )
    } else if raw_payload.is_empty() {
        (None, false)
    } else {
        (Some(raw_payload.to_vec()), false)
    };

    let completeness = if is_capture_truncated {
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::CaptureTruncation,
        }
    } else if payload_truncated {
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::PayloadBudgetExceeded,
        }
    } else {
        PacketCompleteness::Complete
    };

    let packet = NormalizedPacket {
        reference: input.reference,
        timestamp: input.timestamp,
        link_layer: Some(link_layer),
        network_layer: Some(network_layer),
        transport_layer: Some(transport_layer),
        payload,
        completeness,
    };
    PacketNormalizationOutcome::new(packet, collector.take_vec())
}

fn normalize_udp(
    input: &PacketNormalizationInput<'_>,
    link_layer: EthernetMetadata,
    network_layer: NetworkLayer,
    transport_data: &[u8],
    is_capture_truncated: bool,
    limits: &NormalizationLimits,
    collector: &mut DiagnosticCollector,
) -> PacketNormalizationOutcome {
    if transport_data.len() < 8 {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Transport,
            "captured bytes ended before 8-byte UDP header was complete",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: Some(network_layer),
            transport_layer: None,
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::HeaderTruncation,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    let udp_slice = match UdpHeaderSlice::from_slice(transport_data) {
        Ok(slice) => slice,
        Err(_) => {
            collector.push(NormalizationDiagnostic::new(
                NormalizationDiagnosticKind::Malformed,
                NormalizationDiagnosticLayer::Transport,
                "UDP header is malformed",
            ));
            let packet = NormalizedPacket {
                reference: input.reference,
                timestamp: input.timestamp,
                link_layer: Some(link_layer),
                network_layer: Some(network_layer),
                transport_layer: None,
                payload: None,
                completeness: PacketCompleteness::Partial {
                    reason: PacketTruncationReason::DeclaredLengthMismatch,
                },
            };
            return PacketNormalizationOutcome::new(packet, collector.take_vec());
        }
    };

    let length = udp_slice.length();
    let checksum = udp_slice.checksum();
    let udp_meta = UdpMetadata {
        source_port: udp_slice.source_port(),
        destination_port: udp_slice.destination_port(),
        length,
        checksum,
    };
    let transport_layer = TransportLayer::Udp(udp_meta);

    if length < 8 {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Malformed,
            NormalizationDiagnosticLayer::Transport,
            "UDP declared length is less than 8-byte header",
        ));
        let packet = NormalizedPacket {
            reference: input.reference,
            timestamp: input.timestamp,
            link_layer: Some(link_layer),
            network_layer: Some(network_layer),
            transport_layer: Some(transport_layer),
            payload: None,
            completeness: PacketCompleteness::Partial {
                reason: PacketTruncationReason::DeclaredLengthMismatch,
            },
        };
        return PacketNormalizationOutcome::new(packet, collector.take_vec());
    }

    let declared_payload_len = usize::from(length.saturating_sub(8));
    let available_udp_payload = &transport_data[8..];

    let (raw_payload, udp_truncated) = if available_udp_payload.len() < declared_payload_len {
        collector.push(NormalizationDiagnostic::new(
            NormalizationDiagnosticKind::Incomplete,
            NormalizationDiagnosticLayer::Transport,
            "captured packet contains fewer bytes than UDP length declares",
        ));
        (available_udp_payload, true)
    } else {
        // Strictly exclude excess padding bytes beyond declared UDP length
        (&available_udp_payload[..declared_payload_len], false)
    };

    let (payload, payload_budget_truncated) =
        if raw_payload.len() > limits.maximum_retained_payload_bytes {
            collector.push(NormalizationDiagnostic::new(
                NormalizationDiagnosticKind::ResourceLimit,
                NormalizationDiagnosticLayer::Payload,
                "application payload truncated to configured payload retention limit",
            ));
            (
                Some(raw_payload[..limits.maximum_retained_payload_bytes].to_vec()),
                true,
            )
        } else if raw_payload.is_empty() {
            (None, false)
        } else {
            (Some(raw_payload.to_vec()), false)
        };

    let completeness = if is_capture_truncated || udp_truncated {
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::CaptureTruncation,
        }
    } else if payload_budget_truncated {
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::PayloadBudgetExceeded,
        }
    } else {
        PacketCompleteness::Complete
    };

    let packet = NormalizedPacket {
        reference: input.reference,
        timestamp: input.timestamp,
        link_layer: Some(link_layer),
        network_layer: Some(network_layer),
        transport_layer: Some(transport_layer),
        payload,
        completeness,
    };
    PacketNormalizationOutcome::new(packet, collector.take_vec())
}

struct DiagnosticCollector {
    diagnostics: Vec<NormalizationDiagnostic>,
    capacity: usize,
}

impl DiagnosticCollector {
    fn new(capacity: usize) -> Self {
        Self {
            diagnostics: Vec::new(),
            capacity,
        }
    }

    fn push(&mut self, diagnostic: NormalizationDiagnostic) {
        if self.diagnostics.len() < self.capacity {
            self.diagnostics.push(diagnostic);
        }
    }

    fn take_vec(&mut self) -> Vec<NormalizationDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    fn into_vec(self) -> Vec<NormalizationDiagnostic> {
        self.diagnostics
    }
}
