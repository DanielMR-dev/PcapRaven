//! Comprehensive tests for packet normalization.

use pcapraven_domain::{
    FragmentationState, MacAddress, NetworkLayer, NormalizationDiagnosticKind,
    NormalizationDiagnosticLayer, PacketCompleteness, PacketNormalizationInput, PacketReference,
    PacketTimestamp, PacketTimestampResolution, PacketTruncationReason, TcpFlags, TransportLayer,
    UnsupportedLayerReason,
};
use pcapraven_protocols::{
    MAX_ALLOWED_DIAGNOSTICS_PER_PACKET, MAX_ALLOWED_IPV6_EXTENSION_BYTES,
    MAX_ALLOWED_IPV6_EXTENSION_HEADERS, MAX_ALLOWED_RETAINED_PAYLOAD_BYTES, NormalizationLimits,
    NormalizationLimitsBuilder, normalize_packet,
};
use proptest::prelude::*;

fn default_reference() -> PacketReference {
    PacketReference::new(42, Some(1), Some(0), 100, 100, false)
}

fn default_timestamp() -> PacketTimestamp {
    PacketTimestamp::Available {
        seconds: 1_700_000_000,
        fractional_units: 500_000,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 6,
            units_per_second: 1_000_000,
        },
        offset_seconds: 0,
    }
}

fn default_limits() -> NormalizationLimits {
    NormalizationLimits::default()
}

fn make_input<'a>(data: &'a [u8]) -> PacketNormalizationInput<'a> {
    PacketNormalizationInput::new(default_reference(), default_timestamp(), 1, data)
}

fn make_eth_header(src: [u8; 6], dst: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(14);
    header.extend_from_slice(&dst);
    header.extend_from_slice(&src);
    header.extend_from_slice(&ethertype.to_be_bytes());
    header
}

fn make_ipv4_header(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    payload_len: usize,
    options: &[u8],
    frag_offset: u16,
    more_frags: bool,
) -> Vec<u8> {
    let ihl = ((20 + options.len()) / 4) as u8;
    let total_len = (20 + options.len() + payload_len) as u16;
    let mut header = Vec::with_capacity(20 + options.len());
    header.push((4 << 4) | (ihl & 0x0f)); // Version (4) + IHL
    header.push(0x00); // DSCP (0) + ECN (0)
    header.extend_from_slice(&total_len.to_be_bytes());
    header.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    let mut flags_and_offset = frag_offset & 0x1fff;
    if more_frags {
        flags_and_offset |= 0x2000;
    }
    header.extend_from_slice(&flags_and_offset.to_be_bytes());
    header.push(64); // TTL
    header.push(protocol);
    header.extend_from_slice(&0x0000u16.to_be_bytes()); // Checksum placeholder
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);
    header.extend_from_slice(options);
    header
}

fn make_ipv6_header(src: [u8; 16], dst: [u8; 16], next_header: u8, payload_len: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(40);
    // Version 6 + Traffic class 0 + Flow label 0
    header.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    header.extend_from_slice(&payload_len.to_be_bytes());
    header.push(next_header);
    header.push(64); // Hop limit
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);
    header
}

fn make_tcp_header(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    options: &[u8],
) -> Vec<u8> {
    let data_offset = ((20 + options.len()) / 4) as u8;
    let mut header = Vec::with_capacity(20 + options.len());
    header.extend_from_slice(&src_port.to_be_bytes());
    header.extend_from_slice(&dst_port.to_be_bytes());
    header.extend_from_slice(&seq.to_be_bytes());
    header.extend_from_slice(&ack.to_be_bytes());
    let offset_and_flags = ((data_offset as u16) << 12) | (flags & 0x01ff);
    header.extend_from_slice(&offset_and_flags.to_be_bytes());
    header.extend_from_slice(&65535u16.to_be_bytes()); // Window
    header.extend_from_slice(&0xbeefu16.to_be_bytes()); // Checksum
    header.extend_from_slice(&0x0000u16.to_be_bytes()); // Urgent pointer
    header.extend_from_slice(options);
    header
}

fn make_udp_header(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let length = (8 + payload_len) as u16;
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(&src_port.to_be_bytes());
    header.extend_from_slice(&dst_port.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    header.extend_from_slice(&0xcafeu16.to_be_bytes()); // Checksum
    header
}

#[test]
fn normalizes_ethernet_ipv4_tcp_successfully() {
    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let src_ip = [192, 168, 1, 10];
    let dst_ip = [10, 0, 0, 1];
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let mut frame = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr = make_ipv4_header(src_ip, dst_ip, 6, 20 + payload.len(), &[], 0, false);
    let tcp_hdr = make_tcp_header(54321, 80, 1000, 0, 0x0002 /* SYN */, &[]);

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&tcp_hdr);
    frame.extend_from_slice(payload);

    let input = make_input(&frame);
    let outcome = normalize_packet(&input, &default_limits());

    assert!(outcome.diagnostics.is_empty());
    assert_eq!(outcome.packet.completeness, PacketCompleteness::Complete);
    assert_eq!(outcome.packet.reference, default_reference());
    assert_eq!(outcome.packet.timestamp, default_timestamp());

    let eth = outcome.packet.link_layer.expect("link layer");
    assert_eq!(eth.source, MacAddress::new(src_mac));
    assert_eq!(eth.destination, MacAddress::new(dst_mac));
    assert_eq!(eth.ethertype, 0x0800);
    assert_eq!(eth.link_header_length, 14);

    let net = outcome.packet.network_layer.expect("network layer");
    match net {
        NetworkLayer::Ipv4(ip) => {
            assert_eq!(ip.version, 4);
            assert_eq!(ip.header_length, 20);
            assert_eq!(ip.protocol, 6);
            assert_eq!(ip.source, src_ip);
            assert_eq!(ip.destination, dst_ip);
            assert_eq!(ip.fragmentation, FragmentationState::NotFragmented);
        }
        NetworkLayer::Ipv6(_) => panic!("expected IPv4"),
    }

    let transport = outcome.packet.transport_layer.expect("transport layer");
    match transport {
        TransportLayer::Tcp(tcp) => {
            assert_eq!(tcp.source_port, 54321);
            assert_eq!(tcp.destination_port, 80);
            assert_eq!(tcp.sequence_number, 1000);
            assert_eq!(tcp.acknowledgement_number, 0);
            assert_eq!(tcp.data_offset_bytes, 20);
            assert!(tcp.flags.syn);
            assert!(!tcp.flags.ack);
            assert_eq!(tcp.checksum, 0xbeef);
        }
        TransportLayer::Udp(_) => panic!("expected TCP"),
    }

    assert_eq!(outcome.packet.payload.as_deref(), Some(payload.as_slice()));
}

#[test]
fn normalizes_ethernet_ipv4_udp_successfully() {
    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let src_ip = [192, 168, 1, 50];
    let dst_ip = [192, 168, 1, 1];
    let payload = [0x01, 0x02, 0x03, 0x04];

    let mut frame = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr = make_ipv4_header(src_ip, dst_ip, 17, 8 + payload.len(), &[], 0, false);
    let udp_hdr = make_udp_header(5353, 53, payload.len());

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&udp_hdr);
    frame.extend_from_slice(&payload);

    let input = make_input(&frame);
    let outcome = normalize_packet(&input, &default_limits());

    assert!(outcome.diagnostics.is_empty());
    assert_eq!(outcome.packet.completeness, PacketCompleteness::Complete);

    let transport = outcome.packet.transport_layer.expect("transport layer");
    match transport {
        TransportLayer::Udp(udp) => {
            assert_eq!(udp.source_port, 5353);
            assert_eq!(udp.destination_port, 53);
            assert_eq!(udp.length, 12);
            assert_eq!(udp.checksum, 0xcafe);
        }
        TransportLayer::Tcp(_) => panic!("expected UDP"),
    }

    assert_eq!(outcome.packet.payload.as_deref(), Some(payload.as_slice()));
}

#[test]
fn normalizes_ethernet_ipv6_tcp_successfully() {
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let payload = b"hello ipv6 tcp";

    let mut frame = make_eth_header(src_mac, dst_mac, 0x86dd);
    let ip_hdr = make_ipv6_header(src_ip, dst_ip, 6, (20 + payload.len()) as u16);
    let tcp_hdr = make_tcp_header(443, 60000, 500, 600, 0x0018 /* PSH | ACK */, &[]);

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&tcp_hdr);
    frame.extend_from_slice(payload);

    let input = make_input(&frame);
    let outcome = normalize_packet(&input, &default_limits());

    assert!(outcome.diagnostics.is_empty());
    assert_eq!(outcome.packet.completeness, PacketCompleteness::Complete);

    let net = outcome.packet.network_layer.expect("network layer");
    match net {
        NetworkLayer::Ipv6(ip) => {
            assert_eq!(ip.version, 6);
            assert_eq!(ip.effective_protocol, 6);
            assert_eq!(ip.source, src_ip);
            assert_eq!(ip.destination, dst_ip);
            assert_eq!(ip.extension_headers_count, 0);
        }
        NetworkLayer::Ipv4(_) => panic!("expected IPv6"),
    }

    let transport = outcome.packet.transport_layer.expect("transport layer");
    match transport {
        TransportLayer::Tcp(tcp) => {
            assert_eq!(tcp.source_port, 443);
            assert_eq!(tcp.destination_port, 60000);
            assert!(tcp.flags.psh);
            assert!(tcp.flags.ack);
        }
        TransportLayer::Udp(_) => panic!("expected TCP"),
    }

    assert_eq!(outcome.packet.payload.as_deref(), Some(payload.as_slice()));
}

#[test]
fn normalizes_ethernet_ipv6_udp_successfully() {
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    let src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let payload = [0xaa, 0xbb, 0xcc];

    let mut frame = make_eth_header(src_mac, dst_mac, 0x86dd);
    let ip_hdr = make_ipv6_header(src_ip, dst_ip, 17, (8 + payload.len()) as u16);
    let udp_hdr = make_udp_header(0, 65535, payload.len());

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&udp_hdr);
    frame.extend_from_slice(&payload);

    let input = make_input(&frame);
    let outcome = normalize_packet(&input, &default_limits());

    assert!(outcome.diagnostics.is_empty());
    assert_eq!(outcome.packet.completeness, PacketCompleteness::Complete);

    let transport = outcome.packet.transport_layer.expect("transport layer");
    match transport {
        TransportLayer::Udp(udp) => {
            assert_eq!(udp.source_port, 0);
            assert_eq!(udp.destination_port, 65535);
        }
        TransportLayer::Tcp(_) => panic!("expected UDP"),
    }
}

#[test]
fn excludes_ethernet_padding_from_ipv4_and_transport_payload() {
    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let src_ip = [10, 0, 0, 1];
    let dst_ip = [10, 0, 0, 2];
    let payload = [1u8, 2, 3, 4, 5];

    let mut frame = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr = make_ipv4_header(src_ip, dst_ip, 17, 8 + payload.len(), &[], 0, false);
    let udp_hdr = make_udp_header(1234, 5678, payload.len());

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&udp_hdr);
    frame.extend_from_slice(&payload);
    // Add 20 bytes of Ethernet padding to reach min frame size
    let padding = [0x00u8; 20];
    frame.extend_from_slice(&padding);

    let input = make_input(&frame);
    let outcome = normalize_packet(&input, &default_limits());

    assert_eq!(outcome.packet.completeness, PacketCompleteness::Complete);
    // The payload must strictly match the 5 bytes of UDP payload, NOT including padding
    assert_eq!(outcome.packet.payload.as_deref(), Some(payload.as_slice()));
}

#[test]
fn handles_ipv4_options_without_semantic_interpretation() {
    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let src_ip = [10, 1, 2, 3];
    let dst_ip = [10, 4, 5, 6];
    let options = [0x01, 0x01, 0x01, 0x00]; // 4 bytes of NOP/End options (IHL becomes 6 = 24 bytes)
    let payload = [0xde, 0xad, 0xbe, 0xef];

    let mut frame = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr = make_ipv4_header(src_ip, dst_ip, 17, 8 + payload.len(), &options, 0, false);
    let udp_hdr = make_udp_header(8000, 9000, payload.len());

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&udp_hdr);
    frame.extend_from_slice(&payload);

    let input = make_input(&frame);
    let outcome = normalize_packet(&input, &default_limits());

    assert_eq!(outcome.packet.completeness, PacketCompleteness::Complete);
    let net = outcome.packet.network_layer.expect("network layer");
    match net {
        NetworkLayer::Ipv4(ip) => {
            assert_eq!(ip.header_length, 24);
        }
        NetworkLayer::Ipv6(_) => panic!("expected IPv4"),
    }
    assert_eq!(outcome.packet.payload.as_deref(), Some(payload.as_slice()));
}

#[test]
fn traverses_supported_ipv6_extension_headers() {
    let src_mac = [0x02, 0, 0, 0, 0, 1];
    let dst_mac = [0x02, 0, 0, 0, 0, 2];
    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let payload = [0x01, 0x02];

    let mut frame = make_eth_header(src_mac, dst_mac, 0x86dd);
    // HopByHop (next header 0), which points to TCP (6)
    let hop_by_hop_ext = [
        6, // next header: TCP
        0, // hdr ext len: (0 + 1) * 8 = 8 bytes
        1, 4, 0, 0, 0, 0, // PadN option
    ];
    let ip_hdr = make_ipv6_header(
        src_ip,
        dst_ip,
        0, // Next header: Hop-by-Hop
        (hop_by_hop_ext.len() + 20 + payload.len()) as u16,
    );
    let tcp_hdr = make_tcp_header(1111, 2222, 1, 1, 0x0010 /* ACK */, &[]);

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&hop_by_hop_ext);
    frame.extend_from_slice(&tcp_hdr);
    frame.extend_from_slice(&payload);

    let input = make_input(&frame);
    let outcome = normalize_packet(&input, &default_limits());

    assert_eq!(outcome.packet.completeness, PacketCompleteness::Complete);
    let net = outcome.packet.network_layer.expect("network layer");
    match net {
        NetworkLayer::Ipv6(ip) => {
            assert_eq!(ip.next_header, 0);
            assert_eq!(ip.effective_protocol, 6);
            assert_eq!(ip.extension_headers_count, 1);
            assert_eq!(ip.extension_headers_length, 8);
        }
        NetworkLayer::Ipv4(_) => panic!("expected IPv6"),
    }
    assert_eq!(outcome.packet.payload.as_deref(), Some(payload.as_slice()));
}

#[test]
fn handles_unsupported_link_type_deterministically() {
    let data = [0x00u8; 32];
    let input = PacketNormalizationInput::new(
        default_reference(),
        default_timestamp(),
        105, /* 802.11 */
        &data,
    );
    let outcome = normalize_packet(&input, &default_limits());

    assert!(matches!(
        outcome.packet.completeness,
        PacketCompleteness::Unsupported {
            reason: UnsupportedLayerReason::LinkType(105)
        }
    ));
    assert!(outcome.packet.link_layer.is_none());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == NormalizationDiagnosticKind::Unsupported
                && d.layer == NormalizationDiagnosticLayer::Link)
    );
}

#[test]
fn handles_unsupported_ethertypes_deterministically() {
    // ARP EtherType (0x0806)
    let frame = make_eth_header([0; 6], [0; 6], 0x0806);
    let outcome = normalize_packet(&make_input(&frame), &default_limits());
    assert!(matches!(
        outcome.packet.completeness,
        PacketCompleteness::Unsupported {
            reason: UnsupportedLayerReason::EtherType(0x0806)
        }
    ));
    assert!(outcome.packet.link_layer.is_some());
    assert!(outcome.packet.network_layer.is_none());

    // 802.1Q VLAN EtherType (0x8100)
    let vlan_frame = make_eth_header([0; 6], [0; 6], 0x8100);
    let outcome_vlan = normalize_packet(&make_input(&vlan_frame), &default_limits());
    assert!(matches!(
        outcome_vlan.packet.completeness,
        PacketCompleteness::Unsupported {
            reason: UnsupportedLayerReason::EtherType(0x8100)
        }
    ));

    // IEEE 802.3 Length framing (e.g. 500)
    let len_frame = make_eth_header([0; 6], [0; 6], 500);
    let outcome_len = normalize_packet(&make_input(&len_frame), &default_limits());
    assert!(matches!(
        outcome_len.packet.completeness,
        PacketCompleteness::Unsupported {
            reason: UnsupportedLayerReason::EtherType(500)
        }
    ));
}

#[test]
fn handles_unsupported_transport_protocol_preserving_network_facts() {
    let src_mac = [0; 6];
    let dst_mac = [0; 6];
    let src_ip = [10, 0, 0, 1];
    let dst_ip = [10, 0, 0, 2];
    // ICMP protocol 1
    let mut frame = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr = make_ipv4_header(src_ip, dst_ip, 1, 8, &[], 0, false);
    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Echo request

    let outcome = normalize_packet(&make_input(&frame), &default_limits());
    assert!(matches!(
        outcome.packet.completeness,
        PacketCompleteness::Unsupported {
            reason: UnsupportedLayerReason::NetworkProtocol(1)
        }
    ));
    assert!(outcome.packet.link_layer.is_some());
    assert!(outcome.packet.network_layer.is_some());
    assert!(outcome.packet.transport_layer.is_none());
    assert!(outcome.packet.payload.is_none());
}

#[test]
fn handles_malformed_and_truncated_ethernet_frames() {
    // Empty bytes
    let out_empty = normalize_packet(&make_input(&[]), &default_limits());
    assert!(matches!(
        out_empty.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::HeaderTruncation
        }
    ));

    // 1-byte frame
    let out_1 = normalize_packet(&make_input(&[0xaa]), &default_limits());
    assert!(matches!(
        out_1.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::HeaderTruncation
        }
    ));

    // 13-byte frame
    let out_13 = normalize_packet(&make_input(&[0x00; 13]), &default_limits());
    assert!(matches!(
        out_13.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::HeaderTruncation
        }
    ));
}

#[test]
fn handles_ipv4_fragmentation_without_reassembly() {
    let src_mac = [0; 6];
    let dst_mac = [0; 6];
    let src_ip = [192, 168, 1, 100];
    let dst_ip = [192, 168, 1, 200];
    let fragment_data = [0x55u8; 100];

    // First fragment (MF = true, offset = 0)
    let mut frame1 = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr1 = make_ipv4_header(src_ip, dst_ip, 6, fragment_data.len(), &[], 0, true);
    frame1.extend_from_slice(&ip_hdr1);
    frame1.extend_from_slice(&fragment_data);

    let out1 = normalize_packet(&make_input(&frame1), &default_limits());
    assert!(matches!(
        out1.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::Fragmented
        }
    ));
    assert!(out1.packet.transport_layer.is_none());
    let net1 = out1.packet.network_layer.expect("network layer");
    assert!(net1.fragmentation().is_fragmented());

    // Non-initial fragment (MF = false, offset = 100)
    let mut frame2 = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr2 = make_ipv4_header(src_ip, dst_ip, 6, fragment_data.len(), &[], 100, false);
    frame2.extend_from_slice(&ip_hdr2);
    frame2.extend_from_slice(&fragment_data);

    let out2 = normalize_packet(&make_input(&frame2), &default_limits());
    assert!(matches!(
        out2.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::Fragmented
        }
    ));
    assert!(out2.packet.transport_layer.is_none());
}

#[test]
fn handles_ipv6_fragmentation_without_reassembly() {
    let src_mac = [0; 6];
    let dst_mac = [0; 6];
    let src_ip = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let frag_ext = [
        6, // next header: TCP
        0, // reserved
        0x00, 0x09, // offset = 1 (8 bytes), more = 1
        0x00, 0x00, 0x12, 0x34, // ID
    ];
    let frag_payload = [0xaa; 32];

    let mut frame = make_eth_header(src_mac, dst_mac, 0x86dd);
    let ip_hdr = make_ipv6_header(
        src_ip,
        dst_ip,
        44, /* Fragment */
        (8 + frag_payload.len()) as u16,
    );
    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&frag_ext);
    frame.extend_from_slice(&frag_payload);

    let outcome = normalize_packet(&make_input(&frame), &default_limits());
    assert!(matches!(
        outcome.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::Fragmented
        }
    ));
    assert!(outcome.packet.transport_layer.is_none());
    let net = outcome.packet.network_layer.expect("network layer");
    assert!(net.fragmentation().is_fragmented());
}

#[test]
fn bounds_retained_payload_bytes_strictly() {
    let src_mac = [0; 6];
    let dst_mac = [0; 6];
    let src_ip = [10, 0, 0, 1];
    let dst_ip = [10, 0, 0, 2];
    let payload = vec![0x42u8; 100]; // 100 bytes payload

    let mut frame = make_eth_header(src_mac, dst_mac, 0x0800);
    let ip_hdr = make_ipv4_header(src_ip, dst_ip, 17, 8 + payload.len(), &[], 0, false);
    let udp_hdr = make_udp_header(1000, 2000, payload.len());
    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&udp_hdr);
    frame.extend_from_slice(&payload);

    // Limit payload to 30 bytes
    let limits = NormalizationLimitsBuilder::default()
        .maximum_retained_payload_bytes(30)
        .build()
        .expect("limits");

    let outcome = normalize_packet(&make_input(&frame), &limits);
    assert_eq!(
        outcome.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::PayloadBudgetExceeded
        }
    );
    let retained = outcome.packet.payload.expect("payload");
    assert_eq!(retained.len(), 30);
    assert_eq!(&retained[..], &payload[..30]);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == NormalizationDiagnosticKind::ResourceLimit
                && d.layer == NormalizationDiagnosticLayer::Payload)
    );
}

#[test]
fn phase18_payload_retention_covers_n_minus_1_n_n_plus_1() {
    const LIMIT: usize = 30;
    for payload_length in [LIMIT - 1, LIMIT, LIMIT + 1] {
        let payload = vec![0x42_u8; payload_length];
        let mut frame = make_eth_header([0; 6], [0; 6], 0x0800);
        frame.extend_from_slice(&make_ipv4_header(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            17,
            8 + payload.len(),
            &[],
            0,
            false,
        ));
        frame.extend_from_slice(&make_udp_header(1000, 2000, payload.len()));
        frame.extend_from_slice(&payload);
        let limits = NormalizationLimitsBuilder::default()
            .maximum_retained_payload_bytes(LIMIT)
            .build()
            .unwrap();
        let outcome = normalize_packet(&make_input(&frame), &limits);
        assert_eq!(
            outcome.packet.payload.as_ref().map_or(0, Vec::len),
            payload_length.min(LIMIT)
        );
        assert_eq!(
            matches!(
                outcome.packet.completeness,
                PacketCompleteness::Partial {
                    reason: PacketTruncationReason::PayloadBudgetExceeded
                }
            ),
            payload_length > LIMIT
        );
    }
}

#[test]
fn bounds_diagnostics_per_packet_strictly() {
    let mut limits = default_limits();
    limits.maximum_diagnostics_per_packet = 1;

    // A frame that would trigger multiple diagnostics
    let frame = make_eth_header([0; 6], [0; 6], 0x0800); // Ethernet header but truncated IP
    let outcome = normalize_packet(&make_input(&frame), &limits);
    assert!(outcome.diagnostics.len() <= 1);
}

#[test]
fn tcp_flags_full_decoding() {
    let all_flags = TcpFlags::from_bits(0x01ff);
    assert!(all_flags.ns);
    assert!(all_flags.cwr);
    assert!(all_flags.ece);
    assert!(all_flags.urg);
    assert!(all_flags.ack);
    assert!(all_flags.psh);
    assert!(all_flags.rst);
    assert!(all_flags.syn);
    assert!(all_flags.fin);
    assert_eq!(all_flags.raw_bits(), 0x01ff);

    let no_flags = TcpFlags::from_bits(0x0000);
    assert!(!no_flags.ns);
    assert!(!no_flags.fin);
    assert_eq!(no_flags.raw_bits(), 0x0000);
}

#[test]
fn malformed_tcp_data_offset_and_truncation() {
    let mut frame = make_eth_header([0; 6], [0; 6], 0x0800);
    let ip_hdr = make_ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 6, 20, &[], 0, false);
    frame.extend_from_slice(&ip_hdr);
    // TCP with invalid data offset 3 (< 5)
    let bad_tcp = [
        0x00, 0x50, 0x00, 0x50, // ports
        0, 0, 0, 1, // seq
        0, 0, 0, 0, // ack
        0x30, 0x00, // data offset 3 * 4 = 12 (< 20)
        0xff, 0xff, 0, 0, 0, 0,
    ];
    frame.extend_from_slice(&bad_tcp);

    let outcome = normalize_packet(&make_input(&frame), &default_limits());
    assert!(matches!(
        outcome.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::DeclaredLengthMismatch
        }
    ));
    assert!(outcome.packet.transport_layer.is_none());
}

#[test]
fn malformed_udp_lengths_and_empty_payload() {
    // Length < 8
    let mut frame1 = make_eth_header([0; 6], [0; 6], 0x0800);
    let ip_hdr1 = make_ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 17, 8, &[], 0, false);
    frame1.extend_from_slice(&ip_hdr1);
    frame1.extend_from_slice(&[0x00, 53, 0x00, 53, 0x00, 0x04, 0x00, 0x00]); // length = 4

    let outcome1 = normalize_packet(&make_input(&frame1), &default_limits());
    assert!(matches!(
        outcome1.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::DeclaredLengthMismatch
        }
    ));

    // Length == 8 (0 payload bytes)
    let mut frame2 = make_eth_header([0; 6], [0; 6], 0x0800);
    let ip_hdr2 = make_ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 17, 8, &[], 0, false);
    let udp_hdr2 = make_udp_header(53, 53, 0);
    frame2.extend_from_slice(&ip_hdr2);
    frame2.extend_from_slice(&udp_hdr2);

    let outcome2 = normalize_packet(&make_input(&frame2), &default_limits());
    assert_eq!(outcome2.packet.completeness, PacketCompleteness::Complete);
    assert_eq!(outcome2.packet.payload, None);
}

#[test]
fn ipv6_extension_count_and_byte_limits_boundary() {
    let src_mac = [0; 6];
    let dst_mac = [0; 6];
    let src_ip = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    // Build frame with 3 HopByHop extension headers
    let mut frame = make_eth_header(src_mac, dst_mac, 0x86dd);
    let ext1 = [0, 0, 1, 4, 0, 0, 0, 0]; // next: HopByHop (0)
    let ext2 = [0, 0, 1, 4, 0, 0, 0, 0]; // next: HopByHop (0)
    let ext3 = [17, 0, 1, 4, 0, 0, 0, 0]; // next: UDP (17)
    let udp_hdr = make_udp_header(100, 200, 0);

    let total_payload = ext1.len() + ext2.len() + ext3.len() + udp_hdr.len();
    let ip_hdr = make_ipv6_header(src_ip, dst_ip, 0, total_payload as u16);

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&ext1);
    frame.extend_from_slice(&ext2);
    frame.extend_from_slice(&ext3);
    frame.extend_from_slice(&udp_hdr);

    // Limit extension headers to 2
    let limits = NormalizationLimitsBuilder::default()
        .maximum_ipv6_extension_headers(2)
        .build()
        .expect("limits");

    let outcome = normalize_packet(&make_input(&frame), &limits);
    assert!(matches!(
        outcome.packet.completeness,
        PacketCompleteness::Partial {
            reason: PacketTruncationReason::PayloadBudgetExceeded
        }
    ));
    assert!(outcome.packet.transport_layer.is_none());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == NormalizationDiagnosticKind::ResourceLimit
                && d.layer == NormalizationDiagnosticLayer::Ipv6Extension)
    );

    for (limit, complete) in [(2, false), (3, true), (4, true)] {
        let limits = NormalizationLimitsBuilder::default()
            .maximum_ipv6_extension_headers(limit)
            .build()
            .unwrap();
        let out = normalize_packet(&make_input(&frame), &limits);
        assert_eq!(out.packet.completeness.is_complete(), complete);
        if let Some(NetworkLayer::Ipv6(ip)) = &out.packet.network_layer {
            assert!(ip.extension_headers_count <= limit);
        }
    }
    for (limit, complete) in [(23, false), (24, true), (25, true)] {
        let limits = NormalizationLimitsBuilder::default()
            .maximum_ipv6_extension_bytes(limit)
            .build()
            .unwrap();
        let out = normalize_packet(&make_input(&frame), &limits);
        assert_eq!(out.packet.completeness.is_complete(), complete);
        if let Some(NetworkLayer::Ipv6(ip)) = &out.packet.network_layer {
            assert!(usize::from(ip.extension_headers_length) <= limit);
        }
    }
}

#[test]
fn limits_builder_validates_hard_caps() {
    for value in [
        MAX_ALLOWED_RETAINED_PAYLOAD_BYTES - 1,
        MAX_ALLOWED_RETAINED_PAYLOAD_BYTES,
    ] {
        assert!(
            NormalizationLimitsBuilder::default()
                .maximum_retained_payload_bytes(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        NormalizationLimitsBuilder::default()
            .maximum_retained_payload_bytes(MAX_ALLOWED_RETAINED_PAYLOAD_BYTES + 1)
            .build()
            .is_err()
    );

    for value in [
        MAX_ALLOWED_DIAGNOSTICS_PER_PACKET - 1,
        MAX_ALLOWED_DIAGNOSTICS_PER_PACKET,
    ] {
        assert!(
            NormalizationLimitsBuilder::default()
                .maximum_diagnostics_per_packet(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        NormalizationLimitsBuilder::default()
            .maximum_diagnostics_per_packet(MAX_ALLOWED_DIAGNOSTICS_PER_PACKET + 1)
            .build()
            .is_err()
    );

    for value in [
        MAX_ALLOWED_IPV6_EXTENSION_HEADERS - 1,
        MAX_ALLOWED_IPV6_EXTENSION_HEADERS,
    ] {
        assert!(
            NormalizationLimitsBuilder::default()
                .maximum_ipv6_extension_headers(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        NormalizationLimitsBuilder::default()
            .maximum_ipv6_extension_headers(MAX_ALLOWED_IPV6_EXTENSION_HEADERS + 1)
            .build()
            .is_err()
    );

    for value in [
        MAX_ALLOWED_IPV6_EXTENSION_BYTES - 1,
        MAX_ALLOWED_IPV6_EXTENSION_BYTES,
    ] {
        assert!(
            NormalizationLimitsBuilder::default()
                .maximum_ipv6_extension_bytes(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        NormalizationLimitsBuilder::default()
            .maximum_ipv6_extension_bytes(MAX_ALLOWED_IPV6_EXTENSION_BYTES + 1)
            .build()
            .is_err()
    );
}

// Property-based testing
proptest! {
    #[test]
    fn arbitrary_bytes_with_ethernet_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let input = make_input(&bytes);
        let limits = default_limits();
        let outcome = normalize_packet(&input, &limits);
        if let Some(payload) = &outcome.packet.payload {
            prop_assert!(payload.len() <= limits.maximum_retained_payload_bytes);
        }
        if let Some(NetworkLayer::Ipv6(ipv6)) = &outcome.packet.network_layer {
            prop_assert!(ipv6.extension_headers_count <= limits.maximum_ipv6_extension_headers);
            prop_assert!(
                usize::from(ipv6.extension_headers_length) <= limits.maximum_ipv6_extension_bytes
            );
        }
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    }

    #[test]
    fn arbitrary_linktype_and_bytes_never_panic(linktype in any::<u32>(), bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let input = PacketNormalizationInput::new(default_reference(), default_timestamp(), linktype, &bytes);
        let limits = default_limits();
        let outcome = normalize_packet(&input, &limits);
        if linktype != 1 {
            let is_unsupported = matches!(
                outcome.packet.completeness,
                PacketCompleteness::Unsupported { .. }
            );
            prop_assert!(is_unsupported);
        }
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    }

    #[test]
    fn truncated_valid_packets_never_panic(trunc_len in 0usize..200) {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let src_ip = [192, 168, 1, 10];
        let dst_ip = [10, 0, 0, 1];
        let payload = [0x42u8; 64];

        let mut frame = make_eth_header(src_mac, dst_mac, 0x0800);
        let ip_hdr = make_ipv4_header(src_ip, dst_ip, 6, 20 + payload.len(), &[], 0, false);
        let tcp_hdr = make_tcp_header(54321, 80, 1000, 0, 0x0002, &[]);

        frame.extend_from_slice(&ip_hdr);
        frame.extend_from_slice(&tcp_hdr);
        frame.extend_from_slice(&payload);

        let slice_len = trunc_len.min(frame.len());
        let truncated_data = &frame[..slice_len];
        let outcome = normalize_packet(&make_input(truncated_data), &default_limits());
        if slice_len < frame.len() {
            prop_assert!(!outcome.packet.completeness.is_complete());
        }
    }

    #[test]
    fn determinism_identical_input_yields_identical_output(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let input1 = make_input(&bytes);
        let input2 = make_input(&bytes);
        let limits = default_limits();
        let out1 = normalize_packet(&input1, &limits);
        let out2 = normalize_packet(&input2, &limits);
        prop_assert_eq!(out1, out2);
    }
}
