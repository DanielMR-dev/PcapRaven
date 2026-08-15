#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    EthernetMetadata, Ipv4Metadata, MacAddress, NetworkLayer, NormalizedPacket, PacketCompleteness,
    PacketReference, PacketTimestamp, TcpMetadata, TransportLayer, UdpMetadata,
};
use pcapraven_protocols::{parse_dns_packet, DnsLimits};

fuzz_target!(|data: &[u8]| {
    let limits = DnsLimits::default();

    let pkt_ref = PacketReference::new(0, None, None, data.len() as u32, data.len() as u32, false);
    let eth = EthernetMetadata {
        source: MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        destination: MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
        ethertype: 0x0800,
        link_header_length: 14,
    };
    let ip = Ipv4Metadata {
        version: 4,
        header_length: 20,
        dscp: 0,
        ecn: 0,
        total_length: 100,
        identification: 1,
        ttl: 64,
        protocol: 17,
        source: [192, 168, 1, 100],
        destination: [8, 8, 8, 8],
        fragmentation: pcapraven_domain::FragmentationState::NotFragmented,
    };

    // 1. Fuzz UDP on port 53
    let udp_packet = NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Udp(UdpMetadata {
            source_port: 53535,
            destination_port: 53,
            length: 8 + data.len() as u16,
            checksum: 0,
        })),
        payload: Some(data.to_vec()),
        completeness: PacketCompleteness::Complete,
    };

    let udp_outcome = parse_dns_packet(&udp_packet, &limits);
    assert!(udp_outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);

    // 2. Fuzz TCP on port 53
    let tcp_packet = NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: 53535,
            destination_port: 53,
            sequence_number: 1000,
            acknowledgement_number: 2000,
            data_offset_bytes: 20,
            flags: pcapraven_domain::TcpFlags::default(),
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload: Some(data.to_vec()),
        completeness: PacketCompleteness::Complete,
    };

    let tcp_outcome = parse_dns_packet(&tcp_packet, &limits);
    assert!(tcp_outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    assert!(tcp_outcome.observations.len() <= limits.maximum_messages_per_packet);
});
