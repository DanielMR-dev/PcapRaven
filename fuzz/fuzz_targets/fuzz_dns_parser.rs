#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    DnsRdataMetadata, EthernetMetadata, Ipv4Metadata, MacAddress, NetworkLayer, NormalizedPacket,
    PacketCompleteness, PacketReference, PacketTimestamp, PacketTruncationReason, TcpMetadata,
    TransportLayer, UdpMetadata,
};
use pcapraven_protocols::{parse_dns_packet, DnsLimits, DnsLimitsBuilder};

fuzz_target!(|data: &[u8]| {
    let limits = DnsLimits::default();

    let Ok(payload_length) = u32::try_from(data.len()) else {
        return;
    };
    let Ok(udp_length) = u16::try_from(data.len().saturating_add(8)) else {
        return;
    };
    let pkt_ref = PacketReference::new(0, None, None, payload_length, payload_length, false);
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
            length: udp_length,
            checksum: 0,
        })),
        payload: Some(data.to_vec()),
        completeness: PacketCompleteness::Complete,
    };

    let udp_outcome = parse_dns_packet(&udp_packet, &limits);
    assert!(udp_outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    assert!(udp_outcome.observations.len() <= 1);

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

    // 3. Fuzz without network layer
    let no_net_packet = NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: None,
        transport_layer: Some(TransportLayer::Udp(UdpMetadata {
            source_port: 53535,
            destination_port: 53,
            length: udp_length,
            checksum: 0,
        })),
        payload: Some(data.to_vec()),
        completeness: PacketCompleteness::Partial {
            reason: PacketTruncationReason::HeaderTruncation,
        },
    };
    let no_net_outcome = parse_dns_packet(&no_net_packet, &limits);
    assert!(no_net_outcome.observations.is_empty());

    // 4. Fuzz with tight custom limits
    if let Ok(tight_limits) = DnsLimitsBuilder::new()
        .maximum_questions_per_message(2)
        .maximum_resource_records_per_message(4)
        .maximum_edns_options_per_message(1)
        .maximum_name_pointer_hops(2)
        .maximum_total_retained_name_bytes_per_message(256)
        .maximum_messages_per_packet(2)
        .maximum_diagnostics_per_packet(4)
        .build()
    {
        let tight_outcome = parse_dns_packet(&udp_packet, &tight_limits);
        assert!(tight_outcome.diagnostics.len() <= tight_limits.maximum_diagnostics_per_packet);
        assert!(tight_outcome.observations.len() <= tight_limits.maximum_messages_per_packet);
    }

    for observation in udp_outcome
        .observations
        .iter()
        .chain(tcp_outcome.observations.iter())
    {
        assert!(observation.questions.len() <= limits.maximum_questions_per_message);
        assert!(observation.records.len() <= limits.maximum_resource_records_per_message);
        let retained_name_bytes = observation
            .questions
            .iter()
            .map(|question| question.name.wire_length())
            .chain(observation.records.iter().map(|record| record.name.wire_length()))
            .chain(observation.records.iter().filter_map(|record| match &record.rdata {
                DnsRdataMetadata::Cname(name)
                | DnsRdataMetadata::Ns(name)
                | DnsRdataMetadata::Ptr(name) => Some(name.wire_length()),
                DnsRdataMetadata::Mx { exchange, .. } => Some(exchange.wire_length()),
                _ => None,
            }))
            .try_fold(0usize, usize::checked_add);
        let Some(retained_name_bytes) = retained_name_bytes else {
            return;
        };
        assert!(retained_name_bytes <= limits.maximum_total_retained_name_bytes_per_message);
    }

    let repeat = parse_dns_packet(&udp_packet, &limits);
    assert_eq!(udp_outcome, repeat);
});
