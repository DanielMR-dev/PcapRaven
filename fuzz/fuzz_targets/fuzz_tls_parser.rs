#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    EthernetMetadata, Ipv4Metadata, MacAddress, NetworkLayer, NormalizedPacket, PacketCompleteness,
    PacketReference, PacketTimestamp, PacketTruncationReason, TcpFlags, TcpMetadata,
    TransportLayer,
};
use pcapraven_protocols::{parse_tls_packet, TlsLimits, TlsLimitsBuilder};

fuzz_target!(|data: &[u8]| {
    let limits = TlsLimits::default();

    let safe_len_u32 = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let safe_total_len_u16 = u16::try_from(data.len().saturating_add(40)).unwrap_or(u16::MAX);

    let pkt_ref = PacketReference::new(0, None, None, safe_len_u32, safe_len_u32, false);
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
        total_length: safe_total_len_u16,
        identification: 1,
        ttl: 64,
        protocol: 6,
        source: [192, 168, 1, 100],
        destination: [93, 184, 216, 34],
        fragmentation: pcapraven_domain::FragmentationState::NotFragmented,
    };

    // 1. Fuzz TCP on port 443 (Client direction)
    let tcp_client_packet = NormalizedPacket {
        reference: pkt_ref.clone(),
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: 54321,
            destination_port: 443,
            sequence_number: 1000,
            acknowledgement_number: 2000,
            data_offset_bytes: 20,
            flags: TcpFlags::default(),
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload: Some(data.to_vec()),
        completeness: PacketCompleteness::Complete,
    };

    let client_outcome = parse_tls_packet(&tcp_client_packet, &limits);
    assert!(client_outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    for obs in &client_outcome.observations {
        if let Some(ref ch) = obs.client_hello {
            assert!(ch.cipher_suites.len() <= limits.maximum_cipher_suites_per_client_hello);
            assert!(ch.extensions.len() <= limits.maximum_extensions_per_hello);
            if let Some(ref sni) = ch.server_name {
                assert!(sni.len() <= limits.maximum_server_name_bytes);
                let s = sni.display_escaped();
                assert!(!s.bytes().any(|b| (b < 0x20 && b != 0x09) || b == 0x7F));
            }
        }
    }

    // 2. Fuzz TCP on port 443 (Server direction)
    let tcp_server_packet = NormalizedPacket {
        reference: pkt_ref.clone(),
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: 443,
            destination_port: 54321,
            sequence_number: 2000,
            acknowledgement_number: 1000,
            data_offset_bytes: 20,
            flags: TcpFlags::default(),
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload: Some(data.to_vec()),
        completeness: PacketCompleteness::Complete,
    };

    let server_outcome = parse_tls_packet(&tcp_server_packet, &limits);
    assert!(server_outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);

    // 3. Fuzz without network layer
    let no_net_packet = NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: None,
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: 54321,
            destination_port: 443,
            sequence_number: 1000,
            acknowledgement_number: 2000,
            data_offset_bytes: 20,
            flags: TcpFlags::default(),
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload: Some(data.to_vec()),
        completeness: PacketCompleteness::Partial {
            reason: PacketTruncationReason::HeaderTruncation,
        },
    };
    let no_net_outcome = parse_tls_packet(&no_net_packet, &limits);
    assert!(no_net_outcome.observations.is_empty());

    // 4. Fuzz with tight custom limits
    if let Ok(tight_limits) = TlsLimitsBuilder::new()
        .maximum_records_per_packet(4)
        .maximum_handshake_messages_per_packet(4)
        .maximum_handshake_message_bytes(512)
        .maximum_cipher_suites_per_client_hello(8)
        .maximum_extensions_per_hello(8)
        .maximum_supported_versions(4)
        .maximum_supported_groups(4)
        .maximum_signature_algorithms(4)
        .maximum_alpn_protocols(4)
        .maximum_server_name_bytes(64)
        .maximum_diagnostics_per_packet(4)
        .build()
    {
        let tight_outcome = parse_tls_packet(&tcp_client_packet, &tight_limits);
        assert!(tight_outcome.diagnostics.len() <= tight_limits.maximum_diagnostics_per_packet);
    }
});
