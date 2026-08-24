#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    EthernetMetadata, Ipv4Metadata, MacAddress, NetworkLayer, NormalizedPacket, PacketCompleteness,
    PacketReference, PacketTimestamp, PacketTruncationReason, TcpFlags, TcpMetadata,
    TransportLayer,
};
use pcapraven_protocols::{parse_http_packet, HttpLimits, HttpLimitsBuilder};

fuzz_target!(|data: &[u8]| {
    let limits = HttpLimits::default();

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

    // 1. Fuzz TCP on port 80 (Request direction)
    let tcp_req_packet = NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: 54321,
            destination_port: 80,
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

    let req_outcome = parse_http_packet(&tcp_req_packet, &limits);
    assert!(req_outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    assert!(req_outcome.observations.len() <= 1);
    for obs in &req_outcome.observations {
        if obs.completeness.is_complete() {
            assert!(obs.header_section_bytes <= limits.maximum_header_section_bytes);
        }
        for selected in [
            obs.headers.host.as_ref(),
            obs.headers.user_agent.as_ref(),
            obs.headers.server.as_ref(),
            obs.headers.content_type.as_ref(),
            obs.headers.transfer_encoding.as_ref(),
            obs.headers.connection.as_ref(),
            obs.headers.upgrade.as_ref(),
        ] {
            let Some(value) = selected else {
                continue;
            };
            assert!(value.len() <= limits.maximum_selected_field_value_bytes);
            let rendered = value.display_escaped();
            assert!(
                !rendered
                    .bytes()
                    .any(|byte| (byte < 0x20 && byte != 0x09) || byte == 0x7f)
            );
        }
    }

    // 2. Fuzz TCP on port 80 (Response direction)
    let tcp_resp_packet = NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: 80,
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

    let resp_outcome = parse_http_packet(&tcp_resp_packet, &limits);
    assert!(resp_outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    assert!(resp_outcome.observations.len() <= 1);
    assert_eq!(req_outcome, parse_http_packet(&tcp_req_packet, &limits));
    assert_eq!(resp_outcome, parse_http_packet(&tcp_resp_packet, &limits));

    // 3. Fuzz without network layer
    let no_net_packet = NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: None,
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: 54321,
            destination_port: 80,
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
    let no_net_outcome = parse_http_packet(&no_net_packet, &limits);
    assert!(no_net_outcome.observations.is_empty());

    // 4. Fuzz with tight custom limits
    if let Ok(tight_limits) = HttpLimitsBuilder::new()
        .maximum_start_line_bytes(128)
        .maximum_header_line_bytes(128)
        .maximum_header_section_bytes(512)
        .maximum_header_fields(4)
        .maximum_method_bytes(8)
        .maximum_request_target_bytes(64)
        .maximum_selected_field_value_bytes(64)
        .maximum_diagnostics_per_packet(4)
        .build()
    {
        let tight_outcome = parse_http_packet(&tcp_req_packet, &tight_limits);
        assert!(tight_outcome.diagnostics.len() <= tight_limits.maximum_diagnostics_per_packet);
        assert!(tight_outcome.observations.len() <= 1);
        for obs in &tight_outcome.observations {
            if obs.completeness.is_complete() {
                assert!(obs.header_section_bytes <= tight_limits.maximum_header_section_bytes);
            }
        }
    }

    let mut sensitive_payload = b"GET / HTTP/1.1\r\nHost: privacy.example\r\nAuthorization: PHASE18_SECRET_".to_vec();
    for byte in data.iter().take(32) {
        sensitive_payload.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    sensitive_payload.extend_from_slice(
        b"\r\nProxy-Authorization: PHASE18_PROXY_SECRET\r\nCookie: PHASE18_COOKIE_SECRET\r\n\r\n",
    );
    let mut sensitive_packet = tcp_req_packet.clone();
    sensitive_packet.payload = Some(sensitive_payload);
    let sensitive = parse_http_packet(&sensitive_packet, &limits);
    for observation in &sensitive.observations {
        assert!(observation.headers.has_authorization);
        assert!(observation.headers.has_proxy_authorization);
        assert!(observation.headers.has_cookie);
        let debug = format!("{observation:?}");
        assert!(!debug.contains("PHASE18_SECRET_"));
        assert!(!debug.contains("PHASE18_PROXY_SECRET"));
        assert!(!debug.contains("PHASE18_COOKIE_SECRET"));
    }

    let mut set_cookie_payload =
        b"HTTP/1.1 200 OK\r\nSet-Cookie: PHASE18_SET_COOKIE_SECRET_".to_vec();
    for byte in data.iter().take(32) {
        set_cookie_payload.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    set_cookie_payload.extend_from_slice(b"; Secure; HttpOnly\r\n\r\n");
    let mut set_cookie_packet = tcp_resp_packet.clone();
    set_cookie_packet.payload = Some(set_cookie_payload);
    let set_cookie = parse_http_packet(&set_cookie_packet, &limits);
    for observation in &set_cookie.observations {
        assert!(observation.headers.has_set_cookie);
        let debug = format!("{observation:?}");
        assert!(!debug.contains("PHASE18_SET_COOKIE_SECRET_"));
        assert!(!debug.contains("HttpOnly"));
    }
});
