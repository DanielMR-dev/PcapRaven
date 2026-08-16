use pcapraven_domain::{
    EthernetMetadata, Ipv4Metadata, MacAddress, NetworkLayer, NormalizedPacket, PacketCompleteness,
    PacketReference, PacketTimestamp, TcpFlags, TcpMetadata, TlsDiagnosticKind, TlsHandshakeKind,
    TlsObservationCompleteness, TlsVersion, TransportLayer,
};
use pcapraven_protocols::{TlsLimits, TlsLimitsBuilder, TlsPacketDisposition, parse_tls_packet};
use proptest::prelude::*;

fn make_tls_packet(src_port: u16, dst_port: u16, payload: Vec<u8>) -> NormalizedPacket {
    NormalizedPacket {
        reference: PacketReference::new(1, None, None, 64, 64, false),
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(EthernetMetadata {
            source: MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            destination: MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
            ethertype: 0x0800,
            link_header_length: 14,
        }),
        network_layer: Some(NetworkLayer::Ipv4(Ipv4Metadata {
            version: 4,
            header_length: 20,
            dscp: 0,
            ecn: 0,
            total_length: 40 + payload.len() as u16,
            identification: 1,
            ttl: 64,
            protocol: 6,
            source: [192, 168, 1, 100],
            destination: [93, 184, 216, 34],
            fragmentation: pcapraven_domain::FragmentationState::NotFragmented,
        })),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: src_port,
            destination_port: dst_port,
            sequence_number: 1000,
            acknowledgement_number: 2000,
            data_offset_bytes: 20,
            flags: TcpFlags::default(),
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload: Some(payload),
        completeness: PacketCompleteness::Complete,
    }
}

#[test]
fn test_client_hello_tls13_parsed() {
    let bytes = std::fs::read("tests/fixtures/tls/client_hello_tls13.tls").unwrap();
    let packet = make_tls_packet(54321, 443, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);

    let obs = &outcome.observations[0];
    assert_eq!(obs.handshake_kind, TlsHandshakeKind::ClientHello);
    assert_eq!(obs.completeness, TlsObservationCompleteness::Complete);

    let ch = obs.client_hello.as_ref().unwrap();
    assert_eq!(ch.legacy_version, TlsVersion::Tls12);
    assert_eq!(ch.cipher_suites, vec![0x1301, 0x1302]);
    assert_eq!(ch.server_name.as_ref().unwrap().as_bytes(), b"example.com");
    assert_eq!(
        ch.supported_versions,
        vec![TlsVersion::Tls13, TlsVersion::Tls12]
    );
    assert_eq!(ch.supported_groups, vec![0x001d, 0x0017]);
    assert_eq!(ch.signature_algorithms, vec![0x0403, 0x0804]);
    assert_eq!(ch.alpn_protocols.len(), 2);
    assert_eq!(ch.alpn_protocols[0].as_bytes(), b"h2");
    assert_eq!(ch.alpn_protocols[1].as_bytes(), b"http/1.1");
    assert_eq!(ch.key_share_groups, vec![0x001d]);
    assert_eq!(ch.session_id_length, 0);
}

#[test]
fn test_server_hello_tls13_parsed() {
    let bytes = std::fs::read("tests/fixtures/tls/server_hello_tls13.tls").unwrap();
    let packet = make_tls_packet(443, 54321, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);

    let obs = &outcome.observations[0];
    assert_eq!(obs.handshake_kind, TlsHandshakeKind::ServerHello);
    assert_eq!(obs.completeness, TlsObservationCompleteness::Complete);

    let sh = obs.server_hello.as_ref().unwrap();
    assert_eq!(sh.cipher_suite, 0x1301);
    assert_eq!(sh.selected_version, Some(TlsVersion::Tls13));
    assert_eq!(sh.selected_group, Some(0x001d));
}

#[test]
fn test_hello_retry_request_parsed() {
    let bytes = std::fs::read("tests/fixtures/tls/hello_retry_request.tls").unwrap();
    let packet = make_tls_packet(443, 54321, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);

    let obs = &outcome.observations[0];
    assert_eq!(obs.handshake_kind, TlsHandshakeKind::HelloRetryRequest);
    assert_eq!(obs.completeness, TlsObservationCompleteness::Complete);

    let sh = obs.server_hello.as_ref().unwrap();
    assert_eq!(sh.cipher_suite, 0x1301);
    assert_eq!(sh.selected_version, Some(TlsVersion::Tls13));
    assert_eq!(sh.selected_group, Some(0x0017));
}

#[test]
fn test_client_hello_tls12_parsed() {
    let bytes = std::fs::read("tests/fixtures/tls/client_hello_tls12.tls").unwrap();
    let packet = make_tls_packet(54321, 443, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);

    let obs = &outcome.observations[0];
    assert_eq!(obs.handshake_kind, TlsHandshakeKind::ClientHello);
    let ch = obs.client_hello.as_ref().unwrap();
    assert_eq!(ch.cipher_suites, vec![0x002f]);
    assert_eq!(ch.server_name.as_ref().unwrap().as_bytes(), b"example.com");
    assert_eq!(ch.alpn_protocols.len(), 1);
    assert_eq!(ch.alpn_protocols[0].as_bytes(), b"http/1.1");
}

#[test]
fn test_server_hello_tls12_parsed() {
    let bytes = std::fs::read("tests/fixtures/tls/server_hello_tls12.tls").unwrap();
    let packet = make_tls_packet(443, 54321, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);

    let obs = &outcome.observations[0];
    assert_eq!(obs.handshake_kind, TlsHandshakeKind::ServerHello);
    let sh = obs.server_hello.as_ref().unwrap();
    assert_eq!(sh.selected_version, Some(TlsVersion::Tls12));
    assert_eq!(sh.cipher_suite, 0x002f);
    assert_eq!(sh.selected_alpn.as_ref().unwrap().as_bytes(), b"http/1.1");
}

#[test]
fn test_multi_record_handshake_assembly() {
    let bytes = std::fs::read("tests/fixtures/tls/multi_record_handshake.tls").unwrap();
    let packet = make_tls_packet(54321, 443, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);
    assert_eq!(
        outcome.observations[0].handshake_kind,
        TlsHandshakeKind::ClientHello
    );
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Complete
    );
}

#[test]
fn test_non_candidate_packets() {
    let limits = TlsLimits::default();

    // UDP port 443
    let mut pkt_udp = make_tls_packet(54321, 443, vec![22, 3, 1, 0, 10]);
    pkt_udp.transport_layer = Some(TransportLayer::Udp(pcapraven_domain::UdpMetadata {
        source_port: 54321,
        destination_port: 443,
        length: 18,
        checksum: 0,
    }));
    let out_udp = parse_tls_packet(&pkt_udp, &limits);
    assert_eq!(out_udp.disposition, TlsPacketDisposition::NotTlsCandidate);

    // TCP port 80
    let pkt_http = make_tls_packet(54321, 80, vec![22, 3, 1, 0, 10]);
    let out_http = parse_tls_packet(&pkt_http, &limits);
    assert_eq!(out_http.disposition, TlsPacketDisposition::NotTlsCandidate);

    // TCP port 443 empty payload
    let pkt_empty = make_tls_packet(54321, 443, Vec::new());
    let out_empty = parse_tls_packet(&pkt_empty, &limits);
    assert_eq!(
        out_empty.disposition,
        TlsPacketDisposition::CandidateWithoutRecord
    );

    // TCP port 443 non-TLS payload
    let pkt_raw = make_tls_packet(54321, 443, vec![0x47, 0x45, 0x54, 0x20, 0x2f]);
    let out_raw = parse_tls_packet(&pkt_raw, &limits);
    assert_eq!(
        out_raw.disposition,
        TlsPacketDisposition::CandidateWithoutRecord
    );
}

#[test]
fn test_missing_network_layer_produces_no_fake_endpoints() {
    let bytes = std::fs::read("tests/fixtures/tls/client_hello_tls13.tls").unwrap();
    let mut packet = make_tls_packet(54321, 443, bytes);
    packet.network_layer = None;
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert!(outcome.observations.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("missing network layer"))
    );
}

#[test]
fn test_unsupported_tls10_server_hello() {
    let bytes = std::fs::read("tests/fixtures/tls/tls10_unsupported.tls").unwrap();
    let packet = make_tls_packet(443, 54321, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::Unsupported)
    );
}

#[test]
fn test_duplicate_extension_rejected() {
    let bytes = std::fs::read("tests/fixtures/tls/duplicate_extension.tls").unwrap();
    let packet = make_tls_packet(54321, 443, bytes);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert!(outcome.diagnostics.iter().any(
        |d| d.kind == TlsDiagnosticKind::Malformed && d.message.contains("duplicate extension")
    ));
}

#[test]
fn test_truncated_record_and_handshake() {
    let limits = TlsLimits::default();

    let bytes_rec = std::fs::read("tests/fixtures/tls/truncated_record.tls").unwrap();
    let pkt_rec = make_tls_packet(54321, 443, bytes_rec);
    let out_rec = parse_tls_packet(&pkt_rec, &limits);
    assert_eq!(out_rec.disposition, TlsPacketDisposition::Partial);

    let bytes_hs = std::fs::read("tests/fixtures/tls/truncated_handshake.tls").unwrap();
    let pkt_hs = make_tls_packet(54321, 443, bytes_hs);
    let out_hs = parse_tls_packet(&pkt_hs, &limits);
    assert_eq!(out_hs.disposition, TlsPacketDisposition::Partial);
}

#[test]
fn test_limits_builder_validation() {
    assert!(
        TlsLimitsBuilder::new()
            .maximum_records_per_packet(0)
            .build()
            .is_err()
    );
    assert!(
        TlsLimitsBuilder::new()
            .maximum_records_per_packet(1000)
            .build()
            .is_err()
    );
    assert!(
        TlsLimitsBuilder::new()
            .maximum_handshake_message_bytes(0)
            .build()
            .is_err()
    );
    assert!(
        TlsLimitsBuilder::new()
            .maximum_handshake_message_bytes(20_000_000)
            .build()
            .is_err()
    );
    assert!(
        TlsLimitsBuilder::new()
            .maximum_extensions_per_hello(0)
            .build()
            .is_err()
    );
    assert!(
        TlsLimitsBuilder::new()
            .maximum_extensions_per_hello(5000)
            .build()
            .is_err()
    );
    assert!(
        TlsLimitsBuilder::new()
            .maximum_diagnostics_per_packet(0)
            .build()
            .is_err()
    );
    assert!(
        TlsLimitsBuilder::new()
            .maximum_diagnostics_per_packet(500)
            .build()
            .is_err()
    );
}

#[test]
fn test_synthetic_tls_fixtures() {
    let fixtures = [
        ("client_hello_tls13.tls", TlsPacketDisposition::Parsed),
        ("client_hello_tls12.tls", TlsPacketDisposition::Parsed),
        ("server_hello_tls13.tls", TlsPacketDisposition::Parsed),
        ("server_hello_tls12.tls", TlsPacketDisposition::Parsed),
        ("hello_retry_request.tls", TlsPacketDisposition::Parsed),
        ("sni_example.tls", TlsPacketDisposition::Parsed),
        ("alpn_h2_http11.tls", TlsPacketDisposition::Parsed),
        ("multi_record_handshake.tls", TlsPacketDisposition::Parsed),
        ("truncated_record.tls", TlsPacketDisposition::Partial),
        ("truncated_handshake.tls", TlsPacketDisposition::Partial),
        ("duplicate_extension.tls", TlsPacketDisposition::Partial),
        ("tls10_unsupported.tls", TlsPacketDisposition::Partial),
    ];

    let limits = TlsLimits::default();

    for (file_name, expected_disp) in fixtures {
        let path = format!("tests/fixtures/tls/{file_name}");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        let packet = make_tls_packet(54321, 443, bytes);
        let outcome = parse_tls_packet(&packet, &limits);
        assert_eq!(
            outcome.disposition, expected_disp,
            "failed fixture {file_name}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_arbitrary_tcp_443_bytes_never_panic(
        src_port in 1u16..=65535,
        dst_port in 1u16..=65535,
        payload in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let packet = make_tls_packet(src_port, dst_port, payload);
        let limits = TlsLimits::default();
        let outcome = parse_tls_packet(&packet, &limits);
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
        for obs in &outcome.observations {
            if let Some(ref ch) = obs.client_hello {
                prop_assert!(ch.cipher_suites.len() <= limits.maximum_cipher_suites_per_client_hello);
                prop_assert!(ch.extensions.len() <= limits.maximum_extensions_per_hello);
                if let Some(ref sni) = ch.server_name {
                    prop_assert!(sni.len() <= limits.maximum_server_name_bytes);
                }
            }
        }
    }

    #[test]
    fn prop_deterministic_outcome(
        payload in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let packet1 = make_tls_packet(54321, 443, payload.clone());
        let packet2 = make_tls_packet(54321, 443, payload);
        let limits = TlsLimits::default();
        let out1 = parse_tls_packet(&packet1, &limits);
        let out2 = parse_tls_packet(&packet2, &limits);
        prop_assert_eq!(out1, out2);
    }
}
