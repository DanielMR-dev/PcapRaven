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

fn build_tls_record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(content_type);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn build_client_hello_msg(ciphers: &[u16], extensions: &[u8]) -> Vec<u8> {
    let mut msg_body = Vec::new();
    msg_body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    msg_body.extend_from_slice(&[0xaa; 32]); // random
    msg_body.push(0x00); // session_id_len = 0
    let ciphers_len = (ciphers.len() * 2) as u16;
    msg_body.extend_from_slice(&ciphers_len.to_be_bytes());
    for &c in ciphers {
        msg_body.extend_from_slice(&c.to_be_bytes());
    }
    msg_body.extend_from_slice(&[0x01, 0x00]); // compression = null
    if !extensions.is_empty() {
        let ext_len = extensions.len() as u16;
        msg_body.extend_from_slice(&ext_len.to_be_bytes());
        msg_body.extend_from_slice(extensions);
    }

    let mut msg = Vec::new();
    msg.push(1); // ClientHello
    let msg_len = msg_body.len() as u32;
    msg.push((msg_len >> 16) as u8);
    msg.push((msg_len >> 8) as u8);
    msg.push(msg_len as u8);
    msg.extend_from_slice(&msg_body);
    msg
}

fn build_server_hello_msg(
    legacy_ver: u16,
    random: &[u8; 32],
    cipher: u16,
    extensions: &[u8],
) -> Vec<u8> {
    let mut msg_body = Vec::new();
    msg_body.extend_from_slice(&legacy_ver.to_be_bytes());
    msg_body.extend_from_slice(random);
    msg_body.push(0x00); // session_id_echo_length
    msg_body.extend_from_slice(&cipher.to_be_bytes());
    msg_body.push(0x00); // compression_method = 0
    if !extensions.is_empty() {
        let ext_len = extensions.len() as u16;
        msg_body.extend_from_slice(&ext_len.to_be_bytes());
        msg_body.extend_from_slice(extensions);
    }

    let mut msg = Vec::new();
    msg.push(2); // ServerHello
    let msg_len = msg_body.len() as u32;
    msg.push((msg_len >> 16) as u8);
    msg.push((msg_len >> 8) as u8);
    msg.push(msg_len as u8);
    msg.extend_from_slice(&msg_body);
    msg
}

// 1. Handshake message limit exact N
#[test]
fn test_reg_01_handshake_message_limit_exact_n() {
    let msg = build_client_hello_msg(&[0x1301], &[]);
    let mut payload = Vec::new();
    for _ in 0..3 {
        payload.extend_from_slice(&build_tls_record(22, 0x0303, &msg));
    }
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimitsBuilder::new()
        .maximum_handshake_messages_per_packet(3)
        .build()
        .unwrap();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 3);
    assert!(
        !outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::ResourceLimit)
    );
}

// 2. Handshake message limit N+1 across MULTIPLE records
#[test]
fn test_reg_02_handshake_message_limit_n_plus_one_across_multiple_records() {
    let msg = build_client_hello_msg(&[0x1301], &[]);
    let mut payload = Vec::new();
    // Record 1: 2 messages, Record 2: 2 messages (total 4 messages)
    let mut rec1_body = Vec::new();
    rec1_body.extend_from_slice(&msg);
    rec1_body.extend_from_slice(&msg);
    payload.extend_from_slice(&build_tls_record(22, 0x0303, &rec1_body));

    let mut rec2_body = Vec::new();
    rec2_body.extend_from_slice(&msg);
    rec2_body.extend_from_slice(&msg);
    payload.extend_from_slice(&build_tls_record(22, 0x0303, &rec2_body));

    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimitsBuilder::new()
        .maximum_handshake_messages_per_packet(3)
        .build()
        .unwrap();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(outcome.observations.len(), 3);
    assert!(outcome.diagnostics.iter().any(|d| {
        d.kind == TlsDiagnosticKind::ResourceLimit
            && d.message
                .contains("maximum handshake messages per packet limit")
    }));
}

// 3. Message A complete + message B partial in one record, continuation of B in next record, A emitted exactly once
#[test]
fn test_reg_03_assembly_a_complete_b_partial_then_b_continuation_emits_a_once() {
    let msg_a = build_client_hello_msg(&[0x1301], &[]);
    let msg_b = build_client_hello_msg(&[0x1302], &[]);

    let (b_first, b_second) = msg_b.split_at(15);

    let mut rec1_body = Vec::new();
    rec1_body.extend_from_slice(&msg_a);
    rec1_body.extend_from_slice(b_first);
    let rec1 = build_tls_record(22, 0x0303, &rec1_body);

    let rec2 = build_tls_record(22, 0x0303, b_second);

    let mut payload = Vec::new();
    payload.extend_from_slice(&rec1);
    payload.extend_from_slice(&rec2);

    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();
    let outcome = parse_tls_packet(&packet, &limits);

    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 2);
    assert_eq!(
        outcome.observations[0]
            .client_hello
            .as_ref()
            .unwrap()
            .cipher_suites,
        vec![0x1301]
    );
    assert_eq!(
        outcome.observations[1]
            .client_hello
            .as_ref()
            .unwrap()
            .cipher_suites,
        vec![0x1302]
    );
}

// 4. A+B complete + C partial, C continuation, A/B never duplicated
#[test]
fn test_reg_04_assembly_ab_complete_c_partial_then_c_continuation_no_duplicates() {
    let msg_a = build_client_hello_msg(&[0x1301], &[]);
    let msg_b = build_client_hello_msg(&[0x1302], &[]);
    let msg_c = build_client_hello_msg(&[0x1303], &[]);

    let (c_first, c_second) = msg_c.split_at(10);

    let mut rec1_body = Vec::new();
    rec1_body.extend_from_slice(&msg_a);
    rec1_body.extend_from_slice(&msg_b);
    rec1_body.extend_from_slice(c_first);
    let rec1 = build_tls_record(22, 0x0303, &rec1_body);

    let rec2 = build_tls_record(22, 0x0303, c_second);

    let mut payload = Vec::new();
    payload.extend_from_slice(&rec1);
    payload.extend_from_slice(&rec2);

    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();
    let outcome = parse_tls_packet(&packet, &limits);

    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 3);
    assert_eq!(
        outcome.observations[0]
            .client_hello
            .as_ref()
            .unwrap()
            .cipher_suites,
        vec![0x1301]
    );
    assert_eq!(
        outcome.observations[1]
            .client_hello
            .as_ref()
            .unwrap()
            .cipher_suites,
        vec![0x1302]
    );
    assert_eq!(
        outcome.observations[2]
            .client_hello
            .as_ref()
            .unwrap()
            .cipher_suites,
        vec![0x1303]
    );
}

// 5. Key-share count exactly N
#[test]
fn test_reg_05_key_share_count_exact_n() {
    // KeyShare extension (51) with 2 entries (each entry: group u16, key_exchange_len u16, key_exchange bytes)
    let mut ks_data = Vec::new();
    let list_len = (4 + 8) * 2; // 2 entries with 8-byte key each
    ks_data.extend_from_slice(&(list_len as u16).to_be_bytes());
    // Entry 1: group 0x001d, key_len 8
    ks_data.extend_from_slice(&[0x00, 0x1d, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]);
    // Entry 2: group 0x0017, key_len 8
    ks_data.extend_from_slice(&[0x00, 0x17, 0x00, 0x08, 9, 10, 11, 12, 13, 14, 15, 16]);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x33]); // 51
    ext.extend_from_slice(&(ks_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ks_data);

    let msg = build_client_hello_msg(&[0x1301], &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimitsBuilder::new()
        .maximum_key_share_entries(2)
        .build()
        .unwrap();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Complete
    );
    let ch = outcome.observations[0].client_hello.as_ref().unwrap();
    assert_eq!(ch.key_share_groups, vec![0x001d, 0x0017]);
}

// 6. Key-share count N+1: Partial + ResourceLimit
#[test]
fn test_reg_06_key_share_count_n_plus_one() {
    let mut ks_data = Vec::new();
    let list_len = (4 + 8) * 3; // 3 entries
    ks_data.extend_from_slice(&(list_len as u16).to_be_bytes());
    ks_data.extend_from_slice(&[0x00, 0x1d, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]);
    ks_data.extend_from_slice(&[0x00, 0x17, 0x00, 0x08, 9, 10, 11, 12, 13, 14, 15, 16]);
    ks_data.extend_from_slice(&[0x00, 0x18, 0x00, 0x08, 17, 18, 19, 20, 21, 22, 23, 24]);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x33]); // 51
    ext.extend_from_slice(&(ks_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ks_data);

    let msg = build_client_hello_msg(&[0x1301], &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimitsBuilder::new()
        .maximum_key_share_entries(2)
        .build()
        .unwrap();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Partial
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::ResourceLimit
                && d.message.contains("key_share count exceeds limit"))
    );
    let ch = outcome.observations[0].client_hello.as_ref().unwrap();
    assert_eq!(ch.key_share_groups, vec![0x001d, 0x0017]);
}

// 7. SNI one host_name
#[test]
fn test_reg_07_sni_one_host_name() {
    let hostname = b"example.org";
    let mut sni_data = Vec::new();
    let list_len = 3 + hostname.len();
    sni_data.extend_from_slice(&(list_len as u16).to_be_bytes());
    sni_data.push(0x00); // host_name
    sni_data.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(hostname);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]); // SNI
    ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_data);

    let msg = build_client_hello_msg(&[0x1301], &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    let ch = outcome.observations[0].client_hello.as_ref().unwrap();
    assert_eq!(ch.server_name.as_ref().unwrap().as_bytes(), b"example.org");
}

// 8. SNI multiple host_name entries: no silent collapse
#[test]
fn test_reg_08_sni_multiple_host_name_entries_rejected() {
    let h1 = b"first.org";
    let h2 = b"second.org";
    let mut sni_data = Vec::new();
    let list_len = (3 + h1.len()) + (3 + h2.len());
    sni_data.extend_from_slice(&(list_len as u16).to_be_bytes());
    // entry 1
    sni_data.push(0x00);
    sni_data.extend_from_slice(&(h1.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(h1);
    // entry 2
    sni_data.push(0x00);
    sni_data.extend_from_slice(&(h2.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(h2);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_data);

    let msg = build_client_hello_msg(&[0x1301], &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Partial
    );
    assert!(outcome.diagnostics.iter().any(
        |d| d.kind == TlsDiagnosticKind::Malformed && d.message.contains("duplicate host_name")
    ));
}

// 9. SNI unknown NameType + valid structural continuation
#[test]
fn test_reg_09_sni_unknown_name_type_with_valid_continuation() {
    let unk_data = b"unknown_name_type_bytes";
    let h2 = b"target.org";
    let mut sni_data = Vec::new();
    let list_len = (3 + unk_data.len()) + (3 + h2.len());
    sni_data.extend_from_slice(&(list_len as u16).to_be_bytes());
    // entry 1: name_type 5 (unknown)
    sni_data.push(0x05);
    sni_data.extend_from_slice(&(unk_data.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(unk_data);
    // entry 2: name_type 0 (host_name)
    sni_data.push(0x00);
    sni_data.extend_from_slice(&(h2.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(h2);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_data);

    let msg = build_client_hello_msg(&[0x1301], &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    let ch = outcome.observations[0].client_hello.as_ref().unwrap();
    assert_eq!(ch.server_name.as_ref().unwrap().as_bytes(), b"target.org");
}

// 10. Oversized complete ApplicationData record > 18,432
#[test]
fn test_reg_10_oversized_complete_application_data_record() {
    let oversized_len = 18_433usize;
    let body = vec![0x00; oversized_len];
    let payload = build_tls_record(23, 0x0303, &body);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert!(outcome.observations.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::ResourceLimit
                && d.message.contains("maximum fragment limit"))
    );
}

// 11. Oversized complete Handshake record > 16,384
#[test]
fn test_reg_11_oversized_complete_handshake_record() {
    let oversized_len = 16_385usize;
    let body = vec![0x00; oversized_len];
    let payload = build_tls_record(22, 0x0303, &body);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert!(outcome.observations.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::ResourceLimit
                && d.message.contains("16384-byte protocol limit"))
    );
}

// 12. ServerHello selecting TLS 1.0 through supported_versions
#[test]
fn test_reg_12_server_hello_selecting_tls10_through_supported_versions() {
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x01]); // 43, len 2, TLS 1.0 (0x0301)
    let random = [0x11; 32];
    let msg = build_server_hello_msg(0x0303, &random, 0x1301, &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(443, 54321, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Partial
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::Unsupported && d.message.contains("TLS 1.0"))
    );
}

// 13. ServerHello selecting TLS 1.1 through supported_versions
#[test]
fn test_reg_13_server_hello_selecting_tls11_through_supported_versions() {
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x02]); // 43, len 2, TLS 1.1 (0x0302)
    let random = [0x11; 32];
    let msg = build_server_hello_msg(0x0303, &random, 0x1301, &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(443, 54321, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Partial
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::Unsupported && d.message.contains("TLS 1.1"))
    );
}

// 14. ServerHello selecting unknown version through supported_versions
#[test]
fn test_reg_14_server_hello_selecting_unknown_version_through_supported_versions() {
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x09, 0x99]); // 43, len 2, Unknown 0x0999
    let random = [0x11; 32];
    let msg = build_server_hello_msg(0x0303, &random, 0x1301, &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(443, 54321, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Partial
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == TlsDiagnosticKind::Unsupported)
    );
}

// 15. TLS 1.3 ServerHello containing ALPN: no selected_alpn
#[test]
fn test_reg_15_tls13_server_hello_containing_alpn_rejected() {
    let mut ext = Vec::new();
    // supported_versions = TLS 1.3 (0x0304)
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    // ALPN = "h2"
    ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);

    let random = [0x11; 32];
    let msg = build_server_hello_msg(0x0303, &random, 0x1301, &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(443, 54321, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Partial
    );
    let sh = outcome.observations[0].server_hello.as_ref().unwrap();
    assert!(sh.selected_alpn.is_none());
    assert!(outcome.diagnostics.iter().any(|d| {
        d.kind == TlsDiagnosticKind::Malformed
            && d.message
                .contains("ALPN extension in TLS 1.3 ServerHello is invalid")
    }));
}

// 16. TLS 1.2 ServerHello valid ALPN still works
#[test]
fn test_reg_16_tls12_server_hello_valid_alpn_accepted() {
    let mut ext = Vec::new();
    // ALPN = "http/1.1"
    let proto = b"http/1.1";
    let list_len = (1 + proto.len()) as u16;
    let ext_len = 2 + list_len;
    ext.extend_from_slice(&[0x00, 0x10]);
    ext.extend_from_slice(&ext_len.to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.push(proto.len() as u8);
    ext.extend_from_slice(proto);

    let random = [0x11; 32];
    let msg = build_server_hello_msg(0x0303, &random, 0x002f, &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(443, 54321, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Parsed);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Complete
    );
    let sh = outcome.observations[0].server_hello.as_ref().unwrap();
    assert_eq!(sh.selected_alpn.as_ref().unwrap().as_bytes(), b"http/1.1");
}

// 17. Complete Hello followed by bad later record: observation Complete, packet Partial
#[test]
fn test_reg_17_complete_hello_followed_by_bad_later_record() {
    let msg = build_client_hello_msg(&[0x1301], &[]);
    let rec1 = build_tls_record(22, 0x0303, &msg);
    // Bad truncated record header: 2 bytes
    let rec2 = vec![22, 3];

    let mut payload = Vec::new();
    payload.extend_from_slice(&rec1);
    payload.extend_from_slice(&rec2);

    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(outcome.observations.len(), 1);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Complete
    );
}

// 18. Malformed Hello itself: observation Partial
#[test]
fn test_reg_18_malformed_hello_itself_is_partial() {
    let mut ext = Vec::new();
    // duplicate SNI extension
    ext.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    ext.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let msg = build_client_hello_msg(&[0x1301], &ext);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let outcome = parse_tls_packet(&packet, &limits);
    assert_eq!(outcome.disposition, TlsPacketDisposition::Partial);
    assert_eq!(outcome.observations.len(), 1);
    assert_eq!(
        outcome.observations[0].completeness,
        TlsObservationCompleteness::Partial
    );
}

// 19. Identical input remains deterministic
#[test]
fn test_reg_19_identical_input_remains_deterministic() {
    let msg = build_client_hello_msg(&[0x1301, 0x1302], &[]);
    let payload = build_tls_record(22, 0x0303, &msg);
    let packet1 = make_tls_packet(54321, 443, payload.clone());
    let packet2 = make_tls_packet(54321, 443, payload);
    let limits = TlsLimits::default();

    let out1 = parse_tls_packet(&packet1, &limits);
    let out2 = parse_tls_packet(&packet2, &limits);
    assert_eq!(out1, out2);
}

// 20. observations.len() <= effective per-packet handshake-message limit
#[test]
fn test_reg_20_observations_bounded_by_message_limit() {
    let msg = build_client_hello_msg(&[0x1301], &[]);
    let mut payload = Vec::new();
    for _ in 0..10 {
        payload.extend_from_slice(&build_tls_record(22, 0x0303, &msg));
    }
    let packet = make_tls_packet(54321, 443, payload);
    let limits = TlsLimitsBuilder::new()
        .maximum_handshake_messages_per_packet(2)
        .build()
        .unwrap();

    let outcome = parse_tls_packet(&packet, &limits);
    assert!(outcome.observations.len() <= 2);
    assert_eq!(outcome.observations.len(), 2);
}
