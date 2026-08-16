use pcapraven_domain::{
    EthernetMetadata, HttpContentLengthState, HttpDiagnosticKind, HttpMessageKind,
    HttpObservationCompleteness, HttpVersion, Ipv4Metadata, MacAddress, NetworkLayer,
    NormalizedPacket, PacketCompleteness, PacketReference, PacketTimestamp, TcpFlags, TcpMetadata,
    TransportLayer,
};
use pcapraven_protocols::{
    HttpLimits, HttpLimitsBuilder, HttpPacketDisposition, parse_http_packet,
};
use proptest::prelude::*;

fn make_tcp_packet(src_port: u16, dst_port: u16, payload: Vec<u8>) -> NormalizedPacket {
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
fn test_simple_http_get_request() {
    let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);

    let obs = &outcome.observations[0];
    assert_eq!(obs.version, HttpVersion::Http11);
    assert_eq!(obs.message_kind, HttpMessageKind::Request);
    assert_eq!(obs.completeness, HttpObservationCompleteness::Complete);
    assert_eq!(obs.declared_field_count, 2);

    let req = obs.request.as_ref().unwrap();
    assert_eq!(req.method.as_bytes(), b"GET");
    assert_eq!(req.target.as_bytes(), b"/index.html");
    assert_eq!(
        obs.headers.host.as_ref().unwrap().as_bytes(),
        b"example.com"
    );
    assert_eq!(
        obs.headers.user_agent.as_ref().unwrap().as_bytes(),
        b"curl/7.68.0"
    );
    assert!(obs.response.is_none());
}

#[test]
fn test_simple_http_response() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 12\r\nServer: Apache\r\n\r\nHello World!";
    let packet = make_tcp_packet(80, 54321, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);

    let obs = &outcome.observations[0];
    assert_eq!(obs.version, HttpVersion::Http11);
    assert_eq!(obs.message_kind, HttpMessageKind::Response);
    assert_eq!(obs.completeness, HttpObservationCompleteness::Complete);
    assert_eq!(obs.declared_field_count, 3);

    let resp = obs.response.as_ref().unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(
        obs.headers.content_type.as_ref().unwrap().as_bytes(),
        b"text/html; charset=utf-8"
    );
    assert_eq!(
        obs.headers.content_length,
        HttpContentLengthState::Present(12)
    );
    assert_eq!(obs.headers.server.as_ref().unwrap().as_bytes(), b"Apache");
    assert!(obs.request.is_none());
}

#[test]
fn test_http10_request_and_response() {
    let raw_req = b"GET / HTTP/1.0\r\n\r\n";
    let packet_req = make_tcp_packet(54321, 80, raw_req.to_vec());
    let limits = HttpLimits::default();

    let outcome_req = parse_http_packet(&packet_req, &limits);
    assert_eq!(outcome_req.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(outcome_req.observations.len(), 1);
    assert_eq!(outcome_req.observations[0].version, HttpVersion::Http10);

    let raw_resp = b"HTTP/1.0 404 Not Found\r\n\r\n";
    let packet_resp = make_tcp_packet(80, 54321, raw_resp.to_vec());
    let outcome_resp = parse_http_packet(&packet_resp, &limits);
    assert_eq!(outcome_resp.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(
        outcome_resp.observations[0]
            .response
            .as_ref()
            .unwrap()
            .status_code,
        404
    );
}

#[test]
fn test_sensitive_headers_presence_flags_only() {
    let raw = b"GET /secret HTTP/1.1\r\nHost: secret.corp\r\nAuthorization: Basic dXNlcjpwYXNz\r\nProxy-Authorization: Negotiate YWJj\r\nCookie: session=12345; user=admin\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    let obs = &outcome.observations[0];
    assert!(obs.headers.has_authorization);
    assert!(obs.headers.has_proxy_authorization);
    assert!(obs.headers.has_cookie);
    assert!(!obs.headers.has_set_cookie);

    let raw_resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=xyz; Secure; HttpOnly\r\n\r\n";
    let packet_resp = make_tcp_packet(80, 54321, raw_resp.to_vec());
    let outcome_resp = parse_http_packet(&packet_resp, &limits);
    assert_eq!(outcome_resp.disposition, HttpPacketDisposition::Parsed);
    assert!(outcome_resp.observations[0].headers.has_set_cookie);
}

#[test]
fn test_framing_and_chunked_metadata() {
    let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    let obs = &outcome.observations[0];
    assert!(obs.framing.is_chunked);
    assert!(obs.framing.is_keep_alive);
    assert!(!obs.framing.is_close);
    assert!(!obs.framing.has_conflicting_framing);
}

#[test]
fn test_upgrade_and_close_connection() {
    let raw = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    let obs = &outcome.observations[0];
    assert!(obs.framing.is_upgrade);
    assert_eq!(
        obs.headers.upgrade.as_ref().unwrap().as_bytes(),
        b"websocket"
    );

    let raw_close = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let packet_close = make_tcp_packet(54321, 80, raw_close.to_vec());
    let outcome_close = parse_http_packet(&packet_close, &limits);
    assert!(outcome_close.observations[0].framing.is_close);
}

#[test]
fn test_conflicting_framing_te_and_cl() {
    let raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(outcome.diagnostics.iter().any(|d| {
        d.message
            .contains("conflicting Transfer-Encoding and Content-Length")
    }));
    assert!(outcome.observations[0].framing.has_conflicting_framing);
}

#[test]
fn test_http11_missing_host_header_rejected() {
    let raw = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("missing mandatory Host header"))
    );
}

#[test]
fn test_duplicate_host_header_rejected() {
    let raw = b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("duplicate Host header"))
    );
}

#[test]
fn test_content_length_parsing_and_duplicates() {
    let limits = HttpLimits::default();

    // Invalid non-digit
    let raw_bad = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: abc\r\n\r\n";
    let pkt_bad = make_tcp_packet(54321, 80, raw_bad.to_vec());
    let out_bad = parse_http_packet(&pkt_bad, &limits);
    assert_eq!(out_bad.disposition, HttpPacketDisposition::Partial);
    assert_eq!(
        out_bad.observations[0].headers.content_length,
        HttpContentLengthState::Invalid
    );

    // Duplicate identical (valid per RFC 9110)
    let raw_dup =
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\nContent-Length: 42\r\n\r\n";
    let pkt_dup = make_tcp_packet(54321, 80, raw_dup.to_vec());
    let out_dup = parse_http_packet(&pkt_dup, &limits);
    assert_eq!(out_dup.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(
        out_dup.observations[0].headers.content_length,
        HttpContentLengthState::Present(42)
    );

    // Duplicate conflicting
    let raw_conflict =
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\nContent-Length: 99\r\n\r\n";
    let pkt_conflict = make_tcp_packet(54321, 80, raw_conflict.to_vec());
    let out_conflict = parse_http_packet(&pkt_conflict, &limits);
    assert_eq!(out_conflict.disposition, HttpPacketDisposition::Partial);
    assert_eq!(
        out_conflict.observations[0].headers.content_length,
        HttpContentLengthState::Invalid
    );
}

#[test]
fn test_obs_fold_unsupported() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: foo\r\n bar\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("obs-fold"))
    );
}

#[test]
fn test_http2_preface_unsupported() {
    let raw = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(outcome.diagnostics.iter().any(|d| {
        d.message
            .contains("HTTP/2 connection preface is unsupported")
    }));
}

#[test]
fn test_bare_cr_or_bare_lf_rejected() {
    let limits = HttpLimits::default();

    // Bare LF in start line
    let raw_lf = b"GET / HTTP/1.1\nHost: example.com\r\n\r\n";
    let pkt_lf = make_tcp_packet(54321, 80, raw_lf.to_vec());
    let out_lf = parse_http_packet(&pkt_lf, &limits);
    assert_eq!(out_lf.disposition, HttpPacketDisposition::Partial);
    assert!(
        out_lf
            .diagnostics
            .iter()
            .any(|d| d.message.contains("bare LF"))
    );

    // Bare CR in header line
    let raw_cr = b"GET / HTTP/1.1\r\nHost: example.com\rUser-Agent: test\r\n\r\n";
    let pkt_cr = make_tcp_packet(54321, 80, raw_cr.to_vec());
    let out_cr = parse_http_packet(&pkt_cr, &limits);
    assert_eq!(out_cr.disposition, HttpPacketDisposition::Partial);
    assert!(
        out_cr
            .diagnostics
            .iter()
            .any(|d| d.message.contains("bare CR"))
    );
}

#[test]
fn test_whitespace_before_colon_rejected() {
    let raw = b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(outcome.diagnostics.iter().any(|d| {
        d.message
            .contains("invalid characters or whitespace in HTTP header field name")
    }));
}

#[test]
fn test_non_candidate_packets() {
    let limits = HttpLimits::default();

    // UDP port 80
    let mut pkt_udp = make_tcp_packet(54321, 80, b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n".to_vec());
    pkt_udp.transport_layer = Some(TransportLayer::Udp(pcapraven_domain::UdpMetadata {
        source_port: 54321,
        destination_port: 80,
        length: 20,
        checksum: 0,
    }));
    let out_udp = parse_http_packet(&pkt_udp, &limits);
    assert_eq!(out_udp.disposition, HttpPacketDisposition::NotHttpCandidate);

    // TCP port 443
    let pkt_tls = make_tcp_packet(
        54321,
        443,
        b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n".to_vec(),
    );
    let out_tls = parse_http_packet(&pkt_tls, &limits);
    assert_eq!(out_tls.disposition, HttpPacketDisposition::NotHttpCandidate);

    // TCP port 80 empty payload
    let pkt_empty = make_tcp_packet(54321, 80, Vec::new());
    let out_empty = parse_http_packet(&pkt_empty, &limits);
    assert_eq!(
        out_empty.disposition,
        HttpPacketDisposition::CandidateWithoutMessage
    );

    // TCP port 80 non-HTTP binary payload
    let pkt_binary = make_tcp_packet(54321, 80, vec![0x00, 0x01, 0x02, 0x03]);
    let out_binary = parse_http_packet(&pkt_binary, &limits);
    assert_eq!(
        out_binary.disposition,
        HttpPacketDisposition::CandidateWithoutMessage
    );
}

#[test]
fn test_missing_network_layer_produces_no_fake_endpoints() {
    let mut packet = make_tcp_packet(54321, 80, b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n".to_vec());
    packet.network_layer = None;
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(outcome.observations.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("missing network layer"))
    );
}

#[test]
fn test_terminal_safe_escaping() {
    let raw = b"GET /\x1b[31mattack\x00\\ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    // target has control characters, so it gets rejected by parse_start_line as Malformed
    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == HttpDiagnosticKind::Malformed)
    );

    // Test HttpByteString escaping directly
    let bs = pcapraven_domain::HttpByteString::new(b"hello \x1b[31mworld\x00\\".to_vec());
    let escaped = bs.display_escaped();
    assert_eq!(escaped, "hello \\x1b[31mworld\\x00\\\\");
}

#[test]
fn test_limits_builder_validation() {
    assert!(
        HttpLimitsBuilder::new()
            .maximum_start_line_bytes(0)
            .build()
            .is_err()
    );
    assert!(
        HttpLimitsBuilder::new()
            .maximum_start_line_bytes(100_000)
            .build()
            .is_err()
    );
    assert!(
        HttpLimitsBuilder::new()
            .maximum_header_fields(0)
            .build()
            .is_err()
    );
    assert!(
        HttpLimitsBuilder::new()
            .maximum_header_fields(2000)
            .build()
            .is_err()
    );
    assert!(
        HttpLimitsBuilder::new()
            .maximum_diagnostics_per_packet(0)
            .build()
            .is_err()
    );
    assert!(
        HttpLimitsBuilder::new()
            .maximum_diagnostics_per_packet(500)
            .build()
            .is_err()
    );
}

#[test]
fn test_header_fields_limit_enforced() {
    let mut raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n".to_vec();
    for i in 0..5 {
        raw.extend_from_slice(format!("X-Header-{i}: value\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");

    let packet = make_tcp_packet(54321, 80, raw);

    // Limit 10 headers -> Complete
    let limits_10 = HttpLimitsBuilder::new()
        .maximum_header_fields(10)
        .build()
        .unwrap();
    let outcome_10 = parse_http_packet(&packet, &limits_10);
    assert_eq!(outcome_10.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(outcome_10.observations[0].declared_field_count, 6);

    // Limit 3 headers -> Partial with ResourceLimit
    let limits_3 = HttpLimitsBuilder::new()
        .maximum_header_fields(3)
        .build()
        .unwrap();
    let outcome_3 = parse_http_packet(&packet, &limits_3);
    assert_eq!(outcome_3.disposition, HttpPacketDisposition::Partial);
    assert!(
        outcome_3
            .diagnostics
            .iter()
            .any(|d| d.kind == HttpDiagnosticKind::ResourceLimit)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn arbitrary_tcp_bytes_never_panic(
        src_port in 1u16..=65535,
        dst_port in 1u16..=65535,
        payload in prop::collection::vec(any::<u8>(), 0..2048)
    ) {
        let packet = make_tcp_packet(src_port, dst_port, payload);
        let limits = HttpLimits::default();
        let outcome = parse_http_packet(&packet, &limits);
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    }
}
