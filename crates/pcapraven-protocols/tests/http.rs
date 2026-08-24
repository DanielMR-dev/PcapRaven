use pcapraven_domain::{
    EthernetMetadata, HttpContentLengthState, HttpDiagnosticKind, HttpMessageKind,
    HttpObservationCompleteness, HttpVersion, Ipv4Metadata, MacAddress, NetworkLayer,
    NormalizedPacket, PacketCompleteness, PacketReference, PacketTimestamp, PacketTruncationReason,
    TcpFlags, TcpMetadata, TransportLayer,
};
use pcapraven_protocols::{
    HttpLimits, HttpLimitsBuilder, HttpPacketDisposition, MAX_ALLOWED_HTTP_DIAGNOSTICS_PER_PACKET,
    MAX_ALLOWED_HTTP_HEADER_FIELDS, MAX_ALLOWED_HTTP_HEADER_LINE_BYTES,
    MAX_ALLOWED_HTTP_HEADER_SECTION_BYTES, MAX_ALLOWED_HTTP_METHOD_BYTES,
    MAX_ALLOWED_HTTP_REQUEST_TARGET_BYTES, MAX_ALLOWED_HTTP_SELECTED_FIELD_VALUE_BYTES,
    MAX_ALLOWED_HTTP_START_LINE_BYTES, parse_http_packet,
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
fn test_status_line_second_sp_strictness() {
    let limits = HttpLimits::default();

    // Valid: 200 followed by SP and empty reason-phrase
    let raw_valid = b"HTTP/1.1 200 \r\n\r\n";
    let pkt_valid = make_tcp_packet(80, 54321, raw_valid.to_vec());
    let out_valid = parse_http_packet(&pkt_valid, &limits);
    assert_eq!(out_valid.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(out_valid.observations[0].response.unwrap().status_code, 200);

    // Malformed: 200 followed immediately by CRLF without second SP
    let raw_malformed = b"HTTP/1.1 200\r\n\r\n";
    let pkt_malformed = make_tcp_packet(80, 54321, raw_malformed.to_vec());
    let out_malformed = parse_http_packet(&pkt_malformed, &limits);
    assert_eq!(out_malformed.disposition, HttpPacketDisposition::Partial);
    assert!(
        out_malformed
            .diagnostics
            .iter()
            .any(|d| d.message.contains("missing second space after status code"))
    );
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
    let rendered = format!("{outcome_resp:?}");
    assert!(!rendered.contains("session=xyz"));
    assert!(!rendered.contains("Secure"));
    assert!(!rendered.contains("HttpOnly"));
}

#[test]
fn phase18_all_http_limit_hard_caps_accept_n_minus_1_and_n_but_reject_n_plus_1() {
    macro_rules! assert_boundary {
        ($setter:ident, $maximum:expr) => {{
            let maximum = $maximum;
            assert!(
                HttpLimitsBuilder::new()
                    .$setter(maximum - 1)
                    .build()
                    .is_ok()
            );
            assert!(HttpLimitsBuilder::new().$setter(maximum).build().is_ok());
            assert!(
                HttpLimitsBuilder::new()
                    .$setter(maximum + 1)
                    .build()
                    .is_err()
            );
        }};
    }

    assert_boundary!(maximum_start_line_bytes, MAX_ALLOWED_HTTP_START_LINE_BYTES);
    assert_boundary!(
        maximum_header_line_bytes,
        MAX_ALLOWED_HTTP_HEADER_LINE_BYTES
    );
    assert_boundary!(
        maximum_header_section_bytes,
        MAX_ALLOWED_HTTP_HEADER_SECTION_BYTES
    );
    assert_boundary!(maximum_header_fields, MAX_ALLOWED_HTTP_HEADER_FIELDS);
    assert_boundary!(maximum_method_bytes, MAX_ALLOWED_HTTP_METHOD_BYTES);
    assert_boundary!(
        maximum_request_target_bytes,
        MAX_ALLOWED_HTTP_REQUEST_TARGET_BYTES
    );
    assert_boundary!(
        maximum_selected_field_value_bytes,
        MAX_ALLOWED_HTTP_SELECTED_FIELD_VALUE_BYTES
    );
    assert_boundary!(
        maximum_diagnostics_per_packet,
        MAX_ALLOWED_HTTP_DIAGNOSTICS_PER_PACKET
    );
}

#[test]
fn phase18_http_parser_limits_cover_n_minus_1_n_n_plus_1() {
    let raw = b"GET /abc HTTP/1.1\r\nHost: abc\r\nX-Test: x\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let start_line_bytes = b"GET /abc HTTP/1.1".len();
    let header_line_bytes = b"X-Test: x".len();
    let section_bytes = raw.len();

    for (limit, parsed) in [
        (start_line_bytes - 1, false),
        (start_line_bytes, true),
        (start_line_bytes + 1, true),
    ] {
        let limits = HttpLimitsBuilder::new()
            .maximum_start_line_bytes(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_http_packet(&packet, &limits).disposition == HttpPacketDisposition::Parsed,
            parsed
        );
    }
    for (limit, parsed) in [
        (header_line_bytes - 1, false),
        (header_line_bytes, true),
        (header_line_bytes + 1, true),
    ] {
        let limits = HttpLimitsBuilder::new()
            .maximum_header_line_bytes(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_http_packet(&packet, &limits).disposition == HttpPacketDisposition::Parsed,
            parsed
        );
    }
    for (limit, parsed) in [
        (section_bytes - 1, false),
        (section_bytes, true),
        (section_bytes + 1, true),
    ] {
        let limits = HttpLimitsBuilder::new()
            .maximum_header_section_bytes(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_http_packet(&packet, &limits).disposition == HttpPacketDisposition::Parsed,
            parsed
        );
    }
    for (limit, parsed) in [(1, false), (2, true), (3, true)] {
        let limits = HttpLimitsBuilder::new()
            .maximum_header_fields(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_http_packet(&packet, &limits).disposition == HttpPacketDisposition::Parsed,
            parsed
        );
    }
    for (limit, parsed) in [(2, false), (3, true), (4, true)] {
        let limits = HttpLimitsBuilder::new()
            .maximum_method_bytes(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_http_packet(&packet, &limits).disposition == HttpPacketDisposition::Parsed,
            parsed
        );
    }
    for (limit, parsed) in [(3, false), (4, true), (5, true)] {
        let limits = HttpLimitsBuilder::new()
            .maximum_request_target_bytes(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_http_packet(&packet, &limits).disposition == HttpPacketDisposition::Parsed,
            parsed
        );
    }
    for (limit, parsed) in [(2, false), (3, true), (4, true)] {
        let limits = HttpLimitsBuilder::new()
            .maximum_selected_field_value_bytes(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_http_packet(&packet, &limits).disposition == HttpPacketDisposition::Parsed,
            parsed
        );
    }
}

#[test]
fn test_framing_and_chunked_metadata() {
    let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked; q=1.0\r\nConnection: keep-alive, close\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    let obs = &outcome.observations[0];
    assert!(obs.framing.is_chunked);
    assert!(obs.framing.is_keep_alive);
    assert!(obs.framing.is_close);
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
fn test_duplicate_informational_headers_preserve_first() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: first\r\nUser-Agent: second\r\nServer: s1\r\nServer: s2\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let limits = HttpLimits::default();

    let outcome = parse_http_packet(&packet, &limits);
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    let obs = &outcome.observations[0];
    assert_eq!(
        obs.headers.user_agent.as_ref().unwrap().as_bytes(),
        b"first"
    );
    assert_eq!(obs.headers.server.as_ref().unwrap().as_bytes(), b"s1");
}

#[test]
fn test_content_length_parsing_and_lists() {
    let limits = HttpLimits::default();

    // Comma-separated list identical: valid per RFC 9110 Section 8.6
    let raw_list = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42, 42, 42\r\n\r\n";
    let pkt_list = make_tcp_packet(54321, 80, raw_list.to_vec());
    let out_list = parse_http_packet(&pkt_list, &limits);
    assert_eq!(out_list.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(
        out_list.observations[0].headers.content_length,
        HttpContentLengthState::Present(42)
    );

    // Comma-separated list conflicting
    let raw_list_bad = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42, 43\r\n\r\n";
    let pkt_list_bad = make_tcp_packet(54321, 80, raw_list_bad.to_vec());
    let out_list_bad = parse_http_packet(&pkt_list_bad, &limits);
    assert_eq!(out_list_bad.disposition, HttpPacketDisposition::Partial);
    assert_eq!(
        out_list_bad.observations[0].headers.content_length,
        HttpContentLengthState::Invalid
    );

    // Content-length overflow
    let raw_overflow = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 99999999999999999999999999999999\r\n\r\n";
    let pkt_overflow = make_tcp_packet(54321, 80, raw_overflow.to_vec());
    let out_overflow = parse_http_packet(&pkt_overflow, &limits);
    assert_eq!(out_overflow.disposition, HttpPacketDisposition::Partial);
    assert_eq!(
        out_overflow.observations[0].headers.content_length,
        HttpContentLengthState::Invalid
    );
}

#[test]
fn test_line_scanning_and_section_bounds() {
    // 1. Line budget exactly N vs N+1
    let limits = HttpLimitsBuilder::new()
        .maximum_header_line_bytes(11)
        .maximum_header_section_bytes(100)
        .build()
        .unwrap();

    let raw_exact = b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n";
    let pkt_exact = make_tcp_packet(54321, 80, raw_exact.to_vec());
    let out_exact = parse_http_packet(&pkt_exact, &limits);
    assert_eq!(out_exact.disposition, HttpPacketDisposition::Parsed);

    let raw_line_over = b"GET / HTTP/1.1\r\nHost: a_very_long_host_name.com\r\n\r\n";
    let pkt_line_over = make_tcp_packet(54321, 80, raw_line_over.to_vec());
    let out_line_over = parse_http_packet(&pkt_line_over, &limits);
    assert_eq!(out_line_over.disposition, HttpPacketDisposition::Partial);
    assert!(
        out_line_over
            .diagnostics
            .iter()
            .any(|d| d.kind == HttpDiagnosticKind::ResourceLimit)
    );

    // 2. Whole header section limit exactly N vs N+1
    let total_len = raw_exact.len();
    let limits_exact_sec = HttpLimitsBuilder::new()
        .maximum_header_section_bytes(total_len)
        .build()
        .unwrap();
    let out_sec_exact = parse_http_packet(&pkt_exact, &limits_exact_sec);
    assert_eq!(out_sec_exact.disposition, HttpPacketDisposition::Parsed);

    let limits_sec_minus1 = HttpLimitsBuilder::new()
        .maximum_header_section_bytes(total_len.saturating_sub(1))
        .build()
        .unwrap();
    let out_sec_minus1 = parse_http_packet(&pkt_exact, &limits_sec_minus1);
    assert_eq!(out_sec_minus1.disposition, HttpPacketDisposition::Partial);
    assert!(
        out_sec_minus1
            .diagnostics
            .iter()
            .any(|d| d.kind == HttpDiagnosticKind::ResourceLimit)
    );
}

#[test]
fn test_no_silent_selected_header_truncation() {
    let limits = HttpLimitsBuilder::new()
        .maximum_selected_field_value_bytes(5)
        .build()
        .unwrap();

    let raw = b"GET / HTTP/1.1\r\nHost: toolonghostname.com\r\n\r\n";
    let packet = make_tcp_packet(54321, 80, raw.to_vec());
    let outcome = parse_http_packet(&packet, &limits);

    assert_eq!(outcome.disposition, HttpPacketDisposition::Partial);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == HttpDiagnosticKind::ResourceLimit)
    );
    // Oversized value must NOT be retained
    assert!(outcome.observations[0].headers.host.is_none());
}

#[test]
fn test_complete_headers_with_large_body_payload_budget_exceeded() {
    let raw_headers = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut payload = raw_headers.to_vec();
    payload.extend_from_slice(&[0xaa; 1000]);

    let mut packet = make_tcp_packet(54321, 80, payload);
    packet.completeness = PacketCompleteness::Partial {
        reason: PacketTruncationReason::PayloadBudgetExceeded,
    };

    let limits = HttpLimits::default();
    let outcome = parse_http_packet(&packet, &limits);

    // Headers were fully retained up to \r\n\r\n within the payload slice.
    // Observation must remain Complete!
    assert_eq!(outcome.disposition, HttpPacketDisposition::Parsed);
    assert_eq!(
        outcome.observations[0].completeness,
        HttpObservationCompleteness::Complete
    );
}

#[test]
fn test_synthetic_http_fixtures() {
    let fixtures = [
        ("simple_request_http11.http", HttpPacketDisposition::Parsed),
        ("simple_response_http11.http", HttpPacketDisposition::Parsed),
        ("simple_request_http10.http", HttpPacketDisposition::Parsed),
        ("missing_host.http", HttpPacketDisposition::Partial),
        ("duplicate_host.http", HttpPacketDisposition::Partial),
        ("obs_fold.http", HttpPacketDisposition::Partial),
        ("lf_only.http", HttpPacketDisposition::Partial),
        ("truncated_headers.http", HttpPacketDisposition::Partial),
        (
            "content_length_list_identical.http",
            HttpPacketDisposition::Parsed,
        ),
        (
            "content_length_conflict.http",
            HttpPacketDisposition::Partial,
        ),
        ("te_and_cl.http", HttpPacketDisposition::Partial),
        (
            "oversized_selected_header.http",
            HttpPacketDisposition::Partial,
        ),
    ];

    let limits = HttpLimits::default();

    for (file_name, expected_disp) in fixtures {
        let path = format!("tests/fixtures/http/{file_name}");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        let packet = make_tcp_packet(54321, 80, bytes);
        let outcome = parse_http_packet(&packet, &limits);
        assert_eq!(
            outcome.disposition, expected_disp,
            "failed fixture {file_name}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_arbitrary_tcp_bytes_never_panic(
        src_port in 1u16..=65535,
        dst_port in 1u16..=65535,
        payload in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let packet = make_tcp_packet(src_port, dst_port, payload);
        let limits = HttpLimits::default();
        let outcome = parse_http_packet(&packet, &limits);
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
        prop_assert!(outcome.observations.len() <= 1);
        for obs in &outcome.observations {
            if obs.completeness.is_complete() {
                prop_assert!(obs.header_section_bytes <= limits.maximum_header_section_bytes);
            }
            for value in [
                obs.headers.host.as_ref(),
                obs.headers.user_agent.as_ref(),
                obs.headers.server.as_ref(),
                obs.headers.content_type.as_ref(),
                obs.headers.transfer_encoding.as_ref(),
                obs.headers.connection.as_ref(),
                obs.headers.upgrade.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                prop_assert!(value.len() <= limits.maximum_selected_field_value_bytes);
            }
        }
    }

    #[test]
    fn prop_deterministic_outcome(
        payload in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let packet1 = make_tcp_packet(54321, 80, payload.clone());
        let packet2 = make_tcp_packet(54321, 80, payload);
        let limits = HttpLimits::default();
        let out1 = parse_http_packet(&packet1, &limits);
        let out2 = parse_http_packet(&packet2, &limits);
        prop_assert_eq!(out1, out2);
    }
}
