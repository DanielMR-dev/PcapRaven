//! Integration, boundary, security, and property tests for bounded DNS wire-format parsing.

use pcapraven_domain::{
    DnsDiagnosticKind, DnsMessageKind, DnsObservationCompleteness, DnsRdataMetadata, DnsSection,
    DnsTransport, EthernetMetadata, IpAddress, Ipv4Metadata, MacAddress, NetworkLayer,
    NormalizedPacket, PacketCompleteness, PacketReference, PacketTimestamp, TcpMetadata,
    TransportLayer, UdpMetadata,
};
use pcapraven_protocols::{
    DnsLimits, DnsLimitsBuilder, DnsPacketDisposition, MAX_ALLOWED_DNS_DIAGNOSTICS_PER_PACKET,
    MAX_ALLOWED_DNS_EDNS_OPTIONS_PER_MESSAGE, MAX_ALLOWED_DNS_MESSAGES_PER_PACKET,
    MAX_ALLOWED_DNS_NAME_POINTER_HOPS, MAX_ALLOWED_DNS_QUESTIONS_PER_MESSAGE,
    MAX_ALLOWED_DNS_RESOURCE_RECORDS_PER_MESSAGE, MAX_ALLOWED_DNS_TOTAL_NAME_BYTES_PER_MESSAGE,
    parse_dns_packet,
};
use proptest::prelude::*;

const SIMPLE_QUERY_BYTES: &[u8] = include_bytes!("fixtures/dns/simple_query.bin");
const COMPRESSED_RESPONSE_BYTES: &[u8] = include_bytes!("fixtures/dns/compressed_response.bin");
const POINTER_SELF_LOOP_BYTES: &[u8] = include_bytes!("fixtures/dns/pointer_self_loop.bin");
const POINTER_FORWARD_BYTES: &[u8] = include_bytes!("fixtures/dns/pointer_forward.bin");
const POINTER_OUT_OF_BOUNDS_BYTES: &[u8] = include_bytes!("fixtures/dns/pointer_out_of_bounds.bin");
const TRUNCATED_NAME_BYTES: &[u8] = include_bytes!("fixtures/dns/truncated_name.bin");
const OVERSIZED_LABEL_BYTES: &[u8] = include_bytes!("fixtures/dns/oversized_label.bin");
const BAD_RDLENGTH_BYTES: &[u8] = include_bytes!("fixtures/dns/bad_rdlength.bin");
const EDNS_QUERY_BYTES: &[u8] = include_bytes!("fixtures/dns/edns_query.bin");
const DUPLICATE_OPT_BYTES: &[u8] = include_bytes!("fixtures/dns/duplicate_opt.bin");
const TCP_TRUNCATED_FRAME_BYTES: &[u8] = include_bytes!("fixtures/dns/tcp_truncated_frame.bin");

fn make_normalized_udp_packet(src_port: u16, dst_port: u16, payload: Vec<u8>) -> NormalizedPacket {
    let pkt_ref = PacketReference::new(1, Some(0), Some(0), 100, 100, false);
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
    let udp = UdpMetadata {
        source_port: src_port,
        destination_port: dst_port,
        length: 8 + payload.len() as u16,
        checksum: 0,
    };

    NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Udp(udp)),
        payload: Some(payload),
        completeness: PacketCompleteness::Complete,
    }
}

fn make_normalized_tcp_packet(src_port: u16, dst_port: u16, payload: Vec<u8>) -> NormalizedPacket {
    let pkt_ref = PacketReference::new(1, Some(0), Some(0), 100, 100, false);
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
        protocol: 6,
        source: [192, 168, 1, 100],
        destination: [8, 8, 8, 8],
        fragmentation: pcapraven_domain::FragmentationState::NotFragmented,
    };
    let tcp = TcpMetadata {
        source_port: src_port,
        destination_port: dst_port,
        sequence_number: 1000,
        acknowledgement_number: 2000,
        data_offset_bytes: 20,
        flags: pcapraven_domain::TcpFlags::default(),
        window_size: 65535,
        checksum: 0,
        urgent_pointer: 0,
        options_length_bytes: 0,
    };

    NormalizedPacket {
        reference: pkt_ref,
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(eth),
        network_layer: Some(NetworkLayer::Ipv4(ip)),
        transport_layer: Some(TransportLayer::Tcp(tcp)),
        payload: Some(payload),
        completeness: PacketCompleteness::Complete,
    }
}

#[test]
fn test_simple_dns_query() {
    let packet = make_normalized_udp_packet(53535, 53, SIMPLE_QUERY_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);
    assert!(outcome.diagnostics.is_empty());

    let obs = &outcome.observations[0];
    assert_eq!(obs.transport, DnsTransport::Udp);
    assert_eq!(obs.source_ip, IpAddress::Ipv4([192, 168, 1, 100]));
    assert_eq!(obs.source_port, 53535);
    assert_eq!(obs.destination_ip, IpAddress::Ipv4([8, 8, 8, 8]));
    assert_eq!(obs.destination_port, 53);
    assert_eq!(obs.transaction_id, 0x1234);
    assert_eq!(obs.message_kind, DnsMessageKind::Query);
    assert_eq!(obs.declared_qdcount, 1);
    assert_eq!(obs.declared_ancount, 0);
    assert_eq!(obs.questions.len(), 1);

    let q = &obs.questions[0];
    assert_eq!(q.name.display_escaped(), "example.com");
    assert_eq!(q.qtype, 1); // A
    assert_eq!(q.qclass, 1); // IN
    assert_eq!(obs.completeness, DnsObservationCompleteness::Complete);
}

#[test]
fn test_compressed_dns_response() {
    let packet = make_normalized_udp_packet(53, 53535, COMPRESSED_RESPONSE_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);
    assert!(outcome.diagnostics.is_empty());

    let obs = &outcome.observations[0];
    assert_eq!(obs.message_kind, DnsMessageKind::Response);
    assert_eq!(obs.declared_qdcount, 1);
    assert_eq!(obs.declared_ancount, 2);
    assert_eq!(obs.records.len(), 2);

    // Answer 1: CNAME
    let rr1 = &obs.records[0];
    assert_eq!(rr1.name.display_escaped(), "www.example.com");
    assert_eq!(rr1.section, DnsSection::Answer);
    if let DnsRdataMetadata::Cname(ref cname) = rr1.rdata {
        assert_eq!(cname.display_escaped(), "example.com");
    } else {
        panic!("expected CNAME RDATA");
    }

    // Answer 2: A
    let rr2 = &obs.records[1];
    assert_eq!(rr2.name.display_escaped(), "example.com");
    assert_eq!(rr2.section, DnsSection::Answer);
    if let DnsRdataMetadata::A(ip) = rr2.rdata {
        assert_eq!(ip, [93, 184, 216, 34]);
    } else {
        panic!("expected A RDATA");
    }
}

#[test]
fn test_pointer_self_loop_rejected() {
    let packet = make_normalized_udp_packet(53535, 53, POINTER_SELF_LOOP_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DnsDiagnosticKind::Malformed)
    );
}

#[test]
fn test_pointer_forward_rejected() {
    let packet = make_normalized_udp_packet(53535, 53, POINTER_FORWARD_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DnsDiagnosticKind::Malformed)
    );
}

#[test]
fn test_pointer_out_of_bounds_rejected() {
    let packet = make_normalized_udp_packet(53535, 53, POINTER_OUT_OF_BOUNDS_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DnsDiagnosticKind::Incomplete
                || d.kind == DnsDiagnosticKind::Malformed)
    );
}

#[test]
fn test_truncated_name_rejected() {
    let packet = make_normalized_udp_packet(53535, 53, TRUNCATED_NAME_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DnsDiagnosticKind::Incomplete)
    );
}

#[test]
fn test_oversized_label_rejected() {
    let packet = make_normalized_udp_packet(53535, 53, OVERSIZED_LABEL_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(outcome.diagnostics.iter().any(
        |d| d.kind == DnsDiagnosticKind::Unsupported || d.kind == DnsDiagnosticKind::Malformed
    ));
}

#[test]
fn test_bad_rdlength_rejected() {
    let packet = make_normalized_udp_packet(53, 53535, BAD_RDLENGTH_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DnsDiagnosticKind::Malformed)
    );
}

#[test]
fn test_edns_query_parsed() {
    let packet = make_normalized_udp_packet(53535, 53, EDNS_QUERY_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 1);
    let obs = &outcome.observations[0];
    assert!(obs.edns.is_some());

    let edns = obs.edns.as_ref().unwrap();
    assert_eq!(edns.udp_payload_size, 4096);
    assert!(edns.dnssec_ok);
    assert_eq!(edns.options.len(), 1);
    assert_eq!(edns.options[0].code, 10);
    assert_eq!(edns.options[0].length, 4);
}

#[test]
fn test_duplicate_opt_handled() {
    let packet = make_normalized_udp_packet(53535, 53, DUPLICATE_OPT_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("duplicate EDNS OPT"))
    );
}

#[test]
fn test_tcp_truncated_frame_handled() {
    let packet = make_normalized_tcp_packet(53535, 53, TCP_TRUNCATED_FRAME_BYTES.to_vec());
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DnsDiagnosticKind::Incomplete)
    );
}

#[test]
fn test_tcp_multiple_messages_in_packet() {
    let mut tcp_payload = Vec::new();
    // Message 1
    tcp_payload.extend_from_slice(&(SIMPLE_QUERY_BYTES.len() as u16).to_be_bytes());
    tcp_payload.extend_from_slice(SIMPLE_QUERY_BYTES);
    // Message 2
    tcp_payload.extend_from_slice(&(SIMPLE_QUERY_BYTES.len() as u16).to_be_bytes());
    tcp_payload.extend_from_slice(SIMPLE_QUERY_BYTES);

    let packet = make_normalized_tcp_packet(53535, 53, tcp_payload);
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Parsed);
    assert_eq!(outcome.observations.len(), 2);
    assert_eq!(outcome.observations[0].transport, DnsTransport::Tcp);
    assert_eq!(outcome.observations[1].transport, DnsTransport::Tcp);
}

#[test]
fn test_terminal_safe_dns_name_escaping() {
    use pcapraven_domain::DnsName;

    // Name with non-ASCII and control characters
    let label1 = b"test\x1b[31m".to_vec(); // contains ANSI escape ESC [ 3 1 m
    let label2 = b"domain.with.dots".to_vec();
    let label3 = b"com".to_vec();

    let name = DnsName::from_labels(vec![label1, label2, label3]).unwrap();
    let escaped = name.display_escaped();

    // Must not contain raw ESC (0x1b)
    assert!(!escaped.contains('\x1b'));
    // Must format escaped bytes in \DDD notation
    assert!(escaped.contains("\\027"));
    assert!(escaped.contains("\\046")); // dot escaped as \046 inside label
}

#[test]
fn test_non_candidate_packets() {
    // Port 80
    let packet = make_normalized_udp_packet(1000, 80, vec![1, 2, 3]);
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);
    assert_eq!(outcome.disposition, DnsPacketDisposition::NotDnsCandidate);
    assert!(outcome.observations.is_empty());

    // Port 53 with empty payload
    let empty_packet = make_normalized_tcp_packet(1000, 53, Vec::new());
    let outcome_empty = parse_dns_packet(&empty_packet, &limits);
    assert_eq!(
        outcome_empty.disposition,
        DnsPacketDisposition::CandidateWithoutMessage
    );
}

#[test]
fn test_limits_builder_validation() {
    let res = DnsLimitsBuilder::new()
        .maximum_messages_per_packet(0)
        .build();
    assert!(res.is_err());

    let res_cap = DnsLimitsBuilder::new()
        .maximum_name_pointer_hops(1000)
        .build();
    assert!(res_cap.is_err());
}

#[test]
fn phase18_all_dns_limit_hard_caps_accept_n_minus_1_and_n_but_reject_n_plus_1() {
    macro_rules! assert_boundary {
        ($setter:ident, $maximum:expr) => {{
            let maximum = $maximum;
            assert!(DnsLimitsBuilder::new().$setter(maximum - 1).build().is_ok());
            assert!(DnsLimitsBuilder::new().$setter(maximum).build().is_ok());
            assert!(
                DnsLimitsBuilder::new()
                    .$setter(maximum + 1)
                    .build()
                    .is_err()
            );
        }};
    }

    assert_boundary!(
        maximum_messages_per_packet,
        MAX_ALLOWED_DNS_MESSAGES_PER_PACKET
    );
    assert_boundary!(
        maximum_questions_per_message,
        MAX_ALLOWED_DNS_QUESTIONS_PER_MESSAGE
    );
    assert_boundary!(
        maximum_resource_records_per_message,
        MAX_ALLOWED_DNS_RESOURCE_RECORDS_PER_MESSAGE
    );
    assert_boundary!(maximum_name_pointer_hops, MAX_ALLOWED_DNS_NAME_POINTER_HOPS);
    assert_boundary!(
        maximum_edns_options_per_message,
        MAX_ALLOWED_DNS_EDNS_OPTIONS_PER_MESSAGE
    );
    assert_boundary!(
        maximum_diagnostics_per_packet,
        MAX_ALLOWED_DNS_DIAGNOSTICS_PER_PACKET
    );
    assert_boundary!(
        maximum_total_retained_name_bytes_per_message,
        MAX_ALLOWED_DNS_TOTAL_NAME_BYTES_PER_MESSAGE
    );
}

#[test]
fn phase18_dns_tcp_message_and_name_byte_limits_cover_n_minus_1_n_n_plus_1() {
    let mut tcp_payload = Vec::new();
    for _ in 0..2 {
        tcp_payload.extend_from_slice(&(SIMPLE_QUERY_BYTES.len() as u16).to_be_bytes());
        tcp_payload.extend_from_slice(SIMPLE_QUERY_BYTES);
    }
    let packet = make_normalized_tcp_packet(53535, 53, tcp_payload);
    for (limit, expected_observations, limited) in [(1, 1, true), (2, 2, false), (3, 2, false)] {
        let limits = DnsLimitsBuilder::new()
            .maximum_messages_per_packet(limit)
            .build()
            .unwrap();
        let outcome = parse_dns_packet(&packet, &limits);
        assert_eq!(outcome.observations.len(), expected_observations);
        assert_eq!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == DnsDiagnosticKind::ResourceLimit),
            limited
        );
    }

    let udp_packet = make_normalized_udp_packet(53535, 53, SIMPLE_QUERY_BYTES.to_vec());
    let retained_name_bytes = 13;
    for (limit, parsed) in [
        (retained_name_bytes - 1, false),
        (retained_name_bytes, true),
        (retained_name_bytes + 1, true),
    ] {
        let limits = DnsLimitsBuilder::new()
            .maximum_total_retained_name_bytes_per_message(limit)
            .build()
            .unwrap();
        let outcome = parse_dns_packet(&udp_packet, &limits);
        assert_eq!(outcome.disposition == DnsPacketDisposition::Parsed, parsed);
    }
}

fn cname_response_with_repeated_name(compressed: bool) -> Vec<u8> {
    let expanded_name = b"\x07example\x03com\x00";
    let mut message = vec![
        0x12, 0x34, 0x81, 0x80, // ID and standard response flags
        0, 1, 0, 1, 0, 0, 0, 0, // one question and one answer
    ];
    message.extend_from_slice(expanded_name);
    message.extend_from_slice(&[0, 1, 0, 1]);
    if compressed {
        message.extend_from_slice(&[0xc0, 0x0c]);
    } else {
        message.extend_from_slice(expanded_name);
    }
    message.extend_from_slice(&[
        0, 5, // CNAME
        0, 1, // IN
        0, 0, 0, 60, // TTL
    ]);
    if compressed {
        message.extend_from_slice(&[0, 2, 0xc0, 0x0c]);
    } else {
        message.extend_from_slice(&[0, 13]);
        message.extend_from_slice(expanded_name);
    }
    message
}

fn retained_expanded_name_bytes(observation: &pcapraven_domain::DnsObservation) -> usize {
    observation
        .questions
        .iter()
        .map(|question| question.name.wire_length())
        .chain(
            observation
                .records
                .iter()
                .map(|record| record.name.wire_length()),
        )
        .chain(
            observation
                .records
                .iter()
                .filter_map(|record| match &record.rdata {
                    DnsRdataMetadata::Cname(name)
                    | DnsRdataMetadata::Ns(name)
                    | DnsRdataMetadata::Ptr(name) => Some(name.wire_length()),
                    DnsRdataMetadata::Mx { exchange, .. } => Some(exchange.wire_length()),
                    _ => None,
                }),
        )
        .sum()
}

#[test]
fn aggregate_retained_expanded_name_bytes_cover_compressed_and_uncompressed_n_minus_1_n_n_plus_1() {
    const AGGREGATE_EXPANDED_BYTES: usize = 39;

    for compressed in [false, true] {
        let packet =
            make_normalized_udp_packet(53, 53535, cname_response_with_repeated_name(compressed));
        for (limit, complete) in [
            (AGGREGATE_EXPANDED_BYTES - 1, false),
            (AGGREGATE_EXPANDED_BYTES, true),
            (AGGREGATE_EXPANDED_BYTES + 1, true),
        ] {
            let limits = DnsLimitsBuilder::new()
                .maximum_total_retained_name_bytes_per_message(limit)
                .build()
                .expect("valid retained-name limit");
            let outcome = parse_dns_packet(&packet, &limits);
            assert_eq!(outcome.observations.len(), 1);
            let observation = &outcome.observations[0];
            assert_eq!(observation.completeness.is_complete(), complete);
            assert!(retained_expanded_name_bytes(observation) <= limit);
            if complete {
                assert_eq!(
                    retained_expanded_name_bytes(observation),
                    AGGREGATE_EXPANDED_BYTES
                );
                assert_eq!(observation.records.len(), 1);
            } else {
                assert!(observation.records.is_empty());
                assert!(
                    outcome
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.kind == DnsDiagnosticKind::ResourceLimit)
                );
            }
        }
    }
}

#[test]
fn phase18_dns_question_and_resource_record_counts_cover_n_minus_1_n_n_plus_1() {
    let mut two_questions = vec![
        0, 1, 0, 0, // ID and flags
        0, 2, 0, 0, 0, 0, 0, 0, // QDCOUNT=2; all RR counts zero
    ];
    for _ in 0..2 {
        two_questions.extend_from_slice(&[0, 0, 1, 0, 1]);
    }
    let question_packet = make_normalized_udp_packet(53535, 53, two_questions);
    for (limit, parsed) in [(1, false), (2, true), (3, true)] {
        let limits = DnsLimitsBuilder::new()
            .maximum_questions_per_message(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_dns_packet(&question_packet, &limits).disposition == DnsPacketDisposition::Parsed,
            parsed
        );
    }

    let mut two_records = vec![
        0, 1, 0x80, 0, // ID and response flag
        0, 0, 0, 2, 0, 0, 0, 0, // ANCOUNT=2; other counts zero
    ];
    for address in [[192, 0, 2, 1], [192, 0, 2, 2]] {
        two_records.extend_from_slice(&[
            0, // root owner name
            0, 1, // A
            0, 1, // IN
            0, 0, 0, 60, // TTL
            0, 4, // RDLENGTH
        ]);
        two_records.extend_from_slice(&address);
    }
    let record_packet = make_normalized_udp_packet(53, 53535, two_records);
    for (limit, parsed) in [(1, false), (2, true), (3, true)] {
        let limits = DnsLimitsBuilder::new()
            .maximum_resource_records_per_message(limit)
            .build()
            .unwrap();
        assert_eq!(
            parse_dns_packet(&record_packet, &limits).disposition == DnsPacketDisposition::Parsed,
            parsed
        );
    }
}

#[test]
fn test_missing_network_layer_produces_no_fake_endpoints() {
    let mut packet = make_normalized_udp_packet(53535, 53, SIMPLE_QUERY_BYTES.to_vec());
    packet.network_layer = None;
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(outcome.observations.is_empty());
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("missing network layer"))
    );
}

#[test]
fn test_exact_rdlength_enforcement() {
    let limits = DnsLimits::default();

    // 1. NS record where RDLENGTH is 2 bytes larger than the name consumes (5 bytes name vs 7 bytes declared)
    let mut ns_payload = Vec::new();
    // Header: ID=1, QR=1 (response), QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    ns_payload.extend_from_slice(&[
        0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]);
    // AN: Name = root (0x00), TYPE=2 (NS), CLASS=1 (IN), TTL=60, RDLENGTH=7 (name takes 5: \x03ns1\x00 + 2 trailing dummy bytes)
    ns_payload.extend_from_slice(&[
        0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x07,
    ]);
    ns_payload.extend_from_slice(b"\x03ns1\x00\xaa\xbb"); // 5 bytes name + 2 extra bytes = 7 bytes

    let pkt_ns = make_normalized_udp_packet(53, 53535, ns_payload);
    let outcome_ns = parse_dns_packet(&pkt_ns, &limits);
    assert_eq!(outcome_ns.disposition, DnsPacketDisposition::Partial);
    assert!(outcome_ns.diagnostics.iter().any(|d| {
        d.message
            .contains("NS domain name did not consume exact RDLENGTH")
    }));

    // 2. CNAME record where RDLENGTH is 2 bytes larger
    let mut cname_payload = Vec::new();
    cname_payload.extend_from_slice(&[
        0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]);
    cname_payload.extend_from_slice(&[
        0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x07,
    ]);
    cname_payload.extend_from_slice(b"\x03foo\x00\xaa\xbb");

    let pkt_cname = make_normalized_udp_packet(53, 53535, cname_payload);
    let outcome_cname = parse_dns_packet(&pkt_cname, &limits);
    assert_eq!(outcome_cname.disposition, DnsPacketDisposition::Partial);
    assert!(outcome_cname.diagnostics.iter().any(|d| {
        d.message
            .contains("CNAME domain name did not consume exact RDLENGTH")
    }));

    // 3. PTR record where RDLENGTH is 2 bytes larger
    let mut ptr_payload = Vec::new();
    ptr_payload.extend_from_slice(&[
        0x00, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]);
    ptr_payload.extend_from_slice(&[
        0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x07,
    ]);
    ptr_payload.extend_from_slice(b"\x03ptr\x00\xbb\xcc");

    let pkt_ptr = make_normalized_udp_packet(53, 53535, ptr_payload);
    let outcome_ptr = parse_dns_packet(&pkt_ptr, &limits);
    assert_eq!(outcome_ptr.disposition, DnsPacketDisposition::Partial);
    assert!(outcome_ptr.diagnostics.iter().any(|d| {
        d.message
            .contains("PTR domain name did not consume exact RDLENGTH")
    }));

    // 4. MX record where RDLENGTH is 2 bytes larger than preference (2 bytes) + exchange name (5 bytes)
    let mut mx_payload = Vec::new();
    mx_payload.extend_from_slice(&[
        0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]);
    mx_payload.extend_from_slice(&[
        0x00, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x09,
    ]); // RDLENGTH = 9
    mx_payload.extend_from_slice(&[0x00, 0x0a]); // preference 10
    mx_payload.extend_from_slice(b"\x03mx1\x00\xcc\xdd"); // 5 bytes name + 2 extra bytes = 7 bytes RDATA payload

    let pkt_mx = make_normalized_udp_packet(53, 53535, mx_payload);
    let outcome_mx = parse_dns_packet(&pkt_mx, &limits);
    assert_eq!(outcome_mx.disposition, DnsPacketDisposition::Partial);
    assert!(outcome_mx.diagnostics.iter().any(|d| {
        d.message
            .contains("MX preference and exchange name did not consume exact RDLENGTH")
    }));
}

#[test]
fn test_invalid_opt_structure_and_placement() {
    let limits = DnsLimits::default();

    // 1. OPT record with non-root owner name
    let mut opt_non_root = Vec::new();
    opt_non_root.extend_from_slice(&[
        0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]);
    // AR: Name = \x03opt\x00 (non-root), TYPE=41 (OPT), CLASS=4096, TTL=0, RDLENGTH=0
    opt_non_root.extend_from_slice(b"\x03opt\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00");

    let pkt1 = make_normalized_udp_packet(53535, 53, opt_non_root);
    let outcome1 = parse_dns_packet(&pkt1, &limits);
    assert_eq!(outcome1.disposition, DnsPacketDisposition::Partial);
    assert!(
        outcome1
            .diagnostics
            .iter()
            .any(|d| d.message.contains("OPT record owner name must be root"))
    );

    // 2. OPT record in Answer section instead of Additional
    let mut opt_in_answer = Vec::new();
    opt_in_answer.extend_from_slice(&[
        0x00, 0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]);
    // AN: Name = root (\x00), TYPE=41 (OPT), CLASS=4096, TTL=0, RDLENGTH=0
    opt_in_answer.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let pkt2 = make_normalized_udp_packet(53, 53535, opt_in_answer);
    let outcome2 = parse_dns_packet(&pkt2, &limits);
    assert_eq!(outcome2.disposition, DnsPacketDisposition::Partial);
    assert!(outcome2.diagnostics.iter().any(|d| {
        d.message
            .contains("OPT record must only appear in Additional section")
    }));
}

#[test]
fn test_edns_option_limits_exact_boundary() {
    // Construct an OPT record with 2 options
    let mut opt_bytes = Vec::new();
    opt_bytes.extend_from_slice(&[
        0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]);
    // AR: Root, TYPE=41, CLASS=4096, TTL=0, RDLENGTH=12 (two 6-byte options: code=1, len=2, data=0x0000; code=2, len=2, data=0x0000)
    opt_bytes.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
    ]);
    opt_bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb]);
    opt_bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0xcc, 0xdd]);

    let pkt = make_normalized_udp_packet(53535, 53, opt_bytes);

    // Limit = 2 options -> Should parse completely
    let limits_2 = DnsLimitsBuilder::new()
        .maximum_edns_options_per_message(2)
        .build()
        .unwrap();
    let outcome_2 = parse_dns_packet(&pkt, &limits_2);
    assert_eq!(outcome_2.disposition, DnsPacketDisposition::Parsed);
    assert_eq!(
        outcome_2.observations[0]
            .edns
            .as_ref()
            .unwrap()
            .options
            .len(),
        2
    );

    // Limit = 1 option -> Should emit ResourceLimit diagnostic and mark Partial
    let limits_1 = DnsLimitsBuilder::new()
        .maximum_edns_options_per_message(1)
        .build()
        .unwrap();
    let outcome_1 = parse_dns_packet(&pkt, &limits_1);
    assert_eq!(outcome_1.disposition, DnsPacketDisposition::Partial);
    assert!(
        outcome_1
            .diagnostics
            .iter()
            .any(|d| d.kind == DnsDiagnosticKind::ResourceLimit)
    );

    // Limit = N+1 -> same complete output; extra capacity must not change semantics.
    let limits_3 = DnsLimitsBuilder::new()
        .maximum_edns_options_per_message(3)
        .build()
        .unwrap();
    let outcome_3 = parse_dns_packet(&pkt, &limits_3);
    assert_eq!(outcome_3.disposition, DnsPacketDisposition::Parsed);
    assert_eq!(
        outcome_3.observations[0]
            .edns
            .as_ref()
            .unwrap()
            .options
            .len(),
        2
    );
}

#[test]
fn test_undeclared_trailing_bytes_after_sections() {
    let mut payload = SIMPLE_QUERY_BYTES.to_vec();
    payload.extend_from_slice(b"trailing_undeclared_garbage");

    let packet = make_normalized_udp_packet(53535, 53, payload);
    let limits = DnsLimits::default();
    let outcome = parse_dns_packet(&packet, &limits);

    assert_eq!(outcome.disposition, DnsPacketDisposition::Partial);
    assert!(outcome.diagnostics.iter().any(|d| {
        d.message
            .contains("undeclared trailing bytes after DNS message sections")
    }));
}

proptest! {
    #[test]
    fn arbitrary_udp_bytes_never_panic(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
        let packet = make_normalized_udp_packet(53535, 53, payload);
        let limits = DnsLimits::default();
        let outcome = parse_dns_packet(&packet, &limits);
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
        prop_assert_eq!(outcome.clone(), parse_dns_packet(&packet, &limits));
        for observation in &outcome.observations {
            prop_assert!(observation.questions.len() <= limits.maximum_questions_per_message);
            prop_assert!(observation.records.len() <= limits.maximum_resource_records_per_message);
            if let Some(edns) = &observation.edns {
                prop_assert!(edns.options.len() <= limits.maximum_edns_options_per_message);
            }
            let retained_name_bytes: usize = observation
                .questions
                .iter()
                .map(|question| question.name.labels().iter().map(Vec::len).sum::<usize>())
                .chain(observation.records.iter().map(|record| {
                    record.name.labels().iter().map(Vec::len).sum::<usize>()
                }))
                .chain(observation.records.iter().filter_map(|record| match &record.rdata {
                    DnsRdataMetadata::Cname(name)
                    | DnsRdataMetadata::Ns(name)
                    | DnsRdataMetadata::Ptr(name) => {
                        Some(name.labels().iter().map(Vec::len).sum::<usize>())
                    }
                    DnsRdataMetadata::Mx { exchange, .. } => {
                        Some(exchange.labels().iter().map(Vec::len).sum::<usize>())
                    }
                    _ => None,
                }))
                .sum();
            prop_assert!(retained_name_bytes <= limits.maximum_total_retained_name_bytes_per_message);
        }
    }

    #[test]
    fn arbitrary_tcp_bytes_never_panic(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
        let packet = make_normalized_tcp_packet(53535, 53, payload);
        let limits = DnsLimits::default();
        let outcome = parse_dns_packet(&packet, &limits);
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
        prop_assert!(outcome.observations.len() <= limits.maximum_messages_per_packet);
        prop_assert_eq!(outcome.clone(), parse_dns_packet(&packet, &limits));
    }
}
