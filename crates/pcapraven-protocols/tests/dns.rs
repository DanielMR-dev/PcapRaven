//! Integration, boundary, security, and property tests for bounded DNS wire-format parsing.

use pcapraven_domain::{
    DnsDiagnosticKind, DnsMessageKind, DnsObservationCompleteness, DnsRdataMetadata, DnsSection,
    DnsTransport, EthernetMetadata, IpAddress, Ipv4Metadata, MacAddress, NetworkLayer,
    NormalizedPacket, PacketCompleteness, PacketReference, PacketTimestamp, TcpMetadata,
    TransportLayer, UdpMetadata,
};
use pcapraven_protocols::{DnsLimits, DnsLimitsBuilder, DnsPacketDisposition, parse_dns_packet};
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

proptest! {
    #[test]
    fn arbitrary_udp_bytes_never_panic(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
        let packet = make_normalized_udp_packet(53535, 53, payload);
        let limits = DnsLimits::default();
        let outcome = parse_dns_packet(&packet, &limits);
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    }

    #[test]
    fn arbitrary_tcp_bytes_never_panic(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
        let packet = make_normalized_tcp_packet(53535, 53, payload);
        let limits = DnsLimits::default();
        let outcome = parse_dns_packet(&packet, &limits);
        prop_assert!(outcome.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    }
}
