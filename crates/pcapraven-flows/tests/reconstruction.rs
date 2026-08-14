//! Integration, boundary, lifecycle, and property tests for deterministic flow reconstruction.

use pcapraven_domain::{
    EthernetMetadata, FlowDirection, FlowEndReason, FlowEndpoint, FlowKey, FragmentationState,
    IpAddress, Ipv4Metadata, Ipv6Metadata, MacAddress, NetworkLayer, NormalizedPacket,
    PacketCompleteness, PacketReference, PacketTimestamp, PacketTimestampResolution, TcpFlags,
    TcpMetadata, TransportLayer, TransportProtocol, UdpMetadata,
};
use pcapraven_flows::{
    FlowDisposition, FlowError, FlowExclusionReason, FlowReconstructionConfig,
    FlowReconstructionConfigBuilder, FlowReconstructor, has_timed_out,
};
use proptest::prelude::*;

// Helper builders for synthetic NormalizedPacket instances

fn make_packet_ref(ordinal: u64) -> PacketReference {
    PacketReference::new(ordinal, Some(0), Some(0), 64, 64, false)
}

fn make_timestamp_dec(seconds: i128, nanos: u64, offset: i64) -> PacketTimestamp {
    PacketTimestamp::Available {
        seconds,
        fractional_units: nanos,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 9,
            units_per_second: 1_000_000_000,
        },
        offset_seconds: offset,
    }
}

fn make_timestamp_bin(seconds: i128, frac: u64, offset: i64) -> PacketTimestamp {
    PacketTimestamp::Available {
        seconds,
        fractional_units: frac,
        resolution: PacketTimestampResolution::Binary {
            exponent: 32,
            units_per_second: 1 << 32,
        },
        offset_seconds: offset,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_ipv4_tcp_packet(
    ordinal: u64,
    timestamp: PacketTimestamp,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: TcpFlags,
    payload: Option<Vec<u8>>,
) -> NormalizedPacket {
    NormalizedPacket {
        reference: make_packet_ref(ordinal),
        timestamp,
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
            total_length: 40,
            identification: 0x1234,
            ttl: 64,
            protocol: 6,
            source: src_ip,
            destination: dst_ip,
            fragmentation: FragmentationState::NotFragmented,
        })),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: src_port,
            destination_port: dst_port,
            sequence_number: 1000,
            acknowledgement_number: 0,
            data_offset_bytes: 20,
            flags,
            window_size: 65535,
            checksum: 0xabcd,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload,
        completeness: PacketCompleteness::Complete,
    }
}

fn make_ipv4_udp_packet(
    ordinal: u64,
    timestamp: PacketTimestamp,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: Option<Vec<u8>>,
) -> NormalizedPacket {
    NormalizedPacket {
        reference: make_packet_ref(ordinal),
        timestamp,
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
            total_length: 28,
            identification: 0x1234,
            ttl: 64,
            protocol: 17,
            source: src_ip,
            destination: dst_ip,
            fragmentation: FragmentationState::NotFragmented,
        })),
        transport_layer: Some(TransportLayer::Udp(UdpMetadata {
            source_port: src_port,
            destination_port: dst_port,
            length: 8,
            checksum: 0xabcd,
        })),
        payload,
        completeness: PacketCompleteness::Complete,
    }
}

fn make_ipv6_tcp_packet(
    ordinal: u64,
    timestamp: PacketTimestamp,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    flags: TcpFlags,
) -> NormalizedPacket {
    NormalizedPacket {
        reference: make_packet_ref(ordinal),
        timestamp,
        link_layer: Some(EthernetMetadata {
            source: MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            destination: MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
            ethertype: 0x86dd,
            link_header_length: 14,
        }),
        network_layer: Some(NetworkLayer::Ipv6(Ipv6Metadata {
            version: 6,
            traffic_class: 0,
            flow_label: 0,
            payload_length: 20,
            next_header: 6,
            hop_limit: 64,
            source: src_ip,
            destination: dst_ip,
            extension_headers_count: 0,
            extension_headers_length: 0,
            effective_protocol: 6,
            fragmentation: FragmentationState::NotFragmented,
        })),
        transport_layer: Some(TransportLayer::Tcp(TcpMetadata {
            source_port: src_port,
            destination_port: dst_port,
            sequence_number: 1000,
            acknowledgement_number: 0,
            data_offset_bytes: 20,
            flags,
            window_size: 65535,
            checksum: 0xabcd,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload: None,
        completeness: PacketCompleteness::Complete,
    }
}

fn make_ipv6_udp_packet(
    ordinal: u64,
    timestamp: PacketTimestamp,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
) -> NormalizedPacket {
    NormalizedPacket {
        reference: make_packet_ref(ordinal),
        timestamp,
        link_layer: Some(EthernetMetadata {
            source: MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            destination: MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
            ethertype: 0x86dd,
            link_header_length: 14,
        }),
        network_layer: Some(NetworkLayer::Ipv6(Ipv6Metadata {
            version: 6,
            traffic_class: 0,
            flow_label: 0,
            payload_length: 8,
            next_header: 17,
            hop_limit: 64,
            source: src_ip,
            destination: dst_ip,
            extension_headers_count: 0,
            extension_headers_length: 0,
            effective_protocol: 17,
            fragmentation: FragmentationState::NotFragmented,
        })),
        transport_layer: Some(TransportLayer::Udp(UdpMetadata {
            source_port: src_port,
            destination_port: dst_port,
            length: 8,
            checksum: 0xabcd,
        })),
        payload: None,
        completeness: PacketCompleteness::Complete,
    }
}

// 1. Basic Flow Tests and Canonical Key Tests

#[test]
fn basic_ipv4_tcp_bidirectional_association() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let port_a = 12345;
    let port_b = 443;

    // Forward SYN: A -> B
    let p1 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        port_a,
        port_b,
        TcpFlags::from_bits(0x002), // SYN
        None,
    );
    let step1 = reconstructor.observe(&p1).expect("step 1");
    let assoc1 = match step1.disposition {
        FlowDisposition::Associated(a) => a,
        other => panic!("expected Associated, got {:?}", other),
    };
    assert_eq!(assoc1.flow.ordinal(), 0);
    assert_eq!(assoc1.direction, FlowDirection::AToB);
    assert!(step1.closed_flows.is_empty());

    // Reverse SYN-ACK: B -> A
    let p2 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(100, 10_000_000, 0),
        ip_b,
        ip_a,
        port_b,
        port_a,
        TcpFlags::from_bits(0x012), // SYN+ACK
        None,
    );
    let step2 = reconstructor.observe(&p2).expect("step 2");
    let assoc2 = match step2.disposition {
        FlowDisposition::Associated(a) => a,
        other => panic!("expected Associated, got {:?}", other),
    };
    assert_eq!(assoc2.flow.ordinal(), 0);
    assert_eq!(assoc2.direction, FlowDirection::BToA);
    assert!(step2.closed_flows.is_empty());

    let finished = reconstructor.finish();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].reference.ordinal(), 0);
    assert_eq!(finished[0].end_reason, FlowEndReason::EndOfInput);
    assert_eq!(finished[0].first_packet.capture_record_ordinal, 0);
    assert_eq!(finished[0].last_packet.capture_record_ordinal, 1);
}

#[test]
fn canonical_key_equality_for_tcp_and_udp() {
    let ep1 = FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 10]), 50000);
    let ep2 = FlowEndpoint::new(IpAddress::Ipv4([192, 168, 1, 1]), 53);

    let key_tcp1 = FlowKey::new(TransportProtocol::Tcp, ep1, ep2);
    let key_tcp2 = FlowKey::new(TransportProtocol::Tcp, ep2, ep1);
    assert_eq!(key_tcp1, key_tcp2);
    assert!(key_tcp1.endpoint_a() <= key_tcp1.endpoint_b());

    let key_udp1 = FlowKey::new(TransportProtocol::Udp, ep1, ep2);
    let key_udp2 = FlowKey::new(TransportProtocol::Udp, ep2, ep1);
    assert_eq!(key_udp1, key_udp2);
    assert_ne!(key_tcp1, key_udp1);
}

#[test]
fn port_zero_and_max_port_boundary_handling() {
    let ep_zero = FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 1]), 0);
    let ep_max = FlowEndpoint::new(IpAddress::Ipv4([10, 0, 0, 1]), 65535);

    let key = FlowKey::new(TransportProtocol::Udp, ep_zero, ep_max);
    assert_eq!(key.endpoint_a().port(), 0);
    assert_eq!(key.endpoint_b().port(), 65535);
}

#[test]
fn same_endpoint_edge_case_yields_same_endpoint_direction() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip = [127, 0, 0, 1];
    let port = 8080;

    let p = make_ipv4_udp_packet(0, make_timestamp_dec(100, 0, 0), ip, ip, port, port, None);
    let step = reconstructor.observe(&p).expect("observe");
    let assoc = match step.disposition {
        FlowDisposition::Associated(a) => a,
        other => panic!("expected Associated, got {:?}", other),
    };
    assert_eq!(assoc.direction, FlowDirection::SameEndpoint);
}

#[test]
fn ipv6_tcp_and_udp_reconstruction() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let ip_b = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    let p_tcp = make_ipv6_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        8000,
        80,
        TcpFlags::from_bits(0x002),
    );
    let step1 = reconstructor.observe(&p_tcp).expect("tcp observe");
    assert!(matches!(step1.disposition, FlowDisposition::Associated(_)));

    let p_udp = make_ipv6_udp_packet(1, make_timestamp_dec(101, 0, 0), ip_a, ip_b, 5353, 5353);
    let step2 = reconstructor.observe(&p_udp).expect("udp observe");
    assert!(matches!(step2.disposition, FlowDisposition::Associated(_)));

    assert_eq!(reconstructor.active_flow_count(), 2);
    let finished = reconstructor.finish();
    assert_eq!(finished.len(), 2);
}

// 2. Packet Order Tests

#[test]
fn packet_ordinal_strictly_increasing_enforced() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        None,
    );
    assert!(reconstructor.observe(&p1).is_ok());

    // Gap is fine: 1 -> 3
    let p3 = make_ipv4_udp_packet(
        3,
        make_timestamp_dec(101, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        None,
    );
    assert!(reconstructor.observe(&p3).is_ok());

    // Duplicate fails: 3 -> 3
    let p3_dup = make_ipv4_udp_packet(
        3,
        make_timestamp_dec(102, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        None,
    );
    let err = reconstructor.observe(&p3_dup).unwrap_err();
    assert!(matches!(
        err,
        FlowError::NonMonotonicPacketOrder {
            previous_ordinal: 3,
            current_ordinal: 3
        }
    ));

    // Decreasing fails: 3 -> 2
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(103, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        None,
    );
    let err = reconstructor.observe(&p2).unwrap_err();
    assert!(matches!(
        err,
        FlowError::NonMonotonicPacketOrder {
            previous_ordinal: 3,
            current_ordinal: 2
        }
    ));
}

// 3. UDP and TCP Idle Timeout Tests

#[test]
fn udp_idle_timeout_exact_boundaries() {
    let config = FlowReconstructionConfigBuilder::default()
        .udp_idle_timeout_seconds(10)
        .build()
        .expect("config");
    let mut reconstructor = FlowReconstructor::new(config).expect("reconstructor");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Packet 0 at t = 100.000s
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        5000,
        5000,
        None,
    );
    let step0 = reconstructor.observe(&p0).expect("p0");
    assert!(step0.closed_flows.is_empty());

    // Packet 1 at t = 109.999s (gap = 9.999s < 10s timeout -> same flow)
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(109, 999_000_000, 0),
        ip_a,
        ip_b,
        5000,
        5000,
        None,
    );
    let step1 = reconstructor.observe(&p1).expect("p1");
    assert!(step1.closed_flows.is_empty());
    assert_eq!(
        match step1.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );

    // Packet 2 at t = 119.999s (gap from p1 is 10.000s == 10s timeout -> TIMEOUT, closes flow 0, starts flow 1)
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(119, 999_000_000, 0),
        ip_a,
        ip_b,
        5000,
        5000,
        None,
    );
    let step2 = reconstructor.observe(&p2).expect("p2");
    assert_eq!(step2.closed_flows.len(), 1);
    assert_eq!(step2.closed_flows[0].reference.ordinal(), 0);
    assert_eq!(step2.closed_flows[0].end_reason, FlowEndReason::IdleTimeout);
    assert_eq!(step2.closed_flows[0].last_packet.capture_record_ordinal, 1);

    let assoc2 = match step2.disposition {
        FlowDisposition::Associated(a) => a,
        _ => panic!(),
    };
    assert_eq!(assoc2.flow.ordinal(), 1);
}

#[test]
fn timestamp_different_resolutions_and_signed_offsets() {
    let t_dec = make_timestamp_dec(100, 500_000_000, 10); // eff = 110.5s
    let t_bin = make_timestamp_bin(115, 1 << 31, -5); // eff = 110.5s

    // Gap between 110.5s and 110.5s is 0s
    assert!(!has_timed_out(&t_dec, &t_bin, 1));
    assert!(has_timed_out(&t_dec, &t_bin, 0));

    let t_bin_after = make_timestamp_bin(120, 1 << 31, -5); // eff = 115.5s (gap = 5.0s)
    assert!(has_timed_out(&t_dec, &t_bin_after, 5));
    assert!(!has_timed_out(&t_dec, &t_bin_after, 6));
}

#[test]
fn unavailable_and_non_monotonic_timestamps() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Packet 0: Available timestamp
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());

    // Packet 1: Unavailable timestamp (should not trigger false timeout)
    let p1 = make_ipv4_udp_packet(
        1,
        PacketTimestamp::Unavailable,
        ip_a,
        ip_b,
        1000,
        2000,
        None,
    );
    let step1 = reconstructor.observe(&p1).expect("p1");
    assert!(step1.closed_flows.is_empty());

    // Packet 2: Available timestamp, earlier time than p0 (backward/non-monotonic in time, but monotonic in capture ordinal)
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(50, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        None,
    );
    let step2 = reconstructor.observe(&p2).expect("p2");
    assert!(step2.closed_flows.is_empty());
}

// 4. TCP Lifecycle: SYN Retransmissions, New Initial SYN, RST, FIN

#[test]
fn tcp_syn_retransmissions_stay_in_same_flow() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let syn = TcpFlags::from_bits(0x002);
    let syn_ack = TcpFlags::from_bits(0x012);

    // Initial SYN
    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        None,
    );
    let s0 = reconstructor.observe(&p0).expect("s0");
    assert_eq!(
        match s0.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );

    // SYN retransmission from client
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        None,
    );
    let s1 = reconstructor.observe(&p1).expect("s1");
    assert!(s1.closed_flows.is_empty());
    assert_eq!(
        match s1.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );

    // SYN+ACK from server
    let p2 = make_ipv4_tcp_packet(
        2,
        make_timestamp_dec(102, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        syn_ack,
        None,
    );
    let s2 = reconstructor.observe(&p2).expect("s2");
    assert!(s2.closed_flows.is_empty());
    assert_eq!(
        match s2.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );

    // Second SYN retransmission from client before ACK
    let p3 = make_ipv4_tcp_packet(
        3,
        make_timestamp_dec(103, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        None,
    );
    let s3 = reconstructor.observe(&p3).expect("s3");
    assert!(s3.closed_flows.is_empty());
    assert_eq!(
        match s3.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );
}

#[test]
fn tcp_new_initial_syn_after_activity_creates_new_flow() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let ack = TcpFlags::from_bits(0x010);
    let syn = TcpFlags::from_bits(0x002);

    // Flow 0 data packet (e.g. capture started midstream or completed handshake)
    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        ack,
        Some(vec![1, 2, 3]),
    );
    let s0 = reconstructor.observe(&p0).expect("s0");
    assert_eq!(
        match s0.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );

    // New initial SYN arrives for the same 5-tuple -> closes Flow 0 with TcpNewInitialSyn
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(105, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        None,
    );
    let s1 = reconstructor.observe(&p1).expect("s1");
    assert_eq!(s1.closed_flows.len(), 1);
    assert_eq!(s1.closed_flows[0].reference.ordinal(), 0);
    assert_eq!(
        s1.closed_flows[0].end_reason,
        FlowEndReason::TcpNewInitialSyn
    );

    let assoc1 = match s1.disposition {
        FlowDisposition::Associated(a) => a,
        _ => panic!(),
    };
    assert_eq!(assoc1.flow.ordinal(), 1);
}

#[test]
fn tcp_reset_associates_and_closes_immediately() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let ack = TcpFlags::from_bits(0x010);
    let rst = TcpFlags::from_bits(0x004);

    // Packet 0: ACK
    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        ack,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());

    // Packet 1: RST from server -> associates with flow 0, then closes flow 0
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        rst,
        None,
    );
    let s1 = reconstructor.observe(&p1).expect("s1");
    let assoc1 = match s1.disposition {
        FlowDisposition::Associated(a) => a,
        _ => panic!(),
    };
    assert_eq!(assoc1.flow.ordinal(), 0);
    assert_eq!(s1.closed_flows.len(), 1);
    assert_eq!(s1.closed_flows[0].reference.ordinal(), 0);
    assert_eq!(s1.closed_flows[0].end_reason, FlowEndReason::TcpReset);
    assert_eq!(s1.closed_flows[0].last_packet.capture_record_ordinal, 1);

    assert_eq!(reconstructor.active_flow_count(), 0);

    // Packet 2: Next packet on same tuple creates flow 1
    let p2 = make_ipv4_tcp_packet(
        2,
        make_timestamp_dec(102, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        ack,
        None,
    );
    let s2 = reconstructor.observe(&p2).expect("s2");
    let assoc2 = match s2.disposition {
        FlowDisposition::Associated(a) => a,
        _ => panic!(),
    };
    assert_eq!(assoc2.flow.ordinal(), 1);
}

#[test]
fn tcp_fin_does_not_force_immediate_split() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let fin_ack = TcpFlags::from_bits(0x011);
    let ack = TcpFlags::from_bits(0x010);

    // Client FIN+ACK
    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        fin_ack,
        None,
    );
    let s0 = reconstructor.observe(&p0).expect("s0");
    assert!(s0.closed_flows.is_empty());

    // Server ACK
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        ack,
        None,
    );
    let s1 = reconstructor.observe(&p1).expect("s1");
    assert!(s1.closed_flows.is_empty());
    assert_eq!(
        match s1.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );

    // Server FIN+ACK
    let p2 = make_ipv4_tcp_packet(
        2,
        make_timestamp_dec(102, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        fin_ack,
        None,
    );
    let s2 = reconstructor.observe(&p2).expect("s2");
    assert!(s2.closed_flows.is_empty());

    // Client final ACK
    let p3 = make_ipv4_tcp_packet(
        3,
        make_timestamp_dec(103, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        ack,
        None,
    );
    let s3 = reconstructor.observe(&p3).expect("s3");
    assert!(s3.closed_flows.is_empty());

    assert_eq!(reconstructor.active_flow_count(), 1);
}

// 5. Eligibility, Consistency and Truncation Tests

#[test]
fn non_eligible_packets_produce_structured_exclusions() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    // Missing network layer
    let p_no_net = NormalizedPacket {
        reference: make_packet_ref(0),
        timestamp: PacketTimestamp::Unavailable,
        link_layer: None,
        network_layer: None,
        transport_layer: None,
        payload: None,
        completeness: PacketCompleteness::Unsupported {
            reason: pcapraven_domain::UnsupportedLayerReason::LinkType(105),
        },
    };
    let step0 = reconstructor.observe(&p_no_net).expect("step0");
    assert_eq!(
        step0.disposition,
        FlowDisposition::Excluded(FlowExclusionReason::MissingNetworkLayer)
    );

    // Fragmented IP without transport
    let p_frag = NormalizedPacket {
        reference: make_packet_ref(1),
        timestamp: PacketTimestamp::Unavailable,
        link_layer: None,
        network_layer: Some(NetworkLayer::Ipv4(Ipv4Metadata {
            version: 4,
            header_length: 20,
            dscp: 0,
            ecn: 0,
            total_length: 100,
            identification: 1,
            ttl: 64,
            protocol: 6,
            source: [10, 0, 0, 1],
            destination: [10, 0, 0, 2],
            fragmentation: FragmentationState::Fragmented {
                offset: 1,
                more_fragments: true,
                identification: Some(1),
            },
        })),
        transport_layer: None,
        payload: None,
        completeness: PacketCompleteness::Partial {
            reason: pcapraven_domain::PacketTruncationReason::Fragmented,
        },
    };
    let step1 = reconstructor.observe(&p_frag).expect("step1");
    assert_eq!(
        step1.disposition,
        FlowDisposition::Excluded(FlowExclusionReason::FragmentedWithoutTransport)
    );
}

#[test]
fn contradictory_domain_facts_return_invalid_packet_error() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    // Contradictory: IPv4 protocol 6 (TCP) with TransportLayer::Udp
    let mut p = make_ipv4_udp_packet(
        0,
        PacketTimestamp::Unavailable,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        100,
        200,
        None,
    );
    if let Some(NetworkLayer::Ipv4(ref mut ip)) = p.network_layer {
        ip.protocol = 6;
    }

    let err = reconstructor.observe(&p).unwrap_err();
    assert!(matches!(err, FlowError::InvalidNormalizedPacket { .. }));
}

// 6. Resource Limits and Finalization Order Tests

#[test]
fn resource_limits_maximum_tracked_and_instances() {
    let config = FlowReconstructionConfigBuilder::default()
        .maximum_tracked_flows(2)
        .maximum_flow_instances(3)
        .build()
        .expect("config");
    let mut reconstructor = FlowReconstructor::new(config).expect("reconstructor");

    let ip = [10, 0, 0, 1];
    let p0 = make_ipv4_udp_packet(
        0,
        PacketTimestamp::Unavailable,
        ip,
        [10, 0, 0, 2],
        1000,
        2000,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        PacketTimestamp::Unavailable,
        ip,
        [10, 0, 0, 3],
        1000,
        2000,
        None,
    );
    let p2 = make_ipv4_udp_packet(
        2,
        PacketTimestamp::Unavailable,
        ip,
        [10, 0, 0, 4],
        1000,
        2000,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());

    // 3rd flow exceeds maximum_tracked_flows = 2
    let err = reconstructor.observe(&p2).unwrap_err();
    assert!(matches!(
        err,
        FlowError::ResourceLimit {
            limit: "maximum_tracked_flows",
            ..
        }
    ));
}

#[test]
fn finalization_orders_records_by_flow_reference_ordinal() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    // Create flows in order of creation: flow 0, flow 1, flow 2
    let p0 = make_ipv4_udp_packet(
        0,
        PacketTimestamp::Unavailable,
        [10, 0, 0, 9],
        [10, 0, 0, 1],
        10,
        20,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        PacketTimestamp::Unavailable,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        10,
        20,
        None,
    );
    let p2 = make_ipv4_udp_packet(
        2,
        PacketTimestamp::Unavailable,
        [10, 0, 0, 5],
        [10, 0, 0, 2],
        10,
        20,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());
    assert!(reconstructor.observe(&p2).is_ok());

    let finished = reconstructor.finish();
    assert_eq!(finished.len(), 3);
    assert_eq!(finished[0].reference.ordinal(), 0);
    assert_eq!(finished[1].reference.ordinal(), 1);
    assert_eq!(finished[2].reference.ordinal(), 2);
}

#[test]
fn config_builder_validation_rejects_zero_and_excessive_values() {
    assert!(
        FlowReconstructionConfigBuilder::default()
            .tcp_idle_timeout_seconds(0)
            .build()
            .is_err()
    );
    assert!(
        FlowReconstructionConfigBuilder::default()
            .udp_idle_timeout_seconds(0)
            .build()
            .is_err()
    );
    assert!(
        FlowReconstructionConfigBuilder::default()
            .maximum_tracked_flows(0)
            .build()
            .is_err()
    );
    assert!(
        FlowReconstructionConfigBuilder::default()
            .maximum_flow_instances(0)
            .build()
            .is_err()
    );
    assert!(
        FlowReconstructionConfigBuilder::default()
            .maximum_tracked_flows(10_000_000)
            .build()
            .is_err()
    );
}

#[test]
fn payload_truncated_packet_still_associates() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let mut p = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        8080,
        80,
        TcpFlags::from_bits(0x010),
        Some(vec![1, 2, 3]),
    );
    // Policy truncation of payload
    p.completeness = PacketCompleteness::Partial {
        reason: pcapraven_domain::PacketTruncationReason::PayloadBudgetExceeded,
    };

    let step = reconstructor.observe(&p).expect("observe");
    assert!(matches!(step.disposition, FlowDisposition::Associated(_)));
}

#[test]
fn midstream_capture_then_initial_syn_lifecycle() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [192, 168, 1, 50];
    let ip_b = [192, 168, 1, 1];
    let ack = TcpFlags::from_bits(0x010);
    let syn = TcpFlags::from_bits(0x002);

    // Midstream packet without SYN
    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        4000,
        80,
        ack,
        None,
    );
    let s0 = reconstructor.observe(&p0).expect("s0");
    assert_eq!(
        match s0.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );

    // Later initial SYN arrives -> old flow closes with TcpNewInitialSyn
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(110, 0, 0),
        ip_a,
        ip_b,
        4000,
        80,
        syn,
        None,
    );
    let s1 = reconstructor.observe(&p1).expect("s1");
    assert_eq!(s1.closed_flows.len(), 1);
    assert_eq!(s1.closed_flows[0].reference.ordinal(), 0);
    assert_eq!(
        s1.closed_flows[0].end_reason,
        FlowEndReason::TcpNewInitialSyn
    );

    let assoc1 = match s1.disposition {
        FlowDisposition::Associated(a) => a,
        _ => panic!(),
    };
    assert_eq!(assoc1.flow.ordinal(), 1);
}

// 8. Part A Hardening Regression Tests

#[test]
fn idle_timeout_plus_instance_limit_transactional_regression() {
    let config = FlowReconstructionConfigBuilder::default()
        .maximum_flow_instances(1)
        .tcp_idle_timeout_seconds(10)
        .udp_idle_timeout_seconds(5)
        .build()
        .expect("config");
    let mut reconstructor = FlowReconstructor::new(config).expect("reconstructor");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Packet 0 -> creates UDP flow 0
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        None,
    );
    let s0 = reconstructor.observe(&p0).expect("s0");
    assert_eq!(
        match s0.disposition {
            FlowDisposition::Associated(a) => a.flow.ordinal(),
            _ => 99,
        },
        0
    );
    assert_eq!(reconstructor.active_flow_count(), 1);
    assert_eq!(reconstructor.total_flow_instances(), 1);

    // Packet 1 -> same key, timestamp exceeds idle timeout (100 -> 120, timeout = 5s)
    // Would require closing flow 0 and creating flow 1, but maximum_flow_instances = 1
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(120, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        None,
    );
    let err = reconstructor.observe(&p1).unwrap_err();
    assert!(matches!(
        err,
        FlowError::ResourceLimit {
            limit: "maximum_flow_instances",
            ..
        }
    ));

    // Verify transactionality:
    // Flow 0 is still active, count is unchanged, total instances is 1, packet 1 ordinal was not committed
    assert_eq!(reconstructor.active_flow_count(), 1);
    assert_eq!(reconstructor.total_flow_instances(), 1);

    // Finish returns the accepted-prefix flow 0 with EndOfInput
    let finished = reconstructor.finish();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].reference.ordinal(), 0);
    assert_eq!(finished[0].end_reason, FlowEndReason::EndOfInput);
}

#[test]
fn tcp_new_initial_syn_plus_instance_limit_transactional_regression() {
    let config = FlowReconstructionConfigBuilder::default()
        .maximum_flow_instances(1)
        .build()
        .expect("config");
    let mut reconstructor = FlowReconstructor::new(config).expect("reconstructor");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let syn = TcpFlags::from_bits(0x002);
    let ack = TcpFlags::from_bits(0x010);

    // Packet 0 -> SYN creates TCP flow 0
    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());

    // Packet 1 -> ACK progresses past initial SYN retransmission phase
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        ack,
        None,
    );
    assert!(reconstructor.observe(&p1).is_ok());

    // Packet 2 -> new initial SYN after activity while maximum_flow_instances = 1
    let p2 = make_ipv4_tcp_packet(
        2,
        make_timestamp_dec(102, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        None,
    );
    let err = reconstructor.observe(&p2).unwrap_err();
    assert!(matches!(
        err,
        FlowError::ResourceLimit {
            limit: "maximum_flow_instances",
            ..
        }
    ));

    // Verify transactionality:
    // Flow 0 is still active, count is 1, total instances is 1
    assert_eq!(reconstructor.active_flow_count(), 1);
    assert_eq!(reconstructor.total_flow_instances(), 1);

    let finished = reconstructor.finish();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].reference.ordinal(), 0);
    assert_eq!(finished[0].end_reason, FlowEndReason::EndOfInput);
}

#[test]
fn error_retry_does_not_advance_packet_ordinal_regression() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Packet 0 -> valid
    let p0 = make_ipv4_udp_packet(0, PacketTimestamp::Unavailable, ip_a, ip_b, 100, 200, None);
    assert!(reconstructor.observe(&p0).is_ok());

    // Packet 1 -> invalid (captured_len > original_len)
    let mut p1_bad =
        make_ipv4_udp_packet(1, PacketTimestamp::Unavailable, ip_a, ip_b, 100, 200, None);
    p1_bad.reference = PacketReference::new(1, Some(0), Some(0), 100, 50, false);
    let err = reconstructor.observe(&p1_bad).unwrap_err();
    assert!(matches!(err, FlowError::InvalidNormalizedPacket { .. }));

    // Retry with corrected packet at the same ordinal (1) -> MUST succeed because failed observation did not advance ordinal
    let p1_good = make_ipv4_udp_packet(1, PacketTimestamp::Unavailable, ip_a, ip_b, 100, 200, None);
    let step = reconstructor.observe(&p1_good).expect("retry must succeed");
    assert!(matches!(step.disposition, FlowDisposition::Associated(_)));
}

#[test]
fn unsupported_transport_classification_regression() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("valid config");

    // Packet with IPv4 protocol 1 (ICMP) and transport_layer: None
    let p_icmp = NormalizedPacket {
        reference: make_packet_ref(0),
        timestamp: PacketTimestamp::Unavailable,
        link_layer: Some(EthernetMetadata {
            source: MacAddress::new([0, 1, 2, 3, 4, 5]),
            destination: MacAddress::new([6, 7, 8, 9, 10, 11]),
            ethertype: 0x0800,
            link_header_length: 14,
        }),
        network_layer: Some(NetworkLayer::Ipv4(Ipv4Metadata {
            version: 4,
            header_length: 20,
            dscp: 0,
            ecn: 0,
            total_length: 64,
            identification: 1,
            ttl: 64,
            protocol: 1, // ICMP
            source: [10, 0, 0, 1],
            destination: [10, 0, 0, 2],
            fragmentation: FragmentationState::NotFragmented,
        })),
        transport_layer: None,
        payload: None,
        completeness: PacketCompleteness::Unsupported {
            reason: pcapraven_domain::UnsupportedLayerReason::NetworkProtocol(1),
        },
    };

    let step = reconstructor.observe(&p_icmp).expect("observe");
    assert_eq!(
        step.disposition,
        FlowDisposition::Excluded(FlowExclusionReason::UnsupportedTransport)
    );
}

// 7. Property-based Testing with proptest

proptest! {
    #[test]
    fn prop_flow_key_canonical_ordering_and_reversibility(
        src_ip in any::<[u8; 4]>(),
        dst_ip in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        is_tcp in any::<bool>(),
    ) {
        let proto = if is_tcp { TransportProtocol::Tcp } else { TransportProtocol::Udp };
        let ep1 = FlowEndpoint::new(IpAddress::Ipv4(src_ip), src_port);
        let ep2 = FlowEndpoint::new(IpAddress::Ipv4(dst_ip), dst_port);

        let key1 = FlowKey::new(proto, ep1, ep2);
        let key2 = FlowKey::new(proto, ep2, ep1);

        // Property 1: Reversing endpoints produces identical FlowKey
        prop_assert_eq!(key1, key2);

        // Property 2: Always canonical endpoint_a <= endpoint_b
        prop_assert!(key1.endpoint_a() <= key1.endpoint_b());
    }

    #[test]
    fn prop_arbitrary_tcp_flags_never_panic(
        flags_bits in any::<u16>(),
        ordinal in 0u64..100u64,
    ) {
        let mut reconstructor = FlowReconstructor::new(FlowReconstructionConfig::default()).unwrap();
        let flags = TcpFlags::from_bits(flags_bits);
        let p = make_ipv4_tcp_packet(
            ordinal,
            PacketTimestamp::Unavailable,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            flags,
            None,
        );
        let res = reconstructor.observe(&p);
        prop_assert!(res.is_ok());
    }

    #[test]
    fn prop_arbitrary_endpoints_and_ports_never_panic(
        src_ip in any::<[u8; 4]>(),
        dst_ip in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let mut reconstructor = FlowReconstructor::new(FlowReconstructionConfig::default()).unwrap();
        let p = make_ipv4_udp_packet(
            0,
            PacketTimestamp::Unavailable,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            None,
        );
        let res = reconstructor.observe(&p);
        prop_assert!(res.is_ok());
    }

    #[test]
    fn prop_timestamp_combinations_never_overflow_or_panic(
        s1 in any::<i128>(),
        s2 in any::<i128>(),
        f1 in any::<u64>(),
        f2 in any::<u64>(),
        o1 in any::<i64>(),
        o2 in any::<i64>(),
        timeout in 0u32..86400u32,
    ) {
        let t1 = make_timestamp_dec(s1, f1, o1);
        let t2 = make_timestamp_dec(s2, f2, o2);
        let _ = has_timed_out(&t1, &t2, timeout);
    }

    #[test]
    fn prop_reconstruction_determinism(
        count in 1usize..30usize,
    ) {
        let config = FlowReconstructionConfig::default();
        let mut rec1 = FlowReconstructor::new(config).unwrap();
        let mut rec2 = FlowReconstructor::new(config).unwrap();

        let packets: Vec<NormalizedPacket> = (0..count).map(|i| {
            let port = (i % 5) as u16 + 1000;
            make_ipv4_udp_packet(
                i as u64,
                make_timestamp_dec(100 + i as i128, 0, 0),
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                port,
                80,
                None,
            )
        }).collect();

        let mut res1 = Vec::new();
        for p in &packets {
            res1.push(rec1.observe(p).unwrap());
        }
        let fin1 = rec1.finish();

        let mut res2 = Vec::new();
        for p in &packets {
            res2.push(rec2.observe(p).unwrap());
        }
        let fin2 = rec2.finish();

        prop_assert_eq!(res1, res2);
        prop_assert_eq!(fin1, fin2);
    }
}
