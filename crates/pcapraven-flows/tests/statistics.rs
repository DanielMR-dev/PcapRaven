//! Integration tests and property tests for Phase 5 checked flow statistics and exact temporal metrics.

use pcapraven_domain::{
    EthernetMetadata, FlowDuration, FlowEndReason, FlowTemporalUnavailableReason,
    FlowTemporalValue, FragmentationState, Ipv4Metadata, MacAddress, NetworkLayer,
    NormalizedPacket, PacketCompleteness, PacketReference, PacketTimestamp,
    PacketTimestampResolution, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
};
use pcapraven_flows::metrics::exact_duration_between;
use pcapraven_flows::{
    FlowError, FlowReconstructionConfig, FlowReconstructionConfigBuilder, FlowReconstructor,
};
use proptest::prelude::*;

fn make_packet_ref(
    ordinal: u64,
    captured_len: u32,
    original_len: u32,
    truncated: bool,
) -> PacketReference {
    PacketReference::new(
        ordinal,
        Some(0),
        Some(0),
        captured_len,
        original_len,
        truncated,
    )
}

fn make_timestamp_dec(
    seconds: i128,
    fractional_units: u64,
    offset_seconds: i64,
) -> PacketTimestamp {
    PacketTimestamp::Available {
        seconds,
        fractional_units,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 9,
            units_per_second: 1_000_000_000,
        },
        offset_seconds,
    }
}

fn make_timestamp_bin(
    seconds: i128,
    fractional_units: u64,
    exponent: u8,
    offset_seconds: i64,
) -> PacketTimestamp {
    PacketTimestamp::Available {
        seconds,
        fractional_units,
        resolution: PacketTimestampResolution::Binary {
            exponent,
            units_per_second: 1 << exponent,
        },
        offset_seconds,
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
    captured_len: u32,
    original_len: u32,
    truncated: bool,
    payload: Option<Vec<u8>>,
) -> NormalizedPacket {
    NormalizedPacket {
        reference: make_packet_ref(ordinal, captured_len, original_len, truncated),
        timestamp,
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
            total_length: (20 + 20 + payload.as_ref().map_or(0, |p| p.len())) as u16,
            identification: 1,
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
            checksum: 0,
            urgent_pointer: 0,
            options_length_bytes: 0,
        })),
        payload,
        completeness: PacketCompleteness::Complete,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_ipv4_udp_packet(
    ordinal: u64,
    timestamp: PacketTimestamp,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    captured_len: u32,
    original_len: u32,
    truncated: bool,
    payload: Option<Vec<u8>>,
) -> NormalizedPacket {
    NormalizedPacket {
        reference: make_packet_ref(ordinal, captured_len, original_len, truncated),
        timestamp,
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
            total_length: (20 + 8 + payload.as_ref().map_or(0, |p| p.len())) as u16,
            identification: 1,
            ttl: 64,
            protocol: 17,
            source: src_ip,
            destination: dst_ip,
            fragmentation: FragmentationState::NotFragmented,
        })),
        transport_layer: Some(TransportLayer::Udp(UdpMetadata {
            source_port: src_port,
            destination_port: dst_port,
            length: (8 + payload.as_ref().map_or(0, |p| p.len())) as u16,
            checksum: 0,
        })),
        payload,
        completeness: PacketCompleteness::Complete,
    }
}

// 1. Basic Traffic Statistics Tests

#[test]
fn basic_traffic_statistics_directional_buckets() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // 2 A->B packets (captured = 60, wire = 60, truncated = false)
    // and (captured = 40, wire = 100, truncated = true)
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        60,
        60,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        40,
        100,
        true,
        None,
    );

    // 3 B->A packets
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(102, 0, 0),
        ip_b,
        ip_a,
        2000,
        1000,
        50,
        50,
        false,
        None,
    );
    let p3 = make_ipv4_udp_packet(
        3,
        make_timestamp_dec(103, 0, 0),
        ip_b,
        ip_a,
        2000,
        1000,
        70,
        70,
        false,
        None,
    );
    let p4 = make_ipv4_udp_packet(
        4,
        make_timestamp_dec(104, 0, 0),
        ip_b,
        ip_a,
        2000,
        1000,
        80,
        80,
        false,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());
    assert!(reconstructor.observe(&p2).is_ok());
    assert!(reconstructor.observe(&p3).is_ok());
    assert!(reconstructor.observe(&p4).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    // Verify Total bucket
    assert_eq!(flow.traffic.total.packet_count, 5);
    assert_eq!(flow.traffic.total.captured_bytes, 60 + 40 + 50 + 70 + 80); // 300
    assert_eq!(flow.traffic.total.wire_bytes, 60 + 100 + 50 + 70 + 80); // 360
    assert_eq!(flow.traffic.total.truncated_packet_count, 1);

    // Verify AToB bucket
    assert_eq!(flow.traffic.a_to_b.packet_count, 2);
    assert_eq!(flow.traffic.a_to_b.captured_bytes, 100);
    assert_eq!(flow.traffic.a_to_b.wire_bytes, 160);
    assert_eq!(flow.traffic.a_to_b.truncated_packet_count, 1);

    // Verify BToA bucket
    assert_eq!(flow.traffic.b_to_a.packet_count, 3);
    assert_eq!(flow.traffic.b_to_a.captured_bytes, 200);
    assert_eq!(flow.traffic.b_to_a.wire_bytes, 200);
    assert_eq!(flow.traffic.b_to_a.truncated_packet_count, 0);

    // Verify SameEndpoint bucket
    assert_eq!(flow.traffic.same_endpoint.packet_count, 0);
    assert_eq!(flow.traffic.same_endpoint.captured_bytes, 0);
    assert_eq!(flow.traffic.same_endpoint.wire_bytes, 0);
    assert_eq!(flow.traffic.same_endpoint.truncated_packet_count, 0);

    // Verify directional invariant
    assert_eq!(
        flow.traffic.total.packet_count,
        flow.traffic.a_to_b.packet_count
            + flow.traffic.b_to_a.packet_count
            + flow.traffic.same_endpoint.packet_count
    );
    assert_eq!(
        flow.traffic.total.captured_bytes,
        flow.traffic.a_to_b.captured_bytes
            + flow.traffic.b_to_a.captured_bytes
            + flow.traffic.same_endpoint.captured_bytes
    );
    assert_eq!(
        flow.traffic.total.wire_bytes,
        flow.traffic.a_to_b.wire_bytes
            + flow.traffic.b_to_a.wire_bytes
            + flow.traffic.same_endpoint.wire_bytes
    );
    assert_eq!(
        flow.traffic.total.truncated_packet_count,
        flow.traffic.a_to_b.truncated_packet_count
            + flow.traffic.b_to_a.truncated_packet_count
            + flow.traffic.same_endpoint.truncated_packet_count
    );
}

#[test]
fn same_endpoint_traffic_counters() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_self = [127, 0, 0, 1];
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_self,
        ip_self,
        5000,
        5000,
        64,
        64,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_self,
        ip_self,
        5000,
        5000,
        32,
        64,
        true,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    assert_eq!(flow.traffic.total.packet_count, 2);
    assert_eq!(flow.traffic.total.captured_bytes, 96);
    assert_eq!(flow.traffic.total.wire_bytes, 128);
    assert_eq!(flow.traffic.total.truncated_packet_count, 1);

    assert_eq!(flow.traffic.same_endpoint.packet_count, 2);
    assert_eq!(flow.traffic.same_endpoint.captured_bytes, 96);
    assert_eq!(flow.traffic.same_endpoint.wire_bytes, 128);
    assert_eq!(flow.traffic.same_endpoint.truncated_packet_count, 1);

    assert_eq!(flow.traffic.a_to_b.packet_count, 0);
    assert_eq!(flow.traffic.b_to_a.packet_count, 0);
}

#[test]
fn invalid_packet_length_invariant_rejected() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // captured_len (200) > original_len (100)
    let p = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        200,
        100,
        false,
        None,
    );

    let err = reconstructor.observe(&p).unwrap_err();
    assert!(matches!(err, FlowError::InvalidNormalizedPacket { .. }));
    assert_eq!(reconstructor.active_flow_count(), 0);
    assert_eq!(reconstructor.total_flow_instances(), 0);
}

// 2. Exact Temporal Arithmetic and Representation Tests

#[test]
fn one_packet_duration_is_zero_and_insufficient_samples() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(500, 250_000_000, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    // Duration is exactly 0/1 seconds
    assert_eq!(
        flow.temporal.duration,
        FlowTemporalValue::Available(FlowDuration::ZERO)
    );
    assert_eq!(flow.temporal.duration.value().unwrap().numerator(), 0);
    assert_eq!(flow.temporal.duration.value().unwrap().denominator(), 1);

    // Inter-arrival metrics have insufficient samples
    let overall = &flow.temporal.overall_inter_arrival;
    assert_eq!(overall.interval_sample_count, 0);
    assert_eq!(overall.discontinuity_count, 0);
    assert_eq!(
        overall.minimum_interval,
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
    );
    assert_eq!(
        overall.maximum_interval,
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
    );
    assert_eq!(
        overall.mean_interval,
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
    );
    assert_eq!(overall.successive_delta_sample_count, 0);
    assert_eq!(
        overall.mean_absolute_successive_interval_delta,
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
    );
}

#[test]
fn simple_exact_intervals_and_successive_deltas() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Timestamps: 0s, 1s, 3s
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(0, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(1, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(3, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());
    assert!(reconstructor.observe(&p2).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    // Duration: 3s - 0s = 3s
    assert_eq!(
        flow.temporal.duration,
        FlowTemporalValue::Available(FlowDuration::from_secs(3))
    );

    let overall = &flow.temporal.overall_inter_arrival;
    // Intervals: 1s, 2s
    assert_eq!(overall.interval_sample_count, 2);
    assert_eq!(
        overall.minimum_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(1))
    );
    assert_eq!(
        overall.maximum_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(2))
    );
    // Mean: (1 + 2) / 2 = 3/2s
    assert_eq!(
        overall.mean_interval,
        FlowTemporalValue::Available(FlowDuration::from_fraction(3, 2).unwrap())
    );

    // Successive delta: |2 - 1| = 1s (1 sample)
    assert_eq!(overall.successive_delta_sample_count, 1);
    assert_eq!(
        overall.mean_absolute_successive_interval_delta,
        FlowTemporalValue::Available(FlowDuration::from_secs(1))
    );
}

#[test]
fn zero_interval_is_valid_sample() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Equal consecutive timestamps: 10.500s and 10.500s
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(10, 500_000_000, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(10, 500_000_000, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    let overall = &flow.temporal.overall_inter_arrival;
    assert_eq!(overall.interval_sample_count, 1);
    assert_eq!(
        overall.minimum_interval,
        FlowTemporalValue::Available(FlowDuration::ZERO)
    );
    assert_eq!(
        overall.maximum_interval,
        FlowTemporalValue::Available(FlowDuration::ZERO)
    );
    assert_eq!(
        overall.mean_interval,
        FlowTemporalValue::Available(FlowDuration::ZERO)
    );
}

#[test]
fn decimal_and_binary_timestamp_resolutions_and_mixed_exact_duration() {
    // 1. Decimal fraction: 100.250s to 100.750s -> 0.5s = 1/2s
    let t1 = make_timestamp_dec(100, 250_000_000, 0);
    let t2 = make_timestamp_dec(100, 750_000_000, 0);
    let d1 = exact_duration_between(&t1, &t2).expect("valid delta");
    assert_eq!(d1, FlowDuration::from_fraction(1, 2).unwrap());

    // 2. Binary fraction: 2^-2 (exponent 2 = 4 units/s, frac 1 = 1/4s)
    // to 2^-2 (frac 3 = 3/4s) -> delta = 2/4s = 1/2s
    let tb1 = make_timestamp_bin(200, 1, 2, 0);
    let tb2 = make_timestamp_bin(200, 3, 2, 0);
    let db = exact_duration_between(&tb1, &tb2).expect("valid delta");
    assert_eq!(db, FlowDuration::from_fraction(1, 2).unwrap());

    // 3. Mixed Decimal + Binary:
    // t_dec = 100s + 250_000_000 ns (1/4s)
    // t_bin = 102s + 2^-1 s (1/2s, exponent 1, frac 1)
    // Delta = 2s + (1/2 - 1/4)s = 2s + 1/4s = 9/4s
    let t_dec = make_timestamp_dec(100, 250_000_000, 0);
    let t_bin = make_timestamp_bin(102, 1, 1, 0);
    let d_mixed = exact_duration_between(&t_dec, &t_bin).expect("valid mixed delta");
    assert_eq!(d_mixed, FlowDuration::from_fraction(9, 4).unwrap());
    assert_eq!(d_mixed.numerator(), 9);
    assert_eq!(d_mixed.denominator(), 4);
}

#[test]
fn signed_timestamp_offsets_handled_correctly() {
    // t1: 100s with offset +5s -> eff = 105s
    // t2: 110s with offset -2s -> eff = 108s
    // Delta = 108 - 105 = 3s
    let t1 = make_timestamp_dec(100, 0, 5);
    let t2 = make_timestamp_dec(110, 0, -2);
    let d = exact_duration_between(&t1, &t2).expect("valid delta");
    assert_eq!(d, FlowDuration::from_secs(3));
}

#[test]
fn unavailable_and_interior_missing_timestamps() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // t0: valid 10s
    // t1: unavailable
    // t2: valid 14s
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(10, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        PacketTimestamp::Unavailable,
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(14, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());
    assert!(reconstructor.observe(&p2).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    // Traffic count is 3
    assert_eq!(flow.traffic.total.packet_count, 3);

    // Coverage has 2 available, 1 unavailable
    assert_eq!(flow.temporal.coverage.available_timestamps, 2);
    assert_eq!(flow.temporal.coverage.unavailable_timestamps, 1);

    // Duration is first-to-last (14 - 10 = 4s) because both first and last are valid
    assert_eq!(
        flow.temporal.duration,
        FlowTemporalValue::Available(FlowDuration::from_secs(4))
    );

    // Inter-arrival has 0 samples and 1 discontinuity because t1 broke the chain
    let overall = &flow.temporal.overall_inter_arrival;
    assert_eq!(overall.interval_sample_count, 0);
    assert_eq!(overall.discontinuity_count, 1);
}

#[test]
fn non_monotonic_timestamp_handling() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Ordinals 0, 1, 2 with timestamps 100s, 90s, 95s
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(90, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(95, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());
    assert!(reconstructor.observe(&p2).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    // Coverage records 1 non-monotonic transition
    assert_eq!(flow.temporal.coverage.non_monotonic_transitions, 1);

    // First (100) to last (95) is non-monotonic -> duration is Unavailable(NonMonotonicTimestamp)
    assert_eq!(
        flow.temporal.duration,
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::NonMonotonicTimestamp)
    );

    // Inter-arrival: 100 -> 90 was non-monotonic (discontinuity + re-anchor at 90)
    // 90 -> 95 was valid (interval = 5s)
    let overall = &flow.temporal.overall_inter_arrival;
    assert_eq!(overall.interval_sample_count, 1);
    assert_eq!(overall.discontinuity_count, 1);
    assert_eq!(
        overall.minimum_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(5))
    );
    assert_eq!(
        overall.maximum_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(5))
    );
    assert_eq!(
        overall.mean_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(5))
    );
}

#[test]
fn directional_temporal_and_gap_isolation() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // A->B at 0s, B->A at 1s, A->B at 2s, B->A at 4s
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(0, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(1, 0, 0),
        ip_b,
        ip_a,
        2000,
        1000,
        64,
        64,
        false,
        None,
    );
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(2, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p3 = make_ipv4_udp_packet(
        3,
        make_timestamp_dec(4, 0, 0),
        ip_b,
        ip_a,
        2000,
        1000,
        64,
        64,
        false,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());
    assert!(reconstructor.observe(&p2).is_ok());
    assert!(reconstructor.observe(&p3).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    let flow = &records[0];

    // Overall series: intervals (1 - 0 = 1s), (2 - 1 = 1s), (4 - 2 = 2s) -> sample_count = 3
    let overall = &flow.temporal.overall_inter_arrival;
    assert_eq!(overall.interval_sample_count, 3);
    assert_eq!(
        overall.minimum_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(1))
    );
    assert_eq!(
        overall.maximum_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(2))
    );
    // Mean: (1 + 1 + 2) / 3 = 4/3s
    assert_eq!(
        overall.mean_interval,
        FlowTemporalValue::Available(FlowDuration::from_fraction(4, 3).unwrap())
    );

    // A->B series: interval (2 - 0 = 2s) -> sample_count = 1
    let a_to_b = &flow.temporal.a_to_b_inter_arrival;
    assert_eq!(a_to_b.interval_sample_count, 1);
    assert_eq!(
        a_to_b.mean_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(2))
    );

    // B->A series: interval (4 - 1 = 3s) -> sample_count = 1
    let b_to_a = &flow.temporal.b_to_a_inter_arrival;
    assert_eq!(b_to_a.interval_sample_count, 1);
    assert_eq!(
        b_to_a.mean_interval,
        FlowTemporalValue::Available(FlowDuration::from_secs(3))
    );
}

// 3. Lifecycle Boundary Statistics & Metrics Tests

#[test]
fn tcp_reset_statistics_and_temporal_inclusion() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let ack = TcpFlags::from_bits(0x010);
    let rst = TcpFlags::from_bits(0x004);

    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        ack,
        50,
        50,
        false,
        None,
    );
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(102, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        rst,
        40,
        40,
        false,
        None,
    );

    let s0 = reconstructor.observe(&p0).expect("s0");
    assert!(s0.closed_flows.is_empty());

    let s1 = reconstructor.observe(&p1).expect("s1");
    assert_eq!(s1.closed_flows.len(), 1);
    let closed = &s1.closed_flows[0];

    assert_eq!(closed.end_reason, FlowEndReason::TcpReset);
    assert_eq!(closed.traffic.total.packet_count, 2);
    assert_eq!(closed.traffic.total.captured_bytes, 90);
    assert_eq!(closed.traffic.a_to_b.packet_count, 1);
    assert_eq!(closed.traffic.b_to_a.packet_count, 1);
    assert_eq!(
        closed.temporal.duration,
        FlowTemporalValue::Available(FlowDuration::from_secs(2))
    );
}

#[test]
fn idle_timeout_boundary_statistics_attribution() {
    let config = FlowReconstructionConfigBuilder::default()
        .udp_idle_timeout_seconds(5)
        .build()
        .expect("config");
    let mut reconstructor = FlowReconstructor::new(config).expect("reconstructor");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Flow 0: packets 0 and 1 (timestamps 100s, 102s)
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        50,
        50,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(102, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        60,
        60,
        false,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());

    // Packet 2: timestamp 110s (exceeds 5s timeout)
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(110, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        70,
        70,
        false,
        None,
    );
    let step2 = reconstructor.observe(&p2).expect("s2");

    // Old flow 0 was closed with IdleTimeout
    assert_eq!(step2.closed_flows.len(), 1);
    let flow0 = &step2.closed_flows[0];
    assert_eq!(flow0.end_reason, FlowEndReason::IdleTimeout);
    assert_eq!(flow0.traffic.total.packet_count, 2);
    assert_eq!(flow0.traffic.total.captured_bytes, 110);
    assert_eq!(
        flow0.temporal.duration,
        FlowTemporalValue::Available(FlowDuration::from_secs(2))
    );

    // New flow 1 is active with packet 2
    let remaining = reconstructor.finish();
    assert_eq!(remaining.len(), 1);
    let flow1 = &remaining[0];
    assert_eq!(flow1.reference.ordinal(), 1);
    assert_eq!(flow1.traffic.total.packet_count, 1);
    assert_eq!(flow1.traffic.total.captured_bytes, 70);
    assert_eq!(
        flow1.temporal.duration,
        FlowTemporalValue::Available(FlowDuration::ZERO)
    );
}

#[test]
fn new_syn_statistics_regression() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let syn = TcpFlags::from_bits(0x002);
    let ack = TcpFlags::from_bits(0x010);

    // Initial SYN (packet 0, flow 0)
    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        50,
        50,
        false,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());

    // ACK progresses past initial SYN retransmission (packet 1, flow 0)
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        ack,
        60,
        60,
        false,
        None,
    );
    assert!(reconstructor.observe(&p1).is_ok());

    // New initial SYN arrives (packet 2) -> closes flow 0 with TcpNewInitialSyn, starts flow 1
    let p2 = make_ipv4_tcp_packet(
        2,
        make_timestamp_dec(102, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        syn,
        70,
        70,
        false,
        None,
    );
    let step2 = reconstructor.observe(&p2).expect("s2");

    assert_eq!(step2.closed_flows.len(), 1);
    let flow0 = &step2.closed_flows[0];
    assert_eq!(flow0.end_reason, FlowEndReason::TcpNewInitialSyn);
    assert_eq!(flow0.traffic.total.packet_count, 2);
    assert_eq!(flow0.traffic.total.captured_bytes, 110);

    let finished = reconstructor.finish();
    assert_eq!(finished.len(), 1);
    let flow1 = &finished[0];
    assert_eq!(flow1.reference.ordinal(), 1);
    assert_eq!(flow1.traffic.total.packet_count, 1);
    assert_eq!(flow1.traffic.total.captured_bytes, 70);
}

#[test]
fn fin_statistics_regression() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let fin_ack = TcpFlags::from_bits(0x011);
    let ack = TcpFlags::from_bits(0x010);

    let p0 = make_ipv4_tcp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        ack,
        50,
        50,
        false,
        None,
    );
    let p1 = make_ipv4_tcp_packet(
        1,
        make_timestamp_dec(101, 0, 0),
        ip_a,
        ip_b,
        1000,
        80,
        fin_ack,
        50,
        50,
        false,
        None,
    );
    let p2 = make_ipv4_tcp_packet(
        2,
        make_timestamp_dec(102, 0, 0),
        ip_b,
        ip_a,
        80,
        1000,
        ack,
        50,
        50,
        false,
        None,
    );

    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());
    assert!(reconstructor.observe(&p2).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].traffic.total.packet_count, 3);
}

#[test]
fn flow_reuse_resets_statistics_and_temporal_anchors() {
    let config = FlowReconstructionConfigBuilder::default()
        .udp_idle_timeout_seconds(5)
        .build()
        .expect("config");
    let mut reconstructor = FlowReconstructor::new(config).expect("reconstructor");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Flow 0: packet 0 at 100s
    let p0 = make_ipv4_udp_packet(
        0,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        100,
        100,
        false,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());

    // Flow 1 (after timeout): packet 1 at 200s (100s elapsed)
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(200, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        50,
        50,
        false,
        None,
    );
    let step1 = reconstructor.observe(&p1).expect("step1");
    assert_eq!(step1.closed_flows.len(), 1);
    let flow0 = &step1.closed_flows[0];
    assert_eq!(flow0.traffic.total.packet_count, 1);
    assert_eq!(flow0.traffic.total.captured_bytes, 100);

    // Flow 1: packet 2 at 202s
    let p2 = make_ipv4_udp_packet(
        2,
        make_timestamp_dec(202, 0, 0),
        ip_a,
        ip_b,
        5000,
        6000,
        60,
        60,
        false,
        None,
    );
    assert!(reconstructor.observe(&p2).is_ok());

    let finished = reconstructor.finish();
    assert_eq!(finished.len(), 1);
    let flow1 = &finished[0];
    assert_eq!(flow1.reference.ordinal(), 1);
    // Flow 1 contains ONLY packets 1 and 2 (total = 2, bytes = 110, duration = 2s)
    assert_eq!(flow1.traffic.total.packet_count, 2);
    assert_eq!(flow1.traffic.total.captured_bytes, 110);
    assert_eq!(
        flow1.temporal.duration,
        FlowTemporalValue::Available(FlowDuration::from_secs(2))
    );
}

#[test]
fn first_or_last_timestamp_unavailable() {
    let mut reconstructor =
        FlowReconstructor::new(FlowReconstructionConfig::default()).expect("config");

    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Case A: first packet timestamp unavailable
    let p0 = make_ipv4_udp_packet(
        0,
        PacketTimestamp::Unavailable,
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    let p1 = make_ipv4_udp_packet(
        1,
        make_timestamp_dec(100, 0, 0),
        ip_a,
        ip_b,
        1000,
        2000,
        64,
        64,
        false,
        None,
    );
    assert!(reconstructor.observe(&p0).is_ok());
    assert!(reconstructor.observe(&p1).is_ok());

    let records = reconstructor.finish();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].temporal.duration,
        FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::TimestampUnavailable)
    );
}

#[test]
fn invalid_timestamp_structure_and_arithmetic_overflow() {
    // 1. Invalid timestamp: units_per_second == 0
    let t_zero_units = PacketTimestamp::Available {
        seconds: 100,
        fractional_units: 0,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 0,
            units_per_second: 0,
        },
        offset_seconds: 0,
    };
    assert_eq!(
        pcapraven_flows::metrics::validate_timestamp_structure(&t_zero_units),
        Err(FlowTemporalUnavailableReason::InvalidTimestamp)
    );

    // 2. Invalid timestamp: fractional_units >= units_per_second
    let t_bad_frac = PacketTimestamp::Available {
        seconds: 100,
        fractional_units: 1_000_000_000,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 9,
            units_per_second: 1_000_000_000,
        },
        offset_seconds: 0,
    };
    assert_eq!(
        pcapraven_flows::metrics::validate_timestamp_structure(&t_bad_frac),
        Err(FlowTemporalUnavailableReason::InvalidTimestamp)
    );

    // 3. Invalid timestamp: Decimal exponent does not match units_per_second
    let t_bad_exp = PacketTimestamp::Available {
        seconds: 100,
        fractional_units: 0,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 3,
            units_per_second: 100, // Expected 1000
        },
        offset_seconds: 0,
    };
    assert_eq!(
        pcapraven_flows::metrics::validate_timestamp_structure(&t_bad_exp),
        Err(FlowTemporalUnavailableReason::InvalidTimestamp)
    );
}

// 4. Property-based Testing with proptest

proptest! {
    #[test]
    fn prop_traffic_counters_directional_invariants(
        a_to_b_count in 0usize..10usize,
        b_to_a_count in 0usize..10usize,
    ) {
        let mut reconstructor = FlowReconstructor::new(FlowReconstructionConfig::default()).unwrap();
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];

        let mut ordinal = 0u64;

        // A->B
        for _ in 0..a_to_b_count {
            let p = make_ipv4_udp_packet(ordinal, make_timestamp_dec(100 + ordinal as i128, 0, 0), ip_a, ip_b, 1000, 2000, 50, 60, true, None);
            ordinal += 1;
            reconstructor.observe(&p).unwrap();
        }

        // B->A
        for _ in 0..b_to_a_count {
            let p = make_ipv4_udp_packet(ordinal, make_timestamp_dec(100 + ordinal as i128, 0, 0), ip_b, ip_a, 2000, 1000, 70, 70, false, None);
            ordinal += 1;
            reconstructor.observe(&p).unwrap();
        }

        let total_expected = a_to_b_count + b_to_a_count;
        if total_expected > 0 {
            let records = reconstructor.finish();
            prop_assert_eq!(records.len(), 1);
            let flow = &records[0];

            // Invariant 1: Total packet count == AToB + BToA + SameEndpoint
            prop_assert_eq!(
                flow.traffic.total.packet_count,
                flow.traffic.a_to_b.packet_count + flow.traffic.b_to_a.packet_count + flow.traffic.same_endpoint.packet_count
            );
            prop_assert_eq!(flow.traffic.total.packet_count, total_expected as u64);

            // Invariant 2: Captured bytes directional sum
            prop_assert_eq!(
                flow.traffic.total.captured_bytes,
                flow.traffic.a_to_b.captured_bytes + flow.traffic.b_to_a.captured_bytes + flow.traffic.same_endpoint.captured_bytes
            );

            // Invariant 3: Wire bytes directional sum
            prop_assert_eq!(
                flow.traffic.total.wire_bytes,
                flow.traffic.a_to_b.wire_bytes + flow.traffic.b_to_a.wire_bytes + flow.traffic.same_endpoint.wire_bytes
            );

            // Invariant 4: Truncated packets directional sum
            prop_assert_eq!(
                flow.traffic.total.truncated_packet_count,
                flow.traffic.a_to_b.truncated_packet_count + flow.traffic.b_to_a.truncated_packet_count + flow.traffic.same_endpoint.truncated_packet_count
            );
        }
    }

    #[test]
    fn prop_flow_duration_rational_invariants(
        s1 in 0i128..1_000_000i128,
        s2 in 0i128..1_000_000i128,
        f1 in 0u64..1_000_000_000u64,
        f2 in 0u64..1_000_000_000u64,
    ) {
        let t1 = make_timestamp_dec(s1, f1, 0);
        let t2 = make_timestamp_dec(s2, f2, 0);

        if let Ok(duration) = exact_duration_between(&t1, &t2) {
            // Property 7: denominator > 0
            prop_assert!(duration.denominator() > 0);

            // Property 8: canonically reduced (gcd(num, den) == 1)
            let g = pcapraven_flows::metrics::gcd(duration.numerator(), duration.denominator());
            prop_assert_eq!(g, 1);

            // Property 9: zero duration canonicalizes to 0/1
            if duration.numerator() == 0 {
                prop_assert_eq!(duration.denominator(), 1);
            }
        }
    }

    #[test]
    fn prop_inter_arrival_statistical_ordering(
        step_count in 2usize..20usize,
    ) {
        let mut reconstructor = FlowReconstructor::new(FlowReconstructionConfig::default()).unwrap();
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];

        for i in 0..step_count {
            let p = make_ipv4_udp_packet(
                i as u64,
                make_timestamp_dec(100 + (i * i) as i128, 0, 0),
                ip_a,
                ip_b,
                1000,
                2000,
                64,
                64,
                false,
                None,
            );
            reconstructor.observe(&p).unwrap();
        }

        let records = reconstructor.finish();
        prop_assert_eq!(records.len(), 1);
        let flow = &records[0];
        let overall = &flow.temporal.overall_inter_arrival;

        if overall.interval_sample_count > 0 {
            if let (Some(min), Some(mean), Some(max)) = (
                overall.minimum_interval.value(),
                overall.mean_interval.value(),
                overall.maximum_interval.value(),
            ) {
                // Property 10: min <= mean <= max
                prop_assert!(min <= mean);
                prop_assert!(mean <= max);
            }

            // Property 11: successive delta count < interval_sample_count
            prop_assert!(overall.successive_delta_sample_count < overall.interval_sample_count);
        }
    }
}
