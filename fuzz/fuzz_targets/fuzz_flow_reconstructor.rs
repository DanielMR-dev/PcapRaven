#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    EthernetMetadata, FlowInterArrivalMetrics, FlowRecord, FragmentationState, Ipv4Metadata,
    Ipv6Metadata, MacAddress, NetworkLayer, NormalizedPacket, PacketCompleteness, PacketReference,
    PacketTimestamp, PacketTimestampResolution, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
};
use pcapraven_flows::{FlowReconstructionConfigBuilder, FlowReconstructor};

fn checked_directional_sum(a: u64, b: u64, same: u64) -> Option<u64> {
    a.checked_add(b)?.checked_add(same)
}

fn assert_inter_arrival(metrics: &FlowInterArrivalMetrics) {
    for duration in [
        metrics.minimum_interval.value(),
        metrics.maximum_interval.value(),
        metrics.mean_interval.value(),
        metrics.mean_absolute_successive_interval_delta.value(),
    ]
    .into_iter()
    .flatten()
    {
        assert_ne!(duration.denominator(), 0);
        assert_eq!(
            pcapraven_flows::metrics::gcd(duration.numerator(), duration.denominator()),
            1
        );
    }
    if let (Some(minimum), Some(mean), Some(maximum)) = (
        metrics.minimum_interval.value(),
        metrics.mean_interval.value(),
        metrics.maximum_interval.value(),
    ) {
        assert!(minimum <= mean);
        assert!(mean <= maximum);
    }
    assert!(
        metrics.successive_delta_sample_count
            <= metrics.interval_sample_count.saturating_sub(1)
    );
    assert_eq!(
        metrics.mean_absolute_successive_interval_delta.value().is_some(),
        metrics.successive_delta_sample_count > 0
    );
    assert_eq!(
        metrics.minimum_interval.value().is_some(),
        metrics.interval_sample_count > 0
    );
    assert_eq!(
        metrics.maximum_interval.value().is_some(),
        metrics.interval_sample_count > 0
    );
    assert_eq!(
        metrics.mean_interval.value().is_some(),
        metrics.interval_sample_count > 0
    );
}

fn assert_flow(flow: &FlowRecord) {
    assert!(flow.key.endpoint_a() <= flow.key.endpoint_b());
    assert!(
        flow.first_packet.capture_record_ordinal()
            <= flow.last_packet.capture_record_ordinal()
    );
    let total = &flow.traffic.total;
    let a = &flow.traffic.a_to_b;
    let b = &flow.traffic.b_to_a;
    let same = &flow.traffic.same_endpoint;
    assert_eq!(
        Some(total.packet_count),
        checked_directional_sum(a.packet_count, b.packet_count, same.packet_count)
    );
    assert_eq!(
        Some(total.captured_bytes),
        checked_directional_sum(a.captured_bytes, b.captured_bytes, same.captured_bytes)
    );
    assert_eq!(
        Some(total.wire_bytes),
        checked_directional_sum(a.wire_bytes, b.wire_bytes, same.wire_bytes)
    );
    assert_eq!(
        Some(total.truncated_packet_count),
        checked_directional_sum(
            a.truncated_packet_count,
            b.truncated_packet_count,
            same.truncated_packet_count,
        )
    );
    if let Some(duration) = flow.temporal.duration.value() {
        assert_ne!(duration.denominator(), 0);
        assert_eq!(
            pcapraven_flows::metrics::gcd(duration.numerator(), duration.denominator()),
            1
        );
    }
    let coverage = &flow.temporal.coverage;
    assert_eq!(
        Some(total.packet_count),
        coverage
            .available_timestamps
            .checked_add(coverage.unavailable_timestamps)
            .and_then(|count| count.checked_add(coverage.invalid_timestamps))
    );
    assert!(
        flow.temporal
            .overall_inter_arrival
            .interval_sample_count
            .checked_add(flow.temporal.overall_inter_arrival.discontinuity_count)
            .is_some_and(|count| count <= total.packet_count)
    );
    assert!(
        flow.temporal.a_to_b_inter_arrival.interval_sample_count
            <= a.packet_count.saturating_sub(1)
    );
    assert!(
        flow.temporal.b_to_a_inter_arrival.interval_sample_count
            <= b.packet_count.saturating_sub(1)
    );
    assert!(
        flow.temporal
            .same_endpoint_inter_arrival
            .interval_sample_count
            <= same.packet_count.saturating_sub(1)
    );
    assert_inter_arrival(&flow.temporal.overall_inter_arrival);
    assert_inter_arrival(&flow.temporal.a_to_b_inter_arrival);
    assert_inter_arrival(&flow.temporal.b_to_a_inter_arrival);
    assert_inter_arrival(&flow.temporal.same_endpoint_inter_arrival);
}

fn packets(data: &[u8]) -> Vec<NormalizedPacket> {
    let mut packets = Vec::new();
    for (ordinal, raw) in data.chunks_exact(18).take(40).enumerate() {
        let Ok(chunk) = <&[u8; 18]>::try_from(raw) else {
            continue;
        };
        let [control, p1, p2, p3, p4, f1, f2, t1, t2, t3, t4, q1, q2, q3, q4, offset, w1, w2] =
            *chunk;
        let is_ipv6 = control & 0x01 != 0;
        let is_udp = control & 0x02 != 0;
        let has_timestamp = control & 0x04 != 0;
        let is_binary_timestamp = control & 0x08 != 0;
        let truncated = control & 0x10 != 0;
        let source_port = u16::from_be_bytes([p1, p2]);
        let destination_port = u16::from_be_bytes([p3, p4]);
        let flags = u16::from_be_bytes([f1, f2]);
        let seconds = i128::from(i32::from_be_bytes([t1, t2, t3, t4]));
        let fractional = u64::from(u32::from_be_bytes([q1, q2, q3, q4]));
        let offset_seconds = i64::from(i8::from_ne_bytes([offset]));
        let original_length = u32::from(u16::from_be_bytes([w1, w2])).max(40);
        let captured_length = if truncated {
            original_length.min(60)
        } else {
            original_length
        };
        let timestamp = if !has_timestamp {
            PacketTimestamp::Unavailable
        } else if is_binary_timestamp {
            PacketTimestamp::Available {
                seconds,
                fractional_units: fractional,
                resolution: PacketTimestampResolution::Binary {
                    exponent: 32,
                    units_per_second: 1_u64 << 32,
                },
                offset_seconds,
            }
        } else {
            PacketTimestamp::Available {
                seconds,
                fractional_units: fractional % 1_000_000_000,
                resolution: PacketTimestampResolution::Decimal {
                    exponent: 9,
                    units_per_second: 1_000_000_000,
                },
                offset_seconds,
            }
        };
        let network_layer = if is_ipv6 {
            let mut source = [0_u8; 16];
            let mut destination = [0_u8; 16];
            source[0] = p1;
            source[15] = p2;
            destination[0] = p3;
            destination[15] = p4;
            NetworkLayer::Ipv6(Ipv6Metadata {
                version: 6,
                traffic_class: 0,
                flow_label: 0,
                payload_length: 20,
                next_header: if is_udp { 17 } else { 6 },
                hop_limit: 64,
                source,
                destination,
                extension_headers_count: 0,
                extension_headers_length: 0,
                effective_protocol: if is_udp { 17 } else { 6 },
                fragmentation: FragmentationState::NotFragmented,
            })
        } else {
            NetworkLayer::Ipv4(Ipv4Metadata {
                version: 4,
                header_length: 20,
                dscp: 0,
                ecn: 0,
                total_length: 40,
                identification: 1,
                ttl: 64,
                protocol: if is_udp { 17 } else { 6 },
                source: [192, 0, 2, p2],
                destination: [198, 51, 100, p4],
                fragmentation: FragmentationState::NotFragmented,
            })
        };
        let transport_layer = if is_udp {
            TransportLayer::Udp(UdpMetadata {
                source_port,
                destination_port,
                length: 8,
                checksum: 0,
            })
        } else {
            TransportLayer::Tcp(TcpMetadata {
                source_port,
                destination_port,
                sequence_number: 1000,
                acknowledgement_number: 0,
                data_offset_bytes: 20,
                flags: TcpFlags::from_bits(flags),
                window_size: 65_535,
                checksum: 0,
                urgent_pointer: 0,
                options_length_bytes: 0,
            })
        };
        let Ok(ordinal) = u64::try_from(ordinal) else {
            break;
        };
        packets.push(NormalizedPacket {
            reference: PacketReference::new(
                ordinal,
                Some(0),
                Some(0),
                captured_length,
                original_length,
                truncated,
            ),
            timestamp,
            link_layer: Some(EthernetMetadata {
                source: MacAddress::new([0, 1, 2, 3, 4, 5]),
                destination: MacAddress::new([6, 7, 8, 9, 10, 11]),
                ethertype: if is_ipv6 { 0x86dd } else { 0x0800 },
                link_header_length: 14,
            }),
            network_layer: Some(network_layer),
            transport_layer: Some(transport_layer),
            payload: None,
            completeness: PacketCompleteness::Complete,
        });
    }
    packets
}

fn reconstruct(packets: &[NormalizedPacket]) -> (Vec<FlowRecord>, usize) {
    let Ok(config) = FlowReconstructionConfigBuilder::default()
        .maximum_tracked_flows(16)
        .maximum_flow_instances(64)
        .tcp_idle_timeout_seconds(10)
        .udp_idle_timeout_seconds(5)
        .build()
    else {
        return (Vec::new(), 0);
    };
    let Ok(mut reconstructor) = FlowReconstructor::new(config) else {
        return (Vec::new(), 0);
    };
    let mut flows = Vec::new();
    let mut errors = 0usize;
    for packet in packets {
        match reconstructor.observe(packet) {
            Ok(step) => flows.extend(step.closed_flows),
            Err(_) => errors = errors.saturating_add(1),
        }
    }
    let finalized = reconstructor.finish();
    assert!(
        finalized
            .windows(2)
            .all(|window| window[0].reference < window[1].reference)
    );
    flows.extend(finalized);
    flows.sort_by_key(|flow| flow.reference);
    assert!(
        flows
            .windows(2)
            .all(|window| window[0].reference < window[1].reference)
    );
    for flow in &flows {
        assert_flow(flow);
    }
    (flows, errors)
}

fuzz_target!(|data: &[u8]| {
    let packets = packets(data);
    let first = reconstruct(&packets);
    let second = reconstruct(&packets);
    assert_eq!(first, second);
});
