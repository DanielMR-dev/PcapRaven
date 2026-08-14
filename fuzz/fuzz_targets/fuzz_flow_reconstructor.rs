#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    EthernetMetadata, FragmentationState, Ipv4Metadata, Ipv6Metadata, MacAddress, NetworkLayer,
    NormalizedPacket, PacketCompleteness, PacketReference, PacketTimestamp,
    PacketTimestampResolution, TcpFlags, TcpMetadata, TransportLayer, UdpMetadata,
};
use pcapraven_flows::{
    FlowReconstructionConfigBuilder, FlowReconstructor,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let config = match FlowReconstructionConfigBuilder::default()
        .maximum_tracked_flows(16)
        .maximum_flow_instances(64)
        .tcp_idle_timeout_seconds(10)
        .udp_idle_timeout_seconds(5)
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut reconstructor = match FlowReconstructor::new(config) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Synthesize up to 40 normalized packets from data chunks
    let chunk_size = 16;
    let max_packets = (data.len() / chunk_size).min(40);

    for i in 0..max_packets {
        let chunk = &data[i * chunk_size..(i + 1) * chunk_size];
        let is_ipv6 = (chunk[0] & 0x01) != 0;
        let is_udp = (chunk[0] & 0x02) != 0;
        let has_timestamp = (chunk[0] & 0x04) != 0;
        let is_binary_ts = (chunk[0] & 0x08) != 0;

        let src_port = u16::from_be_bytes([chunk[1], chunk[2]]);
        let dst_port = u16::from_be_bytes([chunk[3], chunk[4]]);
        let raw_flags = u16::from_be_bytes([chunk[5], chunk[6]]);
        let ts_sec = i64::from_be_bytes([chunk[7], chunk[8], chunk[9], chunk[10], 0, 0, 0, 0]) as i128;
        let ts_frac = u32::from_be_bytes([chunk[11], chunk[12], chunk[13], chunk[14]]) as u64;
        let offset = (chunk[15] as i8) as i64;

        let timestamp = if has_timestamp {
            if is_binary_ts {
                PacketTimestamp::Available {
                    seconds: ts_sec,
                    fractional_units: ts_frac,
                    resolution: PacketTimestampResolution::Binary {
                        exponent: 32,
                        units_per_second: 1 << 32,
                    },
                    offset_seconds: offset,
                }
            } else {
                PacketTimestamp::Available {
                    seconds: ts_sec,
                    fractional_units: ts_frac % 1_000_000_000,
                    resolution: PacketTimestampResolution::Decimal {
                        exponent: 9,
                        units_per_second: 1_000_000_000,
                    },
                    offset_seconds: offset,
                }
            }
        } else {
            PacketTimestamp::Unavailable
        };

        let network_layer = if is_ipv6 {
            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip[0] = chunk[1];
            src_ip[15] = chunk[2];
            dst_ip[0] = chunk[3];
            dst_ip[15] = chunk[4];
            NetworkLayer::Ipv6(Ipv6Metadata {
                version: 6,
                traffic_class: 0,
                flow_label: 0,
                payload_length: 20,
                next_header: if is_udp { 17 } else { 6 },
                hop_limit: 64,
                source: src_ip,
                destination: dst_ip,
                extension_headers_count: 0,
                extension_headers_length: 0,
                effective_protocol: if is_udp { 17 } else { 6 },
                fragmentation: FragmentationState::NotFragmented,
            })
        } else {
            let src_ip = [10, 0, chunk[1], chunk[2]];
            let dst_ip = [10, 0, chunk[3], chunk[4]];
            NetworkLayer::Ipv4(Ipv4Metadata {
                version: 4,
                header_length: 20,
                dscp: 0,
                ecn: 0,
                total_length: 40,
                identification: 1,
                ttl: 64,
                protocol: if is_udp { 17 } else { 6 },
                source: src_ip,
                destination: dst_ip,
                fragmentation: FragmentationState::NotFragmented,
            })
        };

        let transport_layer = if is_udp {
            TransportLayer::Udp(UdpMetadata {
                source_port: src_port,
                destination_port: dst_port,
                length: 8,
                checksum: 0,
            })
        } else {
            TransportLayer::Tcp(TcpMetadata {
                source_port: src_port,
                destination_port: dst_port,
                sequence_number: 1000,
                acknowledgement_number: 0,
                data_offset_bytes: 20,
                flags: TcpFlags::from_bits(raw_flags),
                window_size: 65535,
                checksum: 0,
                urgent_pointer: 0,
                options_length_bytes: 0,
            })
        };

        let packet = NormalizedPacket {
            reference: PacketReference::new(i as u64, Some(0), Some(0), 64, 64, false),
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
        };

        let _ = reconstructor.observe(&packet);
    }

    let _ = reconstructor.finish();
});
