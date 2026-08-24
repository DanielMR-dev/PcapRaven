#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    PacketNormalizationInput, PacketReference, PacketTimestamp, PacketTimestampResolution,
};
use pcapraven_protocols::{NormalizationLimitsBuilder, normalize_packet};

fn exercise(data: &[u8], linktype: u32, ordinal: u64, truncated: bool) {
    let Ok(length) = u32::try_from(data.len()) else {
        return;
    };
    let original = if truncated {
        length.checked_add(1).unwrap_or(length)
    } else {
        length
    };
    let Ok(limits) = NormalizationLimitsBuilder::default()
        .maximum_retained_payload_bytes(1024)
        .maximum_diagnostics_per_packet(8)
        .maximum_ipv6_extension_headers(4)
        .maximum_ipv6_extension_bytes(512)
        .build()
    else {
        return;
    };
    let reference = PacketReference::new(ordinal, None, None, length, original, truncated);
    let timestamp = PacketTimestamp::Available {
        seconds: 1_700_000_000,
        fractional_units: 0,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 6,
            units_per_second: 1_000_000,
        },
        offset_seconds: 0,
    };
    let input = PacketNormalizationInput::new(reference, timestamp, linktype, data);
    let first = normalize_packet(&input, &limits);
    let second = normalize_packet(&input, &limits);
    assert_eq!(first, second);
    assert!(first.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    if let Some(payload) = &first.packet.payload {
        assert!(payload.len() <= limits.maximum_retained_payload_bytes);
    }
    if let Some(pcapraven_domain::NetworkLayer::Ipv6(ipv6)) = &first.packet.network_layer {
        assert!(ipv6.extension_headers_count <= limits.maximum_ipv6_extension_headers);
        assert!(
            usize::from(ipv6.extension_headers_length) <= limits.maximum_ipv6_extension_bytes
        );
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data, 1, 0, false);
    exercise(data, 1, 1, true);
    if data.len() >= 4 {
        let (prefix, payload) = data.split_at(4);
        let Ok(prefix) = <&[u8; 4]>::try_from(prefix) else {
            return;
        };
        let raw_linktype = u32::from_le_bytes(*prefix);
        exercise(payload, raw_linktype, 2, false);
    }
});
