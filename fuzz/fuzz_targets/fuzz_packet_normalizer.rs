#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_domain::{
    PacketNormalizationInput, PacketReference, PacketTimestamp, PacketTimestampResolution,
};
use pcapraven_protocols::{NormalizationLimitsBuilder, normalize_packet};

fuzz_target!(|data: &[u8]| {
    let limits = NormalizationLimitsBuilder::default()
        .maximum_retained_payload_bytes(1024)
        .maximum_diagnostics_per_packet(8)
        .maximum_ipv6_extension_headers(4)
        .maximum_ipv6_extension_bytes(512)
        .build()
        .expect("valid fuzz limits");

    let reference = PacketReference::new(0, None, None, data.len() as u32, data.len() as u32, false);
    let timestamp = PacketTimestamp::Available {
        seconds: 1_700_000_000,
        fractional_units: 0,
        resolution: PacketTimestampResolution::Decimal {
            exponent: 6,
            units_per_second: 1_000_000,
        },
        offset_seconds: 0,
    };

    // 1. Fuzz with standard LINKTYPE_ETHERNET = 1
    let input_eth = PacketNormalizationInput::new(reference, timestamp, 1, data);
    let outcome_eth = normalize_packet(&input_eth, &limits);

    if let Some(payload) = &outcome_eth.packet.payload {
        assert!(payload.len() <= limits.maximum_retained_payload_bytes);
    }
    assert!(outcome_eth.diagnostics.len() <= limits.maximum_diagnostics_per_packet);

    // 2. Fuzz with arbitrary linktype if at least 4 bytes exist
    if data.len() >= 4 {
        let raw_linktype = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let remaining_data = &data[4..];
        let ref_arb = PacketReference::new(
            1,
            None,
            None,
            remaining_data.len() as u32,
            remaining_data.len() as u32,
            false,
        );
        let input_arb = PacketNormalizationInput::new(ref_arb, timestamp, raw_linktype, remaining_data);
        let outcome_arb = normalize_packet(&input_arb, &limits);

        if let Some(payload) = &outcome_arb.packet.payload {
            assert!(payload.len() <= limits.maximum_retained_payload_bytes);
        }
        assert!(outcome_arb.diagnostics.len() <= limits.maximum_diagnostics_per_packet);
    }
});
