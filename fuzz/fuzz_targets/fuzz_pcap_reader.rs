#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_pcap::{read_capture, ReaderLimits};
use std::io::Cursor;

fuzz_target!(|input: &[u8]| {
    let limits = ReaderLimits::builder()
        .initial_buffer_size(32)
        .maximum_buffer_size(4096)
        .maximum_block_size(2048)
        .maximum_packet_bytes(1024)
        .maximum_interfaces_per_section(8)
        .maximum_sections(8)
        .maximum_diagnostics(16)
        .maximum_records(32)
        .maximum_blocks(64)
        .build();

    if let Ok(limits) = limits {
        let outcome = read_capture(Cursor::new(input), limits);
        assert!(outcome.records.len() <= 32);
        assert!(outcome.diagnostics.len() <= 16);
        for record in &outcome.records {
            assert!(record.packet.len() <= 1024);
            assert_eq!(record.packet.len(), record.captured_length as usize);
        }
    }
});
