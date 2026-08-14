#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_pcap::{CaptureReader, ReaderLimits, read_capture};
use std::io::Cursor;

fuzz_target!(|input: &[u8]| {
    let limits = ReaderLimits::builder()
        .initial_buffer_size(32)
        .maximum_buffer_size(4096)
        .maximum_block_size(2048)
        .maximum_packet_bytes(1024)
        .maximum_retained_packet_bytes(4096)
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
        let mut total_retained = 0usize;
        for record in &outcome.records {
            assert!(record.packet.len() <= 1024);
            assert_eq!(record.packet.len(), record.captured_length as usize);
            total_retained = total_retained.saturating_add(record.packet.len());
        }
        assert!(total_retained <= 4096);

        // Also exercise the low-level streaming interface independently.
        if let Ok(mut reader) = CaptureReader::new(Cursor::new(input), limits) {
            let mut stream_count = 0usize;
            while let Ok(Some(record)) = reader.next_record() {
                stream_count += 1;
                assert!(record.packet.len() <= 1024);
                assert_eq!(record.packet.len(), record.captured_length as usize);
                if stream_count > 32 {
                    break;
                }
            }
            assert!(reader.diagnostics().len() <= 16);
            assert!(reader.records_emitted() <= 32);
        }
    }
});
