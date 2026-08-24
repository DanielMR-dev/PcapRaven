#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapraven_pcap::{CaptureReader, ReaderLimits, read_capture};
use std::io::Cursor;

const MAX_RECORDS: usize = 32;
const MAX_DIAGNOSTICS: usize = 16;
const MAX_PACKET_BYTES: usize = 1024;
const MAX_RETAINED_BYTES: usize = 4096;

fn limits() -> Option<ReaderLimits> {
    ReaderLimits::builder()
        .initial_buffer_size(32)
        .maximum_buffer_size(4096)
        .maximum_block_size(2048)
        .maximum_packet_bytes(MAX_PACKET_BYTES)
        .maximum_retained_packet_bytes(MAX_RETAINED_BYTES)
        .maximum_interfaces_per_section(8)
        .maximum_sections(8)
        .maximum_diagnostics(MAX_DIAGNOSTICS)
        .maximum_records(MAX_RECORDS)
        .maximum_blocks(64)
        .build()
        .ok()
}

fuzz_target!(|input: &[u8]| {
    let Some(limits) = limits() else {
        return;
    };
    let first = read_capture(Cursor::new(input), limits);
    let second = read_capture(Cursor::new(input), limits);
    assert_eq!(first, second);
    assert!(first.records.len() <= MAX_RECORDS);
    assert!(first.diagnostics.len() <= MAX_DIAGNOSTICS);
    let mut retained = 0usize;
    for record in &first.records {
        assert!(record.packet.len() <= MAX_PACKET_BYTES);
        let Ok(captured) = usize::try_from(record.captured_length) else {
            return;
        };
        assert_eq!(record.packet.len(), captured);
        let Some(next_retained) = retained.checked_add(record.packet.len()) else {
            return;
        };
        retained = next_retained;
    }
    assert!(retained <= MAX_RETAINED_BYTES);

    if let Ok(mut reader) = CaptureReader::new(Cursor::new(input), limits) {
        let mut records = 0usize;
        let mut retained = 0usize;
        while let Ok(Some(record)) = reader.next_record() {
            let Some(next_records) = records.checked_add(1) else {
                return;
            };
            records = next_records;
            assert!(records <= MAX_RECORDS);
            let Ok(captured) = usize::try_from(record.captured_length) else {
                return;
            };
            assert_eq!(record.packet.len(), captured);
            assert!(captured <= MAX_PACKET_BYTES);
            let Some(next_retained) = retained.checked_add(captured) else {
                return;
            };
            retained = next_retained;
            assert!(retained <= MAX_RETAINED_BYTES);
        }
        assert!(reader.diagnostics().len() <= MAX_DIAGNOSTICS);
        assert!(reader.records_emitted() <= u64::try_from(MAX_RECORDS).unwrap_or(u64::MAX));
    }
});
