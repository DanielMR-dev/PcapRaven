use pcapraven_pcap::{
    ByteOrder, CaptureCompletion, CaptureDiagnosticKind, CaptureFormat, CaptureReader,
    CaptureReaderErrorKind, CaptureTimestamp, ReaderLimits, read_capture,
};
use proptest::prelude::*;
use std::io::{self, Read};

fn push_u16(bytes: &mut Vec<u8>, value: u16, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn push_u32(bytes: &mut Vec<u8>, value: u32, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn push_i32(bytes: &mut Vec<u8>, value: i32, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn push_i64(bytes: &mut Vec<u8>, value: i64, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn pcap(
    order: ByteOrder,
    nanoseconds: bool,
    snaplen: u32,
    linktype: u32,
    packets: &[(u32, u32, &[u8], u32)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let magic = match (order, nanoseconds) {
        (ByteOrder::Little, false) => [0xd4, 0xc3, 0xb2, 0xa1],
        (ByteOrder::Little, true) => [0x4d, 0x3c, 0xb2, 0xa1],
        (ByteOrder::Big, false) => [0xa1, 0xb2, 0xc3, 0xd4],
        (ByteOrder::Big, true) => [0xa1, 0xb2, 0x3c, 0x4d],
    };
    bytes.extend_from_slice(&magic);
    push_u16(&mut bytes, 2, order);
    push_u16(&mut bytes, 4, order);
    push_i32(&mut bytes, 0, order);
    push_u32(&mut bytes, 0, order);
    push_u32(&mut bytes, snaplen, order);
    push_u32(&mut bytes, linktype, order);
    for (seconds, fraction, packet, original_length) in packets {
        push_u32(&mut bytes, *seconds, order);
        push_u32(&mut bytes, *fraction, order);
        push_u32(&mut bytes, packet.len() as u32, order);
        push_u32(&mut bytes, *original_length, order);
        bytes.extend_from_slice(packet);
    }
    bytes
}

fn padded(packet: &[u8]) -> Vec<u8> {
    let mut result = packet.to_vec();
    while result.len() % 4 != 0 {
        result.push(0);
    }
    result
}

fn ng_block(order: ByteOrder, block_type: u32, body: &[u8]) -> Vec<u8> {
    let total_length = 12 + body.len();
    assert_eq!(total_length % 4, 0);
    let mut block = Vec::new();
    push_u32(&mut block, block_type, order);
    push_u32(&mut block, total_length as u32, order);
    block.extend_from_slice(body);
    push_u32(&mut block, total_length as u32, order);
    block
}

fn shb(order: ByteOrder) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, 0x1a2b_3c4d, order);
    push_u16(&mut body, 1, order);
    push_u16(&mut body, 0, order);
    push_i64(&mut body, -1, order);
    ng_block(order, 0x0a0d_0d0a, &body)
}

fn option(order: ByteOrder, code: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u16(&mut bytes, code, order);
    push_u16(&mut bytes, value.len() as u16, order);
    bytes.extend_from_slice(value);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

fn idb(
    order: ByteOrder,
    linktype: u16,
    snaplen: u32,
    resolution: Option<u8>,
    offset: Option<i64>,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, linktype, order);
    push_u16(&mut body, 0, order);
    push_u32(&mut body, snaplen, order);
    if let Some(resolution) = resolution {
        body.extend_from_slice(&option(order, 9, &[resolution]));
    }
    if let Some(offset) = offset {
        let mut value = Vec::new();
        push_i64(&mut value, offset, order);
        body.extend_from_slice(&option(order, 14, &value));
    }
    body.extend_from_slice(&option(order, 0, &[]));
    ng_block(order, 1, &body)
}

fn epb(
    order: ByteOrder,
    interface: u32,
    timestamp: u64,
    packet: &[u8],
    original_length: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, interface, order);
    push_u32(&mut body, (timestamp >> 32) as u32, order);
    push_u32(&mut body, timestamp as u32, order);
    push_u32(&mut body, packet.len() as u32, order);
    push_u32(&mut body, original_length, order);
    body.extend_from_slice(&padded(packet));
    body.extend_from_slice(&option(order, 0, &[]));
    ng_block(order, 6, &body)
}

fn spb(order: ByteOrder, packet: &[u8], original_length: u32) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, original_length, order);
    body.extend_from_slice(&padded(packet));
    ng_block(order, 3, &body)
}

fn pcapng(order: ByteOrder, blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = shb(order);
    for block in blocks {
        bytes.extend_from_slice(block);
    }
    bytes
}

fn default_limits() -> ReaderLimits {
    ReaderLimits::default()
}

#[test]
fn reads_legacy_little_and_big_endian_microseconds() {
    let first = [1u8, 2, 3];
    let second = [4u8, 5];
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let input = pcap(
            order,
            false,
            64,
            147,
            &[(10, 12, &first, 5), (11, 0, &second, 2)],
        );
        let outcome = read_capture(input.as_slice(), default_limits());
        assert!(outcome.is_complete());
        assert_eq!(outcome.metadata.format, CaptureFormat::LegacyPcap);
        let Some(header) = outcome.metadata.legacy else {
            panic!("legacy metadata missing");
        };
        assert_eq!(header.byte_order, order);
        assert_eq!(header.linktype, 147);
        assert_eq!(outcome.records.len(), 2);
        assert_eq!(outcome.records[0].packet.as_slice(), first);
        assert_eq!(outcome.records[0].captured_length, 3);
        assert_eq!(outcome.records[0].original_length, 5);
        assert!(outcome.records[0].truncated);
        assert_eq!(outcome.records[0].ordinal, 0);
        assert_eq!(outcome.records[1].ordinal, 1);
    }
}

#[test]
fn reads_legacy_nanoseconds_and_rejects_invalid_fraction() {
    let packet = [9u8, 8, 7, 6];
    let input = pcap(
        ByteOrder::Little,
        true,
        64,
        1,
        &[(4, 999_999_999, &packet, 4)],
    );
    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(outcome.is_complete());
    assert_eq!(
        outcome.records[0]
            .timestamp
            .resolution()
            .map(|r| r.raw_value()),
        Some(9)
    );

    let invalid = pcap(
        ByteOrder::Little,
        false,
        64,
        1,
        &[(4, 1_000_000, &packet, 4)],
    );
    let outcome = read_capture(invalid.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::FailedBeforeUsefulRecords { .. } | CaptureCompletion::Partial { .. }
    ));
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == CaptureDiagnosticKind::Malformed)
    );
}

#[test]
fn reads_pcapng_little_endian_epb_spb_and_unknown_block() {
    let packet = [0x10u8, 0x20, 0x30];
    let input = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 64, Some(6), Some(2)),
            epb(ByteOrder::Little, 0, 2_000_001, &packet, 5),
            spb(ByteOrder::Little, &packet, 3),
            ng_block(ByteOrder::Little, 0x1234_5678, &[1, 2, 3, 4]),
        ],
    );
    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(outcome.is_complete());
    assert_eq!(outcome.metadata.format, CaptureFormat::PcapNg);
    assert_eq!(outcome.metadata.sections.len(), 1);
    assert_eq!(outcome.metadata.sections[0].interfaces.len(), 1);
    assert_eq!(outcome.records.len(), 2);
    assert_eq!(outcome.records[0].packet.as_slice(), packet);
    assert_eq!(outcome.records[0].original_length, 5);
    assert_eq!(outcome.records[0].timestamp.effective_seconds(), Some(4));
    assert!(matches!(
        outcome.records[1].timestamp,
        CaptureTimestamp::Unavailable
    ));
    assert!(outcome.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == CaptureDiagnosticKind::Unsupported
            && diagnostic.location.packet_ordinal.is_none()
            && diagnostic.location.block_type == Some(0x1234_5678)
    }));
}

#[test]
fn reads_pcapng_big_endian_and_negative_timestamp_offset() {
    let packet = [1u8, 3, 3, 7];
    let input = pcapng(
        ByteOrder::Big,
        &[
            idb(ByteOrder::Big, 101, 64, Some(0x81), Some(-3)),
            epb(ByteOrder::Big, 0, 5, &packet, 4),
        ],
    );
    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(outcome.is_complete());
    assert_eq!(outcome.metadata.sections[0].byte_order, ByteOrder::Big);
    assert_eq!(
        outcome.metadata.sections[0].interfaces[0]
            .as_valid()
            .unwrap()
            .linktype,
        101
    );
    assert_eq!(outcome.records[0].timestamp.effective_seconds(), Some(-1));
    assert_eq!(outcome.records[0].timestamp.fractional_units(), Some(1));
}

#[test]
fn associates_enhanced_packets_with_multiple_section_local_interfaces() {
    let first = [1u8, 2];
    let second = [3u8, 4, 5];
    let input = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 64, None, None),
            idb(ByteOrder::Little, 101, 128, None, None),
            epb(ByteOrder::Little, 1, 0, &first, 2),
            epb(ByteOrder::Little, 0, 1, &second, 3),
        ],
    );
    let outcome = read_capture(input.as_slice(), default_limits());

    assert!(outcome.is_complete());
    assert_eq!(outcome.metadata.sections[0].interfaces.len(), 2);
    assert_eq!(outcome.records.len(), 2);
    assert_eq!(outcome.records[0].interface_ordinal, Some(1));
    assert_eq!(outcome.records[0].linktype, 101);
    assert_eq!(outcome.records[0].packet.as_slice(), first);
    assert_eq!(outcome.records[1].interface_ordinal, Some(0));
    assert_eq!(outcome.records[1].linktype, 1);
    assert_eq!(outcome.records[1].packet.as_slice(), second);
}

#[test]
fn skips_length_mismatches_at_safe_record_boundaries() {
    let valid = [9u8, 8];
    let invalid = [1u8, 2, 3];
    let input = pcap(
        ByteOrder::Little,
        false,
        64,
        1,
        &[(1, 0, &invalid, 2), (2, 0, &valid, 2)],
    );
    let outcome = read_capture(input.as_slice(), default_limits());

    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].ordinal, 0);
    assert_eq!(outcome.records[0].packet.as_slice(), valid);
    assert!(outcome.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == CaptureDiagnosticKind::Malformed
            && diagnostic.location.packet_ordinal.is_none()
    }));

    let pcapng_input = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 2, None, None),
            epb(ByteOrder::Little, 0, 0, &invalid, 3),
            epb(ByteOrder::Little, 0, 1, &valid, 2),
        ],
    );
    let outcome = read_capture(pcapng_input.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].packet.as_slice(), valid);
}

#[test]
fn hostile_declared_lengths_hit_limits_before_growth() {
    let mut pcap_input = pcap(ByteOrder::Little, false, 64, 1, &[]);
    pcap_input.extend_from_slice(&u32::MAX.to_le_bytes());
    pcap_input.extend_from_slice(&u32::MAX.to_le_bytes());
    pcap_input.extend_from_slice(&u32::MAX.to_le_bytes());
    pcap_input.extend_from_slice(&u32::MAX.to_le_bytes());
    let outcome = read_capture(pcap_input.as_slice(), default_limits());
    assert_eq!(
        outcome.completion.clone().terminal_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );
    assert!(outcome.records.is_empty());

    let mut pcapng_input = shb(ByteOrder::Little);
    let mut oversized = Vec::new();
    push_u32(&mut oversized, 0x1234_5678, ByteOrder::Little);
    push_u32(&mut oversized, u32::MAX - 3, ByteOrder::Little);
    pcapng_input.extend_from_slice(&oversized);
    let outcome = read_capture(pcapng_input.as_slice(), default_limits());
    assert_eq!(
        outcome.completion.clone().terminal_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );
}

#[test]
fn invalid_limits_are_rejected_before_reader_construction() {
    for limits in [
        ReaderLimits::builder().maximum_buffer_size(31),
        ReaderLimits::builder().maximum_packet_bytes(0),
        ReaderLimits::builder().maximum_block_size(31),
        ReaderLimits::builder().maximum_buffer_size(64 * 1024 * 1024 + 1),
    ] {
        assert!(limits.build().is_err());
    }
}

#[test]
fn phase18_all_reader_limit_hard_caps_accept_n_minus_1_and_n_but_reject_n_plus_1() {
    const BYTE_CAP: usize = 64 * 1024 * 1024;

    for value in [BYTE_CAP - 1, BYTE_CAP] {
        assert!(
            ReaderLimits::builder()
                .initial_buffer_size(value)
                .maximum_buffer_size(BYTE_CAP)
                .maximum_block_size(BYTE_CAP)
                .build()
                .is_ok()
        );
        assert!(
            ReaderLimits::builder()
                .maximum_buffer_size(value)
                .build()
                .is_ok()
        );
        assert!(
            ReaderLimits::builder()
                .maximum_buffer_size(BYTE_CAP)
                .maximum_block_size(value)
                .build()
                .is_ok()
        );
        assert!(
            ReaderLimits::builder()
                .maximum_buffer_size(BYTE_CAP)
                .maximum_block_size(BYTE_CAP)
                .maximum_packet_bytes(value)
                .build()
                .is_ok()
        );
        assert!(
            ReaderLimits::builder()
                .maximum_retained_packet_bytes(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        ReaderLimits::builder()
            .initial_buffer_size(BYTE_CAP + 1)
            .maximum_buffer_size(BYTE_CAP)
            .maximum_block_size(BYTE_CAP)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_buffer_size(BYTE_CAP + 1)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_buffer_size(BYTE_CAP)
            .maximum_block_size(BYTE_CAP + 1)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_buffer_size(BYTE_CAP)
            .maximum_block_size(BYTE_CAP)
            .maximum_packet_bytes(BYTE_CAP + 1)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_retained_packet_bytes(BYTE_CAP + 1)
            .build()
            .is_err()
    );

    for value in [65_535, 65_536] {
        assert!(
            ReaderLimits::builder()
                .maximum_interfaces_per_section(value)
                .build()
                .is_ok()
        );
        assert!(
            ReaderLimits::builder()
                .maximum_sections(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        ReaderLimits::builder()
            .maximum_interfaces_per_section(65_537)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_sections(65_537)
            .build()
            .is_err()
    );

    for value in [999_999, 1_000_000] {
        assert!(
            ReaderLimits::builder()
                .maximum_diagnostics(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        ReaderLimits::builder()
            .maximum_diagnostics(1_000_001)
            .build()
            .is_err()
    );

    for value in [9_999_999, 10_000_000] {
        assert!(
            ReaderLimits::builder()
                .maximum_records(value)
                .build()
                .is_ok()
        );
        assert!(
            ReaderLimits::builder()
                .maximum_blocks(value)
                .build()
                .is_ok()
        );
    }
    assert!(
        ReaderLimits::builder()
            .maximum_records(10_000_001)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_blocks(10_000_001)
            .build()
            .is_err()
    );
}

#[test]
fn malformed_pcapng_boundaries_and_timestamp_metadata_are_bounded() {
    let packet = [1u8, 2, 3];
    let valid = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 32, Some(6), None),
            epb(ByteOrder::Little, 0, 0, &packet, 3),
        ],
    );
    for cut in [0usize, 1, 8, 27, 40, valid.len() - 1] {
        let outcome = read_capture(&valid[..cut.min(valid.len())], default_limits());
        assert!(!outcome.is_complete());
    }
    assert!(read_capture(&valid[..28], default_limits()).is_complete());

    let mut contradictory = pcapng(
        ByteOrder::Little,
        &[idb(ByteOrder::Little, 1, 32, Some(6), None)],
    );
    let footer_offset = contradictory.len() - 4;
    contradictory[footer_offset] ^= 0xff;
    let outcome = read_capture(contradictory.as_slice(), default_limits());
    assert_eq!(
        outcome.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::Malformed)
    );

    let malformed_resolution = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 32, Some(0xff), None),
            epb(ByteOrder::Little, 0, 0, &packet, 3),
        ],
    );
    let outcome = read_capture(malformed_resolution.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    assert!(outcome.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == CaptureDiagnosticKind::Malformed
            && diagnostic.location.block_type == Some(1)
    }));
}

#[test]
fn new_section_resets_interfaces_and_recovers_invalid_packet_references() {
    let packet = [1u8, 2];
    let mut input = shb(ByteOrder::Little);
    input.extend_from_slice(&epb(ByteOrder::Little, 4, 0, &packet, 2));
    input.extend_from_slice(&idb(ByteOrder::Little, 1, 32, None, None));
    input.extend_from_slice(&epb(ByteOrder::Little, 0, 0, &packet, 2));
    input.extend_from_slice(&shb(ByteOrder::Little));
    input.extend_from_slice(&spb(ByteOrder::Little, &packet, 2));
    input.extend_from_slice(&idb(ByteOrder::Little, 1, 32, None, None));
    input.extend_from_slice(&spb(ByteOrder::Little, &packet, 2));

    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    assert_eq!(outcome.metadata.sections.len(), 2);
    assert_eq!(outcome.metadata.sections[0].interfaces.len(), 1);
    assert_eq!(outcome.metadata.sections[1].interfaces.len(), 1);
    assert_eq!(outcome.records.len(), 2);
    assert_eq!(outcome.records[0].section_ordinal, Some(0));
    assert_eq!(outcome.records[1].section_ordinal, Some(1));
    assert!(outcome.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == CaptureDiagnosticKind::InvalidReference
            && diagnostic.location.packet_ordinal.is_none()
    }));
}

#[test]
fn distinguishes_empty_unknown_and_truncated_inputs() {
    let empty = read_capture([].as_slice(), default_limits());
    assert!(matches!(
        empty.completion,
        CaptureCompletion::FailedBeforeUsefulRecords { .. }
    ));
    assert_eq!(
        empty.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::Incomplete)
    );

    let unknown = read_capture([0u8, 1, 2, 3, 4].as_slice(), default_limits());
    assert_eq!(
        unknown.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::UnrecognizedFormat)
    );

    let complete = pcap(ByteOrder::Little, false, 32, 1, &[]);
    let truncated = &complete[..10];
    let outcome = read_capture(truncated, default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::FailedBeforeUsefulRecords { .. }
    ));
}

#[test]
fn tiny_chunks_and_small_initial_buffer_grow_deterministically() {
    let packet = [0u8; 48];
    let input = pcap(ByteOrder::Little, false, 128, 1, &[(1, 0, &packet, 48)]);
    let limits = ReaderLimits::builder()
        .initial_buffer_size(8)
        .maximum_buffer_size(128)
        .maximum_block_size(80)
        .maximum_packet_bytes(48)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(TinyReader::new(input, 1), limits);
    assert!(outcome.is_complete());
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].packet.len(), 48);
}

#[test]
fn limits_bound_packets_records_diagnostics_sections_and_interfaces() {
    let packet = [1u8, 2, 3, 4];
    let input = pcap(ByteOrder::Little, false, 32, 1, &[(1, 0, &packet, 4)]);
    let packet_limit = ReaderLimits::builder()
        .maximum_packet_bytes(3)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(input.as_slice(), packet_limit);
    assert_eq!(
        outcome.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );

    let two_packets = pcap(
        ByteOrder::Little,
        false,
        32,
        1,
        &[(1, 0, &packet, 4), (2, 0, &packet, 4)],
    );
    let record_limit = ReaderLimits::builder()
        .maximum_records(1)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(two_packets.as_slice(), record_limit);
    assert_eq!(outcome.records.len(), 1);
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));

    let mut many_unknown = shb(ByteOrder::Little);
    many_unknown.extend_from_slice(&ng_block(ByteOrder::Little, 0x1234_0001, &[0, 0, 0, 0]));
    many_unknown.extend_from_slice(&ng_block(ByteOrder::Little, 0x1234_0002, &[0, 0, 0, 0]));
    let diagnostic_limit = ReaderLimits::builder()
        .maximum_diagnostics(1)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(many_unknown.as_slice(), diagnostic_limit);
    assert_eq!(outcome.diagnostics.len(), 1);
    assert_eq!(
        outcome.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );

    let mut too_many_interfaces = shb(ByteOrder::Little);
    too_many_interfaces.extend_from_slice(&idb(ByteOrder::Little, 1, 32, None, None));
    too_many_interfaces.extend_from_slice(&idb(ByteOrder::Little, 1, 32, None, None));
    let interface_limit = ReaderLimits::builder()
        .maximum_interfaces_per_section(1)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(too_many_interfaces.as_slice(), interface_limit);
    assert_eq!(outcome.metadata.sections[0].interfaces.len(), 1);
    assert_eq!(
        outcome.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );

    let mut too_many_sections = shb(ByteOrder::Little);
    too_many_sections.extend_from_slice(&shb(ByteOrder::Little));
    let section_limit = ReaderLimits::builder()
        .maximum_sections(1)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(too_many_sections.as_slice(), section_limit);
    assert_eq!(outcome.metadata.sections.len(), 1);
    assert_eq!(
        outcome.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );

    let mut too_many_blocks = shb(ByteOrder::Little);
    too_many_blocks.extend_from_slice(&idb(ByteOrder::Little, 1, 32, None, None));
    too_many_blocks.extend_from_slice(&ng_block(ByteOrder::Little, 0x1234_0003, &[0, 0, 0, 0]));
    let block_limit = ReaderLimits::builder()
        .maximum_blocks(2)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(too_many_blocks.as_slice(), block_limit);
    assert_eq!(
        outcome.completion.clone().terminal_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );

    let large_packet = [0u8; 20];
    let large_block = pcap(
        ByteOrder::Little,
        false,
        32,
        1,
        &[(1, 0, &large_packet, 20)],
    );
    let block_limit = ReaderLimits::builder()
        .initial_buffer_size(32)
        .maximum_block_size(32)
        .maximum_buffer_size(64)
        .maximum_packet_bytes(20)
        .build()
        .expect("test limits are valid");
    let outcome = read_capture(large_block.as_slice(), block_limit);
    assert_eq!(
        outcome.completion.clone().failed_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );
}

#[test]
fn injected_io_failure_is_owned_and_bounded() {
    let input = pcap(ByteOrder::Little, false, 32, 1, &[(1, 0, &[1, 2], 2)]);
    let outcome = read_capture(FailingReader::new(input, 24), default_limits());
    assert_eq!(
        outcome.completion.clone().terminal_error_kind(),
        Some(CaptureReaderErrorKind::Io)
    );
    assert!(outcome.records.is_empty());
}

#[test]
fn reader_api_exposes_terminal_error_after_emitted_records() {
    let packet = [1u8, 2];
    let input = pcap(
        ByteOrder::Little,
        false,
        32,
        1,
        &[(1, 0, &packet, 2), (2, 0, &packet, 2)],
    );
    let limits = ReaderLimits::builder()
        .maximum_records(1)
        .build()
        .expect("test limits are valid");
    let mut reader = CaptureReader::new(input.as_slice(), limits).expect("reader construction");
    assert!(reader.next_record().expect("first record").is_some());
    let error = reader
        .next_record()
        .expect_err("record limit must be terminal");
    assert_eq!(error.kind(), CaptureReaderErrorKind::ResourceLimit);
    assert_eq!(reader.records_emitted(), 1);
}

#[test]
fn pcapng_positional_interface_identity_case_a_multi_interface_malformed_middle() {
    let packet_valid = [1u8, 2, 3, 4];
    let packet_skipped = [5u8, 6, 7, 8];
    let input = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 64, Some(6), None), // IDB 0: Valid, linktype 1
            idb(ByteOrder::Little, 12, 64, Some(0xff), None), // IDB 1: Malformed timestamp resolution
            idb(ByteOrder::Little, 101, 128, Some(6), None),  // IDB 2: Valid, linktype 101
            epb(ByteOrder::Little, 2, 1000, &packet_valid, 4), // EPB referencing interface 2
            epb(ByteOrder::Little, 1, 2000, &packet_skipped, 4), // EPB referencing unusable interface 1
        ],
    );
    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    assert_eq!(outcome.metadata.sections.len(), 1);
    let section = &outcome.metadata.sections[0];
    assert_eq!(section.interfaces.len(), 3);
    assert!(section.interfaces[0].is_valid());
    assert_eq!(section.interfaces[0].as_valid().unwrap().linktype, 1);
    assert_eq!(section.interfaces[0].interface_ordinal(), 0);
    assert!(!section.interfaces[1].is_valid());
    assert_eq!(section.interfaces[1].interface_ordinal(), 1);
    assert!(section.interfaces[2].is_valid());
    assert_eq!(section.interfaces[2].as_valid().unwrap().linktype, 101);
    assert_eq!(section.interfaces[2].interface_ordinal(), 2);

    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].ordinal, 0);
    assert_eq!(outcome.records[0].interface_ordinal, Some(2));
    assert_eq!(outcome.records[0].linktype, 101);
    assert_eq!(outcome.records[0].packet.as_slice(), packet_valid);
    assert!(outcome.diagnostics.iter().any(|d| {
        d.kind == CaptureDiagnosticKind::InvalidReference
            && d.message
                .contains("enhanced packet references an unavailable interface")
    }));
}

#[test]
fn pcapng_positional_interface_identity_case_b_first_idb_malformed() {
    let packet = [10u8, 20, 30];
    let input = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 64, Some(0xff), None), // IDB 0: Malformed
            idb(ByteOrder::Little, 1, 64, Some(6), None),    // IDB 1: Valid
            epb(ByteOrder::Little, 0, 100, &packet, 3),      // EPB referencing unusable if 0
            epb(ByteOrder::Little, 1, 200, &packet, 3),      // EPB referencing valid if 1
            spb(ByteOrder::Little, &packet, 3),              // SPB referencing if 0
        ],
    );
    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    let section = &outcome.metadata.sections[0];
    assert_eq!(section.interfaces.len(), 2);
    assert!(!section.interfaces[0].is_valid());
    assert!(section.interfaces[1].is_valid());
    assert_eq!(section.interfaces[1].interface_ordinal(), 1);

    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].interface_ordinal, Some(1));
    assert!(outcome.diagnostics.iter().any(|d| {
        d.kind == CaptureDiagnosticKind::InvalidReference
            && d.message
                .contains("simple packet has no section-local interface zero")
    }));
}

#[test]
fn pcapng_positional_interface_identity_case_c_spb_with_unusable_interface_zero() {
    let packet = [42u8; 8];
    let input = pcapng(
        ByteOrder::Little,
        &[
            idb(ByteOrder::Little, 1, 64, Some(0xfe), None), // IDB 0: Malformed
            idb(ByteOrder::Little, 1, 64, Some(6), None),    // IDB 1: Valid
            spb(ByteOrder::Little, &packet, 8),
        ],
    );
    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    assert!(outcome.records.is_empty());
    assert!(outcome.diagnostics.iter().any(|d| {
        d.kind == CaptureDiagnosticKind::InvalidReference
            && d.message
                .contains("simple packet has no section-local interface zero")
    }));
}

#[test]
fn pcapng_positional_interface_identity_case_d_multi_section_interface_isolation() {
    let packet = [1u8, 2, 3];
    let mut input = shb(ByteOrder::Little);
    input.extend_from_slice(&idb(ByteOrder::Little, 1, 64, None, None)); // Sec 0, IDB 0
    input.extend_from_slice(&idb(ByteOrder::Little, 101, 64, None, None)); // Sec 0, IDB 1
    input.extend_from_slice(&epb(ByteOrder::Little, 1, 100, &packet, 3)); // Sec 0, EPB 1 -> OK

    input.extend_from_slice(&shb(ByteOrder::Little)); // Sec 1 begins
    input.extend_from_slice(&idb(ByteOrder::Little, 12, 64, None, None)); // Sec 1, IDB 0
    input.extend_from_slice(&epb(ByteOrder::Little, 1, 200, &packet, 3)); // Sec 1, EPB 1 -> InvalidReference

    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    assert_eq!(outcome.metadata.sections.len(), 2);
    assert_eq!(outcome.metadata.sections[0].interfaces.len(), 2);
    assert_eq!(outcome.metadata.sections[1].interfaces.len(), 1);
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].section_ordinal, Some(0));
    assert_eq!(outcome.records[0].interface_ordinal, Some(1));
    assert!(outcome.diagnostics.iter().any(|d| {
        d.kind == CaptureDiagnosticKind::InvalidReference
            && d.location.section_ordinal == Some(1)
            && d.location.interface_ordinal == Some(1)
    }));
}

#[test]
fn pcapng_positional_interface_identity_case_e_malformed_options_preserve_slot_indexing() {
    let packet = [7u8, 8, 9];
    let mut malformed_opt_body = Vec::new();
    push_u16(&mut malformed_opt_body, 1, ByteOrder::Little); // linktype
    push_u16(&mut malformed_opt_body, 0, ByteOrder::Little); // reserved
    push_u32(&mut malformed_opt_body, 64, ByteOrder::Little); // snaplen
    // Add invalid length option: IfTsresol with len 2 instead of 1
    malformed_opt_body.extend_from_slice(&option(ByteOrder::Little, 9, &[6, 0]));
    malformed_opt_body.extend_from_slice(&option(ByteOrder::Little, 0, &[]));
    let malformed_idb = ng_block(ByteOrder::Little, 1, &malformed_opt_body);

    let input = pcapng(
        ByteOrder::Little,
        &[
            malformed_idb,                                  // IDB 0: malformed option length
            idb(ByteOrder::Little, 101, 64, Some(6), None), // IDB 1: Valid
            epb(ByteOrder::Little, 1, 1000, &packet, 3),    // EPB 1: References IDB 1
        ],
    );
    let outcome = read_capture(input.as_slice(), default_limits());
    assert!(matches!(
        outcome.completion,
        CaptureCompletion::Partial { .. }
    ));
    let section = &outcome.metadata.sections[0];
    assert_eq!(section.interfaces.len(), 2);
    assert!(!section.interfaces[0].is_valid());
    assert!(section.interfaces[1].is_valid());
    assert_eq!(section.interfaces[1].as_valid().unwrap().linktype, 101);
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].interface_ordinal, Some(1));
    assert_eq!(outcome.records[0].linktype, 101);
}

#[test]
fn streaming_reader_does_not_retain_records_internally() {
    let packet = [0xabu8, 0xcd, 0xef];
    let packets: Vec<(u32, u32, &[u8], u32)> =
        (0..50).map(|i| (i, 0, packet.as_slice(), 3)).collect();
    let input = pcap(ByteOrder::Little, false, 64, 1, &packets);
    let limits = default_limits();
    let mut reader = CaptureReader::new(input.as_slice(), limits).expect("reader creation");
    let mut count = 0u64;
    while let Ok(Some(record)) = reader.next_record() {
        assert_eq!(record.ordinal, count);
        assert_eq!(record.packet.as_slice(), packet);
        count += 1;
        assert_eq!(reader.records_emitted(), count);
    }
    assert_eq!(count, 50);
    assert_eq!(reader.records_emitted(), 50);
}

#[test]
fn aggregate_retained_packet_bytes_limit_enforced_strictly() {
    let packet40 = [1u8; 40];
    let two_packets = pcap(
        ByteOrder::Little,
        false,
        64,
        1,
        &[(1, 0, &packet40, 40), (2, 0, &packet40, 40)],
    );
    let three_packets = pcap(
        ByteOrder::Little,
        false,
        64,
        1,
        &[
            (1, 0, &packet40, 40),
            (2, 0, &packet40, 40),
            (3, 0, &packet40, 40),
        ],
    );
    let limits = ReaderLimits::builder()
        .maximum_retained_packet_bytes(100)
        .maximum_packet_bytes(60)
        .build()
        .expect("valid limits");

    // 2 packets * 40 bytes = 80 <= 100 -> Complete
    let outcome_two = read_capture(two_packets.as_slice(), limits);
    assert!(outcome_two.is_complete());
    assert_eq!(outcome_two.records.len(), 2);

    // 3 packets * 40 bytes = 120 > 100 -> Partial with 2 records retained
    let outcome_three = read_capture(three_packets.as_slice(), limits);
    assert!(matches!(
        outcome_three.completion,
        CaptureCompletion::Partial {
            terminal_error: Some(_)
        }
    ));
    assert_eq!(
        outcome_three.completion.terminal_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );
    assert_eq!(outcome_three.records.len(), 2);

    // 1 packet of 120 bytes when limit is 100 -> FailedBeforeUsefulRecords
    let packet120 = [2u8; 120];
    let one_large = pcap(ByteOrder::Little, false, 200, 1, &[(1, 0, &packet120, 120)]);
    let large_limits = ReaderLimits::builder()
        .maximum_retained_packet_bytes(100)
        .maximum_packet_bytes(150)
        .build()
        .expect("valid limits");
    let outcome_large = read_capture(one_large.as_slice(), large_limits);
    assert!(matches!(
        outcome_large.completion,
        CaptureCompletion::FailedBeforeUsefulRecords { .. }
    ));
    assert_eq!(
        outcome_large.completion.failed_error_kind(),
        Some(CaptureReaderErrorKind::ResourceLimit)
    );
    assert!(outcome_large.records.is_empty());
}

#[test]
fn reader_limits_builder_validates_maximum_retained_packet_bytes() {
    assert!(
        ReaderLimits::builder()
            .maximum_retained_packet_bytes(0)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_retained_packet_bytes(64 * 1024 * 1024 + 1)
            .build()
            .is_err()
    );
    assert!(
        ReaderLimits::builder()
            .maximum_retained_packet_bytes(16 * 1024 * 1024)
            .build()
            .is_ok()
    );
}

#[test]
fn phase18_pcapng_short_block_length_handled_without_panic() {
    let mut bytes = shb(ByteOrder::Little);
    // Append a block with invalid short length (4 bytes instead of minimum 12 bytes).
    bytes.extend_from_slice(&1u32.to_le_bytes()); // IDB block type
    bytes.extend_from_slice(&4u32.to_le_bytes()); // Block length = 4
    let limits = default_limits();
    let outcome = read_capture(&bytes[..], limits);
    assert!(!outcome.is_complete());
    assert!(outcome.records.is_empty());
}

#[derive(Clone)]
struct TinyReader {
    bytes: Vec<u8>,
    position: usize,
    chunk_size: usize,
}

impl TinyReader {
    fn new(bytes: Vec<u8>, chunk_size: usize) -> Self {
        Self {
            bytes,
            position: 0,
            chunk_size,
        }
    }
}

impl Read for TinyReader {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.bytes.len() {
            return Ok(0);
        }
        let count = self
            .chunk_size
            .min(destination.len())
            .min(self.bytes.len() - self.position);
        let end = self.position + count;
        destination[..count].copy_from_slice(&self.bytes[self.position..end]);
        self.position = end;
        Ok(count)
    }
}

struct FailingReader {
    bytes: Vec<u8>,
    position: usize,
    fail_at: usize,
}

impl FailingReader {
    fn new(bytes: Vec<u8>, fail_at: usize) -> Self {
        Self {
            bytes,
            position: 0,
            fail_at,
        }
    }
}

impl Read for FailingReader {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.fail_at {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic failure",
            ));
        }
        let allowed = self.fail_at - self.position;
        let count = allowed
            .min(destination.len())
            .min(self.bytes.len() - self.position);
        let end = self.position + count;
        destination[..count].copy_from_slice(&self.bytes[self.position..end]);
        self.position = end;
        Ok(count)
    }
}

trait CompletionErrorKind {
    fn failed_error_kind(&self) -> Option<CaptureReaderErrorKind>;
    fn terminal_error_kind(&self) -> Option<CaptureReaderErrorKind>;
}

impl CompletionErrorKind for CaptureCompletion {
    fn failed_error_kind(&self) -> Option<CaptureReaderErrorKind> {
        match self {
            CaptureCompletion::FailedBeforeUsefulRecords { terminal_error } => {
                Some(terminal_error.kind())
            }
            _ => None,
        }
    }

    fn terminal_error_kind(&self) -> Option<CaptureReaderErrorKind> {
        match self {
            CaptureCompletion::FailedBeforeUsefulRecords { terminal_error }
            | CaptureCompletion::Partial {
                terminal_error: Some(terminal_error),
            } => Some(terminal_error.kind()),
            _ => None,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn phase18_generated_container_matrix_is_deterministic_bounded_and_progresses(
        use_pcapng in any::<bool>(),
        big_endian in any::<bool>(),
        alternate_resolution in any::<bool>(),
        second_section in any::<bool>(),
        second_interface in any::<bool>(),
        record_count in 0usize..=4,
        cut in 0usize..700,
    ) {
        let order = if big_endian { ByteOrder::Big } else { ByteOrder::Little };
        let packets: Vec<Vec<u8>> = (0..record_count)
            .map(|index| vec![u8::try_from(index).unwrap_or_default(); index + 1])
            .collect();
        let input = if use_pcapng {
            let resolution = Some(if alternate_resolution { 0x8a } else { 6 });
            let mut blocks = vec![idb(order, 1, 128, resolution, Some(-1))];
            if second_interface {
                blocks.push(idb(order, 101, 128, resolution, None));
            }
            for (index, packet) in packets.iter().enumerate() {
                let interface = if second_interface && index % 2 == 1 { 1 } else { 0 };
                blocks.push(epb(
                    order,
                    interface,
                    u64::try_from(index).unwrap_or_default(),
                    packet,
                    u32::try_from(packet.len()).unwrap_or_default(),
                ));
            }
            let mut bytes = pcapng(order, &blocks);
            if second_section {
                bytes.extend_from_slice(&pcapng(
                    order,
                    &[idb(order, 1, 128, resolution, None), spb(order, &[0xaa], 1)],
                ));
            }
            bytes
        } else {
            let records: Vec<_> = packets
                .iter()
                .enumerate()
                .map(|(index, packet)| {
                    (
                        u32::try_from(index).unwrap_or_default(),
                        u32::try_from(index).unwrap_or_default(),
                        packet.as_slice(),
                        u32::try_from(packet.len()).unwrap_or_default(),
                    )
                })
                .collect();
            pcap(order, alternate_resolution, 128, 1, &records)
        };
        let retained = cut.min(input.len());
        let truncated = &input[..retained];
        let limits = ReaderLimits::builder()
            .initial_buffer_size(8)
            .maximum_buffer_size(1024)
            .maximum_block_size(512)
            .maximum_packet_bytes(128)
            .maximum_retained_packet_bytes(512)
            .maximum_interfaces_per_section(4)
            .maximum_sections(4)
            .maximum_records(8)
            .maximum_blocks(16)
            .maximum_diagnostics(8)
            .build()
            .expect("property limits are valid");
        let first = read_capture(TinyReader::new(truncated.to_vec(), 1), limits);
        let second = read_capture(TinyReader::new(truncated.to_vec(), 7), limits);
        prop_assert_eq!(&first, &second);
        prop_assert!(first.records.len() <= 8);
        prop_assert!(first.diagnostics.len() <= 8);
        prop_assert!(first.metadata.sections.len() <= 4);
        prop_assert!(first.metadata.sections.iter().all(|section| section.interfaces.len() <= 4));
        let total_retained: usize = first.records.iter().map(|record| record.packet.len()).sum();
        prop_assert!(total_retained <= 512);
        prop_assert!(first.records.windows(2).all(|window| window[0].ordinal < window[1].ordinal));
    }

    #[test]
    fn arbitrary_finite_input_is_panic_free_and_bounded(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let limits = ReaderLimits::builder()
            .initial_buffer_size(8)
            .maximum_buffer_size(512)
            .maximum_block_size(256)
            .maximum_packet_bytes(128)
            .maximum_records(32)
            .maximum_blocks(64)
            .maximum_diagnostics(16)
            .build()
            .expect("property limits are valid");
        let outcome = read_capture(TinyReader::new(bytes, 3), limits);
        prop_assert!(outcome.records.len() <= 32);
        prop_assert!(outcome.diagnostics.len() <= 16);
        for record in &outcome.records {
            prop_assert!(record.packet.len() <= 128);
            prop_assert_eq!(record.packet.len(), record.captured_length as usize);
        }
    }

    #[test]
    fn truncated_generated_legacy_prefixes_are_panic_free(cut in 0usize..40) {
        let packet = [1u8, 2, 3];
        let input = pcap(ByteOrder::Little, false, 64, 1, &[(1, 0, &packet, 3)]);
        let cut = cut.min(input.len());
        let outcome = read_capture(&input[..cut], default_limits());
        prop_assert!(outcome.records.len() <= 1);
        if outcome.is_complete() {
            prop_assert!(outcome.records.is_empty() || cut == input.len());
        }
    }

    #[test]
    fn truncated_generated_pcapng_prefixes_are_panic_free(cut in 0usize..160) {
        let packet = [4u8, 5, 6];
        let input = pcapng(
            ByteOrder::Little,
            &[
                idb(ByteOrder::Little, 1, 64, Some(6), None),
                epb(ByteOrder::Little, 0, 0, &packet, 3),
            ],
        );
        let cut = cut.min(input.len());
        let outcome = read_capture(&input[..cut], default_limits());
        prop_assert!(outcome.records.len() <= 1);
        if outcome.is_complete() {
            prop_assert!(outcome.records.is_empty() || cut == input.len());
        }
    }

    #[test]
    fn attacker_lengths_remain_bounded(length in any::<u32>()) {
        let mut input = pcap(ByteOrder::Little, false, 64, 1, &[]);
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&length.to_le_bytes());
        input.extend_from_slice(&length.to_le_bytes());
        let limits = ReaderLimits::builder()
            .initial_buffer_size(32)
            .maximum_buffer_size(512)
            .maximum_block_size(256)
            .maximum_packet_bytes(128)
            .maximum_records(32)
            .maximum_blocks(64)
            .maximum_diagnostics(16)
            .build()
            .expect("property limits are valid");
        let outcome = read_capture(TinyReader::new(input, 3), limits);
        prop_assert!(outcome.records.len() <= 32);
        prop_assert!(outcome.diagnostics.len() <= 16);
        for record in &outcome.records {
            prop_assert!(record.packet.len() <= 128);
        }
    }

    #[test]
    fn arbitrary_input_respects_retained_byte_bound(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let limits = ReaderLimits::builder()
            .initial_buffer_size(16)
            .maximum_buffer_size(512)
            .maximum_block_size(256)
            .maximum_packet_bytes(64)
            .maximum_retained_packet_bytes(128)
            .maximum_records(32)
            .maximum_blocks(64)
            .maximum_diagnostics(16)
            .build()
            .expect("property limits are valid");
        let outcome = read_capture(TinyReader::new(bytes, 7), limits);
        let total_retained: usize = outcome.records.iter().map(|r| r.packet.len()).sum();
        prop_assert!(total_retained <= 128);
        prop_assert!(outcome.records.len() <= 32);
        prop_assert!(outcome.diagnostics.len() <= 16);
    }
}
