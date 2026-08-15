//! End-to-end integration tests for the PcapRaven CLI.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempCaptureFile {
    path: PathBuf,
}

impl TempCaptureFile {
    fn new(suffix: &str, data: &[u8]) -> Self {
        let id = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let name = format!("pcapraven_test_{pid}_{id}_{suffix}");
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, data).expect("write temp capture");
        Self { path }
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().to_string()
    }
}

impl Drop for TempCaptureFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_pcapraven");
    let output = Command::new(bin)
        .args(args)
        .output()
        .expect("execute pcapraven binary");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// Synthetic PCAP generator helpers

fn make_pcap_header(snaplen: u32, linktype: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // Magic: little-endian microsecond
    bytes.extend_from_slice(&2u16.to_le_bytes()); // Version major 2
    bytes.extend_from_slice(&4u16.to_le_bytes()); // Version minor 4
    bytes.extend_from_slice(&0i32.to_le_bytes()); // Thiszone 0
    bytes.extend_from_slice(&0u32.to_le_bytes()); // Sigfigs 0
    bytes.extend_from_slice(&snaplen.to_le_bytes());
    bytes.extend_from_slice(&linktype.to_le_bytes());
    bytes
}

fn make_pcap_packet(sec: u32, usec: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&sec.to_le_bytes());
    bytes.extend_from_slice(&usec.to_le_bytes());
    let len = payload.len() as u32;
    bytes.extend_from_slice(&len.to_le_bytes()); // Captured len
    bytes.extend_from_slice(&len.to_le_bytes()); // Original len
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue;
        }
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn make_ipv4_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // IPv4 Header
    let total_len = (20 + 8 + data.len()) as u16;
    let mut ip_hdr = Vec::new();
    ip_hdr.push(0x45); // Version 4, IHL 5
    ip_hdr.push(0x00); // DSCP/ECN
    ip_hdr.extend_from_slice(&total_len.to_be_bytes());
    ip_hdr.extend_from_slice(&0x0001u16.to_be_bytes()); // ID
    ip_hdr.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    ip_hdr.push(64); // TTL
    ip_hdr.push(17); // UDP
    ip_hdr.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    ip_hdr.extend_from_slice(&src_ip);
    ip_hdr.extend_from_slice(&dst_ip);

    let csum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());
    frame.extend_from_slice(&ip_hdr);

    // UDP Header
    let udp_len = (8 + data.len()) as u16;
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // Checksum (0 = none)
    frame.extend_from_slice(data);

    frame
}

#[allow(clippy::too_many_arguments)]
fn make_ipv4_tcp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    let total_len = (20 + 20 + data.len()) as u16;
    let mut ip_hdr = Vec::new();
    ip_hdr.push(0x45);
    ip_hdr.push(0x00);
    ip_hdr.extend_from_slice(&total_len.to_be_bytes());
    ip_hdr.extend_from_slice(&0x0001u16.to_be_bytes());
    ip_hdr.extend_from_slice(&0x4000u16.to_be_bytes());
    ip_hdr.push(64);
    ip_hdr.push(6); // TCP
    ip_hdr.extend_from_slice(&0u16.to_be_bytes());
    ip_hdr.extend_from_slice(&src_ip);
    ip_hdr.extend_from_slice(&dst_ip);

    let csum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());
    frame.extend_from_slice(&ip_hdr);

    // TCP Header
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&ack.to_be_bytes());
    frame.push(0x50); // Data offset (5 * 4 = 20)
    frame.push(flags);
    frame.extend_from_slice(&65535u16.to_be_bytes()); // Window
    frame.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    frame.extend_from_slice(&0u16.to_be_bytes()); // Urgent ptr
    frame.extend_from_slice(data);

    frame
}

#[test]
fn test_help_command() {
    let (code, stdout, stderr) = run_cli(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("flows"));
    assert!(!stdout.contains("  dns"));
    assert!(!stdout.contains("  http"));
    assert!(!stdout.contains("  tls"));
    assert!(!stdout.contains("  findings"));
    assert!(!stdout.contains("  analyze"));
    assert!(stderr.is_empty());
}

#[test]
fn test_version_command() {
    let (code, stdout, stderr) = run_cli(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    assert!(stderr.is_empty());
}

#[test]
fn test_usage_errors() {
    // No subcommand
    let (code, _, _) = run_cli(&[]);
    assert_eq!(code, 2);

    // Unknown subcommand
    let (code, _, _) = run_cli(&["nonexistent"]);
    assert_eq!(code, 2);

    // Missing capture argument for validate
    let (code, _, _) = run_cli(&["validate"]);
    assert_eq!(code, 2);

    // Missing capture argument for flows
    let (code, _, _) = run_cli(&["flows"]);
    assert_eq!(code, 2);

    // Invalid integer limit
    let (code, _, _) = run_cli(&["validate", "test.pcap", "--max-records", "notanumber"]);
    assert_eq!(code, 2);

    // Zero flow limit
    let (code, _, _) = run_cli(&["flows", "test.pcap", "--max-flows", "0"]);
    assert_eq!(code, 2);
}

#[test]
fn test_nonexistent_file() {
    let (code, stdout, stderr) = run_cli(&["validate", "this_file_does_not_exist_12345.pcap"]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("error: failed to open capture file"));
}

#[test]
fn test_validate_complete() {
    let pcap_bytes = make_pcap_header(65535, 1);
    let temp = TempCaptureFile::new("empty.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["validate", &temp.path_str()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Capture"));
    assert!(stdout.contains("Format        PCAP (little-endian)"));
    assert!(stdout.contains("Completion    complete"));
    assert!(stdout.contains("Records       0"));
    assert!(stdout.contains("Linktype      1"));
    assert!(stdout.contains("Snaplen       65535"));
    assert!(stderr.is_empty());
}

#[test]
fn test_validate_partial() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    // Add one complete packet
    let frame = make_ipv4_udp_frame(
        [0, 1, 2, 3, 4, 5],
        [6, 7, 8, 9, 10, 11],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        5678,
        b"hello",
    );
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &frame));
    // Add a truncated packet header (incomplete packet)
    pcap_bytes.extend_from_slice(&[101, 0, 0, 0]); // Truncated record header

    let temp = TempCaptureFile::new("partial.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["validate", &temp.path_str()]);
    assert_eq!(code, 3);
    assert!(stdout.contains("Completion    partial"));
    assert!(stdout.contains("Records       1"));
    assert!(!stderr.is_empty());
}

#[test]
fn test_validate_failed_before_useful() {
    let garbage = b"this is not a valid pcap or pcapng header at all";
    let temp = TempCaptureFile::new("garbage.pcap", garbage);

    let (code, stdout, stderr) = run_cli(&["validate", &temp.path_str()]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("error:"));
}

#[test]
fn test_validate_quiet() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    let frame = make_ipv4_udp_frame(
        [0, 1, 2, 3, 4, 5],
        [6, 7, 8, 9, 10, 11],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        5678,
        b"hello",
    );
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &frame));
    pcap_bytes.extend_from_slice(&[101, 0, 0, 0]); // Truncated header

    let temp = TempCaptureFile::new("partial_quiet.pcap", &pcap_bytes);

    let (code_normal, out_normal, err_normal) = run_cli(&["validate", &temp.path_str()]);
    let (code_quiet, out_quiet, err_quiet) = run_cli(&["--quiet", "validate", &temp.path_str()]);

    assert_eq!(code_normal, 3);
    assert_eq!(code_quiet, 3);
    assert_eq!(out_normal, out_quiet);
    assert!(!err_normal.is_empty());
    assert!(err_quiet.is_empty());
}

#[test]
fn test_flows_basic_udp() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac_b = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];

    // Packet 1: A -> B
    let f1 = make_ipv4_udp_frame(mac_a, mac_b, ip_a, ip_b, 5353, 5353, b"query");
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &f1));

    // Packet 2: B -> A
    let f2 = make_ipv4_udp_frame(mac_b, mac_a, ip_b, ip_a, 5353, 5353, b"response");
    pcap_bytes.extend_from_slice(&make_pcap_packet(101, 500_000, &f2));

    let temp = TempCaptureFile::new("udp_flow.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["flows", &temp.path_str()]);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());

    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2); // Header + 1 flow row
    assert!(lines[0].contains("ID"));
    assert!(lines[0].contains("PROTO"));
    assert!(lines[0].contains("ENDPOINT_A"));
    assert!(lines[0].contains("ENDPOINT_B"));
    assert!(lines[1].contains("UDP"));
    assert!(lines[1].contains("10.0.0.1:5353"));
    assert!(lines[1].contains("10.0.0.2:5353"));
    assert!(lines[1].contains("EndOfInput"));
}

#[test]
fn test_flows_tcp() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac_b = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let ip_a = [192, 168, 1, 10];
    let ip_b = [192, 168, 1, 1];

    // 1. SYN (A -> B)
    let f_syn = make_ipv4_tcp_frame(mac_a, mac_b, ip_a, ip_b, 49152, 443, 1000, 0, 0x02, b"");
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &f_syn));

    // 2. SYN-ACK (B -> A)
    let f_synack = make_ipv4_tcp_frame(mac_b, mac_a, ip_b, ip_a, 443, 49152, 5000, 1001, 0x12, b"");
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 10_000, &f_synack));

    // 3. ACK (A -> B)
    let f_ack = make_ipv4_tcp_frame(mac_a, mac_b, ip_a, ip_b, 49152, 443, 1001, 5001, 0x10, b"");
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 20_000, &f_ack));

    // 4. RST (A -> B)
    let f_rst = make_ipv4_tcp_frame(mac_a, mac_b, ip_a, ip_b, 49152, 443, 1001, 5001, 0x04, b"");
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 30_000, &f_rst));

    let temp = TempCaptureFile::new("tcp_rst_flow.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["flows", &temp.path_str()]);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());

    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[1].contains("TCP"));
    assert!(lines[1].contains("192.168.1.1:443"));
    assert!(lines[1].contains("192.168.1.10:49152"));
    assert!(lines[1].contains("TcpReset"));
}

#[test]
fn test_empty_flow_view() {
    let pcap_bytes = make_pcap_header(65535, 1);
    let temp = TempCaptureFile::new("empty_flows.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["flows", &temp.path_str()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("ID"));
    assert!(stderr.is_empty());
}

#[test]
fn test_flow_exclusion() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    // ICMP packet (IPv4 protocol 1, unsupported transport for TCP/UDP reconstruction)
    let mut icmp_frame = Vec::new();
    icmp_frame.extend_from_slice(&[0; 6]);
    icmp_frame.extend_from_slice(&[0; 6]);
    icmp_frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let mut ip_hdr = vec![
        0x45, 0x00, 0x00, 28, 0x00, 0x01, 0x00, 0x00, 64, 1, // Proto 1 (ICMP)
        0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let csum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());
    icmp_frame.extend_from_slice(&ip_hdr);
    icmp_frame.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]); // ICMP Echo Request

    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &icmp_frame));

    let temp = TempCaptureFile::new("icmp_exclusion.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["flows", &temp.path_str()]);
    assert_eq!(code, 3);
    assert!(stdout.contains("ID"));
    assert!(!stderr.is_empty());
}

#[test]
fn test_partial_flow_finalization() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac_b = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

    // Flow 1
    let f1 = make_ipv4_udp_frame(
        mac_a,
        mac_b,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1000,
        2000,
        b"p1",
    );
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &f1));

    // Flow 2
    let f2 = make_ipv4_udp_frame(
        mac_a,
        mac_b,
        [10, 0, 0, 3],
        [10, 0, 0, 4],
        3000,
        4000,
        b"p2",
    );
    pcap_bytes.extend_from_slice(&make_pcap_packet(101, 0, &f2));

    let temp = TempCaptureFile::new("max_tracked.pcap", &pcap_bytes);

    // Limit maximum tracked flows to 1. Packet 2 exceeds limit and triggers terminal flow error
    let (code, stdout, stderr) = run_cli(&["flows", &temp.path_str(), "--max-flows", "1"]);
    assert_eq!(code, 3);
    assert!(stdout.contains("AnalysisStopped"));
    assert!(!stderr.is_empty());
}

#[test]
fn test_clean_end_flow_finalization() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    let f1 = make_ipv4_udp_frame(
        [0; 6],
        [0; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1000,
        2000,
        b"data",
    );
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &f1));

    let temp = TempCaptureFile::new("clean_end.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["flows", &temp.path_str()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("EndOfInput"));
    assert!(!stdout.contains("AnalysisStopped"));
    assert!(stderr.is_empty());
}

#[test]
fn test_determinism_repeated_run() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    let f1 = make_ipv4_udp_frame(
        [0; 6],
        [0; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1000,
        2000,
        b"1",
    );
    let f2 = make_ipv4_udp_frame(
        [0; 6],
        [0; 6],
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        2000,
        1000,
        b"2",
    );
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &f1));
    pcap_bytes.extend_from_slice(&make_pcap_packet(101, 0, &f2));

    let temp = TempCaptureFile::new("determinism.pcap", &pcap_bytes);

    let (code1, out1, err1) = run_cli(&["flows", &temp.path_str()]);
    let (code2, out2, err2) = run_cli(&["flows", &temp.path_str()]);

    assert_eq!(code1, code2);
    assert_eq!(out1, out2);
    assert_eq!(err1, err2);
}

#[test]
fn test_stdout_stderr_separation() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    let f1 = make_ipv4_udp_frame(
        [0; 6],
        [0; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1000,
        2000,
        b"1",
    );
    pcap_bytes.extend_from_slice(&make_pcap_packet(100, 0, &f1));

    let temp = TempCaptureFile::new("separation.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["flows", &temp.path_str()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("ENDPOINT_A"));
    assert!(stderr.is_empty());
}

#[test]
fn test_diagnostic_amplification() {
    let mut pcap_bytes = make_pcap_header(65535, 1);
    // Create 150 unsupported packets to exceed the 100-line budget
    let mut icmp_frame = Vec::new();
    icmp_frame.extend_from_slice(&[0; 12]);
    icmp_frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let mut ip_hdr = vec![
        0x45, 0x00, 0x00, 28, 0x00, 0x01, 0x00, 0x00, 64, 1, // ICMP
        0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let csum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());
    icmp_frame.extend_from_slice(&ip_hdr);
    icmp_frame.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]);

    for i in 0..150 {
        pcap_bytes.extend_from_slice(&make_pcap_packet(100 + i, 0, &icmp_frame));
    }

    let temp = TempCaptureFile::new("amplification.pcap", &pcap_bytes);

    let (code, _, stderr) = run_cli(&["flows", &temp.path_str()]);
    assert_eq!(code, 3);
    assert!(stderr.contains("warning: suppressed"));
    assert!(stderr.contains("additional diagnostic messages"));

    // Verify quiet mode suppresses all nonfatal diagnostics
    let (code_q, _, stderr_q) = run_cli(&["--quiet", "flows", &temp.path_str()]);
    assert_eq!(code_q, 3);
    assert!(stderr_q.is_empty());
}

#[test]
fn test_limit_boundaries() {
    let pcap_bytes = make_pcap_header(65535, 1);
    let temp = TempCaptureFile::new("limits.pcap", &pcap_bytes);

    // Valid limits
    let (code, _, _) = run_cli(&[
        "flows",
        &temp.path_str(),
        "--max-records",
        "1000",
        "--tcp-idle-timeout",
        "60",
    ]);
    assert_eq!(code, 0);

    // Invalid zero limit
    let (code, _, _) = run_cli(&["flows", &temp.path_str(), "--tcp-idle-timeout", "0"]);
    assert_eq!(code, 2);

    // Exceeding hard cap (timeout > 30 days)
    let (code, _, _) = run_cli(&["flows", &temp.path_str(), "--tcp-idle-timeout", "999999999"]);
    assert_eq!(code, 2);
}

#[test]
fn test_path_robustness() {
    let pcap_bytes = make_pcap_header(65535, 1);
    let temp = TempCaptureFile::new("space test file.pcap", &pcap_bytes);

    let (code, stdout, stderr) = run_cli(&["validate", &temp.path_str()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Capture"));
    assert!(stderr.is_empty());
}
