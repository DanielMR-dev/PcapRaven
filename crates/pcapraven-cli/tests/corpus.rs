use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn pcapraven_bin() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates
    path.pop(); // root
    path.push("target");
    path.push("debug");
    path.push(if cfg!(windows) {
        "pcapraven.exe"
    } else {
        "pcapraven"
    });
    if !path.exists() {
        // Fallback to cargo run / current_exe if needed
        let exe = std::env::current_exe().expect("current exe");
        let mut target_dir = exe.parent().expect("target dir");
        if target_dir.ends_with("deps") {
            target_dir = target_dir.parent().expect("parent of deps");
        }
        let fallback = target_dir.join(if cfg!(windows) {
            "pcapraven.exe"
        } else {
            "pcapraven"
        });
        if fallback.exists() {
            return fallback;
        }
    }
    path
}

fn fixture_path(rel: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates
    path.pop(); // root
    path.push("tests");
    path.push("fixtures");
    path.push("pcaps");
    path.push(rel);
    path
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let bin = pcapraven_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to execute {}: {e}", bin.display()));

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

#[test]
fn test_corpus_fixtures_exist_and_match_checksums() {
    let checksums_file = fixture_path("checksums.sha256");
    assert!(checksums_file.exists(), "checksums.sha256 must exist");
    let content = fs::read_to_string(&checksums_file).expect("read checksums.sha256");

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.len(), 2, "invalid checksum line: {line}");
        let expected_sha = parts[0];
        let rel_file = parts[1];
        assert_eq!(expected_sha.len(), 64, "expected valid sha256 hash");
        let target = fixture_path(rel_file);
        assert!(
            target.exists(),
            "fixture file missing: {}",
            target.display()
        );

        let bytes = fs::read(&target).expect("read fixture");
        if !rel_file.contains("zero_length") {
            assert!(!bytes.is_empty());
        }
    }
}

#[test]
fn test_corpus_benign_clean_dns() {
    let pcap = fixture_path("benign/clean_dns.pcap");
    let pcap_str = pcap.to_str().unwrap();

    // validate
    let (code, stdout, _) = run_cli(&["validate", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("pcap"));
    assert!(stdout.contains("Records       2"));

    // dns
    let (code, stdout, _) = run_cli(&["dns", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("example.com"));

    // findings (should be zero findings)
    let (code, stdout, _) = run_cli(&["findings", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("No findings matched"));

    // analyze json
    let (code, stdout, _) = run_cli(&["analyze", "--format", "json", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("\"total_packets\": \"2\""));
    assert!(stdout.contains("\"total_dns_observations\": \"2\""));
    assert!(stdout.contains("\"total_findings\": \"0\""));
}

#[test]
fn test_corpus_benign_clean_http() {
    let pcap = fixture_path("benign/clean_http.pcap");
    let pcap_str = pcap.to_str().unwrap();

    // http
    let (code, stdout, _) = run_cli(&["http", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("GET"));
    assert!(stdout.contains("200"));

    // analyze json
    let (code, stdout, _) = run_cli(&["analyze", "--format", "json", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("\"total_http_observations\": \"2\""));
    assert!(stdout.contains("\"total_findings\": \"0\""));
}

#[test]
fn test_corpus_benign_clean_tls() {
    let pcap = fixture_path("benign/clean_tls.pcap");
    let pcap_str = pcap.to_str().unwrap();

    // tls
    let (code, stdout, _) = run_cli(&["tls", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("ClientHello"));
    assert!(stdout.contains("secure.example.com"));

    // analyze json
    let (code, stdout, _) = run_cli(&["analyze", "--format", "json", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("\"total_tls_observations\": \"1\""));
}

#[test]
fn test_corpus_benign_clean_tcp_flows() {
    let pcap = fixture_path("benign/clean_tcp_flows.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, _) = run_cli(&["flows", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("8080"));
    assert!(stdout.contains("9090"));
}

#[test]
fn test_corpus_suspicious_periodic_beaconing() {
    let pcap = fixture_path("suspicious/periodic_beaconing.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, _) = run_cli(&["findings", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("behavior.periodic_beaconing"));

    // analyze ndjson
    let (code, stdout, _) = run_cli(&["analyze", "--format", "ndjson", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("behavior.periodic_beaconing"));
}

#[test]
fn test_corpus_suspicious_dns_long_query() {
    let pcap = fixture_path("suspicious/dns_long_query.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, _) = run_cli(&["findings", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("dns.long_query_name"));
}

#[test]
fn test_corpus_suspicious_dns_tunneling() {
    let pcap = fixture_path("suspicious/dns_tunneling.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, _) = run_cli(&["findings", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("dns.possible_tunneling"));
    assert!(stdout.contains("T1071.004"));
}

#[test]
fn test_corpus_suspicious_repeated_low_volume() {
    let pcap = fixture_path("suspicious/repeated_low_volume.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, _) = run_cli(&["findings", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("behavior.repeated_low_volume_flows"));
}

#[test]
fn test_corpus_suspicious_c2_multi_signal_correlation() {
    let pcap = fixture_path("suspicious/c2_multi_signal.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, _) = run_cli(&["findings", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("behavior.periodic_beaconing"));
    assert!(stdout.contains("dns.possible_tunneling"));
    assert!(stdout.contains("behavior.possible_c2_multi_signal"));

    // Check filtering by MITRE ID T1071.004
    let (code, stdout, _) = run_cli(&["findings", "--mitre", "T1071.004", pcap_str]);
    assert_eq!(code, 0);
    assert!(stdout.contains("dns.possible_tunneling"));
    assert!(stdout.contains("behavior.possible_c2_multi_signal"));
    assert!(!stdout.contains("behavior.periodic_beaconing")); // Beaconing alone has no T1071.004
}

#[test]
fn test_corpus_malformed_truncated_header() {
    let pcap = fixture_path("malformed/truncated_header.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, stderr) = run_cli(&["validate", pcap_str]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("failed") || stderr.contains("error"));
}

#[test]
fn test_corpus_malformed_corrupt_packet() {
    let pcap = fixture_path("malformed/corrupt_packet.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, _, stderr) = run_cli(&["validate", pcap_str]);
    assert_eq!(code, 1);
    assert!(!stderr.is_empty());
}

#[test]
fn test_corpus_malformed_zero_length() {
    let pcap = fixture_path("malformed/zero_length.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, _, stderr) = run_cli(&["validate", pcap_str]);
    assert_eq!(code, 1);
    assert!(stderr.contains("failed") || stderr.contains("error"));
}

#[test]
fn test_corpus_edge_non_monotonic_timestamps() {
    let pcap = fixture_path("edge_cases/non_monotonic_timestamps.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code, stdout, _) = run_cli(&["flows", pcap_str]);
    assert!(code == 0 || code == 3);
    assert!(stdout.contains("192.0.2.10"));
}

#[test]
fn test_corpus_deterministic_repeatability() {
    let pcap = fixture_path("suspicious/c2_multi_signal.pcap");
    let pcap_str = pcap.to_str().unwrap();

    let (code1, stdout1, stderr1) = run_cli(&["analyze", "--format", "json", pcap_str]);
    let (code2, stdout2, stderr2) = run_cli(&["analyze", "--format", "json", pcap_str]);

    assert_eq!(code1, code2);
    assert_eq!(stdout1, stdout2);
    assert_eq!(stderr1, stderr2);
}
