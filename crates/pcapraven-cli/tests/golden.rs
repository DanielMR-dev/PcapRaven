//! End-to-end golden report comparison tests for PcapRaven CLI.

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

fn root_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates
    path.pop(); // root
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

fn assert_golden_match(args: &[&str], golden_rel_path: &str) {
    let (code, stdout, stderr) = run_cli(args);
    assert_eq!(code, 0, "CLI execution failed for args {args:?}:\n{stderr}");

    let golden_path = root_path()
        .join("tests")
        .join("golden")
        .join(golden_rel_path);
    assert!(
        golden_path.exists(),
        "golden file not found: {}",
        golden_path.display()
    );

    let expected = fs::read_to_string(&golden_path)
        .unwrap_or_else(|e| panic!("failed to read golden {}: {e}", golden_path.display()));

    assert_eq!(
        stdout,
        expected,
        "stdout did not match golden file {}\nDiff:\n--- STDOUT ---\n{stdout}\n--- EXPECTED ---\n{expected}",
        golden_path.display()
    );
}

// 1. Validate Goldens
#[test]
fn test_golden_validate_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["validate", "--format", "table", pcap.to_str().unwrap()],
        "validate/clean_dns.table.txt",
    );
}

#[test]
fn test_golden_validate_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["validate", "--format", "json", pcap.to_str().unwrap()],
        "validate/clean_dns.json",
    );
}

#[test]
fn test_golden_validate_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["validate", "--format", "ndjson", pcap.to_str().unwrap()],
        "validate/clean_dns.ndjson",
    );
}

#[test]
fn test_golden_validate_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["validate", "--format", "csv", pcap.to_str().unwrap()],
        "validate/clean_dns.csv",
    );
}

// 2. Flows Goldens
#[test]
fn test_golden_flows_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tcp_flows.pcap");
    assert_golden_match(
        &["flows", "--format", "table", pcap.to_str().unwrap()],
        "flows/clean_tcp_flows.table.txt",
    );
}

#[test]
fn test_golden_flows_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tcp_flows.pcap");
    assert_golden_match(
        &["flows", "--format", "json", pcap.to_str().unwrap()],
        "flows/clean_tcp_flows.json",
    );
}

#[test]
fn test_golden_flows_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tcp_flows.pcap");
    assert_golden_match(
        &["flows", "--format", "ndjson", pcap.to_str().unwrap()],
        "flows/clean_tcp_flows.ndjson",
    );
}

#[test]
fn test_golden_flows_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tcp_flows.pcap");
    assert_golden_match(
        &["flows", "--format", "csv", pcap.to_str().unwrap()],
        "flows/clean_tcp_flows.csv",
    );
}

// 3. DNS Goldens
#[test]
fn test_golden_dns_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["dns", "--format", "table", pcap.to_str().unwrap()],
        "dns/clean_dns.table.txt",
    );
}

#[test]
fn test_golden_dns_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["dns", "--format", "json", pcap.to_str().unwrap()],
        "dns/clean_dns.json",
    );
}

#[test]
fn test_golden_dns_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["dns", "--format", "ndjson", pcap.to_str().unwrap()],
        "dns/clean_dns.ndjson",
    );
}

#[test]
fn test_golden_dns_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["dns", "--format", "csv", pcap.to_str().unwrap()],
        "dns/clean_dns.csv",
    );
}

// 4. HTTP Goldens
#[test]
fn test_golden_http_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_http.pcap");
    assert_golden_match(
        &["http", "--format", "table", pcap.to_str().unwrap()],
        "http/clean_http.table.txt",
    );
}

#[test]
fn test_golden_http_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_http.pcap");
    assert_golden_match(
        &["http", "--format", "json", pcap.to_str().unwrap()],
        "http/clean_http.json",
    );
}

#[test]
fn test_golden_http_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_http.pcap");
    assert_golden_match(
        &["http", "--format", "ndjson", pcap.to_str().unwrap()],
        "http/clean_http.ndjson",
    );
}

#[test]
fn test_golden_http_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_http.pcap");
    assert_golden_match(
        &["http", "--format", "csv", pcap.to_str().unwrap()],
        "http/clean_http.csv",
    );
}

// 5. TLS Goldens
#[test]
fn test_golden_tls_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tls.pcap");
    assert_golden_match(
        &["tls", "--format", "table", pcap.to_str().unwrap()],
        "tls/clean_tls.table.txt",
    );
}

#[test]
fn test_golden_tls_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tls.pcap");
    assert_golden_match(
        &["tls", "--format", "json", pcap.to_str().unwrap()],
        "tls/clean_tls.json",
    );
}

#[test]
fn test_golden_tls_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tls.pcap");
    assert_golden_match(
        &["tls", "--format", "ndjson", pcap.to_str().unwrap()],
        "tls/clean_tls.ndjson",
    );
}

#[test]
fn test_golden_tls_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_tls.pcap");
    assert_golden_match(
        &["tls", "--format", "csv", pcap.to_str().unwrap()],
        "tls/clean_tls.csv",
    );
}

// 6. Findings Goldens
#[test]
fn test_golden_findings_periodic_beaconing_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/periodic_beaconing.pcap");
    assert_golden_match(
        &["findings", "--format", "table", pcap.to_str().unwrap()],
        "findings/periodic_beaconing.table.txt",
    );
}

#[test]
fn test_golden_findings_periodic_beaconing_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/periodic_beaconing.pcap");
    assert_golden_match(
        &["findings", "--format", "json", pcap.to_str().unwrap()],
        "findings/periodic_beaconing.json",
    );
}

#[test]
fn test_golden_findings_periodic_beaconing_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/periodic_beaconing.pcap");
    assert_golden_match(
        &["findings", "--format", "ndjson", pcap.to_str().unwrap()],
        "findings/periodic_beaconing.ndjson",
    );
}

#[test]
fn test_golden_findings_periodic_beaconing_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/periodic_beaconing.pcap");
    assert_golden_match(
        &["findings", "--format", "csv", pcap.to_str().unwrap()],
        "findings/periodic_beaconing.csv",
    );
}

#[test]
fn test_golden_findings_dns_tunneling_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/dns_tunneling.pcap");
    assert_golden_match(
        &["findings", "--format", "table", pcap.to_str().unwrap()],
        "findings/dns_tunneling.table.txt",
    );
}

#[test]
fn test_golden_findings_dns_tunneling_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/dns_tunneling.pcap");
    assert_golden_match(
        &["findings", "--format", "json", pcap.to_str().unwrap()],
        "findings/dns_tunneling.json",
    );
}

#[test]
fn test_golden_findings_dns_tunneling_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/dns_tunneling.pcap");
    assert_golden_match(
        &["findings", "--format", "ndjson", pcap.to_str().unwrap()],
        "findings/dns_tunneling.ndjson",
    );
}

#[test]
fn test_golden_findings_dns_tunneling_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/dns_tunneling.pcap");
    assert_golden_match(
        &["findings", "--format", "csv", pcap.to_str().unwrap()],
        "findings/dns_tunneling.csv",
    );
}

#[test]
fn test_golden_findings_c2_multi_signal_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &["findings", "--format", "table", pcap.to_str().unwrap()],
        "findings/c2_multi_signal.table.txt",
    );
}

#[test]
fn test_golden_findings_c2_multi_signal_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &["findings", "--format", "json", pcap.to_str().unwrap()],
        "findings/c2_multi_signal.json",
    );
}

#[test]
fn test_golden_findings_c2_multi_signal_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &["findings", "--format", "ndjson", pcap.to_str().unwrap()],
        "findings/c2_multi_signal.ndjson",
    );
}

#[test]
fn test_golden_findings_c2_multi_signal_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &["findings", "--format", "csv", pcap.to_str().unwrap()],
        "findings/c2_multi_signal.csv",
    );
}

#[test]
fn test_golden_findings_c2_mitre_filter_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &[
            "findings",
            "--mitre",
            "T1071.004",
            "--format",
            "table",
            pcap.to_str().unwrap(),
        ],
        "findings/c2_multi_signal_mitre_filter.table.txt",
    );
}

#[test]
fn test_golden_findings_c2_mitre_filter_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &[
            "findings",
            "--mitre",
            "T1071.004",
            "--format",
            "json",
            pcap.to_str().unwrap(),
        ],
        "findings/c2_multi_signal_mitre_filter.json",
    );
}

#[test]
fn test_golden_findings_c2_mitre_filter_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &[
            "findings",
            "--mitre",
            "T1071.004",
            "--format",
            "ndjson",
            pcap.to_str().unwrap(),
        ],
        "findings/c2_multi_signal_mitre_filter.ndjson",
    );
}

#[test]
fn test_golden_findings_c2_mitre_filter_csv() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &[
            "findings",
            "--mitre",
            "T1071.004",
            "--format",
            "csv",
            pcap.to_str().unwrap(),
        ],
        "findings/c2_multi_signal_mitre_filter.csv",
    );
}

// 7. Analyze Goldens
#[test]
fn test_golden_analyze_clean_dns_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["analyze", "--format", "table", pcap.to_str().unwrap()],
        "analyze/clean_dns.table.txt",
    );
}

#[test]
fn test_golden_analyze_clean_dns_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["analyze", "--format", "json", pcap.to_str().unwrap()],
        "analyze/clean_dns.json",
    );
}

#[test]
fn test_golden_analyze_clean_dns_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/benign/clean_dns.pcap");
    assert_golden_match(
        &["analyze", "--format", "ndjson", pcap.to_str().unwrap()],
        "analyze/clean_dns.ndjson",
    );
}

#[test]
fn test_golden_analyze_c2_multi_signal_table() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &["analyze", "--format", "table", pcap.to_str().unwrap()],
        "analyze/c2_multi_signal.table.txt",
    );
}

#[test]
fn test_golden_analyze_c2_multi_signal_json() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &["analyze", "--format", "json", pcap.to_str().unwrap()],
        "analyze/c2_multi_signal.json",
    );
}

#[test]
fn test_golden_analyze_c2_multi_signal_ndjson() {
    let pcap = root_path().join("tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap");
    assert_golden_match(
        &["analyze", "--format", "ndjson", pcap.to_str().unwrap()],
        "analyze/c2_multi_signal.ndjson",
    );
}
