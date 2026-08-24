mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::{TreeLimits, collect_regular_files_bounded, read_file_bounded};

struct FixtureBehaviorCase {
    path: &'static str,
    args: &'static [&'static str],
    expected_exit: i32,
    stdout_contains: &'static [&'static str],
    expect_empty_stdout: bool,
    expect_empty_stderr: bool,
}

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const FIXTURE_RELATIVE_ROOT: &str = "tests/fixtures/pcaps";
const FIXTURE_TREE_LIMITS: TreeLimits = TreeLimits {
    maximum_depth: 8,
    maximum_entries: 4096,
    maximum_files: 1024,
};

const BEHAVIOR_CASES: &[FixtureBehaviorCase] = &[
    FixtureBehaviorCase {
        path: "benign/clean_dns.pcap",
        args: &["analyze", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"total_dns_observations\": \"2\"", "\"findings\": []"],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "benign/clean_http.pcap",
        args: &["analyze", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"total_http_observations\": \"2\"", "\"findings\": []"],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "benign/clean_tcp_flows.pcap",
        args: &["analyze", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"total_flows\": \"2\"", "\"findings\": []"],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "benign/clean_tls.pcap",
        args: &["analyze", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"total_tls_observations\": \"1\"", "secure.example.com"],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "benign/clean_udp_flows.pcap",
        args: &["analyze", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"total_flows\": \"2\"", "\"findings\": []"],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "edge_cases/csv_formula_sentinels.pcap",
        args: &["http", "--format", "csv"],
        expected_exit: 0,
        stdout_contains: &[
            "'=host.example",
            "'+phase17/type",
            "'-phase17-server",
            "'@phase17-agent",
        ],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "edge_cases/flow_close_out_of_creation_order.pcap",
        args: &["flows", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &[
            "\"total_flows\": \"2\"",
            "\"ordinal\": \"0\"",
            "\"ordinal\": \"1\"",
        ],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "edge_cases/http_privacy_sentinels.pcap",
        args: &["http", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &[
            "\"authorization_present\": true",
            "\"proxy_authorization_present\": true",
            "\"cookie_present\": true",
            "\"set_cookie_present\": true",
        ],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "edge_cases/local_http_partial_with_dns_detection.pcap",
        args: &["findings", "--format", "json"],
        expected_exit: 3,
        stdout_contains: &["dns.possible_tunneling"],
        expect_empty_stdout: false,
        expect_empty_stderr: false,
    },
    FixtureBehaviorCase {
        path: "edge_cases/multi_section.pcapng",
        args: &["validate", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"section_count\": \"2\"", "\"records_emitted\": \"2\""],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "edge_cases/non_monotonic_timestamps.pcap",
        args: &["analyze", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &[
            "\"unavailable_reason\": \"non_monotonic_timestamp\"",
            "\"non_monotonic_transitions\": \"1\"",
            "\"duration\": null",
        ],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "malformed/corrupt_packet.pcap",
        args: &["validate", "--format", "json"],
        expected_exit: 1,
        stdout_contains: &[],
        expect_empty_stdout: true,
        expect_empty_stderr: false,
    },
    FixtureBehaviorCase {
        path: "malformed/truncated_header.pcap",
        args: &["validate", "--format", "json"],
        expected_exit: 1,
        stdout_contains: &[],
        expect_empty_stdout: true,
        expect_empty_stderr: false,
    },
    FixtureBehaviorCase {
        path: "malformed/useful_then_truncated_record.pcap",
        args: &["analyze", "--format", "json"],
        expected_exit: 3,
        stdout_contains: &["\"total_packets\": \"1\"", "\"capture_truncated\""],
        expect_empty_stdout: false,
        expect_empty_stderr: false,
    },
    FixtureBehaviorCase {
        path: "malformed/zero_length.pcap",
        args: &["validate", "--format", "json"],
        expected_exit: 1,
        stdout_contains: &[],
        expect_empty_stdout: true,
        expect_empty_stderr: false,
    },
    FixtureBehaviorCase {
        path: "suspicious/c2_multi_signal.pcap",
        args: &["findings", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &[
            "behavior.periodic_beaconing",
            "dns.possible_tunneling",
            "behavior.possible_c2_multi_signal",
        ],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "suspicious/dns_long_query.pcap",
        args: &["findings", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"detector_id\": \"dns.long_query_name\""],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "suspicious/dns_tunneling.pcap",
        args: &["findings", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"detector_id\": \"dns.possible_tunneling\""],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "suspicious/periodic_beaconing.pcap",
        args: &["findings", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"detector_id\": \"behavior.periodic_beaconing\""],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
    FixtureBehaviorCase {
        path: "suspicious/repeated_low_volume.pcap",
        args: &["findings", "--format", "json"],
        expected_exit: 0,
        stdout_contains: &["\"detector_id\": \"behavior.repeated_low_volume_flows\""],
        expect_empty_stdout: false,
        expect_empty_stderr: true,
    },
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate is below the workspace root")
        .to_path_buf()
}

fn fixture(relative: &str) -> PathBuf {
    root().join(FIXTURE_RELATIVE_ROOT).join(relative)
}

fn preflight_fixture_tree() -> BTreeSet<String> {
    collect_regular_files_bounded(
        &root(),
        Path::new(FIXTURE_RELATIVE_ROOT),
        &["pcap", "pcapng"],
        FIXTURE_TREE_LIMITS,
    )
    .expect("complete bounded fixture traversal before canonical input use")
}

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pcapraven"))
        .args(args)
        .output()
        .expect("execute pcapraven test binary")
}

fn run_fixture(prefix: &[&str], relative: &str) -> Output {
    let _ = preflight_fixture_tree();
    let mut args: Vec<String> = prefix.iter().map(ToString::to_string).collect();
    args.push(fixture(relative).to_string_lossy().into_owned());
    run(&args)
}

fn json_string_values(document: &str, key: &str) -> Vec<String> {
    let prefix = format!("\"{key}\": \"");
    document
        .lines()
        .filter_map(|line| {
            let value = line.trim().strip_prefix(&prefix)?;
            value
                .strip_suffix(',')
                .unwrap_or(value)
                .strip_suffix('"')
                .map(ToString::to_string)
        })
        .collect()
}

#[test]
fn manifest_canonically_covers_the_complete_fixture_tree() {
    let actual = preflight_fixture_tree();
    let manifest_bytes = read_file_bounded(
        &root(),
        Path::new("tests/fixtures/pcaps/manifest.json"),
        MAX_MANIFEST_BYTES,
    )
    .expect("read bounded fixture manifest");
    let manifest = std::str::from_utf8(&manifest_bytes).expect("fixture manifest is UTF-8");
    assert!(manifest.starts_with("{\n  \"schema_version\": 1,\n  \"generator_version\": 1,"));

    let paths = json_string_values(manifest, "path");
    let categories = json_string_values(manifest, "category");
    let hashes = json_string_values(manifest, "sha256");
    assert_eq!(paths.len(), BEHAVIOR_CASES.len());
    assert_eq!(categories.len(), paths.len());
    assert_eq!(hashes.len(), paths.len());
    assert!(paths.windows(2).all(|window| window[0] < window[1]));
    assert!(categories.iter().all(|category| matches!(
        category.as_str(),
        "benign" | "suspicious" | "malformed" | "edge_cases"
    )));
    assert!(hashes.iter().all(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }));
    assert_eq!(manifest.matches("\"synthetic\": true").count(), paths.len());
    assert_eq!(
        manifest.matches("\"license\": \"MIT\"").count(),
        paths.len()
    );
    assert_eq!(manifest.matches("\"purpose\": ").count(), paths.len());
    assert_eq!(
        manifest.matches("\"expected_behavior\": ").count(),
        paths.len()
    );

    let manifest_paths: BTreeSet<_> = paths.iter().cloned().collect();
    let required: BTreeSet<_> = BEHAVIOR_CASES
        .iter()
        .map(|case| case.path.to_string())
        .collect();
    assert_eq!(manifest_paths, required);
    assert_eq!(actual, manifest_paths, "unexpected or unmanifested fixture");
}

#[test]
fn every_manifest_fixture_executes_with_exact_expected_behavior() {
    for case in BEHAVIOR_CASES {
        let output = run_fixture(case.args, case.path);
        assert_eq!(
            output.status.code(),
            Some(case.expected_exit),
            "{} returned the wrong exit state; stderr={}",
            case.path,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout.is_empty(),
            case.expect_empty_stdout,
            "{} stdout emptiness mismatch",
            case.path
        );
        assert_eq!(
            output.stderr.is_empty(),
            case.expect_empty_stderr,
            "{} stderr emptiness mismatch: {}",
            case.path,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for expected in case.stdout_contains {
            assert!(
                stdout.contains(expected),
                "{} missing expected behavior token {expected}",
                case.path
            );
        }
    }
}

#[test]
fn supported_pcapng_and_flow_order_regressions_are_canonical() {
    let validate = run_fixture(
        &["validate", "--format", "json"],
        "edge_cases/multi_section.pcapng",
    );
    assert_eq!(validate.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&validate.stdout).contains("\"section_count\": \"2\""));

    let analysis = run_fixture(
        &["analyze", "--format", "json"],
        "edge_cases/multi_section.pcapng",
    );
    assert_eq!(analysis.status.code(), Some(0));
    assert!(!analysis.stdout.is_empty());

    let flows = run_fixture(
        &["flows", "--format", "json"],
        "edge_cases/flow_close_out_of_creation_order.pcap",
    );
    assert_eq!(flows.status.code(), Some(0));
    let text = String::from_utf8_lossy(&flows.stdout);
    let flow0 = text.find("\"ordinal\": \"0\"").expect("flow:0");
    let flow1 = text.find("\"ordinal\": \"1\"").expect("flow:1");
    assert!(
        flow0 < flow1,
        "flows must be ordered by creation reference, not closure"
    );
}

#[test]
fn malformed_capture_exit_states_distinguish_no_result_from_useful_partial() {
    for command in [
        "validate", "flows", "dns", "http", "tls", "findings", "analyze",
    ] {
        let output = run_fixture(&[command], "malformed/corrupt_packet.pcap");
        assert_eq!(
            output.status.code(),
            Some(1),
            "{command} must fail before useful output"
        );
        assert!(
            output.stdout.is_empty(),
            "{command} emitted misleading output"
        );
    }

    let output = run_fixture(
        &["analyze", "--format", "json"],
        "malformed/useful_then_truncated_record.pcap",
    );
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"capture_truncated\""));
    assert!(stdout.contains("\"total_packets\": \"1\""));
}

#[test]
fn local_http_degradation_does_not_suppress_clean_dns_detection() {
    let output = run_fixture(
        &["findings", "--format", "json"],
        "edge_cases/local_http_partial_with_dns_detection.pcap",
    );
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dns.possible_tunneling"));
}

#[test]
fn csv_formula_cells_are_prefixed_without_mutating_json_or_ndjson() {
    let csv = run_fixture(
        &["http", "--format", "csv"],
        "edge_cases/csv_formula_sentinels.pcap",
    );
    assert_eq!(csv.status.code(), Some(0));
    let csv_text = String::from_utf8_lossy(&csv.stdout);
    for sentinel in [
        "'=host.example",
        "'+phase17/type",
        "'-phase17-server",
        "'@phase17-agent",
    ] {
        assert!(csv_text.contains(sentinel), "missing sanitized {sentinel}");
    }

    for format in ["json", "ndjson"] {
        let output = run_fixture(
            &["http", "--format", format],
            "edge_cases/csv_formula_sentinels.pcap",
        );
        assert_eq!(output.status.code(), Some(0));
        let text = String::from_utf8_lossy(&output.stdout);
        for sentinel in [
            "=host.example",
            "+phase17/type",
            "-phase17-server",
            "@phase17-agent",
        ] {
            assert!(text.contains(sentinel));
            assert!(!text.contains(&format!("'{sentinel}")));
        }
    }
}

#[test]
fn sensitive_http_values_never_reach_reports_or_stderr() {
    const SECRETS: &[&str] = &[
        "PHASE18_AUTH_SECRET",
        "PHASE18_PROXY_AUTH_SECRET",
        "PHASE18_COOKIE_SECRET",
        "PHASE18_SET_COOKIE_SECRET",
    ];
    let json = run_fixture(
        &["http", "--format", "json"],
        "edge_cases/http_privacy_sentinels.pcap",
    );
    assert_eq!(json.status.code(), Some(0));
    for presence_flag in [
        "\"authorization_present\": true",
        "\"proxy_authorization_present\": true",
        "\"cookie_present\": true",
        "\"set_cookie_present\": true",
    ] {
        assert!(
            String::from_utf8_lossy(&json.stdout).contains(presence_flag),
            "missing sensitive-header presence fact: {presence_flag}"
        );
    }
    for format in ["table", "json", "ndjson", "csv"] {
        let output = run_fixture(
            &["http", "--format", format],
            "edge_cases/http_privacy_sentinels.pcap",
        );
        assert_eq!(output.status.code(), Some(0));
        for secret in SECRETS {
            assert!(
                !output
                    .stdout
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
            assert!(
                !output
                    .stderr
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
}

#[test]
fn configured_resource_limits_are_exact_structured_partial_states() {
    let cases = [
        (
            ["--max-records", "1"],
            "benign/clean_dns.pcap",
            "packet_count_budget_reached",
        ),
        (
            ["--max-flows", "1"],
            "benign/clean_udp_flows.pcap",
            "flow_budget_reached",
        ),
        (
            ["--max-flow-instances", "1"],
            "benign/clean_udp_flows.pcap",
            "flow_budget_reached",
        ),
        (
            ["--max-observations", "1"],
            "benign/clean_dns.pcap",
            "observation_budget_reached",
        ),
    ];
    for (limit, capture, expected) in cases {
        let output = run_fixture(
            &["analyze", "--format", "json", limit[0], limit[1]],
            capture,
        );
        assert_eq!(output.status.code(), Some(3), "{expected}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains(expected), "missing {expected}");
        for limitation in [
            "capture_truncated",
            "packet_count_budget_reached",
            "flow_budget_reached",
            "observation_budget_reached",
        ] {
            assert_eq!(
                text.contains(limitation),
                limitation == expected,
                "unexpected limitation set for {expected}: {limitation}"
            );
        }
    }
}

#[test]
fn representative_formats_and_filtered_findings_are_repeatable() {
    let cases = [
        (
            vec!["analyze", "--format", "table"],
            "suspicious/c2_multi_signal.pcap",
        ),
        (
            vec!["analyze", "--format", "json"],
            "suspicious/c2_multi_signal.pcap",
        ),
        (
            vec!["analyze", "--format", "ndjson"],
            "suspicious/c2_multi_signal.pcap",
        ),
        (
            vec!["findings", "--format", "csv"],
            "suspicious/c2_multi_signal.pcap",
        ),
        (
            vec!["findings", "--format", "json", "--mitre", "T1071.004"],
            "suspicious/c2_multi_signal.pcap",
        ),
    ];
    for (args, capture) in cases {
        let first = run_fixture(&args, capture);
        let second = run_fixture(&args, capture);
        assert_eq!(first.status.code(), second.status.code());
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(first.stderr, second.stderr);
    }
}
