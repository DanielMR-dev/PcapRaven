//! Byte-exact CLI golden regression scenarios, including all four exit states.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use support::{TreeLimits, collect_regular_files_bounded, read_file_bounded};

#[derive(Debug)]
struct Scenario {
    name: String,
    args: Vec<String>,
    expected_exit: i32,
    // `None` means the stream must be exactly empty.
    stdout_golden: Option<String>,
    // `None` means the stream must be exactly empty.
    stderr_golden: Option<String>,
}

const MAX_GOLDEN_BYTES: usize = 4 * 1024 * 1024;
const FIXTURE_RELATIVE_ROOT: &str = "tests/fixtures/pcaps";
const GOLDEN_RELATIVE_ROOT: &str = "tests/golden";
const CANONICAL_TREE_LIMITS: TreeLimits = TreeLimits {
    maximum_depth: 8,
    maximum_entries: 4096,
    maximum_files: 1024,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate is below the workspace root")
        .to_path_buf()
}

fn fixture(relative: &str) -> String {
    root()
        .join(FIXTURE_RELATIVE_ROOT)
        .join(relative)
        .to_string_lossy()
        .into_owned()
}

fn add_formats(
    scenarios: &mut Vec<Scenario>,
    command: &str,
    capture: &str,
    prefix: &str,
    formats: &[&str],
    extra: &[&str],
) {
    for output_format in formats {
        let extension = if *output_format == "table" {
            "table.txt"
        } else {
            output_format
        };
        let mut args = vec![
            command.to_string(),
            "--format".to_string(),
            output_format.to_string(),
        ];
        args.extend(extra.iter().map(ToString::to_string));
        args.push(fixture(capture));
        scenarios.push(Scenario {
            name: format!("{prefix}-{output_format}"),
            args,
            expected_exit: 0,
            stdout_golden: Some(format!("{prefix}.{extension}")),
            stderr_golden: None,
        });
    }
}

fn scenarios() -> Vec<Scenario> {
    let mut result = Vec::new();
    let all = ["table", "json", "ndjson", "csv"];
    add_formats(
        &mut result,
        "validate",
        "benign/clean_dns.pcap",
        "validate/clean_dns",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "flows",
        "benign/clean_tcp_flows.pcap",
        "flows/clean_tcp_flows",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "dns",
        "benign/clean_dns.pcap",
        "dns/clean_dns",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "http",
        "benign/clean_http.pcap",
        "http/clean_http",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "tls",
        "benign/clean_tls.pcap",
        "tls/clean_tls",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "findings",
        "suspicious/periodic_beaconing.pcap",
        "findings/periodic_beaconing",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "findings",
        "suspicious/dns_tunneling.pcap",
        "findings/dns_tunneling",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "findings",
        "suspicious/c2_multi_signal.pcap",
        "findings/c2_multi_signal",
        &all,
        &[],
    );
    add_formats(
        &mut result,
        "findings",
        "suspicious/c2_multi_signal.pcap",
        "findings/c2_multi_signal_mitre_filter",
        &all,
        &["--mitre", "T1071.004"],
    );
    add_formats(
        &mut result,
        "analyze",
        "benign/clean_dns.pcap",
        "analyze/clean_dns",
        &["table", "json", "ndjson"],
        &[],
    );
    add_formats(
        &mut result,
        "analyze",
        "suspicious/c2_multi_signal.pcap",
        "analyze/c2_multi_signal",
        &["table", "json", "ndjson"],
        &[],
    );
    let fixed = [
        (
            "multi-section",
            vec!["validate", "--format", "json"],
            "edge_cases/multi_section.pcapng",
            0,
            Some("validate/multi_section.json"),
            None,
        ),
        (
            "flow-close-order",
            vec!["flows", "--format", "table"],
            "edge_cases/flow_close_out_of_creation_order.pcap",
            0,
            Some("flows/flow_close_out_of_creation_order.table.txt"),
            None,
        ),
        (
            "local-http-partial-dns",
            vec![
                "findings",
                "--format",
                "table",
                "--detector",
                "dns.possible_tunneling",
            ],
            "edge_cases/local_http_partial_with_dns_detection.pcap",
            3,
            Some("findings/local_http_partial_with_dns_detection.table.txt"),
            Some("stderr/local_http_partial_with_dns_detection.txt"),
        ),
        (
            "useful-then-truncated",
            vec!["analyze", "--format", "json"],
            "malformed/useful_then_truncated_record.pcap",
            3,
            Some("analyze/useful_then_truncated_record.json"),
            Some("stderr/useful_then_truncated_record.txt"),
        ),
        (
            "corrupt-no-useful",
            vec!["validate"],
            "malformed/corrupt_packet.pcap",
            1,
            None,
            Some("stderr/corrupt_packet.txt"),
        ),
        (
            "analyze-csv-rejected",
            vec!["analyze", "--format", "csv"],
            "benign/clean_dns.pcap",
            2,
            None,
            Some("stderr/analyze_csv_rejected.txt"),
        ),
        (
            "csv-sentinels",
            vec!["http", "--format", "csv"],
            "edge_cases/csv_formula_sentinels.pcap",
            0,
            Some("http/csv_formula_sentinels.csv"),
            None,
        ),
    ];
    for (name, args, capture, expected_exit, stdout, stderr) in fixed {
        let mut args: Vec<String> = args.into_iter().map(ToString::to_string).collect();
        args.push(fixture(capture));
        result.push(Scenario {
            name: name.to_string(),
            args,
            expected_exit,
            stdout_golden: stdout.map(ToString::to_string),
            stderr_golden: stderr.map(ToString::to_string),
        });
    }
    result
}

fn expected_bytes(relative: &str) -> Vec<u8> {
    read_file_bounded(
        &root(),
        &Path::new(GOLDEN_RELATIVE_ROOT).join(relative),
        MAX_GOLDEN_BYTES,
    )
    .unwrap_or_else(|error| panic!("failed to read golden {relative}: {error}"))
}

fn preflight_canonical_inputs(matrix: &[Scenario]) {
    let workspace_root = root();
    let fixture_root = workspace_root.join(FIXTURE_RELATIVE_ROOT);
    let actual_fixtures = collect_regular_files_bounded(
        &workspace_root,
        Path::new(FIXTURE_RELATIVE_ROOT),
        &["pcap", "pcapng"],
        CANONICAL_TREE_LIMITS,
    )
    .expect("complete bounded fixture traversal before scenario execution");
    for scenario in matrix {
        let capture = scenario
            .args
            .last()
            .map(Path::new)
            .and_then(|path| path.strip_prefix(&fixture_root).ok())
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| panic!("{} capture escaped fixture root", scenario.name));
        assert!(
            actual_fixtures.contains(&capture),
            "{} capture is missing or non-regular: {capture}",
            scenario.name
        );
    }

    let actual_goldens = collect_regular_files_bounded(
        &workspace_root,
        Path::new(GOLDEN_RELATIVE_ROOT),
        &["txt", "json", "ndjson", "csv"],
        CANONICAL_TREE_LIMITS,
    )
    .expect("complete bounded golden traversal before expected-byte reads");
    let expected_goldens: BTreeSet<String> = matrix
        .iter()
        .flat_map(|scenario| {
            [
                scenario.stdout_golden.as_ref(),
                scenario.stderr_golden.as_ref(),
            ]
        })
        .flatten()
        .cloned()
        .collect();
    assert_eq!(
        actual_goldens, expected_goldens,
        "canonical golden inventory"
    );
}

#[test]
fn canonical_scenario_matrix_matches_exact_bytes_and_exit_states() {
    let matrix = scenarios();
    preflight_canonical_inputs(&matrix);
    for scenario in matrix {
        let output = Command::new(env!("CARGO_BIN_EXE_pcapraven"))
            .args(&scenario.args)
            .output()
            .unwrap_or_else(|error| panic!("{} failed to execute: {error}", scenario.name));
        assert_eq!(
            output.status.code(),
            Some(scenario.expected_exit),
            "{} returned an unexpected exit state; stderr={:?}",
            scenario.name,
            output.stderr
        );
        match scenario.stdout_golden {
            Some(path) => assert_eq!(
                output.stdout,
                expected_bytes(&path),
                "{} stdout",
                scenario.name
            ),
            None => assert!(
                output.stdout.is_empty(),
                "{} stdout must be empty",
                scenario.name
            ),
        }
        match scenario.stderr_golden {
            Some(path) => assert_eq!(
                output.stderr,
                expected_bytes(&path),
                "{} stderr",
                scenario.name
            ),
            None => assert!(
                output.stderr.is_empty(),
                "{} stderr must be empty: {:?}",
                scenario.name,
                output.stderr
            ),
        }
    }
}
