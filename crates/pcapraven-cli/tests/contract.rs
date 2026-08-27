//! Byte-exact regression tests for the frozen PcapRaven v1 CLI surface.
//!
//! Report payloads remain owned by the existing golden integration target.
//! This target covers the command-line boundary: generated help and usage text,
//! argument scope, aliases, exit states, stream separation, and output files.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const CLEAN_CAPTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/pcaps/benign/clean_dns.pcap"
);
const PARTIAL_CAPTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/pcaps/malformed/useful_then_truncated_record.pcap"
);
const SUSPICIOUS_CAPTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/pcaps/suspicious/c2_multi_signal.pcap"
);
const MISSING_CAPTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/pcaps/does-not-exist.pcap"
);

macro_rules! snapshot {
    ($kind:literal, $name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/cli_contract/",
            $kind,
            "/",
            $name
        ))
    };
}

const PRODUCT_COMMANDS: [&str; 7] = [
    "validate", "flows", "dns", "http", "tls", "findings", "analyze",
];
const FORMATS: [&str; 4] = ["table", "json", "ndjson", "csv"];

fn run<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_pcapraven"))
        .args(args)
        .output()
        .expect("execute pcapraven binary")
}

fn exit_code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn assert_success(output: &Output) {
    assert_eq!(exit_code(output), 0);
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {:?}",
        output.stderr
    );
}

fn assert_snapshot(args: &[&str], expected: &[u8]) {
    let output = run(args);
    assert_eq!(exit_code(&output), 0, "unexpected help failure: {args:?}");
    assert_eq!(
        output.stdout.as_slice(),
        expected,
        "stdout changed: {args:?}"
    );
    assert!(output.stderr.is_empty(), "help wrote stderr: {args:?}");
    assert_no_ansi(&output);
}

fn assert_error_snapshot(args: &[&str], expected: &[u8]) {
    let output = run(args);
    assert_eq!(exit_code(&output), 2, "unexpected usage state: {args:?}");
    assert!(output.stdout.is_empty(), "usage wrote stdout: {args:?}");
    assert_eq!(
        output.stderr.as_slice(),
        expected,
        "stderr changed: {args:?}"
    );
    assert_no_ansi(&output);
}

fn assert_no_ansi(output: &Output) {
    assert!(
        !output.stdout.contains(&0x1b),
        "stdout contains an ANSI escape: {:?}",
        output.stdout
    );
    assert!(
        !output.stderr.contains(&0x1b),
        "stderr contains an ANSI escape: {:?}",
        output.stderr
    );
}

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

fn unique_temp_path(label: &str) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "pcapraven-phase21-contract-{}-{id}-{label}",
        std::process::id()
    ))
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(label: &str, bytes: &[u8]) -> Self {
        let path = unique_temp_path(label);
        let _ = fs::remove_file(&path);
        fs::write(&path, bytes).expect("write temporary contract fixture");
        Self { path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn output_args(command: &str, format: &str, flag: &str, path: &Path) -> Vec<OsString> {
    vec![
        OsString::from(command),
        OsString::from("--format"),
        OsString::from(format),
        OsString::from(flag),
        path.as_os_str().to_os_string(),
        OsString::from(CLEAN_CAPTURE),
    ]
}

fn output_args_before_command(flag: &str, path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from(flag),
        path.as_os_str().to_os_string(),
        OsString::from("validate"),
        OsString::from(CLEAN_CAPTURE),
    ]
}

fn output_args_after_capture(flag: &str, path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("validate"),
        OsString::from(CLEAN_CAPTURE),
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from(flag),
        path.as_os_str().to_os_string(),
    ]
}

fn run_with_capture(prefix: &[&str], capture: &Path) -> Output {
    let mut args = prefix.iter().map(OsString::from).collect::<Vec<_>>();
    args.push(capture.as_os_str().to_os_string());
    run(args)
}

#[test]
fn help_output_is_byte_exact_for_root_and_all_product_commands() {
    let cases: &[(&[&str], &[u8])] = &[
        (&["--help"], snapshot!("help", "root.txt")),
        (&["validate", "--help"], snapshot!("help", "validate.txt")),
        (&["flows", "--help"], snapshot!("help", "flows.txt")),
        (&["dns", "--help"], snapshot!("help", "dns.txt")),
        (&["http", "--help"], snapshot!("help", "http.txt")),
        (&["tls", "--help"], snapshot!("help", "tls.txt")),
        (&["findings", "--help"], snapshot!("help", "findings.txt")),
        (&["analyze", "--help"], snapshot!("help", "analyze.txt")),
    ];

    for (args, expected) in cases {
        assert_snapshot(args, expected);
    }
}

#[test]
fn standard_aliases_and_visible_help_subcommand_are_deliberate() {
    let root_long = run(["--help"]);
    let root_short = run(["-h"]);
    assert_success(&root_long);
    assert_success(&root_short);
    assert_eq!(root_short.stdout, root_long.stdout);

    for command in PRODUCT_COMMANDS {
        let long = run([command, "--help"]);
        let short = run([command, "-h"]);
        assert_success(&long);
        assert_success(&short);
        assert_eq!(
            short.stdout, long.stdout,
            "help alias changed for {command}"
        );
    }

    let implicit_root = run(["help"]);
    assert_success(&implicit_root);
    assert_eq!(
        implicit_root.stdout.as_slice(),
        snapshot!("help", "root.txt"),
        "the visibly advertised built-in help subcommand changed"
    );

    let implicit_validate = run(["help", "validate"]);
    assert_success(&implicit_validate);
    assert_eq!(
        implicit_validate.stdout.as_slice(),
        snapshot!("help", "validate.txt")
    );
}

#[test]
fn version_aliases_use_the_dynamic_package_version_grammar() {
    let expected = format!("pcapraven {}\n", env!("CARGO_PKG_VERSION"));
    for args in [["--version"], ["-V"]] {
        let output = run(args);
        assert_success(&output);
        assert_eq!(output.stdout, expected.as_bytes());
    }
}

#[test]
fn representative_usage_and_error_text_is_byte_exact() {
    let cases: &[(&[&str], &[u8])] = &[
        (&[], snapshot!("usage", "no_args.txt")),
        (&["nonexistent"], snapshot!("usage", "unknown_command.txt")),
        (
            &["validate"],
            snapshot!("usage", "validate_missing_capture.txt"),
        ),
        (&["flows"], snapshot!("usage", "flows_missing_capture.txt")),
        (&["dns"], snapshot!("usage", "dns_missing_capture.txt")),
        (&["http"], snapshot!("usage", "http_missing_capture.txt")),
        (&["tls"], snapshot!("usage", "tls_missing_capture.txt")),
        (
            &["findings"],
            snapshot!("usage", "findings_missing_capture.txt"),
        ),
        (
            &["analyze"],
            snapshot!("usage", "analyze_missing_capture.txt"),
        ),
        (
            &["--format", "invalid", "validate", "capture.pcap"],
            snapshot!("errors", "invalid_format.txt"),
        ),
        (
            &["validate", "--min-severity", "low", "capture.pcap"],
            snapshot!("errors", "validate_filter_scope.txt"),
        ),
        (
            &["dns", "--max-flows", "10", "capture.pcap"],
            snapshot!("errors", "dns_flow_scope.txt"),
        ),
        (
            &["findings", "--min-severity", "urgent", "capture.pcap"],
            snapshot!("errors", "invalid_severity.txt"),
        ),
        (
            &["findings", "--min-confidence", "certain", "capture.pcap"],
            snapshot!("errors", "invalid_confidence.txt"),
        ),
        (
            &["findings", "--detector", "DNS.Tunnel", "capture.pcap"],
            snapshot!("errors", "invalid_detector.txt"),
        ),
        (
            &["findings", "--mitre", "TA0011", "capture.pcap"],
            snapshot!("errors", "invalid_mitre.txt"),
        ),
        (
            &["--format", "csv", "analyze", CLEAN_CAPTURE],
            snapshot!("errors", "analyze_csv.txt"),
        ),
    ];

    for (args, expected) in cases {
        assert_error_snapshot(args, expected);
    }
}

#[test]
fn every_product_command_supports_only_the_frozen_format_matrix() {
    for command in PRODUCT_COMMANDS {
        for format in FORMATS {
            if command == "analyze" && format == "csv" {
                continue;
            }
            let output = run([command, "--format", format, CLEAN_CAPTURE]);
            assert_eq!(
                exit_code(&output),
                0,
                "{command} --format {format} did not complete"
            );
            assert!(
                !output.stdout.is_empty(),
                "{command} --format {format} produced no report"
            );
            assert!(output.stderr.is_empty());
            assert_no_ansi(&output);
        }
    }

    let analyze_csv = run(["analyze", "--format", "csv", CLEAN_CAPTURE]);
    assert_eq!(exit_code(&analyze_csv), 2);
    assert!(analyze_csv.stdout.is_empty());
    assert_eq!(
        analyze_csv.stderr.as_slice(),
        snapshot!("errors", "analyze_csv.txt")
    );
}

#[test]
fn table_is_the_exact_default_for_all_product_commands() {
    for command in PRODUCT_COMMANDS {
        let implicit = run([command, CLEAN_CAPTURE]);
        let explicit = run([command, "--format", "table", CLEAN_CAPTURE]);
        assert_eq!(exit_code(&implicit), 0, "default failed for {command}");
        assert_eq!(exit_code(&implicit), exit_code(&explicit));
        assert_eq!(
            implicit.stdout, explicit.stdout,
            "default changed for {command}"
        );
        assert_eq!(
            implicit.stderr, explicit.stderr,
            "diagnostics changed for {command}"
        );
    }
}

#[test]
fn global_options_have_stable_placement_and_alias_behavior() {
    let format_variants = [
        ["--format", "json", "validate", CLEAN_CAPTURE],
        ["validate", "--format", "json", CLEAN_CAPTURE],
        ["validate", CLEAN_CAPTURE, "--format", "json"],
    ];
    let expected_format = run(format_variants[0]);
    assert_success(&expected_format);
    for args in format_variants.iter().skip(1) {
        let output = run(args);
        assert_success(&output);
        assert_eq!(output.stdout, expected_format.stdout);
        assert_eq!(output.stderr, expected_format.stderr);
    }

    let dashdash = run(["validate", "--", CLEAN_CAPTURE]);
    assert_success(&dashdash);
    let ordinary = run(["validate", CLEAN_CAPTURE]);
    assert_eq!(dashdash.stdout, ordinary.stdout);
    assert_eq!(dashdash.stderr, ordinary.stderr);

    let duplicate_format = run([
        "--format",
        "json",
        "--format",
        "table",
        "validate",
        CLEAN_CAPTURE,
    ]);
    assert_eq!(exit_code(&duplicate_format), 2);
    assert!(duplicate_format.stdout.is_empty());
    assert!(duplicate_format.stderr.starts_with(b"error:"));

    let duplicate_quiet = run(["--quiet", "--quiet", "validate", CLEAN_CAPTURE]);
    assert_eq!(exit_code(&duplicate_quiet), 2);
    assert!(duplicate_quiet.stdout.is_empty());
    assert!(duplicate_quiet.stderr.starts_with(b"error:"));

    let duplicate_output = run([
        "--output",
        "first-report",
        "--output",
        "second-report",
        "validate",
        CLEAN_CAPTURE,
    ]);
    assert_eq!(exit_code(&duplicate_output), 2);
    assert!(duplicate_output.stdout.is_empty());
    assert!(duplicate_output.stderr.starts_with(b"error:"));
}

#[test]
fn canonical_filter_values_and_mitre_technique_shapes_are_accepted() {
    for value in ["info", "low", "medium", "high", "critical"] {
        let output = run(["findings", "--min-severity", value, SUSPICIOUS_CAPTURE]);
        assert_ne!(
            exit_code(&output),
            2,
            "severity value was rejected: {value}"
        );
    }

    for value in ["low", "medium", "high"] {
        let output = run(["findings", "--min-confidence", value, SUSPICIOUS_CAPTURE]);
        assert_ne!(
            exit_code(&output),
            2,
            "confidence value was rejected: {value}"
        );
    }

    let detector = run([
        "findings",
        "--detector",
        "dns.possible_tunneling",
        SUSPICIOUS_CAPTURE,
    ]);
    assert_ne!(exit_code(&detector), 2);

    for value in ["T1071", "T1071.004"] {
        let output = run(["findings", "--mitre", value, SUSPICIOUS_CAPTURE]);
        assert_ne!(exit_code(&output), 2, "MITRE value was rejected: {value}");
    }

    let analyze = run([
        "analyze",
        "--min-severity",
        "low",
        "--min-confidence",
        "medium",
        "--detector",
        "dns.possible_tunneling",
        "--mitre",
        "T1071.004",
        SUSPICIOUS_CAPTURE,
    ]);
    assert_ne!(exit_code(&analyze), 2);
}

#[test]
fn configured_limits_reject_zero_and_values_above_each_hard_cap() {
    let cases = [
        ["validate", "--max-records", "0", CLEAN_CAPTURE],
        ["validate", "--max-records", "10000001", CLEAN_CAPTURE],
        ["flows", "--max-flows", "0", CLEAN_CAPTURE],
        ["flows", "--max-flows", "1000001", CLEAN_CAPTURE],
        ["flows", "--max-flow-instances", "0", CLEAN_CAPTURE],
        ["flows", "--max-flow-instances", "10000001", CLEAN_CAPTURE],
        ["flows", "--tcp-idle-timeout", "0", CLEAN_CAPTURE],
        ["flows", "--tcp-idle-timeout", "2592001", CLEAN_CAPTURE],
        ["flows", "--udp-idle-timeout", "0", CLEAN_CAPTURE],
        ["flows", "--udp-idle-timeout", "2592001", CLEAN_CAPTURE],
        ["findings", "--max-observations", "0", CLEAN_CAPTURE],
        ["findings", "--max-observations", "1000001", CLEAN_CAPTURE],
    ];

    for args in cases {
        let output = run(args);
        assert_eq!(exit_code(&output), 2, "limit was accepted: {args:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.starts_with(b"error:"));
    }
}

#[test]
fn quiet_preserves_result_and_exit_state_but_suppresses_nonfatal_diagnostics() {
    let ordinary = run(["flows", PARTIAL_CAPTURE]);
    assert_eq!(exit_code(&ordinary), 3);
    assert!(!ordinary.stdout.is_empty());
    assert!(!ordinary.stderr.is_empty());
    let ordinary_stderr = String::from_utf8_lossy(&ordinary.stderr);
    assert!(
        ordinary_stderr
            .lines()
            .all(|line| line.starts_with("diagnostic: ") || line.starts_with("warning: "))
    );

    for args in [
        ["--quiet", "flows", PARTIAL_CAPTURE],
        ["flows", "--quiet", PARTIAL_CAPTURE],
        ["flows", PARTIAL_CAPTURE, "--quiet"],
        ["-q", "flows", PARTIAL_CAPTURE],
    ] {
        let quiet = run(args);
        assert_eq!(exit_code(&quiet), exit_code(&ordinary));
        assert_eq!(quiet.stdout, ordinary.stdout);
        assert!(quiet.stderr.is_empty());
        assert_no_ansi(&quiet);
    }

    let fatal = run(["--quiet", "validate", MISSING_CAPTURE]);
    assert_eq!(exit_code(&fatal), 1);
    assert!(fatal.stdout.is_empty());
    assert!(
        fatal.stderr.starts_with(b"error:"),
        "fatal error was suppressed: {:?}",
        fatal.stderr
    );
}

#[test]
fn diagnostic_output_is_bounded_to_one_hundred_lines() {
    let mut bytes = pcap_header();
    let frame = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34];
    for ordinal in 0..150u32 {
        bytes.extend_from_slice(&pcap_record(ordinal, &frame));
    }
    let capture = TempFile::new("diagnostic-bound", &bytes);
    let ordinary = run_with_capture(&["flows"], &capture.path);

    assert_eq!(exit_code(&ordinary), 3);
    let ordinary_stderr = String::from_utf8_lossy(&ordinary.stderr);
    let diagnostic_lines = ordinary_stderr
        .lines()
        .filter(|line| line.starts_with("diagnostic: "))
        .count();
    assert_eq!(diagnostic_lines, 100);
    assert_eq!(
        ordinary_stderr
            .lines()
            .filter(|line| line.starts_with("warning: "))
            .count(),
        1
    );
    assert!(ordinary_stderr.contains("budget: 100"));

    let quiet = run_with_capture(&["--quiet", "flows"], &capture.path);
    assert_eq!(exit_code(&quiet), 3);
    assert_eq!(quiet.stdout, ordinary.stdout);
    assert!(quiet.stderr.is_empty());
}

#[test]
fn output_file_aliases_route_bytes_safely_without_stdout() {
    let direct = run(["validate", "--format", "json", CLEAN_CAPTURE]);
    assert_success(&direct);

    let variants = [
        (
            "command-first",
            output_args("validate", "json", "--output", Path::new("unused")),
        ),
        (
            "before-command",
            output_args_before_command("--output", Path::new("unused")),
        ),
        (
            "after-capture",
            output_args_after_capture("--output", Path::new("unused")),
        ),
        (
            "short-command-first",
            output_args("validate", "json", "-o", Path::new("unused")),
        ),
        (
            "short-before-command",
            output_args_before_command("-o", Path::new("unused")),
        ),
        (
            "short-after-capture",
            output_args_after_capture("-o", Path::new("unused")),
        ),
    ];

    for (label, template) in variants {
        let path = unique_temp_path(label);
        let mut args = template;
        let path_position = args
            .iter()
            .position(|argument| argument == "unused")
            .expect("output path placeholder");
        args[path_position] = path.as_os_str().to_os_string();
        let output = run(args);
        assert_success(&output);
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read(&path).expect("read output report"), direct.stdout);
        fs::remove_file(path).expect("remove temporary output report");
    }
}

#[test]
fn output_collision_and_parent_creation_failure_are_fatal_or_configured_exactly() {
    let collision = unique_temp_path("collision");
    let sentinel = b"do-not-overwrite";
    fs::write(&collision, sentinel).expect("write collision sentinel");
    let collision_output = run(output_args("validate", "table", "--output", &collision));
    assert_eq!(exit_code(&collision_output), 2);
    assert!(collision_output.stdout.is_empty());
    assert_eq!(
        fs::read(&collision).expect("read collision sentinel"),
        sentinel
    );
    assert!(
        collision_output
            .stderr
            .starts_with(b"error: output file already exists:")
    );
    fs::remove_file(&collision).expect("remove collision sentinel");

    let missing_parent = unique_temp_path("missing-parent");
    assert!(!missing_parent.exists());
    let output_path = missing_parent.join("report.txt");
    let creation_output = run(output_args("validate", "table", "--output", &output_path));
    assert_eq!(exit_code(&creation_output), 1);
    assert!(creation_output.stdout.is_empty());
    assert!(
        creation_output
            .stderr
            .starts_with(b"error: failed to create output file")
    );
    assert!(!missing_parent.exists());
}

#[test]
fn process_exit_states_are_zero_one_two_and_three_with_the_frozen_meanings() {
    let complete = run(["validate", CLEAN_CAPTURE]);
    assert_eq!(exit_code(&complete), 0);
    assert!(!complete.stdout.is_empty());

    let useful_partial = run(["validate", PARTIAL_CAPTURE]);
    assert_eq!(exit_code(&useful_partial), 3);
    assert!(!useful_partial.stdout.is_empty());

    let fatal = run(["validate", MISSING_CAPTURE]);
    assert_eq!(exit_code(&fatal), 1);
    assert!(fatal.stdout.is_empty());
    assert!(fatal.stderr.starts_with(b"error:"));

    let usage = run(["--format", "invalid", "validate", CLEAN_CAPTURE]);
    assert_eq!(exit_code(&usage), 2);
    assert!(usage.stdout.is_empty());
    assert!(usage.stderr.starts_with(b"error:"));

    for output in [&complete, &useful_partial, &fatal, &usage] {
        assert_no_ansi(output);
    }
}

fn pcap_header() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&65535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes
}

fn pcap_record(timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("synthetic payload fits u32");
    let mut bytes = Vec::with_capacity(16 + payload.len());
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
