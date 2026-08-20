//! Command-line argument parsing and configuration types.

use clap::{Arg, ArgAction, Command};
use pcapraven_domain::{Confidence, DetectorId, MitreAttackId, Severity};
use pcapraven_reporting::ReportFormat;
use std::path::PathBuf;

/// Parsed top-level command-line configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgs {
    /// Whether to suppress nonfatal diagnostic messages on stderr.
    pub quiet: bool,
    /// The requested output format.
    pub format: ReportFormat,
    /// Optional safe output file path.
    pub output: Option<PathBuf>,
    /// The requested subcommand.
    pub command: Subcommand,
}

/// Requested CLI subcommand and its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subcommand {
    /// Validate capture container integrity and factual metadata.
    Validate(ValidateArgs),
    /// Reconstruct network flows and inspect traffic statistics.
    Flows(FlowsArgs),
    /// Inspect normalized DNS observations.
    Dns(DnsArgs),
    /// Inspect cleartext HTTP/1.x message headers.
    Http(HttpArgs),
    /// Inspect visible TLS 1.2 / TLS 1.3 handshake metadata.
    Tls(TlsArgs),
    /// Inspect analytical security findings with filtering.
    Findings(FindingsArgs),
    /// Perform full unified capture analysis across all layers.
    Analyze(AnalyzeArgs),
}

/// Arguments for `pcapraven validate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateArgs {
    /// Path to the local capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
}

/// Arguments for `pcapraven dns`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsArgs {
    /// Path to the local capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
}

/// Arguments for `pcapraven http`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpArgs {
    /// Path to the local capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
}

/// Arguments for `pcapraven tls`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsArgs {
    /// Path to the local capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
}

/// Arguments for `pcapraven flows`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowsArgs {
    /// Path to the local capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
    /// Maximum simultaneous active flows to track.
    pub max_flows: Option<usize>,
    /// Maximum total flow instances across analysis.
    pub max_flow_instances: Option<usize>,
    /// TCP flow idle timeout in seconds.
    pub tcp_idle_timeout: Option<u32>,
    /// UDP flow idle timeout in seconds.
    pub udp_idle_timeout: Option<u32>,
}

/// Arguments for `pcapraven findings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingsArgs {
    /// Path to the local capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
    /// Maximum simultaneous active flows to track.
    pub max_flows: Option<usize>,
    /// Maximum total flow instances across analysis.
    pub max_flow_instances: Option<usize>,
    /// Maximum protocol observations to retain.
    pub max_observations: Option<usize>,
    /// TCP flow idle timeout in seconds.
    pub tcp_idle_timeout: Option<u32>,
    /// UDP flow idle timeout in seconds.
    pub udp_idle_timeout: Option<u32>,
    /// Minimum severity filter.
    pub min_severity: Option<Severity>,
    /// Minimum confidence filter.
    pub min_confidence: Option<Confidence>,
    /// Filter by specific detector identifier.
    pub detector_id: Option<DetectorId>,
    /// Filter by MITRE ATT&CK technique identifier.
    pub mitre_id: Option<MitreAttackId>,
}

/// Arguments for `pcapraven analyze`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzeArgs {
    /// Path to the local capture file.
    pub capture_path: PathBuf,
    /// Maximum capture records to process.
    pub max_records: Option<u64>,
    /// Maximum simultaneous active flows to track.
    pub max_flows: Option<usize>,
    /// Maximum total flow instances across analysis.
    pub max_flow_instances: Option<usize>,
    /// Maximum protocol observations to retain.
    pub max_observations: Option<usize>,
    /// TCP flow idle timeout in seconds.
    pub tcp_idle_timeout: Option<u32>,
    /// UDP flow idle timeout in seconds.
    pub udp_idle_timeout: Option<u32>,
    /// Minimum severity filter.
    pub min_severity: Option<Severity>,
    /// Minimum confidence filter.
    pub min_confidence: Option<Confidence>,
    /// Filter by specific detector identifier.
    pub detector_id: Option<DetectorId>,
    /// Filter by MITRE ATT&CK technique identifier.
    pub mitre_id: Option<MitreAttackId>,
}

/// Builds the clap [`Command`] definition.
#[must_use]
pub fn build_cli() -> Command {
    Command::new("pcapraven")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Offline network forensics and threat-hunting analyzer.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue)
                .global(true)
                .help("Suppress nonfatal diagnostics on stderr"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .global(true)
                .default_value("table")
                .value_parser(["table", "json", "ndjson", "csv"])
                .help("Output format (table, json, ndjson, csv)"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("PATH")
                .global(true)
                .help("Write report to destination file (fails safely if file exists)"),
        )
        .subcommand(
            Command::new("validate")
                .about("Validate capture file structure and factual metadata.")
                .arg(
                    Arg::new("capture")
                        .value_name("CAPTURE")
                        .required(true)
                        .index(1)
                        .help("Path to the capture file"),
                )
                .arg(
                    Arg::new("max-records")
                        .long("max-records")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum capture records to process"),
                ),
        )
        .subcommand(
            Command::new("flows")
                .about("Inspect reconstructed network flows and factual traffic statistics.")
                .arg(
                    Arg::new("capture")
                        .value_name("CAPTURE")
                        .required(true)
                        .index(1)
                        .help("Path to the capture file"),
                )
                .arg(
                    Arg::new("max-records")
                        .long("max-records")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum capture records to process"),
                )
                .arg(
                    Arg::new("max-flows")
                        .long("max-flows")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum simultaneous active flows to track"),
                )
                .arg(
                    Arg::new("max-flow-instances")
                        .long("max-flow-instances")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum total flow instances across analysis"),
                )
                .arg(
                    Arg::new("tcp-idle-timeout")
                        .long("tcp-idle-timeout")
                        .value_name("SECONDS")
                        .value_parser(clap::value_parser!(u32))
                        .help("TCP flow idle timeout in seconds"),
                )
                .arg(
                    Arg::new("udp-idle-timeout")
                        .long("udp-idle-timeout")
                        .value_name("SECONDS")
                        .value_parser(clap::value_parser!(u32))
                        .help("UDP flow idle timeout in seconds"),
                ),
        )
        .subcommand(
            Command::new("dns")
                .about("Inspect normalized DNS observations.")
                .arg(
                    Arg::new("capture")
                        .value_name("CAPTURE")
                        .required(true)
                        .index(1)
                        .help("Path to the capture file"),
                )
                .arg(
                    Arg::new("max-records")
                        .long("max-records")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum capture records to process"),
                ),
        )
        .subcommand(
            Command::new("http")
                .about("Inspect cleartext HTTP/1.x message headers.")
                .arg(
                    Arg::new("capture")
                        .value_name("CAPTURE")
                        .required(true)
                        .index(1)
                        .help("Path to the capture file"),
                )
                .arg(
                    Arg::new("max-records")
                        .long("max-records")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum capture records to process"),
                ),
        )
        .subcommand(
            Command::new("tls")
                .about("Inspect visible TLS 1.2 / TLS 1.3 handshake metadata.")
                .arg(
                    Arg::new("capture")
                        .value_name("CAPTURE")
                        .required(true)
                        .index(1)
                        .help("Path to the capture file"),
                )
                .arg(
                    Arg::new("max-records")
                        .long("max-records")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum capture records to process"),
                ),
        )
        .subcommand(
            Command::new("findings")
                .about("Inspect analytical security findings with severity, confidence, and MITRE filtering.")
                .arg(
                    Arg::new("capture")
                        .value_name("CAPTURE")
                        .required(true)
                        .index(1)
                        .help("Path to the capture file"),
                )
                .arg(
                    Arg::new("max-records")
                        .long("max-records")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum capture records to process"),
                )
                .arg(
                    Arg::new("max-flows")
                        .long("max-flows")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum simultaneous active flows to track"),
                )
                .arg(
                    Arg::new("max-flow-instances")
                        .long("max-flow-instances")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum total flow instances across analysis"),
                )
                .arg(
                    Arg::new("max-observations")
                        .long("max-observations")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum protocol observations to retain"),
                )
                .arg(
                    Arg::new("tcp-idle-timeout")
                        .long("tcp-idle-timeout")
                        .value_name("SECONDS")
                        .value_parser(clap::value_parser!(u32))
                        .help("TCP flow idle timeout in seconds"),
                )
                .arg(
                    Arg::new("udp-idle-timeout")
                        .long("udp-idle-timeout")
                        .value_name("SECONDS")
                        .value_parser(clap::value_parser!(u32))
                        .help("UDP flow idle timeout in seconds"),
                )
                .arg(
                    Arg::new("min-severity")
                        .long("min-severity")
                        .value_name("SEVERITY")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Minimum severity threshold (info, low, medium, high, critical)"),
                )
                .arg(
                    Arg::new("min-confidence")
                        .long("min-confidence")
                        .value_name("CONFIDENCE")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Minimum confidence threshold (low, medium, high)"),
                )
                .arg(
                    Arg::new("detector")
                        .long("detector")
                        .value_name("ID")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Filter by detector identifier (e.g. dns.possible_tunneling)"),
                )
                .arg(
                    Arg::new("mitre")
                        .long("mitre")
                        .value_name("TECHNIQUE_ID")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Filter by MITRE ATT&CK technique ID (e.g. T1071.004)"),
                ),
        )
        .subcommand(
            Command::new("analyze")
                .about("Perform full unified capture analysis across all protocol and detection layers.")
                .arg(
                    Arg::new("capture")
                        .value_name("CAPTURE")
                        .required(true)
                        .index(1)
                        .help("Path to the capture file"),
                )
                .arg(
                    Arg::new("max-records")
                        .long("max-records")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum capture records to process"),
                )
                .arg(
                    Arg::new("max-flows")
                        .long("max-flows")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum simultaneous active flows to track"),
                )
                .arg(
                    Arg::new("max-flow-instances")
                        .long("max-flow-instances")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum total flow instances across analysis"),
                )
                .arg(
                    Arg::new("max-observations")
                        .long("max-observations")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Maximum protocol observations to retain"),
                )
                .arg(
                    Arg::new("tcp-idle-timeout")
                        .long("tcp-idle-timeout")
                        .value_name("SECONDS")
                        .value_parser(clap::value_parser!(u32))
                        .help("TCP flow idle timeout in seconds"),
                )
                .arg(
                    Arg::new("udp-idle-timeout")
                        .long("udp-idle-timeout")
                        .value_name("SECONDS")
                        .value_parser(clap::value_parser!(u32))
                        .help("UDP flow idle timeout in seconds"),
                )
                .arg(
                    Arg::new("min-severity")
                        .long("min-severity")
                        .value_name("SEVERITY")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Minimum severity threshold (info, low, medium, high, critical)"),
                )
                .arg(
                    Arg::new("min-confidence")
                        .long("min-confidence")
                        .value_name("CONFIDENCE")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Minimum confidence threshold (low, medium, high)"),
                )
                .arg(
                    Arg::new("detector")
                        .long("detector")
                        .value_name("ID")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Filter by detector identifier (e.g. dns.possible_tunneling)"),
                )
                .arg(
                    Arg::new("mitre")
                        .long("mitre")
                        .value_name("TECHNIQUE_ID")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Filter by MITRE ATT&CK technique ID (e.g. T1071.004)"),
                ),
        )
}

/// Parses command-line arguments into [`CliArgs`].
///
/// # Errors
/// Returns [`clap::Error`] on invalid usage, unknown flags, or when displaying help/version.
pub fn parse_args<I, T>(args: I) -> Result<CliArgs, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let matches = build_cli().try_get_matches_from(args)?;
    let quiet = matches.get_flag("quiet");

    let format_str = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("table");
    let format = match format_str {
        "table" => ReportFormat::Table,
        "json" => ReportFormat::Json,
        "ndjson" => ReportFormat::Ndjson,
        "csv" => ReportFormat::Csv,
        _ => ReportFormat::Table,
    };

    let output = matches.get_one::<String>("output").map(PathBuf::from);

    let command = match matches.subcommand() {
        Some(("validate", sub_m)) => {
            let capture_str = sub_m
                .get_one::<String>("capture")
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument))?;
            let max_records = sub_m.get_one::<u64>("max-records").copied();
            Subcommand::Validate(ValidateArgs {
                capture_path: PathBuf::from(capture_str),
                max_records,
            })
        }
        Some(("flows", sub_m)) => {
            let capture_str = sub_m
                .get_one::<String>("capture")
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument))?;
            let max_records = sub_m.get_one::<u64>("max-records").copied();
            let max_flows = sub_m.get_one::<usize>("max-flows").copied();
            let max_flow_instances = sub_m.get_one::<usize>("max-flow-instances").copied();
            let tcp_idle_timeout = sub_m.get_one::<u32>("tcp-idle-timeout").copied();
            let udp_idle_timeout = sub_m.get_one::<u32>("udp-idle-timeout").copied();
            Subcommand::Flows(FlowsArgs {
                capture_path: PathBuf::from(capture_str),
                max_records,
                max_flows,
                max_flow_instances,
                tcp_idle_timeout,
                udp_idle_timeout,
            })
        }
        Some(("dns", sub_m)) => {
            let capture_str = sub_m
                .get_one::<String>("capture")
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument))?;
            let max_records = sub_m.get_one::<u64>("max-records").copied();
            Subcommand::Dns(DnsArgs {
                capture_path: PathBuf::from(capture_str),
                max_records,
            })
        }
        Some(("http", sub_m)) => {
            let capture_str = sub_m
                .get_one::<String>("capture")
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument))?;
            let max_records = sub_m.get_one::<u64>("max-records").copied();
            Subcommand::Http(HttpArgs {
                capture_path: PathBuf::from(capture_str),
                max_records,
            })
        }
        Some(("tls", sub_m)) => {
            let capture_str = sub_m
                .get_one::<String>("capture")
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument))?;
            let max_records = sub_m.get_one::<u64>("max-records").copied();
            Subcommand::Tls(TlsArgs {
                capture_path: PathBuf::from(capture_str),
                max_records,
            })
        }
        Some(("findings", sub_m)) => {
            let capture_str = sub_m
                .get_one::<String>("capture")
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument))?;
            let max_records = sub_m.get_one::<u64>("max-records").copied();
            let max_flows = sub_m.get_one::<usize>("max-flows").copied();
            let max_flow_instances = sub_m.get_one::<usize>("max-flow-instances").copied();
            let max_observations = sub_m.get_one::<usize>("max-observations").copied();
            let tcp_idle_timeout = sub_m.get_one::<u32>("tcp-idle-timeout").copied();
            let udp_idle_timeout = sub_m.get_one::<u32>("udp-idle-timeout").copied();

            let min_severity = if let Some(s) = sub_m.get_one::<String>("min-severity") {
                Some(s.parse::<Severity>().map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --min-severity '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            let min_confidence = if let Some(s) = sub_m.get_one::<String>("min-confidence") {
                Some(s.parse::<Confidence>().map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --min-confidence '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            let detector_id = if let Some(s) = sub_m.get_one::<String>("detector") {
                Some(DetectorId::try_new(s).map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --detector '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            let mitre_id = if let Some(s) = sub_m.get_one::<String>("mitre") {
                Some(MitreAttackId::try_new(s).map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --mitre '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            Subcommand::Findings(FindingsArgs {
                capture_path: PathBuf::from(capture_str),
                max_records,
                max_flows,
                max_flow_instances,
                max_observations,
                tcp_idle_timeout,
                udp_idle_timeout,
                min_severity,
                min_confidence,
                detector_id,
                mitre_id,
            })
        }
        Some(("analyze", sub_m)) => {
            let capture_str = sub_m
                .get_one::<String>("capture")
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument))?;
            let max_records = sub_m.get_one::<u64>("max-records").copied();
            let max_flows = sub_m.get_one::<usize>("max-flows").copied();
            let max_flow_instances = sub_m.get_one::<usize>("max-flow-instances").copied();
            let max_observations = sub_m.get_one::<usize>("max-observations").copied();
            let tcp_idle_timeout = sub_m.get_one::<u32>("tcp-idle-timeout").copied();
            let udp_idle_timeout = sub_m.get_one::<u32>("udp-idle-timeout").copied();

            let min_severity = if let Some(s) = sub_m.get_one::<String>("min-severity") {
                Some(s.parse::<Severity>().map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --min-severity '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            let min_confidence = if let Some(s) = sub_m.get_one::<String>("min-confidence") {
                Some(s.parse::<Confidence>().map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --min-confidence '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            let detector_id = if let Some(s) = sub_m.get_one::<String>("detector") {
                Some(DetectorId::try_new(s).map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --detector '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            let mitre_id = if let Some(s) = sub_m.get_one::<String>("mitre") {
                Some(MitreAttackId::try_new(s).map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("Invalid --mitre '{s}': {e}\n"),
                    )
                })?)
            } else {
                None
            };

            Subcommand::Analyze(AnalyzeArgs {
                capture_path: PathBuf::from(capture_str),
                max_records,
                max_flows,
                max_flow_instances,
                max_observations,
                tcp_idle_timeout,
                udp_idle_timeout,
                min_severity,
                min_confidence,
                detector_id,
                mitre_id,
            })
        }
        _ => {
            return Err(clap::Error::new(clap::error::ErrorKind::MissingSubcommand));
        }
    };

    Ok(CliArgs {
        quiet,
        format,
        output,
        command,
    })
}
