//! Command-line argument parsing and configuration types.

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;

/// Parsed top-level command-line configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgs {
    /// Whether to suppress nonfatal diagnostic messages on stderr.
    pub quiet: bool,
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
        _ => {
            return Err(clap::Error::new(clap::error::ErrorKind::MissingSubcommand));
        }
    };

    Ok(CliArgs { quiet, command })
}
