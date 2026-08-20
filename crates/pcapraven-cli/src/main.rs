//! PcapRaven command-line interface entry point.

mod analysis;
mod app;
mod args;
mod diagnostics;

use std::process::ExitCode;

fn main() -> ExitCode {
    let raw_args = std::env::args_os();
    match args::parse_args(raw_args) {
        Ok(parsed_args) => app::run(parsed_args),
        Err(err) => {
            if err.print().is_err() {
                return ExitCode::from(1);
            }
            match err.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    ExitCode::SUCCESS
                }
                _ => ExitCode::from(2),
            }
        }
    }
}
