//! Error models for reporting and serialization.

use std::fmt;
use std::io;

use crate::{ReportFormat, ReportKind};

/// Errors encountered during report formatting or serialization.
#[derive(Debug)]
pub enum ReportError {
    /// Underlying I/O error while writing to the output stream.
    Io(io::Error),
    /// Serialization error from JSON, CSV, or formatting engines.
    Serialization(String),
    /// An unsupported format combination (e.g. CSV for hierarchical Analysis report).
    UnsupportedFormat {
        /// Requested report format.
        format: ReportFormat,
        /// Requested report kind.
        kind: ReportKind,
        /// Clear explanation why this combination is unsupported.
        rationale: &'static str,
    },
    /// Invalid domain or configuration data passed to the reporter.
    InvalidData(String),
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error during report generation: {err}"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
            Self::UnsupportedFormat {
                format,
                kind,
                rationale,
            } => write!(
                f,
                "unsupported report format '{format}' for {kind} report: {rationale}"
            ),
            Self::InvalidData(msg) => write!(f, "invalid report data: {msg}"),
        }
    }
}

impl std::error::Error for ReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ReportError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
