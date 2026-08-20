//! Format enumerations and schema version constants for reporting.

use std::fmt;
use std::str::FromStr;

/// Canonical schema version string for all structured reports.
pub const REPORT_SCHEMA_VERSION: &str = "v1.0";

/// Output format for rendered reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReportFormat {
    /// Fixed-column human-readable ASCII table.
    Table,
    /// Canonical formatted indented JSON envelope.
    Json,
    /// Newline-delimited JSON streaming records.
    Ndjson,
    /// Comma-separated values with formula injection protection.
    Csv,
}

impl ReportFormat {
    /// Returns the canonical lowercase string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Csv => "csv",
        }
    }
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "ndjson" => Ok(Self::Ndjson),
            "csv" => Ok(Self::Csv),
            other => Err(format!(
                "invalid report format '{other}': expected 'table', 'json', 'ndjson', or 'csv'"
            )),
        }
    }
}

/// Report kind categorizing the payload domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReportKind {
    /// Capture container integrity and metadata validation.
    Validation,
    /// Reconstructed bidirectional network flows.
    Flows,
    /// Normalized DNS observations.
    Dns,
    /// Normalized HTTP/1.x message observations.
    Http,
    /// Normalized TLS 1.2 / TLS 1.3 handshake observations.
    Tls,
    /// Analytical threat-hunting security findings.
    Findings,
    /// Unified analysis combining all inspection layers.
    Analysis,
}

impl ReportKind {
    /// Returns the canonical lowercase string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::Flows => "flows",
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Findings => "findings",
            Self::Analysis => "analysis",
        }
    }
}

impl fmt::Display for ReportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
