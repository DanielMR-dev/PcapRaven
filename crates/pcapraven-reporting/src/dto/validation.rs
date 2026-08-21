//! Serializable DTOs for capture container validation reports.

use serde::Serialize;

use crate::format::REPORT_SCHEMA_VERSION;

/// Root envelope for a capture validation report in JSON / NDJSON.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationReportDto {
    /// Schema version anchor.
    pub schema_version: &'static str,
    /// Report kind identifier ("validation").
    pub kind: &'static str,
    /// File path or source identifier if provided.
    pub source_path: Option<String>,
    /// High-level format and container metadata.
    pub metadata: ValidationMetadataDto,
    /// Summary of records emitted and diagnostics observed.
    pub summary: ValidationSummaryDto,
    /// Detailed capture container diagnostics.
    pub diagnostics: Vec<ValidationDiagnosticDto>,
    /// Terminal completion state.
    pub completion: ValidationCompletionDto,
}

impl Default for ValidationReportDto {
    fn default() -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "validation",
            source_path: None,
            metadata: ValidationMetadataDto::default(),
            summary: ValidationSummaryDto::default(),
            diagnostics: Vec::new(),
            completion: ValidationCompletionDto::default(),
        }
    }
}

/// Metadata describing the capture container format.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ValidationMetadataDto {
    /// Container format name (e.g. "pcap", "pcapng", "unknown").
    pub format: String,
    /// Byte order ("little_endian", "big_endian", or "unknown").
    pub byte_order: String,
    /// Major format version if known.
    pub version_major: Option<u16>,
    /// Minor format version if known.
    pub version_minor: Option<u16>,
    /// Default link type if legacy PCAP.
    pub linktype: Option<u32>,
    /// Snapshot length if legacy PCAP.
    pub snaplen: Option<u32>,
    /// Formatted timestamp resolution if known.
    pub timestamp_resolution: Option<String>,
    /// Total PCAPNG sections if PCAPNG as a decimal string.
    pub section_count: Option<String>,
    /// Total PCAPNG interfaces if PCAPNG as a decimal string.
    pub interface_count: Option<String>,
    /// Usable interfaces count if PCAPNG as a decimal string.
    pub usable_interfaces: Option<String>,
    /// Unusable (malformed) interfaces count if PCAPNG as a decimal string.
    pub unusable_interfaces: Option<String>,
}

/// Record counters and summary facts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ValidationSummaryDto {
    /// Total packet records emitted as a decimal string.
    pub records_emitted: String,
    /// Total diagnostics recorded as a decimal string.
    pub total_diagnostics: String,
    /// Whether any diagnostic was recorded.
    pub had_diagnostics: bool,
}

/// A diagnostic emitted during capture container reading.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationDiagnosticDto {
    /// Zero-based diagnostic index as a decimal string.
    pub index: String,
    /// Processing stage where diagnostic occurred.
    pub stage: String,
    /// Categorical kind.
    pub kind: String,
    /// Plaintext diagnostic message.
    pub message: String,
    /// Absolute byte offset in capture file if known as a decimal string.
    pub byte_offset: Option<String>,
}

/// Completion state of the capture read.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ValidationCompletionDto {
    /// Status string: "complete", "partial", or "failed".
    pub status: String,
    /// Whether reading finished completely without degradation.
    pub is_complete: bool,
    /// Terminal error message if reading stopped before clean end.
    pub terminal_error: Option<String>,
}
