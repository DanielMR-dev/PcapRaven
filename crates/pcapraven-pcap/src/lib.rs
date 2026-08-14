//! Bounded, streaming capture-container ingestion for PcapRaven.
//!
//! This crate deliberately stops at the PCAP/PCAPNG container boundary.  It
//! does not interpret Ethernet or any network-layer, transport-layer, or
//! application protocol.

mod reader;

pub use reader::{
    ByteOrder, CaptureCompletion, CaptureDiagnostic, CaptureDiagnosticKind, CaptureDiagnosticStage,
    CaptureFormat, CaptureGlobalMetadata, CaptureInterface, CaptureLocation, CaptureMetadata,
    CaptureReadOutcome, CaptureReader, CaptureReaderError, CaptureReaderErrorKind, CaptureRecord,
    CaptureSection, CaptureTimestamp, CaptureTimestampResolution, CapturedPacket, MalformedCapture,
    ReaderLimit, ReaderLimits, ReaderLimitsBuilder, UnsupportedCapture, read_capture,
};
