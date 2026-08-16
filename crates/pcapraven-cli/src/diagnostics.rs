//! Bounded diagnostic emission and suppression tracking.

use pcapraven_pcap::CaptureDiagnostic;
use std::io::{self, Write};

/// Default maximum number of diagnostic lines emitted to stderr per command.
pub const DEFAULT_DIAGNOSTIC_BUDGET: usize = 100;

/// Bounded diagnostic manager that enforces display budgets and quiet mode.
pub struct DiagnosticEmitter<W: Write = io::Stderr> {
    writer: W,
    quiet: bool,
    budget: usize,
    emitted_count: usize,
    suppressed_count: usize,
    had_io_error: bool,
}

impl DiagnosticEmitter<io::Stderr> {
    /// Creates a new diagnostic emitter using standard error as the output sink.
    #[must_use]
    pub fn new(quiet: bool, budget: usize) -> Self {
        Self {
            writer: io::stderr(),
            quiet,
            budget,
            emitted_count: 0,
            suppressed_count: 0,
            had_io_error: false,
        }
    }

    /// Emits a fatal error message directly to standard error.
    ///
    /// # Errors
    /// Returns [`io::Error`] if writing to standard error fails.
    pub fn emit_fatal_error(message: &str) -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        writeln!(stderr, "error: {message}")
    }
}

impl<W: Write> DiagnosticEmitter<W> {
    /// Creates a new diagnostic emitter with a custom writer.
    #[cfg(test)]
    #[must_use]
    pub const fn with_writer(writer: W, quiet: bool, budget: usize) -> Self {
        Self {
            writer,
            quiet,
            budget,
            emitted_count: 0,
            suppressed_count: 0,
            had_io_error: false,
        }
    }

    /// Returns `true` if any diagnostic write operation experienced an I/O error.
    #[must_use]
    pub const fn had_io_error(&self) -> bool {
        self.had_io_error
    }

    /// Emits a single nonfatal diagnostic line if quiet is false and budget allows.
    ///
    /// # Errors
    /// Returns [`io::Error`] if writing to the underlying output sink fails.
    pub fn emit_diagnostic(&mut self, message: &str) -> io::Result<()> {
        if self.quiet {
            return Ok(());
        }
        if self.emitted_count < self.budget {
            if let Err(err) = writeln!(self.writer, "diagnostic: {message}") {
                self.had_io_error = true;
                return Err(err);
            }
            self.emitted_count = self.emitted_count.saturating_add(1);
        } else {
            self.suppressed_count = self.suppressed_count.saturating_add(1);
        }
        Ok(())
    }

    /// Emits a structured capture reader diagnostic.
    ///
    /// # Errors
    /// Returns [`io::Error`] if writing to the underlying output sink fails.
    pub fn emit_capture_diagnostic(&mut self, diagnostic: &CaptureDiagnostic) -> io::Result<()> {
        if self.quiet {
            return Ok(());
        }
        let msg = format!(
            "[{:?}] {} at byte {}",
            diagnostic.kind, diagnostic.message, diagnostic.location.offset
        );
        self.emit_diagnostic(&msg)
    }

    /// Emits a fatal error message directly to the emitter's writer.
    ///
    /// # Errors
    /// Returns [`io::Error`] if writing to the underlying output sink fails.
    #[cfg(test)]
    pub fn emit_fatal(&mut self, message: &str) -> io::Result<()> {
        if let Err(err) = writeln!(self.writer, "error: {message}") {
            self.had_io_error = true;
            return Err(err);
        }
        Ok(())
    }

    /// Finishes diagnostic emission, outputting a suppression summary if any messages were dropped.
    ///
    /// # Errors
    /// Returns [`io::Error`] if writing the suppression summary fails.
    pub fn finish(&mut self) -> io::Result<()> {
        if !self.quiet && self.suppressed_count > 0 {
            if let Err(err) = writeln!(
                self.writer,
                "warning: suppressed {} additional diagnostic messages (budget: {})",
                self.suppressed_count, self.budget
            ) {
                self.had_io_error = true;
                return Err(err);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcapraven_pcap::{CaptureDiagnosticKind, CaptureLocation};
    use std::io;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
        }
    }

    #[test]
    fn test_diagnostic_emitter_propagates_io_error() {
        let mut emitter = DiagnosticEmitter::with_writer(FailingWriter, false, 10);
        let res = emitter.emit_diagnostic("test message");
        assert!(res.is_err());
        assert!(emitter.had_io_error());
    }

    #[test]
    fn test_diagnostic_emitter_fatal_propagates_io_error() {
        let mut emitter = DiagnosticEmitter::with_writer(FailingWriter, false, 10);
        let res = emitter.emit_fatal("fatal error");
        assert!(res.is_err());
        assert!(emitter.had_io_error());
    }

    #[test]
    fn test_diagnostic_emitter_finish_propagates_io_error() {
        let mut buffer = Vec::new();
        let mut emitter = DiagnosticEmitter::with_writer(&mut buffer, false, 1);
        assert!(emitter.emit_diagnostic("msg 1").is_ok());
        assert!(emitter.emit_diagnostic("msg 2").is_ok()); // suppressed
        assert_eq!(emitter.suppressed_count, 1);

        let mut failing_emitter = DiagnosticEmitter::with_writer(FailingWriter, false, 0);
        assert!(failing_emitter.emit_diagnostic("msg 1").is_ok()); // suppressed (budget 0)
        let finish_res = failing_emitter.finish();
        assert!(finish_res.is_err());
        assert!(failing_emitter.had_io_error());
    }

    #[test]
    fn test_diagnostic_emitter_quiet_mode() {
        use pcapraven_pcap::CaptureDiagnosticStage;

        let mut buffer = Vec::new();
        {
            let mut emitter = DiagnosticEmitter::with_writer(&mut buffer, true, 10);
            assert!(emitter.emit_diagnostic("silent message").is_ok());
            let diag = CaptureDiagnostic {
                kind: CaptureDiagnosticKind::Malformed,
                stage: CaptureDiagnosticStage::Block,
                location: CaptureLocation {
                    offset: 42,
                    section_ordinal: None,
                    interface_ordinal: None,
                    block_type: None,
                    packet_ordinal: None,
                },
                message: "corrupt block",
                recovered: false,
            };
            assert!(emitter.emit_capture_diagnostic(&diag).is_ok());
            assert!(emitter.finish().is_ok());
            assert!(!emitter.had_io_error());
        }
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_diagnostic_emitter_budget_and_suppression() {
        let mut buffer = Vec::new();
        {
            let mut emitter = DiagnosticEmitter::with_writer(&mut buffer, false, 2);
            assert!(emitter.emit_diagnostic("msg 1").is_ok());
            assert!(emitter.emit_diagnostic("msg 2").is_ok());
            assert!(emitter.emit_diagnostic("msg 3").is_ok());
            assert!(emitter.emit_diagnostic("msg 4").is_ok());
            assert!(emitter.finish().is_ok());
        }
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("diagnostic: msg 1\n"));
        assert!(output.contains("diagnostic: msg 2\n"));
        assert!(!output.contains("diagnostic: msg 3\n"));
        assert!(
            output.contains("warning: suppressed 2 additional diagnostic messages (budget: 2)\n")
        );
    }
}
