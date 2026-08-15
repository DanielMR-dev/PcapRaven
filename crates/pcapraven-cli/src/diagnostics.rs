//! Bounded diagnostic emission and suppression tracking.

use pcapraven_pcap::CaptureDiagnostic;
use std::io::{self, Write};

/// Default maximum number of diagnostic lines emitted to stderr per command.
pub const DEFAULT_DIAGNOSTIC_BUDGET: usize = 100;

/// Bounded diagnostic manager that enforces display budgets and quiet mode.
pub struct DiagnosticEmitter {
    quiet: bool,
    budget: usize,
    emitted_count: usize,
    suppressed_count: usize,
}

impl DiagnosticEmitter {
    /// Creates a new diagnostic emitter with the specified quiet mode and budget.
    #[must_use]
    pub const fn new(quiet: bool, budget: usize) -> Self {
        Self {
            quiet,
            budget,
            emitted_count: 0,
            suppressed_count: 0,
        }
    }

    /// Emits a single nonfatal diagnostic line if quiet is false and budget allows.
    pub fn emit_diagnostic(&mut self, message: &str) {
        if self.quiet {
            return;
        }
        if self.emitted_count < self.budget {
            let _ = writeln!(io::stderr(), "diagnostic: {message}");
            self.emitted_count = self.emitted_count.saturating_add(1);
        } else {
            self.suppressed_count = self.suppressed_count.saturating_add(1);
        }
    }

    /// Emits a structured capture reader diagnostic.
    pub fn emit_capture_diagnostic(&mut self, diagnostic: &CaptureDiagnostic) {
        if self.quiet {
            return;
        }
        let msg = format!(
            "[{:?}] {} at byte {}",
            diagnostic.kind, diagnostic.message, diagnostic.location.offset
        );
        self.emit_diagnostic(&msg);
    }

    /// Emits a fatal error message directly to stderr regardless of quiet mode.
    pub fn emit_fatal_error(message: &str) {
        let _ = writeln!(io::stderr(), "error: {message}");
    }

    /// Finishes diagnostic emission, outputting a suppression summary if any messages were dropped.
    pub fn finish(&self) {
        if !self.quiet && self.suppressed_count > 0 {
            let _ = writeln!(
                io::stderr(),
                "warning: suppressed {} additional diagnostic messages (budget: {})",
                self.suppressed_count,
                self.budget
            );
        }
    }
}
