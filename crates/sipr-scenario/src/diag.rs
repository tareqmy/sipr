//! Diagnostics: warnings and errors with source position context.
//!
//! Rule zero of `docs/SIPP_COMPAT.md`: anything we do not implement fails
//! loudly with file:line context — never a silent skip.

use std::fmt;

/// How bad a diagnostic is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The scenario compiles, but something deserves attention.
    Warning,
    /// The scenario cannot be used.
    Error,
}

/// One warning or error, tied to a source position where possible.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Warning or error.
    pub severity: Severity,
    /// Name of the source (file path or `-sn` name).
    pub source: String,
    /// 1-based line in the source, when known.
    pub line: Option<u32>,
    /// Human-readable message.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        match self.line {
            Some(line) => write!(f, "{}:{line}: {kind}: {}", self.source, self.message),
            None => write!(f, "{}: {kind}: {}", self.source, self.message),
        }
    }
}

/// Collects diagnostics during parsing/compilation.
#[derive(Debug, Default)]
pub struct Diagnostics {
    items: Vec<Diagnostic>,
    source: String,
}

impl Diagnostics {
    /// New collector for a named source (file path or embedded name).
    #[must_use]
    pub fn new(source: &str) -> Self {
        Self {
            items: Vec::new(),
            source: source.to_owned(),
        }
    }

    /// Record a warning at `line`.
    pub fn warn(&mut self, line: Option<u32>, message: impl Into<String>) {
        self.push(Severity::Warning, line, message.into());
    }

    /// Record an error at `line`.
    pub fn error(&mut self, line: Option<u32>, message: impl Into<String>) {
        self.push(Severity::Error, line, message.into());
    }

    fn push(&mut self, severity: Severity, line: Option<u32>, message: String) {
        // Dedupe exact repeats (e.g. the same unknown keyword in ten steps).
        if self
            .items
            .iter()
            .any(|d| d.message == message && d.severity == severity)
        {
            return;
        }
        self.items.push(Diagnostic {
            severity,
            source: self.source.clone(),
            line,
            message,
        });
    }

    /// True if any error was recorded.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity == Severity::Error)
    }

    /// All recorded diagnostics, in order.
    #[must_use]
    pub fn items(&self) -> &[Diagnostic] {
        &self.items
    }

    /// Consume the collector, returning the diagnostics.
    #[must_use]
    pub fn into_items(self) -> Vec<Diagnostic> {
        self.items
    }
}
