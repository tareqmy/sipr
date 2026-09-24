//! Diagnostics: warnings and errors with source position context.
//!
//! Rule zero of `docs/SIPP_COMPAT.md`: anything we do not implement fails
//! loudly with file:line context — never a silent skip.

use std::fmt;

use crate::lint::Lint;

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
    /// The lint that raised this warning, when a `--check` lint did.
    pub lint: Option<Lint>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        // `warning[unreachable]`: the name to put in `sipr-lint: allow`.
        let kind = match self.lint {
            Some(lint) => format!("{severity}[{}]", lint.name()),
            None => severity.to_owned(),
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

    /// Record a warning about one place in the source, which a repeat
    /// elsewhere does not make redundant: not deduplicated.
    pub fn warn_at(&mut self, line: u32, message: impl Into<String>) {
        self.push_each(line, message.into(), None);
    }

    /// Record a lint finding: a warning tagged with the lint's name. Not
    /// deduplicated — each finding belongs to its own step.
    pub fn lint(&mut self, lint: Lint, line: u32, message: impl Into<String>) {
        self.push_each(line, message.into(), Some(lint));
    }

    fn push_each(&mut self, line: u32, message: String, lint: Option<Lint>) {
        self.items.push(Diagnostic {
            severity: Severity::Warning,
            source: self.source.clone(),
            line: Some(line),
            message,
            lint,
        });
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
            lint: None,
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
