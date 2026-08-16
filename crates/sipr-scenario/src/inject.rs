//! Injection files (`-inf`): CSV data driving the `[fieldN]` keyword.
//!
//! Verified against SIPp's `infile.cpp` (docs/SIPP_COMPAT.md §6). The file's
//! first line is a mode token (matched by substring), remaining lines are
//! `;`-separated data rows (`#` comments and blanks skipped). Parsing is pure
//! and testable here; per-call line selection lives in the engine, which owns
//! the sequential counter and RNG.

/// How each new call picks a line from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectMode {
    /// Next line in order, wrapping (a shared per-file counter).
    Sequential,
    /// A uniformly random line.
    Random,
    /// Line = userId-1; needs `-users`, otherwise no injection.
    User,
}

/// A parsed injection file: mode plus pre-split rows.
#[derive(Debug, Clone)]
pub struct InjectionFile {
    /// Selection mode from the header line.
    pub mode: InjectMode,
    /// Display name (the path as given on the CLI).
    pub name: String,
    /// Rows, each already split into fields on `;`.
    rows: Vec<Vec<String>>,
}

impl InjectionFile {
    /// Parse an injection file's text. `name` labels diagnostics.
    ///
    /// # Errors
    ///
    /// Returns a message when the mode header is missing/unknown or the file
    /// has no data rows.
    pub fn parse(name: &str, text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        let header = lines
            .next()
            .ok_or_else(|| format!("injection file {name} is empty"))?;
        // SIPp matches the mode by substring on the first line.
        let mode = if header.contains("RANDOM") {
            InjectMode::Random
        } else if header.contains("SEQUENTIAL") {
            InjectMode::Sequential
        } else if header.contains("USER") {
            InjectMode::User
        } else {
            return Err(format!(
                "injection file {name}: first line must contain SEQUENTIAL, \
                 RANDOM, or USER (got '{header}')"
            ));
        };
        if header.contains("PRINTF") {
            return Err(format!(
                "injection file {name}: PRINTF virtual-line files are not supported yet"
            ));
        }
        let mut rows = Vec::new();
        for line in lines {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                break; // a blank line ends the file (SIPp behavior)
            }
            if line.starts_with('#') {
                continue; // comment
            }
            rows.push(line.split(';').map(str::to_owned).collect());
        }
        if rows.is_empty() {
            return Err(format!("injection file {name} has no data lines"));
        }
        Ok(Self {
            mode,
            name: name.to_owned(),
            rows,
        })
    }

    /// Number of data lines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when the file has no data rows (never, post-parse).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The `field`-th value on `line` (both 0-indexed), or `None` when out of
    /// range (SIPp yields an empty string there).
    #[must_use]
    pub fn field(&self, line: usize, field: usize) -> Option<&str> {
        self.rows.get(line)?.get(field).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "SEQUENTIAL\n\
        # a comment\n\
        alice;sip:alice@example.com;1001\n\
        bob;sip:bob@example.com;1002\n\
        carol;sip:carol@example.com;1003\n";

    #[test]
    fn parses_mode_and_rows_skipping_comments() {
        let f = InjectionFile::parse("users.csv", SAMPLE).unwrap();
        assert_eq!(f.mode, InjectMode::Sequential);
        assert_eq!(f.len(), 3);
        assert_eq!(f.field(0, 0), Some("alice"));
        assert_eq!(f.field(0, 1), Some("sip:alice@example.com"));
        assert_eq!(f.field(2, 2), Some("1003"));
    }

    #[test]
    fn out_of_range_is_none() {
        let f = InjectionFile::parse("u.csv", SAMPLE).unwrap();
        assert_eq!(f.field(0, 9), None, "missing field");
        assert_eq!(f.field(9, 0), None, "missing line");
    }

    #[test]
    fn mode_variants_and_crlf() {
        let r = InjectionFile::parse("r", "RANDOM\r\nx;y\r\n").unwrap();
        assert_eq!(r.mode, InjectMode::Random);
        assert_eq!(r.field(0, 1), Some("y"));
        let u = InjectionFile::parse("u", "USER\na\n").unwrap();
        assert_eq!(u.mode, InjectMode::User);
    }

    #[test]
    fn blank_line_ends_file() {
        let f = InjectionFile::parse("x", "SEQUENTIAL\na\nb\n\nc\n").unwrap();
        assert_eq!(f.len(), 2, "row after the blank line is dropped");
    }

    #[test]
    fn errors_are_clear() {
        assert!(InjectionFile::parse("x", "").is_err());
        assert!(InjectionFile::parse("x", "NONSENSE\na\n").is_err());
        assert!(InjectionFile::parse("x", "SEQUENTIAL\n").is_err()); // no rows
        assert!(InjectionFile::parse("x", "SEQUENTIAL PRINTF=5\na\n").is_err());
    }
}
