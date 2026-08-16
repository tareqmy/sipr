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
    /// Display name (the CLI basename SIPp keys `inFiles` by).
    pub name: String,
    /// Rows, each already split into fields on `;`.
    rows: Vec<Vec<String>>,
    /// Optional `-infindex` index (field number + key→line map). SIPp keeps the
    /// last line for each duplicate key; we do too (`HashMap::insert`).
    index: Option<InjectIndex>,
}

/// A `-infindex` index over one field of an injection file.
#[derive(Debug, Clone)]
struct InjectIndex {
    /// The 0-based field the key is drawn from.
    field: usize,
    /// key → line number (last writer wins, matching SIPp's `reIndex`).
    map: std::collections::HashMap<String, usize>,
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
            index: None,
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

    /// The index key for `line` — its `field`-th value, or `""` when the field
    /// is missing (SIPp's `getField` yields an empty string, which is indexed).
    fn key_at(&self, line: usize, field: usize) -> String {
        self.rows
            .get(line)
            .and_then(|r| r.get(field))
            .cloned()
            .unwrap_or_default()
    }

    /// Build an index on `field` (SIPp `-infindex FILE FIELD`). Rebuildable;
    /// duplicate keys resolve to the last line, matching SIPp.
    pub fn build_index(&mut self, field: usize) {
        let mut map = std::collections::HashMap::with_capacity(self.rows.len());
        for line in 0..self.rows.len() {
            map.insert(self.key_at(line, field), line);
        }
        self.index = Some(InjectIndex { field, map });
    }

    /// Whether `-infindex` has been applied to this file.
    #[must_use]
    pub fn is_indexed(&self) -> bool {
        self.index.is_some()
    }

    /// Look up the line number whose indexed field equals `key`. `None` on a
    /// miss (SIPp's `lookup` returns -1). Callers must check [`Self::is_indexed`]
    /// first — SIPp errors when looking up an unindexed file.
    #[must_use]
    pub fn lookup(&self, key: &str) -> Option<usize> {
        self.index.as_ref()?.map.get(key).copied()
    }

    /// Append a data row from a raw `;`-separated line (SIPp `insert`). Splits
    /// like [`Self::parse`] and reindexes the new line when indexed.
    pub fn insert(&mut self, value: &str) {
        self.rows
            .push(value.split(';').map(str::to_owned).collect());
        self.reindex(self.rows.len() - 1);
    }

    /// Replace line `line` (0-based) with a raw `;`-separated `value` (SIPp
    /// `replace`). Re-indexes around the change.
    ///
    /// # Errors
    ///
    /// Returns a message when `line` is past the end of the file.
    pub fn replace(&mut self, line: usize, value: &str) -> Result<(), String> {
        if line >= self.rows.len() {
            return Err(format!(
                "injection file {}: replace line {line} out of range ({} lines)",
                self.name,
                self.rows.len()
            ));
        }
        self.deindex(line);
        self.rows[line] = value.split(';').map(str::to_owned).collect();
        self.reindex(line);
        Ok(())
    }

    /// (Re)point the index entry for `line` at `line`. No-op when unindexed.
    fn reindex(&mut self, line: usize) {
        let Some(field) = self.index.as_ref().map(|i| i.field) else {
            return;
        };
        let key = self.key_at(line, field);
        if let Some(idx) = self.index.as_mut() {
            idx.map.insert(key, line);
        }
    }

    /// Drop `line`'s index entry, but only if it still maps to `line` (SIPp's
    /// `deIndex` guards against clobbering a duplicate key's later winner).
    fn deindex(&mut self, line: usize) {
        let Some(field) = self.index.as_ref().map(|i| i.field) else {
            return;
        };
        let key = self.key_at(line, field);
        if let Some(idx) = self.index.as_mut()
            && idx.map.get(&key) == Some(&line)
        {
            idx.map.remove(&key);
        }
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

    #[test]
    fn index_and_lookup_last_key_wins() {
        let mut f = InjectionFile::parse("u.csv", SAMPLE).unwrap();
        assert!(!f.is_indexed());
        assert_eq!(f.lookup("alice"), None, "no index yet");
        f.build_index(0);
        assert!(f.is_indexed());
        assert_eq!(f.lookup("alice"), Some(0));
        assert_eq!(f.lookup("carol"), Some(2));
        assert_eq!(f.lookup("nobody"), None, "miss");

        // Duplicate keys: the later line wins, matching SIPp's reIndex.
        let mut d = InjectionFile::parse("d", "SEQUENTIAL\nk;v1\nk;v2\n").unwrap();
        d.build_index(0);
        assert_eq!(d.lookup("k"), Some(1));
    }

    #[test]
    fn insert_appends_and_reindexes() {
        let mut f = InjectionFile::parse("u", "SEQUENTIAL\na;1\n").unwrap();
        f.build_index(0);
        f.insert("b;2");
        assert_eq!(f.len(), 2);
        assert_eq!(f.field(1, 1), Some("2"));
        assert_eq!(f.lookup("b"), Some(1), "new row is indexed");
    }

    #[test]
    fn replace_swaps_row_and_moves_index() {
        let mut f = InjectionFile::parse("u", "SEQUENTIAL\na;1\nb;2\n").unwrap();
        f.build_index(0);
        f.replace(0, "c;9").unwrap();
        assert_eq!(f.field(0, 0), Some("c"));
        assert_eq!(f.lookup("c"), Some(0), "new key indexed");
        assert_eq!(f.lookup("a"), None, "old key dropped");
        assert_eq!(f.lookup("b"), Some(1), "untouched key intact");
        assert!(f.replace(9, "z").is_err(), "out of range");
    }

    #[test]
    fn mutation_without_index_is_inert() {
        let mut f = InjectionFile::parse("u", "SEQUENTIAL\na;1\n").unwrap();
        f.insert("b;2");
        f.replace(0, "c;3").unwrap();
        assert_eq!(f.field(0, 0), Some("c"));
        assert_eq!(f.field(1, 0), Some("b"));
        assert_eq!(f.lookup("c"), None, "unindexed lookups always miss");
    }
}
