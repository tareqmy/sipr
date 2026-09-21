//! Injection files (`-inf`): CSV data driving the `[fieldN]` keyword.
//!
//! Verified against SIPp's `infile.cpp` (docs/SIPP_COMPAT.md §6). The file's
//! first line is a mode token (matched by substring), remaining lines are
//! `;`-separated data rows (`#` comments and blanks skipped). Parsing is pure
//! and testable here; per-call line selection lives in the engine, which owns
//! the sequential counter and RNG.
//!
//! A `PRINTF=<n>` header turns the rows into *templates*: the file then has
//! `n` virtual lines, virtual line `l` reads real line `l % rows`, and every
//! `%d` conversion in a field is filled with `PRINTFOFFSET + l *
//! PRINTFMULTIPLE`.

use std::borrow::Cow;

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
    /// `PRINTF=` header: the rows are templates over virtual lines.
    printf: Option<Printf>,
}

/// The `PRINTF=`/`PRINTFOFFSET=`/`PRINTFMULTIPLE=` header parameters.
#[derive(Debug, Clone, Copy)]
struct Printf {
    /// `PRINTF=<n>`: how many virtual lines the file has.
    lines: usize,
    /// `PRINTFOFFSET=<n>`, added to the substituted number (default 0).
    offset: i64,
    /// `PRINTFMULTIPLE=<n>`, the virtual line's step (default 1).
    multiple: i64,
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
        let printf = parse_printf_header(name, header)?;
        let mut rows: Vec<Vec<String>> = Vec::new();
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
        if let Some(p) = printf {
            for row in &rows {
                for field in row.iter().map(String::as_str) {
                    validate_printf_field(name, field)?;
                }
            }
            if p.lines == 0 {
                return Err(format!(
                    "injection file {name}: a printf file must have at least one virtual line"
                ));
            }
        }
        Ok(Self {
            mode,
            name: name.to_owned(),
            rows,
            index: None,
            printf,
        })
    }

    /// True when the file's rows are `PRINTF=` templates.
    #[must_use]
    pub fn is_printf(&self) -> bool {
        self.printf.is_some()
    }

    /// Number of data lines — the *virtual* count for a `PRINTF=` file, which
    /// is what line selection and `-users` range over (SIPp `numLines`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.printf.map_or(self.rows.len(), |p| p.lines)
    }

    /// True when the file has no data rows (never, post-parse).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The `field`-th value on `line` (both 0-indexed), or `None` when out of
    /// range (SIPp yields an empty string there).
    ///
    /// In a `PRINTF=` file `line` is a virtual line: it selects real line
    /// `line % rows` and every `%d` in the field is filled with
    /// `offset + line * multiple` (SIPp `getField`).
    #[must_use]
    pub fn field(&self, line: usize, field: usize) -> Option<Cow<'_, str>> {
        let Some(p) = self.printf else {
            return self
                .rows
                .get(line)?
                .get(field)
                .map(|v| Cow::Borrowed(v.as_str()));
        };
        if line >= p.lines || self.rows.is_empty() {
            return None;
        }
        let raw = self.rows[line % self.rows.len()].get(field)?;
        #[allow(clippy::cast_possible_wrap)]
        let n = p
            .offset
            .wrapping_add((line as i64).wrapping_mul(p.multiple));
        // `parse` checked every field, so the expansion cannot fail here.
        Some(Cow::Owned(
            expand_printf(raw, n).unwrap_or_else(|_| raw.clone()),
        ))
    }

    /// The index key for `line` — its `field`-th value, or `""` when the field
    /// is missing (SIPp's `getField` yields an empty string, which is indexed).
    fn key_at(&self, line: usize, field: usize) -> String {
        self.field(line, field)
            .map(Cow::into_owned)
            .unwrap_or_default()
    }

    /// Build an index on `field` (SIPp `-infindex FILE FIELD`). Rebuildable;
    /// duplicate keys resolve to the last line, matching SIPp.
    pub fn build_index(&mut self, field: usize) {
        let mut map = std::collections::HashMap::with_capacity(self.len());
        for line in 0..self.len() {
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
    ///
    /// # Errors
    ///
    /// Returns a message for a `PRINTF=` file, whose rows are templates
    /// ("Can not insert or replace into a printf file").
    pub fn insert(&mut self, value: &str) -> Result<(), String> {
        self.reject_printf_mutation()?;
        self.rows
            .push(value.split(';').map(str::to_owned).collect());
        self.reindex(self.rows.len() - 1);
        Ok(())
    }

    /// SIPp's "Can not insert or replace into a printf file".
    fn reject_printf_mutation(&self) -> Result<(), String> {
        if self.printf.is_some() {
            return Err(format!(
                "cannot insert or replace into the printf file {}",
                self.name
            ));
        }
        Ok(())
    }

    /// Replace line `line` (0-based) with a raw `;`-separated `value` (SIPp
    /// `replace`). Re-indexes around the change.
    ///
    /// # Errors
    ///
    /// Returns a message when `line` is past the end of the file, or for a
    /// `PRINTF=` file (SIPp refuses both).
    pub fn replace(&mut self, line: usize, value: &str) -> Result<(), String> {
        self.reject_printf_mutation()?;
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

/// Read the `PRINTF=`/`PRINTFOFFSET=`/`PRINTFMULTIPLE=` parameters out of an
/// injection file's header line (SIPp `infile.cpp`). `None` when the file is
/// not a printf file.
///
/// SIPp finds each parameter with `strstr` over the whole line, which makes
/// `PRINTFOFFSET=` before `PRINTF=` a parse error there (the `PRINTF` match
/// lands inside `PRINTFOFFSET`); sipr splits the header into `,`- and
/// whitespace-separated tokens instead, so the order is free.
fn parse_printf_header(name: &str, header: &str) -> Result<Option<Printf>, String> {
    let mut lines: Option<usize> = None;
    let mut offset = 0i64;
    let mut multiple = 1i64;
    for token in header.split([',', ' ', '\t']) {
        let Some(rest) = token.strip_prefix("PRINTF") else {
            continue;
        };
        if let Some(v) = rest.strip_prefix("OFFSET") {
            offset = parse_printf_value(name, "PRINTFOFFSET", v)?;
        } else if let Some(v) = rest.strip_prefix("MULTIPLE") {
            multiple = parse_printf_value(name, "PRINTFMULTIPLE", v)?;
        } else {
            let n = parse_printf_value(name, "PRINTF", rest)?;
            lines =
                Some(usize::try_from(n).map_err(|_| {
                    format!("injection file {name}: PRINTF={n} is not a line count")
                })?);
        }
    }
    Ok(lines.map(|lines| Printf {
        lines,
        offset,
        multiple,
    }))
}

/// The `=<number>` tail of one printf header parameter. SIPp reads it with
/// `strtoul(…, 0)`, so `0x` is hex and a leading `0` is octal.
fn parse_printf_value(name: &str, what: &str, tail: &str) -> Result<i64, String> {
    let Some(text) = tail.strip_prefix('=') else {
        return Err(format!(
            "injection file {name}: invalid {what} specification (requires =)"
        ));
    };
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (radix, digits) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, hex)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    let magnitude = i64::from_str_radix(digits, radix)
        .map_err(|_| format!("injection file {name}: invalid {what} value '{text}'"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

/// Reject a printf-file field whose `%` conversions SIPp would refuse at
/// render time. sipr checks every field once, at load, so a bad template is a
/// loud start-up error rather than a mid-run one.
fn validate_printf_field(name: &str, field: &str) -> Result<(), String> {
    expand_printf(field, 0)
        .map(|_| ())
        .map_err(|why| format!("injection file {name}: {why}"))
}

/// Fill every `%d` conversion in a printf-file field with `value` (`%%` is a
/// literal `%`; everything else is copied). SIPp's `getField` printf branch.
///
/// # Errors
///
/// A conversion that is not `%[0-9.-]*d`, which SIPp reports as "Invalid
/// printf injection field".
fn expand_printf(field: &str, value: i64) -> Result<String, String> {
    let mut out = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if let Some(tail) = after.strip_prefix('%') {
            out.push('%');
            rest = tail;
            continue;
        }
        let stop = after
            .char_indices()
            .find(|(_, c)| !matches!(c, '0'..='9' | '.' | '-'));
        let Some((end, c)) = stop else {
            return Err(format!(
                "invalid printf injection field (ran off end of line): {field}"
            ));
        };
        if c != 'd' {
            return Err(format!(
                "invalid printf injection field (only decimal values allowed '{c}'): {field}"
            ));
        }
        out.push_str(&format_decimal(&after[..end], value));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// C's `%d` conversion for the flags/width/precision in `spec` — the text
/// between `%` and `d`, which SIPp limits to digits, `.` and `-`.
fn format_decimal(spec: &str, value: i64) -> String {
    let mut rest = spec;
    let mut left = false;
    let mut zero_pad = false;
    while let Some(c) = rest.chars().next() {
        match c {
            '-' => left = true,
            '0' => zero_pad = true,
            _ => break,
        }
        rest = &rest[1..];
    }
    let (width_text, precision_text) = match rest.split_once('.') {
        Some((w, p)) => (w, Some(p)),
        None => (rest, None),
    };
    let width: usize = width_text.parse().unwrap_or(0);
    let precision: Option<usize> = precision_text.map(|p| p.parse().unwrap_or(0));

    let mut digits = value.unsigned_abs().to_string();
    if let Some(p) = precision
        && digits.len() < p
    {
        digits.insert_str(0, &"0".repeat(p - digits.len()));
    }
    let sign = if value < 0 { "-" } else { "" };
    let Some(pad) = width
        .checked_sub(sign.len() + digits.len())
        .filter(|p| *p > 0)
    else {
        return format!("{sign}{digits}");
    };
    if left {
        format!("{sign}{digits}{}", " ".repeat(pad))
    } else if zero_pad && precision.is_none() {
        format!("{sign}{}{digits}", "0".repeat(pad))
    } else {
        format!("{}{sign}{digits}", " ".repeat(pad))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `field` as `Option<&str>`, which is what the assertions read like.
    fn field(f: &InjectionFile, line: usize, index: usize) -> Option<String> {
        f.field(line, index).map(Cow::into_owned)
    }

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
        assert_eq!(field(&f, 0, 0).as_deref(), Some("alice"));
        assert_eq!(field(&f, 0, 1).as_deref(), Some("sip:alice@example.com"));
        assert_eq!(field(&f, 2, 2).as_deref(), Some("1003"));
    }

    #[test]
    fn out_of_range_is_none() {
        let f = InjectionFile::parse("u.csv", SAMPLE).unwrap();
        assert_eq!(field(&f, 0, 9).as_deref(), None, "missing field");
        assert_eq!(field(&f, 9, 0).as_deref(), None, "missing line");
    }

    #[test]
    fn mode_variants_and_crlf() {
        let r = InjectionFile::parse("r", "RANDOM\r\nx;y\r\n").unwrap();
        assert_eq!(r.mode, InjectMode::Random);
        assert_eq!(field(&r, 0, 1).as_deref(), Some("y"));
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
        assert!(InjectionFile::parse("x", "SEQUENTIAL,PRINTF\na\n").is_err()); // no =
        assert!(InjectionFile::parse("x", "SEQUENTIAL,PRINTF=0\na\n").is_err()); // no lines
        assert!(InjectionFile::parse("x", "SEQUENTIAL,PRINTF=x\na\n").is_err()); // not a number
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
        f.insert("b;2").unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(field(&f, 1, 1).as_deref(), Some("2"));
        assert_eq!(f.lookup("b"), Some(1), "new row is indexed");
    }

    #[test]
    fn replace_swaps_row_and_moves_index() {
        let mut f = InjectionFile::parse("u", "SEQUENTIAL\na;1\nb;2\n").unwrap();
        f.build_index(0);
        f.replace(0, "c;9").unwrap();
        assert_eq!(field(&f, 0, 0).as_deref(), Some("c"));
        assert_eq!(f.lookup("c"), Some(0), "new key indexed");
        assert_eq!(f.lookup("a"), None, "old key dropped");
        assert_eq!(f.lookup("b"), Some(1), "untouched key intact");
        assert!(f.replace(9, "z").is_err(), "out of range");
    }

    #[test]
    fn mutation_without_index_is_inert() {
        let mut f = InjectionFile::parse("u", "SEQUENTIAL\na;1\n").unwrap();
        f.insert("b;2").unwrap();
        f.replace(0, "c;3").unwrap();
        assert_eq!(field(&f, 0, 0).as_deref(), Some("c"));
        assert_eq!(field(&f, 1, 0).as_deref(), Some("b"));
        assert_eq!(f.lookup("c"), None, "unindexed lookups always miss");
    }

    // ---- PRINTF= virtual lines (SIPp infile.cpp) ------------------------

    #[test]
    fn printf_file_expands_the_virtual_line_number() {
        let f = InjectionFile::parse(
            "u.csv",
            "SEQUENTIAL,PRINTF=4\nuser%d;sip:user%d@example.com;%04d\n",
        )
        .unwrap();
        assert!(f.is_printf());
        assert_eq!(f.len(), 4, "the file has PRINTF= virtual lines");
        assert_eq!(field(&f, 0, 0).as_deref(), Some("user0"));
        assert_eq!(field(&f, 3, 1).as_deref(), Some("sip:user3@example.com"));
        assert_eq!(
            field(&f, 2, 2).as_deref(),
            Some("0002"),
            "width and zero pad"
        );
        assert_eq!(
            field(&f, 4, 0).as_deref(),
            None,
            "past the last virtual line"
        );
    }

    #[test]
    fn printf_offset_and_multiple_shift_the_number() {
        let f = InjectionFile::parse(
            "u",
            "SEQUENTIAL,PRINTF=3,PRINTFOFFSET=100,PRINTFMULTIPLE=10\n%d\n",
        )
        .unwrap();
        let seen: Vec<_> = (0..f.len()).filter_map(|l| field(&f, l, 0)).collect();
        assert_eq!(seen, ["100", "110", "120"]);
    }

    #[test]
    fn printf_rows_cycle_under_the_virtual_lines() {
        let f = InjectionFile::parse("u", "SEQUENTIAL,PRINTF=5\na%d\nb%d\n").unwrap();
        let seen: Vec<_> = (0..f.len()).filter_map(|l| field(&f, l, 0)).collect();
        assert_eq!(seen, ["a0", "b1", "a2", "b3", "a4"]);
    }

    #[test]
    fn printf_header_order_and_radix() {
        // SIPp's strstr makes this order a parse error; sipr tokenises instead.
        let f = InjectionFile::parse(
            "u",
            "USER,PRINTFOFFSET=1,PRINTF=0x10,PRINTFMULTIPLE=1\n%d\n",
        )
        .unwrap();
        assert_eq!(f.len(), 16, "0x10 is hex, as strtoul(.., 0) reads it");
        assert_eq!(field(&f, 0, 0).as_deref(), Some("1"));
    }

    #[test]
    fn percent_percent_is_a_literal_and_other_text_is_copied() {
        let f = InjectionFile::parse("u", "SEQUENTIAL,PRINTF=2\n100%% of %d\n").unwrap();
        assert_eq!(field(&f, 1, 0).as_deref(), Some("100% of 1"));
    }

    #[test]
    fn malformed_conversions_are_load_errors() {
        // SIPp reports these when the field is read; sipr checks at load.
        let err = InjectionFile::parse("u", "SEQUENTIAL,PRINTF=2\nx%s\n").unwrap_err();
        assert!(err.contains("only decimal values allowed"), "{err}");
        let err = InjectionFile::parse("u", "SEQUENTIAL,PRINTF=2\nx%12\n").unwrap_err();
        assert!(err.contains("ran off end of line"), "{err}");
        // Not a printf file: a stray % is just data.
        let ok = InjectionFile::parse("u", "SEQUENTIAL\nx%s\n").unwrap();
        assert_eq!(field(&ok, 0, 0).as_deref(), Some("x%s"));
    }

    #[test]
    fn printf_files_reject_insert_and_replace() {
        let mut f = InjectionFile::parse("u", "SEQUENTIAL,PRINTF=2\n%d\n").unwrap();
        assert!(f.insert("z").is_err());
        assert!(f.replace(0, "z").is_err());
    }

    #[test]
    fn printf_files_index_over_virtual_lines() {
        let mut f = InjectionFile::parse("u", "SEQUENTIAL,PRINTF=3\nuser%d;x\n").unwrap();
        f.build_index(0);
        assert_eq!(f.lookup("user2"), Some(2));
        assert_eq!(f.lookup("user9"), None);
    }

    #[test]
    fn decimal_conversion_matches_c() {
        assert_eq!(format_decimal("", 7), "7");
        assert_eq!(format_decimal("5", 7), "    7");
        assert_eq!(format_decimal("-5", 7), "7    ");
        assert_eq!(format_decimal("05", 7), "00007");
        assert_eq!(format_decimal("05", -7), "-0007");
        assert_eq!(format_decimal(".3", 7), "007");
        assert_eq!(format_decimal("6.3", 7), "   007");
    }
}
