//! Golden corpus runner (docs/TESTING.md §2).
//!
//! `tests/corpus/positive/*.xml` must compile with zero diagnostics — not
//! even warnings, lints included — so the corpus stays an example of clean
//! scenario style.
//! `tests/corpus/negative/*.xml` must FAIL, and the first line of each file
//! carries `<!-- expect: substring -->` that must appear in an error message.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use sipr_scenario::diag::Severity;
use sipr_scenario::{CompileOptions, compile, compile_with};

fn corpus_dir(kind: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(kind)
}

fn xml_files(kind: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(corpus_dir(kind))
        .expect("corpus dir exists")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "xml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "empty corpus: {kind}");
    files
}

#[test]
fn positive_corpus_compiles_without_diagnostics() {
    for path in xml_files("positive") {
        let name = path.display().to_string();
        let text = fs::read_to_string(&path).expect("readable");
        let lint = CompileOptions {
            lint: true,
            ..CompileOptions::default()
        };
        let out = compile_with(&name, &text, &lint);
        assert!(
            out.diagnostics.is_empty(),
            "{name}: expected clean compile, got: {:#?}",
            out.diagnostics
        );
        assert!(out.scenario.is_some(), "{name}: no scenario produced");
    }
}

#[test]
fn negative_corpus_fails_with_expected_errors() {
    for path in xml_files("negative") {
        let name = path.display().to_string();
        let text = fs::read_to_string(&path).expect("readable");
        let expect = text
            .lines()
            .next()
            .and_then(|l| l.split("expect:").nth(1))
            .map(|s| s.trim_end_matches("-->").trim().to_owned())
            .unwrap_or_else(|| panic!("{name}: first line must be '<!-- expect: ... -->'"));
        let out = compile(&name, &text);
        assert!(out.scenario.is_none(), "{name}: unexpectedly compiled");
        let errors: Vec<String> = out
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(ToString::to_string)
            .collect();
        assert!(
            errors.iter().any(|e| e.contains(&expect)),
            "{name}: no error containing '{expect}' in {errors:#?}"
        );
    }
}
