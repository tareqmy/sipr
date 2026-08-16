//! End-to-end CLI tests for the M0 scaffold. Dependency-free: uses the
//! `CARGO_BIN_EXE_sipr` path cargo provides to integration tests.

// Test code may unwrap/expect freely (docs/CONVENTIONS.md §Errors); clippy's
// `*-in-tests` exemptions only cover `#[test]` fns, not integration-test helpers.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Output};

fn sipr(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sipr"))
        .args(args)
        .output()
        .expect("failed to spawn sipr")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[track_caller]
fn assert_code(o: &Output, want: i32) {
    assert_eq!(
        o.status.code(),
        Some(want),
        "stdout:\n{}\nstderr:\n{}",
        stdout(o),
        stderr(o)
    );
}

#[test]
fn sd_dumps_embedded_uac_scenario() {
    let o = sipr(&["-sd", "uac"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("<scenario name=\"Basic Sipstone UAC\">"));
    assert!(out.contains("INVITE sip:[service]@[remote_ip]"));
}

#[test]
fn sd_dumps_embedded_uas_scenario() {
    let o = sipr(&["-sd", "uas"]);
    assert_code(&o, 0);
    assert!(stdout(&o).contains("<recv request=\"INVITE\""));
}

#[test]
fn sd_unknown_scenario_fails() {
    let o = sipr(&["-sd", "nope"]);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(err.contains("unknown embedded scenario 'nope'"), "{err}");
    assert!(err.contains("uac, uas"), "{err}");
}

#[test]
fn uac_without_target_fails() {
    let o = sipr(&["-sn", "uac"]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("remote target required"));
}

#[test]
fn default_scenario_is_uac_and_needs_target() {
    let o = sipr(&[]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("remote target required"));
}

#[test]
fn uas_without_target_reaches_engine_stub() {
    let o = sipr(&["-sn", "uas", "-p", "5060"]);
    assert_code(&o, 99);
    assert!(stderr(&o).contains("not implemented yet"));
}

#[test]
fn uac_with_target_reaches_engine_stub() {
    let o = sipr(&["-sn", "uac", "-r", "50", "127.0.0.1:5060"]);
    assert_code(&o, 99);
    assert!(stderr(&o).contains("scenario 'uac' accepted"));
}

#[test]
fn unknown_long_flag_errors_with_suggestion() {
    let o = sipr(&["-trace_mgs"]);
    assert_code(&o, 2);
    assert!(stderr(&o).contains("did you mean '-trace_msg'"));
}

#[test]
fn missing_scenario_file_fails() {
    let o = sipr(&["-sf", "/definitely/not/here.xml", "127.0.0.1"]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("scenario file not found"));
}

#[test]
fn version_flag_works_sipp_style() {
    let o = sipr(&["-v"]);
    assert_code(&o, 0);
    assert!(stdout(&o).starts_with("sipr "));
}

#[test]
fn help_mentions_sipp_flag_convention() {
    let o = sipr(&["-h"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("single-dash names"), "{out}");
    assert!(out.contains("-trace_stat"), "{out}");
}
