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
fn uas_runs_and_exits_99_when_no_calls_arrive() {
    let o = sipr(&["-sn", "uas", "-timeout", "1"]);
    assert_code(&o, 99); // listened, processed nothing
    let err = stderr(&o);
    assert!(err.contains("answering calls"), "{err}");
}

#[test]
fn unresolvable_target_is_fatal() {
    let o = sipr(&["-sn", "uac", "definitely-not-a-real-host.invalid."]);
    assert_code(&o, 255);
    assert!(
        stderr(&o).contains("cannot resolve target"),
        "{}",
        stderr(&o)
    );
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
    assert!(stderr(&o).contains("cannot read scenario file"));
}

#[test]
fn version_flag_works_sipp_style() {
    let o = sipr(&["-v"]);
    assert_code(&o, 0);
    assert!(stdout(&o).starts_with("sipr "));
}

/// Write a throwaway scenario file; removed on drop.
struct TempScenario {
    path: std::path::PathBuf,
}

impl TempScenario {
    fn new(name: &str, content: &str) -> Self {
        let path = std::env::temp_dir().join(format!("sipr-test-{}-{name}", std::process::id()));
        std::fs::write(&path, content).expect("write temp scenario");
        Self { path }
    }

    fn path(&self) -> &str {
        self.path.to_str().expect("utf8 temp path")
    }
}

impl Drop for TempScenario {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn check_mode_dumps_ir_for_clean_scenario() {
    let o = sipr(&["-sn", "uac", "--check"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("role=UAC"), "{out}");
    assert!(out.contains("send retrans=500ms"), "{out}");
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

#[test]
fn check_mode_fails_on_warnings_or_errors() {
    let bad = TempScenario::new(
        "bad.xml",
        r#"<scenario name="b">
             <send tyop="1"><![CDATA[
               INVITE sip:[service]@[remote_ip] SIP/2.0
               Call-ID: [call_id]
             ]]></send>
             <recv response="200" next="nowhere"/>
           </scenario>"#,
    );
    let o = sipr(&["-sf", bad.path(), "--check"]);
    assert_code(&o, 1);
    let err = stderr(&o);
    assert!(err.contains("unknown attribute 'tyop'"), "{err}");
    assert!(err.contains("undefined label 'nowhere'"), "{err}");
}

#[test]
fn sf_uas_scenario_needs_no_target() {
    let uas = TempScenario::new(
        "uas.xml",
        r#"<scenario name="mini-uas">
             <recv request="OPTIONS"/>
             <send><![CDATA[
               SIP/2.0 200 OK
               [last_Via:]
               Content-Length: 0
             ]]></send>
           </scenario>"#,
    );
    let o = sipr(&["-sf", uas.path(), "-timeout", "1"]);
    assert_code(&o, 99); // ran as a UAS, no calls arrived
    assert!(stderr(&o).contains("answering calls"), "{}", stderr(&o));
}

#[test]
fn sf_uac_scenario_without_target_fails() {
    let uac = TempScenario::new(
        "uac.xml",
        r#"<scenario name="mini-uac">
             <send><![CDATA[
               OPTIONS sip:[service]@[remote_ip] SIP/2.0
               Call-ID: [call_id]
             ]]></send>
             <recv response="200"/>
           </scenario>"#,
    );
    let o = sipr(&["-sf", uac.path()]);
    assert_code(&o, 255);
    assert!(
        stderr(&o).contains("remote target required"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn compile_errors_are_fatal_outside_check_mode() {
    let bad = TempScenario::new(
        "broken.xml",
        "<scenario name=\"x\"><recieve response=\"200\"/></scenario>",
    );
    let o = sipr(&["-sf", bad.path(), "127.0.0.1"]);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(err.contains("unknown element <recieve>"), "{err}");
    assert!(err.contains("failed to compile"), "{err}");
}

#[test]
fn help_mentions_sipp_flag_convention() {
    let o = sipr(&["-h"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("single-dash names"), "{out}");
    assert!(out.contains("-trace_stat"), "{out}");
}
