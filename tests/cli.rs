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

#[test]
fn sd_dumps_embedded_out_of_call_scenarios() {
    let o = sipr(&["-sd", "ooc_default"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("<scenario name=\"Out-of-call UAS\">"), "{out}");
    assert!(
        out.contains("<recv request=\".*\" regexp_match=\"true\" />"),
        "{out}"
    );
    assert!(out.contains("<timewait milliseconds=\"4000\"/>"), "{out}");
    let o = sipr(&["-sd", "ooc_dummy"]);
    assert_code(&o, 0);
    assert!(stdout(&o).contains("<recv request=\"DUMMY\" />"));
    // -sd's error lists the ooc names alongside uac/uas.
    let o = sipr(&["-sd", "nope"]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("uac, uas, ooc_default, ooc_dummy"));
}

#[test]
fn ooc_scenario_in_server_mode_is_fatal_with_sipps_wording() {
    let o = sipr(&["-sn", "uas", "-oocsn", "ooc_default", "-timeout", "1"]);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(
        err.contains("SIPp cannot use out-of-call scenarios when running in server mode"),
        "{err}"
    );
}

#[test]
fn ooc_flags_are_mutually_exclusive_and_names_are_checked() {
    let o = sipr(&["-oocsf", "x.xml", "-oocsn", "ooc_default", "127.0.0.1:1"]);
    assert_code(&o, 2);
    assert!(stderr(&o).contains("'-oocsf' and '-oocsn' cannot be used together"));
    let o = sipr(&["-oocsn", "nope", "127.0.0.1:1"]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("unknown embedded scenario 'nope'"));
    let o = sipr(&["-oocsf", "/nonexistent/ooc.xml", "127.0.0.1:1"]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("cannot read out-of-call scenario file"));
}

#[test]
fn ooc_scenario_reading_injection_files_is_fatal_with_sipps_wording() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-cli-ooc-field-{}.xml", std::process::id()));
    std::fs::write(
        &path,
        r#"<scenario name="ooc-with-field">
  <recv request="OPTIONS"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:]
    [last_Call-ID:]
    [last_CSeq:]
    X-User: [field0]
    Content-Length: 0

  ]]></send>
</scenario>"#,
    )
    .expect("write scenario");
    let o = sipr(&[
        "-sn",
        "uac",
        "-oocsf",
        path.to_str().expect("utf8"),
        "127.0.0.1:1",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(
        err.contains("Automatic calls (created by -aa, -oocsn or -oocsf) cannot use input files!"),
        "{err}"
    );
}

#[test]
fn check_mode_lints_the_ooc_scenario_too() {
    let o = sipr(&["--check", "-sn", "uac", "-oocsn", "ooc_default"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("scenario 'Basic Sipstone UAC'"), "{out}");
    assert!(
        out.contains("out-of-call scenario 'Out-of-call UAS': role=UAS, 3 steps"),
        "{out}"
    );
    // An unknown element in the ooc scenario fails the lint like the main one.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-cli-ooc-bad-{}.xml", std::process::id()));
    std::fs::write(
        &path,
        "<scenario name=\"bad-ooc\">\n  <recv request=\"OPTIONS\"/>\n  <bogus/>\n</scenario>\n",
    )
    .expect("write scenario");
    let o = sipr(&[
        "--check",
        "-sn",
        "uac",
        "-oocsf",
        path.to_str().expect("utf8"),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_code(&o, 1);
    let err = stderr(&o);
    assert!(err.contains("bogus"), "{err}");
}

#[test]
fn mixed_mode_flags_conflict_and_roles_are_checked() {
    let o = sipr(&["-rxsf", "x.xml", "-rxsn", "uas", "127.0.0.1:1"]);
    assert_code(&o, 2);
    assert!(stderr(&o).contains("'-rxsf' and '-rxsn' cannot be used together"));
    // SIPp never reaches the out-of-call branch in mixed mode: refused loudly.
    let o = sipr(&["-rxsn", "uas", "-oocsn", "ooc_default", "127.0.0.1:1"]);
    assert_code(&o, 2);
    assert!(
        stderr(&o).contains("'-rxsf'/'-rxsn' and '-oocsf'/'-oocsn' cannot be used together"),
        "{}",
        stderr(&o)
    );
    // The main scenario must originate calls, the receive one answer them —
    // what SIPp's help promises and never enforces.
    let o = sipr(&["-sn", "uas", "-rxsn", "uas", "-timeout", "1"]);
    assert_code(&o, 255);
    assert!(
        stderr(&o).contains("the main scenario must be a client-mode scenario"),
        "{}",
        stderr(&o)
    );
    let o = sipr(&["-sn", "uac", "-rxsn", "uac", "127.0.0.1:1"]);
    assert_code(&o, 255);
    assert!(
        stderr(&o).contains("the receive scenario must be a server-mode scenario"),
        "{}",
        stderr(&o)
    );
    let o = sipr(&["-rxsn", "nope", "127.0.0.1:1"]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("unknown embedded scenario 'nope'"));
    let o = sipr(&["-rxsf", "/nonexistent/rx.xml", "127.0.0.1:1"]);
    assert_code(&o, 255);
    assert!(stderr(&o).contains("cannot read receive scenario file"));
}

/// A bare `[fieldN]` reads the first `-inf` file, in the receive scenario
/// too; `-rxinf` alone does not provide one (SIPp's `default_file` is only
/// set by `-inf`, so it errors "No injection file was specified!").
#[test]
fn receive_scenario_with_a_bare_field_needs_an_inf_file() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let xml = dir.join(format!("sipr-cli-rx-field-{pid}.xml"));
    let csv = dir.join(format!("sipr-cli-rx-{pid}.csv"));
    std::fs::write(
        &xml,
        r#"<scenario name="rx-with-field">
  <recv request="INVITE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]RxTag[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    X-User: [field0]
    Content-Length: 0

  ]]></send>
</scenario>"#,
    )
    .expect("write scenario");
    std::fs::write(&csv, "SEQUENTIAL\nalice;\n").expect("write csv");
    let o = sipr(&[
        "-sn",
        "uac",
        "-rxsf",
        xml.to_str().expect("utf8"),
        "-rxinf",
        csv.to_str().expect("utf8"),
        "127.0.0.1:1",
    ]);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(err.contains("No injection file was specified!"), "{err}");
    // A named file that was never loaded is refused as for the main scenario.
    std::fs::write(
        &xml,
        r#"<scenario name="rx-with-named-field">
  <recv request="INVITE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]RxTag[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    X-User: [field0 file=missing.csv]
    Content-Length: 0

  ]]></send>
</scenario>"#,
    )
    .expect("write scenario");
    let o = sipr(&[
        "-sn",
        "uac",
        "-rxsf",
        xml.to_str().expect("utf8"),
        "-rxinf",
        csv.to_str().expect("utf8"),
        "127.0.0.1:1",
    ]);
    let _ = std::fs::remove_file(&xml);
    let _ = std::fs::remove_file(&csv);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(
        err.contains("no injection file named 'missing.csv' was given"),
        "{err}"
    );
}

#[test]
fn check_mode_lints_the_receive_scenario_too() {
    let o = sipr(&["--check", "-sn", "uac", "-rxsn", "uas"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("scenario 'Basic Sipstone UAC'"), "{out}");
    assert!(
        out.contains("receive scenario 'Basic UAS responder': role=UAS"),
        "{out}"
    );
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-cli-rx-bad-{}.xml", std::process::id()));
    std::fs::write(
        &path,
        "<scenario name=\"bad-rx\">\n  <recv request=\"INVITE\"/>\n  <bogus/>\n</scenario>\n",
    )
    .expect("write scenario");
    let o = sipr(&[
        "--check",
        "-sn",
        "uac",
        "-rxsf",
        path.to_str().expect("utf8"),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_code(&o, 1);
    assert!(stderr(&o).contains("bogus"), "{}", stderr(&o));
}

/// A UAC scenario with one `<User>` and two `<Global>` variables (M35).
fn scoped_scenario() -> TempScenario {
    TempScenario::new(
        "scoped.xml",
        r#"<scenario name="scoped">
             <Global variables="region,per_run"/>
             <User variables="per_user"/>
             <nop>
               <action>
                 <add assign_to="per_user" value="1"/>
                 <add assign_to="per_run" value="1"/>
               </action>
             </nop>
             <send><![CDATA[
               INVITE sip:[service]@[remote_ip] SIP/2.0
               Call-ID: [call_id]
               X-Region: [$region]
               X-User-Count: [$per_user]
               X-Run-Count: [$per_run]

             ]]></send>
             <recv response="200"/>
           </scenario>"#,
    )
}

#[test]
fn check_mode_prints_the_variable_scopes() {
    let sc = scoped_scenario();
    let o = sipr(&["-sf", sc.path(), "--check"]);
    assert_code(&o, 0);
    let out = stdout(&o);
    assert!(out.contains("3 variables"), "{out}");
    assert!(out.contains("user variables: per_user"), "{out}");
    assert!(out.contains("global variables: region, per_run"), "{out}");
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

#[test]
fn set_of_an_undeclared_global_is_fatal_with_sipps_wording() {
    let sc = scoped_scenario();
    let o = sipr(&[
        "-sf",
        sc.path(),
        "-set",
        "nope",
        "1",
        "-timeout",
        "1",
        "127.0.0.1:5060",
    ]);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(
        err.contains("Can not set the global variable nope, because it does not exist"),
        "{err}"
    );
    assert!(
        err.contains("declared <Global> variables: region, per_run"),
        "{err}"
    );
}

#[test]
fn user_and_global_elements_are_rejected_when_they_disagree_across_scenarios() {
    // The main and the receive scenario share one user and one global name
    // space (SIPp's `userVariables`/`globalVariables`); scoping one name two
    // ways is a start-up error rather than SIPp's silent first-wins.
    let main = scoped_scenario();
    let rx = TempScenario::new(
        "rx-scoped.xml",
        r#"<scenario name="rx">
             <User variables="per_run"/>
             <recv request="INVITE">
               <action><add assign_to="per_run" value="1"/></action>
             </recv>
             <send><![CDATA[
               SIP/2.0 200 OK
               [last_Via:]
               [last_From:]
               [last_To:];tag=[pid]SIPpTag01[call_number]
               [last_Call-ID:]
               [last_CSeq:]
               Content-Length: 0

             ]]></send>
             <Reference variables="per_run"/>
           </scenario>"#,
    );
    let o = sipr(&[
        "-sf",
        main.path(),
        "-rxsf",
        rx.path(),
        "-timeout",
        "1",
        "127.0.0.1:5060",
    ]);
    assert_code(&o, 255);
    let err = stderr(&o);
    assert!(
        err.contains("variable 'per_run' is <User> in one scenario and <Global> in the other"),
        "{err}"
    );
}
