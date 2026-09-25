//! `--check` lints (M47) through the public API: what each one finds, where
//! it points, and how `sipr-lint: allow` silences it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use sipr_scenario::diag::{Diagnostic, Severity};
use sipr_scenario::lint::Lint;
use sipr_scenario::{CompileOptions, compile, compile_with};

/// A scenario whose `i`-th element sits on line `i + 2` (line 1 is
/// `<scenario>`), so tests can name lines.
fn scenario(elements: &[&str]) -> String {
    format!(
        "<scenario name=\"t\">\n{}\n</scenario>\n",
        elements.join("\n")
    )
}

/// A body-less request on one line.
const SEND: &str = "<send><![CDATA[OPTIONS sip:[service]@[remote_ip] SIP/2.0]]></send>";

fn lint(xml: &str) -> Vec<Diagnostic> {
    let options = CompileOptions {
        lint: true,
        ..CompileOptions::default()
    };
    compile_with("t.xml", xml, &options).diagnostics
}

/// `(lint, line)` of every lint finding.
fn findings(xml: &str) -> Vec<(Lint, u32)> {
    lint(xml)
        .into_iter()
        .filter_map(|d| Some((d.lint?, d.line?)))
        .collect()
}

/// The one finding's message; fails unless there is exactly one.
#[track_caller]
fn only_message(xml: &str) -> String {
    let diags = lint(xml);
    assert_eq!(diags.len(), 1, "{diags:#?}");
    diags[0].message.clone()
}

/// Every diagnostic that is not a lint finding (directive problems, …).
fn plain_warnings(xml: &str) -> Vec<(u32, String)> {
    lint(xml)
        .into_iter()
        .filter(|d| d.lint.is_none() && d.severity == Severity::Warning)
        .map(|d| (d.line.unwrap_or(0), d.message))
        .collect()
}

// ---- optional-window --------------------------------------------------

#[test]
fn optional_recv_before_a_send_is_what_sipp_refuses() {
    let xml = scenario(&[
        SEND,
        r#"<recv response="100" optional="true"/>"#,
        r#"<recv response="180" optional="true"/>"#,
        SEND,
    ]);
    assert_eq!(findings(&xml), [(Lint::OptionalWindow, 3)]);
    let message = only_message(&xml);
    assert!(
        message.contains("optional <recv response=\"100\"> has no mandatory <recv> after it"),
        "{message}"
    );
    assert!(message.contains("before the <send> at line 5"), "{message}");
    // SIPp's own wording, so a search for its error finds this.
    assert!(
        message.contains("\"<recv> before <send> sequence without a mandatory message\""),
        "{message}"
    );
}

#[test]
fn a_mandatory_recv_anchors_the_window_labels_are_transparent() {
    let anchored = scenario(&[
        SEND,
        r#"<recv response="100" optional="true"/>"#,
        r#"<label id="l"/>"#,
        r#"<recv response="200"/>"#,
        SEND,
    ]);
    assert_eq!(findings(&anchored), []);
    let broken = scenario(&[
        SEND,
        r#"<recv response="100" optional="true"/>"#,
        r#"<label id="l"/>"#,
        r#"<pause milliseconds="10"/>"#,
    ]);
    assert_eq!(findings(&broken), [(Lint::OptionalWindow, 3)]);
    assert!(only_message(&broken).contains("before the <pause> at line 5"));
}

#[test]
fn a_mandatory_recv_cmd_anchors_the_window_too() {
    // SIPp's check counts <recvCmd> as a recv (`last_recv_optional`).
    let xml = scenario(&[
        SEND,
        r#"<recv response="200" optional="true"/>"#,
        "<recvCmd/>",
        SEND,
    ]);
    assert_eq!(findings(&xml), []);
}

#[test]
fn a_trailing_optional_recv_without_a_timeout_hangs_the_call() {
    let hangs = scenario(&[
        SEND,
        r#"<recv response="200"/>"#,
        r#"<recv request="BYE" optional="true"/>"#,
    ]);
    assert_eq!(findings(&hangs), [(Lint::OptionalWindow, 4)]);
    let message = only_message(&hangs);
    assert!(message.contains("ends the scenario"), "{message}");
    assert!(message.contains("<timewait>"), "{message}");

    // Its own timeout ends the wait (SIPp arms the current recv's timeout).
    let timed = scenario(&[
        SEND,
        r#"<recv response="200"/>"#,
        r#"<recv request="BYE" optional="true" timeout="1000" ontimeout="end"/>"#,
        r#"<label id="end"/>"#,
    ]);
    assert_eq!(findings(&timed), []);
}

// ---- unreachable ------------------------------------------------------

#[test]
fn steps_after_an_unconditional_next_are_unreachable() {
    let xml = scenario(&[
        SEND,
        r#"<recv response="200" next="done"/>"#,
        SEND,
        r#"<pause milliseconds="10"/>"#,
        r#"<label id="done"/>"#,
        SEND,
    ]);
    // One finding for the whole dead run, on its first step.
    assert_eq!(findings(&xml), [(Lint::Unreachable, 4)]);
    let message = only_message(&xml);
    assert!(
        message.starts_with("<send> can never run (nor can the step after it)"),
        "{message}"
    );
    assert!(
        message.contains(
            "the <recv response=\"200\"> at line 3 before it always jumps to label 'done'"
        ),
        "{message}"
    );
}

#[test]
fn a_conditional_next_leaves_the_fall_through_open() {
    for condition in [r#"test="flag""#, r#"chance="0.5""#, r#"condexec="flag""#] {
        let xml = scenario(&[
            "<nop><action><assignstr assign_to=\"flag\" value=\"1\"/></action></nop>",
            SEND,
            &format!(r#"<recv response="200" next="done" {condition}/>"#),
            SEND,
            r#"<label id="done"/>"#,
        ]);
        assert_eq!(findings(&xml), [], "{condition}");
    }
}

#[test]
fn a_jumped_to_step_is_reachable() {
    let xml = scenario(&[
        SEND,
        r#"<recv response="200" next="done"/>"#,
        r#"<label id="retry"/>"#,
        SEND,
        r#"<recv response="200" next="done"/>"#,
        r#"<label id="done"/>"#,
        r#"<nop next="retry" test="again"/>"#,
        "<nop><action><assignstr assign_to=\"again\" value=\"0\"/></action></nop>",
    ]);
    assert_eq!(findings(&xml), []);
}

#[test]
fn an_optional_recv_that_jumps_away_keeps_its_window_reachable() {
    // A 180 may never come: the 200 behind it still matches from the window.
    let xml = scenario(&[
        SEND,
        r#"<recv response="180" optional="true" next="ringing"/>"#,
        r#"<recv response="200"/>"#,
        r#"<label id="ringing"/>"#,
        r#"<recv response="200"/>"#,
    ]);
    assert_eq!(findings(&xml), []);
}

#[test]
fn ontimeout_and_the_unexpected_handler_make_steps_reachable() {
    let xml = scenario(&[
        SEND,
        r#"<recv response="200" timeout="500" ontimeout="late" next="done"/>"#,
        r#"<label id="late"/>"#,
        SEND,
        r#"<label id="done"/>"#,
        "<timewait milliseconds=\"10\"/>",
        r#"<label id="_unexp.main"/>"#,
        "<nop><action><exec int_cmd=\"stop_call\"/></action></nop>",
    ]);
    assert_eq!(findings(&xml), []);
}

#[test]
fn a_step_after_timewait_is_unreachable() {
    let xml = scenario(&[SEND, "<timewait milliseconds=\"10\"/>", "<nop/>"]);
    assert_eq!(findings(&xml), [(Lint::Unreachable, 4)]);
    assert!(only_message(&xml).contains("SIPp refuses any step after a <timewait>"));
}

#[test]
fn jump_actions_count_and_computed_jumps_disable_the_analysis() {
    // `jump value=` reaches its index when the message before it has no
    // `next=`: only the send on line 4 is dead.
    let by_index = scenario(&[
        SEND,
        r#"<recv response="200" next="end"/>"#,
        SEND,
        SEND,
        r#"<label id="end"/>"#,
        "<nop><action><jump value=\"3\"/></action></nop>",
    ]);
    assert_eq!(findings(&by_index), [(Lint::Unreachable, 4)]);

    // `jump variable=` could go anywhere: no verdict at all.
    let computed = scenario(&[
        "<nop><action><assignstr assign_to=\"to\" value=\"3\"/></action></nop>",
        SEND,
        r#"<recv response="200" next="end"/>"#,
        SEND,
        r#"<label id="end"/>"#,
        "<nop><action><jump variable=\"to\"/></action></nop>",
    ]);
    assert_eq!(findings(&computed), []);

    // ...except the `_unexp.retaddr` return, which goes back to a step
    // that already ran — the dead <send> is still dead.
    let retaddr = scenario(&[
        SEND,
        r#"<recv response="200" next="end"/>"#,
        SEND,
        r#"<label id="end"/>"#,
        "<timewait milliseconds=\"10\"/>",
        r#"<label id="_unexp.main"/>"#,
        "<nop><action><jump variable=\"_unexp.retaddr\"/></action></nop>",
    ]);
    assert_eq!(findings(&retaddr), [(Lint::Unreachable, 4)]);
}

#[test]
fn a_jump_value_counts_messages_not_labels() {
    // Message 3 is the <send> on line 6: the label before the nop is not a
    // message. The <send> on line 5 (message 2) is what the jump skips,
    // and the nop's own `next` goes elsewhere.
    let xml = scenario(&[
        SEND,
        r#"<label id="start"/>"#,
        r#"<nop next="end"><action><jump value="3"/></action></nop>"#,
        SEND,
        SEND,
        r#"<label id="end"/>"#,
    ]);
    assert_eq!(findings(&xml), [(Lint::Unreachable, 5)]);
}

#[test]
fn a_jump_lands_on_the_next_of_the_message_before_its_target() {
    // SIPp's jump to message 2 sets `msg_index = 1`, and `next()` there
    // takes the recv's `next="end"`: the send the jump names never runs.
    let certain = scenario(&[
        SEND,
        r#"<recv response="200" next="end"/>"#,
        SEND,
        r#"<label id="end"/>"#,
        "<nop><action><jump value=\"2\"/></action></nop>",
    ]);
    assert_eq!(findings(&certain), [(Lint::Unreachable, 4)]);

    // A `test=` on that `next=` keeps the target open.
    let conditional = scenario(&[
        SEND,
        r#"<recv response="200" next="end" test="t"/>"#,
        r#"<label id="end"/>"#,
        "<nop><action><jump value=\"2\"/></action></nop>",
        SEND,
        "<nop><action><assignstr assign_to=\"t\" value=\"x\"/></action></nop>",
    ]);
    assert_eq!(findings(&conditional), []);
}

#[test]
fn a_recvs_jump_counts_only_when_the_recv_stays() {
    // A mandatory recv moves on through `next()`, which overwrites the
    // jump: the send on line 4 stays dead.
    let mandatory = scenario(&[
        SEND,
        r#"<recv response="200" next="end"><action><jump value="2"/></action></recv>"#,
        SEND,
        r#"<label id="end"/>"#,
    ]);
    assert_eq!(findings(&mandatory), [(Lint::Unreachable, 4)]);

    // An optional recv whose `test=` is unset stays, and the jump to
    // message 4 leaves the call waiting at message 3 (line 5).
    let stays = scenario(&[
        SEND,
        r#"<recv response="180" optional="true" next="end" test="t"><action><ereg regexp="x" search_in="msg" assign_to="t"/><jump value="4"/></action></recv>"#,
        r#"<recv response="200" next="end"/>"#,
        r#"<recv response="200"/>"#,
        SEND,
        r#"<label id="end"/>"#,
    ]);
    assert_eq!(findings(&stays), []);
}

// ---- body-separator ---------------------------------------------------

#[test]
fn sdp_among_the_headers_means_the_separator_is_missing() {
    let xml = "<scenario name=\"t\">
  <send><![CDATA[
    INVITE sip:[service]@[remote_ip] SIP/2.0
    Call-ID: [call_id]
    Content-Type: application/sdp
    Content-Length: [len]
    v=0
    o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
  ]]></send>
  <recv response=\"200\"/>
</scenario>";
    assert_eq!(findings(xml), [(Lint::BodySeparator, 7)]);
    let message = only_message(xml);
    assert!(
        message.starts_with("'v=0' looks like an SDP line"),
        "{message}"
    );
    assert!(message.contains("[len] does not count it"), "{message}");
}

// ---- content-length ---------------------------------------------------

/// An INVITE with `content_length` as its Content-Length line and `body`
/// after the blank line; the Content-Length header is on line 5.
fn invite(content_length: &str, body: &str) -> String {
    format!(
        "<scenario name=\"t\">
  <send><![CDATA[
    INVITE sip:[service]@[remote_ip] SIP/2.0
    Call-ID: [call_id]
    {content_length}

{body}
  ]]></send>
  <recv response=\"200\"/>
</scenario>"
    )
}

#[test]
fn len_keeps_content_length_right() {
    assert_eq!(
        findings(&invite("Content-Length: [len]", "v=0\ns=[$x]")),
        []
    );
    assert_eq!(findings(&invite("Content-Length: 0", "")), []);
}

#[test]
fn a_literal_content_length_must_match_the_body_in_crlf_bytes() {
    // "v=0\r\ns=-\r\n" is 10 bytes on the wire, 8 with bare newlines.
    assert_eq!(findings(&invite("Content-Length: 10", "v=0\ns=-")), []);
    let wrong = invite("Content-Length: 8", "v=0\ns=-");
    assert_eq!(findings(&wrong), [(Lint::ContentLength, 5)]);
    let message = only_message(&wrong);
    assert!(
        message.starts_with("Content-Length says 8, but the body is 10 bytes"),
        "{message}"
    );
    // The compact form is the same header.
    assert_eq!(
        findings(&invite("l: 8", "v=0\ns=-")),
        [(Lint::ContentLength, 5)]
    );
}

#[test]
fn a_literal_content_length_cannot_follow_a_keyword_body() {
    let xml = invite("Content-Length: 129", "v=0\nc=IN IP4 [local_ip]");
    assert_eq!(findings(&xml), [(Lint::ContentLength, 5)]);
    assert!(only_message(&xml).contains("fixed at 129, but the body holds keywords"));
}

#[test]
fn a_body_without_content_length_cannot_be_framed_on_a_stream() {
    let xml = invite("Max-Forwards: 70", "v=0");
    // Reported on the start line, since there is no header to point at.
    assert_eq!(findings(&xml), [(Lint::ContentLength, 3)]);
    assert!(only_message(&xml).contains("no Content-Length header"));
    assert_eq!(findings(&invite("Max-Forwards: 70", "")), []);
}

// ---- directives -------------------------------------------------------

#[test]
fn an_allow_directive_silences_that_lint_on_the_next_step_only() {
    let xml = scenario(&[
        SEND,
        "<!-- sipr-lint: allow optional-window -->",
        r#"<recv response="200" optional="true"/>"#,
        SEND,
        r#"<recv response="200" optional="true"/>"#,
        SEND,
    ]);
    assert_eq!(findings(&xml), [(Lint::OptionalWindow, 6)]);
}

#[test]
fn a_directive_names_lints_it_silences_and_no_others() {
    let xml = invite("Content-Length: 1", "v=0\nm=audio [media_port] RTP/AVP 0")
        .replace("<send>", "<!-- sipr-lint: allow unreachable -->\n  <send>");
    // Still reported: the directive allows a different lint (lines moved by one).
    assert_eq!(findings(&xml), [(Lint::ContentLength, 6)]);
    let silenced = invite("Content-Length: 1", "v=0").replace(
        "<send>",
        "<!-- sipr-lint: allow unreachable, content-length -->\n  <send>",
    );
    assert_eq!(findings(&silenced), []);
    assert!(lint(&silenced).is_empty(), "{:#?}", lint(&silenced));
}

#[test]
fn directives_stack_and_accept_commas_or_spaces() {
    let xml = scenario(&[
        SEND,
        r#"<recv response="200" next="end"/>"#,
        "<!-- sipr-lint: allow unreachable -->",
        "<!-- sipr-lint: allow content-length optional-window -->",
        r#"<recv response="180" optional="true"/>"#,
        SEND,
        r#"<label id="end"/>"#,
    ]);
    assert!(lint(&xml).is_empty(), "{:#?}", lint(&xml));
}

#[test]
fn bad_directives_warn_instead_of_doing_nothing_silently() {
    let xml = scenario(&[
        SEND,
        "<!-- sipr-lint: allow unreachabel -->",
        SEND,
        "<!-- sipr-lint: deny unreachable -->",
        SEND,
        "<!-- sipr-lint: allow unreachable -->",
        "<Reference variables=\"x\"/>",
        "<nop><action><assignstr assign_to=\"x\" value=\"1\"/></action></nop>",
        "<!-- sipr-lint: allow unreachable -->",
    ]);
    let warnings = plain_warnings(&xml);
    let lines: Vec<u32> = warnings.iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [3, 5, 7, 10], "{warnings:#?}");
    assert!(
        warnings[0].1.contains("unknown lint 'unreachabel'"),
        "{warnings:#?}"
    );
    assert!(
        warnings[0]
            .1
            .contains("known: optional-window, unreachable"),
        "{warnings:#?}"
    );
    assert!(
        warnings[1].1.contains("malformed sipr-lint directive"),
        "{warnings:#?}"
    );
    assert!(
        warnings[2].1.contains("not before <Reference>"),
        "{warnings:#?}"
    );
    assert!(
        warnings[3].1.contains("no step follows it"),
        "{warnings:#?}"
    );
}

#[test]
fn a_directive_may_span_its_own_comment_lines() {
    let xml = scenario(&[
        SEND,
        "<timewait milliseconds=\"10\"/>",
        "<!--",
        "  sipr-lint: allow unreachable",
        "-->",
        "<nop/>",
    ]);
    assert!(lint(&xml).is_empty(), "{:#?}", lint(&xml));
}

#[test]
fn a_directive_outside_the_scenario_level_warns() {
    let xml = "<!-- sipr-lint: allow unreachable -->
<scenario name=\"t\">
  <send>
    <!-- sipr-lint: allow content-length -->
    <![CDATA[OPTIONS sip:[service]@[remote_ip] SIP/2.0]]>
  </send>
</scenario>";
    let lines: Vec<u32> = plain_warnings(xml).iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [1, 4], "{:#?}", plain_warnings(xml));
}

// ---- when lints run ---------------------------------------------------

#[test]
fn lints_and_directives_are_silent_without_check() {
    let xml = scenario(&[
        SEND,
        r#"<recv response="200" optional="true"/>"#,
        SEND,
        "<!-- sipr-lint: allow nonsense -->",
        "<timewait milliseconds=\"10\"/>",
        "<nop/>",
    ]);
    let out = compile("t.xml", &xml);
    assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    assert!(out.scenario.is_some());
}

#[test]
fn a_scenario_with_errors_is_not_linted() {
    let xml = scenario(&[
        SEND,
        r#"<recv response="200" next="nowhere"/>"#,
        "<timewait milliseconds=\"10\"/>",
        "<nop/>",
    ]);
    let diags = lint(&xml);
    assert!(diags.iter().all(|d| d.lint.is_none()), "{diags:#?}");
    assert!(diags.iter().any(|d| d.severity == Severity::Error));
}

#[test]
fn a_finding_prints_with_its_lint_name() {
    let xml = scenario(&[SEND, "<timewait milliseconds=\"10\"/>", "<nop/>"]);
    let printed = lint(&xml)[0].to_string();
    assert!(
        printed.starts_with("t.xml:4: warning[unreachable]: <nop> can never run"),
        "{printed}"
    );
}

#[test]
fn every_lint_name_round_trips() {
    for lint in Lint::ALL {
        assert_eq!(Lint::from_name(lint.name()), Some(lint));
    }
    assert_eq!(Lint::from_name("Unreachable"), None);
}
