//! Compiler behavior tests through the public API.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use sipr_scenario::compile;
use sipr_scenario::diag::Severity;
use sipr_scenario::model::{Action, Expect, PauseSpec, Role, Step};

fn wrap(body: &str) -> String {
    format!("<scenario name=\"t\">{body}</scenario>")
}

fn send_invite() -> &'static str {
    r#"<send><![CDATA[
        INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
        Call-ID: [call_id]

    ]]></send>"#
}

fn errors(xml: &str) -> Vec<String> {
    compile("test", xml)
        .diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.message)
        .collect()
}

fn warnings(xml: &str) -> Vec<String> {
    compile("test", xml)
        .diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| d.message)
        .collect()
}

#[test]
fn label_and_next_resolve_to_indices() {
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200" next="done"/>
           <recv response="180" optional="true"/>
           <label id="done"/>
           <recv response="486"/>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    let sc = out.scenario.expect("compiles");
    // steps: 0 send, 1 recv(next), 2 recv, 3 label, 4 recv
    let Step::Recv(r) = &sc.steps[1] else {
        panic!("step 1 not recv")
    };
    assert_eq!(r.common.next, Some(3));
    assert!(matches!(&sc.steps[3], Step::Label { id, .. } if id == "done"));
}

#[test]
fn undefined_label_is_an_error() {
    let xml = wrap(&format!(
        r#"{invite}<recv response="200" next="nowhere"/>"#,
        invite = send_invite()
    ));
    let errs = errors(&xml);
    assert!(
        errs.iter().any(|e| e.contains("undefined label 'nowhere'")),
        "{errs:?}"
    );
}

#[test]
fn ontimeout_resolves() {
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200" timeout="5000" ontimeout="bail"/>
           <label id="bail"/>
           <recv response="487"/>"#,
        invite = send_invite()
    ));
    let sc = compile("test", &xml).scenario.expect("compiles");
    let Step::Recv(r) = &sc.steps[1] else {
        panic!("step 1 not recv")
    };
    assert_eq!(r.timeout_ms, Some(5000));
    assert_eq!(r.ontimeout, Some(2));
}

#[test]
fn duplicate_label_is_an_error() {
    let xml = wrap(&format!(
        r#"{invite}<label id="x"/><label id="x"/>"#,
        invite = send_invite()
    ));
    assert!(errors(&xml).iter().any(|e| e.contains("duplicate label")));
}

#[test]
fn recv_needs_exactly_one_expectation() {
    let both = wrap(&format!(
        r#"{invite}<recv response="200" request="BYE"/>"#,
        invite = send_invite()
    ));
    assert!(errors(&both).iter().any(|e| e.contains("both")));
    let neither = wrap(&format!(r"{invite}<recv/>", invite = send_invite()));
    assert!(
        errors(&neither)
            .iter()
            .any(|e| e.contains("either 'response' or 'request'"))
    );
}

#[test]
fn unknown_attribute_warns_but_compiles() {
    let xml = wrap(&format!(
        r#"{invite}<recv response="200" retrnas="500"/>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    assert!(out.scenario.is_some());
    let warns = warnings(&xml);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("unknown attribute 'retrnas'")),
        "{warns:?}"
    );
}

#[test]
fn unknown_element_is_an_error() {
    let xml = wrap(&format!(r"{invite}<pauze/>", invite = send_invite()));
    assert!(
        errors(&xml)
            .iter()
            .any(|e| e.contains("unknown element <pauze>"))
    );
}

#[test]
fn threepcc_is_a_clear_error() {
    let xml = wrap(r#"<sendCmd><![CDATA[Call-ID: [call_id]]]></sendCmd>"#);
    assert!(errors(&xml).iter().any(|e| e.contains("3PCC")));
}

#[test]
fn media_exec_is_a_clear_error() {
    let xml = wrap(&format!(
        r#"{invite}
           <nop><action><exec play_pcap_audio="x.pcap"/></action></nop>"#,
        invite = send_invite()
    ));
    assert!(errors(&xml).iter().any(|e| e.contains("media")));
}

#[test]
fn ereg_variables_flow_into_templates() {
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200">
             <action>
               <ereg regexp=".*" search_in="hdr" header="Contact:" check_it="true" assign_to="1"/>
             </action>
           </recv>
           <send><![CDATA[
             ACK [next_url] SIP/2.0
             X-Contact: [$1]

           ]]></send>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    let sc = out.scenario.expect("compiles");
    assert_eq!(sc.vars.len(), 1);
    let Step::Recv(r) = &sc.steps[1] else {
        panic!("not recv")
    };
    assert!(matches!(&r.actions[0], Action::Ereg { check_it: true, .. }));
}

#[test]
fn read_without_write_is_an_error() {
    let xml = wrap(&format!(
        r#"{invite}
           <send><![CDATA[
             ACK x SIP/2.0
             X: [$never_set]

           ]]></send>"#,
        invite = send_invite()
    ));
    assert!(
        errors(&xml)
            .iter()
            .any(|e| e.contains("'never_set' is read but never set"))
    );
}

#[test]
fn unused_variable_warns_and_reference_silences() {
    let noisy = wrap(&format!(
        r#"{invite}
           <recv response="200">
             <action><ereg regexp="x" assign_to="junk"/></action>
           </recv>"#,
        invite = send_invite()
    ));
    assert!(
        warnings(&noisy)
            .iter()
            .any(|w| w.contains("'junk' is set but never used"))
    );
    let silenced = wrap(&format!(
        r#"{invite}
           <recv response="200">
             <action><ereg regexp="x" assign_to="junk"/></action>
           </recv>
           <Reference variables="junk"/>"#,
        invite = send_invite()
    ));
    assert!(warnings(&silenced).is_empty(), "{:?}", warnings(&silenced));
}

#[test]
fn pause_variants_parse() {
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200">
             <action><ereg regexp="[0-9]+" assign_to="dur"/></action>
           </recv>
           <pause/>
           <pause milliseconds="250"/>
           <pause variable="dur"/>
           <pause distribution="uniform(200,3000)"/>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    let sc = out.scenario.expect("compiles");
    let specs: Vec<&PauseSpec> = sc
        .steps
        .iter()
        .filter_map(|s| match s {
            Step::Pause { spec, .. } => Some(spec),
            _ => None,
        })
        .collect();
    assert_eq!(specs.len(), 4);
    assert_eq!(specs[0], &PauseSpec::Default);
    assert_eq!(specs[1], &PauseSpec::Fixed(250));
    assert!(matches!(specs[2], PauseSpec::Variable(_)));
    assert!(
        matches!(specs[3], PauseSpec::Distribution { kind, params } if kind == "uniform" && params == &[200.0, 3000.0])
    );
}

#[test]
fn chance_out_of_range_is_an_error() {
    let xml = wrap(&format!(
        r#"{invite}<recv response="200" chance="1.5" next="x"/><label id="x"/>"#,
        invite = send_invite()
    ));
    assert!(errors(&xml).iter().any(|e| e.contains("0..=1")));
}

#[test]
fn scenario_without_messages_is_an_error() {
    let xml = wrap(r#"<pause milliseconds="100"/>"#);
    assert!(
        errors(&xml)
            .iter()
            .any(|e| e.contains("no <send> or <recv>"))
    );
}

#[test]
fn uas_role_detected_and_auth_flags_carried() {
    let xml = wrap(
        r#"<recv request="REGISTER" auth="true" rrs="true"/>
           <send><![CDATA[
             SIP/2.0 200 OK
             [last_Via:]

           ]]></send>"#,
    );
    let out = compile("test", &xml);
    let sc = out.scenario.expect("compiles");
    assert_eq!(sc.role, Role::Uas);
    let Step::Recv(r) = &sc.steps[0] else {
        panic!("not recv")
    };
    assert!(r.auth);
    assert!(r.record_route_set);
    assert_eq!(r.expect, Expect::Request("REGISTER".into()));
}

#[test]
fn malformed_xml_reports_line() {
    let out = compile("test", "<scenario>\n<send>\n</scenario>");
    assert!(out.scenario.is_none());
    let err = &out.diagnostics[0];
    assert_eq!(err.severity, Severity::Error);
    assert_eq!(err.line, Some(3));
    assert!(err.message.contains("expected </send>"), "{}", err.message);
}

#[test]
fn dump_is_stable_and_informative() {
    let sc = compile("uac", sipr_scenario::embedded("uac").unwrap())
        .scenario
        .expect("compiles");
    let dump = sc.dump();
    assert!(dump.contains("role=UAC"), "{dump}");
    assert!(dump.contains("send retrans=500ms"), "{dump}");
    assert!(dump.contains("recv response=100 optional"), "{dump}");
    assert!(dump.contains("pause default (-d)"), "{dump}");
}
