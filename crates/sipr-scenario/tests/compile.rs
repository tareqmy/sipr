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
fn threepcc_send_and_recv_cmd_compile() {
    // Controller-A shape: capture from a recv, sendCmd it, recvCmd the reply.
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200">
             <action><ereg regexp="Content-Type:.*" search_in="msg" assign_to="1"/></action>
           </recv>
           <sendCmd><![CDATA[
             Call-ID: [call_id]
             [$1]
           ]]></sendCmd>
           <recvCmd>
             <action><ereg regexp="Content-Type:.*" search_in="msg" assign_to="2"/></action>
           </recvCmd>
           <Reference variables="2"/>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    let sc = out.scenario.expect("compiles");
    assert!(matches!(sc.steps[2], Step::SendCmd { .. }));
    assert!(matches!(sc.steps[3], Step::RecvCmd { .. }));
}

#[test]
fn extended_3pcc_attrs_are_rejected() {
    let xml = wrap(r#"<recvCmd src="s1"/>"#);
    assert!(
        errors(&xml).iter().any(|e| e.contains("extended 3PCC")),
        "{:?}",
        errors(&xml)
    );
}

#[test]
fn play_pcap_exec_compiles_to_a_media_action() {
    use sipr_scenario::model::MediaKind;
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200" ignoresdp="true"/>
           <nop><action><exec play_pcap_audio="pcap/x.pcap"/></action></nop>
           <nop><action><exec play_pcap_video=" v.pcap "/></action></nop>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    let sc = out.scenario.expect("compiles");
    let pcaps: Vec<(MediaKind, &str)> = sc.pcap_actions().collect();
    assert_eq!(
        pcaps,
        vec![
            (MediaKind::Audio, "pcap/x.pcap"),
            (MediaKind::Video, "v.pcap")
        ]
    );
    assert!(sc.has_media());
    assert!(matches!(&sc.steps[1], Step::Recv(r) if r.ignore_sdp));
}

#[test]
fn unsupported_media_execs_are_clear_errors() {
    for attr in [
        r#"rtp_echo="startaudio""#,
        r#"play_pcap="x.pcap""#,
        r#"play_pcap_audio="a.pcap" play_pcap_video="v.pcap""#,
        r#"play_pcap_audio="a.pcap" int_cmd="stop_call""#,
        r#"play_pcap_audio=" ""#,
        r#"play_pcap_audio="[pcap]""#,
    ] {
        let xml = wrap(&format!(
            r#"{invite}
               <nop><action><exec {attr}/></action></nop>"#,
            invite = send_invite()
        ));
        let errs = errors(&xml);
        assert!(!errs.is_empty(), "{attr}: expected an error");
        assert!(errs.iter().any(|e| e.contains("exec")), "{attr}: {errs:?}");
    }
}

#[test]
fn media_port_keyword_forms_tokenize() {
    use sipr_scenario::template::Keyword;
    let xml = wrap(
        r#"<send><![CDATA[
        INVITE sip:x SIP/2.0

        m=audio [media_port] RTP/AVP 0
        a=rtcp:[media_port+1]
        m=video [auto_media_port+2] RTP/AVP 96
    ]]></send>"#,
    );
    let out = compile("test", &xml);
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    let sc = out.scenario.expect("compiles");
    let Step::Send(send) = &sc.steps[0] else {
        panic!("send")
    };
    let kws: Vec<&Keyword> = send.template.keywords().collect();
    assert_eq!(
        kws,
        vec![
            &Keyword::MediaPort {
                auto: false,
                offset: 0
            },
            &Keyword::MediaPort {
                auto: false,
                offset: 1
            },
            &Keyword::MediaPort {
                auto: true,
                offset: 2
            },
        ]
    );
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

#[test]
fn field_keyword_tokenizes_with_file_and_line() {
    use sipr_scenario::template::{Keyword, LineExpr};
    let xml = wrap(&format!(
        r#"{invite}
           <send><![CDATA[
             ACK sip:[field0]@[remote_ip] SIP/2.0
             X-Two: [field2 file=users.csv]
             X-Line: [field0 line=3]
             Call-ID: [call_id]

           ]]></send>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    let sc = out.scenario.expect("compiles");
    let Step::Send(ack) = &sc.steps[1] else {
        panic!("step 1 not send");
    };
    let fields: Vec<_> = ack
        .template
        .keywords()
        .filter_map(|k| match k {
            Keyword::Field { index, file, line } => Some((*index, file.clone(), line.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        fields,
        vec![
            (0, None, None),
            (2, Some("users.csv".to_owned()), None),
            (0, None, Some(LineExpr::Literal(3))),
        ]
    );
}

#[test]
fn field_line_var_reads_the_selector_variable() {
    // `[fieldN line=[$v]]` must (a) tokenize the nested variable selector and
    // (b) count as a read of `v`, so the ereg that writes it is not flagged
    // unused and `v` is not "read but never set".
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200">
             <action><ereg regexp="([0-9]+)" search_in="hdr" header="X:" assign_to="idx"/></action>
           </recv>
           <send><![CDATA[
             ACK sip:x SIP/2.0
             X-Var: [field0 line=[$idx]]
             Call-ID: [call_id]

           ]]></send>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
}

#[test]
fn rtp_stream_exec_parses_sipp_grammar() {
    use sipr_scenario::model::{RtpSource, RtpStreamCmd};
    let cases: Vec<(&str, RtpStreamCmd)> = vec![
        (
            "beep.wav",
            RtpStreamCmd::Play {
                source: RtpSource::File("beep.wav".into()),
                loops: 1,
                payload_type: None,
                payload_name: None,
            },
        ),
        (
            "coco.wav,-1,0,PCMU/8000",
            RtpStreamCmd::Play {
                source: RtpSource::File("coco.wav".into()),
                loops: -1,
                payload_type: Some(0),
                payload_name: Some("PCMU/8000".into()),
            },
        ),
        (
            "apattern",
            RtpStreamCmd::Play {
                source: RtpSource::Pattern {
                    video: false,
                    id: 1,
                },
                loops: -1,
                payload_type: None,
                payload_name: None,
            },
        ),
        (
            "vpattern,3,96,H264/90000",
            RtpStreamCmd::Play {
                source: RtpSource::Pattern { video: true, id: 3 },
                loops: -1,
                payload_type: Some(96),
                payload_name: Some("H264/90000".into()),
            },
        ),
        ("pause", RtpStreamCmd::Pause { video: None }),
        ("resumevpattern", RtpStreamCmd::Resume { video: Some(true) }),
    ];
    for (value, expected) in cases {
        let xml = wrap(&format!(
            r#"{invite}
               <nop><action><exec rtp_stream="{value}"/></action></nop>"#,
            invite = send_invite()
        ));
        let out = compile("test", &xml);
        assert!(out.diagnostics.is_empty(), "{value}: {:?}", out.diagnostics);
        let sc = out.scenario.expect("compiles");
        let Step::Nop { actions, .. } = &sc.steps[1] else {
            panic!("nop")
        };
        assert!(
            matches!(&actions[0], Action::RtpStream(cmd) if *cmd == expected),
            "{value}: {:?}",
            actions[0]
        );
        assert!(sc.has_media());
    }
    for bad in [
        r#"rtp_stream="""#,
        r#"rtp_stream="f.wav,-2""#,
        r#"rtp_stream="f.wav,1,200""#,
        r#"rtp_stream="apattern,9""#,
        r#"rtp_stream="f.wav" play_dtmf="1""#,
        r#"play_dtmf="""#,
    ] {
        let xml = wrap(&format!(
            r#"{invite}
               <nop><action><exec {bad}/></action></nop>"#,
            invite = send_invite()
        ));
        assert!(!errors(&xml).is_empty(), "{bad}: expected an error");
    }
    let xml = wrap(&format!(
        r#"{invite}
           <nop><action><exec play_dtmf="12#,[$tone]"/></action></nop>"#,
        invite = send_invite()
    ));
    // [$tone] is read but never set → the compiler's usual error, proving the
    // value is a real template.
    assert!(
        errors(&xml).iter().any(|e| e.contains("never set")),
        "{:?}",
        errors(&xml)
    );
}

#[test]
fn hide_and_display_attributes_land_in_step_common() {
    let xml = wrap(&format!(
        r#"{invite}
           <recv response="200" hide="true"/>
           <nop display="Extract Contact" hide="true"/>
           <pause milliseconds="10" display=" "/>"#,
        invite = send_invite()
    ));
    let out = compile("test", &xml);
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    let sc = out.scenario.expect("compiles");
    let Step::Recv(r) = &sc.steps[1] else {
        panic!("recv")
    };
    assert!(r.common.hide);
    assert_eq!(r.common.display, None);
    let Step::Nop { common, .. } = &sc.steps[2] else {
        panic!("nop")
    };
    assert!(common.hide);
    assert_eq!(common.display.as_deref(), Some("Extract Contact"));
    let Step::Pause { common, .. } = &sc.steps[3] else {
        panic!("pause")
    };
    assert!(!common.hide);
    assert_eq!(common.display, None, "blank display is no display");
}
