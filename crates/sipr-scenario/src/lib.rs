//! `sipr-scenario`: the scenario front end — SIPp-compatible XML parsing,
//! keyword tokenization, actions, and the compiled step IR.
//!
//! Entry point: [`compile`], which turns scenario XML into a [`model::Scenario`]
//! (a flat step list in message-index order) plus loud [`diag::Diagnostic`]s
//! for everything unknown or unsupported. See `docs/SIPP_COMPAT.md` for the
//! implemented surface and `docs/ARCHITECTURE.md` §3.3 for the IR design.
//!
//! Also hosts the embedded default scenarios behind SIPp's `-sn`/`-sd` flags:
//! clean-room ports of SIPp's classic `uac`/`uas` flows and of its
//! `ooc_default`/`ooc_dummy` out-of-call responders (`-oocsn`) —
//! functionally identical (same steps, attributes, keywords) so the two
//! tools interop out of the box.

mod compile;
pub mod diag;
pub mod distribution;
pub mod inject;
pub mod model;
pub mod regex;
pub mod template;
mod xml;

pub use compile::{CompileOutcome, compile};

/// Names accepted by `-sn`, `-sd` and `-oocsn`, in display order.
pub const EMBEDDED_NAMES: &[&str] = &["uac", "uas", "ooc_default", "ooc_dummy"];

/// Returns the embedded default scenario XML for `name` (`"uac"`, `"uas"`,
/// `"ooc_default"`, `"ooc_dummy"`).
#[must_use]
pub fn embedded(name: &str) -> Option<&'static str> {
    match name {
        "uac" => Some(include_str!("../assets/uac.xml")),
        "uas" => Some(include_str!("../assets/uas.xml")),
        "ooc_default" => Some(include_str!("../assets/ooc_default.xml")),
        "ooc_dummy" => Some(include_str!("../assets/ooc_dummy.xml")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_names_resolve() {
        for name in EMBEDDED_NAMES {
            let xml = embedded(name).unwrap();
            assert!(
                xml.contains("<scenario name="),
                "{name}: missing <scenario>"
            );
            assert!(xml.ends_with("</scenario>\n"), "{name}: bad tail");
        }
    }

    #[test]
    fn unknown_name_is_none() {
        assert!(embedded("uac_pcap").is_none());
        assert!(embedded("").is_none());
    }

    #[test]
    fn embedded_scenarios_compile_clean() {
        for name in EMBEDDED_NAMES {
            let out = compile(name, embedded(name).unwrap());
            assert!(out.diagnostics.is_empty(), "{name}: {:?}", out.diagnostics);
            assert!(out.scenario.is_some(), "{name}: no scenario");
        }
    }

    #[test]
    fn embedded_roles_are_correct() {
        use model::Role;
        let uac = compile("uac", embedded("uac").unwrap()).scenario.unwrap();
        assert_eq!(uac.role, Role::Uac);
        assert_eq!(uac.steps.len(), 9); // INVITE 100 180 183 200 ACK pause BYE 200
        assert_eq!(uac.response_time_repartition.len(), 8);
        let uas = compile("uas", embedded("uas").unwrap()).scenario.unwrap();
        assert_eq!(uas.role, Role::Uas);
        assert!(matches!(
            uas.steps.last(),
            Some(model::Step::Timewait { ms: 4000, .. })
        ));
    }

    #[test]
    fn embedded_ooc_scenarios_answer_or_reject_any_request() {
        use model::{Role, Step};
        // ooc_default: recv any request (regexp), send 200, linger 4 s.
        let ooc = compile("ooc_default", embedded("ooc_default").unwrap())
            .scenario
            .unwrap();
        assert_eq!(ooc.name, "Out-of-call UAS");
        assert_eq!(ooc.role, Role::Uas);
        assert_eq!(ooc.steps.len(), 3);
        assert!(matches!(
            &ooc.steps[0],
            Step::Recv(r) if r.regexp_match && matches!(&r.expect, model::Expect::Request(m) if m == ".*")
        ));
        assert!(matches!(&ooc.steps[1], Step::Send(_)));
        assert!(matches!(&ooc.steps[2], Step::Timewait { ms: 4000, .. }));
        assert!(!ooc.uses_injection_fields());
        // ooc_dummy: a recv nobody satisfies, so every spawned call fails.
        let dummy = compile("ooc_dummy", embedded("ooc_dummy").unwrap())
            .scenario
            .unwrap();
        assert_eq!(dummy.steps.len(), 1);
        assert!(matches!(&dummy.steps[0], Step::Recv(_)));
    }

    #[test]
    fn injection_field_use_is_detected() {
        let xml = r#"<scenario name="f">
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
</scenario>"#;
        let sc = compile("f", xml).scenario.unwrap();
        assert!(sc.uses_injection_fields());
    }
}
