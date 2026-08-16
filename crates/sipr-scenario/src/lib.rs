//! `sipr-scenario`: the scenario front end — SIPp-compatible XML parsing,
//! keyword tokenization, actions, and the compiled step IR.
//!
//! Entry point: [`compile`], which turns scenario XML into a [`model::Scenario`]
//! (a flat step list in message-index order) plus loud [`diag::Diagnostic`]s
//! for everything unknown or unsupported. See `docs/SIPP_COMPAT.md` for the
//! implemented surface and `docs/ARCHITECTURE.md` §3.3 for the IR design.
//!
//! Also hosts the embedded default scenarios behind SIPp's `-sn`/`-sd` flags:
//! clean-room ports of SIPp's classic `uac`/`uas` flows — functionally
//! identical (same steps, attributes, keywords) so the two tools interop out
//! of the box.

mod compile;
pub mod diag;
pub mod model;
pub mod template;
mod xml;

pub use compile::{CompileOutcome, compile};

/// Names accepted by `-sn` and `-sd`, in display order.
pub const EMBEDDED_NAMES: &[&str] = &["uac", "uas"];

/// Returns the embedded default scenario XML for `name` (`"uac"` / `"uas"`).
#[must_use]
pub fn embedded(name: &str) -> Option<&'static str> {
    match name {
        "uac" => Some(include_str!("../assets/uac.xml")),
        "uas" => Some(include_str!("../assets/uas.xml")),
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
}
