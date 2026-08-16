//! `sipr-scenario`: the scenario model — SIPp-compatible XML parsing, keyword
//! tokenization, actions, and the compiled step IR (all landing in M1; see
//! `docs/MILESTONES.md` and `docs/SIPP_COMPAT.md`).
//!
//! What exists today (M0): the embedded default scenarios behind SIPp's
//! `-sn`/`-sd` flags. They are clean-room ports of SIPp's classic `uac`/`uas`
//! flows — functionally identical (same steps, attributes, and keywords, which
//! interop requires) so `sipr -sn uac` can drive `sipp -sn uas` and vice versa.

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
    fn uac_shape() {
        let xml = embedded("uac").unwrap();
        // first message command is the INVITE send; flow ends with BYE / 200
        let first_cmd = xml.find("<send").unwrap();
        assert!(xml.find("<recv").unwrap() > first_cmd);
        for needle in [
            "INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0",
            "branch=[branch]",
            "Call-ID: [call_id]",
            "Content-Length: [len]",
            "[peer_tag_param]",
            "<recv response=\"100\" optional=\"true\"/>",
            "<recv response=\"200\" rtd=\"true\"/>",
            "<pause/>",
            "CSeq: 2 BYE",
            "<ResponseTimeRepartition",
            "<CallLengthRepartition",
        ] {
            assert!(xml.contains(needle), "uac missing: {needle}");
        }
    }

    #[test]
    fn uas_shape() {
        let xml = embedded("uas").unwrap();
        // first message command is the INVITE recv
        let first_cmd = xml.find("<recv").unwrap();
        assert!(xml.find("<send").unwrap() > first_cmd);
        for needle in [
            "<recv request=\"INVITE\"",
            "SIP/2.0 180 Ringing",
            "SIP/2.0 200 OK",
            "[last_Via:]",
            "[last_Record-Route:]",
            "[last_To:];tag=[pid]SIPrTag01[call_number]",
            "<recv request=\"BYE\"/>",
            "<timewait milliseconds=\"4000\"/>",
        ] {
            assert!(xml.contains(needle), "uas missing: {needle}");
        }
    }
}
