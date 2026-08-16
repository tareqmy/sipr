//! Inbound SIP message parsing.
//!
//! Planned for `rsip`; implemented in-tree while the workspace stays
//! dependency-free (see docs/MILESTONES.md M2 note). Scope is deliberately
//! what a *test tool's* recv path needs: classify the start line, look up
//! headers (with RFC 3261 compact forms and line folding), and extract the
//! correlation fields — Call-ID, CSeq, top Via branch, From/To tags.
//!
//! Robustness contract: [`Inbound::parse`] and every accessor MUST be
//! panic-free on arbitrary bytes — real devices send garbage
//! (docs/ARCHITECTURE.md §3 rule 5, fuzz tests in `tests/no_panic.rs`).

/// What the start line says this message is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgKind {
    /// `INVITE sip:x SIP/2.0`
    Request {
        /// The method token, verbatim (`INVITE`, `BYE`, ...).
        method: String,
    },
    /// `SIP/2.0 200 OK`
    Response {
        /// The status code.
        code: u16,
        /// The reason phrase, verbatim.
        reason: String,
    },
}

/// Why a datagram was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Empty or whitespace-only datagram.
    Empty,
    /// The start line is neither a SIP request nor a SIP response.
    NotSip,
}

/// A parsed inbound message: owned bytes + lazy header lookups.
///
/// Header access scans on demand — the router only pays for Call-ID, and the
/// engine only pays for the headers a step actually asks for.
#[derive(Debug, Clone)]
pub struct Inbound {
    kind: MsgKind,
    /// Header section as text (lossily decoded; SIP headers are ASCII-ish).
    headers: String,
    /// Message body bytes (after the blank line), verbatim.
    body: Vec<u8>,
}

impl Inbound {
    /// Parse a datagram. Never panics; malformed input yields `Err`.
    ///
    /// # Errors
    ///
    /// [`ParseError::Empty`] for empty input, [`ParseError::NotSip`] when the
    /// start line is not a SIP request or response.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(ParseError::Empty);
        }
        // Split headers from body on the first blank line (tolerate LF-only).
        let (head_bytes, body) = split_head_body(data);
        let head = String::from_utf8_lossy(head_bytes).into_owned();
        let mut lines = head.lines();
        let start = lines.next().unwrap_or_default().trim_end();
        let kind = parse_start_line(start).ok_or(ParseError::NotSip)?;
        // Store headers without the start line, unfolding continuations.
        let mut headers = String::with_capacity(head.len());
        for line in lines {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Folded continuation: append to the previous line.
                while headers.ends_with('\n') || headers.ends_with('\r') {
                    headers.pop();
                }
                headers.push(' ');
                headers.push_str(line.trim_start());
            } else {
                headers.push_str(line.trim_end_matches('\r'));
            }
            headers.push('\n');
        }
        Ok(Self {
            kind,
            headers,
            body: body.to_vec(),
        })
    }

    /// Request or response classification.
    #[must_use]
    pub fn kind(&self) -> &MsgKind {
        &self.kind
    }

    /// The status code, when this is a response.
    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        match &self.kind {
            MsgKind::Response { code, .. } => Some(*code),
            MsgKind::Request { .. } => None,
        }
    }

    /// The request method, when this is a request.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        match &self.kind {
            MsgKind::Request { method } => Some(method),
            MsgKind::Response { .. } => None,
        }
    }

    /// Message body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// First value of `name` (case-insensitive; compact forms resolved),
    /// trimmed. `None` if absent.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_entries(name).next()
    }

    /// All values of `name`, in order (for multi-valued headers).
    #[must_use]
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.header_entries(name).collect()
    }

    /// Full `Name: value` lines for `name`, as received (post-unfolding) —
    /// what `[last_Name:]` substitutes verbatim.
    #[must_use]
    pub fn header_lines(&self, name: &str) -> Vec<&str> {
        self.lines_matching(name).collect()
    }

    /// The Call-ID value.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.header("Call-ID")
    }

    /// CSeq as (number, method).
    #[must_use]
    pub fn cseq(&self) -> Option<(u32, &str)> {
        let v = self.header("CSeq")?;
        let mut parts = v.split_ascii_whitespace();
        let num = parts.next()?.parse().ok()?;
        let method = parts.next()?;
        Some((num, method))
    }

    /// `branch=` parameter of the topmost Via.
    #[must_use]
    pub fn top_via_branch(&self) -> Option<&str> {
        param_value(self.header("Via")?, "branch")
    }

    /// `tag=` parameter of From.
    #[must_use]
    pub fn from_tag(&self) -> Option<&str> {
        param_value(self.header("From")?, "tag")
    }

    /// `tag=` parameter of To.
    #[must_use]
    pub fn to_tag(&self) -> Option<&str> {
        param_value(self.header("To")?, "tag")
    }

    fn header_entries<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> {
        let compact = compact_of(name);
        self.lines_matching_impl(name.to_ascii_lowercase(), compact)
            .filter_map(|line| line.split_once(':').map(|(_, v)| v.trim()))
    }

    fn lines_matching<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> {
        self.lines_matching_impl(name.to_ascii_lowercase(), compact_of(name))
    }

    fn lines_matching_impl(
        &self,
        lower: String,
        compact: Option<char>,
    ) -> impl Iterator<Item = &str> {
        self.headers.lines().filter(move |line| {
            let Some((n, _)) = line.split_once(':') else {
                return false;
            };
            let n = n.trim();
            n.eq_ignore_ascii_case(&lower)
                || (n.len() == 1
                    && compact.is_some_and(|c| {
                        n.chars().next().is_some_and(|f| f.eq_ignore_ascii_case(&c))
                    }))
        })
    }
}

/// RFC 3261 §7.3.3 compact header forms.
fn compact_of(name: &str) -> Option<char> {
    match name.to_ascii_lowercase().as_str() {
        "call-id" => Some('i'),
        "from" => Some('f'),
        "to" => Some('t'),
        "via" => Some('v'),
        "contact" => Some('m'),
        "content-length" => Some('l'),
        "content-type" => Some('c'),
        "subject" => Some('s'),
        "supported" => Some('k'),
        "content-encoding" => Some('e'),
        _ => None,
    }
}

/// Extract `;name=value` from a header value (up to `;` or `,` or end).
fn param_value<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    for part in value.split(';').skip(1) {
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => continue,
        };
        if k.trim().eq_ignore_ascii_case(name) {
            let v = v.trim();
            let v = v.split([',', ' ']).next().unwrap_or(v);
            return Some(v);
        }
    }
    None
}

fn split_head_body(data: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = find(data, b"\r\n\r\n") {
        (&data[..i], &data[i + 4..])
    } else if let Some(i) = find(data, b"\n\n") {
        (&data[..i], &data[i + 2..])
    } else {
        (data, &[])
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_start_line(line: &str) -> Option<MsgKind> {
    if let Some(rest) = line.strip_prefix("SIP/2.0 ") {
        let mut parts = rest.splitn(2, ' ');
        let code: u16 = parts.next()?.parse().ok()?;
        if !(100..=699).contains(&code) {
            return None;
        }
        return Some(MsgKind::Response {
            code,
            reason: parts.next().unwrap_or_default().to_owned(),
        });
    }
    // Request: METHOD SP URI SP SIP/2.0
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next()?;
    let _uri = parts.next()?;
    let version = parts.next()?;
    if version != "SIP/2.0" || parts.next().is_some() {
        return None;
    }
    if method.is_empty() || !method.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(MsgKind::Request {
        method: method.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &[u8] = b"INVITE sip:service@10.0.0.2:5060 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5061;branch=z9hG4bK-1-1-7\r\n\
        From: sipr <sip:sipr@10.0.0.1>;tag=1a2b3c\r\n\
        To: service <sip:service@10.0.0.2>\r\n\
        Call-ID: 1-42@10.0.0.1\r\n\
        CSeq: 1 INVITE\r\n\
        Record-Route: <sip:p1;lr>\r\n\
        Record-Route: <sip:p2;lr>\r\n\
        Content-Length: 5\r\n\
        \r\n\
        v=0\r\n";

    #[test]
    fn parses_request_essentials() {
        let m = Inbound::parse(INVITE).unwrap();
        assert_eq!(m.method(), Some("INVITE"));
        assert_eq!(m.call_id(), Some("1-42@10.0.0.1"));
        assert_eq!(m.cseq(), Some((1, "INVITE")));
        assert_eq!(m.top_via_branch(), Some("z9hG4bK-1-1-7"));
        assert_eq!(m.from_tag(), Some("1a2b3c"));
        assert_eq!(m.to_tag(), None);
        assert_eq!(m.body(), b"v=0\r\n");
    }

    #[test]
    fn parses_response_and_reason() {
        let m = Inbound::parse(b"SIP/2.0 180 Ringing\r\nCall-ID: x\r\n\r\n").unwrap();
        assert_eq!(m.status_code(), Some(180));
        assert_eq!(
            m.kind(),
            &MsgKind::Response {
                code: 180,
                reason: "Ringing".into()
            }
        );
    }

    #[test]
    fn multi_value_headers_keep_order() {
        let m = Inbound::parse(INVITE).unwrap();
        assert_eq!(
            m.header_values("Record-Route"),
            vec!["<sip:p1;lr>", "<sip:p2;lr>"]
        );
        assert_eq!(m.header_lines("Record-Route").len(), 2);
        assert!(m.header_lines("Record-Route")[0].starts_with("Record-Route:"));
    }

    #[test]
    fn compact_forms_resolve() {
        let m =
            Inbound::parse(b"OPTIONS sip:x SIP/2.0\r\ni: compact-id\r\nf: <sip:a>;tag=t1\r\n\r\n")
                .unwrap();
        assert_eq!(m.call_id(), Some("compact-id"));
        assert_eq!(m.from_tag(), Some("t1"));
    }

    #[test]
    fn folded_headers_unfold() {
        let m = Inbound::parse(
            b"OPTIONS sip:x SIP/2.0\r\nSubject: first\r\n second\r\nCall-ID: y\r\n\r\n",
        )
        .unwrap();
        assert_eq!(m.header("Subject"), Some("first second"));
        assert_eq!(m.call_id(), Some("y"));
    }

    #[test]
    fn lf_only_messages_tolerated() {
        let m = Inbound::parse(b"BYE sip:x SIP/2.0\nCall-ID: z\n\nbody").unwrap();
        assert_eq!(m.method(), Some("BYE"));
        assert_eq!(m.call_id(), Some("z"));
        assert_eq!(m.body(), b"body");
    }

    #[test]
    fn garbage_is_rejected_not_panicked() {
        assert_eq!(Inbound::parse(b"").unwrap_err(), ParseError::Empty);
        assert_eq!(Inbound::parse(b"   \r\n").unwrap_err(), ParseError::Empty);
        assert_eq!(
            Inbound::parse(b"GET / HTTP/1.1\r\n\r\n").unwrap_err(),
            ParseError::NotSip
        );
        assert_eq!(
            Inbound::parse(b"SIP/2.0 999 Nope\r\n\r\n").unwrap_err(),
            ParseError::NotSip
        );
        assert_eq!(
            Inbound::parse(&[0xff, 0xfe, 0x00, 0x01]).unwrap_err(),
            ParseError::NotSip
        );
    }

    #[test]
    fn non_utf8_headers_survive_lossily() {
        let mut raw = b"INVITE sip:x SIP/2.0\r\nCall-ID: ok\r\nX-Junk: \xff\xfe\r\n\r\n".to_vec();
        let m = Inbound::parse(&raw).unwrap();
        assert_eq!(m.call_id(), Some("ok"));
        raw.truncate(10); // truncated mid start line
        let _ = Inbound::parse(&raw); // must not panic
    }
}
