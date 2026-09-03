//! Message templates: the pre-tokenized form of `<send>` CDATA bodies.
//!
//! Templates are tokenized ONCE at scenario load into literal and keyword
//! spans; per-send work is slot filling only (docs/ARCHITECTURE.md §3, hot
//! path rule 2). Unknown `[keywords]` warn loudly and pass through verbatim
//! (SIPp behavior — IPv6 literals like `[2001:db8::1]` depend on it).
//!
//! Normalization applied to CDATA before tokenizing, mirroring SIPp: every
//! line is left-trimmed (scenarios are indented for readability), line
//! endings become CRLF, leading/trailing blank lines are dropped, and the
//! message ends with a single trailing CRLF. An internal blank line (the
//! header/body separator) is preserved. Recorded in docs/SIPP_COMPAT.md §6.

use crate::diag::Diagnostics;

/// One span of a tokenized template.
#[derive(Debug, Clone, PartialEq)]
pub enum Span {
    /// Literal bytes, emitted as-is.
    Lit(String),
    /// A keyword slot, filled at send time.
    Kw(Keyword),
}

/// The v1 keyword set — docs/SIPP_COMPAT.md §2.
#[derive(Debug, Clone, PartialEq)]
pub enum Keyword {
    /// `[service]` — the `-s` value.
    Service,
    /// `[remote_ip]`
    RemoteIp,
    /// `[remote_port]`
    RemotePort,
    /// `[local_ip]`
    LocalIp,
    /// `[local_ip_type]` — `4` or `6`.
    LocalIpType,
    /// `[local_port]`
    LocalPort,
    /// `[transport]` — `UDP` / `TCP` / `TLS`.
    Transport,
    /// `[call_id]`
    CallId,
    /// `[call_number]` — 1-based call counter.
    CallNumber,
    /// `[userid]` — this call's 1-based user id (`-users` mode; 0 otherwise).
    UserId,
    /// `[users]` — the configured `-users` count (0 when not in users mode).
    Users,
    /// `[cseq]` — current CSeq value.
    Cseq,
    /// `[branch]` — per-transaction Via branch.
    Branch,
    /// `[msg_index]` — current step index.
    MsgIndex,
    /// `[pid]` — process id discriminator.
    Pid,
    /// `[routes]` — Route header set captured via `rrs`.
    Routes,
    /// `[next_url]` — request-URI for in-dialog requests.
    NextUrl,
    /// `[peer_tag_param]` — `;tag=X` of the peer, or empty.
    PeerTagParam,
    /// `[len]` — computed Content-Length (body bytes after substitution).
    Len,
    /// `[media_ip]` — the `-mi` media address (defaults to the local IP).
    MediaIp,
    /// `[media_port]` / `[auto_media_port]`, optionally with a `+N` offset
    /// (`[media_port+1]` for RTCP, `[media_port+2]` for video). `media_port`
    /// is the `-mp` base for every call; `auto_media_port` reserves a
    /// 4-port block per call (`base + 4*(call_number-1) % 10000`), as SIPp.
    MediaPort {
        /// `auto_media_port` (per-call block) vs plain `media_port`.
        auto: bool,
        /// The `+N` suffix, 0 when absent.
        offset: u16,
    },
    /// `[media_ip_type]` — `4` or `6` for the media address.
    MediaIpType,
    /// `[last_Name:]` — verbatim copy of header(s) from the last received
    /// message. The stored string is the header name without the colon.
    Last(String),
    /// `[$name]` — a call variable reference (resolved to an index later).
    Var(String),
    /// `[authentication ...]` with its `key=value` parameters.
    Authentication(Vec<(String, String)>),
    /// `[fieldN]` — a value from an `-inf` injection file. `file` names the
    /// file (SIPp's basename key) or gives its 0-based `-inf` index; `None`
    /// means the first file. `line` overrides the per-call line.
    Field {
        /// 0-based field index within the row.
        index: usize,
        /// `file=` spec: a basename or a numeric `-inf` index. `None` = first.
        file: Option<String>,
        /// `line=` override (`line=M` or `line=[$var]`), else the call's line.
        line: Option<LineExpr>,
    },
    /// Unrecognized keyword: emitted verbatim (including brackets).
    Unknown(String),
}

/// The `line=` selector of a `[fieldN]` keyword. SIPp renders this as a
/// sub-message; we support the two forms that actually occur: a literal line
/// number and a single variable reference (the shape `lookup` produces).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineExpr {
    /// `line=M` — a fixed 0-based line.
    Literal(usize),
    /// `line=[$var]` / `line=$var` — resolved from a call variable at send time.
    Var(String),
}

/// A tokenized message template.
#[derive(Debug, Clone, PartialEq)]
pub struct MsgTemplate {
    /// Ordered spans; rendering concatenates them.
    pub spans: Vec<Span>,
}

impl MsgTemplate {
    /// All keyword spans, in order.
    pub fn keywords(&self) -> impl Iterator<Item = &Keyword> {
        self.spans.iter().filter_map(|s| match s {
            Span::Kw(k) => Some(k),
            Span::Lit(_) => None,
        })
    }
}

/// Normalize raw CDATA into wire-shaped text (CRLF, left-trimmed lines).
#[must_use]
pub fn normalize_cdata(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().map(str::trim_start).collect();
    let first = lines.iter().position(|l| !l.is_empty());
    let last = lines.iter().rposition(|l| !l.is_empty());
    let (Some(first), Some(last)) = (first, last) else {
        return String::new();
    };
    let mut out = String::with_capacity(raw.len());
    for line in &lines[first..=last] {
        out.push_str(line.trim_end_matches('\r'));
        out.push_str("\r\n");
    }
    // Every SIP message needs the header/body separator (RFC 3261 §7): an empty
    // line after the last header, even with no body. Trimming trailing blank
    // lines above drops it for body-less messages (180, ACK, empty 200); UDP
    // datagrams tolerate the omission, but TCP framing keys on `\r\n\r\n`, and
    // real SIPp expects it. Restore it when the message carries no body.
    if !out.contains("\r\n\r\n") {
        out.push_str("\r\n");
    }
    out
}

/// Tokenize normalized template text into spans.
///
/// `line` is the CDATA's source line, used for diagnostics.
#[must_use]
pub fn tokenize(text: &str, line: u32, diags: &mut Diagnostics) -> MsgTemplate {
    let mut spans: Vec<Span> = Vec::new();
    let mut lit = String::new();
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        // Find the matching ']' at bracket depth 0, allowing balanced nested
        // brackets (SIPp permits `[field0 line=[$1]]`). A keyword never spans a
        // line, so a newline before the close means this '[' is just a literal
        // (IPv6 literals and stray brackets rely on this).
        let Some(close) = matching_close(after) else {
            lit.push_str(&rest[..=open]);
            rest = after;
            continue;
        };
        lit.push_str(&rest[..open]);
        let body = &after[..close];
        rest = &after[close + 1..];
        match classify(body) {
            Classified::Keyword(kw) => {
                if !lit.is_empty() {
                    spans.push(Span::Lit(std::mem::take(&mut lit)));
                }
                spans.push(Span::Kw(kw));
            }
            Classified::Unknown => {
                diags.warn(
                    Some(line),
                    format!("unknown keyword '[{body}]' — passed through verbatim"),
                );
                lit.push('[');
                lit.push_str(body);
                lit.push(']');
            }
        }
    }
    lit.push_str(rest);
    if !lit.is_empty() {
        spans.push(Span::Lit(lit));
    }
    MsgTemplate { spans }
}

/// Offset of the `]` that closes the keyword opened just before `after`,
/// scanning at bracket depth 0. `None` if a newline arrives first (keywords
/// never span lines) or the brackets never balance.
fn matching_close(after: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (i, c) in after.char_indices() {
        match c {
            '\n' => return None,
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

enum Classified {
    Keyword(Keyword),
    Unknown,
}

fn classify(body: &str) -> Classified {
    // `[$var]`
    if let Some(name) = body.strip_prefix('$') {
        if !name.is_empty() && name.chars().all(is_var_char) {
            return Classified::Keyword(Keyword::Var(name.to_owned()));
        }
        return Classified::Unknown;
    }
    // `[last_Header:]`
    if let Some(rest) = body.strip_prefix("last_") {
        let name = rest.strip_suffix(':').unwrap_or(rest);
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Classified::Keyword(Keyword::Last(name.to_owned()));
        }
        return Classified::Unknown;
    }
    let (name, params) = match body.split_once(char::is_whitespace) {
        Some((n, p)) => (n, p.trim()),
        None => (body, ""),
    };
    let simple = |kw: Keyword| -> Classified {
        if params.is_empty() {
            Classified::Keyword(kw)
        } else {
            Classified::Unknown
        }
    };
    match name {
        "service" => simple(Keyword::Service),
        "remote_ip" => simple(Keyword::RemoteIp),
        "remote_port" => simple(Keyword::RemotePort),
        "local_ip" => simple(Keyword::LocalIp),
        "local_ip_type" => simple(Keyword::LocalIpType),
        "local_port" => simple(Keyword::LocalPort),
        "transport" => simple(Keyword::Transport),
        "call_id" => simple(Keyword::CallId),
        "call_number" => simple(Keyword::CallNumber),
        "userid" => simple(Keyword::UserId),
        "users" => simple(Keyword::Users),
        "cseq" => simple(Keyword::Cseq),
        "branch" => simple(Keyword::Branch),
        "msg_index" => simple(Keyword::MsgIndex),
        "pid" => simple(Keyword::Pid),
        "routes" => simple(Keyword::Routes),
        "next_url" => simple(Keyword::NextUrl),
        "peer_tag_param" => simple(Keyword::PeerTagParam),
        "len" => simple(Keyword::Len),
        "media_ip" => simple(Keyword::MediaIp),
        "media_ip_type" => simple(Keyword::MediaIpType),
        "authentication" => Classified::Keyword(Keyword::Authentication(parse_params(params))),
        _ => match classify_media_port(name) {
            Some(kw) => simple(kw),
            None => classify_field(name, params),
        },
    }
}

/// `[media_port]`, `[auto_media_port]`, and their `+N` offset forms.
fn classify_media_port(name: &str) -> Option<Keyword> {
    let (auto, rest) = if let Some(r) = name.strip_prefix("auto_media_port") {
        (true, r)
    } else if let Some(r) = name.strip_prefix("media_port") {
        (false, r)
    } else {
        return None;
    };
    let offset = if rest.is_empty() {
        0
    } else {
        rest.strip_prefix('+')?.parse::<u16>().ok()?
    };
    Some(Keyword::MediaPort { auto, offset })
}

/// `[fieldN]`, `[fieldN file=NAME]`, `[fieldN line=M|[$var]]` — an
/// injection-file value.
fn classify_field(name: &str, params: &str) -> Classified {
    let Some(idx) = name.strip_prefix("field") else {
        return Classified::Unknown;
    };
    let Ok(index) = idx.parse::<usize>() else {
        return Classified::Unknown;
    };
    let mut file = None;
    let mut line = None;
    for (k, v) in parse_params(params) {
        match k.as_str() {
            "file" => file = Some(v),
            "line" => match parse_line_expr(&v) {
                Some(e) => line = Some(e),
                None => return Classified::Unknown,
            },
            _ => return Classified::Unknown,
        }
    }
    Classified::Keyword(Keyword::Field { index, file, line })
}

/// Parse a `line=` value: a literal number, or a `[$var]` / `$var` reference.
fn parse_line_expr(v: &str) -> Option<LineExpr> {
    if let Ok(n) = v.parse::<usize>() {
        return Some(LineExpr::Literal(n));
    }
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(v);
    let name = inner.strip_prefix('$')?;
    if !name.is_empty() && name.chars().all(is_var_char) {
        Some(LineExpr::Var(name.to_owned()))
    } else {
        None
    }
}

fn is_var_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn parse_params(s: &str) -> Vec<(String, String)> {
    s.split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(text: &str) -> (MsgTemplate, Vec<String>) {
        let mut d = Diagnostics::new("test");
        let t = tokenize(text, 1, &mut d);
        let msgs = d.into_items().into_iter().map(|i| i.message).collect();
        (t, msgs)
    }

    #[test]
    fn normalize_left_trims_and_crlf_joins() {
        let raw = "\n\n      INVITE sip:x SIP/2.0\n      Via: y\n\n      v=0\n\n    ";
        let text = normalize_cdata(raw);
        assert_eq!(text, "INVITE sip:x SIP/2.0\r\nVia: y\r\n\r\nv=0\r\n");
    }

    #[test]
    fn normalize_empty_is_empty() {
        assert_eq!(normalize_cdata("  \n \n"), "");
    }

    #[test]
    fn normalize_bodyless_message_keeps_separator() {
        // A no-body message must still end with the header/body blank line so
        // TCP framing (and real SIPp) can find its boundary.
        let raw = "\n  SIP/2.0 180 Ringing\n  CSeq: 1 INVITE\n  Content-Length: 0\n";
        let text = normalize_cdata(raw);
        assert_eq!(
            text,
            "SIP/2.0 180 Ringing\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        );
        assert!(text.ends_with("\r\n\r\n"));
        // A message that already has a body keeps its single separator.
        let with_body = normalize_cdata("INVITE x\nVia: y\n\nv=0\n");
        assert_eq!(with_body, "INVITE x\r\nVia: y\r\n\r\nv=0\r\n");
    }

    #[test]
    fn tokenizes_simple_keywords_and_literals() {
        let (t, warns) = tok("INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\r\n");
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(
            t.spans,
            vec![
                Span::Lit("INVITE sip:".into()),
                Span::Kw(Keyword::Service),
                Span::Lit("@".into()),
                Span::Kw(Keyword::RemoteIp),
                Span::Lit(":".into()),
                Span::Kw(Keyword::RemotePort),
                Span::Lit(" SIP/2.0\r\n".into()),
            ]
        );
    }

    #[test]
    fn last_and_var_and_auth_keywords() {
        let (t, warns) =
            tok("[last_Call-ID:]\r\nX: [$1]\r\n[authentication username=joe password=x]\r\n");
        assert!(warns.is_empty(), "{warns:?}");
        let kws: Vec<_> = t.keywords().collect();
        assert_eq!(kws[0], &Keyword::Last("Call-ID".into()));
        assert_eq!(kws[1], &Keyword::Var("1".into()));
        assert_eq!(
            kws[2],
            &Keyword::Authentication(vec![
                ("username".into(), "joe".into()),
                ("password".into(), "x".into()),
            ])
        );
    }

    #[test]
    fn unknown_keyword_warns_and_passes_verbatim() {
        let (t, warns) = tok("X: [definitely_not_a_keyword]\r\n");
        assert_eq!(warns.len(), 1);
        assert!(warns[0].contains("[definitely_not_a_keyword]"), "{warns:?}");
        assert_eq!(
            t.spans,
            vec![Span::Lit("X: [definitely_not_a_keyword]\r\n".into())]
        );
    }

    #[test]
    fn ipv6_literal_passes_through_with_warning_only() {
        let (t, warns) = tok("Via: SIP/2.0/UDP [2001:db8::1]:5060\r\n");
        assert_eq!(warns.len(), 1);
        assert!(matches!(&t.spans[0], Span::Lit(l) if l.contains("[2001:db8::1]:5060")));
    }

    #[test]
    fn unmatched_bracket_is_literal() {
        let (t, warns) = tok("a [ b\r\nc]\r\n");
        assert!(warns.is_empty(), "keyword must not span lines: {warns:?}");
        assert_eq!(t.spans, vec![Span::Lit("a [ b\r\nc]\r\n".into())]);
    }

    #[test]
    fn media_placeholders_recognized() {
        let (t, warns) =
            tok("c=IN IP[media_ip_type] [media_ip]\r\nm=audio [media_port] RTP/AVP 0\r\n");
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(t.keywords().count(), 3);
    }

    #[test]
    fn embedded_scenarios_tokenize_without_warnings() {
        for name in crate::EMBEDDED_NAMES {
            let xml = crate::embedded(name).unwrap();
            let mut d = Diagnostics::new(name);
            // Crude but effective: every CDATA in the file must tokenize clean.
            let root = crate::xml::parse(xml).unwrap();
            for el in root.child_elements() {
                for node in &el.children {
                    if let crate::xml::Node::CData { text, line } = node {
                        let _ = tokenize(&normalize_cdata(text), *line, &mut d);
                    }
                }
            }
            let warns: Vec<_> = d.into_items();
            assert!(warns.is_empty(), "{name}: {warns:?}");
        }
    }
}
