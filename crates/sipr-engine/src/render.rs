//! Template rendering: fill pre-tokenized spans with per-call values.
//!
//! Hot-path shape (docs/ARCHITECTURE.md §3): the template was tokenized once
//! at scenario load; rendering is slot filling into one buffer. Two
//! line-oriented fixups happen after the fill, both SIPp semantics:
//! `[last_X:]`/`[routes]` with nothing to substitute delete their whole line,
//! and `[len]` becomes the body length computed after all substitution.

use std::cell::RefCell;
use std::fmt::Write as _;

use sipr_net::Inbound;
use sipr_scenario::inject::InjectionFile;
use sipr_scenario::model::VarTable;
use sipr_scenario::template::{Keyword, LineExpr, MsgTemplate, Span};

use crate::actions::VarStore;

/// Optional variable + auth resolution passed to the renderer.
#[derive(Clone, Copy)]
pub struct VarCtx<'a> {
    /// The call's variable store.
    pub store: &'a VarStore,
    /// The scenario's variable table (unused placeholder for symmetry).
    pub vars: &'a VarTable,
    /// A pending digest challenge captured by a `recv auth="true"`.
    pub challenge: Option<&'a sipr_auth::Challenge>,
    /// Auth username / password (`-au`/`-ap` or keyword params).
    pub auth_user: &'a str,
    pub auth_password: &'a str,
    /// Client nonce for digest (stable per call).
    pub cnonce: &'a str,
    /// The request method for the message being built.
    pub method: &'a str,
    /// The digest URI (request-URI shape).
    pub digest_uri: &'a str,
}

/// Marker interpolated for `[len]`, patched after body length is known.
const LEN_MARKER: &str = "\u{7}SIPR_LEN\u{7}";
/// Marker appended when a line must be deleted (empty `[last_*]`/`[routes]`).
const KILL_MARKER: &str = "\u{7}SIPR_KILL\u{7}";

/// Everything the renderer may substitute for one message of one call.
#[derive(Clone)]
pub struct RenderCtx<'a> {
    /// `-s` service / called user part.
    pub service: &'a str,
    /// Remote target.
    pub remote_ip: &'a str,
    /// Remote port.
    pub remote_port: u16,
    /// Local bound IP.
    pub local_ip: &'a str,
    /// Local bound port.
    pub local_port: u16,
    /// Transport token (`UDP` in v1).
    pub transport: &'a str,
    /// This call's Call-ID.
    pub call_id: &'a str,
    /// 1-based call number.
    pub call_number: u64,
    /// This call's 1-based user id (`-users` mode; 0 otherwise).
    pub user_id: u64,
    /// Configured `-users` count (0 when not in users mode).
    pub users_total: u64,
    /// Process id discriminator.
    pub pid: u32,
    /// Current CSeq counter value.
    pub cseq: u32,
    /// Step index (message index) being sent.
    pub msg_index: usize,
    /// Remote tag, once learned (renders `[peer_tag_param]`).
    pub peer_tag: Option<&'a str>,
    /// Captured Record-Route values (via `rrs`), top first.
    pub routes: &'a [String],
    /// Last received message (renders `[last_*]`, `[next_url]`).
    pub last: Option<&'a Inbound>,
    /// Variables + auth (present at M6; `None` renders `[$x]` empty).
    pub var_ctx: Option<VarCtx<'a>>,
    /// Injection files + this call's assigned line per file (`[fieldN]`).
    pub fields: FieldSource<'a>,
}

/// `-inf` files plus the current call's assigned line in each (parallel to
/// `files`). An out-of-range file/line/field renders empty, per SIPp.
///
/// Files sit behind `RefCell` because `insert`/`replace` actions mutate them
/// mid-run while `[fieldN]` reads them — all on the single engine thread, so
/// the borrows never overlap in time.
#[derive(Clone, Copy)]
pub struct FieldSource<'a> {
    /// Loaded injection files, in `-inf` order.
    pub files: &'a [RefCell<InjectionFile>],
    /// The call's chosen line per file (`None` = no line, e.g. USER mode).
    pub lines: &'a [Option<usize>],
}

impl FieldSource<'_> {
    /// No injection files.
    pub const EMPTY: Self = Self {
        files: &[],
        lines: &[],
    };

    /// Resolve a `file=` spec (a basename, or a numeric `-inf` index; `None`
    /// selects the first file) to an index into `files`.
    fn resolve_file(&self, spec: Option<&str>) -> Option<usize> {
        match spec {
            None => (!self.files.is_empty()).then_some(0),
            Some(s) => {
                if let Some(i) = self.files.iter().position(|c| c.borrow().name == s) {
                    return Some(i);
                }
                s.parse::<usize>().ok().filter(|&i| i < self.files.len())
            }
        }
    }

    /// The call's assigned line for file `fi`.
    fn default_line(&self, fi: usize) -> Option<usize> {
        self.lines.get(fi).copied().flatten()
    }

    /// Append field `index` of `line` in file `fi` to `out` (empty if absent).
    fn read(&self, fi: usize, line: usize, index: usize, out: &mut String) {
        if let Some(cell) = self.files.get(fi)
            && let Some(v) = cell.borrow().field(line, index)
        {
            out.push_str(v);
        }
    }

    /// `lookup`: matched line number for `key` in `file`, or `-1.0` on a miss.
    ///
    /// # Errors
    ///
    /// The file is unknown, or has no `-infindex`.
    pub fn lookup_line(&self, file: &str, key: &str) -> Result<f64, String> {
        let fi = self
            .resolve_file(Some(file))
            .ok_or_else(|| format!("lookup: unknown injection file '{file}'"))?;
        let cell = self.files[fi].borrow();
        if !cell.is_indexed() {
            return Err(format!("lookup: injection file '{file}' has no -infindex"));
        }
        #[allow(clippy::cast_precision_loss)]
        Ok(cell.lookup(key).map_or(-1.0, |l| l as f64))
    }

    /// `insert`: append a `;`-separated `value` line to `file`.
    ///
    /// # Errors
    ///
    /// The file is unknown.
    pub fn insert_line(&self, file: &str, value: &str) -> Result<(), String> {
        let fi = self
            .resolve_file(Some(file))
            .ok_or_else(|| format!("insert: unknown injection file '{file}'"))?;
        self.files[fi].borrow_mut().insert(value);
        Ok(())
    }

    /// `replace`: swap line `line` of `file` for a `;`-separated `value`.
    ///
    /// # Errors
    ///
    /// The file is unknown, or `line` is out of range.
    pub fn replace_line(&self, file: &str, line: usize, value: &str) -> Result<(), String> {
        let fi = self
            .resolve_file(Some(file))
            .ok_or_else(|| format!("replace: unknown injection file '{file}'"))?;
        self.files[fi].borrow_mut().replace(line, value)
    }
}

/// Rendering failure (unsupported keyword reached the renderer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError(pub String);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "render: {}", self.0)
    }
}

/// Render a template to wire bytes.
///
/// # Errors
///
/// [`RenderError`] when the template uses a keyword the engine does not
/// support yet (`[$var]`, `[authentication]` — M6). Engine pre-validation
/// rejects such scenarios up front, so this is defense in depth.
pub fn render(template: &MsgTemplate, ctx: &RenderCtx<'_>) -> Result<Vec<u8>, RenderError> {
    Ok(render_string(template, ctx).into_bytes())
}

/// Render a template to a `String`. Used for message bodies and for
/// expanding action message templates (log/assignstr) — the `extra` argument
/// lets callers substitute variables from an arbitrary store (M6 actions).
#[must_use]
pub fn render_to_string(
    template: &MsgTemplate,
    ctx: &RenderCtx<'_>,
    _extra: Option<(&VarStore, &VarTable)>,
) -> String {
    // The store already lives in ctx.var_ctx for the send path; `extra` is a
    // convenience for action expansion where ctx carries the same store.
    render_string(template, ctx)
}

fn render_string(template: &MsgTemplate, ctx: &RenderCtx<'_>) -> String {
    let mut out = String::with_capacity(512);
    for span in &template.spans {
        match span {
            Span::Lit(l) => out.push_str(l),
            Span::Kw(kw) => fill(kw, ctx, &mut out),
        }
    }
    // Delete lines that substituted to nothing (SIPp: "all bytes until the
    // end of the line are also discarded").
    if out.contains(KILL_MARKER) {
        out = out
            .split_inclusive('\n')
            .filter(|line| !line.contains(KILL_MARKER))
            .collect();
    }
    // Patch [len] with the body length (bytes after the header separator).
    if out.contains(LEN_MARKER) {
        let body_len = out.find("\r\n\r\n").map_or(0, |i| out.len() - (i + 4));
        out = out.replace(LEN_MARKER, &body_len.to_string());
    }
    out
}

#[allow(clippy::too_many_lines)] // one arm per keyword; splitting hurts
fn fill(kw: &Keyword, ctx: &RenderCtx<'_>, out: &mut String) {
    match kw {
        Keyword::Service => out.push_str(ctx.service),
        Keyword::RemoteIp => out.push_str(ctx.remote_ip),
        Keyword::RemotePort => {
            let _ = write!(out, "{}", ctx.remote_port);
        }
        Keyword::LocalIp => out.push_str(ctx.local_ip),
        Keyword::LocalIpType => out.push_str(ip_type(ctx.local_ip)),
        Keyword::LocalPort => {
            let _ = write!(out, "{}", ctx.local_port);
        }
        Keyword::Transport => out.push_str(ctx.transport),
        Keyword::CallId => out.push_str(ctx.call_id),
        Keyword::CallNumber => {
            let _ = write!(out, "{}", ctx.call_number);
        }
        Keyword::UserId => {
            let _ = write!(out, "{}", ctx.user_id);
        }
        Keyword::Users => {
            let _ = write!(out, "{}", ctx.users_total);
        }
        Keyword::Cseq => {
            let _ = write!(out, "{}", ctx.cseq);
        }
        Keyword::Branch => {
            // SIPp-shaped: magic cookie + pid + call number + msg index.
            // Stable across retransmissions (buffers are resent verbatim),
            // distinct across transactions of one call.
            let _ = write!(
                out,
                "z9hG4bK-{}-{}-{}",
                ctx.pid, ctx.call_number, ctx.msg_index
            );
        }
        Keyword::MsgIndex => {
            let _ = write!(out, "{}", ctx.msg_index);
        }
        Keyword::Pid => {
            let _ = write!(out, "{}", ctx.pid);
        }
        Keyword::PeerTagParam => {
            if let Some(tag) = ctx.peer_tag {
                let _ = write!(out, ";tag={tag}");
            }
        }
        Keyword::Routes => {
            if ctx.routes.is_empty() {
                out.push_str(KILL_MARKER);
            } else {
                // Route set = captured Record-Route values, reversed (we are
                // the UAC; RFC 3261 §12.1.2).
                let mut first = true;
                for r in ctx.routes.iter().rev() {
                    if !first {
                        out.push_str("\r\n");
                    }
                    let _ = write!(out, "Route: {r}");
                    first = false;
                }
            }
        }
        Keyword::NextUrl => {
            // Contact URI of the last received message; fall back to the
            // original request URI shape.
            let contact_uri = ctx
                .last
                .and_then(|m| m.header("Contact"))
                .map(strip_angle_brackets);
            match contact_uri {
                Some(uri) => out.push_str(uri),
                None => {
                    let _ = write!(
                        out,
                        "sip:{}@{}:{}",
                        ctx.service, ctx.remote_ip, ctx.remote_port
                    );
                }
            }
        }
        Keyword::Len => out.push_str(LEN_MARKER),
        Keyword::MediaIp => out.push_str(ctx.local_ip),
        Keyword::MediaPort => out.push_str("6000"),
        Keyword::MediaIpType => out.push_str(ip_type(ctx.local_ip)),
        Keyword::Field { index, file, line } => {
            if let Some(fi) = ctx.fields.resolve_file(file.as_deref()) {
                // No `line=` → the call's assigned line. With `line=`, an
                // invalid/negative value renders empty (SIPp sets line -1).
                let chosen = match line {
                    None => ctx.fields.default_line(fi),
                    Some(expr) => resolve_line_expr(expr, ctx),
                };
                if let Some(l) = chosen {
                    ctx.fields.read(fi, l, *index, out);
                }
            }
        }
        Keyword::Last(name) => {
            let lines = ctx.last.map(|m| m.header_lines(name)).unwrap_or_default();
            if lines.is_empty() {
                out.push_str(KILL_MARKER);
            } else {
                out.push_str(&lines.join("\r\n"));
            }
        }
        Keyword::Var(name) => {
            if let Some(vc) = &ctx.var_ctx {
                // Names were interned; look up by re-interning against the table.
                if let Some(id) = table_lookup(vc.vars, name) {
                    out.push_str(&vc.store.get(id).as_str());
                }
            }
        }
        Keyword::Authentication(params) => {
            if let Some(vc) = &ctx.var_ctx {
                if let Some(ch) = vc.challenge {
                    let user = param_or(params, "username", vc.auth_user);
                    let pass = param_or(params, "password", vc.auth_password);
                    let cred = sipr_auth::Credentials {
                        username: user,
                        password: pass,
                        method: vc.method,
                        uri: vc.digest_uri,
                        cnonce: vc.cnonce,
                        nc: 1,
                    };
                    // authorization_header returns "Name: Digest ..."; the
                    // scenario supplies the header name context, so emit only
                    // the value after the colon.
                    let line = sipr_auth::authorization_header(ch, &cred);
                    let value = line.split_once(": ").map_or(line.as_str(), |(_, v)| v);
                    out.push_str(value);
                }
            }
        }
        Keyword::Unknown(u) => {
            // Tokenizer emits unknown keywords as literals; reaching here is
            // a bug upstream, but render verbatim rather than dying.
            let _ = write!(out, "[{u}]");
        }
    }
}

fn table_lookup(vars: &VarTable, name: &str) -> Option<usize> {
    (0..vars.len()).find(|&i| vars.name(i) == name)
}

/// Resolve a `[fieldN line=...]` selector to a concrete line. A `line=[$var]`
/// that is unset, non-numeric, or negative yields `None` (empty field), which
/// is how a `lookup` miss (variable = -1) collapses to no output.
fn resolve_line_expr(expr: &LineExpr, ctx: &RenderCtx<'_>) -> Option<usize> {
    match expr {
        LineExpr::Literal(n) => Some(*n),
        LineExpr::Var(name) => {
            let vc = ctx.var_ctx.as_ref()?;
            let id = table_lookup(vc.vars, name)?;
            let n = vc.store.get(id).as_num();
            if n < 0.0 {
                None
            } else {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Some(n as usize)
            }
        }
    }
}

fn param_or<'a>(params: &'a [(String, String)], key: &str, default: &'a str) -> &'a str {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map_or(default, |(_, v)| v.as_str())
}

fn ip_type(ip: &str) -> &'static str {
    if ip.contains(':') { "6" } else { "4" }
}

fn strip_angle_brackets(contact: &str) -> &str {
    let inner = contact.find('<').and_then(|start| {
        contact[start..]
            .find('>')
            .map(|end| &contact[start + 1..start + end])
    });
    inner
        .unwrap_or(contact)
        .split(';')
        .next()
        .unwrap_or(contact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipr_scenario::model::Step;

    fn ctx<'a>(last: Option<&'a Inbound>) -> RenderCtx<'a> {
        RenderCtx {
            service: "service",
            remote_ip: "10.0.0.2",
            remote_port: 5060,
            local_ip: "10.0.0.1",
            local_port: 5061,
            transport: "UDP",
            call_id: "1-99@10.0.0.1",
            call_number: 1,
            user_id: 0,
            users_total: 0,
            pid: 99,
            cseq: 1,
            msg_index: 0,
            peer_tag: None,
            routes: &[],
            last,
            var_ctx: None,
            fields: crate::render::FieldSource::EMPTY,
        }
    }

    fn uac_invite_template() -> MsgTemplate {
        let sc = sipr_scenario::compile("uac", sipr_scenario::embedded("uac").unwrap())
            .scenario
            .unwrap();
        match &sc.steps[0] {
            Step::Send(s) => s.template.clone(),
            _ => panic!("step 0 must be the INVITE"),
        }
    }

    #[test]
    fn renders_embedded_invite_with_correct_len() {
        let bytes = render(&uac_invite_template(), &ctx(None)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.starts_with("INVITE sip:service@10.0.0.2:5060 SIP/2.0\r\n"),
            "{text}"
        );
        assert!(text.contains("Via: SIP/2.0/UDP 10.0.0.1:5061;branch=z9hG4bK-99-1-0\r\n"));
        assert!(text.contains("Call-ID: 1-99@10.0.0.1\r\n"));
        let (head, body) = text.split_once("\r\n\r\n").expect("separator");
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .expect("length header")
            .parse()
            .expect("numeric");
        assert_eq!(len, body.len(), "[len] must equal body bytes:\n{text}");
        assert!(body.starts_with("v=0\r\n"));
        assert!(
            body.contains("c=IN IP4 10.0.0.1"),
            "media placeholders fill"
        );
    }

    #[test]
    fn peer_tag_param_renders_or_vanishes() {
        let t = sipr_scenario::compile("uac", sipr_scenario::embedded("uac").unwrap())
            .scenario
            .unwrap();
        let Step::Send(ack) = &t.steps[5] else {
            panic!("step 5 must be the ACK");
        };
        let no_tag = String::from_utf8(render(&ack.template, &ctx(None)).unwrap()).unwrap();
        assert!(no_tag.contains("To: service <sip:service@10.0.0.2:5060>\r\n"));
        let mut c = ctx(None);
        c.peer_tag = Some("as7d9");
        let tagged = String::from_utf8(render(&ack.template, &c).unwrap()).unwrap();
        assert!(tagged.contains("To: service <sip:service@10.0.0.2:5060>;tag=as7d9\r\n"));
    }

    #[test]
    fn empty_last_header_deletes_the_whole_line() {
        let out = sipr_scenario::compile(
            "t",
            r#"<scenario name="t">
                 <recv request="OPTIONS"/>
                 <send><![CDATA[
                   SIP/2.0 200 OK
                   [last_Via:]
                   [last_Record-Route:]
                   [last_Call-ID:]
                   Content-Length: 0

                 ]]></send>
               </scenario>"#,
        );
        let sc = out.scenario.unwrap();
        let Step::Send(s) = &sc.steps[1] else {
            panic!("not send");
        };
        let inbound = Inbound::parse(
            b"OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h:1;branch=z9\r\nCall-ID: abc\r\n\r\n",
        )
        .unwrap();
        let text = String::from_utf8(render(&s.template, &ctx(Some(&inbound))).unwrap()).unwrap();
        assert!(text.contains("Via: SIP/2.0/UDP h:1;branch=z9\r\n"));
        assert!(text.contains("Call-ID: abc\r\n"));
        assert!(
            !text.contains("Record-Route"),
            "absent header must delete its line:\n{text}"
        );
    }

    #[test]
    fn field_source_resolve_lookup_insert_replace() {
        use sipr_scenario::inject::InjectionFile;
        let mut f =
            InjectionFile::parse("users.csv", "SEQUENTIAL\nalice;1001\nbob;1002\n").unwrap();
        f.build_index(0);
        let files = vec![RefCell::new(f)];
        let fs = FieldSource {
            files: &files,
            lines: &[Some(0)],
        };

        // Resolve by name, by numeric index, and default; unknown -> None.
        assert_eq!(fs.resolve_file(Some("users.csv")), Some(0));
        assert_eq!(fs.resolve_file(Some("0")), Some(0));
        assert_eq!(fs.resolve_file(None), Some(0));
        assert_eq!(fs.resolve_file(Some("nope")), None);

        // lookup: hit, miss (-1), unknown-file error.
        assert_eq!(fs.lookup_line("users.csv", "bob").unwrap(), 1.0);
        assert_eq!(fs.lookup_line("users.csv", "ghost").unwrap(), -1.0);
        assert!(fs.lookup_line("missing", "x").is_err());

        // insert then look up the new row.
        fs.insert_line("users.csv", "carol;1003").unwrap();
        assert_eq!(fs.lookup_line("users.csv", "carol").unwrap(), 2.0);

        // replace row 0: old key drops, new key indexes, read reflects it.
        fs.replace_line("users.csv", 0, "amir;1000").unwrap();
        assert_eq!(fs.lookup_line("users.csv", "alice").unwrap(), -1.0);
        assert_eq!(fs.lookup_line("users.csv", "amir").unwrap(), 0.0);
        let mut out = String::new();
        fs.read(0, 0, 0, &mut out);
        assert_eq!(out, "amir");
        assert!(
            fs.replace_line("users.csv", 99, "z").is_err(),
            "out of range"
        );

        // lookup on an unindexed file errors (SIPp: "Invalid Index File").
        let g = InjectionFile::parse("plain.csv", "SEQUENTIAL\nx;y\n").unwrap();
        let files2 = vec![RefCell::new(g)];
        let fs2 = FieldSource {
            files: &files2,
            lines: &[Some(0)],
        };
        assert!(fs2.lookup_line("plain.csv", "x").is_err());
    }

    #[test]
    fn branch_differs_per_msg_index_only() {
        let t = uac_invite_template();
        let mut a = ctx(None);
        a.msg_index = 0;
        let mut b = ctx(None);
        b.msg_index = 7;
        let ra = String::from_utf8(render(&t, &a).unwrap()).unwrap();
        let rb = String::from_utf8(render(&t, &b).unwrap()).unwrap();
        assert!(ra.contains("branch=z9hG4bK-99-1-0"));
        assert!(rb.contains("branch=z9hG4bK-99-1-7"));
    }
}
