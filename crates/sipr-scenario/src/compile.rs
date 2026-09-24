//! Compile a scenario XML document into the flat step IR.
//!
//! Diagnostics policy (docs/SIPP_COMPAT.md rule zero): unknown *attributes*
//! and *keywords* warn loudly and are otherwise ignored/passed through, but
//! unknown or unsupported *elements and actions* are hard errors — silently
//! skipping a step would change the call flow, which is worse than refusing
//! to run.

use std::collections::HashMap;

use crate::diag::{Diagnostic, Diagnostics};
use crate::distribution::Distribution;
use crate::lint::{self, Lint, LintInput};
use crate::model::{
    Action, ArithOp, CompareOp, Expect, IntCmd, JumpTarget, MediaKind, Operand, PauseSpec,
    RecvStep, Role, RtpEchoCmd, RtpEchoVerb, RtpSource, RtpStreamCmd, Scenario, SearchIn, SendStep,
    Step, StepCommon, StepIndex, Transaction, TxnId, VarId, VarScope, VarTable,
};
use crate::template::{self, Keyword, MsgTemplate};
use crate::xml::{self, Element, Node};

/// The declaring element of a non-call scope (call has none).
fn element_for(scope: VarScope) -> &'static str {
    match scope {
        VarScope::Global => "Global",
        VarScope::User => "User",
        VarScope::Call => "scenario",
    }
}

/// Result of a compilation: the scenario (unless errors) plus diagnostics.
#[derive(Debug)]
pub struct CompileOutcome {
    /// The compiled scenario; `None` when errors were found.
    pub scenario: Option<Scenario>,
    /// Warnings and errors, in discovery order.
    pub diagnostics: Vec<Diagnostic>,
}

/// Compile scenario XML. `source_name` labels diagnostics (path or `-sn` name).
#[must_use]
pub fn compile(source_name: &str, xml_text: &str) -> CompileOutcome {
    compile_with(source_name, xml_text, &CompileOptions::default())
}

/// Run-time inputs the compiler needs to know about.
#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    /// `-key KEYWORD VALUE` names: `[KEYWORD]` compiles to a generic
    /// keyword instead of drawing the unknown-keyword warning.
    pub generic_keywords: Vec<String>,
    /// `--check`: also run the lints ([`crate::lint`]), honouring the
    /// `<!-- sipr-lint: allow NAME -->` directives.
    pub lint: bool,
}

/// [`compile`] with [`CompileOptions`].
#[must_use]
pub fn compile_with(source_name: &str, xml_text: &str, options: &CompileOptions) -> CompileOutcome {
    let mut diags = Diagnostics::new(source_name);
    let root = match xml::parse(xml_text) {
        Ok(root) => root,
        Err(e) => {
            diags.error(Some(e.line), format!("XML: {}", e.message));
            return CompileOutcome {
                scenario: None,
                diagnostics: diags.into_items(),
            };
        }
    };
    let mut c = Compiler {
        diags,
        generic_keywords: options.generic_keywords.clone(),
        lint: options.lint,
        lint_allows: Vec::new(),
        directive_lines: Vec::new(),
        send_lines: Vec::new(),
        vars: VarTable::default(),
        var_read: Vec::new(),
        var_written: Vec::new(),
        var_first_line: Vec::new(),
        cur_line: 0,
        txns: Vec::new(),
        steps: Vec::new(),
        labels: HashMap::new(),
        pending: Vec::new(),
        name: String::new(),
        response_time_repartition: Vec::new(),
        call_length_repartition: Vec::new(),
    };
    c.compile_root(&root, source_name);
    if c.lint {
        c.warn_misplaced_directives(xml_text);
    }
    c.finish()
}

/// A label reference awaiting resolution.
struct Pending {
    step: StepIndex,
    slot: Slot,
    label: String,
    line: u32,
}

enum Slot {
    Next,
    Ontimeout,
}

/// One named transaction while compiling (SIPp `txnControlInfo`).
struct TxnControl {
    name: String,
    is_invite: bool,
    started: u32,
    responses: u32,
    acks: u32,
}

/// How a step refers to a transaction (SIPp `get_txn`'s flags).
#[derive(Clone, Copy, PartialEq, Eq)]
enum TxnUse {
    /// `start_txn` on a request; `is_invite` when that request is an INVITE.
    Start { is_invite: bool },
    /// `ack_txn` on an ACK.
    Ack,
    /// `response_txn` on a `recv response=`.
    Response,
}

impl TxnUse {
    /// SIPp's wording for the name checks ("… for start transaction").
    fn what(self) -> &'static str {
        match self {
            Self::Start { .. } => "start transaction",
            Self::Ack => "ack transaction",
            Self::Response => "transaction response",
        }
    }
}

struct Compiler {
    diags: Diagnostics,
    /// `-key` names (see [`CompileOptions`]).
    generic_keywords: Vec<String>,
    /// Run the lints (`--check`).
    lint: bool,
    /// `sipr-lint: allow` directives: the step each one precedes, and the
    /// lints it silences there.
    lint_allows: Vec<(StepIndex, Vec<Lint>)>,
    /// Source lines of the directives found where they belong (directly
    /// inside `<scenario>`), to tell the misplaced ones apart.
    directive_lines: Vec<u32>,
    /// Each `<send>`'s step and the source line its message starts on.
    send_lines: Vec<(StepIndex, u32)>,
    vars: VarTable,
    var_read: Vec<bool>,
    var_written: Vec<bool>,
    /// Line of the top-level element that first mentioned each variable.
    var_first_line: Vec<u32>,
    /// Line of the top-level element being compiled.
    cur_line: u32,
    /// Manual transactions in declaration order (SIPp `txnMap`), with the
    /// use counts `validate_txn_usage` checks.
    txns: Vec<TxnControl>,
    steps: Vec<Step>,
    labels: HashMap<String, StepIndex>,
    pending: Vec<Pending>,
    name: String,
    response_time_repartition: Vec<u64>,
    call_length_repartition: Vec<u64>,
}

impl Compiler {
    fn var(&mut self, name: &str) -> VarId {
        let id = self.vars.intern(name);
        if id >= self.var_read.len() {
            self.var_read.push(false);
            self.var_written.push(false);
            self.var_first_line.push(self.cur_line);
        }
        id
    }

    /// `<Global variables="a,b"/>` / `<User variables="x"/>`: give the named
    /// variables a scope. SIPp resolves scopes by declaration order — a name
    /// used *before* its declaration is already call-scoped and stays so —
    /// which silently splits one name into two variables; sipr applies the
    /// scope to the whole scenario and warns about the earlier use.
    fn compile_scope_declaration(&mut self, el: &Element, scope: VarScope) {
        self.warn_unknown_attrs(el, &["variables"]);
        let Some(list) = self.require_attr(el, "variables") else {
            return;
        };
        for name in list.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            let earlier = self.vars.find(name);
            let id = self.var(name);
            let current = self.vars.scope(id);
            if current != VarScope::Call && current != scope {
                self.diags.error(
                    Some(el.line),
                    format!(
                        "variable '{name}' is declared both <{}> and <{}>",
                        element_for(current),
                        element_for(scope)
                    ),
                );
                continue;
            }
            if let Some(id) = earlier
                && current == VarScope::Call
            {
                self.diags.warn(
                    Some(el.line),
                    format!(
                        "variable '{name}' is used at line {} before this <{}> declaration: \
                         SIPp would keep that use call-scoped and create a second, {} '{name}' \
                         here; sipr makes every use {} — move the declaration above the first use",
                        self.var_first_line.get(id).copied().unwrap_or(0),
                        element_for(scope),
                        scope.label(),
                        scope.label()
                    ),
                );
            }
            self.vars.set_scope(id, scope);
        }
    }

    fn var_reads(&mut self, name: &str) -> VarId {
        let id = self.var(name);
        self.var_read[id] = true;
        id
    }

    /// SIPp's `handle_rhs`: exactly one of `value=` (numeric) or `variable=`.
    fn parse_operand(&mut self, el: &Element, line: u32) -> Operand {
        match (el.attr("value"), el.attr("variable")) {
            (Some(v), None) => match v.parse() {
                Ok(n) => Operand::Value(n),
                Err(_) => {
                    self.diags.error(
                        Some(line),
                        format!("{} 'value' must be numeric: '{v}'", el.name),
                    );
                    Operand::Value(0.0)
                }
            },
            (None, Some(v)) => {
                let v = v.to_owned();
                Operand::Var(self.var_reads(&v))
            }
            _ => {
                self.diags.error(
                    Some(line),
                    format!("<{}> needs exactly one of 'value' or 'variable'", el.name),
                );
                Operand::Value(0.0)
            }
        }
    }

    fn var_writes(&mut self, name: &str) -> VarId {
        let id = self.var(name);
        self.var_written[id] = true;
        id
    }

    /// Tokenize template text and record `[$var]` reads.
    fn templ(&mut self, text: &str, line: u32) -> MsgTemplate {
        let t = template::tokenize_with(text, line, &mut self.diags, &self.generic_keywords);
        // `[$v]` reads, `[fieldN line=[$v]]` reads its selector variable,
        // `[fill variable=v]` its length, and a `[file name=…]` sub-template
        // whatever it references.
        let mut vars: Vec<String> = t
            .keywords()
            .filter_map(|k| match k {
                Keyword::Var(v) | Keyword::Fill { variable: v, .. } => Some(v.clone()),
                Keyword::Field {
                    line: Some(template::LineExpr::Var(v)),
                    ..
                } => Some(v.clone()),
                _ => None,
            })
            .collect();
        for k in t.keywords() {
            if let Keyword::File { name } = k {
                vars.extend(name.keywords().filter_map(|k| match k {
                    Keyword::Var(v) => Some(v.clone()),
                    _ => None,
                }));
            }
        }
        // `[authentication username=[$u] aka_K=[field2]]`: SIPp renders each
        // parameter as a sub-message, so their `[$var]` reads count too.
        for k in t.keywords() {
            if let Keyword::Authentication(params) = k {
                for (_, value) in params {
                    if value.contains('[') {
                        let sub = template::tokenize_with(
                            value,
                            line,
                            &mut self.diags,
                            &self.generic_keywords,
                        );
                        vars.extend(sub.keywords().filter_map(|k| match k {
                            Keyword::Var(v) => Some(v.clone()),
                            _ => None,
                        }));
                    }
                }
            }
        }
        for v in vars {
            self.var_reads(&v);
        }
        t
    }

    /// Register one use of a named transaction (SIPp `scenario::get_txn`):
    /// the first mention creates it, later ones bump the use counts that
    /// `finish()` validates.
    fn txn(&mut self, name: &str, usage: TxnUse, line: u32) -> Option<TxnId> {
        if name.is_empty() {
            self.diags.error(
                Some(line),
                format!("Variable names may not be empty for {}", usage.what()),
            );
            return None;
        }
        if name.contains(['$', ',']) {
            self.diags.error(
                Some(line),
                format!("Variable names may not contain $ or , for {}", usage.what()),
            );
            return None;
        }
        let id = match self.txns.iter().position(|t| t.name == name) {
            Some(id) => id,
            None => {
                self.txns.push(TxnControl {
                    name: name.to_owned(),
                    is_invite: false,
                    started: 0,
                    responses: 0,
                    acks: 0,
                });
                self.txns.len() - 1
            }
        };
        let txn = &mut self.txns[id];
        match usage {
            TxnUse::Start { is_invite } => {
                txn.started += 1;
                txn.is_invite = is_invite;
            }
            TxnUse::Ack => txn.acks += 1,
            TxnUse::Response => txn.responses += 1,
        }
        Some(id)
    }

    /// SIPp `validate_txn_usage`: every transaction must be started and
    /// answered, an INVITE one acknowledged, a non-INVITE one not.
    fn validate_txn_usage(&mut self) {
        let findings: Vec<String> = self
            .txns
            .iter()
            .flat_map(|t| {
                let mut out = Vec::new();
                if t.started == 0 {
                    out.push(format!("Transaction {} is never started!", t.name));
                } else if t.responses == 0 {
                    out.push(format!("Transaction {} has no responses defined!", t.name));
                }
                if t.is_invite && t.acks == 0 {
                    out.push(format!(
                        "Transaction {} is an INVITE transaction without an ACK!",
                        t.name
                    ));
                }
                if !t.is_invite && t.acks > 0 {
                    out.push(format!(
                        "Transaction {} is a non-INVITE transaction with an ACK!",
                        t.name
                    ));
                }
                out
            })
            .collect();
        for message in findings {
            self.diags.error(None, message);
        }
    }

    /// The `start_txn`/`ack_txn` attributes of a `<send>` (SIPp
    /// `scenario.cpp` ~l.878-910): only a request may start a transaction,
    /// only an ACK may acknowledge one, and a response may do neither.
    fn parse_send_txns(
        &mut self,
        el: &Element,
        first_word: &str,
    ) -> (Option<TxnId>, Option<TxnId>) {
        let is_response = first_word == "SIP/2.0";
        let is_ack = first_word == "ACK";
        if el.attr("response_txn").is_some() {
            self.diags.error(
                Some(el.line),
                "response_txn can only be used for received messages.",
            );
        }
        let start = el.attr("start_txn").map(ToOwned::to_owned);
        let ack = el.attr("ack_txn").map(ToOwned::to_owned);
        if start.is_some() && ack.is_some() {
            self.diags.error(
                Some(el.line),
                "<send> cannot have both 'start_txn' and 'ack_txn'",
            );
            return (None, None);
        }
        let start_txn = start.and_then(|name| {
            if is_response {
                self.diags
                    .error(Some(el.line), "Responses can not start a transaction");
                return None;
            }
            if is_ack {
                self.diags
                    .error(Some(el.line), "An ACK message can not start a transaction!");
                return None;
            }
            let is_invite = first_word == "INVITE";
            self.txn(&name, TxnUse::Start { is_invite }, el.line)
        });
        let ack_txn = ack.and_then(|name| {
            if is_response {
                self.diags
                    .error(Some(el.line), "Responses can not ACK a transaction");
                return None;
            }
            if !is_ack {
                self.diags.error(
                    Some(el.line),
                    "The ack_txn attribute is valid only for ACK messages!",
                );
                return None;
            }
            self.txn(&name, TxnUse::Ack, el.line)
        });
        (start_txn, ack_txn)
    }

    fn compile_root(&mut self, root: &Element, source_name: &str) {
        if root.name != "scenario" {
            self.diags.error(
                Some(root.line),
                format!("root element must be <scenario>, found <{}>", root.name),
            );
            return;
        }
        self.name = root
            .attr("name")
            .map_or_else(|| source_name.to_owned(), ToOwned::to_owned);
        self.warn_unknown_attrs(root, &["name"]);
        // A `sipr-lint:` directive applies to the step the next element
        // compiles to.
        let mut pending: Option<(u32, Vec<Lint>)> = None;
        for node in &root.children {
            match node {
                Node::Element(el) => {
                    let step = self.steps.len();
                    self.compile_element(el);
                    if let Some((line, lints)) = pending.take() {
                        if self.steps.len() > step {
                            self.lint_allows.push((step, lints));
                        } else if self.lint {
                            self.diags.warn_at(
                                line,
                                format!(
                                    "sipr-lint directive has no effect: it must come right \
                                     before a step, not before <{}>",
                                    el.name
                                ),
                            );
                        }
                    }
                }
                Node::Comment { text, line } => {
                    if let Some(lints) = self.lint_directive(text, *line) {
                        let (_, allowed) = pending.get_or_insert_with(|| (*line, Vec::new()));
                        allowed.extend(lints);
                    }
                }
                Node::Text(_) | Node::CData { .. } => {}
            }
        }
        if let Some((line, _)) = pending
            && self.lint
        {
            self.diags.warn_at(
                line,
                "sipr-lint directive has no effect: no step follows it",
            );
        }
    }

    /// Parse `sipr-lint: allow NAME[, NAME…]`. `None` for any other
    /// comment; an unknown name or a malformed directive warns (under
    /// `--check`, the only time directives matter) and keeps what it can.
    fn lint_directive(&mut self, comment: &str, line: u32) -> Option<Vec<Lint>> {
        let rest = comment.trim().strip_prefix("sipr-lint:")?;
        // The line the directive itself is on, for a comment that opens on
        // an earlier one.
        let opening = comment.len() - comment.trim_start().len();
        let newlines = comment[..opening].matches('\n').count();
        let line = line.saturating_add(u32::try_from(newlines).unwrap_or(0));
        self.directive_lines.push(line);
        let names = rest
            .trim()
            .strip_prefix("allow")
            .filter(|names| names.starts_with(char::is_whitespace) && !names.trim().is_empty());
        let Some(names) = names else {
            if self.lint {
                self.diags.warn_at(
                    line,
                    "malformed sipr-lint directive: write 'sipr-lint: allow NAME[, NAME…]'",
                );
            }
            return Some(Vec::new());
        };
        let mut lints = Vec::new();
        for name in names.split(|c: char| c == ',' || c.is_whitespace()) {
            if name.is_empty() {
                continue;
            }
            match Lint::from_name(name) {
                Some(lint) => lints.push(lint),
                None if self.lint => {
                    let known: Vec<&str> = Lint::ALL.iter().map(|l| l.name()).collect();
                    self.diags.warn_at(
                        line,
                        format!(
                            "unknown lint '{name}' in sipr-lint directive (known: {})",
                            known.join(", ")
                        ),
                    );
                }
                None => {}
            }
        }
        Some(lints)
    }

    /// A directive anywhere but directly inside `<scenario>` — before the
    /// root, inside a `<send>` — would silently do nothing; say so.
    fn warn_misplaced_directives(&mut self, xml_text: &str) {
        for (line, text) in (1u32..).zip(xml_text.lines()) {
            if text.contains("sipr-lint:") && !self.directive_lines.contains(&line) {
                self.diags.warn_at(
                    line,
                    "sipr-lint directive has no effect here: put it directly inside \
                     <scenario>, right before the step it is for",
                );
            }
        }
    }

    fn compile_element(&mut self, el: &Element) {
        self.cur_line = el.line;
        match el.name.as_str() {
            "send" => self.compile_send(el),
            "recv" => self.compile_recv(el),
            "pause" => self.compile_pause(el),
            "nop" => self.compile_nop(el),
            "label" => self.compile_label(el),
            "timewait" => self.compile_timewait(el),
            "ResponseTimeRepartition" => {
                self.warn_unknown_attrs(el, &["value"]);
                self.response_time_repartition = self.parse_bucket_list(el);
            }
            "CallLengthRepartition" => {
                self.warn_unknown_attrs(el, &["value"]);
                self.call_length_repartition = self.parse_bucket_list(el);
            }
            "Global" => self.compile_scope_declaration(el, VarScope::Global),
            "User" => self.compile_scope_declaration(el, VarScope::User),
            "Reference" => {
                self.warn_unknown_attrs(el, &["variables"]);
                let vars = el.attr("variables").unwrap_or_default().to_owned();
                if vars.is_empty() {
                    self.diags
                        .error(Some(el.line), "<Reference> needs a 'variables' attribute");
                }
                for v in vars.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                    self.var_reads(v);
                }
            }
            "sendCmd" => self.compile_send_cmd(el),
            "recvCmd" => self.compile_recv_cmd(el),
            other => self.diags.error(
                Some(el.line),
                format!("unknown element <{other}> — refusing to silently skip a step"),
            ),
        }
    }

    // ---- steps ---------------------------------------------------------

    fn compile_send(&mut self, el: &Element) {
        const ATTRS: &[&str] = &[
            "retrans",
            "lost",
            "start_txn",
            "ack_txn",
            "response_txn", // rejected below with SIPp's wording, not as unknown
        ];
        let common = self.parse_common(el, ATTRS);
        let retrans_ms = self.parse_num_attr(el, "retrans");
        let lost_pct = self.parse_num_attr(el, "lost");
        let mut body = String::new();
        let mut cdata_line = el.line;
        let mut actions = Vec::new();
        for node in &el.children {
            match node {
                Node::CData { text, line } => {
                    if body.is_empty() {
                        cdata_line = *line;
                    }
                    body.push_str(text);
                }
                Node::Text(t) => {
                    if !t.trim().is_empty() {
                        body.push_str(t);
                    }
                }
                Node::Element(a) if a.name == "action" => {
                    actions.extend(self.parse_actions(a));
                }
                Node::Element(a) => self.diags.error(
                    Some(a.line),
                    format!("unexpected <{}> inside <send>", a.name),
                ),
                Node::Comment { .. } => {}
            }
        }
        let normalized = template::normalize_cdata(&body);
        if normalized.is_empty() {
            self.diags
                .error(Some(el.line), "<send> has no message body");
        }
        let first_word = normalized
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let (start_txn, ack_txn) = self.parse_send_txns(el, &first_word);
        let tmpl = self.templ(&normalized, cdata_line);
        // Normalization drops the blank lines before the start line (the
        // rest of the `<![CDATA[` line, typically).
        let leading_blank = body.lines().take_while(|l| l.trim().is_empty()).count();
        let first_line = cdata_line.saturating_add(u32::try_from(leading_blank).unwrap_or(0));
        self.send_lines.push((self.steps.len(), first_line));
        self.steps.push(Step::Send(SendStep {
            template: tmpl,
            retrans_ms,
            lost_pct,
            start_txn,
            ack_txn,
            actions,
            common,
        }));
    }

    fn compile_recv(&mut self, el: &Element) {
        const ATTRS: &[&str] = &[
            "response",
            "request",
            "optional",
            "rrs",
            "auth",
            "lost",
            "timeout",
            "ontimeout",
            "regexp_match",
            "response_txn",
            "ignoresdp",
            "ignosesdp", // sic: the DTD spells it this way
        ];
        // The DTD misspells it `ignosesdp`; SIPp accepts both.
        let ignore_sdp =
            self.parse_bool_attr(el, "ignoresdp") || self.parse_bool_attr(el, "ignosesdp");
        let common = self.parse_common(el, ATTRS);
        let expect = match (el.attr("response"), el.attr("request")) {
            (Some(r), None) => Expect::Response(r.to_owned()),
            (None, Some(m)) => Expect::Request(m.to_owned()),
            (Some(_), Some(_)) => {
                self.diags.error(
                    Some(el.line),
                    "<recv> cannot have both 'response' and 'request'",
                );
                Expect::Response(String::new())
            }
            (None, None) => {
                self.diags
                    .error(Some(el.line), "<recv> needs either 'response' or 'request'");
                Expect::Response(String::new())
            }
        };
        // `response_txn` ties the recv to a started transaction; SIPp allows
        // it on received responses only (`scenario.cpp` ~l.923-932).
        let response_txn = match (el.attr("response_txn"), &expect) {
            (None, _) => None,
            (Some(name), Expect::Response(_)) => {
                let name = name.to_owned();
                self.txn(&name, TxnUse::Response, el.line)
            }
            (Some(_), Expect::Request(_)) => {
                self.diags.error(
                    Some(el.line),
                    "response_txn can only be used for received responses.",
                );
                None
            }
        };
        let ontimeout_label = el.attr("ontimeout").map(ToOwned::to_owned);
        if let Some(label) = ontimeout_label {
            self.pending.push(Pending {
                step: self.steps.len(),
                slot: Slot::Ontimeout,
                label,
                line: el.line,
            });
        }
        let mut actions = Vec::new();
        for a in el.child_elements() {
            if a.name == "action" {
                actions.extend(self.parse_actions(a));
            } else {
                self.diags.error(
                    Some(a.line),
                    format!("unexpected <{}> inside <recv>", a.name),
                );
            }
        }
        let regexp_match = self.parse_bool_attr(el, "regexp_match");
        let expect_regex = if regexp_match {
            let raw = match &expect {
                Expect::Response(c) => c.clone(),
                Expect::Request(m) => m.clone(),
            };
            match crate::regex::Regex::compile(&raw) {
                Ok(re) => Some(re),
                Err(e) => {
                    self.diags
                        .error(Some(el.line), format!("bad recv pattern '{raw}': {e}"));
                    None
                }
            }
        } else {
            None
        };
        let recv = RecvStep {
            expect,
            optional: self.parse_bool_attr(el, "optional"),
            regexp_match,
            expect_regex,
            timeout_ms: self.parse_num_attr(el, "timeout"),
            ontimeout: None, // resolved in finish()
            record_route_set: self.parse_bool_attr(el, "rrs"),
            auth: self.parse_bool_attr(el, "auth"),
            lost_pct: self.parse_num_attr(el, "lost"),
            ignore_sdp,
            response_txn,
            actions,
            common,
        };
        self.steps.push(Step::Recv(recv));
    }

    fn compile_pause(&mut self, el: &Element) {
        let mut attrs = vec!["milliseconds", "variable", "sanity_check"];
        attrs.extend(crate::distribution::all_param_attrs(true));
        let common = self.parse_common(el, &attrs);
        // SIPp's default is a sanity check on; `sanity_check="false"` turns
        // the 99th-percentile guard off.
        let sanity_check = match el.attr("sanity_check") {
            None => true,
            Some(_) => self.parse_bool_attr(el, "sanity_check"),
        };
        let ms = el.attr("milliseconds");
        let var = el.attr("variable").map(ToOwned::to_owned);
        let kind = crate::distribution::kind_of(&|name| el.attr(name), true);
        let spec = match (ms, &var, kind) {
            (None, None, None) => PauseSpec::Default,
            (Some(_), None, None) => match self.parse_num_attr(el, "milliseconds") {
                Some(v) => PauseSpec::Fixed(v),
                None => PauseSpec::Default,
            },
            (None, Some(v), None) => {
                let id = self.var_reads(v);
                PauseSpec::Variable(id)
            }
            (None, None, Some(kind)) => match self.parse_distribution(el, &kind, sanity_check) {
                Some(d) => PauseSpec::Distribution(d),
                None => PauseSpec::Default,
            },
            _ => {
                self.diags.error(
                    Some(el.line),
                    "<pause> takes at most one of 'milliseconds', 'variable', 'distribution'",
                );
                PauseSpec::Default
            }
        };
        self.steps.push(Step::Pause { spec, common });
    }

    fn compile_nop(&mut self, el: &Element) {
        const ATTRS: &[&str] = &["display"];
        let common = self.parse_common(el, ATTRS);
        let mut actions = Vec::new();
        for a in el.child_elements() {
            if a.name == "action" {
                actions.extend(self.parse_actions(a));
            } else {
                self.diags.error(
                    Some(a.line),
                    format!("unexpected <{}> inside <nop>", a.name),
                );
            }
        }
        self.steps.push(Step::Nop { actions, common });
    }

    /// `<sendCmd>` — a 3PCC control command whose CDATA is the message body
    /// (SIPp appends an ESC delimiter on the wire; the engine does that).
    /// `dest=` names the peer in extended mode; whether it is required or
    /// even known is the engine's call, since that depends on the command
    /// line (`-slave_cfg`).
    fn compile_send_cmd(&mut self, el: &Element) {
        let dest = self.peer_name_attr(el, "dest");
        let common = self.parse_common(el, &["dest"]);
        let mut body = String::new();
        let mut cdata_line = el.line;
        for node in &el.children {
            match node {
                Node::CData { text, line } => {
                    if body.is_empty() {
                        cdata_line = *line;
                    }
                    body.push_str(text);
                }
                Node::Text(t) => {
                    if !t.trim().is_empty() {
                        body.push_str(t);
                    }
                }
                Node::Element(a) => self.diags.error(
                    Some(a.line),
                    format!("unexpected <{}> inside <sendCmd>", a.name),
                ),
                Node::Comment { .. } => {}
            }
        }
        let normalized = template::normalize_cdata(&body);
        if normalized.is_empty() {
            self.diags
                .error(Some(el.line), "<sendCmd> has no command body (CDATA)");
        }
        let template = self.templ(&normalized, cdata_line);
        self.steps.push(Step::SendCmd {
            template,
            common,
            dest,
        });
    }

    /// `dest=` / `src=`: a peer name for extended 3PCC. Present but empty
    /// names nothing and is an error rather than a silent classic fallback.
    fn peer_name_attr(&mut self, el: &Element, attr: &str) -> Option<String> {
        let value = el.attr(attr)?.trim();
        if value.is_empty() {
            self.diags.error(
                Some(el.line),
                format!("<{}> '{attr}' must name a peer from -slave_cfg", el.name),
            );
            return None;
        }
        Some(value.to_owned())
    }

    /// `<recvCmd>` — wait for a twin command; its `<action>`s run against the
    /// received command text. `src=` names the peer the command must come
    /// from in extended mode.
    fn compile_recv_cmd(&mut self, el: &Element) {
        let src = self.peer_name_attr(el, "src");
        let common = self.parse_common(el, &["optional", "src"]);
        let optional = self.parse_bool_attr(el, "optional");
        let mut actions = Vec::new();
        for a in el.child_elements() {
            if a.name == "action" {
                actions.extend(self.parse_actions(a));
            } else {
                self.diags.error(
                    Some(a.line),
                    format!("unexpected <{}> inside <recvCmd>", a.name),
                );
            }
        }
        self.steps.push(Step::RecvCmd {
            actions,
            common,
            optional,
            src,
        });
    }

    fn compile_label(&mut self, el: &Element) {
        self.warn_unknown_attrs(el, &["id"]);
        let Some(id) = el.attr("id") else {
            self.diags
                .error(Some(el.line), "<label> needs an 'id' attribute");
            return;
        };
        if self
            .labels
            .insert(id.to_owned(), self.steps.len())
            .is_some()
        {
            self.diags
                .error(Some(el.line), format!("duplicate label id '{id}'"));
        }
        self.steps.push(Step::Label {
            id: id.to_owned(),
            line: el.line,
        });
    }

    fn compile_timewait(&mut self, el: &Element) {
        self.warn_unknown_attrs(el, &["milliseconds"]);
        let Some(ms) = self.parse_num_attr(el, "milliseconds") else {
            self.diags
                .error(Some(el.line), "<timewait> needs 'milliseconds'");
            return;
        };
        self.steps.push(Step::Timewait { ms, line: el.line });
    }

    // ---- shared attribute parsing --------------------------------------

    /// Common attrs (`%messageCmdCommon`), registering a pending `next` ref.
    fn parse_common(&mut self, el: &Element, element_attrs: &[&str]) -> StepCommon {
        const COMMON: &[&str] = &[
            "start_rtd",
            "rtd",
            "repeat_rtd",
            "crlf",
            "next",
            "test",
            "chance",
            "condexec",
            "condexec_inverse",
            "counter",
            "hide",
            "display",
        ];
        let allowed: Vec<&str> = COMMON.iter().chain(element_attrs).copied().collect();
        self.warn_unknown_attrs(el, &allowed);
        if let Some(label) = el.attr("next") {
            self.pending.push(Pending {
                step: self.steps.len(),
                slot: Slot::Next,
                label: label.to_owned(),
                line: el.line,
            });
        }
        let chance = el.attr("chance").and_then(|raw| {
            let parsed: Option<f64> = raw.parse().ok();
            let valid = parsed.filter(|c| (0.0..=1.0).contains(c));
            if valid.is_none() {
                self.diags.error(
                    Some(el.line),
                    format!("'chance' must be a number in 0..=1, got '{raw}'"),
                );
            }
            valid
        });
        if chance.is_some() && el.attr("next").is_none() {
            self.diags
                .warn(Some(el.line), "'chance' without 'next' has no effect");
        }
        let norm_rtd = |v: &str| -> String {
            if v == "true" {
                "1".to_owned()
            } else {
                v.to_owned()
            }
        };
        StepCommon {
            start_rtd: el.attr("start_rtd").map(norm_rtd),
            rtd: el.attr("rtd").map(norm_rtd),
            repeat_rtd: self.parse_bool_attr(el, "repeat_rtd"),
            crlf: self.parse_bool_attr(el, "crlf"),
            next: None, // resolved in finish()
            test: el
                .attr("test")
                .map(ToOwned::to_owned)
                .map(|v| self.var_reads(&v)),
            chance,
            condexec: el
                .attr("condexec")
                .map(ToOwned::to_owned)
                .map(|v| self.var_reads(&v)),
            condexec_inverse: self.parse_bool_attr(el, "condexec_inverse"),
            counter: el.attr("counter").map(ToOwned::to_owned),
            hide: self.parse_bool_attr(el, "hide"),
            display: el
                .attr("display")
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(ToOwned::to_owned),
            line: el.line,
        }
    }

    fn warn_unknown_attrs(&mut self, el: &Element, allowed: &[&str]) {
        let unknown: Vec<String> = el
            .attrs
            .iter()
            .filter(|(n, _)| !allowed.contains(&n.as_str()))
            .map(|(n, _)| n.clone())
            .collect();
        for name in unknown {
            self.diags.warn(
                Some(el.line),
                format!("unknown attribute '{name}' on <{}> — ignored", el.name),
            );
        }
    }

    fn parse_bool_attr(&mut self, el: &Element, name: &str) -> bool {
        match el.attr(name) {
            None => false,
            Some("true") => true,
            Some("false") => false,
            Some(other) => {
                self.diags.error(
                    Some(el.line),
                    format!("attribute '{name}' must be true|false, got '{other}'"),
                );
                false
            }
        }
    }

    fn parse_num_attr<T: std::str::FromStr>(&mut self, el: &Element, name: &str) -> Option<T> {
        let raw = el.attr(name)?;
        match raw.parse() {
            Ok(v) => Some(v),
            Err(_) => {
                self.diags.error(
                    Some(el.line),
                    format!(
                        "invalid numeric value '{raw}' for '{name}' on <{}>",
                        el.name
                    ),
                );
                None
            }
        }
    }

    fn parse_bucket_list(&mut self, el: &Element) -> Vec<u64> {
        let Some(raw) = el.attr("value") else {
            self.diags
                .error(Some(el.line), format!("<{}> needs 'value'", el.name));
            return Vec::new();
        };
        let mut out = Vec::new();
        for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.parse() {
                Ok(v) => out.push(v),
                Err(_) => {
                    self.diags.error(
                        Some(el.line),
                        format!("invalid bucket '{part}' in <{}>", el.name),
                    );
                }
            }
        }
        out
    }

    /// Build the distribution `kind` from `el`'s attributes (SIPp's names
    /// and error wording, `crate::distribution`); with `sanity_check`, refuse
    /// one whose 99th percentile exceeds `INT_MAX` ms, as SIPp does.
    fn parse_distribution(
        &mut self,
        el: &Element,
        kind: &str,
        sanity_check: bool,
    ) -> Option<Distribution> {
        let dist = match crate::distribution::from_attrs(kind, &|name| el.attr(name)) {
            Ok(d) => d,
            Err(msg) => {
                self.diags.error(Some(el.line), msg);
                return None;
            }
        };
        if sanity_check {
            if let Some(p99) = dist.percentile_99() {
                if p99 > f64::from(i32::MAX) {
                    self.diags.error(
                        Some(el.line),
                        format!(
                            "The distribution {} has a 99th percentile of {p99:.0} ms, which \
                             is larger than INT_MAX. You should choose different parameters.",
                            dist.describe()
                        ),
                    );
                    return None;
                }
            }
        }
        Some(dist)
    }

    // ---- actions -------------------------------------------------------

    fn parse_actions(&mut self, action_el: &Element) -> Vec<Action> {
        let mut out = Vec::new();
        for el in action_el.child_elements() {
            if let Some(a) = self.parse_action(el) {
                out.push(a);
            }
        }
        out
    }

    #[allow(clippy::too_many_lines)] // one arm per DTD action; splitting hurts
    fn parse_action(&mut self, el: &Element) -> Option<Action> {
        let line = el.line;
        match el.name.as_str() {
            "ereg" => {
                self.warn_unknown_attrs(
                    el,
                    &[
                        "regexp",
                        "search_in",
                        "header",
                        "variable",
                        "start_line",
                        "check_it",
                        "assign_to",
                    ],
                );
                let regexp_raw = self.require_attr(el, "regexp")?;
                let regexp = match crate::regex::Regex::compile(&regexp_raw) {
                    Ok(re) => re,
                    Err(e) => {
                        self.diags
                            .error(Some(line), format!("bad ereg pattern '{regexp_raw}': {e}"));
                        return None;
                    }
                };
                let search_in = match el.attr("search_in").unwrap_or("msg") {
                    "msg" => SearchIn::Msg,
                    "hdr" => SearchIn::Hdr,
                    "body" => SearchIn::Body,
                    // SIPp `xp_get_var("variable", "ereg")`: required.
                    "var" => match el.attr("variable") {
                        Some(name) => {
                            let name = name.to_owned();
                            SearchIn::Var(self.var_reads(&name))
                        }
                        None => {
                            self.diags
                                .error(Some(line), "ereg with search_in=\"var\" needs 'variable'");
                            SearchIn::Msg
                        }
                    },
                    other => {
                        self.diags
                            .error(Some(line), format!("Unknown search_in value {other}"));
                        SearchIn::Msg
                    }
                };
                let header = el.attr("header").map(ToOwned::to_owned);
                if search_in == SearchIn::Hdr && header.is_none() {
                    self.diags
                        .error(Some(line), "ereg with search_in=\"hdr\" needs 'header'");
                }
                let assign_raw = self.require_attr(el, "assign_to")?;
                let assign_to: Vec<VarId> = assign_raw
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(|v| self.var_writes(v))
                    .collect();
                if assign_to.is_empty() {
                    self.diags.error(Some(line), "ereg 'assign_to' is empty");
                }
                Some(Action::Ereg {
                    regexp,
                    search_in,
                    header,
                    start_line: self.parse_bool_attr(el, "start_line"),
                    check_it: self.parse_bool_attr(el, "check_it"),
                    assign_to,
                })
            }
            "log" | "warning" | "error" => {
                self.warn_unknown_attrs(el, &["message"]);
                let msg = self.require_attr(el, "message")?;
                let tmpl = self.templ(&msg, line);
                Some(match el.name.as_str() {
                    "log" => Action::Log(tmpl),
                    "warning" => Action::Warn(tmpl),
                    _ => Action::Fail(tmpl),
                })
            }
            "assign" => {
                self.warn_unknown_attrs(el, &["assign_to", "variable"]);
                let to = self.require_attr(el, "assign_to")?;
                let from = self.require_attr(el, "variable")?;
                Some(Action::Assign {
                    assign_to: self.var_writes(&to),
                    variable: self.var_reads(&from),
                })
            }
            "assignstr" => {
                self.warn_unknown_attrs(el, &["assign_to", "value"]);
                let to = self.require_attr(el, "assign_to")?;
                let value = self.require_attr(el, "value")?;
                let tmpl = self.templ(&value, line);
                Some(Action::AssignStr {
                    assign_to: self.var_writes(&to),
                    value: tmpl,
                })
            }
            "verifyauth" => {
                self.warn_unknown_attrs(el, &["assign_to", "username", "password"]);
                let to = self.require_attr(el, "assign_to")?;
                let username = self.require_attr(el, "username")?;
                let password = self.require_attr(el, "password")?;
                Some(Action::VerifyAuth {
                    assign_to: self.var_writes(&to),
                    username: self.templ(&username, line),
                    password: self.templ(&password, line),
                })
            }
            "strcmp" => {
                self.warn_unknown_attrs(el, &["assign_to", "variable", "value"]);
                let to = self.require_attr(el, "assign_to")?;
                let var = self.require_attr(el, "variable")?;
                let value = self.require_attr(el, "value")?;
                Some(Action::Strcmp {
                    assign_to: self.var_writes(&to),
                    variable: self.var_reads(&var),
                    value,
                })
            }
            "test" => {
                self.warn_unknown_attrs(el, &["assign_to", "variable", "compare", "value"]);
                let to = self.require_attr(el, "assign_to")?;
                let var = self.require_attr(el, "variable")?;
                let compare = match self.require_attr(el, "compare")?.as_str() {
                    "equal" => CompareOp::Equal,
                    "not_equal" => CompareOp::NotEqual,
                    "greater_than" => CompareOp::Greater,
                    "greater_than_equal" => CompareOp::GreaterEqual,
                    "less_than" => CompareOp::Less,
                    "less_than_equal" => CompareOp::LessEqual,
                    other => {
                        self.diags
                            .error(Some(line), format!("unknown compare op '{other}'"));
                        CompareOp::Equal
                    }
                };
                let value = self.require_attr(el, "value")?;
                let value: f64 = match value.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        self.diags.error(
                            Some(line),
                            format!("test 'value' must be numeric: '{value}'"),
                        );
                        0.0
                    }
                };
                Some(Action::Test {
                    assign_to: self.var_writes(&to),
                    variable: self.var_reads(&var),
                    compare,
                    value,
                })
            }
            "add" | "subtract" | "multiply" | "divide" => {
                self.warn_unknown_attrs(el, &["assign_to", "value", "variable"]);
                let op = match el.name.as_str() {
                    "add" => ArithOp::Add,
                    "subtract" => ArithOp::Subtract,
                    "multiply" => ArithOp::Multiply,
                    _ => ArithOp::Divide,
                };
                let to = self.require_attr(el, "assign_to")?;
                let operand = self.parse_operand(el, line);
                // Read-modify-write: the destination is also an input.
                let assign_to = self.var_reads(&to);
                let assign_to_w = self.var_writes(&to);
                debug_assert_eq!(assign_to, assign_to_w);
                Some(Action::Arith {
                    op,
                    assign_to,
                    operand,
                })
            }
            "todouble" => {
                self.warn_unknown_attrs(el, &["assign_to", "variable"]);
                let to = self.require_attr(el, "assign_to")?;
                let var = self.require_attr(el, "variable")?;
                Some(Action::ToDouble {
                    assign_to: self.var_writes(&to),
                    variable: self.var_reads(&var),
                })
            }
            "jump" => {
                self.warn_unknown_attrs(el, &["value", "variable"]);
                match (el.attr("value"), el.attr("variable")) {
                    (Some(raw), None) => match raw.parse::<usize>() {
                        Ok(dest) => Some(Action::Jump {
                            dest: JumpTarget::Index(dest),
                        }),
                        Err(_) => {
                            self.diags.error(
                                Some(line),
                                format!("jump 'value' must be a message index: '{raw}'"),
                            );
                            None
                        }
                    },
                    (None, Some(v)) => {
                        let v = v.to_owned();
                        Some(Action::Jump {
                            dest: JumpTarget::Var(self.var_reads(&v)),
                        })
                    }
                    _ => {
                        self.diags.error(
                            Some(line),
                            "<jump> needs exactly one of 'value' or 'variable'",
                        );
                        None
                    }
                }
            }
            "pauserestore" => {
                self.warn_unknown_attrs(el, &["value", "variable"]);
                Some(Action::PauseRestore(self.parse_operand(el, line)))
            }
            "closecon" => {
                self.warn_unknown_attrs(el, &[]);
                Some(Action::CloseCon)
            }
            "trim" | "urlencode" | "urldecode" => {
                self.warn_unknown_attrs(el, &["variable"]);
                let var = self.require_attr(el, "variable")?;
                let id = self.var_reads(&var);
                let id_w = self.var_writes(&var);
                debug_assert_eq!(id, id_w);
                Some(match el.name.as_str() {
                    "trim" => Action::Trim { variable: id },
                    "urlencode" => Action::UrlEncode { variable: id },
                    _ => Action::UrlDecode { variable: id },
                })
            }
            "gettimeofday" => {
                self.warn_unknown_attrs(el, &["assign_to"]);
                let raw = self.require_attr(el, "assign_to")?;
                let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
                if let [sec, usec] = parts.as_slice() {
                    let sec = (*sec).to_owned();
                    let usec = (*usec).to_owned();
                    Some(Action::GetTimeOfDay {
                        seconds: self.var_writes(&sec),
                        microseconds: self.var_writes(&usec),
                    })
                } else {
                    self.diags.error(
                        Some(line),
                        "gettimeofday 'assign_to' needs two variables: \"sec,usec\"",
                    );
                    None
                }
            }
            "exec" => {
                self.warn_unknown_attrs(
                    el,
                    &[
                        "int_cmd",
                        "command",
                        "play_pcap",
                        "play_pcap_audio",
                        "play_pcap_video",
                        "play_pcap_image",
                        "play_dtmf",
                        "rtp_stream",
                        "rtp_echo",
                    ],
                );
                let media_attrs = [
                    "rtp_stream",
                    "rtp_echo",
                    "play_dtmf",
                    "play_pcap_audio",
                    "play_pcap_video",
                    "play_pcap_image",
                    "int_cmd",
                    "command",
                ]
                .iter()
                .filter(|a| el.attr(a).is_some())
                .count();
                if media_attrs > 1 {
                    self.diags.error(
                        Some(line),
                        "exec: only one of rtp_stream=/rtp_echo=/play_dtmf=/play_pcap_*=/\
                         int_cmd=/command= per action",
                    );
                    return None;
                }
                if let Some(v) = el.attr("rtp_echo") {
                    return self.parse_rtp_echo(v, line).map(Action::RtpEcho);
                }
                if let Some(v) = el.attr("rtp_stream") {
                    return self.parse_rtp_stream(v, line).map(Action::RtpStream);
                }
                if let Some(v) = el.attr("play_dtmf") {
                    if v.trim().is_empty() {
                        self.diags.error(Some(line), "exec play_dtmf= needs digits");
                        return None;
                    }
                    return Some(Action::PlayDtmf(self.templ(v, line)));
                }
                if el.attr("play_pcap").is_some() {
                    self.diags.error(
                        Some(line),
                        "exec play_pcap= is declared in sipp.dtd but SIPp never implemented \
                         it — use play_pcap_audio= (or _video/_image)",
                    );
                    return None;
                }
                if let Some(action) = self.parse_play_pcap(el) {
                    return action;
                }
                if let Some(command) = el.attr("command") {
                    if command.trim().is_empty() {
                        self.diags
                            .error(Some(line), "exec command= needs a command to run");
                        return None;
                    }
                    return Some(Action::ExecCommand(self.templ(command, line)));
                }
                let cmd = match el.attr("int_cmd").unwrap_or("stop_call") {
                    "stop_now" => IntCmd::StopNow,
                    "stop_gracefully" => IntCmd::StopGracefully,
                    "stop_call" => IntCmd::StopCall,
                    other => {
                        self.diags
                            .error(Some(line), format!("unknown int_cmd '{other}'"));
                        IntCmd::StopCall
                    }
                };
                Some(Action::ExecInt(cmd))
            }
            "lookup" => {
                self.warn_unknown_attrs(el, &["assign_to", "file", "key"]);
                let to = self.require_attr(el, "assign_to")?;
                let file = self.require_attr(el, "file")?;
                let key = self.require_attr(el, "key")?;
                Some(Action::Lookup {
                    file: self.templ(&file, line),
                    key: self.templ(&key, line),
                    assign_to: self.var_writes(&to),
                })
            }
            "insert" => {
                self.warn_unknown_attrs(el, &["file", "value"]);
                let file = self.require_attr(el, "file")?;
                let value = self.require_attr(el, "value")?;
                Some(Action::Insert {
                    file: self.templ(&file, line),
                    value: self.templ(&value, line),
                })
            }
            "replace" => {
                self.warn_unknown_attrs(el, &["file", "line", "value"]);
                let file = self.require_attr(el, "file")?;
                let line_attr = self.require_attr(el, "line")?;
                let value = self.require_attr(el, "value")?;
                Some(Action::Replace {
                    file: self.templ(&file, line),
                    line: self.templ(&line_attr, line),
                    value: self.templ(&value, line),
                })
            }
            "setdest" => {
                self.warn_unknown_attrs(el, &["host", "port", "protocol"]);
                // SIPp `xp_get_string`: each is required.
                let mut value = |name: &str| -> Option<MsgTemplate> {
                    match el.attr(name) {
                        Some(v) => Some(self.templ(v, line)),
                        None => {
                            self.diags.error(
                                Some(line),
                                format!("setdest is missing the required '{name}' parameter."),
                            );
                            None
                        }
                    }
                };
                let host = value("host");
                let port = value("port");
                let protocol = value("protocol");
                Some(Action::SetDest {
                    host: host?,
                    port: port?,
                    protocol: protocol?,
                })
            }
            "sample" => {
                let mut allowed = vec!["assign_to"];
                allowed.extend(crate::distribution::all_param_attrs(false));
                self.warn_unknown_attrs(el, &allowed);
                let to = self.require_attr(el, "assign_to")?;
                let Some(kind) = crate::distribution::kind_of(&|name| el.attr(name), false) else {
                    self.diags.error(
                        Some(line),
                        "statistically distributed actions or pauses requires 'distribution' parameter",
                    );
                    return None;
                };
                let distribution = self.parse_distribution(el, &kind, false)?;
                Some(Action::Sample {
                    assign_to: self.var_writes(&to),
                    distribution,
                })
            }
            "index" => {
                self.diags.error(
                    Some(line),
                    "action <index> is not supported — sipr builds injection indexes from \
                     -infindex at load (docs/SIPP_COMPAT.md §1)",
                );
                None
            }
            "rtp_echo" => {
                self.warn_unknown_attrs(el, &["value", "variable"]);
                Some(Action::RtpEchoState(self.parse_operand(el, line)))
            }
            other => {
                self.diags
                    .error(Some(line), format!("unknown action <{other}>"));
                None
            }
        }
    }

    /// `exec rtp_echo="<verb>[,payload_type[,payload_name]]"` — SIPp's
    /// `setRTPEchoActInfo` grammar; verbs matched by prefix as SIPp does.
    fn parse_rtp_echo(&mut self, value: &str, line: u32) -> Option<RtpEchoCmd> {
        let mut fields = value.trim().split(',').map(str::trim);
        let verb_text = fields.next().unwrap_or_default();
        let (verb, video) = if let Some(rest) = verb_text.strip_prefix("start") {
            (RtpEchoVerb::Start, rest)
        } else if let Some(rest) = verb_text.strip_prefix("update") {
            (RtpEchoVerb::Update, rest)
        } else if let Some(rest) = verb_text.strip_prefix("stop") {
            (RtpEchoVerb::Stop, rest)
        } else {
            self.diags.error(
                Some(line),
                format!(
                    "exec rtp_echo=\"{verb_text}\": expected startaudio|updateaudio|stopaudio|\
                     startvideo|updatevideo|stopvideo"
                ),
            );
            return None;
        };
        let video = match video {
            "audio" => false,
            "video" => true,
            _ => {
                self.diags.error(
                    Some(line),
                    format!("exec rtp_echo=\"{verb_text}\": verb must end in audio or video"),
                );
                return None;
            }
        };
        let payload_type = match fields.next().filter(|f| !f.is_empty()) {
            None => None,
            Some(raw) => match raw.parse::<u8>() {
                Ok(pt) if pt <= 127 => Some(pt),
                _ => {
                    self.diags.error(
                        Some(line),
                        format!("exec rtp_echo=: invalid payload type '{raw}' (0..=127)"),
                    );
                    return None;
                }
            },
        };
        let payload_name = fields
            .next()
            .filter(|f| !f.is_empty())
            .map(ToOwned::to_owned);
        Some(RtpEchoCmd {
            verb,
            video,
            payload_type,
            payload_name,
        })
    }

    /// `exec rtp_stream="file|apattern|vpattern|pause|resume[,...]"` —
    /// SIPp's `setRTPStreamActInfo` grammar: `name,loops|pattern_id,
    /// payload_type,payload_name`. Codec parameters are resolved by the
    /// engine (it knows the `-rtp_payload` default).
    fn parse_rtp_stream(&mut self, value: &str, line: u32) -> Option<RtpStreamCmd> {
        let value = value.trim();
        let control = match value {
            "pause" => Some(RtpStreamCmd::Pause { video: None }),
            "resume" => Some(RtpStreamCmd::Resume { video: None }),
            "pauseapattern" => Some(RtpStreamCmd::Pause { video: Some(false) }),
            "resumeapattern" => Some(RtpStreamCmd::Resume { video: Some(false) }),
            "pausevpattern" => Some(RtpStreamCmd::Pause { video: Some(true) }),
            "resumevpattern" => Some(RtpStreamCmd::Resume { video: Some(true) }),
            _ => None,
        };
        if control.is_some() {
            return control;
        }
        let mut fields = value.split(',').map(str::trim);
        let name = fields.next().unwrap_or_default();
        if name.is_empty() {
            self.diags
                .error(Some(line), "exec rtp_stream= needs a file name or pattern");
            return None;
        }
        let pattern = name
            .strip_prefix("apattern")
            .map(|_| false)
            .or_else(|| name.strip_prefix("vpattern").map(|_| true));
        let second = fields.next().filter(|f| !f.is_empty());
        let payload_type = match fields.next().filter(|f| !f.is_empty()) {
            None => None,
            Some(raw) => match raw.parse::<u8>() {
                Ok(pt) if pt <= 127 => Some(pt),
                _ => {
                    self.diags.error(
                        Some(line),
                        format!("exec rtp_stream=: invalid payload type '{raw}' (0..=127)"),
                    );
                    return None;
                }
            },
        };
        let payload_name = fields
            .next()
            .filter(|f| !f.is_empty())
            .map(ToOwned::to_owned);
        if fields.next().is_some() {
            self.diags.warn(
                Some(line),
                "exec rtp_stream=: extra fields after payload_name are ignored",
            );
        }
        let (source, loops) = match pattern {
            Some(video) => {
                // SIPp: pattern id from the 2nd field (default 1), loop forever.
                let id = match second.map(str::parse::<u8>) {
                    None => 1,
                    Some(Ok(id)) if (1..=6).contains(&id) => id,
                    Some(_) => {
                        self.diags
                            .error(Some(line), "exec rtp_stream=: pattern id must be 1..=6");
                        return None;
                    }
                };
                (RtpSource::Pattern { video, id }, -1)
            }
            None => {
                let loops = match second.map(str::parse::<i64>) {
                    None => 1,
                    Some(Ok(n)) if n >= -1 => n,
                    Some(_) => {
                        self.diags.error(
                            Some(line),
                            "exec rtp_stream=: loop count must be -1 (forever) or >= 0",
                        );
                        return None;
                    }
                };
                (RtpSource::File(name.to_owned()), loops)
            }
        };
        Some(RtpStreamCmd::Play {
            source,
            loops,
            payload_type,
            payload_name,
        })
    }

    /// `exec play_pcap_audio|video|image="file"`. `Some(None)` when the
    /// element is a pcap action but invalid (already diagnosed); `None` when
    /// it carries no pcap attribute at all.
    fn parse_play_pcap(&mut self, el: &Element) -> Option<Option<Action>> {
        const ATTRS: [(&str, MediaKind); 3] = [
            ("play_pcap_audio", MediaKind::Audio),
            ("play_pcap_video", MediaKind::Video),
            ("play_pcap_image", MediaKind::Image),
        ];
        let present: Vec<(MediaKind, &str)> = ATTRS
            .iter()
            .filter_map(|(attr, kind)| el.attr(attr).map(|v| (*kind, v)))
            .collect();
        let (kind, file) = *present.first()?;
        if present.len() > 1 {
            self.diags.error(
                Some(el.line),
                "exec: only one play_pcap_* attribute per action (SIPp plays one \
                 stream per exec)",
            );
            return Some(None);
        }
        if el.attr("int_cmd").is_some() || el.attr("command").is_some() {
            self.diags.error(
                Some(el.line),
                "exec: play_pcap_* cannot be combined with int_cmd= or command=",
            );
            return Some(None);
        }
        let file = file.trim();
        if file.is_empty() {
            self.diags.error(
                Some(el.line),
                format!("exec play_pcap_{}= needs a file name", kind.as_str()),
            );
            return Some(None);
        }
        if file.starts_with('[') && file.ends_with(']') {
            // SIPp looks a bracketed value up in its `-key` table; sipr has
            // no -key yet, so this would be a literal path that cannot exist.
            self.diags.error(
                Some(el.line),
                format!(
                    "exec play_pcap_{}=\"{file}\": bracketed -key references are not \
                     supported yet — write the path",
                    kind.as_str()
                ),
            );
            return Some(None);
        }
        Some(Some(Action::PlayPcap {
            kind,
            file: file.to_owned(),
        }))
    }

    fn require_attr(&mut self, el: &Element, name: &str) -> Option<String> {
        let v = el.attr(name).map(ToOwned::to_owned);
        if v.is_none() {
            self.diags.error(
                Some(el.line),
                format!("<{}> needs a '{name}' attribute", el.name),
            );
        }
        v
    }

    // ---- finalization --------------------------------------------------

    /// Run the lints and report the findings no directive silences.
    fn run_lints(&mut self) {
        let input = LintInput {
            steps: &self.steps,
            send_lines: &self.send_lines,
            unexpected_jump: self.labels.get("_unexp.main").copied(),
            unexp_retaddr: self.vars.find("_unexp.retaddr"),
        };
        for finding in lint::run(&input) {
            let allowed = self
                .lint_allows
                .iter()
                .any(|(step, lints)| *step == finding.step && lints.contains(&finding.lint));
            if !allowed {
                self.diags.lint(finding.lint, finding.line, finding.message);
            }
        }
    }

    fn finish(mut self) -> CompileOutcome {
        // Resolve label references.
        for p in std::mem::take(&mut self.pending) {
            match self.labels.get(&p.label) {
                Some(&dest) => {
                    let slot = match self.steps.get_mut(p.step) {
                        Some(Step::Send(s)) => Some(&mut s.common.next),
                        Some(Step::Recv(r)) => match p.slot {
                            Slot::Next => Some(&mut r.common.next),
                            Slot::Ontimeout => Some(&mut r.ontimeout),
                        },
                        Some(
                            Step::Pause { common, .. }
                            | Step::Nop { common, .. }
                            | Step::SendCmd { common, .. }
                            | Step::RecvCmd { common, .. },
                        ) => Some(&mut common.next),
                        _ => None,
                    };
                    if let Some(slot) = slot {
                        *slot = Some(dest);
                    }
                }
                None => self.diags.error(
                    Some(p.line),
                    format!("reference to undefined label '{}'", p.label),
                ),
            }
        }
        // Bounds-check jump actions.
        let max = self.steps.len();
        let mut bad_jumps = Vec::new();
        for step in &self.steps {
            let actions = match step {
                Step::Send(s) => &s.actions,
                Step::Recv(r) => &r.actions,
                Step::Nop { actions, .. } | Step::RecvCmd { actions, .. } => actions,
                _ => continue,
            };
            for a in actions {
                if let Action::Jump {
                    dest: JumpTarget::Index(dest),
                } = a
                    && *dest >= max
                {
                    bad_jumps.push(*dest);
                }
            }
        }
        for dest in bad_jumps {
            self.diags.error(
                None,
                format!("jump to message index {dest} is out of range (0..{max})"),
            );
        }
        self.validate_txn_usage();
        // Role detection.
        let role = self.steps.iter().find_map(|s| match s {
            Step::Send(_) => Some(Role::Uac),
            Step::Recv(_) => Some(Role::Uas),
            _ => None,
        });
        if role.is_none() {
            self.diags
                .error(None, "scenario has no <send> or <recv> steps");
        }
        // Variable usage.
        for id in 0..self.vars.len() {
            let name = self.vars.name(id).to_owned();
            // `_unexp.retaddr` / `_unexp.pausedaddr` are written by the
            // engine on an `_unexp.main` jump, not by an action. A global's
            // value may come from `-set` or from the other scenario's
            // actions, so "never set here" is no finding for it.
            let engine_set = name.starts_with("_unexp.") || self.vars.scope(id) == VarScope::Global;
            match (self.var_read[id], self.var_written[id] || engine_set) {
                (true, false) => self.diags.error(
                    None,
                    format!("variable '{name}' is read but never set by any action"),
                ),
                (false, true) => self.diags.warn(
                    None,
                    format!(
                        "variable '{name}' is set but never used — list it in \
                         <Reference variables=\"{name}\"/> to silence this"
                    ),
                ),
                _ => {}
            }
        }
        // Lint only what compiled: a broken scenario's flow means nothing.
        if self.lint && !self.diags.has_errors() {
            self.run_lints();
        }
        let scenario = if self.diags.has_errors() {
            None
        } else {
            role.map(|role| Scenario {
                name: self.name,
                role,
                steps: self.steps,
                response_time_repartition: self.response_time_repartition,
                call_length_repartition: self.call_length_repartition,
                // SIPp: `labelMap.find("_unexp.main")`, `find_var` on the two
                // `_unexp.*` names — present only if the scenario mentions them.
                unexpected_jump: self.labels.get("_unexp.main").copied(),
                unexp_retaddr: self.vars.find("_unexp.retaddr"),
                unexp_pausedaddr: self.vars.find("_unexp.pausedaddr"),
                vars: self.vars,
                transactions: self
                    .txns
                    .into_iter()
                    .map(|t| Transaction {
                        name: t.name,
                        is_invite: t.is_invite,
                    })
                    .collect(),
            })
        };
        CompileOutcome {
            scenario,
            diagnostics: self.diags.into_items(),
        }
    }
}
