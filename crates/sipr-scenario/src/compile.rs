//! Compile a scenario XML document into the flat step IR.
//!
//! Diagnostics policy (docs/SIPP_COMPAT.md rule zero): unknown *attributes*
//! and *keywords* warn loudly and are otherwise ignored/passed through, but
//! unknown or unsupported *elements and actions* are hard errors — silently
//! skipping a step would change the call flow, which is worse than refusing
//! to run.

use std::collections::HashMap;

use crate::diag::{Diagnostic, Diagnostics};
use crate::model::{
    Action, ArithOp, CompareOp, Expect, IntCmd, JumpTarget, MediaKind, Operand, PauseSpec,
    RecvStep, Role, RtpEchoCmd, RtpEchoVerb, RtpSource, RtpStreamCmd, Scenario, SearchIn, SendStep,
    Step, StepCommon, StepIndex, VarId, VarScope, VarTable,
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
        vars: VarTable::default(),
        var_read: Vec::new(),
        var_written: Vec::new(),
        var_first_line: Vec::new(),
        cur_line: 0,
        steps: Vec::new(),
        labels: HashMap::new(),
        pending: Vec::new(),
        name: String::new(),
        response_time_repartition: Vec::new(),
        call_length_repartition: Vec::new(),
    };
    c.compile_root(&root, source_name);
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

struct Compiler {
    diags: Diagnostics,
    vars: VarTable,
    var_read: Vec<bool>,
    var_written: Vec<bool>,
    /// Line of the top-level element that first mentioned each variable.
    var_first_line: Vec<u32>,
    /// Line of the top-level element being compiled.
    cur_line: u32,
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
        let t = template::tokenize(text, line, &mut self.diags);
        // `[$v]` reads, and `[fieldN line=[$v]]` reads its selector variable.
        let mut vars: Vec<String> = t
            .keywords()
            .filter_map(|k| match k {
                Keyword::Var(v) => Some(v.clone()),
                Keyword::Field {
                    line: Some(template::LineExpr::Var(v)),
                    ..
                } => Some(v.clone()),
                _ => None,
            })
            .collect();
        // `[authentication username=[$u] aka_K=[field2]]`: SIPp renders each
        // parameter as a sub-message, so their `[$var]` reads count too.
        for k in t.keywords() {
            if let Keyword::Authentication(params) = k {
                for (_, value) in params {
                    if value.contains('[') {
                        let sub = template::tokenize(value, line, &mut self.diags);
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
        // Collect elements first so labels can be registered in step order.
        let children: Vec<&Element> = root.child_elements().collect();
        for el in children {
            self.compile_element(el);
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
            "ack_txn", // + common
        ];
        for txn in ["start_txn", "ack_txn"] {
            if el.attr(txn).is_some() {
                self.diags.error(
                    Some(el.line),
                    format!("attribute '{txn}' (manual transactions) is not supported yet — v1.x"),
                );
            }
        }
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
            }
        }
        let normalized = template::normalize_cdata(&body);
        if normalized.is_empty() {
            self.diags
                .error(Some(el.line), "<send> has no message body");
        }
        let tmpl = self.templ(&normalized, cdata_line);
        self.steps.push(Step::Send(SendStep {
            template: tmpl,
            retrans_ms,
            lost_pct,
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
        if el.attr("response_txn").is_some() {
            self.diags.error(
                Some(el.line),
                "attribute 'response_txn' (manual transactions) is not supported yet — v1.x",
            );
        }
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
            actions,
            common,
        };
        self.steps.push(Step::Recv(recv));
    }

    fn compile_pause(&mut self, el: &Element) {
        const ATTRS: &[&str] = &["milliseconds", "variable", "distribution", "sanity_check"];
        let common = self.parse_common(el, ATTRS);
        // `sanity_check` only tunes a runtime warning in SIPp; accepted, no-op.
        let ms = el.attr("milliseconds");
        let var = el.attr("variable").map(ToOwned::to_owned);
        let dist = el.attr("distribution");
        let spec = match (ms, &var, dist) {
            (None, None, None) => PauseSpec::Default,
            (Some(_), None, None) => match self.parse_num_attr(el, "milliseconds") {
                Some(v) => PauseSpec::Fixed(v),
                None => PauseSpec::Default,
            },
            (None, Some(v), None) => {
                let id = self.var_reads(v);
                PauseSpec::Variable(id)
            }
            (None, None, Some(d)) => self.parse_distribution(d, el.line),
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
    fn compile_send_cmd(&mut self, el: &Element) {
        // `dest=` (extended 3pcc peer routing) is not supported.
        if el.attr("dest").is_some() {
            self.diags.error(
                Some(el.line),
                "sendCmd 'dest' (extended 3PCC) is not supported yet — classic -3pcc only",
            );
        }
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
            }
        }
        let normalized = template::normalize_cdata(&body);
        if normalized.is_empty() {
            self.diags
                .error(Some(el.line), "<sendCmd> has no command body (CDATA)");
        }
        let template = self.templ(&normalized, cdata_line);
        self.steps.push(Step::SendCmd { template, common });
    }

    /// `<recvCmd>` — wait for a twin command; its `<action>`s run against the
    /// received command text.
    fn compile_recv_cmd(&mut self, el: &Element) {
        if el.attr("src").is_some() {
            self.diags.error(
                Some(el.line),
                "recvCmd 'src' (extended 3PCC) is not supported yet — classic -3pcc only",
            );
        }
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

    fn parse_distribution(&mut self, raw: &str, line: u32) -> PauseSpec {
        const KINDS: &[&str] = &[
            "uniform",
            "normal",
            "exponential",
            "lognormal",
            "weibull",
            "pareto",
            "gamma",
            "negbin",
            "poisson",
            "fixed",
        ];
        let (kind, rest) = raw.split_once('(').unwrap_or((raw, ""));
        let kind = kind.trim();
        if !KINDS.contains(&kind) {
            self.diags.error(
                Some(line),
                format!("unknown pause distribution '{kind}' (expected one of {KINDS:?})"),
            );
            return PauseSpec::Default;
        }
        let params: Vec<f64> = rest
            .trim_end_matches(')')
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect();
        PauseSpec::Distribution {
            kind: kind.to_owned(),
            params,
        }
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
                    other => {
                        self.diags.error(
                            Some(line),
                            format!("search_in must be msg|hdr, got '{other}'"),
                        );
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
                if el.attr("command").is_some() {
                    self.diags.error(
                        Some(line),
                        "exec command= (external process) is not supported yet — v1.x",
                    );
                    return None;
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
            "sample" | "setdest" | "index" => {
                self.diags.error(
                    Some(line),
                    format!(
                        "action <{}> is not supported yet — planned for v1.x",
                        el.name
                    ),
                );
                None
            }
            "rtp_echo" => {
                self.warn_unknown_attrs(el, &["value", "variable"]);
                if el.attr("variable").is_some() {
                    self.diags.error(
                        Some(line),
                        "<rtp_echo variable=…> is not supported yet — use value=\"0|1\"",
                    );
                    return None;
                }
                let value = self.require_attr(el, "value")?;
                match value.trim().parse::<f64>() {
                    Ok(v) => Some(Action::RtpEchoState(v != 0.0)),
                    Err(_) => {
                        self.diags.error(
                            Some(line),
                            format!("<rtp_echo value=\"{value}\">: expected a number (0 = off)"),
                        );
                        None
                    }
                }
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
            })
        };
        CompileOutcome {
            scenario,
            diagnostics: self.diags.into_items(),
        }
    }
}
