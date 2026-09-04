//! Per-call variable store and the action executor (milestone M6).
//!
//! Variables are indexed slots (compiled from names by `sipr-scenario`); the
//! store is a flat `Vec<Value>`. Actions run when their owning step executes
//! (send/nop) or when a recv matches. `ereg` reads the just-received message;
//! everything else is arithmetic/string/control over the store.

use sipr_net::Inbound;
use sipr_scenario::model::{Action, ArithOp, CompareOp, Operand, SearchIn, VarId, VarTable};
use sipr_scenario::template::MsgTemplate;

use crate::render::{RenderCtx, render_to_string};

/// A call variable value. SIPp variables are loosely typed; we keep a string
/// and an optional numeric view, matching its coercion behavior.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Value {
    /// Never assigned.
    #[default]
    Unset,
    /// A string (from ereg capture, assignstr, ...).
    Str(String),
    /// A double (from arithmetic, test results, todouble).
    Num(f64),
    /// A boolean (from test/strcmp).
    Bool(bool),
}

impl Value {
    /// True when the variable has been set to anything.
    #[must_use]
    pub fn is_set(&self) -> bool {
        !matches!(self, Self::Unset)
    }

    /// Numeric view, coercing strings and bools like SIPp.
    #[must_use]
    pub fn as_num(&self) -> f64 {
        match self {
            Self::Num(n) => *n,
            Self::Bool(true) => 1.0,
            Self::Str(s) => s.trim().parse().unwrap_or(0.0),
            Self::Unset | Self::Bool(false) => 0.0,
        }
    }

    /// String view for keyword substitution.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Num(n) => format_num(*n),
            Self::Bool(b) => b.to_string(),
            Self::Unset => String::new(),
        }
    }
}

/// Format a double the way SIPp prints variables: integers without a fraction.
fn format_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        #[allow(clippy::cast_possible_truncation)]
        {
            (n as i64).to_string()
        }
    } else {
        n.to_string()
    }
}

/// Per-call variable store.
#[derive(Debug, Clone)]
pub struct VarStore {
    slots: Vec<Value>,
}

impl VarStore {
    /// Store sized for a scenario's variable table.
    #[must_use]
    pub fn new(vars: &VarTable) -> Self {
        Self {
            slots: vec![Value::Unset; vars.len()],
        }
    }

    /// Read a variable (Unset if out of range).
    #[must_use]
    pub fn get(&self, id: VarId) -> &Value {
        self.slots.get(id).unwrap_or(&Value::Unset)
    }

    /// Write a variable (ignored if out of range — compiler guarantees range).
    pub fn set(&mut self, id: VarId, value: Value) {
        if let Some(slot) = self.slots.get_mut(id) {
            *slot = value;
        }
    }

    /// Is this variable set? (backs `test`/`condexec`).
    #[must_use]
    pub fn is_set(&self, id: VarId) -> bool {
        self.get(id).is_set()
    }
}

/// What an action asked the engine to do next.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionOutcome {
    /// Continue normally.
    Continue,
    /// A `<log>`/`<warning>` produced a line for the error trace.
    Log(String),
    /// Fail this call (`<error>`, `ereg check_it` miss, `exec stop_call`).
    FailCall(String),
    /// Jump to a message index (`<jump>`).
    Jump(usize),
    /// Stop the whole run gracefully (`exec stop_gracefully`).
    StopGracefully,
    /// Stop the whole run immediately (`exec stop_now`).
    StopNow,
    /// Start a pcap replay for this call (`exec play_pcap_*`). Not terminal:
    /// the scenario continues immediately, as in SIPp.
    PlayPcap {
        /// Which stream.
        kind: sipr_scenario::model::MediaKind,
        /// The file as written in the scenario (the engine's pcap table key).
        file: String,
    },
    /// `exec rtp_stream=`: start/pause/resume a generated RTP stream. Not
    /// terminal.
    RtpStream(sipr_scenario::model::RtpStreamCmd),
    /// `exec play_dtmf=`: the rendered `digits[,tone_ms]` value. Not terminal.
    PlayDtmf(String),
    /// `<rtp_echo value=>`: switch global echoing. Not terminal.
    RtpEcho(bool),
}

/// Run every action in order, mutating the store and collecting outcomes.
/// Control-flow outcomes (jump/fail/stop) short-circuit the rest.
pub fn run_actions(
    actions: &[Action],
    store: &mut VarStore,
    last_msg: Option<&Inbound>,
    base_ctx: &RenderCtx<'_>,
) -> Vec<ActionOutcome> {
    run_actions_impl(actions, store, last_msg, None, base_ctx)
}

/// Like [`run_actions`], but `ereg` searches the raw 3PCC command `cmd_text`
/// instead of a received SIP message (`<recvCmd>` actions).
pub fn run_cmd_actions(
    actions: &[Action],
    store: &mut VarStore,
    cmd_text: &str,
    base_ctx: &RenderCtx<'_>,
) -> Vec<ActionOutcome> {
    run_actions_impl(actions, store, None, Some(cmd_text), base_ctx)
}

fn run_actions_impl(
    actions: &[Action],
    store: &mut VarStore,
    last_msg: Option<&Inbound>,
    cmd_text: Option<&str>,
    base_ctx: &RenderCtx<'_>,
) -> Vec<ActionOutcome> {
    let mut out = Vec::new();
    for action in actions {
        let outcome = run_one(action, store, last_msg, cmd_text, base_ctx);
        let terminal = !matches!(
            outcome,
            ActionOutcome::Continue
                | ActionOutcome::Log(_)
                | ActionOutcome::PlayPcap { .. }
                | ActionOutcome::RtpStream(_)
                | ActionOutcome::PlayDtmf(_)
                | ActionOutcome::RtpEcho(_)
        );
        out.push(outcome);
        if terminal {
            break;
        }
    }
    out
}

/// Render `t` with `[$var]` resolved from the CURRENT store (not the snapshot
/// baked into `base_ctx`), so a `<log>` sees earlier actions' writes.
fn render_with_store(t: &MsgTemplate, store: &VarStore, base_ctx: &RenderCtx<'_>) -> String {
    let mut ctx = base_ctx.clone();
    if let Some(vc) = ctx.var_ctx.as_mut() {
        vc.store = store;
    }
    render_to_string(t, &ctx, None)
}

#[allow(clippy::too_many_lines)]
fn run_one(
    action: &Action,
    store: &mut VarStore,
    last_msg: Option<&Inbound>,
    cmd_text: Option<&str>,
    base_ctx: &RenderCtx<'_>,
) -> ActionOutcome {
    match action {
        Action::Ereg {
            regexp,
            search_in,
            header,
            start_line,
            check_it,
            assign_to,
        } => {
            let haystack = match cmd_text {
                Some(text) => cmd_haystack(*search_in, header.as_deref(), text),
                None => ereg_haystack(*search_in, header.as_deref(), *start_line, last_msg),
            };
            match regexp.find_strings(haystack.as_bytes()) {
                Some(caps) => {
                    // assign_to[0] gets the whole match; [1..] get groups.
                    for (i, &var) in assign_to.iter().enumerate() {
                        let val = caps
                            .get(i)
                            .and_then(Clone::clone)
                            .map_or(Value::Unset, Value::Str);
                        store.set(var, val);
                    }
                    ActionOutcome::Continue
                }
                None => {
                    for &var in assign_to {
                        store.set(var, Value::Unset);
                    }
                    if *check_it {
                        ActionOutcome::FailCall(format!(
                            "ereg /{}/ did not match (check_it)",
                            regexp.raw
                        ))
                    } else {
                        ActionOutcome::Continue
                    }
                }
            }
        }
        Action::Log(t) => {
            ActionOutcome::Log(format!("[log] {}", render_with_store(t, store, base_ctx)))
        }
        Action::Warn(t) => ActionOutcome::Log(format!(
            "[warning] {}",
            render_with_store(t, store, base_ctx)
        )),
        Action::Fail(t) => ActionOutcome::FailCall(render_with_store(t, store, base_ctx)),
        Action::Assign {
            assign_to,
            variable,
        } => {
            store.set(*assign_to, store.get(*variable).clone());
            ActionOutcome::Continue
        }
        Action::AssignStr { assign_to, value } => {
            let rendered = render_with_store(value, store, base_ctx);
            store.set(*assign_to, Value::Str(rendered));
            ActionOutcome::Continue
        }
        Action::Strcmp {
            assign_to,
            variable,
            value,
        } => {
            // SIPp strcmp: 0 when equal (C strcmp semantics).
            let equal = store.get(*variable).as_str() == *value;
            store.set(*assign_to, Value::Num(if equal { 0.0 } else { 1.0 }));
            ActionOutcome::Continue
        }
        Action::Test {
            assign_to,
            variable,
            compare,
            value,
        } => {
            let lhs = store.get(*variable).as_num();
            let result = match compare {
                CompareOp::Equal => (lhs - *value).abs() < f64::EPSILON,
                CompareOp::NotEqual => (lhs - *value).abs() >= f64::EPSILON,
                CompareOp::Greater => lhs > *value,
                CompareOp::GreaterEqual => lhs >= *value,
                CompareOp::Less => lhs < *value,
                CompareOp::LessEqual => lhs <= *value,
            };
            store.set(*assign_to, Value::Bool(result));
            ActionOutcome::Continue
        }
        Action::Arith {
            op,
            assign_to,
            operand,
        } => {
            let lhs = store.get(*assign_to).as_num();
            let rhs = match operand {
                Operand::Value(v) => *v,
                Operand::Var(id) => store.get(*id).as_num(),
            };
            let result = match op {
                ArithOp::Add => lhs + rhs,
                ArithOp::Subtract => lhs - rhs,
                ArithOp::Multiply => lhs * rhs,
                ArithOp::Divide => {
                    if rhs == 0.0 {
                        lhs
                    } else {
                        lhs / rhs
                    }
                }
            };
            store.set(*assign_to, Value::Num(result));
            ActionOutcome::Continue
        }
        Action::ToDouble {
            assign_to,
            variable,
        } => {
            store.set(*assign_to, Value::Num(store.get(*variable).as_num()));
            ActionOutcome::Continue
        }
        Action::Jump { dest } => ActionOutcome::Jump(*dest),
        Action::Trim { variable } => {
            let v = store.get(*variable).as_str().trim().to_owned();
            store.set(*variable, Value::Str(v));
            ActionOutcome::Continue
        }
        Action::GetTimeOfDay {
            seconds,
            microseconds,
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            store.set(*seconds, Value::Num(now.as_secs() as f64));
            store.set(*microseconds, Value::Num(f64::from(now.subsec_micros())));
            ActionOutcome::Continue
        }
        Action::UrlEncode { variable } => {
            let encoded = url_encode(&store.get(*variable).as_str());
            store.set(*variable, Value::Str(encoded));
            ActionOutcome::Continue
        }
        Action::UrlDecode { variable } => {
            let decoded = url_decode(&store.get(*variable).as_str());
            store.set(*variable, Value::Str(decoded));
            ActionOutcome::Continue
        }
        Action::PlayPcap { kind, file } => ActionOutcome::PlayPcap {
            kind: *kind,
            file: file.clone(),
        },
        Action::RtpStream(cmd) => ActionOutcome::RtpStream(cmd.clone()),
        Action::PlayDtmf(t) => ActionOutcome::PlayDtmf(render_with_store(t, store, base_ctx)),
        Action::RtpEchoState(on) => ActionOutcome::RtpEcho(*on),
        Action::ExecInt(cmd) => match cmd {
            sipr_scenario::model::IntCmd::StopCall => {
                ActionOutcome::FailCall("exec stop_call".into())
            }
            sipr_scenario::model::IntCmd::StopGracefully => ActionOutcome::StopGracefully,
            sipr_scenario::model::IntCmd::StopNow => ActionOutcome::StopNow,
        },
        Action::Lookup {
            file,
            key,
            assign_to,
        } => {
            let file = render_with_store(file, store, base_ctx);
            let key = render_with_store(key, store, base_ctx);
            match base_ctx.fields.lookup_line(&file, &key) {
                Ok(line) => {
                    store.set(*assign_to, Value::Num(line));
                    ActionOutcome::Continue
                }
                Err(e) => ActionOutcome::FailCall(e),
            }
        }
        Action::Insert { file, value } => {
            let file = render_with_store(file, store, base_ctx);
            let value = render_with_store(value, store, base_ctx);
            match base_ctx.fields.insert_line(&file, &value) {
                Ok(()) => ActionOutcome::Continue,
                Err(e) => ActionOutcome::FailCall(e),
            }
        }
        Action::Replace { file, line, value } => {
            let file = render_with_store(file, store, base_ctx);
            let line_s = render_with_store(line, store, base_ctx);
            let value = render_with_store(value, store, base_ctx);
            let Ok(line_n) = line_s.trim().parse::<usize>() else {
                return ActionOutcome::FailCall(format!("replace: invalid line number '{line_s}'"));
            };
            match base_ctx.fields.replace_line(&file, line_n, &value) {
                Ok(()) => ActionOutcome::Continue,
                Err(e) => ActionOutcome::FailCall(e),
            }
        }
    }
}

/// Haystack for `<recvCmd>` actions: the raw twin command text (`search_in`
/// `msg`), or a header extracted from it (`hdr`). The command is a plain text
/// blob (SIPp treats it likewise), so header extraction is a simple line scan.
fn cmd_haystack(search_in: SearchIn, header: Option<&str>, text: &str) -> String {
    match search_in {
        SearchIn::Msg => text.to_owned(),
        SearchIn::Hdr => {
            let want = header.unwrap_or("").trim_end_matches(':');
            text.lines()
                .filter_map(|l| {
                    l.split_once(':').and_then(|(name, val)| {
                        name.trim().eq_ignore_ascii_case(want).then(|| val.trim())
                    })
                })
                .collect::<Vec<_>>()
                .join("\r\n")
        }
    }
}

fn ereg_haystack(
    search_in: SearchIn,
    header: Option<&str>,
    start_line: bool,
    last: Option<&Inbound>,
) -> String {
    let Some(msg) = last else {
        return String::new();
    };
    match search_in {
        SearchIn::Hdr => header
            .map(|h| msg.header_lines(h).join("\r\n"))
            .unwrap_or_default(),
        SearchIn::Msg => {
            if start_line {
                msg.start_line().to_owned()
            } else {
                msg.reconstruct()
            }
        }
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_coercions() {
        assert_eq!(Value::Str("42".into()).as_num(), 42.0);
        assert_eq!(Value::Num(3.0).as_str(), "3");
        assert_eq!(Value::Num(3.5).as_str(), "3.5");
        assert_eq!(Value::Bool(true).as_num(), 1.0);
        assert_eq!(Value::Unset.as_str(), "");
        assert!(!Value::Unset.is_set());
        assert!(Value::Num(0.0).is_set());
    }

    #[test]
    fn url_roundtrip() {
        let s = "sip:alice@example.com;tag=a b";
        assert_eq!(url_decode(&url_encode(s)), s);
        assert_eq!(url_encode("a b"), "a%20b");
    }
}
