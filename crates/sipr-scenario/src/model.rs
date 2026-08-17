//! The compiled scenario IR: a flat step list in message-index order, exactly
//! SIPp's execution model (docs/ARCHITECTURE.md §4). Jump targets are resolved
//! to indices and variables to table slots at compile time — the engine never
//! sees names.

use crate::template::{Keyword, MsgTemplate, Span};

/// Index into [`Scenario::steps`].
pub type StepIndex = usize;
/// Index into the scenario's variable table.
pub type VarId = usize;

/// Which side of the call this scenario plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// First message command is a `send`: we place calls.
    Uac,
    /// First message command is a `recv`: we answer calls.
    Uas,
}

/// Per-call variable table: names interned to indices at compile time.
#[derive(Debug, Default, Clone)]
pub struct VarTable {
    names: Vec<String>,
}

impl VarTable {
    /// Intern `name`, returning its id.
    pub fn intern(&mut self, name: &str) -> VarId {
        if let Some(i) = self.names.iter().position(|n| n == name) {
            return i;
        }
        self.names.push(name.to_owned());
        self.names.len() - 1
    }

    /// Name of a variable id.
    #[must_use]
    pub fn name(&self, id: VarId) -> &str {
        self.names.get(id).map_or("?", String::as_str)
    }

    /// Number of variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// True if no variables are defined.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Attributes shared by all message commands (`%messageCmdCommon` in the DTD).
#[derive(Debug, Clone, Default)]
pub struct StepCommon {
    /// `start_rtd`: start this response-time stopwatch.
    pub start_rtd: Option<String>,
    /// `rtd`: stop this response-time stopwatch.
    pub rtd: Option<String>,
    /// `repeat_rtd`: restart the stopwatch instead of stopping it once.
    pub repeat_rtd: bool,
    /// `crlf`: blank line after this step in the statistics screen.
    pub crlf: bool,
    /// `next`: jump target (resolved from a label id).
    pub next: Option<StepIndex>,
    /// `test`: only take `next` if this variable is set/true.
    pub test: Option<VarId>,
    /// `chance`: probability (0..=1) of taking `next`.
    pub chance: Option<f64>,
    /// `condexec`: execute this step only if the variable is set.
    pub condexec: Option<VarId>,
    /// `condexec_inverse`: invert the `condexec` test.
    pub condexec_inverse: bool,
    /// `counter`: increment this named counter when the step executes.
    pub counter: Option<String>,
    /// Source line of the element.
    pub line: u32,
}

/// What a `recv` step is waiting for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// `response="200"` — a status code (string, e.g. `200`).
    Response(String),
    /// `request="INVITE"` — a request method.
    Request(String),
}

/// `<send>`.
#[derive(Debug, Clone)]
pub struct SendStep {
    /// Pre-tokenized message body.
    pub template: MsgTemplate,
    /// `retrans`: base retransmission interval in ms.
    pub retrans_ms: Option<u64>,
    /// `lost`: simulated loss percentage.
    pub lost_pct: Option<f64>,
    /// Actions attached to the send.
    pub actions: Vec<Action>,
    /// Shared attributes.
    pub common: StepCommon,
}

/// `<recv>`.
#[derive(Debug, Clone)]
pub struct RecvStep {
    /// Expected response code or request method.
    pub expect: Expect,
    /// `optional`: may be skipped / arrive out of order.
    pub optional: bool,
    /// `regexp_match`: treat the expectation as a regular expression.
    pub regexp_match: bool,
    /// Compiled expectation when `regexp_match` is set.
    pub expect_regex: Option<crate::regex::Regex>,
    /// `timeout`: ms to wait before `ontimeout` (or call failure).
    pub timeout_ms: Option<u64>,
    /// `ontimeout`: jump target on timeout (resolved from a label id).
    pub ontimeout: Option<StepIndex>,
    /// `rrs`: capture the Record-Route set for `[routes]`.
    pub record_route_set: bool,
    /// `auth`: capture a 401/407 challenge for `[authentication]`.
    pub auth: bool,
    /// `lost`: simulated loss percentage.
    pub lost_pct: Option<f64>,
    /// Actions run when the message matches.
    pub actions: Vec<Action>,
    /// Shared attributes.
    pub common: StepCommon,
}

/// How long a `<pause>` lasts.
#[derive(Debug, Clone, PartialEq)]
pub enum PauseSpec {
    /// No attributes: use the `-d` default.
    Default,
    /// `milliseconds="N"`.
    Fixed(u64),
    /// `variable="name"`: duration from a call variable.
    Variable(VarId),
    /// `distribution="uniform(200,3000)"` etc.
    Distribution {
        /// Distribution kind (`uniform`, `normal`, `exponential`, ...).
        kind: String,
        /// Numeric parameters.
        params: Vec<f64>,
    },
}

/// One step of the compiled scenario.
#[derive(Debug, Clone)]
pub enum Step {
    /// Send a message.
    Send(SendStep),
    /// Wait for a message.
    Recv(RecvStep),
    /// Wait for a duration.
    Pause {
        /// Duration specification.
        spec: PauseSpec,
        /// Shared attributes.
        common: StepCommon,
    },
    /// No-op step carrying actions.
    Nop {
        /// Actions to run.
        actions: Vec<Action>,
        /// Shared attributes.
        common: StepCommon,
    },
    /// 3PCC: send a command to the twin over the control channel (`<sendCmd>`).
    SendCmd {
        /// The command body, rendered with keywords/variables at send time.
        template: MsgTemplate,
        /// Shared attributes.
        common: StepCommon,
    },
    /// 3PCC: wait for a command from the twin, then run actions against its
    /// text (`<recvCmd>`).
    RecvCmd {
        /// Actions executed against the received command text.
        actions: Vec<Action>,
        /// Shared attributes.
        common: StepCommon,
        /// `optional="true"`.
        optional: bool,
    },
    /// Jump target marker (no-op at runtime).
    Label {
        /// The label id.
        id: String,
        /// Source line.
        line: u32,
    },
    /// Post-scenario linger absorbing late retransmissions.
    Timewait {
        /// Duration in ms.
        ms: u64,
        /// Source line.
        line: u32,
    },
}

/// `search_in` of `ereg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchIn {
    /// Match against the whole message.
    Msg,
    /// Match against one header's value(s).
    Hdr,
}

/// Comparison operator of the `test` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    /// `equal`
    Equal,
    /// `not_equal`
    NotEqual,
    /// `greater_than`
    Greater,
    /// `greater_than_equal`
    GreaterEqual,
    /// `less_than`
    Less,
    /// `less_than_equal`
    LessEqual,
}

/// Arithmetic action kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    /// `<add>`
    Add,
    /// `<subtract>`
    Subtract,
    /// `<multiply>`
    Multiply,
    /// `<divide>`
    Divide,
}

/// Operand of an arithmetic action: a literal or another variable.
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    /// `value="2"`
    Value(f64),
    /// `variable="other"`
    Var(VarId),
}

/// `int_cmd` of the `exec` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntCmd {
    /// Stop everything immediately.
    StopNow,
    /// Stop placing calls, drain, exit.
    StopGracefully,
    /// Fail and abort this call only.
    StopCall,
}

/// A v1 action (docs/SIPP_COMPAT.md §1).
#[derive(Debug, Clone)]
pub enum Action {
    /// Regex capture over the message or a header.
    Ereg {
        /// The compiled pattern (in-tree ERE engine — SIPP_COMPAT §6).
        regexp: crate::regex::Regex,
        /// Where to search.
        search_in: SearchIn,
        /// Header name when `search_in="hdr"`.
        header: Option<String>,
        /// Restrict the search to the start line.
        start_line: bool,
        /// Fail the call if the pattern does not match.
        check_it: bool,
        /// Whole match + capture groups, in order.
        assign_to: Vec<VarId>,
    },
    /// Log a keyword-expanded message.
    Log(MsgTemplate),
    /// Warn with a keyword-expanded message.
    Warn(MsgTemplate),
    /// Fail the call with a keyword-expanded message.
    Fail(MsgTemplate),
    /// Copy one variable to another.
    Assign {
        /// Destination.
        assign_to: VarId,
        /// Source.
        variable: VarId,
    },
    /// Set a variable to a keyword-expanded string.
    AssignStr {
        /// Destination.
        assign_to: VarId,
        /// Value template.
        value: MsgTemplate,
    },
    /// String-compare a variable against a literal; result to a variable.
    Strcmp {
        /// Destination for the comparison result.
        assign_to: VarId,
        /// Variable to compare.
        variable: VarId,
        /// Literal to compare against.
        value: String,
    },
    /// Numeric comparison; boolean result to a variable.
    Test {
        /// Destination for the boolean result.
        assign_to: VarId,
        /// Variable to compare.
        variable: VarId,
        /// Operator.
        compare: CompareOp,
        /// Right-hand side.
        value: f64,
    },
    /// Arithmetic on a variable.
    Arith {
        /// Which operation.
        op: ArithOp,
        /// Destination (and left-hand side).
        assign_to: VarId,
        /// Right-hand side.
        operand: Operand,
    },
    /// Convert a variable to a double.
    ToDouble {
        /// Destination.
        assign_to: VarId,
        /// Source.
        variable: VarId,
    },
    /// Jump to a message index.
    Jump {
        /// Absolute step index.
        dest: StepIndex,
    },
    /// Trim whitespace around a variable's value.
    Trim {
        /// Variable to trim in place.
        variable: VarId,
    },
    /// Store the current time into `seconds,microseconds` variables.
    GetTimeOfDay {
        /// Seconds destination.
        seconds: VarId,
        /// Microseconds destination.
        microseconds: VarId,
    },
    /// URL-encode a variable in place.
    UrlEncode {
        /// Variable to encode.
        variable: VarId,
    },
    /// URL-decode a variable in place.
    UrlDecode {
        /// Variable to decode.
        variable: VarId,
    },
    /// Internal command.
    ExecInt(IntCmd),
    /// Look up a key in an indexed injection file; store the matched line
    /// number (or -1 on a miss) into a variable.
    Lookup {
        /// Injection file, by name (rendered).
        file: MsgTemplate,
        /// Key to look up (rendered).
        key: MsgTemplate,
        /// Destination variable for the line number.
        assign_to: VarId,
    },
    /// Append a rendered `;`-separated line to an injection file.
    Insert {
        /// Injection file, by name (rendered).
        file: MsgTemplate,
        /// The new line (rendered).
        value: MsgTemplate,
    },
    /// Replace a line of an injection file with a rendered value.
    Replace {
        /// Injection file, by name (rendered).
        file: MsgTemplate,
        /// Line number to replace (rendered, then parsed).
        line: MsgTemplate,
        /// Replacement line (rendered).
        value: MsgTemplate,
    },
}

/// A compiled scenario.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// The `name` attribute.
    pub name: String,
    /// UAC or UAS, from the first message command.
    pub role: Role,
    /// Steps in message-index order.
    pub steps: Vec<Step>,
    /// Variable table.
    pub vars: VarTable,
    /// `ResponseTimeRepartition` bucket bounds (ms).
    pub response_time_repartition: Vec<u64>,
    /// `CallLengthRepartition` bucket bounds (ms).
    pub call_length_repartition: Vec<u64>,
}

impl Scenario {
    /// Human-readable dump of the compiled IR (used by `--check`).
    #[must_use]
    pub fn dump(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let role = match self.role {
            Role::Uac => "UAC",
            Role::Uas => "UAS",
        };
        let _ = writeln!(
            out,
            "scenario '{}': role={role}, {} steps, {} variables",
            self.name,
            self.steps.len(),
            self.vars.len()
        );
        for (i, step) in self.steps.iter().enumerate() {
            let line = match step {
                Step::Send(s) => {
                    let first = first_line(&s.template);
                    let mut extra = String::new();
                    if let Some(ms) = s.retrans_ms {
                        let _ = write!(extra, " retrans={ms}ms");
                    }
                    if !s.actions.is_empty() {
                        let _ = write!(extra, " actions={}", s.actions.len());
                    }
                    format!("send{extra}{}: {first}", common_suffix(&s.common))
                }
                Step::Recv(r) => {
                    let what = match &r.expect {
                        Expect::Response(c) => format!("response={c}"),
                        Expect::Request(m) => format!("request={m}"),
                    };
                    let mut extra = String::new();
                    if r.optional {
                        extra.push_str(" optional");
                    }
                    if r.auth {
                        extra.push_str(" auth");
                    }
                    if r.record_route_set {
                        extra.push_str(" rrs");
                    }
                    if let Some(t) = r.timeout_ms {
                        let _ = write!(extra, " timeout={t}ms");
                    }
                    if let Some(d) = r.ontimeout {
                        let _ = write!(extra, " ontimeout->{d}");
                    }
                    if !r.actions.is_empty() {
                        let _ = write!(extra, " actions={}", r.actions.len());
                    }
                    format!("recv {what}{extra}{}", common_suffix(&r.common))
                }
                Step::Pause { spec, common } => {
                    let what = match spec {
                        PauseSpec::Default => "default (-d)".to_owned(),
                        PauseSpec::Fixed(ms) => format!("{ms}ms"),
                        PauseSpec::Variable(v) => format!("variable ${}", self.vars.name(*v)),
                        PauseSpec::Distribution { kind, params } => {
                            format!("{kind}{params:?}")
                        }
                    };
                    format!("pause {what}{}", common_suffix(common))
                }
                Step::Nop { actions, common } => {
                    format!("nop actions={}{}", actions.len(), common_suffix(common))
                }
                Step::SendCmd { common, .. } => {
                    format!("sendCmd (3pcc){}", common_suffix(common))
                }
                Step::RecvCmd {
                    actions,
                    common,
                    optional,
                } => format!(
                    "recvCmd (3pcc) actions={}{}{}",
                    actions.len(),
                    if *optional { " optional" } else { "" },
                    common_suffix(common)
                ),
                Step::Label { id, .. } => format!("label '{id}'"),
                Step::Timewait { ms, .. } => format!("timewait {ms}ms"),
            };
            let _ = writeln!(out, "  {i:>3}: {line}");
        }
        out
    }
}

fn common_suffix(c: &StepCommon) -> String {
    let mut s = String::new();
    if let Some(next) = c.next {
        s.push_str(&format!(" next->{next}"));
    }
    if c.test.is_some() {
        s.push_str(" (test)");
    }
    if c.chance.is_some() {
        s.push_str(" (chance)");
    }
    if c.condexec.is_some() {
        s.push_str(" (condexec)");
    }
    s
}

fn first_line(t: &MsgTemplate) -> String {
    let mut line = String::new();
    for span in &t.spans {
        let text = match span {
            Span::Lit(l) => l.clone(),
            Span::Kw(k) => keyword_name(k),
        };
        if let Some(idx) = text.find('\r') {
            line.push_str(&text[..idx]);
            return line;
        }
        line.push_str(&text);
    }
    line
}

fn keyword_name(k: &Keyword) -> String {
    let simple = match k {
        Keyword::Last(h) => return format!("[last_{h}:]"),
        Keyword::Var(v) => return format!("[${v}]"),
        Keyword::Unknown(u) => return format!("[{u}]"),
        Keyword::Field { index, file, .. } => {
            return match file {
                Some(f) => format!("[field{index} file={f}]"),
                None => format!("[field{index}]"),
            };
        }
        Keyword::Authentication(_) => "authentication",
        Keyword::Service => "service",
        Keyword::RemoteIp => "remote_ip",
        Keyword::RemotePort => "remote_port",
        Keyword::LocalIp => "local_ip",
        Keyword::LocalIpType => "local_ip_type",
        Keyword::LocalPort => "local_port",
        Keyword::Transport => "transport",
        Keyword::CallId => "call_id",
        Keyword::CallNumber => "call_number",
        Keyword::Cseq => "cseq",
        Keyword::Branch => "branch",
        Keyword::MsgIndex => "msg_index",
        Keyword::Pid => "pid",
        Keyword::Routes => "routes",
        Keyword::NextUrl => "next_url",
        Keyword::PeerTagParam => "peer_tag_param",
        Keyword::Len => "len",
        Keyword::MediaIp => "media_ip",
        Keyword::MediaPort => "media_port",
        Keyword::MediaIpType => "media_ip_type",
    };
    format!("[{simple}]")
}
