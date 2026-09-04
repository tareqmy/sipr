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
    /// `hide`: leave this step off the scenario screen while `set hide
    /// true` (the default) holds.
    pub hide: bool,
    /// `display`: text shown on the scenario screen instead of the
    /// derived label (SIPp reads it for every message command).
    pub display: Option<String>,
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
    /// `ignoresdp`: do not learn the remote media endpoint from this
    /// message's SDP (media milestones).
    pub ignore_sdp: bool,
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

/// Which media stream an `exec play_pcap_*` action feeds. Each kind is
/// independent: its own SDP `m=` line, its own local port, its own replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaKind {
    /// `play_pcap_audio` — the `m=audio` stream.
    Audio,
    /// `play_pcap_video` — the `m=video` stream.
    Video,
    /// `play_pcap_image` — the `m=image` stream (T.38 / UDPTL).
    Image,
}

impl MediaKind {
    /// Every kind, in index order.
    pub const ALL: [Self; 3] = [Self::Audio, Self::Video, Self::Image];

    /// The SDP media name (`audio` / `video` / `image`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Image => "image",
        }
    }

    /// Stable index (0..3) for per-call arrays.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::Audio => 0,
            Self::Video => 1,
            Self::Image => 2,
        }
    }
}

/// What an `exec rtp_stream=` streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtpSource {
    /// A raw codec file (a RIFF/WAVE header is skipped, not decoded).
    File(String),
    /// SIPp's `apattern`/`vpattern` test patterns, id 1..=6.
    Pattern {
        /// `vpattern` (video) vs `apattern` (audio).
        video: bool,
        /// Pattern id.
        id: u8,
    },
}

/// `exec rtp_stream="..."` — SIPp `rtpstream.cpp` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtpStreamCmd {
    /// Start (or replace) a stream.
    Play {
        /// File or pattern.
        source: RtpSource,
        /// Loop count; `-1` = forever.
        loops: i64,
        /// Payload type; `None` = the `-rtp_payload` default (8).
        payload_type: Option<u8>,
        /// Payload name (`PCMU/8000`, ...); `None` = SIPp's default for the
        /// static types 0/8/9/18.
        payload_name: Option<String>,
    },
    /// `pause` / `pauseapattern` / `pausevpattern`.
    Pause {
        /// `None` = every stream of the call; `Some(video?)` = one kind.
        video: Option<bool>,
    },
    /// `resume` / `resumeapattern` / `resumevpattern`.
    Resume {
        /// As for [`RtpStreamCmd::Pause`].
        video: Option<bool>,
    },
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
    /// `exec play_pcap_audio|video|image="file"`: replay a capture's UDP
    /// payloads to the peer's media endpoint (learned from its SDP). The
    /// file is resolved and parsed once by the engine at startup; `file` is
    /// the attribute text verbatim.
    PlayPcap {
        /// Which stream (`m=` line / local port) this feeds.
        kind: MediaKind,
        /// The pcap path as written in the scenario.
        file: String,
    },
    /// `exec rtp_stream="..."`: generated RTP from a file or pattern, or a
    /// pause/resume of the call's streams.
    RtpStream(RtpStreamCmd),
    /// `exec play_dtmf="digits[,tone_ms]"` (keywords allowed, as SIPp
    /// renders the value): RFC 4733 events on the audio stream.
    PlayDtmf(MsgTemplate),
    /// `<rtp_echo value="0|1"/>`: switch the process-wide `-rtp_echo`
    /// echoing off or on (SIPp's global `rtp_echo_state`).
    RtpEchoState(bool),
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
    /// Every action of every step, in step order.
    pub fn all_actions(&self) -> impl Iterator<Item = &Action> {
        self.steps.iter().flat_map(|step| match step {
            Step::Send(s) => s.actions.iter(),
            Step::Recv(r) => r.actions.iter(),
            Step::Nop { actions, .. } | Step::RecvCmd { actions, .. } => actions.iter(),
            _ => [].iter(),
        })
    }

    /// The `(kind, file)` of every `play_pcap_*` action.
    pub fn pcap_actions(&self) -> impl Iterator<Item = (MediaKind, &str)> {
        self.all_actions().filter_map(|a| match a {
            Action::PlayPcap { kind, file } => Some((*kind, file.as_str())),
            _ => None,
        })
    }

    /// Every `rtp_stream` play command.
    pub fn rtp_stream_plays(&self) -> impl Iterator<Item = &RtpStreamCmd> {
        self.all_actions().filter_map(|a| match a {
            Action::RtpStream(cmd @ RtpStreamCmd::Play { .. }) => Some(cmd),
            _ => None,
        })
    }

    /// True when any step plays media (SIPp's `hasMedia`): the engine then
    /// learns remote media endpoints from received SDP.
    #[must_use]
    pub fn has_media(&self) -> bool {
        self.all_actions().any(|a| {
            matches!(
                a,
                Action::PlayPcap { .. } | Action::RtpStream(_) | Action::PlayDtmf(_)
            )
        })
    }

    /// True when any step toggles `<rtp_echo>` (needs `-rtp_echo`).
    #[must_use]
    pub fn toggles_rtp_echo(&self) -> bool {
        self.all_actions()
            .any(|a| matches!(a, Action::RtpEchoState(_)))
    }

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
        Keyword::RtpStreamPort { video, offset } => {
            let base = if *video {
                "rtpstream_video_port"
            } else {
                "rtpstream_audio_port"
            };
            return if *offset > 0 {
                format!("[{base}+{offset}]")
            } else {
                format!("[{base}]")
            };
        }
        Keyword::Crypto {
            kw,
            slot,
            video,
            offset,
        } => {
            let media = if *video { "video" } else { "audio" };
            let base = match kw {
                crate::template::CryptoKw::Tag => "cryptotag".to_owned(),
                crate::template::CryptoKw::KeyParams => "cryptokeyparams".to_owned(),
                crate::template::CryptoKw::Suite(s) => format!("cryptosuite{}", short_suite(s)),
                crate::template::CryptoKw::Unencrypted(s) => format!("ue{}", short_suite(s)),
            };
            let off = match offset {
                0 => String::new(),
                n if *n > 0 => format!("+{n}"),
                n => n.to_string(),
            };
            return format!("[{base}{slot}{media}{off}]");
        }
        Keyword::MediaPort { auto, offset } => {
            let base = if *auto {
                "auto_media_port"
            } else {
                "media_port"
            };
            return if *offset > 0 {
                format!("[{base}+{offset}]")
            } else {
                format!("[{base}]")
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
        Keyword::UserId => "userid",
        Keyword::Users => "users",
        Keyword::Cseq => "cseq",
        Keyword::Branch => "branch",
        Keyword::MsgIndex => "msg_index",
        Keyword::Pid => "pid",
        Keyword::Routes => "routes",
        Keyword::NextUrl => "next_url",
        Keyword::PeerTagParam => "peer_tag_param",
        Keyword::Len => "len",
        Keyword::MediaIp => "media_ip",
        Keyword::MediaIpType => "media_ip_type",
    };
    format!("[{simple}]")
}

/// SIPp's short suite spelling used in keyword names.
fn short_suite(suite: &str) -> &'static str {
    match suite {
        "AES_CM_128_HMAC_SHA1_80" => "aescm128sha180",
        "AES_CM_128_HMAC_SHA1_32" => "aescm128sha132",
        "NULL_HMAC_SHA1_80" => "nullsha180",
        "NULL_HMAC_SHA1_32" => "nullsha132",
        _ => "unknown",
    }
}
