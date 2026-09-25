//! Scenario lints (M47): scenarios that compile, and run, but do not do
//! what their author meant — the folklore of `docs/SIPP_COMPAT.md` §6
//! turned into diagnostics.
//!
//! A compile error is a scenario sipr cannot run; a lint finding is one
//! that runs and surprises. Lints run only under `--check`
//! ([`crate::CompileOptions::lint`]), where, like every other warning, they
//! fail the check. A test tool must be able to misbehave on purpose, so a
//! `<!-- sipr-lint: allow NAME -->` comment directly before a step silences
//! that lint for that step (the compiler applies the directives; this module
//! only finds).

use crate::model::{Action, Expect, JumpTarget, Step, StepCommon, StepIndex, VarId};
use crate::template::{Keyword, MsgTemplate, Span};

/// One lint, by the name written in diagnostics and `sipr-lint: allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lint {
    /// An optional recv with no mandatory recv after it: it holds the call
    /// exactly as a mandatory one would.
    OptionalWindow,
    /// Steps that no path through the scenario reaches.
    Unreachable,
    /// SDP-looking lines among the headers: the blank line that ends the
    /// headers is missing, so the body goes out as header lines.
    BodySeparator,
    /// A literal `Content-Length` that disagrees with the body, or cannot
    /// agree with it because the body holds keywords.
    ContentLength,
}

impl Lint {
    /// Every lint, in documentation order.
    pub const ALL: [Self; 4] = [
        Self::OptionalWindow,
        Self::Unreachable,
        Self::BodySeparator,
        Self::ContentLength,
    ];

    /// The name used in diagnostics and in `sipr-lint: allow`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::OptionalWindow => "optional-window",
            Self::Unreachable => "unreachable",
            Self::BodySeparator => "body-separator",
            Self::ContentLength => "content-length",
        }
    }

    /// The lint called `name`, if there is one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|lint| lint.name() == name)
    }
}

/// A lint finding, before the `sipr-lint: allow` directives are applied.
#[derive(Debug)]
pub(crate) struct Finding {
    /// Which lint.
    pub(crate) lint: Lint,
    /// The step it belongs to: a directive right before that step
    /// silences it.
    pub(crate) step: StepIndex,
    /// The line to report: the element's, or a header's inside its CDATA.
    pub(crate) line: u32,
    /// What is wrong, and what it does at run time.
    pub(crate) message: String,
}

/// What the lints need to know beyond the steps themselves.
pub(crate) struct LintInput<'a> {
    /// The compiled steps, labels resolved.
    pub(crate) steps: &'a [Step],
    /// For each `<send>`: its step and the source line of the first line of
    /// its message (the start line), so header findings point at the header.
    pub(crate) send_lines: &'a [(StepIndex, u32)],
    /// The `_unexp.main` label, which any unexpected message can reach.
    pub(crate) unexpected_jump: Option<StepIndex>,
    /// `_unexp.retaddr`: a jump through it returns to a step already run.
    pub(crate) unexp_retaddr: Option<VarId>,
}

/// Run every lint.
pub(crate) fn run(input: &LintInput<'_>) -> Vec<Finding> {
    let mut findings = optional_windows(input.steps);
    findings.extend(unreachable_steps(input));
    for &(step, first_line) in input.send_lines {
        if let Some(Step::Send(send)) = input.steps.get(step) {
            findings.extend(message_findings(step, &send.template, first_line));
        }
    }
    findings
}

// ---- optional-window ----------------------------------------------------

/// An optional recv only means something next to a mandatory one: the
/// engine scans the window of optionals *up to* the next mandatory recv for
/// a match. With no mandatory recv behind it the call still waits at the
/// optional, so `optional` changes nothing — except that SIPp refuses the
/// scenario outright when a non-recv step follows (`scenario.cpp`
/// `checkOptionalRecv`), and a trailing one with no timeout hangs the call.
fn optional_windows(steps: &[Step]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut i = 0;
    while i < steps.len() {
        if !is_optional_recv(&steps[i]) {
            i += 1;
            continue;
        }
        let first = i;
        let mut all_timed = true;
        while let Some(step) = steps.get(i) {
            if is_optional_recv(step) {
                all_timed &= matches!(step, Step::Recv(r) if r.timeout_ms.is_some());
            } else if !matches!(step, Step::Label { .. }) {
                break;
            }
            i += 1;
        }
        let message = match steps.get(i) {
            Some(step) if is_recv(step) => continue,
            Some(step) => format!(
                "optional {} has no mandatory <recv> after it before the {} at line {}: \
                 it holds the call exactly as a mandatory one would, and SIPp refuses to \
                 load this scenario (\"<recv> before <{}> sequence without a mandatory \
                 message\")",
                describe(&steps[first]),
                describe(step),
                line_of(step),
                element_name(step),
            ),
            None if all_timed => continue,
            None => format!(
                "optional {} ends the scenario with no mandatory <recv> after it: the \
                 call waits for it all the same, and without a timeout (its own or \
                 -recv_timeout) never ends if it does not arrive — give it timeout= and \
                 ontimeout=, or end the scenario with a <timewait>",
                describe(&steps[first]),
            ),
        };
        findings.push(Finding {
            lint: Lint::OptionalWindow,
            step: first,
            line: line_of(&steps[first]),
            message,
        });
    }
    findings
}

fn is_optional_recv(step: &Step) -> bool {
    matches!(step, Step::Recv(r) if r.optional)
        || matches!(step, Step::RecvCmd { optional: true, .. })
}

/// A recv that can anchor a window: SIPp's check counts `<recvCmd>` too.
fn is_recv(step: &Step) -> bool {
    matches!(step, Step::Recv(_) | Step::RecvCmd { .. })
}

// ---- unreachable --------------------------------------------------------

/// Steps no path reaches, reported once per contiguous run. A `jump
/// variable=` could land anywhere, so a scenario with one (other than the
/// `_unexp.retaddr` return, which goes back to a step already run) is not
/// analysed at all.
fn unreachable_steps(input: &LintInput<'_>) -> Vec<Finding> {
    let steps = input.steps;
    let Some(reached) = reachable(input) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let mut i = 0;
    while i < steps.len() {
        if reached[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < steps.len() && !reached[i] {
            i += 1;
        }
        findings.push(unreachable_finding(steps, start, i - start));
    }
    findings
}

/// Which steps some path reaches, from step 0 and the `_unexp.main`
/// handler; `None` when a computed jump makes that unknowable.
fn reachable(input: &LintInput<'_>) -> Option<Vec<bool>> {
    let steps = input.steps;
    let mut reached = vec![false; steps.len()];
    let mut todo: Vec<StepIndex> = std::iter::once(0).chain(input.unexpected_jump).collect();
    while let Some(i) = todo.pop() {
        let Some(slot) = reached.get_mut(i) else {
            continue;
        };
        if *slot {
            continue;
        }
        *slot = true;
        todo.extend(successors(steps, i, input.unexp_retaddr)?);
    }
    Some(reached)
}

/// Where execution can go after step `i` — conservatively: a condition
/// (`test`, `chance`, `condexec`) keeps both ways open, and a `jump` action
/// adds where it lands without closing the fall-through. `None` for a jump
/// whose target is only known at run time.
fn successors(steps: &[Step], i: StepIndex, retaddr: Option<VarId>) -> Option<Vec<StepIndex>> {
    let Some(step) = steps.get(i) else {
        return Some(Vec::new());
    };
    if matches!(step, Step::Timewait { .. }) {
        return Some(Vec::new());
    }
    let Some(common) = step.common() else {
        return Some(vec![i + 1]); // a label
    };
    let mut out = Vec::new();
    // An optional recv is a window: a message for a later step can match
    // while the call waits here, so the next step stays reachable even when
    // this one jumps away on its own match.
    if !always_jumps(common) || is_optional_recv(step) {
        out.push(i + 1);
    }
    out.extend(common.next);
    out.extend(step.ontimeout());
    if !jump_takes_effect(step) {
        return Some(out);
    }
    for action in step_actions(step) {
        match action {
            Action::Jump {
                dest: JumpTarget::Index(dest),
            } => out.extend(jump_landing(steps, step, *dest)),
            Action::Jump {
                dest: JumpTarget::Var(var),
            } if Some(*var) != retaddr => return None,
            _ => {}
        }
    }
    Some(out)
}

/// Whether a `<jump>` among the step's actions moves the call. After a
/// recv's actions SIPp sets `msg_index = search_index` and runs `next()`,
/// which overwrites the jump — unless the recv is optional and stays where
/// the call waited, which only a `next=` beside a `test=` can make it do.
/// A recvCmd always overwrites it.
fn jump_takes_effect(step: &Step) -> bool {
    match step {
        Step::Recv(r) => r.optional && r.common.next.is_some() && r.common.test.is_some(),
        Step::RecvCmd { .. } => false,
        _ => true,
    }
}

/// Where `step`'s jump to step `dest` (message N) goes. SIPp sets
/// `msg_index = N - 1`: an optional recv that stays then waits at message
/// N-1, and any other step runs `next()` there, which takes message N-1's
/// `next=` (when its test and chance allow) before N.
fn jump_landing(steps: &[Step], step: &Step, dest: StepIndex) -> Vec<StepIndex> {
    let before = steps[..dest.min(steps.len())]
        .iter()
        .rposition(|s| !matches!(s, Step::Label { .. }));
    if matches!(step, Step::Recv(_)) {
        return vec![before.unwrap_or(0)];
    }
    let Some(common) = before.and_then(|i| steps[i].common()) else {
        return vec![dest];
    };
    let mut landing: Vec<StepIndex> = common.next.into_iter().collect();
    if common.next.is_none() || common.test.is_some() || common.chance.is_some() {
        landing.push(dest);
    }
    landing
}

/// `next` with nothing that can make the step skip it.
fn always_jumps(common: &StepCommon) -> bool {
    common.next.is_some()
        && common.test.is_none()
        && common.chance.is_none()
        && common.condexec.is_none()
}

fn unreachable_finding(steps: &[Step], start: StepIndex, len: usize) -> Finding {
    let first = &steps[start];
    let rest = match len - 1 {
        0 => String::new(),
        1 => " (nor can the step after it)".to_owned(),
        n => format!(" (nor can the {n} steps after it)"),
    };
    // The run is maximal and step 0 is always reached, so the step before
    // it is reached and does not fall through: it is a <timewait>, or it
    // always jumps away.
    let why = match start.checked_sub(1).and_then(|i| steps.get(i)) {
        Some(Step::Timewait { .. }) => {
            "the <timewait> before it ends the call, and SIPp refuses any step after a \
             <timewait>"
                .to_owned()
        }
        Some(prev) => match prev.common().and_then(|c| c.next) {
            Some(dest) => format!(
                "the {} at line {} before it always jumps to label '{}', and no next, ontimeout \
                 or jump leads here",
                describe(prev),
                line_of(prev),
                label_at(steps, dest),
            ),
            None => "no step falls through or jumps to it".to_owned(),
        },
        None => "no step falls through or jumps to it".to_owned(),
    };
    Finding {
        lint: Lint::Unreachable,
        step: start,
        line: line_of(first),
        message: format!("{} can never run{rest}: {why}", describe(first)),
    }
}

fn label_at(steps: &[Step], index: StepIndex) -> &str {
    match steps.get(index) {
        Some(Step::Label { id, .. }) => id,
        _ => "?",
    }
}

// ---- body-separator, content-length ------------------------------------

/// Stands in for a keyword when a template is examined as text: its
/// rendered value is unknown until send time.
const KEYWORD: char = '\u{1}';
/// Stands in for `[len]`.
const LEN: char = '\u{2}';

/// The header and body checks of one `<send>`. `first_line` is the source
/// line of the message's start line; header `n` sits `n` lines below it
/// (normalization drops only leading and trailing blank lines).
fn message_findings(step: StepIndex, template: &MsgTemplate, first_line: u32) -> Vec<Finding> {
    let text = shape(template);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    // Line 0 is the start line; headers follow.
    let headers: Vec<(u32, &str)> = (0u32..).zip(head.split("\r\n")).skip(1).collect();
    let mut findings = Vec::new();
    let line = |n: u32| first_line.saturating_add(n);
    if let Some(&(n, sdp)) = headers.iter().find(|(_, h)| looks_like_sdp(h)) {
        findings.push(Finding {
            lint: Lint::BodySeparator,
            step,
            line: line(n),
            message: format!(
                "'{}' looks like an SDP line but sits among the headers: the blank line \
                 that ends the headers is missing, so the body is sent as header lines \
                 (and [len] does not count it)",
                readable(sdp)
            ),
        });
    }
    if let Some((n, message)) = content_length_problem(&headers, body) {
        findings.push(Finding {
            lint: Lint::ContentLength,
            step,
            line: line(n),
            message,
        });
    }
    findings
}

/// A `Content-Length` (or compact `l:`) that is, or may be, wrong — or a
/// body with none at all. `[len]`, or any other keyword, renders at send
/// time and is left alone.
fn content_length_problem(headers: &[(u32, &str)], body: &str) -> Option<(u32, String)> {
    let header = headers.iter().find_map(|&(n, header)| {
        let (name, value) = header.split_once(':')?;
        let name = name.trim();
        (name.eq_ignore_ascii_case("Content-Length") || name.eq_ignore_ascii_case("l"))
            .then(|| (n, value.trim()))
    });
    let Some((n, value)) = header else {
        // Reported on the start line: there is no header line to point at.
        return (!body.is_empty()).then(|| {
            (
                0,
                "the message has a body but no Content-Length header: over TCP or TLS \
                 the peer cannot tell where it ends — add Content-Length: [len]"
                    .to_owned(),
            )
        });
    };
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let declared: usize = value.parse().ok()?;
    if body.contains([KEYWORD, LEN]) {
        return Some((
            n,
            format!(
                "Content-Length is fixed at {declared}, but the body holds keywords whose \
                 rendered length varies from call to call: use Content-Length: [len]"
            ),
        ));
    }
    (declared != body.len()).then(|| {
        (
            n,
            format!(
                "Content-Length says {declared}, but the body is {} bytes (lines end in \
                 CRLF on the wire): use Content-Length: [len]",
                body.len()
            ),
        )
    })
}

/// `v=0`, `o=…`, `m=audio …`: a lowercase letter then `=`. No SIP header
/// looks like that — a header needs a `:`, compact forms included.
fn looks_like_sdp(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_lowercase() && bytes[1] == b'='
}

/// The template as text, each keyword replaced by a placeholder.
fn shape(template: &MsgTemplate) -> String {
    let mut out = String::new();
    for span in &template.spans {
        match span {
            Span::Lit(text) => out.push_str(text),
            Span::Kw(Keyword::Len) => out.push(LEN),
            Span::Kw(_) => out.push(KEYWORD),
        }
    }
    out
}

/// A shape line fit for a message: placeholders back to brackets.
fn readable(line: &str) -> String {
    line.replace(KEYWORD, "[…]").replace(LEN, "[len]")
}

// ---- describing steps ---------------------------------------------------

fn step_actions(step: &Step) -> &[Action] {
    match step {
        Step::Send(s) => &s.actions,
        Step::Recv(r) => &r.actions,
        Step::Nop { actions, .. } | Step::RecvCmd { actions, .. } => actions,
        _ => &[],
    }
}

fn line_of(step: &Step) -> u32 {
    match step {
        Step::Label { line, .. } | Step::Timewait { line, .. } => *line,
        _ => step.common().map_or(0, |c| c.line),
    }
}

fn element_name(step: &Step) -> &'static str {
    match step {
        Step::Send(_) => "send",
        Step::Recv(_) => "recv",
        Step::Pause { .. } => "pause",
        Step::Nop { .. } => "nop",
        Step::SendCmd { .. } => "sendCmd",
        Step::RecvCmd { .. } => "recvCmd",
        Step::Label { .. } => "label",
        Step::Timewait { .. } => "timewait",
    }
}

/// `<recv response="180">`, `<label id="end">`, `<send>`.
fn describe(step: &Step) -> String {
    match step {
        Step::Recv(r) => match &r.expect {
            Expect::Response(code) => format!("<recv response=\"{code}\">"),
            Expect::Request(method) => format!("<recv request=\"{method}\">"),
        },
        Step::Label { id, .. } => format!("<label id=\"{id}\">"),
        other => format!("<{}>", element_name(other)),
    }
}
