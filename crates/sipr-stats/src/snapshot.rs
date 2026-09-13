//! The snapshot the TUI renders: a pure-data copy of everything the screens
//! show, published by the engine about once a second. The TUI never touches
//! live engine state (docs/ARCHITECTURE.md: "the TUI never touches the
//! engine — it reads 1-second stat snapshots").

use std::time::Duration;

/// Per-step counters for the scenario screen.
#[derive(Debug, Default, Clone)]
pub struct StepStats {
    /// Messages sent from this step (first transmissions).
    pub sent: u64,
    /// Messages matched at this step.
    pub recv: u64,
    /// Retransmissions of this step's send.
    pub retrans: u64,
    /// Recv timeouts while this step was the mandatory expectation.
    pub timeouts: u64,
    /// Unexpected messages while parked at this step.
    pub unexpected: u64,
}

/// One row of the scenario screen: a step label plus its counters.
#[derive(Debug, Clone)]
pub struct StepRow {
    /// Short human description ("send INVITE", "recv 200", "pause 3000ms").
    pub label: String,
    /// `hide="true"` on the step: skipped while [`Snapshot::hide`] holds.
    pub hidden: bool,
    /// The counters.
    pub stats: StepStats,
}

/// Summary of one RTD histogram for display.
#[derive(Debug, Clone)]
pub struct RtdRow {
    /// RTD name (`"1"`, `"2"`, ...).
    pub name: String,
    /// Samples recorded.
    pub count: u64,
    /// Mean in ms.
    pub mean_ms: f64,
    /// Standard deviation in ms.
    pub stddev_ms: f64,
    /// 99th percentile in ms.
    pub p99_ms: u64,
    /// Maximum in ms.
    pub max_ms: u64,
}

/// Which scenario the screens show (SIPp `display_scenario`, switched with
/// `set display main|ooc|rx`). Every counter in the snapshot — the main
/// screen, the statistics and repartition screens and the scenario page —
/// belongs to the displayed scenario, as SIPp's `screen.cpp` reads
/// `display_scenario->stats` throughout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Display {
    /// The main scenario.
    #[default]
    Main,
    /// The out-of-call scenario (`-oocsf`/`-oocsn`), by name.
    OutOfCall(String),
    /// The mixed-mode receive scenario (`-rxsf`/`-rxsn`), by name.
    Receive(String),
}

impl Display {
    /// SIPp's `set display` word for this choice: `main`, `ooc` or `rx`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::OutOfCall(_) => "ooc",
            Self::Receive(_) => "rx",
        }
    }

    /// The displayed secondary scenario's name, `None` for the main one.
    #[must_use]
    pub fn secondary_name(&self) -> Option<&str> {
        match self {
            Self::Main => None,
            Self::OutOfCall(name) | Self::Receive(name) => Some(name),
        }
    }
}

/// Everything a redraw needs.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Name of the displayed scenario (see [`Display`]).
    pub scenario: String,
    /// True when the displayed scenario answers calls (UAS).
    pub uas: bool,
    /// Mixed mode (`-rxsf`/`-rxsn`): a receive scenario is loaded next to
    /// the main one (SIPp's "Sipp Mixed Mode" header).
    pub mixed: bool,
    /// Wall-clock elapsed.
    pub elapsed: Duration,
    /// Live calls right now.
    pub live: usize,
    /// Target rate (calls per period) as currently set.
    pub rate_target: f64,
    /// Achieved rate over the last snapshot period (cps).
    pub rate_period: f64,
    /// Achieved rate over the whole run (cps).
    pub rate_cumulative: f64,
    /// Traffic paused via 'p'.
    pub paused: bool,
    /// Total calls created.
    pub created: u64,
    /// Calls completed successfully.
    pub successful: u64,
    /// Calls failed (all causes).
    pub failed: u64,
    /// Failure breakdown: unexpected message.
    pub failed_unexpected: u64,
    /// Failure breakdown: recv timeout.
    pub failed_timeout: u64,
    /// Failure breakdown: retransmissions exhausted.
    pub failed_retrans: u64,
    /// Failure breakdown: everything else.
    pub failed_other: u64,
    /// First transmissions sent.
    pub messages_sent: u64,
    /// Matched inbound messages.
    pub messages_matched: u64,
    /// Retransmissions sent.
    pub retrans_sent: u64,
    /// Inbound retransmissions absorbed.
    pub retrans_recv: u64,
    /// `-aa` auto-answers sent.
    pub auto_answered: u64,
    /// Unexpected messages.
    pub unexpected: u64,
    /// Non-SIP datagrams.
    pub garbage: u64,
    /// pcap replays started.
    pub rtp_streams_started: u64,
    /// RTP datagrams sent by media replays.
    pub rtp_packets_sent: u64,
    /// Payload bytes sent by media replays.
    pub rtp_bytes_sent: u64,
    /// Bytes received on generated RTP streams' sockets.
    pub rtp_bytes_received: u64,
    /// `-rtp_echo` datagrams echoed, audio socket.
    pub rtp_echo_packets: u64,
    /// `-rtp_echo` datagrams echoed, video socket.
    pub rtp_echo2_packets: u64,
    /// RTP checks passed.
    pub rtp_check_ok: u64,
    /// RTP checks failed.
    pub rtp_check_failed: u64,
    /// RTD summaries, sorted by name.
    pub rtds: Vec<RtdRow>,
    /// Call-length summary (count, mean ms, max ms).
    pub call_length: (u64, f64, u64),
    /// ResponseTimeRepartition rows (label, count).
    pub response_rows: Vec<(String, u64)>,
    /// CallLengthRepartition rows (label, count).
    pub call_length_rows: Vec<(String, u64)>,
    /// Per-step rows for the scenario screen.
    pub steps: Vec<StepRow>,
    /// Which scenario every counter and row above belongs to.
    pub display: Display,
    /// `set hide true|false` (SIPp `do_hide`, default true): whether
    /// hidden steps stay off the scenario screen.
    pub hide: bool,
    /// A screen requested through the control socket's digit keys
    /// (`1` scenario, `2` statistics, `3` repartition), with a sequence
    /// number so the TUI applies each request once.
    pub screen_request: Option<(u64, u8)>,
}

impl crate::StatSet {
    /// Fill the stats-owned part of a snapshot. The engine adds scenario
    /// name, role, rates, pause state, and step labels.
    pub fn fill_snapshot(&self, snap: &mut Snapshot, live: usize) {
        snap.elapsed = self.started.elapsed();
        snap.live = live;
        snap.created = self.created();
        snap.successful = self.successful;
        snap.failed = self.failed();
        snap.failed_unexpected = self.failed_unexpected;
        snap.failed_timeout = self.failed_timeout;
        snap.failed_retrans = self.failed_retrans;
        snap.failed_other = self.failed_other;
        snap.messages_sent = self.messages_sent;
        snap.messages_matched = self.messages_matched;
        snap.retrans_sent = self.retrans_sent;
        snap.retrans_recv = self.retrans_recv;
        snap.auto_answered = self.auto_answered;
        snap.unexpected = self.unexpected;
        snap.garbage = self.garbage;
        snap.rtp_streams_started = self.rtp_streams_started;
        snap.rtp_packets_sent = self.rtp_packets_sent;
        snap.rtp_bytes_sent = self.rtp_bytes_sent;
        snap.rtp_bytes_received = self.rtp_bytes_received;
        snap.rtp_echo_packets = self.rtp_echo_packets;
        snap.rtp_echo2_packets = self.rtp_echo2_packets;
        snap.rtp_check_ok = self.rtp_check_ok;
        snap.rtp_check_failed = self.rtp_check_failed;
        #[allow(clippy::cast_precision_loss)]
        {
            snap.rate_cumulative = self.created() as f64 / snap.elapsed.as_secs_f64().max(1e-9);
        }
        snap.rtds = {
            let mut rows: Vec<RtdRow> = self
                .rtd
                .iter()
                .map(|(name, h)| RtdRow {
                    name: name.clone(),
                    count: h.count(),
                    mean_ms: h.mean_ms(),
                    stddev_ms: h.stddev_ms(),
                    p99_ms: h.percentile_ms(99.0),
                    max_ms: h.max_ms(),
                })
                .collect();
            rows.sort_by(|a, b| a.name.cmp(&b.name));
            rows
        };
        snap.call_length = (
            self.call_length.count(),
            self.call_length.mean_ms(),
            self.call_length.max_ms(),
        );
        snap.response_rows = self.response_repartition.rows();
        snap.call_length_rows = self.call_length_repartition.rows();
        snap.steps = self.step_rows();
    }

    /// The per-step rows of the scenario screen.
    #[must_use]
    pub fn step_rows(&self) -> Vec<StepRow> {
        self.steps
            .iter()
            .enumerate()
            .map(|(i, s)| StepRow {
                label: self
                    .step_labels
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| format!("step {i}")),
                hidden: self.step_hidden.get(i).copied().unwrap_or(false),
                stats: s.clone(),
            })
            .collect()
    }
}
