//! `sipr-stats`: counters, response-time histograms, repartitions, the
//! statistics CSV, and message/error trace files (milestone M4).
//!
//! The engine's event loop owns a [`StatSet`] and feeds it directly — no
//! locks, per docs/ARCHITECTURE.md ("stats are read from snapshots"). File
//! writers are plain buffered writers owned by the same thread; a load run
//! with `-trace_msg` enabled is expected to pay for its I/O (same as SIPp).
//!
//! CSV format: SIPp's `-trace_stat` columns in SIPp's order, with its
//! `(P)`/`(C)` periodic/cumulative naming (M40; SIPP_COMPAT §6).

pub mod clock;
mod histogram;
mod snapshot;

pub use histogram::{Histogram, Repartition};
pub use snapshot::{CounterRow, Display, RtdRow, Snapshot, StepRow, StepStats};

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Everything counted during a run. The engine's `RunReport` is a summary
/// distilled from this at the end.
#[derive(Debug)]
pub struct StatSet {
    /// Run start.
    pub started: Instant,
    /// Calls created by the pacer (UAC side).
    pub outgoing_created: u64,
    /// Calls created from inbound initial requests (UAS side).
    pub incoming_created: u64,
    /// Calls that completed their scenario.
    pub successful: u64,
    /// Failed: unexpected message.
    pub failed_unexpected: u64,
    /// Failed: recv timeout with no ontimeout.
    pub failed_timeout: u64,
    /// Failed: retransmissions exhausted.
    pub failed_retrans: u64,
    /// Failed: everything else (render errors, aborts, global timeout).
    pub failed_other: u64,
    /// Failed: a TCP/TLS connection could not be (re)established
    /// (SIPp `E_FAILED_TCP_CONNECT`).
    pub failed_tcp_connect: u64,
    /// Failed: the TCP/TLS connection closed under the call
    /// (SIPp `E_FAILED_TCP_CLOSED`, `-reconnect_close`).
    pub failed_tcp_closed: u64,
    /// Failed: a message could not be sent — the call that finds the
    /// connection dead (SIPp `E_FAILED_CANNOT_SEND_MSG`).
    pub failed_cannot_send: u64,
    /// First transmissions sent.
    pub messages_sent: u64,
    /// Messages received and matched to a step.
    pub messages_matched: u64,
    /// Retransmissions sent (timer-driven).
    pub retrans_sent: u64,
    /// Inbound retransmissions detected (answered from last response).
    pub retrans_recv: u64,
    /// In-dialog requests answered automatically (`-aa`).
    pub auto_answered: u64,
    /// Inbound that matched no live call / no step.
    pub unexpected: u64,
    /// Datagrams that were not SIP.
    pub garbage: u64,
    /// pcap replays started (`exec play_pcap_*`).
    pub rtp_streams_started: u64,
    /// RTP/UDP datagrams sent by media replays (sampled from the media thread).
    pub rtp_packets_sent: u64,
    /// Payload bytes sent by media replays.
    pub rtp_bytes_sent: u64,
    /// Bytes received on generated RTP streams' sockets (echoes).
    pub rtp_bytes_received: u64,
    /// `-rtp_echo`: datagrams echoed on the audio socket (SIPp "1st stream").
    pub rtp_echo_packets: u64,
    /// `-rtp_echo`: datagrams echoed on the video socket ("2nd stream").
    pub rtp_echo2_packets: u64,
    /// RTP checks that passed (streams judged against a tolerance).
    pub rtp_check_ok: u64,
    /// RTP checks that failed (SIPp: exit code -3).
    pub rtp_check_failed: u64,
    /// Response-time stopwatches by RTD name (`"1"`, `"2"`, ...).
    pub rtd: HashMap<String, Histogram>,
    /// Call duration histogram (created → ended).
    pub call_length: Histogram,
    /// `ResponseTimeRepartition` (fed by RTD "1").
    pub response_repartition: Repartition,
    /// `CallLengthRepartition`.
    pub call_length_repartition: Repartition,
    /// A response-time repartition per RTD name (SIPp keeps one table per
    /// RTD; `response_repartition` above is RTD `1`'s, for the screen).
    pub rtd_repartitions: HashMap<String, Repartition>,
    /// RTD names in scenario order (SIPp numbers them by first appearance).
    pub rtd_names: Vec<String>,
    /// Messages for no live call (SIPp `OutOfCallMsgs`).
    pub out_of_call_msgs: u64,
    /// Messages absorbed by a call in timewait (SIPp `DeadCallMsgs`).
    pub dead_call_msgs: u64,
    /// Response codes of unexpected messages since the last dump
    /// (`-trace_error_codes`).
    pub error_codes: Vec<u16>,
    /// Per-step counters (scenario screen).
    pub steps: Vec<StepStats>,
    /// Short per-step labels, set once by the engine.
    pub step_labels: Vec<String>,
    /// Per-step `hide` flags, parallel to `step_labels`.
    pub step_hidden: Vec<bool>,
    /// What each step is, for the `-trace_counts` columns.
    pub step_kinds: Vec<StepKind>,
    /// Delimiter, timestamp form and periodic-repartition switch of the
    /// statistics files.
    pub dump: DumpOptions,
    /// When the run started, wall clock (`StartTime`).
    start_time: SystemTime,
    /// When the current period started (`LastResetTime`).
    period_start_time: SystemTime,
    period_start: Instant,
    /// Cumulative counters at the last dump: the `(P)` columns are the
    /// difference (SIPp resets its PL counters at every dump).
    last_dump: Counters,
    /// This period's response-time and call-length samples.
    rtd_period: HashMap<String, Histogram>,
    call_length_period: Histogram,
    /// Buffered `-trace_rtt` rows: (seconds since start, rtt in seconds,
    /// rtd name).
    rtt_rows: Vec<(f64, f64, String)>,
    /// The scenario's generic counters (`counter=`), in the order the
    /// scenario first names them.
    counters: Vec<GenericCounter>,
    /// Each step's counter, as an index into `counters`, so a tick on the
    /// per-message path is an index and not a name lookup.
    step_counters: Vec<Option<usize>>,
}

/// One generic counter (SIPp `E_ADD_GENERIC_COUNTER`): a scenario-wide
/// tally that every step naming it adds one to, whichever call runs it.
#[derive(Debug, Clone)]
struct GenericCounter {
    /// The name as the scenario writes it.
    name: String,
    /// Ticks since the start of the run (SIPp `GENERIC_C`).
    total: u64,
    /// `total` at the last `-fd` dump: the `(P)` column is the difference
    /// (SIPp resets its `GENERIC_PL` value after each dump).
    at_dump: u64,
    /// `total` at the last screen refresh: the screen's periodic value is
    /// the difference (SIPp resets `GENERIC_PD` at each refresh).
    at_display: u64,
}

impl GenericCounter {
    fn new(name: String) -> Self {
        Self {
            name,
            total: 0,
            at_dump: 0,
            at_display: 0,
        }
    }
}

/// What a scenario step is, for the `-trace_counts` columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepKind {
    /// A send: the method, or the status code of a response; `retrans` is
    /// whether the step carries `retrans=` (SIPp adds a `Timeout` column).
    Send {
        /// Method or status code.
        name: String,
        /// `retrans=` set.
        retrans: bool,
    },
    /// A recv: the method or status code expected.
    Recv {
        /// Method or status code.
        name: String,
    },
    /// Any other message — a pause, a timewait, a nop, a `sendCmd` or a
    /// `recvCmd`: `Pause_Sessions` and `Pause_Unexp`. SIPp's
    /// `print_count_file` tests `pause_distribution || pause_variable`
    /// next, and `pause_variable` defaults to -1, so its nop, `SendCmd`
    /// and `RecvCmd` arms never run.
    Pause,
    /// A label: no columns, and not a SIPp message, so it takes no index —
    /// the columns after it keep SIPp's message numbering.
    Label,
}

/// How the statistics files are written.
#[derive(Debug, Clone)]
pub struct DumpOptions {
    /// `-stat_delimiter` (SIPp's default `;`).
    pub delimiter: String,
    /// `-rfc3339`: the time columns' form.
    pub rfc3339: bool,
    /// `-periodic_rtd`: zero the repartition tables at every dump.
    pub periodic_rtd: bool,
    /// `-rtt_freq`: buffered `-trace_rtt` rows before a flush.
    pub rtt_freq: usize,
    /// `-trace_rtt` is on: keep the per-response rows.
    pub trace_rtt: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            delimiter: ";".to_owned(),
            rfc3339: false,
            periodic_rtd: false,
            rtt_freq: 200,
            trace_rtt: false,
        }
    }
}

/// The cumulative counters a dump reads, snapshotted per period.
#[derive(Debug, Default, Clone, Copy)]
struct Counters {
    incoming: u64,
    outgoing: u64,
    successful: u64,
    failed: u64,
    cannot_send: u64,
    max_retrans: u64,
    tcp_connect: u64,
    tcp_closed: u64,
    unexpected_msg: u64,
    timeout: u64,
    out_of_call: u64,
    dead_call: u64,
    retrans: u64,
    auto_answered: u64,
}

impl StatSet {
    /// New stat set with the scenario's repartition bounds.
    #[must_use]
    pub fn new(response_bounds: &[u64], call_length_bounds: &[u64]) -> Self {
        Self {
            started: Instant::now(),
            outgoing_created: 0,
            incoming_created: 0,
            successful: 0,
            failed_unexpected: 0,
            failed_timeout: 0,
            failed_retrans: 0,
            failed_other: 0,
            failed_tcp_connect: 0,
            failed_tcp_closed: 0,
            failed_cannot_send: 0,
            messages_sent: 0,
            messages_matched: 0,
            retrans_sent: 0,
            retrans_recv: 0,
            auto_answered: 0,
            unexpected: 0,
            garbage: 0,
            rtp_streams_started: 0,
            rtp_packets_sent: 0,
            rtp_bytes_sent: 0,
            rtp_bytes_received: 0,
            rtp_echo_packets: 0,
            rtp_echo2_packets: 0,
            rtp_check_ok: 0,
            rtp_check_failed: 0,
            rtd: HashMap::new(),
            call_length: Histogram::new(),
            response_repartition: Repartition::new(response_bounds),
            call_length_repartition: Repartition::new(call_length_bounds),
            steps: Vec::new(),
            step_labels: Vec::new(),
            step_hidden: Vec::new(),
            rtd_repartitions: HashMap::new(),
            rtd_names: Vec::new(),
            out_of_call_msgs: 0,
            dead_call_msgs: 0,
            error_codes: Vec::new(),
            step_kinds: Vec::new(),
            dump: DumpOptions::default(),
            start_time: SystemTime::now(),
            period_start_time: SystemTime::now(),
            period_start: Instant::now(),
            last_dump: Counters::default(),
            rtd_period: HashMap::new(),
            call_length_period: Histogram::new(),
            rtt_rows: Vec::new(),
            counters: Vec::new(),
            step_counters: Vec::new(),
        }
    }

    /// Zero every counter (SIPp's `set reset`), keeping the scenario-shaped
    /// data: step labels, kinds and hide flags, RTD and counter names, dump
    /// options.
    pub fn reset(&mut self) {
        let labels = std::mem::take(&mut self.step_labels);
        let hidden = std::mem::take(&mut self.step_hidden);
        let kinds = std::mem::take(&mut self.step_kinds);
        let rtd_names = std::mem::take(&mut self.rtd_names);
        let counters = std::mem::take(&mut self.counters);
        let step_counters = std::mem::take(&mut self.step_counters);
        let dump = self.dump.clone();
        let response_bounds = self.response_repartition.bounds();
        let call_length_bounds = self.call_length_repartition.bounds();
        *self = Self::new(&response_bounds, &call_length_bounds);
        self.init_steps(labels);
        self.step_hidden = hidden;
        self.step_kinds = kinds;
        self.rtd_names = rtd_names;
        self.counters = counters
            .into_iter()
            .map(|c| GenericCounter::new(c.name))
            .collect();
        self.step_counters = step_counters;
        self.dump = dump;
    }

    /// Size the per-step table and install display labels (engine, once).
    pub fn init_steps(&mut self, labels: Vec<String>) {
        self.steps = vec![StepStats::default(); labels.len()];
        self.step_hidden = vec![false; labels.len()];
        self.step_labels = labels;
    }

    /// Install per-step `hide` flags (parallel to the labels).
    pub fn set_step_hidden(&mut self, hidden: Vec<bool>) {
        self.step_hidden = hidden;
    }

    /// Per-step counter access; out-of-range indices are ignored safely.
    pub fn step_mut(&mut self, index: usize) -> Option<&mut StepStats> {
        self.steps.get_mut(index)
    }

    /// Total calls created.
    #[must_use]
    pub fn created(&self) -> u64 {
        self.outgoing_created + self.incoming_created
    }

    /// Total failed calls.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed_unexpected
            + self.failed_timeout
            + self.failed_retrans
            + self.failed_other
            + self.failed_tcp_connect
            + self.failed_tcp_closed
            + self.failed_cannot_send
    }

    /// A response time for RTD `name` (`rtd=` closed a `start_rtd=`).
    pub fn record_rtd(&mut self, name: &str, d: Duration) {
        self.rtd.entry(name.to_owned()).or_default().record(d);
        self.rtd_period
            .entry(name.to_owned())
            .or_default()
            .record(d);
        if name == "1" {
            self.response_repartition.record(d);
        }
        let bounds = self.response_repartition.bounds();
        self.rtd_repartitions
            .entry(name.to_owned())
            .or_insert_with(|| Repartition::new(&bounds))
            .record(d);
        if !self.rtd_names.iter().any(|n| n == name) {
            self.rtd_names.push(name.to_owned());
        }
        if self.dump.trace_rtt {
            // SIPp `computeRtt`: the stop time and the rtt, both in seconds
            // (its columns say ms; the values are divided by 1000).
            self.rtt_rows.push((
                self.started.elapsed().as_secs_f64(),
                d.as_secs_f64(),
                name.to_owned(),
            ));
        }
    }

    /// A finished call's duration.
    pub fn record_call_length(&mut self, d: Duration) {
        self.call_length.record(d);
        self.call_length_period.record(d);
        self.call_length_repartition.record(d);
    }

    /// An unexpected response's status code, for `-trace_error_codes`.
    pub fn record_error_code(&mut self, code: u16) {
        self.error_codes.push(code);
    }

    /// Name the RTDs in scenario order before any is recorded, so the CSV
    /// columns follow SIPp's numbering (first appearance).
    pub fn set_rtd_names(&mut self, names: Vec<String>) {
        self.rtd_names = names;
    }

    /// What each step is, in step order (`-trace_counts` columns).
    pub fn set_step_kinds(&mut self, kinds: Vec<StepKind>) {
        self.step_kinds = kinds;
    }

    /// Each step's `counter=` name, in step order. Registers the counters
    /// in the order the scenario first names them, which is the order of
    /// their screen rows and CSV columns (SIPp `findCounter`, called as the
    /// scenario loads), and maps each step to its counter.
    pub fn set_step_counters(&mut self, per_step: Vec<Option<String>>) {
        self.counters.clear();
        self.step_counters = per_step
            .into_iter()
            .map(|name| {
                let name = name?;
                let id = match self.counters.iter().position(|c| c.name == name) {
                    Some(id) => id,
                    None => {
                        self.counters.push(GenericCounter::new(name));
                        self.counters.len() - 1
                    }
                };
                Some(id)
            })
            .collect();
    }

    /// Step `step` ran: add one to its counter, if it names one (SIPp
    /// `do_bookkeeping`). Out-of-range steps are ignored.
    pub fn tick_counter(&mut self, step: usize) {
        if let Some(Some(id)) = self.step_counters.get(step)
            && let Some(counter) = self.counters.get_mut(*id)
        {
            counter.total += 1;
        }
    }

    /// Counter `name`'s value since the start of the run; `None` when the
    /// scenario names no such counter.
    #[must_use]
    pub fn counter(&self, name: &str) -> Option<u64> {
        self.counters
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.total)
    }

    /// Start a new screen period (SIPp `E_RESET_PD_COUNTERS`, run at every
    /// screen refresh): the counters' periodic values restart from zero.
    pub fn end_display_period(&mut self) {
        for c in &mut self.counters {
            c.at_display = c.total;
        }
    }

    fn counters(&self) -> Counters {
        Counters {
            incoming: self.incoming_created,
            outgoing: self.outgoing_created,
            successful: self.successful,
            failed: self.failed(),
            cannot_send: self.failed_cannot_send,
            max_retrans: self.failed_retrans,
            tcp_connect: self.failed_tcp_connect,
            tcp_closed: self.failed_tcp_closed,
            unexpected_msg: self.failed_unexpected,
            timeout: self.failed_timeout,
            out_of_call: self.out_of_call_msgs,
            dead_call: self.dead_call_msgs,
            retrans: self.retrans_sent,
            auto_answered: self.auto_answered,
        }
    }

    /// Close the statistics period after a dump (SIPp `E_RESET_PL_COUNTERS`):
    /// the `(P)` baselines move, the period histograms empty, and with
    /// `-periodic_rtd` the repartition tables zero.
    pub fn end_period(&mut self) {
        self.last_dump = self.counters();
        self.period_start_time = SystemTime::now();
        self.period_start = Instant::now();
        self.rtd_period.clear();
        self.call_length_period = Histogram::new();
        for c in &mut self.counters {
            c.at_dump = c.total;
        }
        if self.dump.periodic_rtd {
            self.response_repartition.reset();
            self.call_length_repartition.reset();
            for r in self.rtd_repartitions.values_mut() {
                r.reset();
            }
        }
    }

    /// One-line human summary (used by `-bg` and the final report).
    #[must_use]
    pub fn line(&self, live: usize) -> String {
        let rtd1 = self.rtd.get("1");
        let rtd_part = rtd1.map_or_else(String::new, |h| {
            format!(
                " | rtd1 avg {:.1}ms p99 {}ms",
                h.mean_ms(),
                h.percentile_ms(99.0)
            )
        });
        let mut rtp_part = if self.rtp_streams_started > 0 {
            format!(
                " | rtp {} streams {} pkts",
                self.rtp_streams_started, self.rtp_packets_sent
            )
        } else {
            String::new()
        };
        if self.rtp_check_ok + self.rtp_check_failed > 0 {
            rtp_part.push_str(&format!(
                " rtpcheck {}/{} failed",
                self.rtp_check_failed,
                self.rtp_check_ok + self.rtp_check_failed
            ));
        }
        if self.rtp_echo_packets + self.rtp_echo2_packets > 0 {
            rtp_part.push_str(&format!(
                " echo {}/{} pkts",
                self.rtp_echo_packets, self.rtp_echo2_packets
            ));
        }
        format!(
            "live {live} created {} ok {} failed {} | sent {} matched {} \
             retrans {}/{} unexpected {} garbage {}{rtd_part}{rtp_part}",
            self.created(),
            self.successful,
            self.failed(),
            self.messages_sent,
            self.messages_matched,
            self.retrans_sent,
            self.retrans_recv,
            self.unexpected,
            self.garbage,
        )
    }

    /// The `-trace_stat` header: SIPp's `CStat::dumpData` columns in its
    /// order — the fixed counter set, `ResponseTime<rtd>` mean and standard
    /// deviation per RTD, `CallLength`, a `(P)`/`(C)` pair per generic
    /// counter, then a repartition block per RTD and for the call length
    /// (each a name column plus `_<b` … `_>=last`).
    #[must_use]
    pub fn csv_header(&self) -> String {
        let d = self.dump.delimiter.as_str();
        let mut out = String::new();
        for name in CSV_FIXED_COLUMNS {
            out.push_str(name);
            out.push_str(d);
        }
        for rtd in &self.rtd_names {
            for col in [
                format!("ResponseTime{rtd}(P)"),
                format!("ResponseTime{rtd}(C)"),
                format!("ResponseTime{rtd}StDev(P)"),
                format!("ResponseTime{rtd}StDev(C)"),
            ] {
                out.push_str(&col);
                out.push_str(d);
            }
        }
        for col in [
            "CallLength(P)",
            "CallLength(C)",
            "CallLengthStDev(P)",
            "CallLengthStDev(C)",
        ] {
            out.push_str(col);
            out.push_str(d);
        }
        for c in &self.counters {
            let name = csv_counter_name(&c.name);
            let _ = write!(out, "{name}(P){d}{name}(C){d}");
        }
        let response_bounds = self.response_repartition.bounds();
        for rtd in &self.rtd_names {
            out.push_str(&repartition_header(
                &format!("ResponseTimeRepartition{rtd}"),
                &response_bounds,
                d,
            ));
        }
        out.push_str(&repartition_header(
            "CallLengthRepartition",
            &self.call_length_repartition.bounds(),
            d,
        ));
        out.push('\n');
        out
    }

    /// One `-trace_stat` row. `target` is the `-r` rate (or the `-users`
    /// count, which SIPp prints instead when in users mode), `live` the
    /// current calls. The caller ends the period afterwards.
    #[must_use]
    pub fn csv_row(&self, live: usize, target: f64, users: Option<usize>) -> String {
        let d = self.dump.delimiter.as_str();
        let now = SystemTime::now();
        let elapsed = self.started.elapsed();
        let period = self.period_start.elapsed();
        let cur = self.counters();
        let last = self.last_dump;
        let p = |now: u64, then: u64| now.saturating_sub(then);
        #[allow(clippy::cast_precision_loss)]
        let rate_p = p(cur.incoming + cur.outgoing, last.incoming + last.outgoing) as f64
            / period.as_secs_f64().max(1e-9);
        #[allow(clippy::cast_precision_loss)]
        let rate_c = (cur.incoming + cur.outgoing) as f64 / elapsed.as_secs_f64().max(1e-9);
        let mut cols: Vec<String> = vec![
            clock::sipp_timestamp(self.start_time, self.dump.rfc3339),
            clock::sipp_timestamp(self.period_start_time, self.dump.rfc3339),
            clock::sipp_timestamp(now, self.dump.rfc3339),
            hhmmss(period),
            hhmmss(elapsed),
            match users {
                Some(u) => u.to_string(),
                None => format!("{target:.3}"),
            },
            format!("{rate_p:.3}"),
            format!("{rate_c:.3}"),
        ];
        // A `(P)`/`(C)` pair: the period delta, then the cumulative value.
        fn pc(cols: &mut Vec<String>, now: u64, then: u64) {
            cols.push(now.saturating_sub(then).to_string());
            cols.push(now.to_string());
        }
        pc(&mut cols, cur.incoming, last.incoming);
        pc(&mut cols, cur.outgoing, last.outgoing);
        cols.push((cur.incoming + cur.outgoing).to_string());
        cols.push(live.to_string());
        pc(&mut cols, cur.successful, last.successful);
        pc(&mut cols, cur.failed, last.failed);
        pc(&mut cols, cur.cannot_send, last.cannot_send);
        pc(&mut cols, cur.max_retrans, last.max_retrans);
        pc(&mut cols, cur.tcp_connect, last.tcp_connect);
        pc(&mut cols, cur.tcp_closed, last.tcp_closed);
        pc(&mut cols, cur.unexpected_msg, last.unexpected_msg);
        // FailedCallRejected, FailedCmdNotSent, FailedRegexp{DoesntMatch,
        // ShouldntMatch,HdrNotFound}, FailedOutboundCongestion: no sipr
        // counter, always 0 (SIPP_COMPAT §6).
        for _ in 0..6 {
            pc(&mut cols, 0, 0);
        }
        pc(&mut cols, cur.timeout, last.timeout);
        // FailedTimeoutOnSend, FailedTest*, FailedStrcmp*: 0.
        for _ in 0..5 {
            pc(&mut cols, 0, 0);
        }
        pc(&mut cols, cur.out_of_call, last.out_of_call);
        pc(&mut cols, cur.dead_call, last.dead_call);
        pc(&mut cols, cur.retrans, last.retrans);
        pc(&mut cols, cur.auto_answered, last.auto_answered);
        // Warnings, FatalErrors, WatchdogMajor, WatchdogMinor: 0.
        for _ in 0..4 {
            pc(&mut cols, 0, 0);
        }
        for rtd in &self.rtd_names {
            let period = self.rtd_period.get(rtd);
            let total = self.rtd.get(rtd);
            cols.push(hhmmss_us(period.map_or(0.0, Histogram::mean_ms)));
            cols.push(hhmmss_us(total.map_or(0.0, Histogram::mean_ms)));
            cols.push(hhmmss_us(period.map_or(0.0, Histogram::stddev_ms)));
            cols.push(hhmmss_us(total.map_or(0.0, Histogram::stddev_ms)));
        }
        cols.push(hhmmss_us(self.call_length_period.mean_ms()));
        cols.push(hhmmss_us(self.call_length.mean_ms()));
        cols.push(hhmmss_us(self.call_length_period.stddev_ms()));
        cols.push(hhmmss_us(self.call_length.stddev_ms()));
        for c in &self.counters {
            pc(&mut cols, c.total, c.at_dump);
        }
        let mut out = cols.join(d);
        out.push_str(d);
        let response_bounds = self.response_repartition.bounds();
        for rtd in &self.rtd_names {
            let rows = self.rtd_repartitions.get(rtd).map_or_else(
                || Repartition::new(&response_bounds).rows(),
                Repartition::rows,
            );
            out.push_str(&repartition_values(&rows, d));
        }
        out.push_str(&repartition_values(&self.call_length_repartition.rows(), d));
        out.push('\n');
        out
    }

    /// SIPp's message index of each step, by step: SIPp numbers messages,
    /// and a label is not one (`None`).
    pub(crate) fn message_indices(&self) -> impl Iterator<Item = Option<usize>> + '_ {
        let mut next = 0;
        self.step_kinds.iter().map(move |kind| {
            if matches!(kind, StepKind::Label) {
                return None;
            }
            let index = next;
            next += 1;
            Some(index)
        })
    }

    /// The steps `-trace_counts` has columns for, as `(step, message
    /// index, kind)`: labels have none, and a hidden step keeps its message
    /// index but has no columns.
    fn counted_steps(&self) -> impl Iterator<Item = (usize, usize, &StepKind)> {
        self.step_kinds
            .iter()
            .zip(self.message_indices())
            .enumerate()
            .filter_map(|(step, (kind, index))| Some((step, index?, kind)))
            .filter(|(step, _, _)| !self.step_hidden.get(*step).copied().unwrap_or(false))
    }

    /// The `-trace_counts` header (SIPp `print_count_file(header)`): time,
    /// elapsed, then per visible message `<index>_<name>_Sent`/`_Retrans`
    /// (+ `_Timeout` when the send has `retrans=`) for sends,
    /// `_Recv`/`_Retrans`/`_Timeout`/`_Unexp` for recvs and
    /// `<index>_Pause_Sessions`/`_Unexp` for everything else.
    #[must_use]
    pub fn counts_header(&self) -> String {
        let d = self.dump.delimiter.as_str();
        let mut out = format!("CurrentTime{d}ElapsedTime{d}");
        for (_, i, kind) in self.counted_steps() {
            match kind {
                StepKind::Send { name, retrans } => {
                    let _ = write!(out, "{i}_{name}_Sent{d}{i}_{name}_Retrans{d}");
                    if *retrans {
                        let _ = write!(out, "{i}_{name}_Timeout{d}");
                    }
                }
                StepKind::Recv { name } => {
                    let _ = write!(
                        out,
                        "{i}_{name}_Recv{d}{i}_{name}_Retrans{d}{i}_{name}_Timeout{d}{i}_{name}_Unexp{d}"
                    );
                }
                StepKind::Pause => {
                    let _ = write!(out, "{i}_Pause_Sessions{d}{i}_Pause_Unexp{d}");
                }
                StepKind::Label => {}
            }
        }
        out.push('\n');
        out
    }

    /// One `-trace_counts` row: the per-step counters, cumulative.
    #[must_use]
    pub fn counts_row(&self) -> String {
        let d = self.dump.delimiter.as_str();
        let mut out = format!(
            "{}{d}{}{d}",
            clock::sipp_timestamp(SystemTime::now(), self.dump.rfc3339),
            hhmmss_us(self.started.elapsed().as_secs_f64() * 1000.0)
        );
        for (step, _, kind) in self.counted_steps() {
            let st = self.steps.get(step).cloned().unwrap_or_default();
            match kind {
                StepKind::Send { retrans, .. } => {
                    let _ = write!(out, "{}{d}{}{d}", st.sent, st.retrans);
                    if *retrans {
                        let _ = write!(out, "{}{d}", st.timeouts);
                    }
                }
                StepKind::Recv { .. } => {
                    let _ = write!(
                        out,
                        "{}{d}{}{d}{}{d}{}{d}",
                        st.recv, st.retrans, st.timeouts, st.unexpected
                    );
                }
                StepKind::Pause => {
                    let _ = write!(out, "{}{d}{}{d}", st.sessions, st.unexpected);
                }
                StepKind::Label => {}
            }
        }
        out.push('\n');
        out
    }

    /// One `-trace_error_codes` row (SIPp `print_error_codes_file`): time,
    /// elapsed, then the unexpected response codes since the last row,
    /// comma-terminated, newest first as SIPp pops them. Takes the codes.
    pub fn error_codes_row(&mut self) -> String {
        let d = self.dump.delimiter.as_str();
        let mut out = format!(
            "{}{d}{}{d}",
            clock::sipp_timestamp(SystemTime::now(), self.dump.rfc3339),
            hhmmss_us(self.started.elapsed().as_secs_f64() * 1000.0)
        );
        for code in self.error_codes.drain(..).rev() {
            let _ = write!(out, "{code},");
        }
        out.push('\n');
        out
    }

    /// The `-trace_rtt` header (`CStat::dumpDataRtt`).
    #[must_use]
    pub fn rtt_header(&self) -> String {
        let d = self.dump.delimiter.as_str();
        format!("Date_ms{d}response_time_ms{d}rtd_no\n")
    }

    /// Whether enough `-trace_rtt` rows are buffered for a flush
    /// (`-rtt_freq`).
    #[must_use]
    pub fn rtt_due(&self) -> bool {
        self.rtt_rows.len() >= self.dump.rtt_freq.max(1)
    }

    /// The buffered `-trace_rtt` rows, taken; empty when there are none.
    pub fn take_rtt_rows(&mut self) -> String {
        let d = self.dump.delimiter.as_str();
        let mut out = String::new();
        for (date, rtt, rtd) in self.rtt_rows.drain(..) {
            let _ = writeln!(out, "{}{d}{}{d}{rtd}", g6(date), g6(rtt));
        }
        out
    }
}

/// Buffered line writer for trace files; write failures degrade to a
/// one-time warning rather than killing the run.
/// SIPp's fixed `-trace_stat` columns, before the per-RTD ones.
const CSV_FIXED_COLUMNS: &[&str] = &[
    "StartTime",
    "LastResetTime",
    "CurrentTime",
    "ElapsedTime(P)",
    "ElapsedTime(C)",
    "TargetRate",
    "CallRate(P)",
    "CallRate(C)",
    "IncomingCall(P)",
    "IncomingCall(C)",
    "OutgoingCall(P)",
    "OutgoingCall(C)",
    "TotalCallCreated",
    "CurrentCall",
    "SuccessfulCall(P)",
    "SuccessfulCall(C)",
    "FailedCall(P)",
    "FailedCall(C)",
    "FailedCannotSendMessage(P)",
    "FailedCannotSendMessage(C)",
    "FailedMaxUDPRetrans(P)",
    "FailedMaxUDPRetrans(C)",
    "FailedTcpConnect(P)",
    "FailedTcpConnect(C)",
    "FailedTcpClosed(P)",
    "FailedTcpClosed(C)",
    "FailedUnexpectedMessage(P)",
    "FailedUnexpectedMessage(C)",
    "FailedCallRejected(P)",
    "FailedCallRejected(C)",
    "FailedCmdNotSent(P)",
    "FailedCmdNotSent(C)",
    "FailedRegexpDoesntMatch(P)",
    "FailedRegexpDoesntMatch(C)",
    "FailedRegexpShouldntMatch(P)",
    "FailedRegexpShouldntMatch(C)",
    "FailedRegexpHdrNotFound(P)",
    "FailedRegexpHdrNotFound(C)",
    "FailedOutboundCongestion(P)",
    "FailedOutboundCongestion(C)",
    "FailedTimeoutOnRecv(P)",
    "FailedTimeoutOnRecv(C)",
    "FailedTimeoutOnSend(P)",
    "FailedTimeoutOnSend(C)",
    "FailedTestDoesntMatch(P)",
    "FailedTestDoesntMatch(C)",
    "FailedTestShouldntMatch(P)",
    "FailedTestShouldntMatch(C)",
    "FailedStrcmpDoesntMatch(P)",
    "FailedStrcmpDoesntMatch(C)",
    "FailedStrcmpShouldntMatch(P)",
    "FailedStrcmpShouldntMatch(C)",
    "OutOfCallMsgs(P)",
    "OutOfCallMsgs(C)",
    "DeadCallMsgs(P)",
    "DeadCallMsgs(C)",
    "Retransmissions(P)",
    "Retransmissions(C)",
    "AutoAnswered(P)",
    "AutoAnswered(C)",
    "Warnings(P)",
    "Warnings(C)",
    "FatalErrors(P)",
    "FatalErrors(C)",
    "WatchdogMajor(P)",
    "WatchdogMajor(C)",
    "WatchdogMinor(P)",
    "WatchdogMinor(C)",
];

/// A generic counter's `-trace_stat` column name (SIPp `findCounter`): the
/// name as written, or `GenericCounter<name>` for an all-digit one — cut
/// to 19 characters, as SIPp formats it into a 20-byte buffer, so
/// `counter="123456"` heads `GenericCounter12345`.
fn csv_counter_name(name: &str) -> String {
    const SIPP_BUFFER_CHARS: usize = 19;
    if !name.bytes().all(|b| b.is_ascii_digit()) {
        return name.to_owned();
    }
    let mut column = format!("GenericCounter{name}");
    column.truncate(SIPP_BUFFER_CHARS);
    column
}

/// SIPp `sRepartitionHeader`: `Name;Name_<b0;…;Name_<bn;Name_>=bn;` — the
/// name column, one `<bound` column per bound, one `>=last`. Empty
/// without bounds.
fn repartition_header(name: &str, bounds: &[u64], d: &str) -> String {
    let Some(last) = bounds.last() else {
        return String::new();
    };
    let mut out = format!("{name}{d}");
    for b in bounds {
        let _ = write!(out, "{name}_<{b}{d}");
    }
    let _ = write!(out, "{name}_>={last}{d}");
    out
}

/// SIPp `sRepartitionInfo`: an empty name column, then the counts.
fn repartition_values(rows: &[(String, u64)], d: &str) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut out = d.to_owned();
    for (_, n) in rows {
        let _ = write!(out, "{n}{d}");
    }
    out
}

/// SIPp `msToHHMMSS`: `hh:mm:ss`.
#[must_use]
pub fn hhmmss(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
}

/// SIPp `msToHHMMSSus`: `hh:mm:ss:uuuuuu` of a millisecond count (the
/// microseconds are the leftover milliseconds × 1000).
#[must_use]
pub fn hhmmss_us(ms: f64) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = if ms.is_nan() || ms < 0.0 {
        0
    } else {
        ms as u64
    };
    let s = ms / 1000;
    format!(
        "{:02}:{:02}:{:02}:{:06}",
        s / 3600,
        s % 3600 / 60,
        s % 60,
        (ms % 1000) * 1000
    )
}

/// A double as a C++ `ostream` prints it by default (`%g`, six significant
/// digits, no trailing zeros), for the `-trace_rtt` rows.
#[must_use]
pub fn g6(v: f64) -> String {
    if v == 0.0 {
        return "0".to_owned();
    }
    #[allow(clippy::cast_possible_truncation)]
    let magnitude = v.abs().log10().floor() as i32;
    if !(-5..6).contains(&magnitude) {
        let s = format!("{v:.5e}");
        // Rust's `1.5e-1` → C's `1.5e-01`.
        let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
        let mant = mant.trim_end_matches('0').trim_end_matches('.');
        let e: i32 = exp.parse().unwrap_or(0);
        return format!("{mant}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    let decimals = usize::try_from(5 - magnitude).unwrap_or(0);
    let s = format!("{v:.decimals$}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_owned()
    } else {
        s
    }
}

/// Rotation policy shared by every log file: SIPp's `-ringbuffer_files`,
/// `-ringbuffer_size` and `-max_log_size` (`logger.cpp` `_trace`/`rotatef`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogRotation {
    /// How many rotated files to keep (0: rotation truncates in place).
    pub ringbuffer_files: usize,
    /// Rotate once this many bytes were written to the current file (0: never).
    pub ringbuffer_size: u64,
    /// Stop writing once this many bytes were written in total (0: never).
    pub max_log_size: u64,
}

/// A log file the engine writes to: `-trace_msg`, `-trace_err`,
/// `-trace_logs`, `-trace_shortmsg`, `-trace_calldebug` and the statistics
/// CSVs. Writes count bytes for SIPp's size-based rotation; a write error
/// disables the file with one warning instead of failing the run.
pub struct TraceFile {
    writer: Option<std::io::BufWriter<std::fs::File>>,
    path: PathBuf,
    /// `<scenario>_<pid>` and the kind (`messages`, `errors`, …), the
    /// rotated files' name parts. `None`: never rotates.
    rotated_base: Option<(String, String)>,
    rotation: LogRotation,
    /// Bytes written to the current file (SIPp `lfi->count`).
    count: u64,
    /// Unix seconds when the current file was opened (SIPp `starttime`).
    started: u64,
    /// The rotated files kept, oldest first: (start seconds, disambiguator).
    kept: Vec<(u64, u32)>,
}

impl TraceFile {
    /// Create (truncate) `path`; no rotation.
    ///
    /// # Errors
    ///
    /// The file cannot be created.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            writer: Some(std::io::BufWriter::new(std::fs::File::create(path)?)),
            path: path.to_owned(),
            rotated_base: None,
            rotation: LogRotation::default(),
            count: 0,
            started: unix_now(),
            kept: Vec::new(),
        })
    }

    /// Open `path` for a `kind` log of the run `base` (`<scenario>_<pid>`):
    /// truncated when `overwrite` (SIPp's default), appended to otherwise
    /// (`-<kind>_overwrite false`), rotating per `rotation`.
    ///
    /// # Errors
    ///
    /// The file cannot be opened.
    pub fn open(
        path: &Path,
        base: &str,
        kind: &str,
        overwrite: bool,
        rotation: LogRotation,
    ) -> std::io::Result<Self> {
        let file = if overwrite {
            std::fs::File::create(path)?
        } else {
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)?
        };
        Ok(Self {
            writer: Some(std::io::BufWriter::new(file)),
            path: path.to_owned(),
            rotated_base: Some((base.to_owned(), kind.to_owned())),
            rotation,
            count: 0,
            started: unix_now(),
            kept: Vec::new(),
        })
    }

    /// Where the file is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether writes still reach the file (a `-max_log_size` overrun or a
    /// write error closes it).
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.writer.is_some()
    }

    pub fn write(&mut self, chunk: &str) {
        let Some(w) = self.writer.as_mut() else {
            return;
        };
        if w.write_all(chunk.as_bytes()).is_err() {
            eprintln!(
                "sipr: warning: cannot write {}; tracing disabled",
                self.path.display()
            );
            self.writer = None;
            return;
        }
        self.count += chunk.len() as u64;
        let r = self.rotation;
        if r.max_log_size > 0 && self.count > r.max_log_size {
            // SIPp closes the file for good once the cap is passed.
            self.flush();
            self.writer = None;
            return;
        }
        if r.ringbuffer_size > 0 && self.count > r.ringbuffer_size {
            self.rotate();
            self.count = 0;
        }
    }

    /// SIPp `rotatef`: with `-ringbuffer_files` the current file is renamed
    /// to `<base>_<kind>_<start>.log` (`<start>.<n>.log` when a file of the
    /// same second exists) and the oldest kept file beyond the count is
    /// deleted; then the file is reopened, truncated. Without
    /// `-ringbuffer_files` the file is simply truncated in place.
    fn rotate(&mut self) {
        self.flush();
        self.writer = None;
        if let Some((base, kind)) = self.rotated_base.clone()
            && self.rotation.ringbuffer_files > 0
        {
            let name = |start: u64, n: u32| {
                let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
                if n > 0 {
                    dir.join(format!("{base}_{kind}_{start}.{n}.log"))
                } else {
                    dir.join(format!("{base}_{kind}_{start}.log"))
                }
            };
            if self.kept.len() >= self.rotation.ringbuffer_files {
                let (start, n) = self.kept.remove(0);
                let _ = std::fs::remove_file(name(start, n));
            }
            let n = match self.kept.last() {
                Some(&(last_start, last_n)) if last_start == self.started => last_n + 1,
                _ => 0,
            };
            let _ = std::fs::rename(&self.path, name(self.started, n));
            self.kept.push((self.started, n));
        }
        self.started = unix_now();
        match std::fs::File::create(&self.path) {
            Ok(f) => self.writer = Some(std::io::BufWriter::new(f)),
            Err(e) => eprintln!(
                "sipr: warning: cannot reopen {} after rotation: {e}",
                self.path.display()
            ),
        }
    }

    pub fn flush(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The first line of the `-trace_err` file (SIPp writes it when the file
/// is created).
pub const ERROR_LOG_HEADER: &str = "The following events occurred:\n";

/// One `-trace_msg` entry as SIPp's `TRACE_MSG` writes it on send and
/// receive: a rule, the time (always the RFC 3339 form there), then
/// `<TRANSPORT> message sent|received [<len>] bytes:` and the message.
#[must_use]
pub fn sipp_message_frame(transport: &str, direction: &str, payload: &[u8]) -> String {
    format!(
        "----------------------------------------------- {}\n{transport} message {direction} [{}] bytes:\n\n{}\n",
        clock::sipp_timestamp(SystemTime::now(), true),
        payload.len(),
        String::from_utf8_lossy(payload)
    )
}

/// One `-trace_msg` entry for a message that reached no live call (SIPp
/// `deadcall::process_incoming`).
#[must_use]
pub fn dead_call_frame(call_id: &str, transport: &str, payload: &[u8]) -> String {
    format!(
        "-----------------------------------------------\nDead call {call_id} received a {transport} message:\n\n{}\n",
        String::from_utf8_lossy(payload)
    )
}

/// One `-trace_shortmsg` line (SIPp `TRACE_SHORTMSG`): the time, `S` or
/// `R`, the Call-ID, `CSeq:<value>` and the start line, tab-separated.
/// SIPp's receive side always uses the default time form, its send side
/// honours `-rfc3339`; so does this.
#[must_use]
pub fn short_message_line(direction: char, message: &[u8], rfc3339: bool) -> String {
    let text = String::from_utf8_lossy(message);
    let call_id = header_value(&text, "Call-ID").unwrap_or_default();
    let cseq = header_value(&text, "CSeq").unwrap_or_default();
    let first = text
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end_matches('\r');
    let ts = clock::sipp_timestamp(SystemTime::now(), rfc3339 && direction == 'S');
    format!("{ts}\t{direction}\t{call_id}\tCSeq:{cseq}\t{first}\n")
}

/// One `-trace_err` line (SIPp `_screen_error`): the time, `: `, the text.
#[must_use]
pub fn error_line(text: &str, rfc3339: bool) -> String {
    format!(
        "{}: {text}\n",
        clock::sipp_timestamp(SystemTime::now(), rfc3339)
    )
}

/// One `-trace_calldebug` line (SIPp `callDebug`): the time, a space, the
/// text (which carries its own newline).
#[must_use]
pub fn calldebug_line(text: &str, rfc3339: bool) -> String {
    format!(
        "{} {text}",
        clock::sipp_timestamp(SystemTime::now(), rfc3339)
    )
}

/// The Call-ID of a message on the wire (for the per-call logs of an
/// outbound message, which the engine has only as bytes).
#[must_use]
pub fn message_call_id(message: &[u8]) -> Option<String> {
    header_value(&String::from_utf8_lossy(message), "Call-ID")
}

/// A header's value in a SIP message text (case-insensitive name, the first
/// occurrence), trimmed.
fn header_value(text: &str, name: &str) -> Option<String> {
    text.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_line_render() {
        let mut s = StatSet::new(&[10, 100], &[100, 1000]);
        s.outgoing_created = 10;
        s.successful = 8;
        s.failed_timeout = 2;
        s.record_rtd("1", Duration::from_millis(25));
        s.record_call_length(Duration::from_millis(500));
        assert_eq!(s.created(), 10);
        assert_eq!(s.failed(), 2);
        let line = s.line(3);
        assert!(line.contains("created 10 ok 8 failed 2"), "{line}");
        assert!(line.contains("rtd1 avg 25.0ms"), "{line}");
    }

    #[test]
    fn csv_header_is_sipps_column_set() {
        let mut s = StatSet::new(&[10, 100], &[500]);
        s.set_rtd_names(vec!["1".to_owned(), "setup".to_owned()]);
        let header = s.csv_header();
        let cols: Vec<&str> = header.trim_end().split(';').collect();
        // SIPp writes a trailing delimiter, so the last split is empty.
        assert_eq!(cols.last(), Some(&""));
        assert_eq!(&cols[..3], &["StartTime", "LastResetTime", "CurrentTime"]);
        assert_eq!(cols[67], "WatchdogMinor(C)");
        assert_eq!(cols[68], "ResponseTime1(P)");
        assert_eq!(cols[71], "ResponseTime1StDev(C)");
        assert_eq!(cols[72], "ResponseTimesetup(P)");
        assert_eq!(cols[76], "CallLength(P)");
        assert_eq!(cols[79], "CallLengthStDev(C)");
        assert_eq!(
            &cols[80..84],
            &[
                "ResponseTimeRepartition1",
                "ResponseTimeRepartition1_<10",
                "ResponseTimeRepartition1_<100",
                "ResponseTimeRepartition1_>=100"
            ]
        );
        assert_eq!(cols[84], "ResponseTimeRepartitionsetup");
        assert_eq!(
            &cols[88..91],
            &[
                "CallLengthRepartition",
                "CallLengthRepartition_<500",
                "CallLengthRepartition_>=500"
            ]
        );
        assert_eq!(cols.len(), 92);
        // Every row has exactly the header's columns.
        s.outgoing_created = 5;
        s.successful = 4;
        s.failed_timeout = 1;
        s.record_rtd("1", Duration::from_millis(25));
        s.record_rtd("setup", Duration::from_millis(250));
        s.record_call_length(Duration::from_millis(600));
        let row = s.csv_row(2, 10.0, None);
        let vals: Vec<&str> = row.trim_end().split(';').collect();
        assert_eq!(vals.len(), cols.len(), "{header}{row}");
        assert_eq!(vals[5], "10.000", "TargetRate");
        assert_eq!(vals[10], "5", "OutgoingCall(P)");
        assert_eq!(vals[12], "5", "TotalCallCreated");
        assert_eq!(vals[13], "2", "CurrentCall");
        assert_eq!(vals[15], "4", "SuccessfulCall(C)");
        assert_eq!(vals[41], "1", "FailedTimeoutOnRecv(C)");
        assert_eq!(vals[68], "00:00:00:025000", "ResponseTime1(P)");
        assert_eq!(vals[73], "00:00:00:250000", "ResponseTimesetup(C)");
        assert_eq!(vals[77], "00:00:00:600000", "CallLength(C)");
        assert_eq!(&vals[80..84], &["", "0", "1", "0"], "rtd 1 repartition");
        assert_eq!(&vals[88..91], &["", "0", "1"], "call length repartition");
        // -users prints the user count where the rate goes.
        let row = s.csv_row(2, 10.0, Some(7));
        assert_eq!(row.split(';').nth(5), Some("7"));
    }

    #[test]
    fn csv_periods_roll() {
        let mut s = StatSet::new(&[], &[]);
        s.outgoing_created = 5;
        s.successful = 5;
        s.record_rtd("1", Duration::from_millis(40));
        let row1 = s.csv_row(0, 1.0, None);
        s.end_period();
        // Second period with no new completions: periodic columns read 0,
        // cumulative ones stay; the period RTD mean is empty, the total not.
        let row2 = s.csv_row(0, 1.0, None);
        let c1: Vec<&str> = row1.split(';').collect();
        let c2: Vec<&str> = row2.split(';').collect();
        assert_eq!(c1[14], "5", "SuccessfulCall(P) first period: {row1}");
        assert_eq!(c2[14], "0", "SuccessfulCall(P) second period: {row2}");
        assert_eq!(c2[15], "5", "SuccessfulCall(C): {row2}");
        assert_eq!(c1[68], "00:00:00:040000");
        assert_eq!(c2[68], "00:00:00:000000");
        assert_eq!(c2[69], "00:00:00:040000");
    }

    #[test]
    fn periodic_rtd_zeroes_the_repartitions() {
        let mut s = StatSet::new(&[50], &[]);
        s.dump.periodic_rtd = true;
        s.record_rtd("1", Duration::from_millis(10));
        assert_eq!(s.response_repartition.rows()[0].1, 1);
        s.end_period();
        assert_eq!(s.response_repartition.rows()[0].1, 0);
        assert_eq!(s.rtd_repartitions["1"].rows()[0].1, 0);
    }

    /// Steps 0 and 2 share `reg`, step 1 names `7`, step 3 names none.
    fn counting_stat_set() -> StatSet {
        let mut s = StatSet::new(&[], &[500]);
        s.set_step_counters(vec![
            Some("reg".to_owned()),
            Some("7".to_owned()),
            Some("reg".to_owned()),
            None,
        ]);
        s
    }

    #[test]
    fn counters_are_scenario_wide_and_named_in_first_mention_order() {
        let mut s = counting_stat_set();
        for step in [0, 2, 2, 1, 3, 99] {
            s.tick_counter(step);
        }
        assert_eq!(s.counter("reg"), Some(3), "steps 0 and 2 share it");
        assert_eq!(s.counter("7"), Some(1));
        assert_eq!(s.counter("other"), None);
        let mut snap = Snapshot::default();
        s.fill_snapshot(&mut snap, 0);
        let names: Vec<&str> = snap.counters.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["reg", "7"]);
        // `reset stats` zeroes the values and keeps the counters.
        s.reset();
        assert_eq!(s.counter("reg"), Some(0));
        s.tick_counter(2);
        assert_eq!(s.counter("reg"), Some(1));
    }

    #[test]
    fn counters_periodic_value_restarts_at_each_screen_refresh() {
        let mut s = counting_stat_set();
        s.tick_counter(0);
        s.tick_counter(0);
        let mut snap = Snapshot::default();
        s.fill_snapshot(&mut snap, 0);
        assert_eq!(
            (snap.counters[0].periodic, snap.counters[0].cumulative),
            (2, 2)
        );
        s.end_display_period();
        s.tick_counter(2);
        s.fill_snapshot(&mut snap, 0);
        assert_eq!(
            (snap.counters[0].periodic, snap.counters[0].cumulative),
            (1, 3)
        );
        // The screen period and the `-fd` dump period are separate clocks.
        let row = s.csv_row(0, 1.0, None);
        let cols: Vec<&str> = row.split(';').collect();
        assert_eq!(&cols[72..76], &["3", "3", "0", "0"], "{row}");
    }

    #[test]
    fn counters_take_csv_columns_after_the_call_length() {
        let mut s = counting_stat_set();
        s.tick_counter(0);
        s.tick_counter(1);
        let header = s.csv_header();
        let cols: Vec<&str> = header.split(';').collect();
        // No RTDs: the call length takes columns 68-71.
        assert_eq!(cols[71], "CallLengthStDev(C)");
        assert_eq!(
            &cols[72..77],
            &[
                "reg(P)",
                "reg(C)",
                "GenericCounter7(P)",
                "GenericCounter7(C)",
                "CallLengthRepartition"
            ]
        );
        let row = s.csv_row(0, 1.0, None);
        let vals: Vec<&str> = row.split(';').collect();
        assert_eq!(vals.len(), cols.len(), "{header}{row}");
        assert_eq!(&vals[72..76], &["1", "1", "1", "1"]);
        // `(P)` is since the last dump, `(C)` since the start.
        s.end_period();
        s.tick_counter(2);
        let row = s.csv_row(0, 1.0, None);
        let vals: Vec<&str> = row.split(';').collect();
        assert_eq!(&vals[72..76], &["1", "2", "0", "1"], "{row}");
    }

    #[test]
    fn numeric_counter_columns_are_cut_like_sipps_buffer() {
        assert_eq!(csv_counter_name("reg-ok"), "reg-ok");
        assert_eq!(csv_counter_name("12"), "GenericCounter12");
        assert_eq!(csv_counter_name("12345"), "GenericCounter12345");
        assert_eq!(csv_counter_name("1234567"), "GenericCounter12345");
        assert_eq!(csv_counter_name("12a"), "12a");
    }

    #[test]
    fn counts_file_follows_sipps_columns() {
        let mut s = StatSet::new(&[], &[]);
        s.init_steps(vec!["a".into(), "b".into(), "c".into(), "d".into()]);
        s.set_step_kinds(vec![
            StepKind::Send {
                name: "INVITE".into(),
                retrans: true,
            },
            StepKind::Recv { name: "200".into() },
            StepKind::Pause,
            StepKind::Send {
                name: "200".into(),
                retrans: false,
            },
            StepKind::Pause,
            StepKind::Pause,
            StepKind::Pause,
        ]);
        s.init_steps((0..7).map(|i| format!("s{i}")).collect());
        s.set_step_hidden(vec![false, false, false, true, false, false, false]);
        // Steps 4-6 stand for a sendCmd, a recvCmd and a nop, which the
        // engine counts as Pause steps.
        assert_eq!(
            s.counts_header(),
            "CurrentTime;ElapsedTime;0_INVITE_Sent;0_INVITE_Retrans;0_INVITE_Timeout;\
             1_200_Recv;1_200_Retrans;1_200_Timeout;1_200_Unexp;2_Pause_Sessions;\
             2_Pause_Unexp;4_Pause_Sessions;4_Pause_Unexp;5_Pause_Sessions;\
             5_Pause_Unexp;6_Pause_Sessions;6_Pause_Unexp;\n"
        );
        s.steps[0].sent = 3;
        s.steps[0].retrans = 1;
        s.steps[1].recv = 2;
        s.steps[1].unexpected = 1;
        s.steps[2].sessions = 3;
        s.steps[4].sent = 2;
        s.steps[5].recv = 2;
        s.steps[5].unexpected = 1;
        let row = s.counts_row();
        assert!(row.ends_with(";3;1;0;2;0;0;1;3;0;0;0;0;1;0;0;\n"), "{row}");
        assert_eq!(row.split(';').count(), s.counts_header().split(';').count());
    }

    #[test]
    fn counts_columns_number_messages_so_labels_take_no_index() {
        let mut s = StatSet::new(&[], &[]);
        s.init_steps((0..5).map(|i| format!("s{i}")).collect());
        s.set_step_kinds(vec![
            StepKind::Label,
            StepKind::Pause,
            StepKind::Label,
            StepKind::Pause,
            StepKind::Pause,
        ]);
        s.steps[4].unexpected = 7;
        // Steps 1, 3 and 4 are SIPp messages 0, 1 and 2.
        assert_eq!(
            s.counts_header(),
            "CurrentTime;ElapsedTime;0_Pause_Sessions;0_Pause_Unexp;1_Pause_Sessions;\
             1_Pause_Unexp;2_Pause_Sessions;2_Pause_Unexp;\n"
        );
        assert!(s.counts_row().ends_with(";0;0;0;0;0;7;\n"));
    }

    #[test]
    fn error_codes_and_rtt_rows() {
        let mut s = StatSet::new(&[], &[]);
        s.dump.trace_rtt = true;
        s.dump.rtt_freq = 2;
        s.record_error_code(486);
        s.record_error_code(503);
        let row = s.error_codes_row();
        assert!(row.ends_with(";503,486,\n"), "{row}");
        assert!(s.error_codes_row().ends_with(";\n"));
        assert_eq!(s.rtt_header(), "Date_ms;response_time_ms;rtd_no\n");
        assert!(!s.rtt_due());
        s.record_rtd("1", Duration::from_millis(25));
        s.record_rtd("x", Duration::from_millis(1500));
        assert!(s.rtt_due());
        let rows = s.take_rtt_rows();
        let lines: Vec<&str> = rows.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with(";0.025;1"), "{rows}");
        assert!(lines[1].ends_with(";1.5;x"), "{rows}");
        assert!(s.take_rtt_rows().is_empty());
    }

    #[test]
    fn sipp_number_formats() {
        assert_eq!(hhmmss(Duration::from_secs(3661)), "01:01:01");
        assert_eq!(hhmmss_us(25.0), "00:00:00:025000");
        assert_eq!(hhmmss_us(61_002.7), "00:01:01:002000");
        assert_eq!(hhmmss_us(f64::NAN), "00:00:00:000000");
        assert_eq!(g6(0.0), "0");
        assert_eq!(g6(0.025), "0.025");
        assert_eq!(g6(12.3456789), "12.3457");
        assert_eq!(g6(1500.0), "1500");
        assert_eq!(g6(123_456.0), "123456");
        assert_eq!(g6(1_234_567.0), "1.23457e+06");
        assert_eq!(g6(0.0000012), "1.2e-06");
    }

    #[test]
    fn rtd1_feeds_response_repartition() {
        let mut s = StatSet::new(&[50], &[]);
        s.record_rtd("1", Duration::from_millis(10));
        s.record_rtd("2", Duration::from_millis(500)); // rtd2 must NOT feed it
        let rows = s.response_repartition.rows();
        assert_eq!(rows[0].1 + rows[1].1, 1);
    }

    #[test]
    fn trace_file_writes_and_frames() {
        let dir = std::env::temp_dir().join(format!("sipr-stats-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("trace.log");
        let mut t = TraceFile::create(&path).expect("create");
        t.write(&sipp_message_frame(
            "UDP",
            "sent",
            b"INVITE sip:x SIP/2.0\r\n",
        ));
        t.flush();
        let content = std::fs::read_to_string(&path).expect("read");
        let first = content.lines().next().unwrap();
        assert!(
            first.starts_with("----------------------------------------------- 20")
                && first.ends_with('Z'),
            "{content}"
        );
        assert!(
            content.contains("UDP message sent [22] bytes:\n\nINVITE sip:x SIP/2.0\r\n\n"),
            "{content}"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn log_lines_have_sipps_shapes() {
        let msg = b"INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h\r\ncall-id: abc@h\r\nCSeq: 7 INVITE\r\n\r\n";
        let s = short_message_line('S', msg, true);
        let cols: Vec<&str> = s.trim_end().split('\t').collect();
        assert_eq!(cols.len(), 5, "{s}");
        assert!(cols[0].ends_with('Z'), "send side honours -rfc3339: {s}");
        assert_eq!(
            &cols[1..],
            &["S", "abc@h", "CSeq:7 INVITE", "INVITE sip:x SIP/2.0"]
        );
        let r = short_message_line('R', msg, true);
        assert!(
            !r.starts_with(|c: char| c.is_ascii_digit()) || r.split('\t').count() == 7,
            "receive side keeps the tabbed time form: {r}"
        );
        assert_eq!(
            r.trim_end().split('\t').next_back(),
            Some("INVITE sip:x SIP/2.0")
        );
        let e = error_line("call c failed", false);
        assert!(e.contains(": call c failed\n"), "{e}");
        let d = calldebug_line("Starting call c\n", true);
        assert!(d.ends_with(" Starting call c\n") && d.contains('Z'), "{d}");
        let f = dead_call_frame("c", "UDP", b"BYE sip:x SIP/2.0\r\n");
        assert!(
            f.contains("Dead call c received a UDP message:\n\nBYE"),
            "{f}"
        );
    }

    #[test]
    fn log_rotation_follows_sipps_ring_buffer() {
        let dir = std::env::temp_dir().join(format!("sipr-rot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("uac_1_messages.log");
        let rotation = LogRotation {
            ringbuffer_files: 2,
            ringbuffer_size: 10,
            max_log_size: 0,
        };
        let mut t = TraceFile::open(&path, "uac_1", "messages", true, rotation).unwrap();
        for i in 0..4 {
            // 12 bytes each: every write passes the 10-byte ring size.
            t.write(&format!("chunk-{i:05}\n"));
        }
        t.flush();
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        // Four rotations of a file opened within the same second: the
        // rotated names take .1/.2/.3 disambiguators and only the last two
        // rotated files survive, plus the live one.
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(
            names.contains(&"uac_1_messages.log".to_owned()),
            "{names:?}"
        );
        assert!(
            names
                .iter()
                .filter(|n| n.starts_with("uac_1_messages_"))
                .count()
                == 2,
            "{names:?}"
        );
        assert!(std::fs::read_to_string(&path).unwrap().is_empty());
        // -max_log_size closes the file for good.
        let path2 = dir.join("uac_1_errors.log");
        let mut t2 = TraceFile::open(
            &path2,
            "uac_1",
            "errors",
            true,
            LogRotation {
                ringbuffer_files: 0,
                ringbuffer_size: 0,
                max_log_size: 5,
            },
        )
        .unwrap();
        t2.write("123456");
        assert!(!t2.is_open());
        t2.write("more");
        t2.flush();
        assert_eq!(std::fs::read_to_string(&path2).unwrap(), "123456");
        // -<kind>_overwrite false appends.
        let mut t3 =
            TraceFile::open(&path2, "uac_1", "errors", false, LogRotation::default()).unwrap();
        t3.write("+");
        t3.flush();
        assert_eq!(std::fs::read_to_string(&path2).unwrap(), "123456+");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
