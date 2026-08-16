//! The M3 UAC engine: one event-loop thread owning every call.
//!
//! Runtime shape (docs/ARCHITECTURE.md §2, as-built note): the UDP recv
//! loop, the timer service, the pacer, and the stdin watcher all send into
//! ONE mpsc channel; this loop drains it and advances call state machines.
//! Single ownership of the call map means no locks anywhere on the hot path.
//!
//! Recv matching implements the semantics verified against SIPp's
//! `call.cpp` (docs/SIPP_COMPAT.md §6): forward scan skipping unmatched
//! optionals until the first mandatory step, backward contiguous-optional
//! scan for late/repeated matches, CSeq-method guard on responses, and
//! retransmission cancel on any matched recv.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use sipr_net::timer::TimerId;
use sipr_net::{
    Inbound, NetEvent, RetransSchedule, TcpTransport, TimerService, TransportConfig, UdpTransport,
};
use sipr_scenario::inject::{InjectMode, InjectionFile};
use sipr_scenario::model::{Action, Expect, PauseSpec, RecvStep, Role, Scenario, Step, StepCommon};
use sipr_scenario::template::{Keyword, MsgTemplate, Span};

use crate::render::{RenderCtx, render};

/// Engine configuration, distilled from the CLI.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Remote target for outbound calls (required for UAC scenarios).
    pub target: Option<SocketAddr>,
    /// Local IP to bind (`-i`).
    pub local_ip: Option<IpAddr>,
    /// Local port to bind (`-p`).
    pub port: Option<u16>,
    /// `[service]` value (`-s`).
    pub service: String,
    /// New calls per rate period (`-r`).
    pub rate: f64,
    /// Rate period (`-rp`).
    pub rate_period: Duration,
    /// Concurrent-call cap (`-l`); excess calls are not started, not queued.
    pub limit: Option<u64>,
    /// Total calls to start (`-m`).
    pub max_calls: Option<u64>,
    /// `<pause/>` default duration (`-d`).
    pub pause_default: Duration,
    /// Global retransmission attempt cap (`-max_retrans`).
    pub max_retrans: Option<u32>,
    /// Disable retransmissions (`-nr`).
    pub no_retrans: bool,
    /// Global test timeout (`-timeout`).
    pub timeout: Option<Duration>,
    /// Initial `[cseq]` value (`-base_cseq`).
    pub base_cseq: u32,
    /// `[call_id]` format (`-cid_str`): `%u` call number, `%p` pid, `%s` ip.
    pub call_id_format: Option<String>,
    /// Seed for pause distributions / chance / loss.
    pub seed: u64,
    /// Print periodic stat lines (headless mode).
    pub periodic_stats: bool,
    /// `-aa`: auto-answer in-dialog OPTIONS/INFO/UPDATE/NOTIFY with 200.
    pub auto_answer: bool,
    /// `-au`: default digest username for `[authentication]`.
    pub auth_user: Option<String>,
    /// `-ap`: default digest password for `[authentication]`.
    pub auth_password: Option<String>,
    /// `-trace_msg` destination.
    pub trace_msg: Option<std::path::PathBuf>,
    /// `-trace_err` destination.
    pub trace_err: Option<std::path::PathBuf>,
    /// `-trace_stat` destination (`-stf`).
    pub trace_stat: Option<std::path::PathBuf>,
    /// `-fd`: statistics dump interval.
    pub stat_interval: Duration,
    /// `-inf`: injection-file paths (CSV) for `[fieldN]`, in order.
    pub inf_files: Vec<std::path::PathBuf>,
    /// `-infindex FILE FIELD`: build a lookup index on `FIELD` of the injection
    /// file named `FILE` (matched by basename), enabling `<lookup>`.
    pub inf_index: Vec<(String, usize)>,
    /// `-t`: which transport to run.
    pub transport: TransportKind,
}

/// Transport selection (`-t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportKind {
    /// `u1`: UDP, one socket shared by all calls (SIPp default).
    #[default]
    UdpMono,
    /// `t1`: TCP, one connection per peer (client dials, server accepts).
    TcpMono,
}

/// Final counters of a run.
#[derive(Debug, Default, Clone)]
pub struct RunReport {
    /// Calls started.
    pub created: u64,
    /// Calls that completed their scenario.
    pub successful: u64,
    /// Calls that failed (unexpected message, timeout, retrans exhausted...).
    pub failed: u64,
    /// Messages sent (first transmissions).
    pub messages_sent: u64,
    /// Messages received and matched.
    pub messages_matched: u64,
    /// Retransmissions sent.
    pub retrans_sent: u64,
    /// Inbound retransmissions detected (deduped).
    pub retrans_recv: u64,
    /// Messages that matched no step of any live call.
    pub unexpected: u64,
    /// Datagrams that were not SIP at all.
    pub garbage: u64,
    /// Wall-clock duration of the run.
    pub elapsed: Duration,
}

impl RunReport {
    /// SIPp-compatible exit code (docs/SIPP_COMPAT.md §5).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.failed > 0 {
            1
        } else if self.successful > 0 {
            0
        } else {
            99 // aborted, no calls processed
        }
    }

    /// One-line summary for logs.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "created {} successful {} failed {} | sent {} matched {} \
             retrans-sent {} retrans-recv {} unexpected {} garbage {} | {:.1?}",
            self.created,
            self.successful,
            self.failed,
            self.messages_sent,
            self.messages_matched,
            self.retrans_sent,
            self.retrans_recv,
            self.unexpected,
            self.garbage,
            self.elapsed
        )
    }
}

/// Handle for runtime control (rate changes from the future TUI; tests).
#[derive(Clone)]
pub struct EngineControl {
    /// Rate in milli-calls-per-period, adjustable while running.
    rate_millis: Arc<AtomicU64>,
    stop_pacer: Arc<AtomicBool>,
}

impl EngineControl {
    /// Replace the call rate (calls per rate period).
    pub fn set_rate(&self, rate: f64) {
        let clamped = rate.clamp(0.0, 1_000_000.0);
        // Millis precision is plenty for a call rate.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        self.rate_millis
            .store((clamped * 1000.0) as u64, Ordering::Relaxed);
    }

    /// Current rate.
    #[must_use]
    pub fn rate(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let r = self.rate_millis.load(Ordering::Relaxed) as f64;
        r / 1000.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerKind {
    Retrans,
    RecvTimeout,
    Pause,
    Timewait,
}

enum Event {
    Net(NetEvent),
    CallTimer {
        call_id: String,
        generation: u64,
        kind: TimerKind,
    },
    PacerTick,
    GlobalTimeout,
    Stdin(char),
}

struct RetransCtx {
    buf: Vec<u8>,
    lost_pct: Option<f64>,
    /// Step index of the send, for per-step retrans counters.
    msg_index: usize,
    attempt: u32,
    schedule: RetransSchedule,
    timer: TimerId,
}

struct CallState {
    number: u64,
    /// Where this call's messages go (per-call for UAS; `-target` for UAC).
    remote: SocketAddr,
    /// Next step to execute; when `waiting`, start of the recv window.
    index: usize,
    waiting: bool,
    /// In timewait: absorb retransmissions, never fail.
    completing: bool,
    started: Instant,
    cseq: u32,
    /// Last message we sent (re-sent when the peer retransmits).
    last_sent: Option<Vec<u8>>,
    /// Running RTD stopwatches: (name, started-at).
    rtd_starts: Vec<(String, Instant)>,
    /// Assigned injection-file line per `-inf` file (None = no line).
    field_lines: Vec<Option<usize>>,
    /// Per-call variable store.
    store: crate::actions::VarStore,
    /// Named counters (`counter` step attribute).
    counters: std::collections::HashMap<String, u64>,
    /// Stable client nonce for digest auth.
    cnonce: String,
    /// Pending digest challenge captured by a `recv auth="true"`.
    challenge: Option<sipr_auth::Challenge>,
    peer_tag: Option<String>,
    routes: Vec<String>,
    last_recv: Option<Inbound>,
    /// (branch, cseq-line, start-line-ish) key for inbound retrans dedupe.
    last_recv_key: Option<(String, String, String)>,
    retrans: Option<RetransCtx>,
    timer: Option<(TimerId, TimerKind)>,
    /// Bumped whenever timers are (re)armed; stale fires are ignored.
    generation: u64,
}

/// Why the engine refused to run a scenario.
#[derive(Debug)]
pub struct EngineError(pub String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Channels wiring a live UI to the engine: snapshots flow out about once
/// a second; single-character key commands flow in (`+ - * / p q Q`).
pub struct UiChannels {
    /// Engine → UI: periodic stat snapshots.
    pub snapshots: std::sync::mpsc::Sender<sipr_stats::Snapshot>,
    /// UI → engine: key commands.
    pub keys: Receiver<char>,
}

/// Run a UAC scenario to completion. Blocks until done.
///
/// # Errors
///
/// [`EngineError`] when the scenario needs features beyond M3 (actions,
/// variables, auth, UAS role) or the transport cannot bind.
pub fn run(scenario: &Scenario, config: &EngineConfig) -> Result<RunReport, EngineError> {
    let (report, _control) = run_with_control(scenario, config)?;
    Ok(report)
}

/// [`run`], also exposing the runtime control handle to the caller thread
/// via a callback-free pattern: control is returned only after completion in
/// M3 (the TUI consumes it live at M5).
///
/// # Errors
///
/// See [`run`].
pub fn run_with_control(
    scenario: &Scenario,
    config: &EngineConfig,
) -> Result<(RunReport, EngineControl), EngineError> {
    run_with_ui(scenario, config, None)
}

/// [`run`] with an optional live UI attached (see [`UiChannels`]).
///
/// # Errors
///
/// See [`run`].
pub fn run_with_ui(
    scenario: &Scenario,
    config: &EngineConfig,
    ui: Option<UiChannels>,
) -> Result<(RunReport, EngineControl), EngineError> {
    validate_for_engine(scenario)?;
    if scenario.role == Role::Uac && config.target.is_none() {
        return Err(EngineError(
            "this scenario places calls (UAC): a remote target is required".into(),
        ));
    }
    let mut engine = Engine::new(scenario, config, ui)?;
    let control = engine.control.clone();
    let report = engine.run_loop();
    Ok((report, control))
}

/// The bound transport, dispatched by kind. Both variants expose the same
/// address/send surface the engine uses.
enum Transport {
    Udp(UdpTransport),
    Tcp(TcpTransport),
}

impl Transport {
    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(u) => u.local_addr(),
            Self::Tcp(t) => t.local_addr(),
        }
    }

    fn send_to(&self, data: &[u8], to: SocketAddr, lost_pct: Option<f64>) -> std::io::Result<bool> {
        match self {
            Self::Udp(u) => u.send_to(data, to, lost_pct),
            Self::Tcp(t) => t.send_to(data, to, lost_pct),
        }
    }
}

struct Engine<'s> {
    scenario: &'s Scenario,
    config: EngineConfig,
    transport: Transport,
    /// `[transport]` token and whether the transport is reliable (no retrans).
    transport_token: &'static str,
    reliable: bool,
    timers: TimerService<Event>,
    rx: Receiver<Event>,
    calls: HashMap<String, CallState>,
    stats: sipr_stats::StatSet,
    trace_msg: Option<sipr_stats::TraceFile>,
    trace_err: Option<sipr_stats::TraceFile>,
    trace_stat: Option<sipr_stats::TraceFile>,
    inf_files: Vec<std::cell::RefCell<InjectionFile>>,
    inf_seq: Vec<usize>,
    rng: sipr_net::rng::Rng,
    /// Per-step: CSeq method a response recv must carry (SIPp guard).
    expected_cseq_method: Vec<Option<String>>,
    control: EngineControl,
    pacer_carry: f64,
    /// Fraction of the rate period each pacer tick represents.
    tick_ratio: f64,
    paused: bool,
    snapshot_tx: Option<std::sync::mpsc::Sender<sipr_stats::Snapshot>>,
    /// (when, created-count) at the last snapshot, for the period rate.
    last_snapshot: (Instant, u64),
    soft_stopping: bool,
    hard_stop: bool,
    local_ip_str: String,
    pid: u32,
}

impl<'s> Engine<'s> {
    fn new(
        scenario: &'s Scenario,
        config: &EngineConfig,
        ui: Option<UiChannels>,
    ) -> Result<Self, EngineError> {
        let (tx, rx) = channel::<Event>();
        let snapshot_tx = ui.map(|ui| {
            // Forward UI key presses into the event loop.
            let key_tx = tx.clone();
            let keys = ui.keys;
            let _keys = std::thread::Builder::new()
                .name("sipr-ui-keys".into())
                .spawn(move || {
                    while let Ok(c) = keys.recv() {
                        if key_tx.send(Event::Stdin(c)).is_err() {
                            return;
                        }
                    }
                });
            ui.snapshots
        });
        // Bridge net events into the engine channel.
        let (net_tx, net_rx) = channel::<NetEvent>();
        let bridge_tx = tx.clone();
        let _bridge = std::thread::Builder::new()
            .name("sipr-net-bridge".into())
            .spawn(move || {
                while let Ok(ev) = net_rx.recv() {
                    if bridge_tx.send(Event::Net(ev)).is_err() {
                        return;
                    }
                }
            });
        let tcfg = TransportConfig {
            local_ip: config.local_ip,
            port: config.port,
            send_loss_pct: 0.0,
            recv_loss_pct: 0.0,
            loss_seed: config.seed,
        };
        let (transport, transport_token, reliable) = match config.transport {
            TransportKind::UdpMono => {
                let u = UdpTransport::bind(&tcfg, net_tx)
                    .map_err(|e| EngineError(format!("cannot bind UDP socket: {e}")))?;
                (Transport::Udp(u), "UDP", false)
            }
            TransportKind::TcpMono => {
                let t = match scenario.role {
                    // Client: one mono-socket connection to the target, opened now.
                    Role::Uac => {
                        let remote = config
                            .target
                            .ok_or_else(|| EngineError("TCP UAC needs a remote target".into()))?;
                        TcpTransport::connect(&tcfg, net_tx, remote).map_err(|e| {
                            EngineError(format!("cannot connect TCP to {remote}: {e}"))
                        })?
                    }
                    // Server: listen and accept, framing each connection.
                    Role::Uas => TcpTransport::listen(&tcfg, net_tx)
                        .map_err(|e| EngineError(format!("cannot bind TCP listener: {e}")))?,
                };
                (Transport::Tcp(t), "TCP", true)
            }
        };
        let timers = TimerService::start(tx.clone());
        let control = EngineControl {
            rate_millis: Arc::new(AtomicU64::new(0)),
            stop_pacer: Arc::new(AtomicBool::new(false)),
        };
        control.set_rate(config.rate);
        // Pacer: tick faster than the rate period and start fractional
        // batches, so a `-r 500 -rp 1000` run smooths into ~20ms bursts of
        // ~10 instead of one burst of 500 (SIPp smooths within the period).
        let tick = config.rate_period.min(Duration::from_millis(20));
        let pacer_tx = tx.clone();
        let pacer_stop = Arc::clone(&control.stop_pacer);
        let _pacer = std::thread::Builder::new()
            .name("sipr-pacer".into())
            .spawn(move || {
                while !pacer_stop.load(Ordering::Relaxed) {
                    std::thread::sleep(tick);
                    if pacer_tx.send(Event::PacerTick).is_err() {
                        return;
                    }
                }
            });
        // Stdin watcher: 'q' = soft quit, 'Q' = hard quit.
        let stdin_tx = tx.clone();
        let _stdin = std::thread::Builder::new()
            .name("sipr-stdin".into())
            .spawn(move || {
                let mut line = String::new();
                loop {
                    line.clear();
                    match std::io::stdin().read_line(&mut line) {
                        Ok(0) | Err(_) => return, // EOF: no interactive control
                        Ok(_) => {
                            if let Some(c) = line.trim().chars().next() {
                                if stdin_tx.send(Event::Stdin(c)).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            });
        if let Some(t) = config.timeout {
            timers.arm(t, Event::GlobalTimeout);
        }
        let local_addr = transport.local_addr();
        eprintln!(
            "sipr: bound to {local_addr} ({})",
            match scenario.role {
                Role::Uac => "placing calls",
                Role::Uas => "answering calls",
            }
        );
        let open_trace = |path: &Option<std::path::PathBuf>,
                          what: &str|
         -> Result<Option<sipr_stats::TraceFile>, EngineError> {
            path.as_ref()
                .map(|p| {
                    sipr_stats::TraceFile::create(p).map_err(|e| {
                        EngineError(format!("cannot create {what} file {}: {e}", p.display()))
                    })
                })
                .transpose()
        };
        let mut trace_stat = open_trace(&config.trace_stat, "statistics")?;
        if let Some(f) = trace_stat.as_mut() {
            f.write(&sipr_stats::StatSet::csv_header());
        }
        let mut stat_set = sipr_stats::StatSet::new(
            &scenario.response_time_repartition,
            &scenario.call_length_repartition,
        );
        stat_set.init_steps(scenario.steps.iter().map(step_label).collect());
        // Load -inf injection files up front (fail fast on bad files). SIPp
        // keys files by basename; keyword `file=` and `-infindex` match that.
        let mut inf_files = Vec::with_capacity(config.inf_files.len());
        for path in &config.inf_files {
            let text = std::fs::read_to_string(path).map_err(|e| {
                EngineError(format!(
                    "cannot read injection file {}: {e}",
                    path.display()
                ))
            })?;
            let name = path.file_name().map_or_else(
                || path.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            let file = InjectionFile::parse(&name, &text).map_err(EngineError)?;
            if file.mode == InjectMode::User {
                eprintln!(
                    "sipr: warning: injection file {name} uses USER mode, which needs \
                     -users (unsupported); its [fieldN] will render empty"
                );
            }
            inf_files.push(std::cell::RefCell::new(file));
        }
        // Apply -infindex: build the lookup index on the named file's field.
        for (file_name, field) in &config.inf_index {
            let cell = inf_files
                .iter()
                .find(|c| c.borrow().name == *file_name)
                .ok_or_else(|| {
                    EngineError(format!("-infindex: no injection file named '{file_name}'"))
                })?;
            cell.borrow_mut().build_index(*field);
        }
        // Reject scenarios whose [fieldN file=…] names a file we did not load.
        validate_field_files(scenario, &inf_files)?;
        let inf_len = inf_files.len();
        Ok(Self {
            scenario,
            config: config.clone(),
            transport,
            transport_token,
            reliable,
            timers,
            rx,
            calls: HashMap::new(),
            stats: stat_set,
            trace_msg: open_trace(&config.trace_msg, "message trace")?,
            trace_err: open_trace(&config.trace_err, "error trace")?,
            trace_stat,
            inf_files,
            inf_seq: vec![0; inf_len],
            rng: sipr_net::rng::Rng::new(config.seed ^ 0x51B8_0003),
            expected_cseq_method: precompute_cseq_methods(scenario),
            control,
            pacer_carry: 0.0,
            tick_ratio: tick.as_secs_f64() / config.rate_period.as_secs_f64(),
            paused: false,
            snapshot_tx,
            last_snapshot: (Instant::now(), 0),
            soft_stopping: false,
            hard_stop: false,
            local_ip_str: local_addr.ip().to_string(),
            pid: std::process::id(),
        })
    }

    fn run_loop(&mut self) -> RunReport {
        let started = Instant::now();
        let mut last_line = Instant::now();
        let mut last_stat_dump = Instant::now();
        // First tick immediately: SIPp starts placing calls right away.
        self.on_pacer_tick();
        loop {
            if self.hard_stop || (self.done_creating() && self.calls.is_empty()) {
                break;
            }
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Event::Net(NetEvent::Packet(p))) => self.on_packet(&p),
                Ok(Event::Net(NetEvent::Garbage { .. })) => self.stats.garbage += 1,
                Ok(Event::Net(NetEvent::SocketError(kind))) => {
                    eprintln!("sipr: socket error: {kind:?}; stopping");
                    self.fail_all("socket error");
                    break;
                }
                Ok(Event::CallTimer {
                    call_id,
                    generation,
                    kind,
                }) => self.on_call_timer(&call_id, generation, kind),
                Ok(Event::PacerTick) => self.on_pacer_tick(),
                Ok(Event::GlobalTimeout) => {
                    eprintln!("sipr: global timeout reached; failing active calls");
                    self.fail_all("global timeout");
                    self.soft_stopping = true;
                    self.control.stop_pacer.store(true, Ordering::Relaxed);
                }
                Ok(Event::Stdin(c)) => match c {
                    'q' => {
                        self.soft_stopping = true;
                        self.control.stop_pacer.store(true, Ordering::Relaxed);
                    }
                    'Q' => {
                        self.fail_all("hard quit");
                        self.hard_stop = true;
                    }
                    // SIPp rate keys: +/- by 1, */÷ by 10.
                    '+' => self.control.set_rate(self.control.rate() + 1.0),
                    '-' => self.control.set_rate((self.control.rate() - 1.0).max(0.0)),
                    '*' => self.control.set_rate(self.control.rate() + 10.0),
                    '/' => self.control.set_rate((self.control.rate() - 10.0).max(0.0)),
                    'p' => self.paused = !self.paused,
                    _ => {}
                },
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if last_line.elapsed() >= Duration::from_secs(1) {
                last_line = Instant::now();
                if self.config.periodic_stats {
                    eprintln!("sipr: {}", self.stats.line(self.calls.len()));
                }
                self.publish_snapshot();
            }
            if self.trace_stat.is_some() && last_stat_dump.elapsed() >= self.config.stat_interval {
                last_stat_dump = Instant::now();
                let row = self.stats.csv_row(self.calls.len());
                if let Some(f) = self.trace_stat.as_mut() {
                    f.write(&row);
                    f.flush();
                }
            }
        }
        self.control.stop_pacer.store(true, Ordering::Relaxed);
        // Final CSV row + flush all trace files.
        if self.trace_stat.is_some() {
            let row = self.stats.csv_row(self.calls.len());
            if let Some(f) = self.trace_stat.as_mut() {
                f.write(&row);
            }
        }
        for f in [
            &mut self.trace_msg,
            &mut self.trace_err,
            &mut self.trace_stat,
        ]
        .into_iter()
        .flatten()
        {
            f.flush();
        }
        RunReport {
            created: self.stats.created(),
            successful: self.stats.successful,
            failed: self.stats.failed(),
            messages_sent: self.stats.messages_sent,
            messages_matched: self.stats.messages_matched,
            retrans_sent: self.stats.retrans_sent,
            retrans_recv: self.stats.retrans_recv,
            unexpected: self.stats.unexpected,
            garbage: self.stats.garbage,
            elapsed: started.elapsed(),
        }
    }

    fn publish_snapshot(&mut self) {
        let Some(tx) = self.snapshot_tx.as_ref() else {
            return;
        };
        let mut snap = sipr_stats::Snapshot {
            scenario: self.scenario.name.clone(),
            uas: self.scenario.role == Role::Uas,
            rate_target: self.control.rate(),
            paused: self.paused,
            ..Default::default()
        };
        self.stats.fill_snapshot(&mut snap, self.calls.len());
        let now = Instant::now();
        let (last_at, last_created) = self.last_snapshot;
        #[allow(clippy::cast_precision_loss)]
        {
            snap.rate_period = (self.stats.created() - last_created) as f64
                / now.duration_since(last_at).as_secs_f64().max(1e-9);
        }
        self.last_snapshot = (now, self.stats.created());
        let _ = tx.send(snap); // UI gone → ignored; run continues headless
    }

    fn done_creating(&self) -> bool {
        self.soft_stopping
            || self
                .config
                .max_calls
                .is_some_and(|m| self.stats.created() >= m)
    }

    // ---- pacing --------------------------------------------------------

    fn on_pacer_tick(&mut self) {
        if self.scenario.role == Role::Uas || self.paused || self.done_creating() {
            return;
        }
        self.pacer_carry += self.control.rate() * self.tick_ratio;
        // Non-queuing cap: what cannot start this period is forgotten, not
        // deferred (SIPp -l semantics; SIPP_COMPAT §6).
        let mut budget = self.pacer_carry.floor();
        self.pacer_carry -= budget;
        while budget >= 1.0 {
            budget -= 1.0;
            if self.done_creating() {
                return;
            }
            #[allow(clippy::cast_possible_truncation)]
            let live = self.calls.len() as u64;
            if self.config.limit.is_some_and(|l| live >= l) {
                self.pacer_carry = 0.0;
                return;
            }
            self.start_call();
        }
    }

    fn start_call(&mut self) {
        let Some(target) = self.config.target else {
            return; // unreachable: validated in run_with_control
        };
        self.stats.outgoing_created += 1;
        let number = self.stats.created();
        let call_id = self.make_call_id(number);
        let cnonce = self.make_cnonce(number);
        let field_lines = self.assign_field_lines();
        self.calls.insert(
            call_id.clone(),
            new_call(
                number,
                target,
                self.config.base_cseq,
                &self.scenario.vars,
                cnonce,
                field_lines,
            ),
        );
        self.advance(&call_id);
    }

    fn make_call_id(&self, number: u64) -> String {
        match &self.config.call_id_format {
            Some(fmt) => fmt
                .replace("%u", &number.to_string())
                .replace("%p", &self.pid.to_string())
                .replace("%s", &self.local_ip_str),
            None => format!("{number}-{}@{}", self.pid, self.local_ip_str),
        }
    }

    /// Choose this call's line in each injection file, per its mode.
    fn assign_field_lines(&mut self) -> Vec<Option<usize>> {
        let mut out = Vec::with_capacity(self.inf_files.len());
        for (i, cell) in self.inf_files.iter().enumerate() {
            let file = cell.borrow();
            let n = file.len();
            let line = match file.mode {
                _ if n == 0 => None,
                InjectMode::Sequential => {
                    let l = self.inf_seq[i] % n;
                    self.inf_seq[i] = self.inf_seq[i].wrapping_add(1);
                    Some(l)
                }
                InjectMode::Random =>
                {
                    #[allow(clippy::cast_possible_truncation)]
                    Some((self.rng.next_u64() % n as u64) as usize)
                }
                InjectMode::User => None, // needs -users
            };
            out.push(line);
        }
        out
    }

    /// Deterministic-but-unique client nonce for digest auth.
    fn make_cnonce(&self, number: u64) -> String {
        format!(
            "{:016x}",
            (u64::from(self.pid) << 32) ^ number ^ self.config.seed
        )
    }

    // ---- step execution ------------------------------------------------

    #[allow(clippy::too_many_lines)]
    fn advance(&mut self, call_id: &str) {
        loop {
            let Some(call) = self.calls.get(call_id) else {
                return;
            };
            let index = call.index;
            let Some(step) = self.scenario.steps.get(index) else {
                self.complete_call(call_id);
                return;
            };
            // condexec: run this step only if the variable's set-ness matches.
            if let Some(common) = step_common(step) {
                if let Some(v) = common.condexec {
                    let set = self.calls.get(call_id).is_some_and(|c| c.store.is_set(v));
                    if set == common.condexec_inverse {
                        if let Some(call) = self.calls.get_mut(call_id) {
                            call.index = index + 1;
                        }
                        continue;
                    }
                }
            }
            match step {
                Step::Send(send) => {
                    let first = template_first_word(&send.template).unwrap_or_default();
                    let is_req = first != "SIP/2.0";
                    let method_is_new_txn = is_req && first != "ACK" && first != "CANCEL";
                    let (buf, remote) = {
                        let Some(call) = self.calls.get(call_id) else {
                            return;
                        };
                        let remote_ip = call.remote.ip().to_string();
                        let digest_uri = format!(
                            "sip:{}@{}:{}",
                            self.config.service,
                            remote_ip,
                            call.remote.port()
                        );
                        let var_ctx = crate::render::VarCtx {
                            store: &call.store,
                            vars: &self.scenario.vars,
                            challenge: call.challenge.as_ref(),
                            auth_user: self.config.auth_user.as_deref().unwrap_or(""),
                            auth_password: self.config.auth_password.as_deref().unwrap_or(""),
                            cnonce: &call.cnonce,
                            method: if is_req { &first } else { "REGISTER" },
                            digest_uri: &digest_uri,
                        };
                        let ctx = RenderCtx {
                            service: &self.config.service,
                            remote_ip: &remote_ip,
                            remote_port: call.remote.port(),
                            local_ip: &self.local_ip_str,
                            local_port: self.transport.local_addr().port(),
                            transport: self.transport_token,
                            call_id,
                            call_number: call.number,
                            pid: self.pid,
                            cseq: call.cseq,
                            msg_index: index,
                            peer_tag: call.peer_tag.as_deref(),
                            routes: &call.routes,
                            last: call.last_recv.as_ref(),
                            var_ctx: Some(var_ctx),
                            fields: crate::render::FieldSource {
                                files: &self.inf_files,
                                lines: &call.field_lines,
                            },
                        };
                        match render(&send.template, &ctx) {
                            Ok(buf) => (buf, call.remote),
                            Err(e) => {
                                self.fail_call(call_id, &format!("render failed: {e}"));
                                return;
                            }
                        }
                    };
                    // Run this send's actions (rare, but SIPp allows them).
                    if !send.actions.is_empty()
                        && self.run_step_actions(call_id, &send.actions, index)
                    {
                        return;
                    }
                    let _ = self
                        .transport
                        .send_to(&buf, remote, send.lost_pct)
                        .unwrap_or(false); // simulated drops still count as "sent"
                    self.stats.messages_sent += 1;
                    if let Some(s) = self.stats.step_mut(index) {
                        s.sent += 1;
                    }
                    self.trace_send(&buf, remote);
                    let retrans_ms = send.retrans_ms;
                    let lost_pct = send.lost_pct;
                    let jump = self.jump_target(&send.common, index, call_id);
                    let now = Instant::now();
                    let common = send.common.clone();
                    let Some(call) = self.calls.get_mut(call_id) else {
                        return;
                    };
                    apply_rtds(call, &mut self.stats, &common, now);
                    if method_is_new_txn {
                        call.cseq = call.cseq.wrapping_add(1);
                    }
                    call.last_sent = Some(buf.clone());
                    // Replace any pending retransmission with this send's.
                    if let Some(old) = call.retrans.take() {
                        self.timers.cancel(old.timer);
                    }
                    // Reliable transports (TCP/TLS) carry no SIP-layer
                    // retransmissions (RFC 3261 §18.2).
                    if let Some(base) = retrans_ms.filter(|_| !self.reliable) {
                        let schedule = RetransSchedule::new(
                            Some(base),
                            self.config.max_retrans,
                            self.config.no_retrans,
                        );
                        if let Some(interval) = schedule.interval(1) {
                            call.generation += 1;
                            let timer = self.timers.arm(
                                interval,
                                Event::CallTimer {
                                    call_id: call_id.to_owned(),
                                    generation: call.generation,
                                    kind: TimerKind::Retrans,
                                },
                            );
                            call.retrans = Some(RetransCtx {
                                buf,
                                lost_pct,
                                msg_index: index,
                                attempt: 1,
                                schedule,
                                timer,
                            });
                        }
                    }
                    call.index = jump;
                }
                Step::Recv(_) => {
                    let mandatory = self.window_mandatory(index);
                    let Some(call) = self.calls.get_mut(call_id) else {
                        return;
                    };
                    call.waiting = true;
                    if let Some((mi, timeout)) = mandatory {
                        let _ = mi;
                        if let Some(ms) = timeout {
                            call.generation += 1;
                            let timer = self.timers.arm(
                                Duration::from_millis(ms),
                                Event::CallTimer {
                                    call_id: call_id.to_owned(),
                                    generation: call.generation,
                                    kind: TimerKind::RecvTimeout,
                                },
                            );
                            call.timer = Some((timer, TimerKind::RecvTimeout));
                        }
                    }
                    return;
                }
                Step::Pause { spec, common } => {
                    let dur = self.sample_pause(spec, call_id);
                    let jump = self.jump_target(common, index, call_id);
                    let Some(call) = self.calls.get_mut(call_id) else {
                        return;
                    };
                    call.generation += 1;
                    call.index = jump; // applied when the timer fires
                    let timer = self.timers.arm(
                        dur,
                        Event::CallTimer {
                            call_id: call_id.to_owned(),
                            generation: call.generation,
                            kind: TimerKind::Pause,
                        },
                    );
                    call.timer = Some((timer, TimerKind::Pause));
                    return;
                }
                Step::Nop { common, actions } => {
                    if !actions.is_empty() && self.run_step_actions(call_id, actions, index) {
                        return;
                    }
                    // A jump action may have moved us; only advance if not.
                    let moved = self.calls.get(call_id).is_some_and(|c| c.index != index);
                    if !moved {
                        let jump = self.jump_target(common, index, call_id);
                        if let Some(call) = self.calls.get_mut(call_id) {
                            call.index = jump;
                        }
                    }
                }
                Step::Label { .. } => {
                    if let Some(call) = self.calls.get_mut(call_id) {
                        call.index = index + 1;
                    }
                }
                Step::Timewait { ms, .. } => {
                    let Some(call) = self.calls.get_mut(call_id) else {
                        return;
                    };
                    call.generation += 1;
                    call.completing = true;
                    call.index = index + 1;
                    let timer = self.timers.arm(
                        Duration::from_millis(*ms),
                        Event::CallTimer {
                            call_id: call_id.to_owned(),
                            generation: call.generation,
                            kind: TimerKind::Timewait,
                        },
                    );
                    call.timer = Some((timer, TimerKind::Timewait));
                    return;
                }
            }
        }
    }

    /// Where execution goes after `index` finishes: `next` (with `chance`),
    /// else the following step.
    fn jump_target(&mut self, common: &StepCommon, index: usize, call_id: &str) -> usize {
        // A named counter ticks when its step executes.
        if let Some(name) = &common.counter {
            if let Some(call) = self.calls.get_mut(call_id) {
                *call.counters.entry(name.clone()).or_insert(0) += 1;
            }
        }
        if let Some(dest) = common.next {
            let test_ok = match common.test {
                Some(v) => self
                    .calls
                    .get(call_id)
                    .is_some_and(|c| test_truthy(c.store.get(v))),
                None => true,
            };
            let chance_ok = common.chance.is_none_or(|c| self.rng.next_f64() < c);
            if test_ok && chance_ok {
                return dest;
            }
        }
        index + 1
    }

    /// The window's mandatory recv step (index, timeout), scanning from
    /// `start` over optional recvs and labels.
    fn window_mandatory(&self, start: usize) -> Option<(usize, Option<u64>)> {
        let mut i = start;
        while let Some(step) = self.scenario.steps.get(i) {
            match step {
                Step::Recv(r) if r.optional => i += 1,
                Step::Recv(r) => return Some((i, r.timeout_ms)),
                Step::Label { .. } => i += 1,
                _ => return None,
            }
        }
        None
    }

    fn sample_pause(&mut self, spec: &PauseSpec, call_id: &str) -> Duration {
        match spec {
            PauseSpec::Default => self.config.pause_default,
            PauseSpec::Fixed(ms) => Duration::from_millis(*ms),
            PauseSpec::Variable(v) => {
                let ms = self
                    .calls
                    .get(call_id)
                    .map_or(0.0, |c| c.store.get(*v).as_num());
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Duration::from_millis(ms.max(0.0) as u64)
            }
            PauseSpec::Distribution { kind, params } => {
                let u = self.rng.next_f64();
                let ms = match (kind.as_str(), params.as_slice()) {
                    ("uniform", [a, b]) => u.mul_add(b - a, *a),
                    ("fixed", [v]) => *v,
                    ("exponential", [mean]) => -mean * (1.0 - u).ln(),
                    ("normal", [mean, stddev]) => {
                        // Box-Muller (one sample is fine here).
                        let v = self.rng.next_f64().max(f64::MIN_POSITIVE);
                        let z = (-2.0 * v.ln()).sqrt() * (2.0 * std::f64::consts::PI * u).cos();
                        z.mul_add(*stddev, *mean)
                    }
                    _ => 0.0, // pre-validated out
                };
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Duration::from_millis(ms.max(0.0) as u64)
            }
        }
    }

    // ---- inbound -------------------------------------------------------

    fn on_packet(&mut self, packet: &sipr_net::InboundPacket) {
        let msg = &packet.message;
        self.trace_recv(packet);
        let Some(call_id) = msg.call_id().map(ToOwned::to_owned) else {
            self.stats.unexpected += 1;
            return;
        };
        // Inbound retransmission dedupe (branch + CSeq + start line). SIPp
        // answers a retransmitted request by re-sending the last response.
        let key = (
            msg.top_via_branch().unwrap_or_default().to_owned(),
            msg.header("CSeq").unwrap_or_default().to_owned(),
            msg.status_code().map_or_else(
                || msg.method().unwrap_or_default().to_owned(),
                |c| c.to_string(),
            ),
        );
        if !self.calls.contains_key(&call_id) {
            // UAS: an unknown Call-ID carrying the scenario's initial request
            // creates a new call.
            if self.scenario.role == Role::Uas
                && msg.method().is_some()
                && matches!(
                    scan_for_match(self.scenario, &self.expected_cseq_method, 0, true, msg),
                    Scan::Forward(_)
                )
            {
                self.stats.incoming_created += 1;
                let number = self.stats.created();
                let cnonce = self.make_cnonce(number);
                let field_lines = self.assign_field_lines();
                self.calls.insert(
                    call_id.clone(),
                    new_call(
                        number,
                        packet.from,
                        self.config.base_cseq,
                        &self.scenario.vars,
                        cnonce,
                        field_lines,
                    ),
                );
                // Fall through to normal matching below (window at 0).
            } else {
                self.stats.unexpected += 1;
                self.log_err(&format!("out-of-call message ignored (Call-ID {call_id})"));
                return;
            }
        }
        let (window_start, waiting, completing, is_dup) = match self.calls.get(&call_id) {
            Some(c) => (
                c.index,
                c.waiting,
                c.completing,
                c.last_recv_key.as_ref() == Some(&key),
            ),
            None => return,
        };
        if is_dup {
            self.stats.retrans_recv += 1;
            // Re-send our last message (SIPp: retransmitted request → last
            // response again; harmless for a duplicated response).
            let resend = self
                .calls
                .get(&call_id)
                .and_then(|c| c.last_sent.clone().map(|b| (b, c.remote)));
            if let Some((buf, remote)) = resend {
                let _ = self.transport.send_to(&buf, remote, None);
                self.stats.retrans_sent += 1;
                self.trace_send(&buf, remote);
            }
            return;
        }
        if completing {
            // Timewait: absorb without failing (deadcall behavior).
            self.stats.unexpected += 1;
            return;
        }
        let scan = scan_for_match(
            self.scenario,
            &self.expected_cseq_method,
            window_start,
            waiting || window_start == 0,
            msg,
        );
        match scan {
            Scan::Forward(si) => self.on_matched(&call_id, si, msg, key),
            Scan::Old => {
                // Late/repeated optional (e.g. another 180): absorbed.
                self.stats.messages_matched += 1;
                if let Some(call) = self.calls.get_mut(&call_id) {
                    call.last_recv_key = Some(key);
                }
            }
            Scan::NoMatch => {
                if self.try_auto_answer(&call_id, msg) {
                    return;
                }
                self.stats.unexpected += 1;
                if let Some(s) = self.stats.step_mut(window_start) {
                    s.unexpected += 1;
                }
                let what = msg
                    .method()
                    .map_or_else(|| format!("{:?}", msg.status_code()), ToOwned::to_owned);
                self.log_err(&format!(
                    "unexpected {what} for call {call_id}; call failed"
                ));
                self.stats.failed_unexpected += 1;
                self.remove_call(&call_id);
            }
        }
    }

    /// Common handling for a message matched at step `si`.
    fn on_matched(
        &mut self,
        call_id: &str,
        si: usize,
        msg: &Inbound,
        key: (String, String, String),
    ) {
        self.stats.messages_matched += 1;
        if let Some(s) = self.stats.step_mut(si) {
            s.recv += 1;
        }
        let (rrs, common) = match &self.scenario.steps[si] {
            Step::Recv(r) => (r.record_route_set, r.common.clone()),
            _ => (false, StepCommon::default()),
        };
        let now = Instant::now();
        let Some(call) = self.calls.get_mut(call_id) else {
            return;
        };
        // A matched recv cancels the pending retransmission
        // (call.cpp: next_retrans = 0) and the window timeout.
        if let Some(r) = call.retrans.take() {
            self.timers.cancel(r.timer);
        }
        if let Some((t, _)) = call.timer.take() {
            self.timers.cancel(t);
        }
        call.generation += 1;
        if let Some(tag) = if msg.status_code().is_some() {
            msg.to_tag()
        } else {
            msg.from_tag()
        } {
            call.peer_tag = Some(tag.to_owned());
        }
        if rrs {
            call.routes = msg
                .header_values("Record-Route")
                .into_iter()
                .map(ToOwned::to_owned)
                .collect();
        }
        apply_rtds(call, &mut self.stats, &common, now);
        call.last_recv_key = Some(key);
        call.last_recv = Some(msg.clone());
        call.waiting = false;
        call.index = si + 1;
        // Capture a digest challenge when this recv has auth="true".
        let auth = matches!(&self.scenario.steps[si], Step::Recv(r) if r.auth);
        if auth {
            let challenge = msg
                .header("WWW-Authenticate")
                .and_then(|h| sipr_auth::parse_challenge(h, false))
                .or_else(|| {
                    msg.header("Proxy-Authenticate")
                        .and_then(|h| sipr_auth::parse_challenge(h, true))
                });
            if let Some(call) = self.calls.get_mut(call_id) {
                call.challenge = challenge;
            }
        }
        // Run the recv step's actions (ereg captures, etc.).
        let recv_actions = match &self.scenario.steps[si] {
            Step::Recv(r) => r.actions.clone(),
            _ => Vec::new(),
        };
        if !recv_actions.is_empty() && self.run_step_actions(call_id, &recv_actions, si) {
            return;
        }
        self.advance(call_id);
    }

    /// Execute a step's actions against the call's store. Returns true when a
    /// terminal outcome (fail/stop) removed the call or ended the run — the
    /// caller must stop touching this call.
    fn run_step_actions(&mut self, call_id: &str, actions: &[Action], index: usize) -> bool {
        let Some(call) = self.calls.get(call_id) else {
            return true;
        };
        let remote_ip = call.remote.ip().to_string();
        let digest_uri = format!(
            "sip:{}@{}:{}",
            self.config.service,
            remote_ip,
            call.remote.port()
        );
        let mut store = call.store.clone();
        let snapshot = call.store.clone(); // immutable copy for the base ctx
        let last = call.last_recv.clone();
        let outcomes = {
            let var_ctx = crate::render::VarCtx {
                store: &snapshot,
                vars: &self.scenario.vars,
                challenge: call.challenge.as_ref(),
                auth_user: self.config.auth_user.as_deref().unwrap_or(""),
                auth_password: self.config.auth_password.as_deref().unwrap_or(""),
                cnonce: &call.cnonce,
                method: "REGISTER",
                digest_uri: &digest_uri,
            };
            let ctx = RenderCtx {
                service: &self.config.service,
                remote_ip: &remote_ip,
                remote_port: call.remote.port(),
                local_ip: &self.local_ip_str,
                local_port: self.transport.local_addr().port(),
                transport: self.transport_token,
                call_id,
                call_number: call.number,
                pid: self.pid,
                cseq: call.cseq,
                msg_index: index,
                peer_tag: call.peer_tag.as_deref(),
                routes: &call.routes,
                last: last.as_ref(),
                var_ctx: Some(var_ctx),
                fields: crate::render::FieldSource {
                    files: &self.inf_files,
                    lines: &call.field_lines,
                },
            };
            crate::actions::run_actions(actions, &mut store, last.as_ref(), &ctx)
        };
        // Persist the mutated store.
        if let Some(call) = self.calls.get_mut(call_id) {
            call.store = store;
        }
        for outcome in outcomes {
            match outcome {
                crate::actions::ActionOutcome::Continue => {}
                crate::actions::ActionOutcome::Log(line) => self.log_err(&line),
                crate::actions::ActionOutcome::Jump(dest) => {
                    if let Some(call) = self.calls.get_mut(call_id) {
                        call.index = dest;
                    }
                    self.advance(call_id);
                    return true;
                }
                crate::actions::ActionOutcome::FailCall(why) => {
                    self.stats.failed_other += 1;
                    self.log_err(&format!("call {call_id} failed: {why}"));
                    self.remove_call(call_id);
                    return true;
                }
                crate::actions::ActionOutcome::StopGracefully => {
                    self.soft_stopping = true;
                    self.control.stop_pacer.store(true, Ordering::Relaxed);
                }
                crate::actions::ActionOutcome::StopNow => {
                    self.fail_all("exec stop_now");
                    self.hard_stop = true;
                    return true;
                }
            }
        }
        false
    }

    /// `-aa`: answer in-dialog OPTIONS/INFO/UPDATE/NOTIFY with 200 without
    /// disturbing the scenario. Returns true when handled.
    fn try_auto_answer(&mut self, call_id: &str, msg: &Inbound) -> bool {
        if !self.config.auto_answer {
            return false;
        }
        let Some(method) = msg.method() else {
            return false;
        };
        if !matches!(method, "OPTIONS" | "INFO" | "UPDATE" | "NOTIFY") {
            return false;
        }
        let Some(remote) = self.calls.get(call_id).map(|c| c.remote) else {
            return false;
        };
        let mut out = String::from("SIP/2.0 200 OK\r\n");
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            for line in msg.header_lines(name) {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
        out.push_str("Content-Length: 0\r\n\r\n");
        let buf = out.into_bytes();
        let _ = self.transport.send_to(&buf, remote, None);
        self.stats.auto_answered += 1;
        self.trace_send(&buf, remote);
        true
    }

    fn trace_send(&mut self, buf: &[u8], remote: SocketAddr) {
        if let Some(f) = self.trace_msg.as_mut() {
            f.write(&sipr_stats::frame_message(
                "UDP message sent to",
                &remote.to_string(),
                self.stats.started.elapsed(),
                buf,
            ));
        }
    }

    fn trace_recv(&mut self, packet: &sipr_net::InboundPacket) {
        if self.trace_msg.is_some() {
            let framed = sipr_stats::frame_message(
                "UDP message received from",
                &packet.from.to_string(),
                self.stats.started.elapsed(),
                &packet.raw,
            );
            if let Some(f) = self.trace_msg.as_mut() {
                f.write(&framed);
            }
        }
    }

    fn log_err(&mut self, line: &str) {
        if let Some(f) = self.trace_err.as_mut() {
            f.write(&format!("{line}\n"));
        }
    }

    // ---- timers --------------------------------------------------------

    fn on_call_timer(&mut self, call_id: &str, generation: u64, kind: TimerKind) {
        if kind == TimerKind::Retrans {
            self.on_retrans_timer(call_id, generation);
            return;
        }
        let index = match self.calls.get_mut(call_id) {
            Some(call) if call.generation == generation => {
                call.timer = None;
                call.index
            }
            _ => return, // gone or stale
        };
        match kind {
            TimerKind::RecvTimeout => {
                let mandatory = self.window_mandatory(index);
                if let Some((mi, _)) = mandatory {
                    if let Some(s) = self.stats.step_mut(mi) {
                        s.timeouts += 1;
                    }
                }
                let ontimeout = mandatory.and_then(|(mi, _)| match &self.scenario.steps[mi] {
                    Step::Recv(RecvStep { ontimeout, .. }) => *ontimeout,
                    _ => None,
                });
                match ontimeout {
                    Some(dest) => {
                        if let Some(call) = self.calls.get_mut(call_id) {
                            call.waiting = false;
                            call.index = dest;
                        }
                        self.advance(call_id);
                    }
                    None => self.fail_call(call_id, "recv timeout"),
                }
            }
            TimerKind::Pause => self.advance(call_id),
            TimerKind::Timewait => self.complete_call(call_id),
            TimerKind::Retrans => unreachable!("handled above"),
        }
    }

    fn on_retrans_timer(&mut self, call_id: &str, generation: u64) {
        let Some((buf, lost, next, msg_index)) = self.calls.get_mut(call_id).and_then(|call| {
            let r = call.retrans.as_mut()?;
            r.attempt += 1;
            Some((
                r.buf.clone(),
                r.lost_pct,
                r.schedule.interval(r.attempt),
                r.msg_index,
            ))
        }) else {
            return; // call gone or retransmission already cancelled
        };
        if let Some(s) = self.stats.step_mut(msg_index) {
            s.retrans += 1;
        }
        let Some(remote) = self.calls.get(call_id).map(|c| c.remote) else {
            return;
        };
        let _ = self.transport.send_to(&buf, remote, lost);
        self.stats.retrans_sent += 1;
        self.trace_send(&buf, remote);
        match next {
            Some(interval) => {
                let timer = self.timers.arm(
                    interval,
                    Event::CallTimer {
                        call_id: call_id.to_owned(),
                        generation,
                        kind: TimerKind::Retrans,
                    },
                );
                if let Some(r) = self.calls.get_mut(call_id).and_then(|c| c.retrans.as_mut()) {
                    r.timer = timer;
                }
            }
            None => self.fail_call(call_id, "retransmissions exhausted"),
        }
    }

    // ---- lifecycle -----------------------------------------------------

    fn cancel_call_timers(&mut self, call: &mut CallState) {
        if let Some(r) = call.retrans.take() {
            self.timers.cancel(r.timer);
        }
        if let Some((t, _)) = call.timer.take() {
            self.timers.cancel(t);
        }
        call.generation += 1;
    }

    fn complete_call(&mut self, call_id: &str) {
        if let Some(mut call) = self.calls.remove(call_id) {
            self.cancel_call_timers(&mut call);
            self.stats.successful += 1;
            self.stats.record_call_length(call.started.elapsed());
        }
    }

    /// Remove a call and record its duration WITHOUT bumping a failure
    /// counter — the caller has already categorized the failure.
    fn remove_call(&mut self, call_id: &str) {
        if let Some(mut call) = self.calls.remove(call_id) {
            self.cancel_call_timers(&mut call);
            self.stats.record_call_length(call.started.elapsed());
        }
    }

    fn fail_call(&mut self, call_id: &str, reason: &str) {
        if self.calls.contains_key(call_id) {
            match reason {
                r if r.contains("retransmissions") => self.stats.failed_retrans += 1,
                r if r.contains("timeout") => self.stats.failed_timeout += 1,
                _ => self.stats.failed_other += 1,
            }
            self.log_err(&format!("call {call_id} failed: {reason}"));
            self.remove_call(call_id);
        }
    }

    fn fail_all(&mut self, reason: &str) {
        let ids: Vec<String> = self.calls.keys().cloned().collect();
        for id in ids {
            self.fail_call(&id, reason);
        }
    }
}

/// The shared attributes of a step, when it has any.
fn step_common(step: &Step) -> Option<&StepCommon> {
    match step {
        Step::Send(s) => Some(&s.common),
        Step::Recv(r) => Some(&r.common),
        Step::Pause { common, .. } | Step::Nop { common, .. } => Some(common),
        Step::Label { .. } | Step::Timewait { .. } => None,
    }
}

/// SIPp `test`/`condexec` truthiness: a variable counts as true when it is
/// set and not numerically zero / boolean false.
fn test_truthy(v: &crate::actions::Value) -> bool {
    use crate::actions::Value;
    match v {
        Value::Unset => false,
        Value::Bool(b) => *b,
        Value::Num(n) => *n != 0.0,
        Value::Str(s) => !s.is_empty() && s != "0" && !s.eq_ignore_ascii_case("false"),
    }
}

/// Short display label for a step (scenario screen rows).
fn step_label(step: &Step) -> String {
    match step {
        Step::Send(s) => {
            let what = template_first_word(&s.template).unwrap_or_default();
            if what == "SIP/2.0" {
                // Response send: show the status code from the template.
                let code = s.template.spans.first().map_or(String::new(), |sp| {
                    if let Span::Lit(l) = sp {
                        l.split_whitespace().nth(1).unwrap_or("").to_owned()
                    } else {
                        String::new()
                    }
                });
                format!("send {code}")
            } else {
                format!("send {what}")
            }
        }
        Step::Recv(r) => {
            let what = match &r.expect {
                Expect::Response(c) => c.clone(),
                Expect::Request(m) => m.clone(),
            };
            if r.optional {
                format!("recv {what} (opt)")
            } else {
                format!("recv {what}")
            }
        }
        Step::Pause { .. } => "pause".to_owned(),
        Step::Nop { .. } => "nop".to_owned(),
        Step::Label { id, .. } => format!("label {id}"),
        Step::Timewait { ms, .. } => format!("timewait {ms}ms"),
    }
}

/// Fresh call state.
fn new_call(
    number: u64,
    remote: SocketAddr,
    base_cseq: u32,
    vars: &sipr_scenario::model::VarTable,
    cnonce: String,
    field_lines: Vec<Option<usize>>,
) -> CallState {
    CallState {
        number,
        remote,
        index: 0,
        waiting: false,
        completing: false,
        started: Instant::now(),
        cseq: base_cseq,
        last_sent: None,
        rtd_starts: Vec::new(),
        field_lines,
        store: crate::actions::VarStore::new(vars),
        counters: std::collections::HashMap::new(),
        cnonce,
        challenge: None,
        peer_tag: None,
        routes: Vec::new(),
        last_recv: None,
        last_recv_key: None,
        retrans: None,
        timer: None,
        generation: 0,
    }
}

/// Apply a step's RTD attributes: start stopwatches, stop them into the
/// histograms, restart when `repeat_rtd`. Free function to keep borrows of
/// the call and the stats disjoint.
fn apply_rtds(
    call: &mut CallState,
    stats: &mut sipr_stats::StatSet,
    common: &StepCommon,
    now: Instant,
) {
    if let Some(name) = &common.start_rtd {
        match call.rtd_starts.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = now,
            None => call.rtd_starts.push((name.clone(), now)),
        }
    }
    if let Some(name) = &common.rtd {
        if let Some(pos) = call.rtd_starts.iter().position(|(n, _)| n == name) {
            let (_, started) = call.rtd_starts[pos];
            stats.record_rtd(name, now.saturating_duration_since(started));
            if common.repeat_rtd {
                call.rtd_starts[pos].1 = now;
            } else {
                call.rtd_starts.swap_remove(pos);
            }
        }
    }
}

enum Scan {
    /// Matched at this forward step index.
    Forward(usize),
    /// Matched an already-passed optional (contiguous block behind us).
    Old,
    NoMatch,
}

/// SIPp's recv window scan, as verified in call.cpp (SIPP_COMPAT §6).
fn scan_for_match(
    scenario: &Scenario,
    expected_cseq_method: &[Option<String>],
    window_start: usize,
    waiting: bool,
    msg: &Inbound,
) -> Scan {
    // Forward: optionals may be skipped; stop at first mandatory recv
    // (inclusive) or any non-recv step.
    if waiting {
        let mut i = window_start;
        while let Some(step) = scenario.steps.get(i) {
            match step {
                Step::Label { .. } => {
                    i += 1;
                }
                Step::Recv(r) => {
                    if recv_matches(r, expected_cseq_method.get(i), i, msg) {
                        return Scan::Forward(i);
                    }
                    if r.optional {
                        i += 1;
                        continue;
                    }
                    break;
                }
                _ => break,
            }
        }
    }
    // Backward: contiguous optional block behind the window may re-match
    // (late 180 after the 200 advanced us, a repeated provisional...).
    let mut i = window_start;
    let mut contig = true;
    while i > 0 {
        i -= 1;
        match scenario.steps.get(i) {
            Some(Step::Label { .. }) => {}
            Some(Step::Recv(r)) => {
                if !r.optional {
                    contig = false;
                }
                if contig && recv_matches(r, expected_cseq_method.get(i), i, msg) {
                    return Scan::Old;
                }
            }
            _ => contig = false,
        }
        if !contig {
            break;
        }
    }
    Scan::NoMatch
}

fn recv_matches(
    step: &RecvStep,
    expected_method: Option<&Option<String>>,
    index: usize,
    msg: &Inbound,
) -> bool {
    match &step.expect {
        Expect::Request(m) => msg.method() == Some(m.as_str()),
        Expect::Response(code) => {
            let Some(actual) = msg.status_code() else {
                return false;
            };
            if code.parse::<u16>() != Ok(actual) {
                return false;
            }
            // SIPp guard: beyond index 0, the response's CSeq method must
            // match the nearest preceding request (call.cpp
            // recv_response_for_cseq_method_list).
            if index == 0 {
                return true;
            }
            match expected_method.and_then(Option::as_deref) {
                Some(expected) => msg.cseq().is_some_and(|(_, m)| m == expected),
                None => true,
            }
        }
    }
}

/// For every step, the method of the nearest preceding request `<send>`.
fn precompute_cseq_methods(scenario: &Scenario) -> Vec<Option<String>> {
    let mut out = Vec::with_capacity(scenario.steps.len());
    let mut last: Option<String> = None;
    for step in &scenario.steps {
        if let Step::Send(s) = step {
            if let Some(word) = template_first_word(&s.template) {
                if word != "SIP/2.0" {
                    last = Some(word);
                }
            }
        }
        out.push(last.clone());
    }
    out
}

/// First whitespace-delimited token of a template (the method or SIP/2.0).
fn template_first_word(t: &MsgTemplate) -> Option<String> {
    match t.spans.first()? {
        Span::Lit(l) => l.split_whitespace().next().map(ToOwned::to_owned),
        Span::Kw(Keyword::Last(_) | Keyword::Var(_)) | Span::Kw(_) => None,
    }
}

/// Reject scenarios that need features beyond M3, loudly and up front.
fn validate_for_engine(scenario: &Scenario) -> Result<(), EngineError> {
    // As of M6 the engine executes the full v1 surface; the only things left
    // to reject are pause distributions the sampler does not implement.
    // (regexp_match responses now compile to a real matcher.)
    for (i, step) in scenario.steps.iter().enumerate() {
        if let Step::Pause {
            spec: PauseSpec::Distribution { kind, .. },
            ..
        } = step
        {
            if !matches!(
                kind.as_str(),
                "uniform" | "fixed" | "exponential" | "normal"
            ) {
                return Err(EngineError(format!(
                    "step {i}: pause distribution '{kind}' is not implemented yet"
                )));
            }
        }
    }
    Ok(())
}

/// Reject a scenario whose `[fieldN file=…]` names an injection file that was
/// not loaded (SIPp errors at parse time). A bare name or a numeric index both
/// count; `None` (default file) needs at least one `-inf`.
fn validate_field_files(
    scenario: &Scenario,
    files: &[std::cell::RefCell<InjectionFile>],
) -> Result<(), EngineError> {
    let resolves = |spec: Option<&str>| -> bool {
        match spec {
            None => !files.is_empty(),
            Some(s) => {
                files.iter().any(|c| c.borrow().name == s)
                    || s.parse::<usize>().is_ok_and(|i| i < files.len())
            }
        }
    };
    for step in &scenario.steps {
        let Step::Send(send) = step else { continue };
        for kw in send.template.keywords() {
            if let Keyword::Field { file, .. } = kw
                && !resolves(file.as_deref())
            {
                return Err(EngineError(match file {
                    Some(f) => format!(
                        "scenario uses [field... file={f}] but no injection file \
                         named '{f}' was given with -inf"
                    ),
                    None => "scenario uses [fieldN] but no -inf file was given".to_owned(),
                }));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uac() -> Scenario {
        sipr_scenario::compile("uac", sipr_scenario::embedded("uac").unwrap())
            .scenario
            .unwrap()
    }

    fn response(code: u16, cseq_method: &str, to_tag: bool) -> Inbound {
        let tag = if to_tag { ";tag=remote1" } else { "" };
        let raw = format!(
            "SIP/2.0 {code} X\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK-1\r\n\
             From: <sip:a>;tag=t1\r\nTo: <sip:b>{tag}\r\nCall-ID: c1\r\n\
             CSeq: 1 {cseq_method}\r\n\r\n"
        );
        Inbound::parse(raw.as_bytes()).unwrap()
    }

    #[test]
    fn forward_scan_skips_unmatched_optionals() {
        let sc = uac();
        let methods = precompute_cseq_methods(&sc);
        // Window starts at step 1 (recv 100 opt). A 200 must land on step 4.
        assert!(matches!(
            scan_for_match(&sc, &methods, 1, true, &response(200, "INVITE", true)),
            Scan::Forward(4)
        ));
        // A 183 lands on its own optional step 3.
        assert!(matches!(
            scan_for_match(&sc, &methods, 1, true, &response(183, "INVITE", false)),
            Scan::Forward(3)
        ));
    }

    #[test]
    fn cseq_method_guard_blocks_stale_finals() {
        let sc = uac();
        let methods = precompute_cseq_methods(&sc);
        // Window at step 8 (recv 200 after BYE): a late 200 for the INVITE
        // must NOT match forward; it is absorbed... by nothing behind (the
        // steps behind 8 are send/pause), so it is unexpected.
        assert!(matches!(
            scan_for_match(&sc, &methods, 8, true, &response(200, "INVITE", true)),
            Scan::NoMatch
        ));
        // The right 200 (CSeq BYE) matches.
        assert!(matches!(
            scan_for_match(&sc, &methods, 8, true, &response(200, "BYE", true)),
            Scan::Forward(8)
        ));
    }

    #[test]
    fn backward_scan_absorbs_out_of_order_provisionals() {
        let sc = uac();
        let methods = precompute_cseq_methods(&sc);
        // A 183 matched at step 3, so the call is parked at the mandatory
        // 200 (step 4). A distinct out-of-order 180 hits the contiguous
        // optional block behind the window.
        assert!(matches!(
            scan_for_match(&sc, &methods, 4, true, &response(180, "INVITE", false)),
            Scan::Old
        ));
        // Once past the mandatory 200 (ACK sent, window start 5), contig is
        // broken by the mandatory step: a late 180 is unexpected — verified
        // against call.cpp's backward loop (contig dies at OPTIONAL_FALSE).
        assert!(matches!(
            scan_for_match(&sc, &methods, 5, false, &response(180, "INVITE", false)),
            Scan::NoMatch
        ));
        // And a random 486 never matches backward.
        assert!(matches!(
            scan_for_match(&sc, &methods, 4, true, &response(486, "INVITE", false)),
            Scan::NoMatch
        ));
    }

    #[test]
    fn unexpected_request_is_no_match() {
        let sc = uac();
        let methods = precompute_cseq_methods(&sc);
        let bye = Inbound::parse(
            b"BYE sip:x SIP/2.0\r\nCall-ID: c1\r\nCSeq: 2 BYE\r\nFrom: <a>;tag=z\r\n\r\n",
        )
        .unwrap();
        assert!(matches!(
            scan_for_match(&sc, &methods, 1, true, &bye),
            Scan::NoMatch
        ));
    }

    #[test]
    fn precomputed_methods_follow_sends() {
        let sc = uac();
        let m = precompute_cseq_methods(&sc);
        assert_eq!(m[1].as_deref(), Some("INVITE")); // recv 100
        assert_eq!(m[4].as_deref(), Some("INVITE")); // recv 200
        assert_eq!(m[8].as_deref(), Some("BYE")); // final recv 200
    }

    #[test]
    fn validation_accepts_v1_features_including_actions_and_auth() {
        let uas = sipr_scenario::compile("uas", sipr_scenario::embedded("uas").unwrap())
            .scenario
            .unwrap();
        assert!(validate_for_engine(&uas).is_ok(), "UAS runs as of M4");
        let with_actions = sipr_scenario::compile(
            "t",
            r#"<scenario name="t">
                 <send><![CDATA[
                   OPTIONS sip:[service]@[remote_ip] SIP/2.0
                   Call-ID: [call_id]
                   [authentication username=u password=p]

                 ]]></send>
                 <recv response="200">
                   <action><ereg regexp="([0-9]+)" search_in="msg" assign_to="whole,n"/></action>
                 </recv>
               </scenario>"#,
        )
        .scenario
        .unwrap();
        assert!(
            validate_for_engine(&with_actions).is_ok(),
            "actions + [authentication] run as of M6"
        );
        assert!(validate_for_engine(&uac()).is_ok());
        // Still rejected: an unimplemented pause distribution.
        let bad_dist = sipr_scenario::compile(
            "t",
            r#"<scenario name="t">
                 <send><![CDATA[OPTIONS sip:[service]@[remote_ip] SIP/2.0
                   Call-ID: [call_id]
                 ]]></send>
                 <recv response="200"/>
                 <pause distribution="weibull(1,2)"/>
               </scenario>"#,
        )
        .scenario
        .unwrap();
        assert!(validate_for_engine(&bad_dist).is_err());
    }

    #[test]
    fn exit_codes_follow_sipp() {
        let mut r = RunReport::default();
        assert_eq!(r.exit_code(), 99);
        r.successful = 5;
        assert_eq!(r.exit_code(), 0);
        r.failed = 1;
        assert_eq!(r.exit_code(), 1);
    }
}
