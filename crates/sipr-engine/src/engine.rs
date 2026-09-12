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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sipr_control::{ControlCmd, ControlLink, ControlRequest, ControlState, Quitting};
use sipr_media::sdp::CryptoAttr;
use sipr_media::{MediaEvent, MediaPlayer, PcapStream, Source, StreamSpec};
use sipr_net::timer::TimerId;
use sipr_net::{
    Inbound, NetEvent, RetransSchedule, TcpCallConn, TcpTransport, TimerService, TlsCallConn,
    TlsTransport, TransportConfig, TwinChannel, UdpCallSocket, UdpTransport,
};
#[cfg(feature = "sctp")]
use sipr_net::{SctpCallConn, SctpTransport};
use sipr_scenario::inject::{InjectMode, InjectionFile};
use sipr_scenario::model::{
    Action, Expect, MediaKind, PauseSpec, RecvStep, Role, RtpEchoCmd, RtpEchoVerb, RtpSource,
    RtpStreamCmd, Scenario, Step, StepCommon,
};
use sipr_scenario::template::{CryptoKw, Keyword, MsgTemplate, Span};

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
    /// `-max_socket`: per-call socket modes share sockets round-robin past
    /// this many open ones (SIPp default 50000).
    pub max_socket: usize,
    /// `-rsa host[:port]`: send every message there instead of to the target
    /// (UAC) or back to the request's source (UAS); keywords keep rendering
    /// the nominal remote.
    pub remote_sending_addr: Option<SocketAddr>,
    /// `-ip_field`: the field of the first `-inf` file holding the IP a call
    /// uses under `-t ui` (SIPp default 0).
    pub ip_field: usize,
    /// `-max_reconnect`: TCP/TLS reconnections allowed (0 = none, SIPp's
    /// default; -1 = unlimited).
    pub max_reconnect: i64,
    /// `-reconnect_close`: fail the calls on a connection that closed or
    /// reset (SIPp default true).
    pub reconnect_close: bool,
    /// `-reconnect_sleep`: pause before re-dialing (SIPp default 1 s).
    pub reconnect_sleep: Duration,
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
    /// `-auth_uri`: the digest `uri=` after SIPp's `sip:` prefix (default
    /// `remote_ip:remote_port`, as SIPp).
    pub auth_uri: Option<String>,
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
    /// `-3pcc HOST:PORT`: the twin control socket for classic 3PCC. The role
    /// (dial vs listen) is derived from the scenario's first twin command.
    pub twin_addr: Option<SocketAddr>,
    /// `-users N`: closed-loop mode — keep N concurrent calls, each holding a
    /// 1-based user id (drives `[userid]`/`[users]` and USER injection files).
    pub users: Option<usize>,
    /// `-tls_*` options; required when `transport` is [`TransportKind::TlsMono`].
    pub tls: Option<sipr_net::TlsConfig>,
    /// `-mi`: media address for `[media_ip]` and the RTP sockets (default:
    /// the local signaling IP).
    pub media_ip: Option<IpAddr>,
    /// `-mp` / `-min_rtp_port`: base port for `[media_port]` (default 6000).
    pub media_port: Option<u16>,
    /// `-max_rtp_port`: top of the `[rtpstream_*_port]` range (default 65535).
    pub max_rtp_port: Option<u16>,
    /// `-rtp_payload`: default payload type for `rtp_stream` (default 8).
    pub rtp_payload: Option<u8>,
    /// `-random_base_ssrc`: seed the SSRC base randomly (SIPp: `0xCA110000`).
    pub random_base_ssrc: bool,
    /// `-rate_increase`: add this to the rate every `rate_interval`.
    pub rate_increase: Option<f64>,
    /// `-rate_max`: clamp the ramp here; exceeding it quits unless `!rate_quit`.
    pub rate_max: Option<f64>,
    /// `-rate_interval`: ramp period (`None` = `stat_interval`, SIPp's `-fd`).
    pub rate_interval: Option<Duration>,
    /// `-no_rate_quit` unsets this: quit (drain) when `rate_max` is exceeded.
    pub rate_quit: bool,
    /// `-rate_scale`: the step for the rate keys (default 1).
    pub rate_scale: Option<f64>,
    /// `-rtp_echo`: echo RTP received on the media port (+2) back.
    pub rtp_echo: bool,
    /// `-mb`: echo receive buffer size (default 2048).
    pub media_bufsize: Option<usize>,
    /// `-audiotolerance`: judge audio `rtp_stream` echo checks against this
    /// failure ratio; `None` = do not judge (SIPp judges always, default 1.0).
    pub audio_tolerance: Option<f64>,
    /// `-videotolerance`: same for video streams.
    pub video_tolerance: Option<f64>,
    /// Directory of the `-sf` file: pcap paths resolve there first, then in
    /// the working directory (SIPp `find_file`).
    pub scenario_dir: Option<std::path::PathBuf>,
    /// `-cp`: SIPp's UDP control port. `None` probes 8888..8947 (SIPp's
    /// default), `Some(0)` disables the socket (sipr addition).
    pub control_port: Option<u16>,
    /// `-ci`: control socket bind address (default loopback — SIPp binds
    /// every interface).
    pub control_ip: Option<IpAddr>,
    /// `--sipr-http`: HTTP/JSON control API bind address.
    pub http_addr: Option<SocketAddr>,
    /// `--sipr-http-token`: bearer token for the HTTP API (required when
    /// `http_addr` is not loopback).
    pub http_token: Option<String>,
    /// `<scenario>_<pid>`: the stem for trace files opened at runtime by
    /// `trace messages|error on` (SIPp's naming).
    pub trace_name_base: Option<String>,
}

/// SIPp's `DEFAULT_MEDIA_PORT`.
const DEFAULT_MEDIA_PORT: u16 = 6000;
/// SIPp's `rtp_default_payload` (PCMA).
const DEFAULT_RTP_PAYLOAD: u8 = 8;
/// SIPp's initial `play_args_a.last_seq_no` for `play_dtmf`.
const DTMF_FIRST_SEQ: u16 = 1200;

/// Transport selection (`-t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportKind {
    /// `u1`: UDP, one socket shared by all calls (SIPp default).
    #[default]
    UdpMono,
    /// `un`: UDP, one socket per call (client side; a server answers from
    /// the socket the call arrived on, as SIPp does).
    UdpPerCall,
    /// `ui`: UDP, one socket per IP address from the injection file
    /// (`-ip_field`): a client sends each call from its line's IP, a server
    /// binds every listed IP and answers on the one the request hit.
    UdpPerIp,
    /// `t1`: TCP, one connection per peer (client dials, server accepts).
    TcpMono,
    /// `tn`: TCP, one connection per call (client side).
    TcpPerCall,
    /// `l1`: TLS over TCP, same connection-per-peer model.
    TlsMono,
    /// `ln`: TLS, one connection per call (client side).
    TlsPerCall,
    /// `s1`: SCTP, one association per peer (cargo feature `sctp`; needs an
    /// OS SCTP stack at run time).
    SctpMono,
    /// `sn`: SCTP, one association per call (client side).
    SctpPerCall,
}

impl TransportKind {
    /// SIPp's `multisocket`: one socket per call on the client side.
    #[must_use]
    pub fn per_call(self) -> bool {
        matches!(
            self,
            Self::UdpPerCall | Self::TcpPerCall | Self::TlsPerCall | Self::SctpPerCall
        )
    }
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
    /// The run was cut short by a fatal error (exit 255, SIPp's `ERROR`).
    pub fatal: Option<String>,
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
    /// RTP datagrams sent by pcap replays.
    pub rtp_packets_sent: u64,
    /// RTP echo checks that passed their tolerance.
    pub rtp_check_ok: u64,
    /// RTP echo checks that failed their tolerance (SIPp: exit -3).
    pub rtp_check_failed: u64,
    /// Wall-clock duration of the run.
    pub elapsed: Duration,
}

impl RunReport {
    /// SIPp-compatible exit code (docs/SIPP_COMPAT.md §5). A failed RTP
    /// check wins over everything, as in SIPp (`EXIT_RTPCHECK_FAILED` = -3,
    /// which the shell sees as 253).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.fatal.is_some() {
            255
        } else if self.rtp_check_failed > 0 {
            253
        } else if self.failed > 0 {
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
        let mut rtp = if self.rtp_packets_sent > 0 {
            format!(" rtp-sent {}", self.rtp_packets_sent)
        } else {
            String::new()
        };
        let checks = self.rtp_check_ok + self.rtp_check_failed;
        if checks > 0 {
            rtp.push_str(&format!(
                " rtpcheck {}/{checks} failed",
                self.rtp_check_failed
            ));
        }
        format!(
            "created {} successful {} failed {} | sent {} matched {} \
             retrans-sent {} retrans-recv {} unexpected {} garbage {}{rtp} | {:.1?}",
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
    /// A 3PCC command arrived on the twin control channel.
    TwinCmd(String),
    /// The media thread finished or abandoned a replay.
    Media(MediaEvent),
    /// A runtime control command (UDP control socket or HTTP API).
    Control(ControlRequest),
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
    /// Blocked on a `<recvCmd>` waiting for a 3PCC twin command.
    awaiting_cmd: bool,
    /// `-users` mode: this call's 1-based user id (returned to the pool at end).
    user_id: Option<usize>,
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
    /// Remote media endpoints learned from received SDP, by [`MediaKind`]
    /// index. Stale values persist when a later SDP omits a stream (SIPp).
    remote_media: [Option<SocketAddr>; 3],
    /// `[rtpstream_audio_port]` / `[rtpstream_video_port]` once allocated.
    rtpstream_ports: [Option<u16>; 2],
    /// SRTP: what this call offered/answered and what the peer sent.
    crypto: crate::render::CallCrypto,
    /// Next `play_dtmf` sequence number (SIPp: from 1200, advanced per burst).
    dtmf_seq: u16,
    /// (branch, cseq-line, start-line-ish) key for inbound retrans dedupe.
    last_recv_key: Option<(String, String, String)>,
    retrans: Option<RetransCtx>,
    timer: Option<(TimerId, TimerKind)>,
    /// Bumped whenever timers are (re)armed; stale fires are ignored.
    generation: u64,
    /// The running `<pause>`: its step index and when it ends (SIPp's
    /// `msg_index` / `paused_until`), for `_unexp.retaddr` / `pausedaddr`
    /// — `index` already points past the pause while it runs.
    pause_deadline: Option<(usize, Instant)>,
    /// A `<pauserestore>` deadline to serve before the next step executes.
    paused_until: Option<Instant>,
    /// This call's own socket in the per-call modes (opened at its first
    /// send, SIPp's `connect_socket_if_needed`); `None` = the shared one.
    socket: Option<CallSocket>,
    /// What `[remote_ip]`/`[remote_port]` and the digest URI render: the
    /// nominal remote (target, or the request's source), which `-rsa` does
    /// not change (SIPp's `remote_ip`/`remote_port` globals).
    render_remote: SocketAddr,
    /// `[server_ip]`: the IP of the socket this call's messages leave on.
    server_ip: String,
    /// Runs the out-of-call scenario (spawned by an unmapped request) rather
    /// than the main one; never counts toward `-l`/`-users`/`-m`.
    ooc: bool,
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
    run_scenarios(scenario, None, config, ui)
}

/// [`run_with_ui`] with an out-of-call scenario (`-oocsf`/`-oocsn`) loaded
/// next to the main one: a request whose Call-ID matches no live call spawns
/// a call on `ooc` instead of being discarded (SIPp `socket.cpp`
/// `process_message`). Client mode only, as in SIPp.
///
/// # Errors
///
/// See [`run`]; additionally when `ooc` is given in server mode or reads
/// injection files (`[fieldN]`), with SIPp's wordings.
pub fn run_scenarios(
    scenario: &Scenario,
    ooc: Option<&Scenario>,
    config: &EngineConfig,
    ui: Option<UiChannels>,
) -> Result<(RunReport, EngineControl), EngineError> {
    validate_for_engine(scenario)?;
    if let Some(ooc) = ooc {
        validate_for_engine(ooc)?;
        if scenario.role == Role::Uas {
            return Err(EngineError(
                "SIPp cannot use out-of-call scenarios when running in server mode".into(),
            ));
        }
        if ooc.uses_injection_fields() {
            return Err(EngineError(
                "Automatic calls (created by -aa, -oocsn or -oocsf) cannot use input files!".into(),
            ));
        }
    }
    if scenario.role == Role::Uac && config.target.is_none() {
        return Err(EngineError(
            "this scenario places calls (UAC): a remote target is required".into(),
        ));
    }
    let mut engine = Engine::new(scenario, ooc, config, ui)?;
    let control = engine.control.clone();
    let report = engine.run_loop();
    Ok((report, control))
}

/// Which end of the 3PCC twin socket this instance is.
#[derive(Clone, Copy)]
enum TwinRole {
    /// First twin command is `sendCmd`: dial the peer (controller A).
    Connect,
    /// First twin command is `recvCmd`: listen for the peer (controller B).
    Listen,
}

/// Decide the twin role from the scenario's first twin command, or `None` when
/// the scenario has none.
fn twin_role(scenario: &Scenario) -> Option<TwinRole> {
    scenario.steps.iter().find_map(|s| match s {
        Step::SendCmd { .. } => Some(TwinRole::Connect),
        Step::RecvCmd { .. } => Some(TwinRole::Listen),
        _ => None,
    })
}

/// The bound transport, dispatched by kind. Both variants expose the same
/// address/send surface the engine uses.
enum Transport {
    Udp(UdpTransport),
    Tcp(TcpTransport),
    Tls(TlsTransport),
    #[cfg(feature = "sctp")]
    Sctp(SctpTransport),
}

/// A call's own socket in the per-call modes (`un`/`tn`/`ln`). Shared
/// (`Arc`) because past `-max_socket` calls share sockets, as SIPp's
/// `new_sipp_call_socket` hands out existing ones round-robin; the socket
/// closes when the last call holding it ends (SIPp's refcount).
#[derive(Clone)]
enum CallSocket {
    Udp(Arc<UdpCallSocket>),
    Tcp(Arc<TcpCallConn>),
    Tls(Arc<TlsCallConn>),
    #[cfg(feature = "sctp")]
    Sctp(Arc<SctpCallConn>),
}

impl CallSocket {
    fn local_port(&self) -> u16 {
        self.local_addr().port()
    }

    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(s) => s.local_addr(),
            Self::Tcp(c) => c.local_addr(),
            Self::Tls(c) => c.local_addr(),
            #[cfg(feature = "sctp")]
            Self::Sctp(c) => c.local_addr(),
        }
    }

    fn downgrade(&self) -> WeakCallSocket {
        match self {
            Self::Udp(s) => WeakCallSocket::Udp(Arc::downgrade(s)),
            Self::Tcp(c) => WeakCallSocket::Tcp(Arc::downgrade(c)),
            Self::Tls(c) => WeakCallSocket::Tls(Arc::downgrade(c)),
            #[cfg(feature = "sctp")]
            Self::Sctp(c) => WeakCallSocket::Sctp(Arc::downgrade(c)),
        }
    }
}

/// The pool's view of a call socket: it must not keep one alive.
enum WeakCallSocket {
    Udp(std::sync::Weak<UdpCallSocket>),
    Tcp(std::sync::Weak<TcpCallConn>),
    Tls(std::sync::Weak<TlsCallConn>),
    #[cfg(feature = "sctp")]
    Sctp(std::sync::Weak<SctpCallConn>),
}

impl WeakCallSocket {
    fn upgrade(&self) -> Option<CallSocket> {
        match self {
            Self::Udp(w) => w.upgrade().map(CallSocket::Udp),
            Self::Tcp(w) => w.upgrade().map(CallSocket::Tcp),
            Self::Tls(w) => w.upgrade().map(CallSocket::Tls),
            #[cfg(feature = "sctp")]
            Self::Sctp(w) => w.upgrade().map(CallSocket::Sctp),
        }
    }
}

impl Transport {
    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(u) => u.local_addr(),
            Self::Tcp(t) => t.local_addr(),
            Self::Tls(t) => t.local_addr(),
            #[cfg(feature = "sctp")]
            Self::Sctp(t) => t.local_addr(),
        }
    }

    fn send_to(&self, data: &[u8], to: SocketAddr, lost_pct: Option<f64>) -> std::io::Result<bool> {
        match self {
            Self::Udp(u) => u.send_to(data, to, lost_pct),
            Self::Tcp(t) => t.send_to(data, to, lost_pct),
            Self::Tls(t) => t.send_to(data, to, lost_pct),
            #[cfg(feature = "sctp")]
            Self::Sctp(t) => t.send_to(data, to, lost_pct),
        }
    }

    /// Forget a stream connection whose end the engine has processed.
    fn forget(&self, peer: SocketAddr) {
        match self {
            Self::Udp(_) => {}
            Self::Tcp(t) => t.forget(peer),
            Self::Tls(t) => t.forget(peer),
            #[cfg(feature = "sctp")]
            Self::Sctp(t) => t.forget(peer),
        }
    }
}

/// The out-of-call scenario (`-oocsf`/`-oocsn`), compiled independently of
/// the main one: its own step stats, repartitions and CSeq guard (SIPp's
/// `ooc_scenario` with its own `CStat`).
struct OocScenario<'s> {
    scenario: &'s Scenario,
    stats: sipr_stats::StatSet,
    /// Per-step: CSeq method a response recv must carry (SIPp guard).
    expected_cseq_method: Vec<Option<String>>,
}

struct Engine<'s> {
    scenario: &'s Scenario,
    /// Requests of no known call spawn calls here; `None` keeps SIPp's
    /// default of discarding them (the `ooc_default` fallback is commented
    /// out in `sipp.cpp`).
    ooc: Option<OocScenario<'s>>,
    /// Live calls on the ooc scenario (SIPp's `open_calls` never includes
    /// them: `-l`, `-users` and the end of the run look at the main ones).
    ooc_live: usize,
    /// `set display ooc`: the scenario screen shows the ooc scenario.
    display_ooc: bool,
    config: EngineConfig,
    transport: Transport,
    /// `[transport]` token and whether the transport is reliable (no retrans).
    transport_token: &'static str,
    reliable: bool,
    /// `-max_reconnect` budget left (SIPp `reset_number`; -1 = unlimited).
    reconnects_left: i64,
    /// The mono client connection is gone (SIPp `ss_invalid`): the next send
    /// re-dials or, with no budget left, ends the run.
    mono_conn_invalid: bool,
    /// A fatal condition that ends the run with exit 255 (SIPp `ERROR`).
    fatal: Option<String>,
    /// A send just hit the dead mono connection: reset it once the failed
    /// call is gone (SIPp's `sockets_pending_reset`, drained by the main
    /// loop after `send_raw` deleted the call).
    pending_reset: Option<SocketAddr>,
    /// One socket per call (`un`/`tn`/`ln` as a client).
    per_call: bool,
    /// `-rsa` as a server: responses leave on a socket of their own aimed at
    /// the sending address (SIPp's `call_remote_socket`), shared across
    /// calls unless the transport is per-call.
    rsa_server: bool,
    /// `-t ui`: the sockets bound per injected IP (SIPp `map_perip_fd`),
    /// persistent for the run; the main socket's own IP is not in here.
    ip_sockets: HashMap<IpAddr, Arc<UdpCallSocket>>,
    /// `-max_socket`: share call sockets round-robin past this many.
    max_socket: usize,
    /// Every call socket opened and not yet closed, for sharing.
    call_socket_pool: Vec<WeakCallSocket>,
    /// Round-robin cursor over the pool (SIPp's `next_socket`).
    next_shared_socket: usize,
    timers: TimerService<Event>,
    rx: Receiver<Event>,
    calls: HashMap<String, CallState>,
    stats: sipr_stats::StatSet,
    trace_msg: Option<sipr_stats::TraceFile>,
    trace_err: Option<sipr_stats::TraceFile>,
    trace_stat: Option<sipr_stats::TraceFile>,
    inf_files: Vec<std::cell::RefCell<InjectionFile>>,
    inf_seq: Vec<usize>,
    /// 3PCC twin control channel (`-3pcc`), when the scenario uses it.
    twin: Option<TwinChannel>,
    /// Twin commands that arrived before a call was ready to consume them.
    pending_cmds: std::collections::VecDeque<String>,
    /// `-users` closed loop: the pool of free user ids (1..=N).
    free_users: std::collections::VecDeque<usize>,
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
    /// The media thread, started only when the scenario plays pcaps.
    media: Option<MediaPlayer>,
    /// Parsed captures by the scenario's file attribute, loaded once.
    pcaps: HashMap<String, Arc<PcapStream>>,
    media_ip: IpAddr,
    media_ip_str: String,
    media_port: u16,
    /// Per [`MediaKind`]: which `[media_port]` form (auto, +offset) the SDP
    /// uses on that `m=` line — the local port a replay must send from.
    port_layout: [(bool, u16); 3],
    /// `rtp_stream` file bytes by the scenario's file attribute (WAV header
    /// already skipped), loaded once.
    rtp_files: HashMap<String, Arc<[u8]>>,
    /// Cursor for `[rtpstream_*_port]` allocation (SIPp `next_rtp_port`).
    next_rtp_port: u16,
    max_rtp_port: u16,
    rtp_payload: u8,
    /// SSRC base; a call's audio/video streams take `base + 2*(n-1) + {0,1}`.
    ssrc_base: u32,
    /// Counter for `play_dtmf` SSRCs (SIPp: a fresh SSRC per burst).
    dtmf_ssrc_counter: u32,
    /// Latest snapshot for the HTTP API, when it is enabled.
    control_snapshot: Option<Arc<Mutex<sipr_stats::Snapshot>>>,
    /// Keeps the HTTP listener alive for the run.
    _http: Option<sipr_control::http::HttpServer>,
    /// `set rate-scale`: the step multiplier for the rate keys.
    rate_scale: f64,
    /// `-rtp_echo`: the global echo sockets, when enabled.
    echo: Option<sipr_media::EchoServer>,
    /// Per-call `exec rtp_echo=` streams by `(call id, video?)`.
    call_echoes: HashMap<(String, bool), sipr_media::EchoStream>,
    /// Counters shared by every per-call echo, `[audio, video]`.
    call_echo_counters: [Arc<sipr_media::echo::EchoCounters>; 2],
    /// `-rate_increase`: when the ramp last fired (SIPp `ratetask`).
    last_ramp: Instant,
    /// `set hide` (SIPp `do_hide`): hidden steps stay off the scenario screen.
    hide: bool,
    /// The last screen requested via a control-socket digit key, with a
    /// sequence number (the TUI applies each once).
    screen_request: Option<(u64, u8)>,
}

impl<'s> Engine<'s> {
    fn new(
        scenario: &'s Scenario,
        ooc: Option<&'s Scenario>,
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
        // Injection files first: `-t ui` binds sockets from their IP column.
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
            if file.mode == InjectMode::User && config.users.is_none() {
                eprintln!(
                    "sipr: warning: injection file {name} uses USER mode but -users \
                     was not given; its [fieldN] will render empty"
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
        let mut tcfg = TransportConfig {
            local_ip: config.local_ip,
            port: config.port,
            send_loss_pct: 0.0,
            recv_loss_pct: 0.0,
            loss_seed: config.seed,
        };
        let per_call = config.transport.per_call() && scenario.role == Role::Uac;
        // `-t ui`: the main socket binds the first injected IP (SIPp: "on some
        // machines it fails to bind to the self computed local IP").
        let per_ip = config.transport == TransportKind::UdpPerIp;
        if per_ip {
            let first = inf_files
                .first()
                .and_then(|f| f.borrow().field(0, config.ip_field).map(ToOwned::to_owned))
                .ok_or_else(|| {
                    EngineError(
                        "-t ui needs an -inf file with an IP in the -ip_field column".into(),
                    )
                })?;
            let ip: IpAddr = first.trim().parse().map_err(|_| {
                EngineError(format!(
                    "-t ui: '{first}' (line 0, -ip_field) is not an IP address"
                ))
            })?;
            tcfg.local_ip = Some(ip);
        }
        let rsa_server = config.remote_sending_addr.is_some() && scenario.role == Role::Uas;
        let (transport, transport_token, reliable) = match config.transport {
            TransportKind::UdpMono | TransportKind::UdpPerCall | TransportKind::UdpPerIp => {
                let u = UdpTransport::bind(&tcfg, net_tx)
                    .map_err(|e| EngineError(format!("cannot bind UDP socket: {e}")))?;
                (Transport::Udp(u), "UDP", false)
            }
            TransportKind::TcpMono | TransportKind::TcpPerCall => {
                let t = match scenario.role {
                    // `tn` client: every call dials its own connection later.
                    Role::Uac if per_call => TcpTransport::client_pool(&tcfg, net_tx),
                    // Client: one mono-socket connection to the target, opened now.
                    Role::Uac => {
                        let remote = config
                            .target
                            .ok_or_else(|| EngineError("TCP UAC needs a remote target".into()))?;
                        let remote = config.remote_sending_addr.unwrap_or(remote);
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
            TransportKind::SctpMono | TransportKind::SctpPerCall => {
                build_sctp_transport(config, &tcfg, net_tx, scenario.role, per_call)?
            }
            TransportKind::TlsMono | TransportKind::TlsPerCall => {
                let tls_cfg = config
                    .tls
                    .as_ref()
                    .ok_or_else(|| EngineError("TLS transport needs TLS configuration".into()))?;
                let t = match scenario.role {
                    // `ln` client: every call dials and handshakes its own.
                    Role::Uac if per_call => TlsTransport::client_pool(&tcfg, tls_cfg, net_tx)
                        .map_err(|e| EngineError(format!("TLS configuration: {e}")))?,
                    // Client: dial + handshake now; a failure is a startup error.
                    Role::Uac => {
                        let remote = config
                            .target
                            .ok_or_else(|| EngineError("TLS UAC needs a remote target".into()))?;
                        let remote = config.remote_sending_addr.unwrap_or(remote);
                        TlsTransport::connect(&tcfg, tls_cfg, net_tx, remote).map_err(|e| {
                            EngineError(format!("cannot connect TLS to {remote}: {e}"))
                        })?
                    }
                    // Server: listen; each accepted connection handshakes on
                    // its own thread and a bad client is dropped, not fatal.
                    Role::Uas => TlsTransport::listen(&tcfg, tls_cfg, net_tx)
                        .map_err(|e| EngineError(format!("cannot bind TLS listener: {e}")))?,
                };
                (Transport::Tls(t), "TLS", true)
            }
        };
        // 3PCC twin control channel. The role comes from the first twin command
        // in the scenario: sendCmd-first dials the peer, recvCmd-first listens.
        if ooc.is_some_and(|o| twin_role(o).is_some()) {
            return Err(EngineError(
                "the out-of-call scenario cannot use <sendCmd>/<recvCmd> (3PCC)".into(),
            ));
        }
        let twin = match (twin_role(scenario), config.twin_addr) {
            (Some(role), Some(addr)) => {
                let (twin_tx, twin_rx) = channel::<String>();
                let bridge_tx = tx.clone();
                std::thread::Builder::new()
                    .name("sipr-twin-bridge".into())
                    .spawn(move || {
                        while let Ok(cmd) = twin_rx.recv() {
                            if bridge_tx.send(Event::TwinCmd(cmd)).is_err() {
                                return;
                            }
                        }
                    })
                    .ok();
                let ch = match role {
                    TwinRole::Connect => TwinChannel::connect(addr, twin_tx).map_err(|e| {
                        EngineError(format!("cannot connect 3PCC twin socket {addr}: {e}"))
                    })?,
                    TwinRole::Listen => TwinChannel::listen(addr, twin_tx).map_err(|e| {
                        EngineError(format!("cannot bind 3PCC twin socket {addr}: {e}"))
                    })?,
                };
                Some(ch)
            }
            (Some(_), None) => {
                return Err(EngineError(
                    "scenario uses <sendCmd>/<recvCmd> (3PCC) but no twin address \
                     was given — pass -3pcc HOST:PORT"
                        .into(),
                ));
            }
            (None, _) => None,
        };
        // Media: captures are parsed once here (SIPp: at scenario parse) and
        // the media thread exists only when something will be played.
        let mut pcaps = load_pcaps(scenario, config)?;
        let mut rtp_files = load_rtp_files(scenario, config)?;
        if let Some(o) = ooc {
            pcaps.extend(load_pcaps(o, config)?);
            rtp_files.extend(load_rtp_files(o, config)?);
        }
        for cmd in scenario
            .rtp_echo_cmds()
            .chain(ooc.into_iter().flat_map(Scenario::rtp_echo_cmds))
        {
            // SIPp resolves the echo's codec at parse time and fails on an
            // unknown one; sipr only needs the validation.
            sipr_media::RtpParams::resolve(
                cmd.payload_type
                    .unwrap_or(config.rtp_payload.unwrap_or(DEFAULT_RTP_PAYLOAD)),
                cmd.payload_name.as_deref(),
            )
            .map_err(|e| EngineError(format!("exec rtp_echo=: {e}")))?;
        }
        // -rtp_echo binds the media port (and +2) up front, probing upward
        // like SIPp; the port that bound is what [media_port] renders.
        let echo_ip = config
            .media_ip
            .unwrap_or_else(|| transport.local_addr().ip());
        let mut media_port = config.media_port.unwrap_or(DEFAULT_MEDIA_PORT);
        let echo = if config.rtp_echo {
            let bufsize = config
                .media_bufsize
                .unwrap_or(sipr_media::echo::DEFAULT_BUFSIZE);
            let server = sipr_media::EchoServer::start(echo_ip, media_port, bufsize)
                .map_err(|e| EngineError(format!("-rtp_echo: cannot bind media sockets: {e}")))?;
            media_port = server.media_port;
            eprintln!(
                "sipr: RTP echo on {echo_ip}:{media_port} and {echo_ip}:{}",
                media_port.wrapping_add(2)
            );
            Some(server)
        } else {
            if scenario.toggles_rtp_echo() || ooc.is_some_and(Scenario::toggles_rtp_echo) {
                eprintln!(
                    "sipr: warning: the scenario uses <rtp_echo> but -rtp_echo was not given — \
                     nothing is echoing"
                );
            }
            None
        };
        let media = if !(scenario.has_media() || ooc.is_some_and(Scenario::has_media)) {
            None
        } else {
            let (media_tx, media_rx) = channel::<MediaEvent>();
            let bridge_tx = tx.clone();
            std::thread::Builder::new()
                .name("sipr-media-bridge".into())
                .spawn(move || {
                    while let Ok(ev) = media_rx.recv() {
                        if bridge_tx.send(Event::Media(ev)).is_err() {
                            return;
                        }
                    }
                })
                .ok();
            Some(MediaPlayer::start(media_tx))
        };
        // Runtime control: SIPp's UDP control socket and the HTTP API both
        // feed Event::Control through one bridge.
        let (ctrl_tx, ctrl_rx) = channel::<ControlRequest>();
        let bridge_tx = tx.clone();
        std::thread::Builder::new()
            .name("sipr-ctrl-bridge".into())
            .spawn(move || {
                while let Ok(req) = ctrl_rx.recv() {
                    if bridge_tx.send(Event::Control(req)).is_err() {
                        return;
                    }
                }
            })
            .ok();
        if config.control_port != Some(0) {
            match sipr_control::udp::bind(config.control_ip, config.control_port) {
                Ok(sock) => {
                    if let Ok(addr) = sock.local_addr() {
                        eprintln!("sipr: control socket (UDP, SIPp -cp protocol) on {addr}");
                    }
                    sipr_control::udp::serve(sock, ctrl_tx.clone(), |w| {
                        eprintln!("sipr: warning: {w}");
                    })
                    .map_err(|e| EngineError(format!("cannot start the control socket: {e}")))?;
                }
                Err(e) if config.control_port.is_some() => {
                    return Err(EngineError(format!(
                        "cannot bind the control socket (-cp {}): {e}",
                        config.control_port.unwrap_or_default()
                    )));
                }
                Err(e) => eprintln!(
                    "sipr: warning: no free control port in 8888..8947 ({e}); running without a \
                     control socket (pass -cp PORT to choose one, -cp 0 to silence this)"
                ),
            }
        }
        let mut control_snapshot = None;
        let mut http = None;
        if let Some(addr) = config.http_addr {
            if !addr.ip().is_loopback() && config.http_token.is_none() {
                return Err(EngineError(format!(
                    "--sipr-http {addr} is not a loopback address: the API can stop the run and \
                     change its load, so a --sipr-http-token is required there"
                )));
            }
            let snapshot = Arc::new(Mutex::new(sipr_stats::Snapshot::default()));
            let steps: Vec<String> = scenario
                .dump()
                .lines()
                .skip(1)
                .map(ToOwned::to_owned)
                .collect();
            let link = ControlLink {
                requests: ctrl_tx.clone(),
                snapshot: Arc::clone(&snapshot),
                scenario_name: scenario.name.clone(),
                role: if scenario.role == Role::Uas {
                    "UAS"
                } else {
                    "UAC"
                },
                steps,
                version: env!("CARGO_PKG_VERSION"),
            };
            let server = sipr_control::http::HttpServer::start(
                addr,
                sipr_control::api::handler(link, config.http_token.clone()),
            )
            .map_err(|e| EngineError(format!("cannot bind --sipr-http {addr}: {e}")))?;
            eprintln!("sipr: HTTP control API on http://{}/", server.local_addr());
            control_snapshot = Some(snapshot);
            http = Some(server);
        }
        if let Some(uri) = &config.auth_uri
            && (uri.starts_with("sip:") || uri.starts_with("sips:"))
        {
            eprintln!(
                "sipr: warning: -auth_uri '{uri}' already has a scheme; SIPp (and sipr) \
                 prepend 'sip:' regardless, so the digest uri= will be 'sip:{uri}'"
            );
        }
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
        // `-t ui` server: one socket per distinct injected IP, on the main
        // socket's port (SIPp `open_connections`, MODE_SERVER).
        let mut ip_sockets = HashMap::new();
        if per_ip && scenario.role == Role::Uas {
            let Transport::Udp(udp) = &transport else {
                return Err(EngineError("-t ui is UDP only".into()));
            };
            let file = inf_files
                .first()
                .ok_or_else(|| EngineError("-t ui needs an -inf file".into()))?
                .borrow();
            for line in 0..file.len() {
                let raw = file
                    .field(line, config.ip_field)
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                let ip: IpAddr = raw.parse().map_err(|_| {
                    EngineError(format!(
                        "-t ui: '{raw}' (line {line}, -ip_field) is not an IP address"
                    ))
                })?;
                if ip == local_addr.ip() || ip_sockets.contains_key(&ip) {
                    continue;
                }
                let sock = udp
                    .open_call_socket_at(SocketAddr::new(ip, local_addr.port()))
                    .map_err(|e| {
                        EngineError(format!(
                            "-t ui: cannot bind {ip}:{}: {e}",
                            local_addr.port()
                        ))
                    })?;
                ip_sockets.insert(ip, Arc::new(sock));
            }
        }
        if per_call && !matches!(transport, Transport::Udp(_)) {
            eprintln!(
                "sipr: one connection per call from {} (placing calls)",
                local_addr.ip()
            );
        } else {
            eprintln!(
                "sipr: bound to {local_addr} ({})",
                match scenario.role {
                    Role::Uac => "placing calls",
                    Role::Uas => "answering calls",
                }
            );
        }
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
        let stat_set = new_stat_set(scenario);
        let ooc = ooc.map(|o| OocScenario {
            scenario: o,
            stats: new_stat_set(o),
            expected_cseq_method: precompute_cseq_methods(o),
        });
        // Load -inf injection files up front (fail fast on bad files). SIPp
        // keys files by basename; keyword `file=` and `-infindex` match that.
        let inf_len = inf_files.len();
        Ok(Self {
            scenario,
            ooc,
            ooc_live: 0,
            display_ooc: false,
            config: config.clone(),
            transport,
            transport_token,
            reliable,
            reconnects_left: config.max_reconnect,
            mono_conn_invalid: false,
            fatal: None,
            pending_reset: None,
            per_call,
            rsa_server,
            ip_sockets,
            max_socket: config.max_socket.max(1),
            call_socket_pool: Vec::new(),
            next_shared_socket: 0,
            timers,
            rx,
            calls: HashMap::new(),
            stats: stat_set,
            trace_msg: open_trace(&config.trace_msg, "message trace")?,
            trace_err: open_trace(&config.trace_err, "error trace")?,
            trace_stat,
            inf_files,
            inf_seq: vec![0; inf_len],
            twin,
            pending_cmds: std::collections::VecDeque::new(),
            free_users: config
                .users
                .map_or_else(Default::default, |n| (1..=n).collect()),
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
            local_ip_str: config
                .local_ip
                .unwrap_or_else(|| local_addr.ip())
                .to_string(),
            pid: std::process::id(),
            media,
            pcaps,
            media_ip: config.media_ip.unwrap_or_else(|| local_addr.ip()),
            media_ip_str: config
                .media_ip
                .unwrap_or_else(|| local_addr.ip())
                .to_string(),
            media_port,
            port_layout: media_port_layout(scenario),
            rtp_files,
            next_rtp_port: media_port,
            max_rtp_port: config.max_rtp_port.unwrap_or(u16::MAX),
            rtp_payload: config.rtp_payload.unwrap_or(DEFAULT_RTP_PAYLOAD),
            ssrc_base: if config.random_base_ssrc {
                // Any seed-derived base; SIPp uses rand().
                #[allow(clippy::cast_possible_truncation)]
                let r = sipr_net::rng::Rng::new(config.seed ^ 0x55C0_0001).next_u64() as u32;
                r
            } else {
                sipr_media::rtp::BASE_SSRC
            },
            dtmf_ssrc_counter: 0,
            control_snapshot,
            _http: http,
            rate_scale: config.rate_scale.unwrap_or(1.0),
            echo,
            call_echoes: HashMap::new(),
            call_echo_counters: [Arc::default(), Arc::default()],
            last_ramp: Instant::now(),
            hide: true,
            screen_request: None,
        })
    }

    fn run_loop(&mut self) -> RunReport {
        let started = Instant::now();
        let mut last_line = Instant::now();
        let mut last_stat_dump = Instant::now();
        // First tick immediately: SIPp starts placing calls right away.
        self.on_pacer_tick();
        self.refill_users(); // users mode opens its initial N calls now
        loop {
            // SIPp's `open_calls` counts main-scenario calls only: the run
            // ends when they are done, whatever ooc calls still linger.
            if self.hard_stop || (self.done_creating() && self.live_main() == 0) {
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
                Ok(Event::Net(NetEvent::Disconnected { peer, local, clean })) => {
                    self.on_disconnected(peer, local, clean);
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
                Ok(Event::Stdin(c)) => self.apply_key(c),
                Ok(Event::Control(req)) => self.on_control(req),
                Ok(Event::TwinCmd(cmd)) => self.on_twin_cmd(cmd),
                Ok(Event::Media(ev)) => self.on_media_event(ev),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            // Closed-loop: replace any calls that just ended (no-op otherwise).
            self.refill_users();
            self.run_rate_ramp();
            if last_line.elapsed() >= Duration::from_secs(1) {
                last_line = Instant::now();
                self.sample_media_counters();
                if self.config.periodic_stats {
                    eprintln!("sipr: {}", self.stats.line(self.live_main()));
                }
                self.publish_snapshot();
            }
            if self.trace_stat.is_some() && last_stat_dump.elapsed() >= self.config.stat_interval {
                last_stat_dump = Instant::now();
                let row = self.stats.csv_row(self.live_main());
                if let Some(f) = self.trace_stat.as_mut() {
                    f.write(&row);
                    f.flush();
                }
            }
        }
        self.control.stop_pacer.store(true, Ordering::Relaxed);
        self.sample_media_counters();
        self.collect_final_media_events();
        // Final CSV row + flush all trace files.
        if self.trace_stat.is_some() {
            let row = self.stats.csv_row(self.live_main());
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
            fatal: self.fatal.take(),
            messages_sent: self.stats.messages_sent,
            messages_matched: self.stats.messages_matched,
            retrans_sent: self.stats.retrans_sent,
            retrans_recv: self.stats.retrans_recv,
            unexpected: self.stats.unexpected,
            garbage: self.stats.garbage,
            rtp_packets_sent: self.stats.rtp_packets_sent,
            rtp_check_ok: self.stats.rtp_check_ok,
            rtp_check_failed: self.stats.rtp_check_failed,
            elapsed: started.elapsed(),
        }
    }

    /// Streams that end with their calls report their RTP-check tallies
    /// asynchronously; the last of them arrive after the call map empties.
    /// Shut the media thread down (it flushes every stream's tally on the
    /// way out) and drain what the bridge forwards before the report.
    fn collect_final_media_events(&mut self) {
        if self.media.take().is_none() {
            return;
        }
        let mut quiet_rounds = 0;
        while quiet_rounds < 3 {
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Event::Media(ev)) => {
                    self.on_media_event(ev);
                    quiet_rounds = 0;
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => quiet_rounds += 1,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        self.sample_media_counters();
    }

    /// Copy the media thread's atomics into the stat set (once a second and
    /// at the end), so the TUI/CSV/report see them without touching the
    /// media thread.
    fn sample_media_counters(&mut self) {
        if let Some(m) = self.media.as_ref() {
            self.stats.rtp_packets_sent = m.packets_sent();
            self.stats.rtp_bytes_sent = m.bytes_sent();
        }
        let global = self.echo.as_ref().map_or((0, 0), |e| {
            (
                e.audio.packets.load(Ordering::Relaxed),
                e.video.packets.load(Ordering::Relaxed),
            )
        });
        self.stats.rtp_echo_packets =
            global.0 + self.call_echo_counters[0].packets.load(Ordering::Relaxed);
        self.stats.rtp_echo2_packets =
            global.1 + self.call_echo_counters[1].packets.load(Ordering::Relaxed);
    }

    fn publish_snapshot(&mut self) {
        if self.snapshot_tx.is_none() && self.control_snapshot.is_none() {
            return;
        }
        let mut snap = sipr_stats::Snapshot {
            scenario: self.scenario.name.clone(),
            uas: self.scenario.role == Role::Uas,
            rate_target: self.control.rate(),
            paused: self.paused,
            hide: self.hide,
            screen_request: self.screen_request,
            ..Default::default()
        };
        self.stats.fill_snapshot(&mut snap, self.live_main());
        // `set display ooc` (SIPp `display_scenario`): only the scenario
        // screen follows; the statistics stay the main scenario's.
        if self.display_ooc
            && let Some(o) = self.ooc.as_ref()
        {
            snap.display_ooc = Some(o.scenario.name.clone());
            snap.steps = o.stats.step_rows();
        }
        let now = Instant::now();
        let (last_at, last_created) = self.last_snapshot;
        #[allow(clippy::cast_precision_loss)]
        {
            snap.rate_period = (self.stats.created() - last_created) as f64
                / now.duration_since(last_at).as_secs_f64().max(1e-9);
        }
        self.last_snapshot = (now, self.stats.created());
        if let Some(shared) = self.control_snapshot.as_ref()
            && let Ok(mut slot) = shared.lock()
        {
            *slot = snap.clone();
        }
        if let Some(tx) = self.snapshot_tx.as_ref() {
            let _ = tx.send(snap); // UI gone → ignored; run continues headless
        }
    }

    /// The digest `uri=` (SIPp `call.cpp` ~l.4159): literally `sip:` +
    /// (`-auth_uri`, else `remote_ip:remote_port`) — with SIPp's quirk that a
    /// value already carrying a scheme yields `sip:sip:…`, kept for
    /// fidelity and warned about at startup.
    fn digest_uri(&self, remote: SocketAddr) -> String {
        match &self.config.auth_uri {
            Some(uri) => format!("sip:{uri}"),
            None => format!("sip:{}:{}", remote.ip(), remote.port()),
        }
    }

    // ---- rate ramp (-rate_increase) ------------------------------------

    /// SIPp's `ratetask`: every `rate_interval`, `rate += rate_increase`;
    /// past `rate_max` the rate is clamped there and, with `rate_quit`, the
    /// run drains. The task dies once quitting (rate mode only — users
    /// mode ignores the rate, as in SIPp).
    fn run_rate_ramp(&mut self) {
        let Some(increase) = self.config.rate_increase else {
            return;
        };
        if self.soft_stopping || self.config.users.is_some() {
            return;
        }
        let interval = self
            .config
            .rate_interval
            .unwrap_or(self.config.stat_interval);
        if self.last_ramp.elapsed() < interval {
            return;
        }
        self.last_ramp = Instant::now();
        let (rate, quit) = ramp_step(
            self.control.rate(),
            increase,
            self.config.rate_max,
            self.config.rate_quit,
        );
        self.control.set_rate(rate);
        if quit {
            eprintln!("sipr: rate reached -rate_max {rate}; quitting (drain)");
            self.soft_quit();
        }
    }

    // ---- runtime control -----------------------------------------------

    /// SIPp's hot keys (`socket.cpp` `process_key`): the rate keys step by
    /// `rate-scale`, and act on the user count in `-users` mode; `q` drains,
    /// a second `q` (or `Q`) aborts.
    fn apply_key(&mut self, c: char) {
        match c {
            'q' => {
                if self.soft_stopping {
                    self.hard_quit();
                } else {
                    self.soft_quit();
                }
            }
            'Q' => self.hard_quit(),
            '+' => self.bump_load(1.0),
            '-' => self.bump_load(-1.0),
            '*' => self.bump_load(10.0),
            '/' => self.bump_load(-10.0),
            'p' => self.paused = !self.paused,
            // SIPp's screen keys: forwarded to the TUI through the snapshot.
            '1'..='9' => {
                let seq = self.screen_request.map_or(1, |(n, _)| n + 1);
                self.screen_request = Some((seq, c as u8 - b'0'));
                self.publish_snapshot();
            }
            _ => {}
        }
    }

    fn bump_load(&mut self, step: f64) {
        let delta = step * self.rate_scale;
        if let Some(users) = self.config.users {
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let target = (users as f64 + delta).max(0.0).round() as usize;
            self.set_users(target);
        } else {
            self.control
                .set_rate((self.control.rate() + delta).max(0.0));
        }
    }

    fn soft_quit(&mut self) {
        self.soft_stopping = true;
        self.control.stop_pacer.store(true, Ordering::Relaxed);
    }

    fn hard_quit(&mut self) {
        self.fail_all("hard quit");
        self.soft_stopping = true;
        self.hard_stop = true;
    }

    /// `set users N` at runtime (SIPp `CallGenerationTask::set_users`): new
    /// ids join the free pool, a smaller target lets excess calls finish
    /// without replacement, and traffic is un-paused.
    fn set_users(&mut self, target: usize) {
        let current = self.config.users.unwrap_or(0);
        for id in current + 1..=target {
            self.free_users.push_back(id);
        }
        self.free_users.retain(|id| *id <= target);
        self.config.users = Some(target);
        self.paused = false;
        self.refill_users();
    }

    fn control_state(&self) -> ControlState {
        ControlState {
            rate: self.control.rate(),
            rate_scale: self.rate_scale,
            paused: self.paused,
            users: self.config.users.map(|u| u as u64),
            limit: self.config.limit,
            quitting: if self.hard_stop {
                Quitting::Hard
            } else if self.soft_stopping {
                Quitting::Soft
            } else {
                Quitting::No
            },
        }
    }

    fn on_control(&mut self, req: ControlRequest) {
        let result = self.apply_control(&req.cmd);
        match req.reply {
            Some(reply) => {
                let _ = reply.send(result.map(|()| self.control_state()));
            }
            None => {
                if let Err(e) = result {
                    eprintln!("sipr: warning: {e}");
                    self.log_err(&e);
                }
            }
        }
    }

    /// Execute one control command; `Err` carries SIPp's warning text.
    fn apply_control(&mut self, cmd: &ControlCmd) -> Result<(), String> {
        match cmd {
            ControlCmd::Key(c) => self.apply_key(*c),
            ControlCmd::SetRate(v) => {
                if self.config.users.is_some() {
                    return Err("Rates can not be set in a user-based benchmark.".into());
                }
                self.control.set_rate(v.max(0.0));
            }
            ControlCmd::SetRateScale(v) => self.rate_scale = *v,
            ControlCmd::SetUsers(n) => {
                if self.config.users.is_none() {
                    return Err(
                        "Users can not be changed at run time for a rate-based benchmark.".into(),
                    );
                }
                self.set_users(usize::try_from(*n).unwrap_or(usize::MAX));
            }
            ControlCmd::SetLimit(n) => {
                if self.config.users.is_some() {
                    return Err("Limits can not be set in a user-based benchmark.".into());
                }
                self.config.limit = Some(*n);
            }
            ControlCmd::SetDisplay(which) => match which.as_str() {
                "main" => self.display_ooc = false,
                "ooc" if self.ooc.is_some() => self.display_ooc = true,
                // SIPp: "Unknown display scenario: %s" when that scenario is
                // not loaded (and sipr has no rx scenario at all).
                other => return Err(format!("Unknown display scenario: {other}")),
            },
            ControlCmd::SetHide(on) => self.hide = *on,
            ControlCmd::Trace { log, on } => self.set_trace(log, *on)?,
            ControlCmd::Dump(what) => {
                if what != "tasks" {
                    return Err(format!("dump {what} is not supported by sipr"));
                }
                let mut lines: Vec<String> = self
                    .calls
                    .iter()
                    .map(|(id, c)| format!("call {id}: number {} at step {}", c.number, c.index))
                    .collect();
                lines.sort();
                self.log_err(&format!("---- {} Active Tasks ----", lines.len()));
                for l in lines {
                    self.log_err(&l);
                }
            }
            ControlCmd::ResetStats => {
                self.stats.reset();
                if let Some(o) = self.ooc.as_mut() {
                    o.stats.reset();
                }
                self.last_snapshot = (Instant::now(), 0);
            }
            ControlCmd::SetPaused(p) => self.paused = *p,
            ControlCmd::Quit { force } => {
                if *force {
                    self.hard_quit();
                } else {
                    self.soft_quit();
                }
            }
            ControlCmd::Query => {}
        }
        Ok(())
    }

    /// `trace messages|error on|off`: open (SIPp's file naming) or close a
    /// trace file at runtime.
    fn set_trace(&mut self, log: &str, on: bool) -> Result<(), String> {
        let (slot, configured, suffix, label) = match log {
            "messages" => (
                &mut self.trace_msg,
                self.config.trace_msg.clone(),
                "messages",
                "message trace",
            ),
            "error" => (
                &mut self.trace_err,
                self.config.trace_err.clone(),
                "errors",
                "error trace",
            ),
            other => return Err(format!("trace {other} is not supported by sipr")),
        };
        if !on {
            if let Some(f) = slot.as_mut() {
                f.flush();
            }
            *slot = None;
            return Ok(());
        }
        if slot.is_some() {
            return Ok(());
        }
        let path = configured.or_else(|| {
            self.config
                .trace_name_base
                .as_ref()
                .map(|b| std::path::PathBuf::from(format!("{b}_{suffix}.log")))
        });
        let Some(path) = path else {
            return Err(format!(
                "trace {log} on: no file name known for the {label}"
            ));
        };
        *slot = Some(
            sipr_stats::TraceFile::create(&path)
                .map_err(|e| format!("cannot open {label} {}: {e}", path.display()))?,
        );
        Ok(())
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
        // Users mode is closed-loop (event-driven via refill_users), not paced.
        if self.config.users.is_some()
            || self.scenario.role == Role::Uas
            || self.paused
            || self.done_creating()
        {
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
            let live = self.live_main() as u64;
            if self.config.limit.is_some_and(|l| live >= l) {
                self.pacer_carry = 0.0;
                return;
            }
            self.start_call(None);
        }
    }

    /// Live calls on the main scenario — SIPp's `open_calls`, which the
    /// `-l` cap, `-users` refills and the end of the run look at.
    fn live_main(&self) -> usize {
        self.calls.len().saturating_sub(self.ooc_live)
    }

    fn is_ooc(&self, call_id: &str) -> bool {
        self.calls.get(call_id).is_some_and(|c| c.ooc)
    }

    /// The scenario a call runs (the ooc one for out-of-call calls).
    fn scenario_of(&self, call_id: &str) -> &'s Scenario {
        match self.ooc.as_ref() {
            Some(o) if self.is_ooc(call_id) => o.scenario,
            _ => self.scenario,
        }
    }

    /// The stat set of the scenario a call runs (see [`stats_for`]).
    fn stats_of(&mut self, ooc: bool) -> &mut sipr_stats::StatSet {
        stats_for(&mut self.stats, self.ooc.as_mut(), ooc)
    }

    fn call_stats(&mut self, call_id: &str) -> &mut sipr_stats::StatSet {
        let ooc = self.is_ooc(call_id);
        self.stats_of(ooc)
    }

    /// The recv-window scan against the scenario a call runs.
    fn scan_call(&self, ooc: bool, window_start: usize, waiting: bool, msg: &Inbound) -> Scan {
        match self.ooc.as_ref() {
            Some(o) if ooc => scan_for_match(
                o.scenario,
                &o.expected_cseq_method,
                window_start,
                waiting,
                msg,
            ),
            _ => scan_for_match(
                self.scenario,
                &self.expected_cseq_method,
                window_start,
                waiting,
                msg,
            ),
        }
    }

    fn start_call(&mut self, user_id: Option<usize>) {
        let Some(target) = self.config.target else {
            return; // unreachable: validated in run_with_control
        };
        self.stats.outgoing_created += 1;
        let number = self.stats.created();
        let call_id = self.make_call_id(number);
        let cnonce = self.make_cnonce(number);
        let field_lines = self.assign_field_lines(user_id);
        self.calls.insert(
            call_id.clone(),
            new_call(
                number,
                self.config.remote_sending_addr.unwrap_or(target),
                target,
                self.config.base_cseq,
                &self.scenario.vars,
                cnonce,
                field_lines,
                user_id,
            ),
        );
        self.advance(&call_id);
    }

    /// `-users` closed loop: open replacement calls until N are live (or the
    /// `-m` cap / free pool runs out). No-op outside users mode.
    fn refill_users(&mut self) {
        let Some(n) = self.config.users else {
            return;
        };
        while self.live_main() < n && !self.done_creating() {
            let Some(uid) = self.free_users.pop_front() else {
                break;
            };
            self.start_call(Some(uid));
        }
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

    /// Choose this call's line in each injection file, per its mode. In USER
    /// mode the line is `userId - 1` (SIPp `nextLine`), or `None` when there is
    /// no user id (not `-users` mode) or it exceeds the file.
    fn assign_field_lines(&mut self, user_id: Option<usize>) -> Vec<Option<usize>> {
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
                InjectMode::User => user_id.filter(|&u| u >= 1 && u - 1 < n).map(|u| u - 1),
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
            let scenario = self.scenario_of(call_id);
            let Some(step) = scenario.steps.get(index) else {
                self.complete_call(call_id);
                return;
            };
            // A restored pause (SIPp `run()`: `paused_until` is served before
            // the step, which is then skipped with `next()`).
            if let Some(deadline) = self.calls.get(call_id).and_then(|c| c.paused_until) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Some(call) = self.calls.get_mut(call_id) else {
                    return;
                };
                call.paused_until = None;
                call.index = index + 1;
                if remaining.is_zero() {
                    continue;
                }
                call.generation += 1;
                let timer = self.timers.arm(
                    remaining,
                    Event::CallTimer {
                        call_id: call_id.to_owned(),
                        generation: call.generation,
                        kind: TimerKind::Pause,
                    },
                );
                call.timer = Some((timer, TimerKind::Pause));
                call.pause_deadline = Some((index, deadline));
                return;
            }
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
                    self.allocate_rtpstream_ports(call_id, &send.template);
                    self.prepare_crypto(call_id, &send.template);
                    // SIPp: the socket (and so `[local_port]`) must exist
                    // before substitution; a failed dial fails this call only.
                    if let Err(why) = self.ensure_call_socket(call_id) {
                        self.call_stats(call_id).failed_other += 1;
                        eprintln!("sipr: warning: call {call_id}: {why}");
                        self.log_err(&format!("call {call_id} failed: {why}"));
                        self.remove_call(call_id);
                        return;
                    }
                    let (buf, remote) = {
                        let Some(call) = self.calls.get(call_id) else {
                            return;
                        };
                        let remote_ip = call.render_remote.ip().to_string();
                        let digest_uri = self.digest_uri(call.render_remote);
                        let var_ctx = crate::render::VarCtx {
                            store: &call.store,
                            vars: &scenario.vars,
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
                            remote_port: call.render_remote.port(),
                            local_ip: &self.local_ip_str,
                            server_ip: self.server_ip_of(call),
                            local_port: self.call_local_port(call),
                            media_ip: &self.media_ip_str,
                            media_port: self.media_port,
                            rtpstream_ports: rtpstream_ports(call),
                            crypto: Some(&call.crypto),
                            transport: self.transport_token,
                            call_id,
                            call_number: call.number,
                            user_id: call.user_id.map_or(0, |u| u as u64),
                            users_total: self.config.users.map_or(0, |n| n as u64),
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
                    // SIPp `send_raw`: a send that fails ends the call
                    // (E_FAILED_CANNOT_SEND_MSG); a dead connection is then
                    // reset for the calls that follow (-max_reconnect).
                    // Simulated drops still count as "sent".
                    if let Err(e) = self.send_for_call(call_id, &buf, remote, send.lost_pct) {
                        self.after_send_failure(call_id, &e);
                        return;
                    }
                    let stats = self.call_stats(call_id);
                    stats.messages_sent += 1;
                    if let Some(s) = stats.step_mut(index) {
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
                    let is_ooc = call.ooc;
                    apply_rtds(
                        call,
                        stats_for(&mut self.stats, self.ooc.as_mut(), is_ooc),
                        &common,
                        now,
                    );
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
                    let mandatory = self.window_mandatory(call_id, index);
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
                    call.pause_deadline = Some((index, Instant::now() + dur));
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
                Step::SendCmd { template, common } => {
                    if self.twin.is_none() {
                        self.fail_call(call_id, "3PCC <sendCmd> reached but no -3pcc twin socket");
                        return;
                    }
                    let Some(rendered) = self.render_call_template(call_id, index, template) else {
                        return;
                    };
                    let result = self.twin.as_ref().map(|t| t.send(&rendered));
                    if let Some(Err(e)) = result {
                        self.fail_call(call_id, &format!("3PCC <sendCmd> failed: {e}"));
                        return;
                    }
                    let jump = self.jump_target(common, index, call_id);
                    if let Some(call) = self.calls.get_mut(call_id) {
                        call.index = jump;
                    }
                }
                Step::RecvCmd {
                    actions, common, ..
                } => {
                    // Consume a queued command immediately, else block until one
                    // arrives (Event::TwinCmd wakes the call).
                    if let Some(cmd) = self.pending_cmds.pop_front() {
                        if self.deliver_recv_cmd(call_id, index, actions, common, &cmd) {
                            return;
                        }
                        // index advanced in place; the loop runs the next step.
                    } else {
                        if let Some(call) = self.calls.get_mut(call_id) {
                            call.awaiting_cmd = true;
                        }
                        return;
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
    fn window_mandatory(&self, call_id: &str, start: usize) -> Option<(usize, Option<u64>)> {
        let scenario = self.scenario_of(call_id);
        let mut i = start;
        while let Some(step) = scenario.steps.get(i) {
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
                // Incoming (UAS) calls have no user id.
                let field_lines = self.assign_field_lines(None);
                self.calls.insert(
                    call_id.clone(),
                    new_call(
                        number,
                        self.config.remote_sending_addr.unwrap_or(packet.from),
                        packet.from,
                        self.config.base_cseq,
                        &self.scenario.vars,
                        cnonce,
                        field_lines,
                        None,
                    ),
                );
                // The call answers from the socket the request hit (`-t ui`)
                // and `[server_ip]` names that socket's IP (SIPp getsockname).
                let received_on = self.ip_sockets.get(&packet.local.ip()).cloned();
                if let Some(call) = self.calls.get_mut(&call_id) {
                    call.server_ip = packet.local.ip().to_string();
                    call.socket = received_on.map(CallSocket::Udp);
                }
                // Fall through to normal matching below (window at 0).
            } else if let Some(method) = msg.method().filter(|_| self.ooc.is_some()) {
                // Client mode with an ooc scenario (SIPp socket.cpp
                // `process_message`): a request of no known call spawns a
                // call on it — no user id, no injection line — counted as
                // an incoming call on the ooc stats and as an auto-answer
                // globally; the request is then matched against its step 0.
                self.log_err(&format!(
                    "Received out-of-call {method} message, using the out-of-call scenario"
                ));
                self.spawn_ooc_call(&call_id, packet);
            } else {
                // An unmapped response (or no ooc scenario at all): SIPp's
                // E_OUT_OF_CALL_MSGS.
                self.stats.unexpected += 1;
                self.log_err(&format!("out-of-call message ignored (Call-ID {call_id})"));
                return;
            }
        }
        let (window_start, waiting, completing, is_dup, ooc) = match self.calls.get(&call_id) {
            Some(c) => (
                c.index,
                c.waiting,
                c.completing,
                c.last_recv_key.as_ref() == Some(&key),
                c.ooc,
            ),
            None => return,
        };
        if is_dup {
            self.stats_of(ooc).retrans_recv += 1;
            // Re-send our last message (SIPp: retransmitted request → last
            // response again; harmless for a duplicated response).
            let resend = self
                .calls
                .get(&call_id)
                .and_then(|c| c.last_sent.clone().map(|b| (b, c.remote)));
            if let Some((buf, remote)) = resend {
                let _ = self.send_for_call(&call_id, &buf, remote, None);
                self.stats_of(ooc).retrans_sent += 1;
                self.trace_send(&buf, remote);
            }
            return;
        }
        if completing {
            // Timewait: absorb without failing (deadcall behavior).
            self.stats_of(ooc).unexpected += 1;
            return;
        }
        let scan = self.scan_call(ooc, window_start, waiting || window_start == 0, msg);
        match scan {
            Scan::Forward(si) => self.on_matched(&call_id, si, msg, key),
            Scan::Old => {
                // Late/repeated optional (e.g. another 180): absorbed.
                self.stats_of(ooc).messages_matched += 1;
                if let Some(call) = self.calls.get_mut(&call_id) {
                    call.last_recv_key = Some(key);
                }
            }
            Scan::NoMatch => {
                if self.try_unexpected_jump(&call_id, packet) {
                    return;
                }
                if self.try_auto_answer(&call_id, msg) {
                    return;
                }
                let stats = self.stats_of(ooc);
                stats.unexpected += 1;
                if let Some(s) = stats.step_mut(window_start) {
                    s.unexpected += 1;
                }
                stats.failed_unexpected += 1;
                let what = msg
                    .method()
                    .map_or_else(|| format!("{:?}", msg.status_code()), ToOwned::to_owned);
                self.log_err(&format!(
                    "unexpected {what} for call {call_id}; call failed"
                ));
                self.remove_call(&call_id);
            }
        }
    }

    /// Create a call on the out-of-call scenario for a request of no known
    /// call, keyed by its Call-ID. The remote is the packet's source (or
    /// `-rsa`); the reply leaves on the socket the request hit, when that
    /// is a per-IP or per-call one.
    fn spawn_ooc_call(&mut self, call_id: &str, packet: &sipr_net::InboundPacket) {
        let Some(o) = self.ooc.as_mut() else {
            return;
        };
        o.stats.incoming_created += 1;
        let number = o.stats.created();
        let vars = &o.scenario.vars;
        self.stats.auto_answered += 1;
        let cnonce = self.make_cnonce(number);
        let mut call = new_call(
            number,
            self.config.remote_sending_addr.unwrap_or(packet.from),
            packet.from,
            self.config.base_cseq,
            vars,
            cnonce,
            vec![None; self.inf_files.len()],
            None,
        );
        call.ooc = true;
        call.server_ip = packet.local.ip().to_string();
        call.socket = self
            .ip_sockets
            .get(&packet.local.ip())
            .cloned()
            .map(CallSocket::Udp)
            .or_else(|| {
                self.call_socket_pool
                    .iter()
                    .filter_map(WeakCallSocket::upgrade)
                    .find(|s| s.local_addr() == packet.local)
            });
        self.calls.insert(call_id.to_owned(), call);
        self.ooc_live += 1;
    }

    /// Common handling for a message matched at step `si`.
    fn on_matched(
        &mut self,
        call_id: &str,
        si: usize,
        msg: &Inbound,
        key: (String, String, String),
    ) {
        let stats = self.call_stats(call_id);
        stats.messages_matched += 1;
        if let Some(s) = stats.step_mut(si) {
            s.recv += 1;
        }
        let scenario = self.scenario_of(call_id);
        let (rrs, ignore_sdp, common) = match &scenario.steps[si] {
            Step::Recv(r) => (r.record_route_set, r.ignore_sdp, r.common.clone()),
            _ => (false, false, StepCommon::default()),
        };
        let has_media = self.media.is_some();
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
        let is_ooc = call.ooc;
        apply_rtds(
            call,
            stats_for(&mut self.stats, self.ooc.as_mut(), is_ooc),
            &common,
            now,
        );
        call.last_recv_key = Some(key);
        if has_media && !ignore_sdp {
            learn_remote_media(call, msg);
        }
        call.last_recv = Some(msg.clone());
        call.waiting = false;
        call.index = si + 1;
        // Capture a digest challenge when this recv has auth="true".
        let auth = matches!(&scenario.steps[si], Step::Recv(r) if r.auth);
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
        let recv_actions = match &scenario.steps[si] {
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
        self.run_step_actions_inner(call_id, actions, index, None)
    }

    /// Shared body for step actions. `cmd_text` is set only for `<recvCmd>`,
    /// where `ereg` searches the raw twin command instead of a SIP message.
    fn run_step_actions_inner(
        &mut self,
        call_id: &str,
        actions: &[Action],
        index: usize,
        cmd_text: Option<&str>,
    ) -> bool {
        let Some(call) = self.calls.get(call_id) else {
            return true;
        };
        let remote_ip = call.render_remote.ip().to_string();
        let digest_uri = self.digest_uri(call.render_remote);
        let mut store = call.store.clone();
        let snapshot = call.store.clone(); // immutable copy for the base ctx
        let last = call.last_recv.clone();
        let scenario = self.scenario_of(call_id);
        let outcomes = {
            let var_ctx = crate::render::VarCtx {
                store: &snapshot,
                vars: &scenario.vars,
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
                remote_port: call.render_remote.port(),
                local_ip: &self.local_ip_str,
                server_ip: self.server_ip_of(call),
                local_port: self.call_local_port(call),
                media_ip: &self.media_ip_str,
                media_port: self.media_port,
                rtpstream_ports: rtpstream_ports(call),
                crypto: Some(&call.crypto),
                transport: self.transport_token,
                call_id,
                call_number: call.number,
                user_id: call.user_id.map_or(0, |u| u as u64),
                users_total: self.config.users.map_or(0, |n| n as u64),
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
            match cmd_text {
                Some(text) => crate::actions::run_cmd_actions(actions, &mut store, text, &ctx),
                None => crate::actions::run_actions(
                    actions,
                    &mut store,
                    last.as_ref(),
                    &ctx,
                    self.config.auth_uri.as_deref(),
                ),
            }
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
                    // SIPp: "Jump statement out of range" is fatal; sipr
                    // fails the call instead of the run.
                    if dest >= scenario.steps.len() {
                        self.call_stats(call_id).failed_other += 1;
                        self.log_err(&format!(
                            "call {call_id} failed: jump to message index {dest} is out of \
                             range (0..{})",
                            scenario.steps.len()
                        ));
                        self.remove_call(call_id);
                        return true;
                    }
                    if let Some(call) = self.calls.get_mut(call_id) {
                        call.index = dest;
                    }
                    self.advance(call_id);
                    return true;
                }
                crate::actions::ActionOutcome::PauseRestore(ms) => {
                    let started = self.stats.started;
                    if let Some(call) = self.calls.get_mut(call_id) {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let deadline = started + Duration::from_millis(ms.max(0.0) as u64);
                        call.paused_until = (ms > 0.0).then_some(deadline);
                    }
                }
                // SIPp releases the call's reference to its socket: on a
                // mono-socket transport that closes nothing; in the per-call
                // modes the socket closes with its last holder and the next
                // send opens a fresh one (docs/SIPP_COMPAT.md §6).
                crate::actions::ActionOutcome::CloseCon => {
                    if let Some(call) = self.calls.get_mut(call_id) {
                        call.socket = None;
                    }
                }
                crate::actions::ActionOutcome::FailCall(why) => {
                    self.call_stats(call_id).failed_other += 1;
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
                crate::actions::ActionOutcome::PlayPcap { kind, file } => {
                    self.start_pcap(call_id, kind, &file);
                }
                crate::actions::ActionOutcome::RtpStream(cmd) => {
                    self.on_rtp_stream(call_id, &cmd);
                }
                crate::actions::ActionOutcome::PlayDtmf(value) => {
                    self.start_dtmf(call_id, &value);
                }
                crate::actions::ActionOutcome::RtpEcho(on) => {
                    if let Some(e) = self.echo.as_ref() {
                        e.set_enabled(on);
                    }
                }
                crate::actions::ActionOutcome::RtpEchoCmd(cmd) => {
                    self.on_rtp_echo(call_id, &cmd);
                }
            }
        }
        false
    }

    /// `exec rtp_echo=start…|update…|stop…`: this call echoes (S)RTP on
    /// the port it advertised (`[rtpstream_*_port]`, else the `[media_port]`
    /// form), re-keying under the negotiated SDES contexts when the peer
    /// offered crypto — SIPp's `rtpstream_rtpecho_start*`. `update` restarts
    /// with the current negotiation (SIPp re-derives keys in place).
    fn on_rtp_echo(&mut self, call_id: &str, cmd: &RtpEchoCmd) {
        let key = (call_id.to_owned(), cmd.video);
        if cmd.verb == RtpEchoVerb::Stop {
            self.call_echoes.remove(&key);
            return;
        }
        let Some(call) = self.calls.get(call_id) else {
            return;
        };
        let kind = if cmd.video {
            MediaKind::Video
        } else {
            MediaKind::Audio
        };
        let number = call.number;
        let local_port = call.rtpstream_ports[usize::from(cmd.video)].unwrap_or_else(|| {
            let (auto, offset) = self.port_layout[kind.index()];
            crate::render::media_port_value(self.media_port, auto, offset, number)
        });
        // Echo receives under the peer's key and sends under ours: the
        // reverse of a stream's (send, receive) pair.
        let srtp = match call.crypto.negotiate(cmd.video) {
            Ok(Some((tx, rx))) => Some((rx, tx)),
            Ok(None) => None,
            Err(why) => {
                self.log_err(&format!(
                    "call {call_id}: rtp_echo: SRTP: {why} — echoing plain RTP"
                ));
                None
            }
        };
        let encrypted = srtp.is_some();
        // A restart (start twice, or update) replaces the running echo,
        // freeing its port first.
        self.call_echoes.remove(&key);
        let local = SocketAddr::new(self.media_ip, local_port);
        match sipr_media::EchoStream::start(
            local,
            srtp,
            Arc::clone(&self.call_echo_counters[usize::from(cmd.video)]),
        ) {
            Ok(stream) => {
                self.log_err(&format!(
                    "call {call_id}: rtp_echo {}: echoing on {local} ({})",
                    kind.as_str(),
                    if encrypted { "SRTP" } else { "plain RTP" }
                ));
                self.call_echoes.insert(key, stream);
            }
            Err(e) => {
                let line = format!("call {call_id}: rtp_echo: cannot bind {local}: {e}");
                eprintln!("sipr: warning: {line}");
                self.log_err(&line);
            }
        }
    }

    /// `[rtpstream_audio_port]` / `[rtpstream_video_port]`: give the call a
    /// port from the `-mp`..`-max_rtp_port` range (steps of two, wrapping)
    /// the first time a template renders the keyword — SIPp
    /// `rtpstream_get_localport`, minus the trial bind (the bind happens
    /// when the stream starts and fails loudly then).
    fn allocate_rtpstream_ports(&mut self, call_id: &str, template: &MsgTemplate) {
        let mut wanted = [false; 2];
        for kw in template.keywords() {
            if let Keyword::RtpStreamPort { video, offset: 0 } = kw {
                wanted[usize::from(*video)] = true;
            }
        }
        if !wanted.iter().any(|w| *w) {
            return;
        }
        let Some(call) = self.calls.get_mut(call_id) else {
            return;
        };
        for (i, want) in wanted.iter().enumerate() {
            if *want && call.rtpstream_ports[i].is_none() {
                let port = self.next_rtp_port;
                self.next_rtp_port = match self.next_rtp_port.checked_add(2) {
                    Some(p) if p <= self.max_rtp_port.saturating_sub(1) => p,
                    _ => self.media_port,
                };
                call.rtpstream_ports[i] = Some(port);
            }
        }
    }

    /// SIPp's crypto keywords have side effects at render time (`call.cpp`
    /// ~l.2860-3300): a suite keyword selects the local suite for that
    /// slot, `ue…` switches it to authenticate-only, and `cryptokeyparams`
    /// generates a fresh master key — unless its offset is negative, which
    /// reuses the existing key (the `[cryptokeyparams1audio-9]` idiom in
    /// SIPp's renegotiation scenarios). Done before rendering so the
    /// renderer stays pure.
    fn prepare_crypto(&mut self, call_id: &str, template: &MsgTemplate) {
        let mut fresh: Vec<(bool, u8)> = Vec::new();
        {
            let Some(call) = self.calls.get_mut(call_id) else {
                return;
            };
            for kw in template.keywords() {
                let Keyword::Crypto {
                    kw,
                    slot,
                    video,
                    offset,
                } = kw
                else {
                    continue;
                };
                let local = call.crypto.local_mut(*video, *slot);
                match kw {
                    CryptoKw::Tag => {}
                    CryptoKw::Suite(suite) => local.suite = Some(suite.clone()),
                    CryptoKw::Unencrypted(suite) => {
                        local.suite.get_or_insert_with(|| suite.clone());
                        local.unencrypted = true;
                    }
                    CryptoKw::KeyParams => {
                        if !(*offset < 0 && local.key.is_some()) {
                            fresh.push((*video, *slot));
                        }
                    }
                }
            }
        }
        for (video, slot) in fresh {
            let mut raw = [0u8; 30];
            self.rng.fill(&mut raw);
            if let Some(call) = self.calls.get_mut(call_id) {
                call.crypto.local_mut(video, slot).key =
                    Some(sipr_media::MasterKey::from_bytes(&raw));
            }
        }
    }

    /// `exec rtp_stream=`: start a generated stream, or pause/resume.
    fn on_rtp_stream(&mut self, call_id: &str, cmd: &RtpStreamCmd) {
        match cmd {
            RtpStreamCmd::Pause { video } => self.set_rtp_paused(call_id, *video, true),
            RtpStreamCmd::Resume { video } => self.set_rtp_paused(call_id, *video, false),
            RtpStreamCmd::Play {
                source,
                loops,
                payload_type,
                payload_name,
            } => self.start_rtp_stream(
                call_id,
                source,
                *loops,
                *payload_type,
                payload_name.as_deref(),
            ),
        }
    }

    fn set_rtp_paused(&self, call_id: &str, video: Option<bool>, paused: bool) {
        if let Some(m) = self.media.as_ref() {
            let tag = video.map(|v| if v { "rtp-video" } else { "rtp-audio" });
            m.set_paused(call_id, tag, paused);
        }
    }

    fn start_rtp_stream(
        &mut self,
        call_id: &str,
        source: &RtpSource,
        loops: i64,
        payload_type: Option<u8>,
        payload_name: Option<&str>,
    ) {
        let pt = payload_type.unwrap_or(self.rtp_payload);
        let params = match sipr_media::RtpParams::resolve(pt, payload_name) {
            Ok(p) => p,
            Err(e) => {
                // Validated at startup; only reachable if a default changed.
                self.log_err(&format!("call {call_id}: rtp_stream: {e}"));
                return;
            }
        };
        let data = match source {
            RtpSource::File(name) => match self.rtp_files.get(name) {
                Some(d) => Arc::clone(d),
                None => {
                    self.log_err(&format!(
                        "call {call_id}: rtp_stream: '{name}' was not loaded"
                    ));
                    return;
                }
            },
            RtpSource::Pattern { id, .. } => {
                match sipr_media::rtp::pattern_bytes(*id, params.bytes_per_packet) {
                    Some(d) => d,
                    None => return,
                }
            }
        };
        let kind = if params.video {
            MediaKind::Video
        } else {
            MediaKind::Audio
        };
        let tag = if params.video {
            "rtp-video"
        } else {
            "rtp-audio"
        };
        let Some(call) = self.calls.get(call_id) else {
            return;
        };
        let number = call.number;
        let Some(remote) = call.remote_media[kind.index()] else {
            self.log_err(&format!(
                "call {call_id}: rtp_stream: no remote {} endpoint yet (no SDP with a live \
                 m={} line received) — not streaming",
                kind.as_str(),
                kind.as_str()
            ));
            return;
        };
        // Send from the port the SDP advertised: the allocated
        // [rtpstream_*_port] when the scenario used it, else the
        // [media_port] form on that m= line.
        let local_port = call.rtpstream_ports[usize::from(params.video)].unwrap_or_else(|| {
            let (auto, offset) = self.port_layout[kind.index()];
            crate::render::media_port_value(self.media_port, auto, offset, number)
        });
        let ssrc = self
            .ssrc_base
            .wrapping_add(u32::try_from(2 * number.saturating_sub(1)).unwrap_or(0))
            .wrapping_add(u32::from(params.video));
        // SIPp derives the initial timestamp from the wall clock in ticks.
        let initial_ts =
            u32::try_from(self.stats.started.elapsed().as_millis() % u128::from(u32::MAX))
                .unwrap_or(0)
                .wrapping_mul(params.ticks_per_ms());
        let srtp = match call.crypto.negotiate(params.video) {
            Ok(pair) => {
                if let Some((tx, rx)) = &pair {
                    self.log_err(&format!(
                        "call {call_id}: rtp_stream: SRTP negotiated — send {} receive {}",
                        tx.suite().as_str(),
                        rx.suite().as_str()
                    ));
                }
                pair
            }
            Err(why) => {
                self.log_err(&format!(
                    "call {call_id}: rtp_stream: SRTP: {why} — streaming plain RTP"
                ));
                None
            }
        };
        let spec = StreamSpec {
            call_id: call_id.to_owned(),
            tag: tag.to_owned(),
            source: Source::Rtp(sipr_media::RtpSource::new(
                data, params, loops, ssrc, initial_ts,
            )),
            local_ip: self.media_ip,
            local_port,
            remote,
            srtp,
        };
        let Some(media) = self.media.as_ref() else {
            return;
        };
        match media.play(spec) {
            Ok(()) => self.stats.rtp_streams_started += 1,
            Err(e) => {
                let line = format!(
                    "call {call_id}: rtp_stream: cannot open media socket {}:{local_port} → \
                     {remote}: {e}",
                    self.media_ip
                );
                eprintln!("sipr: warning: {line}");
                self.log_err(&line);
            }
        }
    }

    /// `exec play_dtmf=`: generate the RFC 4733 burst and replay it on the
    /// audio stream (SIPp: same `play_args_a` path as `play_pcap_audio`).
    fn start_dtmf(&mut self, call_id: &str, value: &str) {
        let Some(call) = self.calls.get_mut(call_id) else {
            return;
        };
        self.dtmf_ssrc_counter = self.dtmf_ssrc_counter.wrapping_add(1);
        let ssrc = 0xD7F0_0000u32
            .wrapping_add(
                u32::try_from(call.number)
                    .unwrap_or(0)
                    .wrapping_mul(0x10000),
            )
            .wrapping_add(self.dtmf_ssrc_counter);
        let req = sipr_media::dtmf::DtmfRequest::parse(
            value,
            sipr_media::dtmf::DEFAULT_PAYLOAD_TYPE,
            ssrc,
            call.dtmf_seq,
        );
        let (stream, count) = sipr_media::dtmf::generate(&req);
        call.dtmf_seq = call.dtmf_seq.wrapping_add(count);
        let number = call.number;
        let remote = call.remote_media[MediaKind::Audio.index()];
        if stream.is_empty() {
            self.log_err(&format!(
                "call {call_id}: play_dtmf=\"{value}\": no valid digits — nothing sent"
            ));
            return;
        }
        let Some(remote) = remote else {
            self.log_err(&format!(
                "call {call_id}: play_dtmf: no remote audio endpoint yet — not playing"
            ));
            return;
        };
        let (auto, offset) = self.port_layout[MediaKind::Audio.index()];
        let local_port = crate::render::media_port_value(self.media_port, auto, offset, number);
        let spec = StreamSpec {
            call_id: call_id.to_owned(),
            tag: MediaKind::Audio.as_str().to_owned(),
            source: Source::Pcap(Arc::new(stream)),
            local_ip: self.media_ip,
            local_port,
            remote,
            srtp: None,
        };
        let Some(media) = self.media.as_ref() else {
            return;
        };
        match media.play(spec) {
            Ok(()) => self.stats.rtp_streams_started += 1,
            Err(e) => {
                let line = format!(
                    "call {call_id}: play_dtmf: cannot open media socket {}:{local_port} → \
                     {remote}: {e}",
                    self.media_ip
                );
                eprintln!("sipr: warning: {line}");
                self.log_err(&line);
            }
        }
    }

    // ---- media ---------------------------------------------------------

    /// `exec play_pcap_*`: replay `file` to the endpoint this call learned
    /// for `kind`. Non-blocking; a missing endpoint or a socket failure is
    /// logged and the call carries on (SIPp: warning, replay aborted).
    fn start_pcap(&mut self, call_id: &str, kind: MediaKind, file: &str) {
        let tag = kind.as_str();
        let Some(stream) = self.pcaps.get(file).cloned() else {
            self.log_err(&format!(
                "call {call_id}: play_pcap_{tag}: '{file}' was not loaded"
            ));
            return;
        };
        let Some(call) = self.calls.get(call_id) else {
            return;
        };
        let number = call.number;
        let remote = call.remote_media[kind.index()];
        let Some(remote) = remote else {
            self.log_err(&format!(
                "call {call_id}: play_pcap_{tag}: no remote {tag} endpoint yet (no SDP \
                 with a live m={tag} line received) — not playing"
            ));
            return;
        };
        let (auto, offset) = self.port_layout[kind.index()];
        let local_port = crate::render::media_port_value(self.media_port, auto, offset, number);
        let spec = StreamSpec {
            call_id: call_id.to_owned(),
            tag: tag.to_owned(),
            source: Source::Pcap(stream),
            local_ip: self.media_ip,
            local_port,
            remote,
            srtp: None,
        };
        let Some(media) = self.media.as_ref() else {
            return;
        };
        match media.play(spec) {
            Ok(()) => self.stats.rtp_streams_started += 1,
            Err(e) => {
                let line = format!(
                    "call {call_id}: play_pcap_{tag}: cannot open media socket \
                     {}:{local_port} → {remote}: {e}",
                    self.media_ip
                );
                eprintln!("sipr: warning: {line}");
                self.log_err(&line);
            }
        }
    }

    fn on_media_event(&mut self, ev: MediaEvent) {
        match ev {
            MediaEvent::Finished { .. } => {}
            MediaEvent::CheckResult {
                call_id,
                tag,
                video,
                sent,
                failed,
                bytes_in,
            } => {
                self.stats.rtp_bytes_received += bytes_in;
                // SIPp judges every stream against its tolerance (default
                // 1.0, so a peer that never echoes fails the run); sipr only
                // judges when a tolerance was asked for.
                let tolerance = if video {
                    self.config.video_tolerance
                } else {
                    self.config.audio_tolerance
                };
                if let Some(tol) = tolerance
                    && sent > 0
                {
                    #[allow(clippy::cast_precision_loss)]
                    let ratio = failed as f64 / sent as f64;
                    if ratio >= tol {
                        self.stats.rtp_check_failed += 1;
                        self.log_err(&format!(
                            "call {call_id}: {tag}: RTP check FAILED — {failed}/{sent} packets \
                             ({ratio:.2} ≥ tolerance {tol}); {bytes_in} bytes received"
                        ));
                    } else {
                        self.stats.rtp_check_ok += 1;
                    }
                }
            }
            MediaEvent::SendError {
                call_id,
                tag,
                error,
            } => {
                let line = format!(
                    "call {call_id}: play_pcap_{tag}: send failed: {error} — replay aborted"
                );
                eprintln!("sipr: warning: {line}");
                self.log_err(&line);
            }
        }
    }

    /// Render a call's template (a 3PCC `<sendCmd>` body) to a string, using
    /// the same keyword/variable context as message rendering.
    fn render_call_template(
        &self,
        call_id: &str,
        index: usize,
        template: &MsgTemplate,
    ) -> Option<String> {
        let call = self.calls.get(call_id)?;
        let remote_ip = call.render_remote.ip().to_string();
        let digest_uri = self.digest_uri(call.render_remote);
        let var_ctx = crate::render::VarCtx {
            store: &call.store,
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
            remote_port: call.render_remote.port(),
            local_ip: &self.local_ip_str,
            server_ip: self.server_ip_of(call),
            local_port: self.call_local_port(call),
            media_ip: &self.media_ip_str,
            media_port: self.media_port,
            rtpstream_ports: rtpstream_ports(call),
            crypto: Some(&call.crypto),
            transport: self.transport_token,
            call_id,
            call_number: call.number,
            user_id: call.user_id.map_or(0, |u| u as u64),
            users_total: self.config.users.map_or(0, |n| n as u64),
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
        Some(crate::render::render_to_string(template, &ctx, None))
    }

    /// Run a `<recvCmd>`'s actions against `cmd`, then advance the call. Returns
    /// true when a control-flow outcome (jump/fail/stop) already handled it.
    fn deliver_recv_cmd(
        &mut self,
        call_id: &str,
        index: usize,
        actions: &[Action],
        common: &StepCommon,
        cmd: &str,
    ) -> bool {
        if !actions.is_empty() && self.run_step_actions_inner(call_id, actions, index, Some(cmd)) {
            return true; // actions jumped/failed/stopped
        }
        let moved = self.calls.get(call_id).is_some_and(|c| c.index != index);
        if !moved {
            let jump = self.jump_target(common, index, call_id);
            if let Some(call) = self.calls.get_mut(call_id) {
                call.index = jump;
            }
        }
        false
    }

    /// A twin command arrived: hand it to a call blocked on `<recvCmd>`, or
    /// queue it until one is.
    fn on_twin_cmd(&mut self, cmd: String) {
        let waiting = self
            .calls
            .iter()
            .find(|(_, c)| c.awaiting_cmd)
            .map(|(id, _)| id.clone());
        let Some(call_id) = waiting else {
            self.pending_cmds.push_back(cmd);
            return;
        };
        let index = self.calls.get(&call_id).map_or(0, |c| c.index);
        let (actions, common) = match self.scenario_of(&call_id).steps.get(index) {
            Some(Step::RecvCmd {
                actions, common, ..
            }) => (actions, common),
            _ => {
                // The blocked call is not on a recvCmd anymore; re-queue.
                self.pending_cmds.push_back(cmd);
                return;
            }
        };
        if let Some(call) = self.calls.get_mut(&call_id) {
            call.awaiting_cmd = false;
        }
        if !self.deliver_recv_cmd(&call_id, index, actions, common, &cmd) {
            self.advance(&call_id);
        }
    }

    /// `-aa`: answer in-dialog OPTIONS/INFO/UPDATE/NOTIFY with 200 without
    /// disturbing the scenario. Returns true when handled.
    /// SIPp's `_unexp.main` label (`call.cpp` ~l.5449): an unexpected message
    /// jumps there, saving the interrupted step index in `_unexp.retaddr`
    /// and a running pause's deadline (ms since start, 0 = none) in
    /// `_unexp.pausedaddr`, then the message is offered to the handler
    /// (SIPp `queue_up`). Not re-entered while `_unexp.retaddr` is non-zero
    /// — SIPp's "already in a jump".
    fn try_unexpected_jump(&mut self, call_id: &str, packet: &sipr_net::InboundPacket) -> bool {
        let scenario = self.scenario_of(call_id);
        let Some(target) = scenario.unexpected_jump else {
            return false;
        };
        let started = self.stats.started;
        let Some(call) = self.calls.get_mut(call_id) else {
            return false;
        };
        // The step being interrupted: the running pause, else the recv.
        let interrupted = call.pause_deadline.map_or(call.index, |(i, _)| i);
        if let Some(v) = scenario.unexp_retaddr {
            if call.store.get(v).as_num() != 0.0 {
                return false;
            }
            #[allow(clippy::cast_precision_loss)]
            call.store
                .set(v, crate::actions::Value::Num(interrupted as f64));
        }
        if let Some(v) = scenario.unexp_pausedaddr {
            #[allow(clippy::cast_precision_loss)]
            let ms = call.pause_deadline.map_or(0.0, |(_, d)| {
                d.saturating_duration_since(started).as_millis() as f64
            });
            call.store.set(v, crate::actions::Value::Num(ms));
        }
        let pending = call.timer.take();
        call.generation += 1;
        call.pause_deadline = None;
        call.waiting = false;
        call.index = target;
        if let Some((timer, _)) = pending {
            self.timers.cancel(timer);
        }
        let what = packet.message.method().map_or_else(
            || format!("{:?}", packet.message.status_code()),
            ToOwned::to_owned,
        );
        self.log_err(&format!(
            "call {call_id}: unexpected {what} at index {interrupted}: jumping to _unexp.main"
        ));
        self.advance(call_id);
        self.on_packet(packet);
        true
    }

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
        let _ = self.send_for_call(call_id, &buf, remote, None);
        self.stats.auto_answered += 1;
        self.trace_send(&buf, remote);
        true
    }

    /// Open (or, past `-max_socket`, share) this call's socket in the
    /// per-call modes — SIPp's `connect_socket_if_needed` +
    /// `new_sipp_call_socket`. No-op elsewhere.
    fn ensure_call_socket(&mut self, call_id: &str) -> Result<(), String> {
        if self.config.transport == TransportKind::UdpPerIp && self.scenario.role == Role::Uac {
            return self.ensure_per_ip_socket(call_id);
        }
        if !(self.per_call || self.rsa_server) {
            return Ok(());
        }
        let Some(call) = self.calls.get(call_id) else {
            return Ok(());
        };
        if call.socket.is_some() {
            return Ok(());
        }
        let remote = call.remote;
        // SIPp: one `main_remote_socket` for every -rsa server call unless
        // the transport is per-call.
        let cap = if self.rsa_server && !self.config.transport.per_call() {
            1
        } else {
            self.max_socket
        };
        // Sockets whose last call ended are gone; the rest can be shared.
        self.call_socket_pool.retain(|w| w.upgrade().is_some());
        let socket = if self.call_socket_pool.len() >= cap {
            let i = self.next_shared_socket % self.call_socket_pool.len();
            self.next_shared_socket = self.next_shared_socket.wrapping_add(1);
            self.call_socket_pool[i]
                .upgrade()
                .ok_or_else(|| "no call socket left to share".to_owned())?
        } else {
            let opened = match &self.transport {
                Transport::Udp(u) => u
                    .open_call_socket()
                    .map(|s| CallSocket::Udp(Arc::new(s)))
                    .map_err(|e| format!("cannot open a UDP call socket: {e}"))?,
                Transport::Tcp(t) => t
                    .connect_call(remote)
                    .map(|c| CallSocket::Tcp(Arc::new(c)))
                    .map_err(|e| format!("cannot connect TCP to {remote}: {e}"))?,
                Transport::Tls(t) => t
                    .connect_call(remote)
                    .map(|c| CallSocket::Tls(Arc::new(c)))
                    .map_err(|e| format!("cannot connect TLS to {remote}: {e}"))?,
                #[cfg(feature = "sctp")]
                Transport::Sctp(t) => t
                    .connect_call(remote)
                    .map(|c| CallSocket::Sctp(Arc::new(c)))
                    .map_err(|e| format!("cannot connect SCTP to {remote}: {e}"))?,
            };
            self.call_socket_pool.push(opened.downgrade());
            opened
        };
        if let Some(call) = self.calls.get_mut(call_id) {
            call.socket = Some(socket);
        }
        Ok(())
    }

    /// `-t ui` client (SIPp `connect_socket_if_needed`, `peripsocket`): the
    /// call sends from the IP in its injection line's `-ip_field` column —
    /// the main socket when that is its IP, else a socket bound to
    /// `ip:port` that is created once and kept for the run (`map_perip_fd`).
    /// An unbindable IP is fatal, as SIPp's "Unable to bind UDP socket".
    fn ensure_per_ip_socket(&mut self, call_id: &str) -> Result<(), String> {
        let Some(call) = self.calls.get(call_id) else {
            return Ok(());
        };
        if call.socket.is_some() {
            return Ok(());
        }
        let line = call.field_lines.first().copied().flatten();
        let raw = self
            .inf_files
            .first()
            .and_then(|f| {
                f.borrow()
                    .field(line?, self.config.ip_field)
                    .map(|v| v.trim().to_owned())
            })
            .unwrap_or_default();
        let ip: IpAddr = raw
            .parse()
            .map_err(|_| format!("-t ui: '{raw}' (-ip_field) is not an IP address"))?;
        let main_addr = self.transport.local_addr();
        let socket = if ip == main_addr.ip() {
            None
        } else if let Some(existing) = self.ip_sockets.get(&ip) {
            Some(CallSocket::Udp(Arc::clone(existing)))
        } else {
            let Transport::Udp(udp) = &self.transport else {
                return Err("-t ui is UDP only".into());
            };
            match udp.open_call_socket_at(SocketAddr::new(ip, main_addr.port())) {
                Ok(sock) => {
                    let sock = Arc::new(sock);
                    self.ip_sockets.insert(ip, Arc::clone(&sock));
                    Some(CallSocket::Udp(sock))
                }
                Err(e) => {
                    let msg = format!("Unable to bind UDP socket {ip}:{}: {e}", main_addr.port());
                    eprintln!("sipr: error: {msg}");
                    self.log_err(&msg);
                    self.fatal = Some(msg.clone());
                    self.hard_stop = true;
                    return Err(msg);
                }
            }
        };
        if let Some(call) = self.calls.get_mut(call_id) {
            call.socket = socket;
            call.server_ip = ip.to_string();
        }
        Ok(())
    }

    /// Send on the call's own socket when it has one, else the shared
    /// transport. A send on a dropped mono client connection first goes
    /// through SIPp's reset (`-max_reconnect`/`-reconnect_sleep`): re-dial
    /// and retry, or end the run when the budget is spent.
    fn send_for_call(
        &mut self,
        call_id: &str,
        data: &[u8],
        to: SocketAddr,
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        let own = self.calls.get(call_id).and_then(|c| c.socket.as_ref());
        match (own, &self.transport) {
            (Some(CallSocket::Udp(s)), Transport::Udp(u)) => {
                return u.send_via(s, data, to, lost_pct);
            }
            (Some(CallSocket::Tcp(c)), Transport::Tcp(t)) => {
                return t.send_via(c, data, lost_pct);
            }
            (Some(CallSocket::Tls(c)), Transport::Tls(t)) => {
                return t.send_via(c, data, lost_pct);
            }
            #[cfg(feature = "sctp")]
            (Some(CallSocket::Sctp(c)), Transport::Sctp(t)) => {
                return t.send_via(c, data, lost_pct);
            }
            _ => {}
        }
        if !self.send_may_reconnect(to) {
            return self.transport.send_to(data, to, lost_pct);
        }
        // SIPp: writing to an invalid socket is EPIPE — the call fails and
        // the socket is queued for a reset; no retry for this send.
        let result = if self.mono_conn_invalid {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "connection closed",
            ))
        } else {
            self.transport.send_to(data, to, lost_pct)
        };
        if let Err(e) = &result
            && matches!(
                e.kind(),
                std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            )
        {
            self.mono_conn_invalid = true;
            self.pending_reset = Some(to);
        }
        result
    }

    /// SIPp `send_raw` after a failed write: the call fails
    /// (`E_FAILED_CANNOT_SEND_MSG`), then the main loop resets the dead
    /// connection for the calls that follow.
    fn after_send_failure(&mut self, call_id: &str, e: &std::io::Error) {
        if self.calls.contains_key(call_id) {
            self.call_stats(call_id).failed_cannot_send += 1;
            self.log_err(&format!("call {call_id} failed: cannot send message: {e}"));
            self.remove_call(call_id);
        }
        if let Some(peer) = self.pending_reset.take() {
            self.reset_mono_connection(peer);
        }
    }

    /// The mono client TCP/TLS connection to `to` is the one `-max_reconnect`
    /// manages (servers and per-call sockets are not re-dialed).
    fn send_may_reconnect(&self, to: SocketAddr) -> bool {
        !self.per_call
            && self.scenario.role == Role::Uac
            && !matches!(self.transport, Transport::Udp(_))
            && self
                .config
                .target
                .is_some_and(|t| self.config.remote_sending_addr.unwrap_or(t) == to)
    }

    fn reconnect_allowed(&self) -> bool {
        self.reconnects_left == -1 || self.reconnects_left > 0
    }

    /// SIPp's `SIPpSocket::reset_connection`: spend one reconnection (or end
    /// the run — "Max number of reconnections reached"), close the calls on
    /// the connection when `-reconnect_close`, sleep `-reconnect_sleep`,
    /// re-dial. Returns whether the connection is usable again.
    fn reset_mono_connection(&mut self, peer: SocketAddr) -> bool {
        if !self.reconnect_allowed() {
            let msg = "Max number of reconnections reached".to_owned();
            eprintln!("sipr: error: {msg}");
            self.log_err(&msg);
            self.fatal = Some(msg);
            self.fail_all("connection lost");
            self.hard_stop = true;
            return false;
        }
        if self.reconnects_left > 0 {
            self.reconnects_left -= 1;
        }
        if self.config.reconnect_close {
            self.close_calls_to(peer);
        }
        std::thread::sleep(self.config.reconnect_sleep);
        let result = match &self.transport {
            Transport::Tcp(t) => t.reconnect(peer),
            Transport::Tls(t) => t.reconnect(peer),
            #[cfg(feature = "sctp")]
            Transport::Sctp(t) => t.reconnect(peer),
            Transport::Udp(_) => Ok(()),
        };
        match result {
            Ok(()) => {
                self.mono_conn_invalid = false;
                self.log_err("Socket required a reconnection.");
                eprintln!("sipr: warning: socket required a reconnection");
                true
            }
            Err(e) => {
                let line = format!("Could not reconnect TCP socket: {e}");
                eprintln!("sipr: warning: {line}");
                self.log_err(&line);
                self.close_calls_to(peer);
                false
            }
        }
    }

    /// SIPp's `close_calls()` for one connection: every call sending to
    /// `peer` on the shared connection fails with `E_FAILED_TCP_CLOSED`.
    fn close_calls_to(&mut self, peer: SocketAddr) {
        let ids: Vec<String> = self
            .calls
            .iter()
            .filter(|(_, c)| c.remote == peer && c.socket.is_none())
            .map(|(id, _)| id.clone())
            .collect();
        self.close_calls(ids);
    }

    /// Fail `ids` because their connection went away — except calls already
    /// past their last step: SIPp keeps those only "for handling final
    /// retransmissions. If the connection closes, we do not mark it as
    /// failed" (`call.cpp` timewait), so they complete instead.
    fn close_calls(&mut self, ids: Vec<String>) {
        let (done, live): (Vec<String>, Vec<String>) = ids
            .into_iter()
            .partition(|id| self.calls.get(id).is_some_and(|c| c.completing));
        for id in done {
            self.complete_call(&id);
        }
        if live.is_empty() {
            return;
        }
        self.log_err("Closing calls, because of TCP reset or close!");
        for id in live {
            self.call_stats(&id).failed_tcp_closed += 1;
            self.log_err(&format!("call {id} failed: TCP connection closed"));
            self.remove_call(&id);
        }
    }

    /// A TCP/TLS connection ended (`NetEvent::Disconnected`). SIPp
    /// (`socket.cpp` ~l.1940-1970): a clean close invalidates the socket and,
    /// with `-reconnect_close`, closes its calls — the next send re-dials; an
    /// error close additionally resets the connection right away. Per-call
    /// connections drop the call's socket so its next send re-dials; a
    /// server never re-dials (and, unlike SIPp, never dies) when a client
    /// goes away.
    fn on_disconnected(&mut self, peer: SocketAddr, local: SocketAddr, clean: bool) {
        let what = if clean {
            format!("TCP connection with {peer} closed by the peer")
        } else {
            format!("Error on TCP connection with {peer}, remote peer probably closed the socket")
        };
        self.log_err(&what);
        if !self.per_call {
            self.transport.forget(peer);
        }
        if self.per_call {
            let ids: Vec<String> = self
                .calls
                .iter()
                .filter(|(_, c)| {
                    c.socket
                        .as_ref()
                        .is_some_and(|s| s.local_port() == local.port())
                })
                .map(|(id, _)| id.clone())
                .collect();
            if self.config.reconnect_close {
                self.close_calls(ids);
            } else {
                for id in ids {
                    if let Some(call) = self.calls.get_mut(&id) {
                        call.socket = None; // the next send dials afresh
                    }
                }
            }
            return;
        }
        if self.config.reconnect_close {
            self.close_calls_to(peer);
        }
        if self.send_may_reconnect(peer) {
            self.mono_conn_invalid = true;
            if !clean {
                self.reset_mono_connection(peer);
            }
        }
    }

    /// `[server_ip]`: the IP this call's messages leave from — the per-IP
    /// or receiving socket under `-t ui`, else the main socket's.
    fn server_ip_of<'c>(&'c self, call: &'c CallState) -> &'c str {
        if call.server_ip.is_empty() {
            &self.local_ip_str
        } else {
            &call.server_ip
        }
    }

    /// `[local_port]`: the call's own socket in the per-call client modes
    /// (SIPp's `call_port`), else the transport's.
    fn call_local_port(&self, call: &CallState) -> u16 {
        if !self.per_call {
            return self.transport.local_addr().port(); // servers: `-p`, as SIPp
        }
        call.socket.as_ref().map_or_else(
            || self.transport.local_addr().port(),
            CallSocket::local_port,
        )
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
                let mandatory = self.window_mandatory(call_id, index);
                if let Some((mi, _)) = mandatory {
                    if let Some(s) = self.call_stats(call_id).step_mut(mi) {
                        s.timeouts += 1;
                    }
                }
                let scenario = self.scenario_of(call_id);
                let ontimeout = mandatory.and_then(|(mi, _)| match &scenario.steps[mi] {
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
            TimerKind::Pause => {
                if let Some(call) = self.calls.get_mut(call_id) {
                    call.pause_deadline = None;
                }
                self.advance(call_id);
            }
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
        if let Some(s) = self.call_stats(call_id).step_mut(msg_index) {
            s.retrans += 1;
        }
        let Some(remote) = self.calls.get(call_id).map(|c| c.remote) else {
            return;
        };
        if let Err(e) = self.send_for_call(call_id, &buf, remote, lost) {
            self.after_send_failure(call_id, &e);
            return;
        }
        self.call_stats(call_id).retrans_sent += 1;
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
            self.stop_media(call_id);
            self.forget_ooc(&call);
            let stats = self.stats_of(call.ooc);
            stats.successful += 1;
            stats.record_call_length(call.started.elapsed());
            self.return_user(&call);
        }
    }

    /// Keep the ooc live count in step when an ooc call leaves the table.
    fn forget_ooc(&mut self, call: &CallState) {
        if call.ooc {
            self.ooc_live = self.ooc_live.saturating_sub(1);
        }
    }

    /// Remove a call and record its duration WITHOUT bumping a failure
    /// counter — the caller has already categorized the failure.
    fn remove_call(&mut self, call_id: &str) {
        if let Some(mut call) = self.calls.remove(call_id) {
            self.cancel_call_timers(&mut call);
            self.stop_media(call_id);
            self.forget_ooc(&call);
            self.stats_of(call.ooc)
                .record_call_length(call.started.elapsed());
            self.return_user(&call);
        }
    }

    /// A call that ends takes its media with it (SIPp joins the media thread
    /// in the call destructor).
    fn stop_media(&mut self, call_id: &str) {
        if let Some(m) = self.media.as_ref() {
            m.stop(call_id, None);
        }
        self.call_echoes.retain(|(id, _), _| id != call_id);
    }

    /// Return a finished call's user id to the free pool (`-users` mode), so a
    /// replacement call can reuse it.
    fn return_user(&mut self, call: &CallState) {
        if let Some(uid) = call.user_id
            && self.config.users.is_some_and(|target| uid <= target)
        {
            self.free_users.push_back(uid);
        }
    }

    fn fail_call(&mut self, call_id: &str, reason: &str) {
        if self.calls.contains_key(call_id) {
            let stats = self.call_stats(call_id);
            match reason {
                r if r.contains("retransmissions") => stats.failed_retrans += 1,
                r if r.contains("timeout") => stats.failed_timeout += 1,
                _ => stats.failed_other += 1,
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
        Step::Pause { common, .. }
        | Step::Nop { common, .. }
        | Step::SendCmd { common, .. }
        | Step::RecvCmd { common, .. } => Some(common),
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
    // `display="…"` replaces the derived label (SIPp shows it verbatim).
    if let Some(d) = step_common(step).and_then(|c| c.display.as_deref()) {
        return d.to_owned();
    }
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
        Step::SendCmd { .. } => "sendCmd".to_owned(),
        Step::RecvCmd { .. } => "recvCmd".to_owned(),
        Step::Label { id, .. } => format!("label {id}"),
        Step::Timewait { ms, .. } => format!("timewait {ms}ms"),
    }
}

/// `-t s1|sn`: the SCTP transport, when sipr was built with the `sctp`
/// feature and the host has an SCTP stack (SIPp without `USE_SCTP` says
/// "SCTP support is not enabled!" at the same point).
#[cfg(feature = "sctp")]
fn build_sctp_transport(
    config: &EngineConfig,
    tcfg: &TransportConfig,
    net_tx: std::sync::mpsc::Sender<NetEvent>,
    role: Role,
    per_call: bool,
) -> Result<(Transport, &'static str, bool), EngineError> {
    if !sipr_net::sctp::available() {
        return Err(EngineError(
            "SCTP is not supported on this host (the kernel has no SCTP stack; Linux needs the \
             `sctp` module)"
                .into(),
        ));
    }
    let t = match role {
        Role::Uac if per_call => SctpTransport::client_pool(tcfg, net_tx),
        Role::Uac => {
            let remote = config
                .target
                .ok_or_else(|| EngineError("SCTP UAC needs a remote target".into()))?;
            let remote = config.remote_sending_addr.unwrap_or(remote);
            SctpTransport::connect(tcfg, net_tx, remote)
                .map_err(|e| EngineError(format!("cannot connect SCTP to {remote}: {e}")))?
        }
        Role::Uas => SctpTransport::listen(tcfg, net_tx)
            .map_err(|e| EngineError(format!("cannot bind SCTP listener: {e}")))?,
    };
    Ok((Transport::Sctp(t), "SCTP", true))
}

/// `-t s1|sn` in a build without the `sctp` feature.
#[cfg(not(feature = "sctp"))]
fn build_sctp_transport(
    _config: &EngineConfig,
    _tcfg: &TransportConfig,
    _net_tx: std::sync::mpsc::Sender<NetEvent>,
    _role: Role,
    _per_call: bool,
) -> Result<(Transport, &'static str, bool), EngineError> {
    Err(EngineError(
        "SCTP support is not enabled: rebuild sipr with `--features sctp` (Linux only at run time)"
            .into(),
    ))
}

/// Fresh call state.
#[allow(clippy::too_many_arguments)]
fn new_call(
    number: u64,
    remote: SocketAddr,
    render_remote: SocketAddr,
    base_cseq: u32,
    vars: &sipr_scenario::model::VarTable,
    cnonce: String,
    field_lines: Vec<Option<usize>>,
    user_id: Option<usize>,
) -> CallState {
    CallState {
        number,
        remote,
        index: 0,
        waiting: false,
        awaiting_cmd: false,
        user_id,
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
        remote_media: [None; 3],
        rtpstream_ports: [None; 2],
        crypto: crate::render::CallCrypto::default(),
        dtmf_seq: DTMF_FIRST_SEQ,
        last_recv_key: None,
        retrans: None,
        timer: None,
        generation: 0,
        pause_deadline: None,
        paused_until: None,
        socket: None,
        render_remote,
        server_ip: String::new(),
        ooc: false,
    }
}

/// A scenario's own stat set: repartitions and per-step counters/labels.
fn new_stat_set(scenario: &Scenario) -> sipr_stats::StatSet {
    let mut stats = sipr_stats::StatSet::new(
        &scenario.response_time_repartition,
        &scenario.call_length_repartition,
    );
    stats.init_steps(scenario.steps.iter().map(step_label).collect());
    stats.set_step_hidden(
        scenario
            .steps
            .iter()
            .map(|s| step_common(s).is_some_and(|c| c.hide))
            .collect(),
    );
    stats
}

/// The stat set a call's events land on (SIPp: each scenario owns its
/// `CStat`), as a free function for the spots that already hold a `&mut`
/// into the call table.
fn stats_for<'a>(
    main: &'a mut sipr_stats::StatSet,
    ooc: Option<&'a mut OocScenario<'_>>,
    is_ooc: bool,
) -> &'a mut sipr_stats::StatSet {
    match ooc {
        Some(o) if is_ooc => &mut o.stats,
        _ => main,
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
        // `regexp_match`: SIPp `matches_scenario` searches the method (and,
        // below, the decimal status code) with the unanchored regex.
        Expect::Request(m) => match (&step.expect_regex, msg.method()) {
            (Some(re), Some(method)) => re.find(method.as_bytes()).is_some(),
            (None, method) => method == Some(m.as_str()),
            (Some(_), None) => false,
        },
        Expect::Response(code) => {
            let Some(actual) = msg.status_code() else {
                return false;
            };
            let code_matches = match &step.expect_regex {
                Some(re) => {
                    let (digits, len) = decimal_digits(actual);
                    re.find(&digits[..len]).is_some()
                }
                None => code.parse::<u16>() == Ok(actual),
            };
            if !code_matches {
                return false;
            }
            // SIPp guard: beyond index 0, the response's CSeq method must
            // match the nearest preceding request (call.cpp
            // recv_response_for_cseq_method_list).
            if index == 0 {
                return true;
            }
            match expected_method.and_then(Option::as_deref) {
                // strstr, as SIPp: the method must occur in the sent-so-far list.
                Some(expected) => msg.cseq().is_some_and(|(_, m)| expected.contains(m)),
                None => true,
            }
        }
    }
}

/// A status code as ASCII digits without allocating (hot path: a
/// `regexp_match` response recv runs per inbound message).
fn decimal_digits(mut n: u16) -> ([u8; 5], usize) {
    let mut buf = [0u8; 5];
    let mut end = buf.len();
    loop {
        end -= 1;
        #[allow(clippy::cast_possible_truncation)]
        {
            buf[end] = b'0' + (n % 10) as u8;
        }
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let len = buf.len() - end;
    buf.copy_within(end.., 0);
    (buf, len)
}

/// For every step, the method of the nearest preceding request `<send>`.
/// SIPp's `recv_response_for_cseq_method_list` (`scenario.cpp` ~l.893): the
/// methods of **every** request sent so far, concatenated; a response
/// matches a recv when its CSeq method occurs in that list (`strstr`). So
/// after `INVITE … PRACK`, both the PRACK's 200 and the INVITE's 200 match
/// the following `recv response="200"` steps.
fn precompute_cseq_methods(scenario: &Scenario) -> Vec<Option<String>> {
    let mut out = Vec::with_capacity(scenario.steps.len());
    let mut list: Option<String> = None;
    for step in &scenario.steps {
        if let Step::Send(s) = step
            && let Some(word) = template_first_word(&s.template)
            && word != "SIP/2.0"
        {
            list.get_or_insert_with(String::new).push_str(&word);
        }
        out.push(list.clone());
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

/// Learn where the peer wants media from a received message's SDP —
/// SIPp's `get_remote_media_addr`: any response with a body, or an
/// INVITE/ACK/PRACK request. Streams absent from this SDP keep their
/// previous endpoint.
fn learn_remote_media(call: &mut CallState, msg: &Inbound) {
    let body = msg.body();
    if body.is_empty() {
        return;
    }
    if msg.status_code().is_none() && !matches!(msg.method(), Some("INVITE" | "ACK" | "PRACK")) {
        return;
    }
    for kind in MediaKind::ALL {
        if let Some(addr) = sipr_media::sdp::remote_endpoint(body, kind.as_str()) {
            call.remote_media[kind.index()] = Some(addr);
        }
        if kind != MediaKind::Image {
            let attrs: Vec<CryptoAttr> = sipr_media::sdp::crypto_attributes(body, kind.as_str());
            if !attrs.is_empty() {
                call.crypto.set_remote(kind == MediaKind::Video, attrs);
            }
        }
    }
}

/// Which `[media_port]` form each `m=<kind>` line of the scenario's SDP
/// uses: `(auto_media_port?, +offset)`. That rendered port is the local
/// port the kind's replay must send from, so the peer sees RTP coming from
/// the port we advertised. SIPp discovers this at render time by scanning
/// the output buffer backwards for "audio"/"video"/"image"; the templates
/// are pre-tokenized here, so it is read off the spans once. Defaults to
/// plain `[media_port]` for a kind the SDP never mentions.
fn media_port_layout(scenario: &Scenario) -> [(bool, u16); 3] {
    let mut layout = [(false, 0u16); 3];
    let mut found = [false; 3];
    for step in &scenario.steps {
        let Step::Send(send) = step else { continue };
        let mut line = String::new();
        for span in &send.template.spans {
            match span {
                Span::Lit(text) => match text.rfind('\n') {
                    Some(pos) => line = text[pos + 1..].to_owned(),
                    None => line.push_str(text),
                },
                Span::Kw(Keyword::MediaPort { auto, offset }) => {
                    let head = line.trim_start();
                    for kind in MediaKind::ALL {
                        if head.starts_with(&format!("m={} ", kind.as_str()))
                            && !found[kind.index()]
                        {
                            found[kind.index()] = true;
                            layout[kind.index()] = (*auto, *offset);
                        }
                    }
                    line.push('?');
                }
                Span::Kw(_) => line.push('?'),
            }
        }
    }
    layout
}

/// One ramp tick (SIPp `ratetask::run`): the new rate, and whether the
/// cap was exceeded and `rate_quit` asks to stop. Reaching the cap exactly
/// does not quit; only the tick that would go past it does.
fn ramp_step(rate: f64, increase: f64, max: Option<f64>, quit: bool) -> (f64, bool) {
    let mut next = rate + increase;
    match max {
        Some(m) if next > m => {
            next = m;
            (next, quit)
        }
        _ => (next, false),
    }
}

/// The call's allocated rtpstream ports for rendering (0 = none yet).
fn rtpstream_ports(call: &CallState) -> [u16; 2] {
    [
        call.rtpstream_ports[0].unwrap_or(0),
        call.rtpstream_ports[1].unwrap_or(0),
    ]
}

/// Load every `rtp_stream` file once (WAV header skipped, like SIPp's
/// `rtpstream_cache_file`) and validate every play command's codec
/// parameters, so a bad scenario fails before any call starts.
fn load_rtp_files(
    scenario: &Scenario,
    config: &EngineConfig,
) -> Result<HashMap<String, Arc<[u8]>>, EngineError> {
    let default_pt = config.rtp_payload.unwrap_or(DEFAULT_RTP_PAYLOAD);
    let mut files: HashMap<String, Arc<[u8]>> = HashMap::new();
    for cmd in scenario.rtp_stream_plays() {
        let RtpStreamCmd::Play {
            source,
            payload_type,
            payload_name,
            ..
        } = cmd
        else {
            continue;
        };
        let params = sipr_media::RtpParams::resolve(
            payload_type.unwrap_or(default_pt),
            payload_name.as_deref(),
        )
        .map_err(|e| EngineError(format!("exec rtp_stream=: {e}")))?;
        match source {
            RtpSource::Pattern { video, id } => {
                if *video != params.video {
                    eprintln!(
                        "sipr: warning: rtp_stream {}pattern {id} with an {} payload type — \
                         the payload decides the stream (SIPp does the same)",
                        if *video { "v" } else { "a" },
                        if params.video { "video" } else { "audio" }
                    );
                }
            }
            RtpSource::File(name) => {
                if files.contains_key(name) {
                    continue;
                }
                let path = resolve_media_file(name, config.scenario_dir.as_deref());
                let bytes = std::fs::read(&path).map_err(|e| {
                    EngineError(format!(
                        "exec rtp_stream=: cannot read '{name}' ({}): {e}",
                        path.display()
                    ))
                })?;
                let data = sipr_media::rtp::stream_bytes(&bytes);
                if data.len() < params.bytes_per_packet {
                    eprintln!(
                        "sipr: warning: rtp_stream '{name}' is shorter than one packet ({} < {} \
                         bytes)",
                        data.len(),
                        params.bytes_per_packet
                    );
                }
                files.insert(name.clone(), data);
            }
        }
    }
    Ok(files)
}

/// Resolve and parse every `play_pcap_*` file once. A missing or malformed
/// capture is fatal before any call starts (SIPp: fatal at scenario parse).
fn load_pcaps(
    scenario: &Scenario,
    config: &EngineConfig,
) -> Result<HashMap<String, Arc<PcapStream>>, EngineError> {
    let mut pcaps: HashMap<String, Arc<PcapStream>> = HashMap::new();
    for (kind, file) in scenario.pcap_actions() {
        if pcaps.contains_key(file) {
            continue;
        }
        let path = resolve_media_file(file, config.scenario_dir.as_deref());
        let bytes = std::fs::read(&path).map_err(|e| {
            EngineError(format!(
                "play_pcap_{}: cannot read '{file}' ({}): {e}",
                kind.as_str(),
                path.display()
            ))
        })?;
        let stream = sipr_media::pcap::parse(&bytes).map_err(|e| {
            EngineError(format!(
                "play_pcap_{}: cannot load '{file}' ({}): {e}",
                kind.as_str(),
                path.display()
            ))
        })?;
        if stream.is_empty() {
            eprintln!(
                "sipr: warning: pcap '{file}' contains no UDP packets — play_pcap_{} will \
                 send nothing",
                kind.as_str()
            );
        } else if stream.skipped > 0 {
            eprintln!(
                "sipr: pcap '{file}': {} packets, {} non-UDP packets skipped",
                stream.len(),
                stream.skipped
            );
        }
        pcaps.insert(file.to_owned(), Arc::new(stream));
    }
    Ok(pcaps)
}

/// SIPp `find_file`: absolute paths as-is; otherwise next to the scenario
/// file when that exists, else relative to the working directory (with the
/// same warning SIPp prints when it falls back).
fn resolve_media_file(file: &str, scenario_dir: Option<&std::path::Path>) -> std::path::PathBuf {
    let raw = std::path::Path::new(file);
    if raw.is_absolute() {
        return raw.to_path_buf();
    }
    if let Some(dir) = scenario_dir {
        let beside = dir.join(raw);
        if beside.is_file() {
            return beside;
        }
        if !dir.as_os_str().is_empty() {
            eprintln!(
                "sipr: warning: '{file}' not found next to the scenario ({}); trying the \
                 working directory",
                dir.display()
            );
        }
    }
    raw.to_path_buf()
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
    fn cseq_method_guard_follows_sipps_sent_method_list() {
        let sc = uac();
        let methods = precompute_cseq_methods(&sc);
        // Window at step 8 (recv 200 after BYE). SIPp's guard is a strstr
        // over every method sent so far ("INVITEACKBYE"): a late 200 for
        // the INVITE still matches, and so does the BYE's 200 …
        assert!(matches!(
            scan_for_match(&sc, &methods, 8, true, &response(200, "INVITE", true)),
            Scan::Forward(8)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, 8, true, &response(200, "BYE", true)),
            Scan::Forward(8)
        ));
        // … but a response to a method never sent cannot.
        assert!(matches!(
            scan_for_match(&sc, &methods, 8, true, &response(200, "OPTIONS", true)),
            Scan::NoMatch
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
    fn regexp_match_searches_the_method_and_the_status_code() {
        let xml = r#"<scenario name="re">
  <recv request="OPTIONS|INFO" regexp_match="true"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:]
    [last_Call-ID:]
    [last_CSeq:]
    Content-Length: 0

  ]]></send>
  <send><![CDATA[
    INVITE sip:a SIP/2.0
    Via: SIP/2.0/UDP h;branch=[branch]
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Content-Length: 0

  ]]></send>
  <recv response="18[0-9]" regexp_match="true" optional="true"/>
  <recv response="^2" regexp_match="true"/>
</scenario>"#;
        let sc = sipr_scenario::compile("re", xml).scenario.unwrap();
        let methods = precompute_cseq_methods(&sc);
        let request = |m: &str| {
            Inbound::parse(
                format!(
                    "{m} sip:b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK-9\r\n\
                     From: <sip:a>;tag=t\r\nTo: <sip:b>\r\nCall-ID: c9\r\nCSeq: 3 {m}\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap()
        };
        assert!(matches!(
            scan_for_match(&sc, &methods, 0, true, &request("INFO")),
            Scan::Forward(0)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, 0, true, &request("OPTIONS")),
            Scan::Forward(0)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, 0, true, &request("BYE")),
            Scan::NoMatch
        ));
        // Responses: the regex runs over the decimal code, unanchored.
        assert!(matches!(
            scan_for_match(&sc, &methods, 3, true, &response(183, "INVITE", false)),
            Scan::Forward(3)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, 3, true, &response(200, "INVITE", true)),
            Scan::Forward(4)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, 3, true, &response(486, "INVITE", true)),
            Scan::NoMatch
        ));
        let digits = |n: u16| {
            let (buf, len) = decimal_digits(n);
            String::from_utf8_lossy(&buf[..len]).into_owned()
        };
        assert_eq!(digits(0), "0");
        assert_eq!(digits(486), "486");
        assert_eq!(digits(65535), "65535");
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
        // SIPp concatenates every request method sent so far.
        assert_eq!(m[8].as_deref(), Some("INVITEACKBYE")); // final recv 200
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
    fn ramp_step_follows_sipp_ratetask() {
        assert_eq!(ramp_step(10.0, 5.0, None, true), (15.0, false));
        assert_eq!(ramp_step(10.0, 5.0, Some(100.0), true), (15.0, false));
        // Reaching the cap exactly: no quit yet.
        assert_eq!(ramp_step(95.0, 5.0, Some(100.0), true), (100.0, false));
        // Going past it: clamp and quit (unless -no_rate_quit).
        assert_eq!(ramp_step(100.0, 5.0, Some(100.0), true), (100.0, true));
        assert_eq!(ramp_step(100.0, 5.0, Some(100.0), false), (100.0, false));
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
