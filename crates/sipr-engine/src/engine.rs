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
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sipr_control::{ControlCmd, ControlLink, ControlRequest, ControlState, Quitting};
use sipr_media::sdp::CryptoAttr;
use sipr_media::{MediaEvent, MediaPlayer, PcapStream, Source, StreamSpec};
use sipr_net::timer::TimerId;
use sipr_net::{
    Inbound, NetEvent, PeerLinks, RetransCaps, RetransSchedule, TcpCallConn, TcpTransport,
    TimerService, TlsCallConn, TlsTransport, TransportConfig, TwinChannel, TwinEvent,
    UdpCallSocket, UdpTransport,
};
#[cfg(feature = "sctp")]
use sipr_net::{SctpCallConn, SctpTransport};
use sipr_scenario::inject::{InjectMode, InjectionFile};
use sipr_scenario::model::{
    Action, Expect, MediaKind, PauseSpec, RecvStep, Role, RtpEchoCmd, RtpEchoVerb, RtpSource,
    RtpStreamCmd, Scenario, SendStep, Step, StepCommon, TxnId,
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
    /// `-rxinf`: further injection files, loaded after the `-inf` ones into
    /// the same table (SIPp's shared `inFiles` map) and reachable by name
    /// from either scenario; a bare `[fieldN]` still means the first `-inf`.
    pub rx_inf_files: Vec<std::path::PathBuf>,
    /// `-infindex FILE FIELD`: build a lookup index on `FIELD` of the injection
    /// file named `FILE` (matched by basename), enabling `<lookup>`.
    pub inf_index: Vec<(String, usize)>,
    /// `-t`: which transport to run.
    pub transport: TransportKind,
    /// `-3pcc HOST:PORT`: the twin control socket for classic 3PCC. The role
    /// (dial vs listen) is derived from the scenario's first twin command.
    pub twin_addr: Option<SocketAddr>,
    /// Extended 3PCC (`-slave_cfg` with `-master NAME` or `-slave NAME`):
    /// this instance's name and role, and every named peer's address.
    pub extended_3pcc: Option<Extended3pcc>,
    /// `-users N`: closed-loop mode — keep N concurrent calls, each holding a
    /// 1-based user id (drives `[userid]`/`[users]` and USER injection files).
    pub users: Option<usize>,
    /// `-set VARIABLE VALUE`: initial values of `<Global>` variables.
    pub global_sets: Vec<(String, String)>,
    /// `[remote_host]`: the target host as typed on the command line.
    pub remote_host: String,
    /// `-key KEYWORD VALUE` generic keywords: `[KEYWORD]` renders VALUE.
    pub generic_keywords: Vec<(String, String)>,
    /// `[dynamic_id]` start, step and maximum (`-dynamicStart`,
    /// `-dynamicStep`, `-dynamicMax`; SIPp's defaults 10000, 4, 18000).
    pub dynamic_id: (u32, u32, u32),
    /// `-tdmmap`: the circuit table `[tdmmap]` renders from.
    pub tdm_map: Option<crate::tdm::TdmMap>,
    /// `-rfc3339`: `[timestamp]` in RFC 3339 form.
    pub rfc3339: bool,
    /// `-f`: how often the screen snapshot and the `-bg` line refresh.
    pub report_interval: Duration,
    /// `-trace_rtt` destination.
    pub trace_rtt: Option<std::path::PathBuf>,
    /// `-trace_counts` destination.
    pub trace_counts: Option<std::path::PathBuf>,
    /// `-trace_error_codes` destination.
    pub trace_error_codes: Option<std::path::PathBuf>,
    /// `-rtt_freq`: buffered response times before a `-trace_rtt` flush.
    pub rtt_freq: usize,
    /// `-stat_delimiter`: the statistics files' column separator.
    pub stat_delimiter: String,
    /// `-periodic_rtd`: zero the repartition tables at every dump.
    pub periodic_rtd: bool,
    /// `-trace_logs` destination (`<log>` actions).
    pub trace_logs: Option<std::path::PathBuf>,
    /// `-trace_shortmsg` destination.
    pub trace_shortmsg: Option<std::path::PathBuf>,
    /// `-trace_calldebug` destination.
    pub trace_calldebug: Option<std::path::PathBuf>,
    /// `-<kind>_overwrite`: truncate or append each log file.
    pub log_overwrite: LogOverwrite,
    /// `-ringbuffer_files`/`-ringbuffer_size`/`-max_log_size`.
    pub log_rotation: sipr_stats::LogRotation,
    /// `-deadcall_wait`: how long a finished call's Call-ID stays known so
    /// late messages are logged against it (0 disables).
    pub deadcall_wait: Duration,
    /// `-max_invite_retrans` (SIPp's default 5).
    pub max_invite_retrans: u32,
    /// `-max_non_invite_retrans` (SIPp's default 9).
    pub max_non_invite_retrans: u32,
    /// `-recv_timeout`: the timeout of every recv without its own.
    pub recv_timeout: Option<Duration>,
    /// `-timeout_error`: reaching `-timeout` is a fatal error.
    pub timeout_error: bool,
    /// `-lost`: the default loss percentage of every send and recv.
    pub lost: Option<f64>,
    /// `-pause_msg_ign`: drop what arrives while a call is in a pause.
    pub pause_msg_ign: bool,
    /// `-default_behaviors` / `-nd`.
    pub behaviors: Behaviors,
    /// `-callid_slash_ign`: keep a `///` prefix in Call-IDs (SIPp strips
    /// it as its 3PCC marker otherwise).
    pub callid_slash_ign: bool,
    /// `-nostdin`: no keyboard control on stdin.
    pub nostdin: bool,
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

/// SIPp's `-<kind>_overwrite` flags: truncate (true, the default) or append
/// to each log file.
#[derive(Debug, Clone, Copy)]
pub struct LogOverwrite {
    /// `-message_overwrite`.
    pub messages: bool,
    /// `-error_overwrite`.
    pub errors: bool,
    /// `-log_overwrite`.
    pub logs: bool,
    /// `-shortmessage_overwrite`.
    pub shortmessages: bool,
    /// `-calldebug_overwrite`.
    pub calldebug: bool,
}

impl Default for LogOverwrite {
    fn default() -> Self {
        Self {
            messages: true,
            errors: true,
            logs: true,
            shortmessages: true,
            calldebug: true,
        }
    }
}

/// SIPp's default behaviors (`-default_behaviors`, all on; `-nd` = none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Behaviors {
    /// `bye`: abort a call with BYE/CANCEL/ACK, answer an unexpected
    /// BYE/CANCEL with 200 before aborting.
    pub bye: bool,
    /// `abortunexp`: an unexpected message aborts the call (else it is
    /// counted and the call continues).
    pub abortunexp: bool,
    /// `pingreply`: an unexpected `PING` gets a 200 and ends the call.
    pub pingreply: bool,
    /// `cseq`: an ACK must carry the CSeq of the last INVITE received.
    pub cseq: bool,
}

impl Default for Behaviors {
    fn default() -> Self {
        Self::all()
    }
}

impl Behaviors {
    /// SIPp's `all`.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            bye: true,
            abortunexp: true,
            pingreply: true,
            cseq: true,
        }
    }

    /// SIPp's `none` (`-nd`).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            bye: false,
            abortunexp: false,
            pingreply: false,
            cseq: false,
        }
    }

    /// Parse SIPp's `-default_behaviors` list: comma-separated `all`,
    /// `none`, `bye`, `abortunexp`, `pingreply`, `cseq`, each optionally
    /// prefixed `+` (add) or `-` (remove), applied left to right from none
    /// (`sipp.cpp` `SIPP_OPTION_DEFAULTS`).
    ///
    /// # Errors
    ///
    /// SIPp's "Unknown default behavior" for anything else.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut b = Self::none();
        for token in spec.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if token == "none" {
                b = Self::none();
                continue;
            }
            let (remove, name) = match token.strip_prefix('-') {
                Some(n) => (true, n),
                None => (false, token.strip_prefix('+').unwrap_or(token)),
            };
            let mask = match name {
                "all" => Self::all(),
                "bye" => Self {
                    bye: true,
                    ..Self::none()
                },
                "abortunexp" => Self {
                    abortunexp: true,
                    ..Self::none()
                },
                "pingreply" => Self {
                    pingreply: true,
                    ..Self::none()
                },
                "cseq" => Self {
                    cseq: true,
                    ..Self::none()
                },
                _ => return Err(format!("Unknown default behavior: '{token}'")),
            };
            let apply = |current: bool, bit: bool| {
                if bit { !remove } else { current }
            };
            b = Self {
                bye: apply(b.bye, mask.bye),
                abortunexp: apply(b.abortunexp, mask.abortunexp),
                pingreply: apply(b.pingreply, mask.pingreply),
                cseq: apply(b.cseq, mask.cseq),
            };
        }
        Ok(b)
    }
}

/// SIPp's built-in messages for aborting a call and answering an
/// unexpected BYE, CANCEL or PING (`call.cpp` `default_message_strings`),
/// compiled with the scenario's template engine.
struct DefaultMessages {
    ack: MsgTemplate,
    bye: MsgTemplate,
    cancel: MsgTemplate,
    ok: MsgTemplate,
}

impl DefaultMessages {
    fn compile() -> Self {
        let one = |text: &str| {
            let mut diags = sipr_scenario::diag::Diagnostics::new("default message");
            sipr_scenario::template::tokenize(
                &sipr_scenario::template::normalize_cdata(text),
                0,
                &mut diags,
            )
        };
        Self {
            ack: one(
                "ACK [last_Request_URI] SIP/2.0\n[last_Via]\n[last_From]\n[last_To]\n\
                 Call-ID: [call_id]\nCSeq: [last_cseq_number] ACK\n\
                 Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n\
                 Max-Forwards: 70\nSubject: Performance Test\nContent-Length: 0\n\n",
            ),
            bye: one("BYE [next_url] SIP/2.0\n\
                 Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n\
                 [routes]\n[last_From]\n[last_To]\nCall-ID: [call_id]\n\
                 CSeq: [last_cseq_number+1] BYE\nMax-Forwards: 70\n\
                 Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n\
                 Content-Length: 0\n\n"),
            cancel: one(
                "CANCEL [last_Request_URI] SIP/2.0\n[last_Via]\n[last_From]\n[last_To]\n\
                 Call-ID: [call_id]\nCSeq: [last_cseq_number] CANCEL\nMax-Forwards: 70\n\
                 Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n\
                 Content-Length: 0\n\n",
            ),
            ok: one(
                "SIP/2.0 200 OK\n[last_Via:]\n[last_From:]\n[last_To:]\n[last_Call-ID:]\n\
                 [last_CSeq:]\nContact: <sip:[local_ip]:[local_port];transport=[transport]>\n\
                 Content-Length: 0\n\n",
            ),
        }
    }
}

/// A finished call kept for `-deadcall_wait` (SIPp `deadcall`): a late
/// message is logged against it instead of being an out-of-call message.
struct DeadCall {
    expires: Instant,
    reason: String,
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
    /// The screens' data at the end of the run (`-trace_screen`).
    pub snapshot: Box<sipr_stats::Snapshot>,
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
    /// Something happened on the 3PCC control link.
    Twin(TwinEvent),
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

/// A call's view of one manual transaction (SIPp `txnInstanceInfo`).
#[derive(Debug, Clone, Default)]
struct TxnInstance {
    /// The Via branch of the `start_txn` request, once it was sent.
    branch: Option<String>,
    /// Hash of the last response matched for it: a repeat is ignored.
    final_hash: Option<u64>,
    /// The `ack_txn` step's index, once sent (re-sent on a late final).
    ack_index: Option<usize>,
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
    /// One slot per manual transaction of the call's scenario.
    txns: Vec<TxnInstance>,
    /// Named counters (`counter` step attribute).
    counters: std::collections::HashMap<String, u64>,
    /// Stable client nonce for digest auth.
    cnonce: String,
    /// Pending digest challenge captured by a `recv auth="true"`.
    challenge: Option<sipr_auth::Challenge>,
    peer_tag: Option<String>,
    routes: Vec<String>,
    last_recv: Option<Inbound>,
    /// This call's `-tdmmap` circuit, held until the call ends.
    tdm_number: Option<u32>,
    /// The `-trace_calldebug` buffer (SIPp `debugBuffer`), when tracing.
    debug: Option<String>,
    /// SIPp `call_established`: an ACK was sent or received.
    established: bool,
    /// SIPp `ack_is_pending`: a 200 was received and no ACK sent since.
    ack_pending: bool,
    /// The CSeq number of the last INVITE received (the `cseq` behavior's
    /// guard on ACKs).
    last_recv_invite_cseq: Option<u32>,
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
    /// Runs the secondary scenario (out-of-call or receive, spawned by a
    /// request of no known call) rather than the main one; never counts
    /// toward `-l`/`-users`/`-m`.
    secondary: bool,
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

/// Which second scenario runs next to the main one (SIPp's `ooc_scenario`
/// and `rx_scenario`; at most one is loaded — SIPp never reaches the
/// out-of-call branch in mixed mode, so sipr refuses the combination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryKind {
    /// `-oocsf`/`-oocsn`: answers requests of no known call, no injection
    /// line, counted as auto-answered.
    OutOfCall,
    /// `-rxsf`/`-rxsn` (mixed mode): terminates the calls the peer
    /// originates towards us while the main scenario originates ours.
    Receive,
}

/// [`run_with_ui`] with a secondary scenario loaded next to the main one:
/// a request whose Call-ID matches no live call spawns a call on it instead
/// of being discarded (SIPp `socket.cpp` `process_message`, the
/// `ooc_scenario` and `MODE_MIXED` branches). Client mode only, as in SIPp.
///
/// # Errors
///
/// See [`run`]; additionally, with SIPp's wordings where it has them: an
/// out-of-call scenario in server mode or reading injection files
/// (`[fieldN]`); a receive scenario next to a server-mode main scenario, or
/// one that is not itself server-mode.
pub fn run_scenarios(
    scenario: &Scenario,
    secondary: Option<(SecondaryKind, &Scenario)>,
    config: &EngineConfig,
    ui: Option<UiChannels>,
) -> Result<(RunReport, EngineControl), EngineError> {
    if config.tdm_map.is_none() && uses_tdmmap(scenario) {
        // SIPp's wording, at start-up rather than at the first render.
        return Err(EngineError(
            "[tdmmap] keyword without -tdmmap parameter on command line".to_owned(),
        ));
    }
    if let Some((kind, second)) = secondary {
        validate_secondary(kind, scenario, second)?;
    }
    if scenario.role == Role::Uac && config.target.is_none() {
        return Err(EngineError(
            "this scenario places calls (UAC): a remote target is required".into(),
        ));
    }
    let mut engine = Engine::new(scenario, secondary, config, ui)?;
    let control = engine.control.clone();
    let report = engine.run_loop();
    Ok((report, control))
}

/// The startup rules for a secondary scenario. SIPp enforces only the
/// out-of-call ones; the mixed-mode ones are what its help text promises
/// ("the second scenario MUST be a server mode scenario, and the first
/// scenario MUST be a client-mode scenario") and never checks.
fn validate_secondary(
    kind: SecondaryKind,
    main: &Scenario,
    second: &Scenario,
) -> Result<(), EngineError> {
    match kind {
        SecondaryKind::OutOfCall => {
            if main.role == Role::Uas {
                return Err(EngineError(
                    "SIPp cannot use out-of-call scenarios when running in server mode".into(),
                ));
            }
            if second.uses_injection_fields() {
                return Err(EngineError(
                    "Automatic calls (created by -aa, -oocsn or -oocsf) cannot use input files!"
                        .into(),
                ));
            }
        }
        SecondaryKind::Receive => {
            if main.role == Role::Uas {
                return Err(EngineError(format!(
                    "-rxsf/-rxsn: the main scenario must be a client-mode scenario \
                     (it originates the calls), but '{}' starts with a recv",
                    main.name
                )));
            }
            if second.role == Role::Uac {
                return Err(EngineError(format!(
                    "-rxsf/-rxsn: the receive scenario must be a server-mode scenario \
                     (its first message command a recv), but '{}' starts with a send",
                    second.name
                )));
            }
        }
    }
    if twin_role(second).is_some() {
        return Err(EngineError(format!(
            "the {} scenario cannot use <sendCmd>/<recvCmd> (3PCC)",
            kind.noun()
        )));
    }
    Ok(())
}

impl SecondaryKind {
    /// How messages name this scenario: "out-of-call" or "receive".
    #[must_use]
    pub fn noun(self) -> &'static str {
        match self {
            Self::OutOfCall => "out-of-call",
            Self::Receive => "receive",
        }
    }
}

/// Extended 3PCC configuration (SIPp `-master`/`-slave` + `-slave_cfg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extended3pcc {
    /// `-master NAME`: this instance initiates and dials its peers at
    /// start-up (SIPp: the master is launched last). A slave only listens
    /// and dials back once a peer has reached it.
    pub master: bool,
    /// This instance's name in the peer table.
    pub name: String,
    /// The resolved `-slave_cfg` table, in file order.
    pub peers: Vec<(String, SocketAddr)>,
}

/// The 3PCC control link the engine talks to.
enum TwinLink {
    /// Classic `-3pcc`: one connection to the other controller.
    Classic(TwinChannel),
    /// Extended mode: our listening socket plus one dialed connection per
    /// `dest=` peer, which a slave only opens once a peer has reached it.
    Extended {
        links: PeerLinks,
        /// Every `dest=` of the scenario, resolved, in first-use order.
        dests: Vec<(String, SocketAddr)>,
    },
}

/// SIPp's 3PCC "server" creation (`computeSippMode`: the first of
/// send/recv/sendCmd/recvCmd is a `recvCmd`, so controller B and every
/// slave): calls are opened by the commands that name them, not paced.
fn twin_creates_calls(scenario: &Scenario) -> bool {
    scenario.steps.iter().find_map(|s| match s {
        Step::Send(_) | Step::Recv(_) | Step::SendCmd { .. } => Some(false),
        Step::RecvCmd { .. } => Some(true),
        _ => None,
    }) == Some(true)
}

/// The Call-ID a twin command names (`Call-ID:` or its compact `i:`, case
/// folded), trimmed the way SIPp keys calls (`///` marker).
fn command_call_id(cmd: &str, slash_ign: bool) -> Option<String> {
    let raw = command_header(cmd, &["call-id", "i"])?;
    let trimmed = trim_call_id(raw, slash_ign);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// The first token of a command's `From:` line — the sender's peer name in
/// extended mode (SIPp `check_peer_src`).
fn command_from(cmd: &str) -> Option<&str> {
    command_header(cmd, &["from"]).and_then(|v| v.split_whitespace().next())
}

/// SIPp `checkInternalCmd`: `internal-cmd: abort_call` ends the call.
fn is_abort_command(cmd: &str) -> bool {
    command_header(cmd, &["internal-cmd"]).and_then(|v| v.split_whitespace().next())
        == Some("abort_call")
}

/// The trimmed value of the first line whose name (before `:`) matches one
/// of `names`, case folded.
fn command_header<'a>(cmd: &'a str, names: &[&str]) -> Option<&'a str> {
    cmd.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        let name = name.trim();
        names
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
            .then(|| value.trim())
    })
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

/// Open the 3PCC control link the scenario and command line call for:
/// nothing without twin commands, the classic pair for `-3pcc`, the peer
/// mesh for `-slave_cfg`. The role comes from the first twin command in
/// the scenario: `sendCmd`-first dials (controller A / master),
/// `recvCmd`-first listens (controller B / slave).
fn open_twin(
    scenario: &Scenario,
    config: &EngineConfig,
    tx: &Sender<Event>,
) -> Result<Option<TwinLink>, EngineError> {
    let role = twin_role(scenario);
    match (role, config.extended_3pcc.as_ref(), config.twin_addr) {
        (None, Some(_), _) => Err(EngineError(
            "-slave_cfg: extended 3PCC mode enabled but the scenario has no \
             <sendCmd>/<recvCmd> (SIPp: thirdPartyMode is different from MASTER and SLAVE)"
                .into(),
        )),
        (None, None, _) => Ok(None),
        (Some(role), Some(ext), _) => {
            let dests = check_extended_scenario(scenario, ext, role)?;
            let own = ext
                .peers
                .iter()
                .find(|(n, _)| *n == ext.name)
                .map(|(_, a)| *a)
                .ok_or_else(|| {
                    EngineError(format!("get_peer_addr: Peer {} not found", ext.name))
                })?;
            let mut links = PeerLinks::listen(own, twin_bridge(tx)).map_err(|e| {
                EngineError(format!(
                    "Unable to bind twin sipp socket {own} for '{}': {e}",
                    ext.name
                ))
            })?;
            if ext.master {
                links
                    .connect_all(&dests)
                    .map_err(|e| EngineError(e.to_string()))?;
            }
            Ok(Some(TwinLink::Extended { links, dests }))
        }
        (Some(role), None, Some(addr)) => {
            if let Some(dest) = scenario.steps.iter().find_map(|s| match s {
                Step::SendCmd {
                    dest: Some(dest), ..
                } => Some(dest),
                _ => None,
            }) {
                return Err(EngineError(format!(
                    "get_peer_addr: Peer {dest} not found — sendCmd dest= needs extended \
                     3PCC mode (-slave_cfg with -master or -slave), not -3pcc"
                )));
            }
            if scenario
                .steps
                .iter()
                .any(|s| matches!(s, Step::RecvCmd { src: Some(_), .. }))
            {
                eprintln!(
                    "sipr: warning: recvCmd src= is only checked in extended 3PCC mode \
                     (-slave_cfg); classic -3pcc has a single twin"
                );
            }
            let ch = match role {
                TwinRole::Connect => TwinChannel::connect(addr, twin_bridge(tx)).map_err(|e| {
                    EngineError(format!("cannot connect 3PCC twin socket {addr}: {e}"))
                })?,
                TwinRole::Listen => TwinChannel::listen(addr, twin_bridge(tx)).map_err(|e| {
                    EngineError(format!("cannot bind 3PCC twin socket {addr}: {e}"))
                })?,
            };
            Ok(Some(TwinLink::Classic(ch)))
        }
        (Some(_), None, None) => Err(EngineError(
            "scenario uses <sendCmd>/<recvCmd> (3PCC) but no twin address \
             was given — pass -3pcc HOST:PORT, or -slave_cfg with -master/-slave"
                .into(),
        )),
    }
}

/// A channel whose far end forwards twin events into the engine loop.
fn twin_bridge(tx: &Sender<Event>) -> Sender<TwinEvent> {
    let (twin_tx, twin_rx) = channel::<TwinEvent>();
    let bridge_tx = tx.clone();
    std::thread::Builder::new()
        .name("sipr-twin-bridge".into())
        .spawn(move || {
            while let Ok(ev) = twin_rx.recv() {
                if bridge_tx.send(Event::Twin(ev)).is_err() {
                    return;
                }
            }
        })
        .ok();
    twin_tx
}

/// SIPp's extended-mode consistency checks (`scenario.cpp`): the role the
/// scenario implies must match `-master`/`-slave`, every `sendCmd` needs a
/// `dest=` and every `recvCmd` a `src=`, and each `dest=` must be in the
/// peer table. Returns the resolved `dest=` peers in first-use order.
fn check_extended_scenario(
    scenario: &Scenario,
    ext: &Extended3pcc,
    role: TwinRole,
) -> Result<Vec<(String, SocketAddr)>, EngineError> {
    match role {
        TwinRole::Connect if !ext.master => {
            return Err(EngineError(
                "Inconsistency between command line and scenario: master scenario but \
                 -master option not set"
                    .into(),
            ));
        }
        TwinRole::Listen if ext.master => {
            return Err(EngineError(
                "Inconsistency between command line and scenario: slave scenario but \
                 -slave option not set"
                    .into(),
            ));
        }
        _ => {}
    }
    let mut dests: Vec<(String, SocketAddr)> = Vec::new();
    for step in &scenario.steps {
        match step {
            Step::SendCmd { dest: None, .. } => {
                return Err(EngineError(
                    "You must specify a 'dest' for sendCmd with extended 3pcc mode!".into(),
                ));
            }
            Step::RecvCmd { src: None, .. } => {
                return Err(EngineError(
                    "You must specify a 'src' for recvCmd when using extended 3pcc mode!".into(),
                ));
            }
            Step::SendCmd {
                dest: Some(dest), ..
            } => {
                if dests.iter().any(|(n, _)| n == dest) {
                    continue;
                }
                let addr = ext
                    .peers
                    .iter()
                    .find(|(n, _)| n == dest)
                    .map(|(_, a)| *a)
                    .ok_or_else(|| EngineError(format!("get_peer_addr: Peer {dest} not found")))?;
                dests.push((dest.clone(), addr));
            }
            _ => {}
        }
    }
    Ok(dests)
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

    /// Another call holds this socket too (the pool keeps only weak refs).
    fn shared(&self) -> bool {
        match self {
            Self::Udp(s) => Arc::strong_count(s) > 1,
            Self::Tcp(c) => Arc::strong_count(c) > 1,
            Self::Tls(c) => Arc::strong_count(c) > 1,
            #[cfg(feature = "sctp")]
            Self::Sctp(c) => Arc::strong_count(c) > 1,
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

/// The secondary scenario (out-of-call or receive), compiled independently
/// of the main one: its own step stats, repartitions and CSeq guard (SIPp's
/// `ooc_scenario`/`rx_scenario`, each with its own `CStat`).
struct SecondaryScenario<'s> {
    kind: SecondaryKind,
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
    secondary: Option<SecondaryScenario<'s>>,
    /// Live calls on the secondary scenario (SIPp's `open_calls` never includes
    /// them: `-l`, `-users` and the end of the run look at the main ones).
    secondary_live: usize,
    /// `set display ooc|rx`: the screens show the secondary scenario.
    display_secondary: bool,
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
    trace_rtt: Option<sipr_stats::TraceFile>,
    trace_counts: Option<sipr_stats::TraceFile>,
    trace_codes: Option<sipr_stats::TraceFile>,
    trace_logs: Option<sipr_stats::TraceFile>,
    trace_shortmsg: Option<sipr_stats::TraceFile>,
    trace_calldebug: Option<sipr_stats::TraceFile>,
    /// Finished calls still answering to their Call-ID (`-deadcall_wait`).
    dead_calls: HashMap<String, DeadCall>,
    /// SIPp's built-in abort/answer messages.
    default_msgs: DefaultMessages,
    inf_files: Vec<std::cell::RefCell<InjectionFile>>,
    inf_seq: Vec<usize>,
    /// 3PCC control link, when the scenario uses twin commands.
    twin: Option<TwinLink>,
    /// Calls are opened by the twin commands that name them (SIPp's 3PCC
    /// server modes: controller B and every slave), not by the pacer.
    twin_creates_calls: bool,
    /// A twin ending has been reported; SIPp drains and exits on it.
    twin_ended: bool,
    /// `-users` closed loop: the pool of free user ids. SIPp's `freeUsers`
    /// order — filled 1..=N at start-up, taken from the back, returned to
    /// the front — so the first call is user N's and a returning id waits
    /// its turn behind the ones still free.
    free_users: std::collections::VecDeque<usize>,
    /// Ids parked by a shrink (`set users`): a call that ends while more
    /// calls are live than the target retires its id here (SIPp
    /// `retiredUsers`); the next growth takes them back, oldest first,
    /// before creating fresh ids.
    retired_users: std::collections::VecDeque<usize>,
    /// The next never-used user id a growth may create.
    next_user_id: usize,
    /// The user- and global-scoped names of both scenarios, and each
    /// scenario's variable layout in that space.
    var_space: crate::vars::VarSpace,
    main_layout: std::rc::Rc<crate::vars::VarLayout>,
    secondary_layout: Option<std::rc::Rc<crate::vars::VarLayout>>,
    /// `<Global variables=…/>`: one table for the run.
    global_vars: crate::vars::SharedTable,
    /// `<User variables=…/>`: one table per user id, created when the id
    /// is first handed out and kept for the run (SIPp `userVarMap`), so a
    /// retired id that returns still has its values.
    user_vars: HashMap<usize, crate::vars::SharedTable>,
    rng: sipr_net::rng::Rng,
    /// When the run started (`[clock_tick]`).
    run_start: Instant,
    /// The `[dynamic_id]` counter (`-dynamicStart`/`-dynamicStep`/`-dynamicMax`).
    dynamic_id: crate::render::DynamicId,
    /// `-tdmmap` circuits in use, indexed by circuit number.
    tdm_in_use: Vec<bool>,
    /// `[file name=…]` contents by rendered name, read once per run.
    file_cache: std::cell::RefCell<HashMap<String, String>>,
    /// Per-step: CSeq method a response recv must carry (SIPp guard).
    expected_cseq_method: Vec<Option<String>>,
    control: EngineControl,
    pacer_carry: f64,
    /// When the pacer last credited calls: pacing is by elapsed wall time,
    /// as in SIPp, so a tick that arrives late (a loaded host oversleeping)
    /// credits the whole interval it covers rather than a nominal one.
    last_pacer_tick: Instant,
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
    /// `exec command=` runner thread, started on the first command.
    exec_runner: Option<crate::exec::ExecRunner>,
    /// The blocking-DNS note for `<setdest host=…>` was logged once.
    setdest_dns_warned: bool,
}

impl<'s> Engine<'s> {
    /// Hand a free `-tdmmap` circuit to a new outgoing call (`None` without
    /// a map); SIPp's warning text when every circuit is taken.
    fn alloc_tdm(&mut self) -> Result<Option<u32>, &'static str> {
        if self.tdm_in_use.is_empty() {
            return Ok(None);
        }
        let Some(free) = self.tdm_in_use.iter().position(|used| !used) else {
            return Err("Can't create new outgoing call: all tdm_map circuits busy");
        };
        self.tdm_in_use[free] = true;
        Ok(Some(u32::try_from(free).unwrap_or(u32::MAX)))
    }

    /// Return a finished call's `-tdmmap` circuit to the table.
    fn release_tdm(&mut self, call: &CallState) {
        if let Some(slot) = call
            .tdm_number
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| self.tdm_in_use.get_mut(n))
        {
            *slot = false;
        }
    }

    fn new(
        scenario: &'s Scenario,
        secondary: Option<(SecondaryKind, &'s Scenario)>,
        config: &EngineConfig,
        ui: Option<UiChannels>,
    ) -> Result<Self, EngineError> {
        // Variable scopes and `-set` are checked before any socket opens.
        let var_space = crate::vars::VarSpace::new(&secondary.map_or_else(
            || vec![&scenario.vars],
            |(_, sc)| vec![&scenario.vars, &sc.vars],
        ));
        if let [name, ..] = var_space.conflicts() {
            return Err(EngineError(format!(
                "variable '{name}' is <User> in one scenario and <Global> in the other: \
                 the two share one user and one global name space, as in SIPp"
            )));
        }
        let global_vars = var_space.global_table();
        seed_globals(&var_space, &global_vars, &config.global_sets)?;
        let main_layout = var_space.layout(&scenario.vars);
        let secondary_layout = secondary.map(|(_, sc)| var_space.layout(&sc.vars));
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
        // `-inf` files lead, `-rxinf` ones follow in the same table (SIPp's
        // one `inFiles` map): the first `-inf` stays the default file.
        let inf_default_files = config.inf_files.len();
        let mut inf_files = Vec::with_capacity(inf_default_files + config.rx_inf_files.len());
        for path in config.inf_files.iter().chain(&config.rx_inf_files) {
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
        validate_field_files(scenario, &inf_files, inf_default_files)?;
        if let Some((SecondaryKind::Receive, rx)) = secondary {
            validate_field_files(rx, &inf_files, inf_default_files)?;
        }
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
        let twin = open_twin(scenario, config, &tx)?;
        // Media: captures are parsed once here (SIPp: at scenario parse) and
        // the media thread exists only when something will be played.
        let second: Option<&'s Scenario> = secondary.map(|(_, sc)| sc);
        let mut pcaps = load_pcaps(scenario, config)?;
        let mut rtp_files = load_rtp_files(scenario, config)?;
        if let Some(o) = second {
            pcaps.extend(load_pcaps(o, config)?);
            rtp_files.extend(load_rtp_files(o, config)?);
        }
        for cmd in scenario
            .rtp_echo_cmds()
            .chain(second.into_iter().flat_map(Scenario::rtp_echo_cmds))
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
            if scenario.toggles_rtp_echo() || second.is_some_and(Scenario::toggles_rtp_echo) {
                eprintln!(
                    "sipr: warning: the scenario uses <rtp_echo> but -rtp_echo was not given — \
                     nothing is echoing"
                );
            }
            None
        };
        let media = if !(scenario.has_media() || second.is_some_and(Scenario::has_media)) {
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
        // Stdin watcher: 'q' = soft quit, 'Q' = hard quit (`-nostdin` off).
        let stdin_tx = tx.clone();
        let _stdin = (!config.nostdin).then(|| {
            std::thread::Builder::new()
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
                })
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
        // The statistics CSVs are plain files; the logs rotate and honour
        // `-<kind>_overwrite`, named for SIPp's `<scenario>_<pid>_<kind>.log`.
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
        let log_base = config
            .trace_name_base
            .clone()
            .unwrap_or_else(|| "sipr".to_owned());
        let open_log = |path: &Option<std::path::PathBuf>,
                        kind: &str,
                        overwrite: bool,
                        what: &str|
         -> Result<Option<sipr_stats::TraceFile>, EngineError> {
            path.as_ref()
                .map(|p| {
                    sipr_stats::TraceFile::open(p, &log_base, kind, overwrite, config.log_rotation)
                        .map_err(|e| {
                            EngineError(format!("cannot create {what} file {}: {e}", p.display()))
                        })
                })
                .transpose()
        };
        let trace_logs = open_log(&config.trace_logs, "logs", config.log_overwrite.logs, "log")?;
        let trace_shortmsg = open_log(
            &config.trace_shortmsg,
            "shortmessages",
            config.log_overwrite.shortmessages,
            "short message",
        )?;
        let trace_calldebug = open_log(
            &config.trace_calldebug,
            "calldebug",
            config.log_overwrite.calldebug,
            "call debug",
        )?;
        let mut trace_err = open_log(
            &config.trace_err,
            "errors",
            config.log_overwrite.errors,
            "error trace",
        )?;
        if let Some(f) = trace_err.as_mut() {
            f.write(sipr_stats::ERROR_LOG_HEADER);
        }
        let mut stat_set = new_stat_set(scenario);
        stat_set.dump = sipr_stats::DumpOptions {
            delimiter: config.stat_delimiter.clone(),
            rfc3339: config.rfc3339,
            periodic_rtd: config.periodic_rtd,
            rtt_freq: config.rtt_freq,
            trace_rtt: config.trace_rtt.is_some(),
        };
        let mut trace_stat = open_trace(&config.trace_stat, "statistics")?;
        if let Some(f) = trace_stat.as_mut() {
            f.write(&stat_set.csv_header());
        }
        let mut trace_rtt = open_trace(&config.trace_rtt, "rtt")?;
        if let Some(f) = trace_rtt.as_mut() {
            f.write(&stat_set.rtt_header());
        }
        let mut trace_counts = open_trace(&config.trace_counts, "counts")?;
        if let Some(f) = trace_counts.as_mut() {
            f.write(&stat_set.counts_header());
        }
        let trace_codes = open_trace(&config.trace_error_codes, "error codes")?;
        let secondary = secondary.map(|(kind, sc)| SecondaryScenario {
            kind,
            scenario: sc,
            stats: new_stat_set(sc),
            expected_cseq_method: precompute_cseq_methods(sc),
        });
        // Load -inf injection files up front (fail fast on bad files). SIPp
        // keys files by basename; keyword `file=` and `-infindex` match that.
        let inf_len = inf_files.len();
        Ok(Self {
            scenario,
            secondary,
            secondary_live: 0,
            display_secondary: false,
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
            trace_msg: open_log(
                &config.trace_msg,
                "messages",
                config.log_overwrite.messages,
                "message trace",
            )?,
            trace_err,
            trace_stat,
            trace_rtt,
            trace_counts,
            trace_codes,
            trace_logs,
            trace_shortmsg,
            trace_calldebug,
            dead_calls: HashMap::new(),
            default_msgs: DefaultMessages::compile(),
            inf_files,
            inf_seq: vec![0; inf_len],
            twin_creates_calls: twin.is_some() && twin_creates_calls(scenario),
            twin,
            twin_ended: false,
            free_users: config
                .users
                .map_or_else(Default::default, |n| (1..=n).collect()),
            retired_users: std::collections::VecDeque::new(),
            next_user_id: config.users.unwrap_or(0) + 1,
            var_space,
            main_layout,
            secondary_layout,
            global_vars,
            user_vars: HashMap::new(),
            rng: sipr_net::rng::Rng::new(config.seed ^ 0x51B8_0003),
            run_start: Instant::now(),
            dynamic_id: crate::render::DynamicId::new(
                config.dynamic_id.0,
                config.dynamic_id.1,
                config.dynamic_id.2,
            ),
            tdm_in_use: vec![
                false;
                config
                    .tdm_map
                    .as_ref()
                    .map_or(0, |m| usize::try_from(m.circuits()).unwrap_or(0))
            ],
            file_cache: std::cell::RefCell::new(HashMap::new()),
            expected_cseq_method: precompute_cseq_methods(scenario),
            control,
            pacer_carry: 0.0,
            last_pacer_tick: Instant::now(),
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
            exec_runner: None,
            setdest_dns_warned: false,
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
            // ends when they are done, whatever secondary calls still linger.
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
                    if self.config.timeout_error {
                        // SIPp `timeout_alarm`: an ERROR, so the run exits fatal.
                        self.fatal = Some(format!(
                            "{} timed out after '{:.3}' seconds",
                            self.scenario.name,
                            self.run_start.elapsed().as_secs_f64()
                        ));
                    }
                    self.fail_all("global timeout");
                    self.soft_stopping = true;
                    self.control.stop_pacer.store(true, Ordering::Relaxed);
                }
                Ok(Event::Stdin(c)) => self.apply_key(c),
                Ok(Event::Control(req)) => self.on_control(req),
                Ok(Event::Twin(ev)) => self.on_twin_event(ev),
                Ok(Event::Media(ev)) => self.on_media_event(ev),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            // Closed-loop: replace any calls that just ended (no-op otherwise).
            self.refill_users();
            self.run_rate_ramp();
            self.flush_rtt(false);
            if last_line.elapsed() >= self.config.report_interval {
                last_line = Instant::now();
                let now = Instant::now();
                self.dead_calls.retain(|_, d| d.expires > now);
                self.sample_media_counters();
                if self.config.periodic_stats {
                    eprintln!("sipr: {}", self.stats.line(self.live_main()));
                }
                self.publish_snapshot();
            }
            if last_stat_dump.elapsed() >= self.config.stat_interval {
                last_stat_dump = Instant::now();
                self.dump_statistics();
            }
        }
        self.control.stop_pacer.store(true, Ordering::Relaxed);
        self.sample_media_counters();
        self.collect_final_media_events();
        // Final rows of every statistics file, then flush all trace files.
        self.dump_statistics();
        self.flush_rtt(true);
        for f in [
            &mut self.trace_msg,
            &mut self.trace_err,
            &mut self.trace_stat,
            &mut self.trace_rtt,
            &mut self.trace_counts,
            &mut self.trace_codes,
            &mut self.trace_logs,
            &mut self.trace_shortmsg,
            &mut self.trace_calldebug,
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
            snapshot: Box::new(self.build_snapshot()),
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
        let snap = self.build_snapshot();
        if let Some(shared) = self.control_snapshot.as_ref()
            && let Ok(mut slot) = shared.lock()
        {
            *slot = snap.clone();
        }
        if let Some(tx) = self.snapshot_tx.as_ref() {
            let _ = tx.send(snap); // UI gone → ignored; run continues headless
        }
    }

    /// The screens' data as of now (the TUI's, and `-trace_screen`'s at exit).
    fn build_snapshot(&mut self) -> sipr_stats::Snapshot {
        // `set display ooc|rx` (SIPp `display_scenario`): every screen —
        // counters, statistics, repartitions and the scenario page — shows
        // the displayed scenario (`screen.cpp` reads `display_scenario->stats`
        // throughout). Global counters stay global.
        let displayed = self.displayed_scenario();
        let (shown, live) = match displayed.secondary_name() {
            Some(_) => match self.secondary.as_ref() {
                Some(o) => (&o.stats, self.secondary_live),
                None => (&self.stats, self.live_main()),
            },
            None => (&self.stats, self.live_main()),
        };
        let shown_scenario = match self.secondary.as_ref() {
            Some(o) if displayed.secondary_name().is_some() => o.scenario,
            _ => self.scenario,
        };
        let mut snap = sipr_stats::Snapshot {
            scenario: shown_scenario.name.clone(),
            uas: shown_scenario.role == Role::Uas,
            mixed: self
                .secondary
                .as_ref()
                .is_some_and(|o| o.kind == SecondaryKind::Receive),
            rate_target: self.control.rate(),
            paused: self.paused,
            hide: self.hide,
            screen_request: self.screen_request,
            display: displayed,
            ..Default::default()
        };
        shown.fill_snapshot(&mut snap, live);
        snap.auto_answered = self.stats.auto_answered;
        snap.garbage = self.stats.garbage;
        let now = Instant::now();
        let (last_at, last_created) = self.last_snapshot;
        #[allow(clippy::cast_precision_loss)]
        {
            snap.rate_period = shown.created().saturating_sub(last_created) as f64
                / now.duration_since(last_at).as_secs_f64().max(1e-9);
        }
        self.last_snapshot = (now, shown.created());
        snap
    }

    /// The `-fd` dump (SIPp `stattask::report`): a `-trace_stat` row, a
    /// `-trace_counts` row and a `-trace_error_codes` row, then the period
    /// ends. Nothing happens without one of the three files.
    fn dump_statistics(&mut self) {
        if self.trace_stat.is_none() && self.trace_counts.is_none() && self.trace_codes.is_none() {
            return;
        }
        let live = self.live_main();
        let rate = self.control.rate();
        let users = self.config.users;
        if let Some(f) = self.trace_stat.as_mut() {
            f.write(&self.stats.csv_row(live, rate, users));
            f.flush();
        }
        if let Some(f) = self.trace_counts.as_mut() {
            f.write(&self.stats.counts_row());
            f.flush();
        }
        if let Some(f) = self.trace_codes.as_mut() {
            f.write(&self.stats.error_codes_row());
            f.flush();
        }
        self.stats.end_period();
    }

    /// Write the buffered `-trace_rtt` rows once `-rtt_freq` of them are
    /// waiting (SIPp `computeRtt` → `dumpDataRtt`), or all of them when
    /// `force` (the end of the run).
    fn flush_rtt(&mut self, force: bool) {
        if self.trace_rtt.is_none() || !(force || self.stats.rtt_due()) {
            return;
        }
        let rows = self.stats.take_rtt_rows();
        if let Some(f) = self.trace_rtt.as_mut() {
            f.write(&rows);
            f.flush();
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

    /// `set users N` at runtime (SIPp `CallGenerationTask::set_users`): a
    /// growth re-activates retired ids first (oldest first, with their
    /// variables), then creates fresh ones; a shrink touches no pool — the
    /// excess calls finish without replacement and retire their ids as they
    /// do (see [`Self::return_user`]). Traffic is un-paused either way.
    fn set_users(&mut self, target: usize) {
        let mut users = self.config.users.unwrap_or(0);
        while users < target {
            let id = self.retired_users.pop_back().unwrap_or_else(|| {
                self.next_user_id += 1;
                self.next_user_id - 1
            });
            self.free_users.push_front(id);
            users += 1;
        }
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
            ControlCmd::SetDisplay(which) => {
                let kind = self.secondary.as_ref().map(|o| o.kind);
                match (which.as_str(), kind) {
                    ("main", _) => self.display_secondary = false,
                    ("ooc", Some(SecondaryKind::OutOfCall))
                    | ("rx", Some(SecondaryKind::Receive)) => self.display_secondary = true,
                    // SIPp: "Unknown display scenario: %s" when that scenario
                    // is not loaded.
                    (other, _) => return Err(format!("Unknown display scenario: {other}")),
                }
                // The period rate restarts from the displayed scenario's count.
                let created = match self.secondary.as_ref() {
                    Some(o) if self.display_secondary => o.stats.created(),
                    _ => self.stats.created(),
                };
                self.last_snapshot = (Instant::now(), created);
            }
            ControlCmd::SetHide(on) => self.hide = *on,
            ControlCmd::Trace { log, on } => self.set_trace(log, *on)?,
            ControlCmd::Dump(what) if what == "variables" => self.dump_variables(),
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
                if let Some(o) = self.secondary.as_mut() {
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
            "logs" => (
                &mut self.trace_logs,
                self.config.trace_logs.clone(),
                "logs",
                "log trace",
            ),
            "shortmessages" => (
                &mut self.trace_shortmsg,
                self.config.trace_shortmsg.clone(),
                "shortmessages",
                "short message trace",
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
        let base = self
            .config
            .trace_name_base
            .clone()
            .unwrap_or_else(|| "sipr".to_owned());
        *slot = Some(
            sipr_stats::TraceFile::open(&path, &base, suffix, true, self.config.log_rotation)
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
        let now = Instant::now();
        let since_last = now.duration_since(self.last_pacer_tick);
        self.last_pacer_tick = now;
        // Users mode is closed-loop (event-driven via refill_users), not paced.
        // A paused run credits nothing for the time it was paused.
        if self.config.users.is_some()
            || self.scenario.role == Role::Uas
            || self.twin_creates_calls
            || self.paused
            || self.done_creating()
        {
            return;
        }
        self.pacer_carry += pacer_credit(self.control.rate(), since_last, self.config.rate_period);
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

    /// What the screens show (SIPp `display_scenario`).
    fn displayed_scenario(&self) -> sipr_stats::Display {
        match self.secondary.as_ref() {
            Some(o) if self.display_secondary => match o.kind {
                SecondaryKind::OutOfCall => sipr_stats::Display::OutOfCall(o.scenario.name.clone()),
                SecondaryKind::Receive => sipr_stats::Display::Receive(o.scenario.name.clone()),
            },
            _ => sipr_stats::Display::Main,
        }
    }

    /// Live calls on the main scenario — SIPp's `open_calls`, which the
    /// `-l` cap, `-users` refills and the end of the run look at.
    fn live_main(&self) -> usize {
        self.calls.len().saturating_sub(self.secondary_live)
    }

    fn on_secondary(&self, call_id: &str) -> bool {
        self.calls.get(call_id).is_some_and(|c| c.secondary)
    }

    /// The scenario a call runs (the secondary one for calls spawned on it).
    fn scenario_of(&self, call_id: &str) -> &'s Scenario {
        match self.secondary.as_ref() {
            Some(o) if self.on_secondary(call_id) => o.scenario,
            _ => self.scenario,
        }
    }

    /// The stat set of the scenario a call runs (see [`stats_for`]).
    fn stats_of(&mut self, secondary: bool) -> &mut sipr_stats::StatSet {
        stats_for(&mut self.stats, self.secondary.as_mut(), secondary)
    }

    fn call_stats(&mut self, call_id: &str) -> &mut sipr_stats::StatSet {
        let secondary = self.on_secondary(call_id);
        self.stats_of(secondary)
    }

    /// The recv-window scan against the scenario a call runs.
    /// Render a send step for a call: the message bytes and where they go
    /// (`None` when the call is gone). Also used to re-send a recorded ACK
    /// out of order, so it must not touch the call's state.
    fn render_send(
        &self,
        call_id: &str,
        index: usize,
        send: &SendStep,
    ) -> Option<Result<(Vec<u8>, SocketAddr), crate::render::RenderError>> {
        let call = self.calls.get(call_id)?;
        let scenario = self.scenario_of(call_id);
        let first = template_first_word(&send.template).unwrap_or_default();
        let is_req = first != "SIP/2.0";
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
            run: run_info(
                &self.config,
                &self.dynamic_id,
                &self.file_cache,
                self.run_start,
                call,
            ),
            fields: crate::render::FieldSource {
                files: &self.inf_files,
                lines: &call.field_lines,
            },
        };
        Some(render(&send.template, &ctx).map(|buf| (buf, call.remote)))
    }

    /// Send a step's message again, out of order (SIPp `sendBuffer(
    /// createSendingMessage(...))` for a late final's ACK).
    fn resend_step(&mut self, call_id: &str, index: usize) {
        let Some(Step::Send(send)) = self.scenario_of(call_id).steps.get(index) else {
            return;
        };
        let Some(Ok((buf, remote))) = self.render_send(call_id, index, send) else {
            return;
        };
        if self.send_for_call(call_id, &buf, remote, None).is_ok() {
            self.call_stats(call_id).retrans_sent += 1;
            self.trace_send(&buf, remote);
        }
    }

    /// A response for a named transaction the call already moved past
    /// (SIPp `call::process_incoming` ~l.5395-5430): a provisional is
    /// ignored, a final one for an INVITE transaction gets the recorded ACK
    /// again, a repeat of the final response already taken is ignored with
    /// SIPp's warning. Returns false when none applies (then it is an
    /// unexpected message like any other).
    fn on_old_transaction_response(
        &mut self,
        call_id: &str,
        txn: TxnId,
        msg: &Inbound,
        msg_hash: u64,
    ) -> bool {
        let name = self
            .scenario_of(call_id)
            .transactions
            .get(txn)
            .map(|t| t.name.clone())
            .unwrap_or_default();
        let transport = self.transport_token;
        let (ack_index, final_hash) = self
            .calls
            .get(call_id)
            .and_then(|c| c.txns.get(txn))
            .map_or((None, None), |x| (x.ack_index, x.final_hash));
        let code = msg.status_code().unwrap_or(0);
        if (100..200).contains(&code) {
            self.log_err(&format!(
                "Ignoring provisional {transport} message for transaction {name}"
            ));
            return true;
        }
        if let Some(ack_index) = ack_index {
            self.resend_step(call_id, ack_index);
            return true;
        }
        if final_hash == Some(msg_hash) {
            self.log_err(&format!(
                "Ignoring final {transport} message for transaction {name} (hash {msg_hash})"
            ));
            return true;
        }
        false
    }

    fn scan_call(&self, call_id: &str, window_start: usize, waiting: bool, msg: &Inbound) -> Scan {
        let (secondary, txns, invite_cseq) =
            self.calls.get(call_id).map_or((false, &[][..], None), |c| {
                (c.secondary, c.txns.as_slice(), c.last_recv_invite_cseq)
            });
        let ack_guard = if self.config.behaviors.cseq {
            invite_cseq
        } else {
            None
        };
        match self.secondary.as_ref() {
            Some(o) if secondary => scan_for_match_guarded(
                o.scenario,
                &o.expected_cseq_method,
                txns,
                window_start,
                waiting,
                msg,
                ack_guard,
            ),
            _ => scan_for_match_guarded(
                self.scenario,
                &self.expected_cseq_method,
                txns,
                window_start,
                waiting,
                msg,
                ack_guard,
            ),
        }
    }

    fn start_call(&mut self, user_id: Option<usize>) {
        let Some(target) = self.config.target else {
            return; // unreachable: validated in run_with_control
        };
        // SIPp takes the TDM circuit in the call constructor and books a
        // failed call (E_FAILED_OUTBOUND_CONGESTION) when none is free.
        let tdm_number = match self.alloc_tdm() {
            Ok(n) => n,
            Err(msg) => {
                self.log_err(msg);
                self.stats.failed_other += 1;
                return;
            }
        };
        self.stats.outgoing_created += 1;
        let number = self.stats.created();
        let call_id = self.make_call_id(number);
        self.insert_outgoing_call(call_id, number, target, tdm_number, user_id);
    }

    /// A call opened by a twin command that names it (SIPp's 3PCC server
    /// modes, `process_message`: "Adding a new OUTGOING call" keyed by the
    /// command's Call-ID, so `[call_id]` on this side is the master's).
    fn start_commanded_call(&mut self, call_id: &str) {
        let Some(target) = self.config.target else {
            return;
        };
        let tdm_number = match self.alloc_tdm() {
            Ok(n) => n,
            Err(msg) => {
                self.log_err(msg);
                self.stats.failed_other += 1;
                return;
            }
        };
        self.stats.outgoing_created += 1;
        let number = self.stats.created();
        self.insert_outgoing_call(call_id.to_owned(), number, target, tdm_number, None);
    }

    fn insert_outgoing_call(
        &mut self,
        call_id: String,
        number: u64,
        target: SocketAddr,
        tdm_number: Option<u32>,
        user_id: Option<usize>,
    ) {
        let cnonce = self.make_cnonce(number);
        let field_lines = self.assign_field_lines(user_id);
        let store = self.new_store(false, user_id);
        let txns = vec![TxnInstance::default(); self.scenario.transactions.len()];
        self.calls.insert(
            call_id.clone(),
            new_call(
                number,
                self.config.remote_sending_addr.unwrap_or(target),
                target,
                self.config.base_cseq,
                store,
                txns,
                cnonce,
                field_lines,
                user_id,
            ),
        );
        if let Some(call) = self.calls.get_mut(&call_id) {
            call.tdm_number = tdm_number;
        }
        self.call_debug(&call_id, format!("Starting call {call_id}\n"));
        self.advance(&call_id);
    }

    /// `-users` closed loop: open replacement calls until N are live (or the
    /// `-m` cap / free pool runs out). No-op outside users mode.
    fn refill_users(&mut self) {
        let Some(n) = self.config.users else {
            return;
        };
        while self.live_main() < n && !self.done_creating() {
            let Some(uid) = self.free_users.pop_back() else {
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
                    let (buf, remote) = match self.render_send(call_id, index, send) {
                        Some(Ok(rendered)) => rendered,
                        Some(Err(e)) => {
                            self.fail_call(call_id, &format!("render failed: {e}"));
                            return;
                        }
                        None => return,
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
                    if let Err(e) = self.send_for_call(
                        call_id,
                        &buf,
                        remote,
                        send.lost_pct.or(self.config.lost),
                    ) {
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
                    let lost_pct = send.lost_pct.or(self.config.lost);
                    let jump = self.jump_target(&send.common, index, call_id);
                    let now = Instant::now();
                    let common = send.common.clone();
                    let Some(call) = self.calls.get_mut(call_id) else {
                        return;
                    };
                    let on_secondary = call.secondary;
                    if first == "ACK" {
                        // SIPp `call_established = true` on sending an ACK.
                        call.established = true;
                        call.ack_pending = false;
                    }
                    apply_rtds(
                        call,
                        stats_for(&mut self.stats, self.secondary.as_mut(), on_secondary),
                        &common,
                        now,
                    );
                    if method_is_new_txn {
                        call.cseq = call.cseq.wrapping_add(1);
                    }
                    // Manual transactions (SIPp call.cpp ~l.2110-2116): a
                    // `start_txn` send names its Via branch, an `ack_txn`
                    // send records where its ACK lives.
                    if let Some(t) = send.start_txn
                        && let Some(slot) = call.txns.get_mut(t)
                    {
                        slot.branch = sent_via_branch(&buf);
                    }
                    if let Some(t) = send.ack_txn
                        && let Some(slot) = call.txns.get_mut(t)
                    {
                        slot.ack_index = Some(index);
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
                            first == "INVITE",
                            RetransCaps {
                                invite: self.config.max_invite_retrans,
                                non_invite: self.config.max_non_invite_retrans,
                                global: self.config.max_retrans,
                            },
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
                    // SIPp `curmsg->sessions++` on entering the pause.
                    if let Some(s) = self.call_stats(call_id).step_mut(index) {
                        s.sessions += 1;
                    }
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
                Step::SendCmd {
                    template,
                    common,
                    dest,
                } => {
                    let Some(rendered) = self.render_call_template(call_id, index, template) else {
                        return;
                    };
                    // Classic: the one twin. Extended: the named peer's link
                    // (SIPp `sendCmdMessage` → `get_peer_socket(peer_dest)`).
                    let result = match (&self.twin, dest) {
                        (Some(TwinLink::Classic(ch)), _) => ch.send(&rendered),
                        (Some(TwinLink::Extended { links, .. }), Some(peer)) => {
                            links.send_to(peer, &rendered)
                        }
                        (Some(TwinLink::Extended { .. }), None) => Err(std::io::Error::new(
                            std::io::ErrorKind::NotConnected,
                            "sendCmd without dest= in extended 3PCC mode",
                        )),
                        (None, _) => Err(std::io::Error::new(
                            std::io::ErrorKind::NotConnected,
                            "no -3pcc twin socket",
                        )),
                    };
                    if let Err(e) = result {
                        self.fail_call(call_id, &format!("3PCC <sendCmd> failed: {e}"));
                        return;
                    }
                    // SIPp `M_nbCmdSent` (the `-trace_counts` SendCmd column).
                    if let Some(s) = self.call_stats(call_id).step_mut(index) {
                        s.sent += 1;
                    }
                    let jump = self.jump_target(common, index, call_id);
                    if let Some(call) = self.calls.get_mut(call_id) {
                        call.index = jump;
                    }
                }
                Step::RecvCmd { optional, .. } => {
                    // Block until a command naming this call arrives. An
                    // optional recvCmd is transparent to SIP (SIPp's
                    // `process_incoming` skips optional steps): the recv
                    // window behind it stays open, so a message for the
                    // next recv passes over it.
                    let mandatory = if *optional {
                        self.window_mandatory(call_id, index)
                    } else {
                        None
                    };
                    let Some(call) = self.calls.get_mut(call_id) else {
                        return;
                    };
                    call.awaiting_cmd = true;
                    if *optional {
                        call.waiting = true;
                        if let Some((_, Some(ms))) = mandatory {
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
                    .is_some_and(|c| test_truthy(&c.store.get(v))),
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
                Step::RecvCmd { optional: true, .. } => i += 1,
                Step::Recv(r) => {
                    // `-recv_timeout`: the default for a recv without its own.
                    let default_ms = self
                        .config
                        .recv_timeout
                        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    return Some((i, r.timeout_ms.or(default_ms)));
                }
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
            PauseSpec::Distribution(d) => {
                let ms = crate::sample::sample(d, &mut self.rng);
                Duration::from_millis(crate::sample::pause_millis(ms))
            }
        }
    }

    // ---- inbound -------------------------------------------------------

    fn on_packet(&mut self, packet: &sipr_net::InboundPacket) {
        let msg = &packet.message;
        self.trace_recv(packet);
        let Some(call_id) = self.trimmed_call_id(msg) else {
            self.stats.unexpected += 1;
            self.stats.out_of_call_msgs += 1;
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
            // A finished call still remembered (`-deadcall_wait`): SIPp's
            // deadcall answers with a warning and a trace entry, refreshes
            // its expiry and counts DeadCallMsgs — no new call, no
            // out-of-call handling.
            if let Some(reason) = self.dead_calls.get(&call_id).map(|d| d.reason.clone()) {
                if let Some(d) = self.dead_calls.get_mut(&call_id) {
                    d.expires = Instant::now() + self.config.deadcall_wait;
                }
                self.stats.dead_call_msgs += 1;
                let transport = self.transport_token;
                if let Some(f) = self.trace_msg.as_mut() {
                    f.write(&sipr_stats::dead_call_frame(
                        &call_id,
                        transport,
                        &packet.raw,
                    ));
                }
                self.log_err(&format!(
                    "Dead call {call_id} ({reason}), received '{}'",
                    String::from_utf8_lossy(&packet.raw)
                ));
                return;
            }
            // UAS: an unknown Call-ID carrying the scenario's initial request
            // creates a new call.
            if self.scenario.role == Role::Uas
                && msg.method().is_some()
                && matches!(
                    scan_for_match(self.scenario, &self.expected_cseq_method, &[], 0, true, msg),
                    Scan::Forward(_)
                )
            {
                self.stats.incoming_created += 1;
                let number = self.stats.created();
                let cnonce = self.make_cnonce(number);
                // Incoming (UAS) calls have no user id.
                let field_lines = self.assign_field_lines(None);
                let store = self.new_store(false, None);
                let txns = vec![TxnInstance::default(); self.scenario.transactions.len()];
                self.calls.insert(
                    call_id.clone(),
                    new_call(
                        number,
                        self.config.remote_sending_addr.unwrap_or(packet.from),
                        packet.from,
                        self.config.base_cseq,
                        store,
                        txns,
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
                self.call_debug(&call_id, format!("Starting call {call_id}\n"));
                // Fall through to normal matching below (window at 0).
            } else if let Some(method) = msg.method()
                && let Some(kind) = self.secondary.as_ref().map(|o| o.kind)
            {
                // Client mode with a secondary scenario (SIPp socket.cpp
                // `process_message`): a request of no known call spawns a
                // call on it — no user id — counted as an incoming call on
                // that scenario's stats; the request is then matched against
                // its step 0. Out-of-call: SIPp's warning plus the global
                // auto-answered counter. Mixed mode: SIPp logs nothing; the
                // error-trace line is sipr's.
                match kind {
                    SecondaryKind::OutOfCall => self.log_err(&format!(
                        "Received out-of-call {method} message, using the out-of-call scenario"
                    )),
                    SecondaryKind::Receive => self.log_err(&format!(
                        "Received {method} for no known call, using the receive scenario"
                    )),
                }
                self.spawn_secondary_call(&call_id, packet);
            } else {
                // An unmapped response (or no secondary scenario at all):
                // SIPp's E_OUT_OF_CALL_MSGS. (In mixed mode SIPp spawns a
                // receive call even for a response, which then fails on it;
                // sipr keeps discarding responses, as its UAS does.)
                self.stats.unexpected += 1;
                self.stats.out_of_call_msgs += 1;
                self.log_err(&format!("out-of-call message ignored (Call-ID {call_id})"));
                return;
            }
        }
        // `-pause_msg_ign`: whatever arrives while the call sits in a pause
        // is dropped before anything is counted or answered.
        if self.config.pause_msg_ign
            && self
                .calls
                .get(&call_id)
                .is_some_and(|c| c.pause_deadline.is_some())
        {
            return;
        }
        let (window_start, waiting, completing, is_dup, secondary) = match self.calls.get(&call_id)
        {
            Some(c) => (
                c.index,
                c.waiting,
                c.completing,
                c.last_recv_key.as_ref() == Some(&key),
                c.secondary,
            ),
            None => return,
        };
        if is_dup {
            self.stats_of(secondary).retrans_recv += 1;
            // Re-send our last message (SIPp: retransmitted request → last
            // response again; harmless for a duplicated response).
            let resend = self
                .calls
                .get(&call_id)
                .and_then(|c| c.last_sent.clone().map(|b| (b, c.remote)));
            if let Some((buf, remote)) = resend {
                let _ = self.send_for_call(&call_id, &buf, remote, None);
                self.stats_of(secondary).retrans_sent += 1;
                self.trace_send(&buf, remote);
            }
            return;
        }
        if completing {
            // Timewait: absorb without failing (deadcall behavior).
            let stats = self.stats_of(secondary);
            stats.unexpected += 1;
            stats.dead_call_msgs += 1;
            return;
        }
        let msg_hash = hash_bytes(&packet.raw);
        let scan = match self.scan_call(&call_id, window_start, waiting || window_start == 0, msg) {
            Scan::OldTxn(txn) => {
                if self.on_old_transaction_response(&call_id, txn, msg, msg_hash) {
                    return;
                }
                Scan::NoMatch
            }
            other => other,
        };
        match scan {
            Scan::Forward(si) => {
                // A recv's `lost=` (or the global `-lost`) drops the
                // message it just matched (SIPp `call::lost` on receive).
                let lost = match &self.scenario_of(&call_id).steps[si] {
                    Step::Recv(r) => r.lost_pct.or(self.config.lost),
                    _ => None,
                };
                if let Some(p) = lost
                    && self.rng.chance_pct(p)
                {
                    let transport = self.transport_token;
                    self.call_debug(
                        &call_id,
                        format!("{transport} message lost (recv) (hash {msg_hash}).\n"),
                    );
                    return;
                }
                self.on_matched(&call_id, si, msg, msg_hash, key);
            }
            Scan::Old => {
                // Late/repeated optional (e.g. another 180): absorbed.
                self.stats_of(secondary).messages_matched += 1;
                if let Some(call) = self.calls.get_mut(&call_id) {
                    call.last_recv_key = Some(key);
                }
            }
            Scan::NoMatch | Scan::OldTxn(_) => {
                if self.try_unexpected_jump(&call_id, packet) {
                    return;
                }
                if self.try_auto_answer(&call_id, msg) {
                    return;
                }
                let transport = self.transport_token;
                self.call_debug(
                    &call_id,
                    format!(
                        "Unexpected {transport} message received (index {window_start}, hash {}):\n\n{}\n",
                        msg_hash,
                        String::from_utf8_lossy(&packet.raw)
                    ),
                );
                let stats = self.stats_of(secondary);
                stats.unexpected += 1;
                if let Some(code) = msg.status_code() {
                    stats.record_error_code(code);
                }
                if let Some(s) = stats.step_mut(window_start) {
                    s.unexpected += 1;
                }
                // SIPp `checkAutomaticResponseMode`: BYE, CANCEL and PING
                // have their own automatic handling; everything else is
                // the plain unexpected-message case.
                match msg.method() {
                    Some(m @ ("BYE" | "CANCEL")) => {
                        self.on_unexpected_bye_or_cancel(&call_id, m, secondary);
                    }
                    Some("PING") => self.on_unexpected_ping(&call_id),
                    _ => {
                        let what = msg
                            .method()
                            .map_or_else(|| format!("{:?}", msg.status_code()), ToOwned::to_owned);
                        if !self.config.behaviors.abortunexp {
                            // SIPp: "Continuing call on unexpected message …".
                            self.log_err(&format!(
                                "Continuing call on unexpected message for Call-Id '{call_id}': {what}"
                            ));
                            return;
                        }
                        self.stats_of(secondary).failed_unexpected += 1;
                        self.log_err(&format!(
                            "Aborting call on unexpected message for Call-Id '{call_id}': {what}"
                        ));
                        self.send_twin_abort(&call_id);
                        self.send_abort_messages(&call_id);
                        self.remove_call(&call_id);
                    }
                }
            }
        }
    }

    /// Create a call on the secondary scenario for a request of no known
    /// call, keyed by its Call-ID. The remote is the packet's source (or
    /// `-rsa`); the reply leaves on the socket the request hit, when that
    /// is a per-IP or per-call one. An out-of-call call carries no injection
    /// line and counts as auto-answered (SIPp `E_AUTO_ANSWERED`); a receive
    /// call draws its lines like any incoming call.
    fn spawn_secondary_call(&mut self, call_id: &str, packet: &sipr_net::InboundPacket) {
        let Some(kind) = self.secondary.as_ref().map(|o| o.kind) else {
            return;
        };
        let field_lines = match kind {
            SecondaryKind::OutOfCall => vec![None; self.inf_files.len()],
            SecondaryKind::Receive => self.assign_field_lines(None),
        };
        let Some(o) = self.secondary.as_mut() else {
            return;
        };
        o.stats.incoming_created += 1;
        let number = o.stats.created();
        if kind == SecondaryKind::OutOfCall {
            self.stats.auto_answered += 1;
        }
        let txns = vec![TxnInstance::default(); o.scenario.transactions.len()];
        let cnonce = self.make_cnonce(number);
        let store = self.new_store(true, None);
        let mut call = new_call(
            number,
            self.config.remote_sending_addr.unwrap_or(packet.from),
            packet.from,
            self.config.base_cseq,
            store,
            txns,
            cnonce,
            field_lines,
            None,
        );
        call.secondary = true;
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
        self.secondary_live += 1;
    }

    /// Common handling for a message matched at step `si`.
    fn on_matched(
        &mut self,
        call_id: &str,
        si: usize,
        msg: &Inbound,
        msg_hash: u64,
        key: (String, String, String),
    ) {
        let stats = self.call_stats(call_id);
        stats.messages_matched += 1;
        if let Some(s) = stats.step_mut(si) {
            s.recv += 1;
        }
        let scenario = self.scenario_of(call_id);
        let (rrs, ignore_sdp, response_txn, common) = match &scenario.steps[si] {
            Step::Recv(r) => (
                r.record_route_set,
                r.ignore_sdp,
                r.response_txn,
                r.common.clone(),
            ),
            _ => (false, false, None, StepCommon::default()),
        };
        let has_media = self.media.is_some();
        let now = Instant::now();
        let Some(call) = self.calls.get_mut(call_id) else {
            return;
        };
        // SIPp: an ACK received establishes the call, a 200 received leaves
        // an ACK pending (abort sends ACK+BYE rather than CANCEL), and the
        // last INVITE's CSeq guards later ACKs (`cseq` behavior).
        if msg.method() == Some("ACK") {
            call.established = true;
        }
        if msg.status_code() == Some(200) {
            call.ack_pending = true;
        }
        if msg.method() == Some("INVITE") {
            call.last_recv_invite_cseq = msg.cseq().map(|(n, _)| n);
        }
        // A matched recv cancels the pending retransmission
        // (call.cpp: next_retrans = 0) and the window timeout.
        if let Some(r) = call.retrans.take() {
            self.timers.cancel(r.timer);
        }
        if let Some((t, _)) = call.timer.take() {
            self.timers.cancel(t);
        }
        call.generation += 1;
        // SIPp: the response taken for a named transaction is "the final
        // response" — a later copy of it is recognised by hash.
        if let Some(t) = response_txn
            && let Some(slot) = call.txns.get_mut(t)
        {
            slot.final_hash = Some(msg_hash);
        }
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
        let on_secondary = call.secondary;
        apply_rtds(
            call,
            stats_for(&mut self.stats, self.secondary.as_mut(), on_secondary),
            &common,
            now,
        );
        call.last_recv_key = Some(key);
        if has_media && !ignore_sdp {
            learn_remote_media(call, msg);
        }
        call.last_recv = Some(msg.clone());
        call.waiting = false;
        call.awaiting_cmd = false;
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
        // Owned so the ctx borrows no `&self` method result: the actions
        // below draw from `self.rng` while the ctx is alive.
        let server_ip = self.server_ip_of(call).to_owned();
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
                server_ip: &server_ip,
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
                run: run_info(
                    &self.config,
                    &self.dynamic_id,
                    &self.file_cache,
                    self.run_start,
                    call,
                ),
                fields: crate::render::FieldSource {
                    files: &self.inf_files,
                    lines: &call.field_lines,
                },
            };
            match cmd_text {
                Some(text) => {
                    crate::actions::run_cmd_actions(actions, &mut store, text, &ctx, &mut self.rng)
                }
                None => crate::actions::run_actions(
                    actions,
                    &mut store,
                    last.as_ref(),
                    &ctx,
                    self.config.auth_uri.as_deref(),
                    &mut self.rng,
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
                crate::actions::ActionOutcome::Log(line) => self.log_action(&line),
                crate::actions::ActionOutcome::Warn(line) => self.log_err(&line),
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
                crate::actions::ActionOutcome::ExecCommand(command) => {
                    self.exec_runner
                        .get_or_insert_with(crate::exec::ExecRunner::start)
                        .run(command);
                }
                crate::actions::ActionOutcome::SetDest {
                    host,
                    port,
                    protocol,
                } => {
                    if let Err(why) = self.apply_setdest(call_id, &host, &port, &protocol) {
                        self.call_stats(call_id).failed_other += 1;
                        self.log_err(&format!("call {call_id} failed: setdest: {why}"));
                        self.remove_call(call_id);
                        return true;
                    }
                }
            }
        }
        false
    }

    /// `<setdest>` (SIPp `E_AT_SET_DEST`, `call.cpp` ~l.5841-5935): move the
    /// rest of this call's traffic to another peer. Every check SIPp makes
    /// is made here with its wording — but a failure ends the call, not the
    /// run. UDP retargets the call; per-call TCP/SCTP closes the call's
    /// connection and dials the new peer, a failure spending one
    /// `-max_reconnect` credit. `[remote_ip]`/`[remote_port]` keep the
    /// nominal remote, as SIPp's globals do.
    fn apply_setdest(
        &mut self,
        call_id: &str,
        host: &str,
        port: &str,
        protocol: &str,
    ) -> Result<(), String> {
        let wire = setdest_protocol(protocol, self.config.transport)?;
        let port = setdest_port(port)?;
        if host.parse::<IpAddr>().is_err() && !self.setdest_dns_warned {
            self.setdest_dns_warned = true;
            self.log_err(
                "setdest: resolving a host name blocks the engine thread while it runs \
                 (SIPp's getaddrinfo does the same)",
            );
        }
        let new_remote = resolve_setdest_host(host, port)?;
        let Some(call) = self.calls.get(call_id) else {
            return Ok(());
        };
        if wire == SetDestWire::Udp || call.socket.is_none() {
            // No connection to move: the next send goes (and, per-call,
            // dials) to the new peer.
            if let Some(call) = self.calls.get_mut(call_id) {
                call.remote = new_remote;
            }
            return Ok(());
        }
        if call.socket.as_ref().is_some_and(CallSocket::shared) {
            return Err(
                "Can not change destinations for a TCP/SCTP socket that has more than one user."
                    .to_owned(),
            );
        }
        let dialed = match &self.transport {
            Transport::Tcp(t) => t
                .connect_call(new_remote)
                .map(|c| CallSocket::Tcp(Arc::new(c))),
            #[cfg(feature = "sctp")]
            Transport::Sctp(t) => t
                .connect_call(new_remote)
                .map(|c| CallSocket::Sctp(Arc::new(c))),
            // Refused above (TLS) or moved without a dial (UDP).
            _ => return Ok(()),
        };
        match dialed {
            Ok(socket) => {
                self.call_socket_pool.push(socket.downgrade());
                if let Some(call) = self.calls.get_mut(call_id) {
                    call.socket = Some(socket);
                    call.remote = new_remote;
                }
                Ok(())
            }
            Err(e) => {
                // SIPp: a warning and one reconnection credit; out of
                // credits it is "Max number of reconnections reached".
                if !self.reconnect_allowed() {
                    let msg = "Max number of reconnections reached".to_owned();
                    eprintln!("sipr: error: {msg}");
                    self.log_err(&msg);
                    self.fatal = Some(msg.clone());
                    self.fail_all("connection lost");
                    self.hard_stop = true;
                    return Err(msg);
                }
                if self.reconnects_left > 0 {
                    self.reconnects_left -= 1;
                }
                self.log_err("Unable to connect a TCP/SCTP/TLS socket");
                Err(format!("cannot connect to {new_remote}: {e}"))
            }
        }
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
            run: run_info(
                &self.config,
                &self.dynamic_id,
                &self.file_cache,
                self.run_start,
                call,
            ),
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
        // SIPp `M_nbCmdRecv` (the `-trace_counts` RecvCmd column).
        if let Some(s) = self.call_stats(call_id).step_mut(index) {
            s.recv += 1;
        }
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

    fn on_twin_event(&mut self, event: TwinEvent) {
        match event {
            TwinEvent::Command(cmd) => self.on_twin_cmd(cmd),
            TwinEvent::Connected => self.on_twin_connected(),
            TwinEvent::Closed => self.on_twin_closed(),
        }
    }

    /// A peer reached our twin socket. A slave dials its own `dest=` peers
    /// only now (SIPp `pollset_process`: `connect_to_all_peers` on the
    /// first accepted local socket), so the master can be launched last.
    fn on_twin_connected(&mut self) {
        let Some(TwinLink::Extended { links, dests }) = &mut self.twin else {
            return;
        };
        if links.is_connected() {
            return;
        }
        if let Err(e) = links.connect_all(dests) {
            eprintln!("sipr: error: {e}");
            self.log_err(&e.to_string());
            self.fail_all("twin peer unreachable");
            self.hard_stop = true;
        }
    }

    /// A twin connection ended. SIPp treats this as the run being over:
    /// "One of the twin instances has ended -> exiting" (extended), "3PCC
    /// controller A has ended -> exiting" (controller B); controller A just
    /// stops creating calls. sipr drains the calls in flight.
    fn on_twin_closed(&mut self) {
        if self.twin_ended {
            return;
        }
        self.twin_ended = true;
        let line = match (&self.twin, twin_role(self.scenario)) {
            (Some(TwinLink::Extended { .. }), _) => {
                "One of the twin instances has ended -> exiting"
            }
            (Some(TwinLink::Classic(_)), Some(TwinRole::Listen)) => {
                "3PCC controller A has ended -> exiting"
            }
            _ => "3PCC twin has ended -> no more calls",
        };
        eprintln!("sipr: warning: {line}");
        self.log_err(line);
        self.soft_stopping = true;
    }

    /// A twin command arrived. SIPp routes it like a SIP message: by the
    /// Call-ID it carries, opening the call when this side's calls are
    /// command-driven (controller B, slaves) and discarding it otherwise.
    fn on_twin_cmd(&mut self, cmd: String) {
        let Some(call_id) = command_call_id(&cmd, self.config.callid_slash_ign) else {
            self.stats.out_of_call_msgs += 1;
            self.log_err("twin command without Call-ID discarded");
            return;
        };
        if !self.calls.contains_key(&call_id) {
            if !self.twin_creates_calls {
                self.stats.out_of_call_msgs += 1;
                self.log_err(&format!(
                    "Discarding message which can't be mapped to a known SIPp call:\n{cmd}"
                ));
                return;
            }
            if self.done_creating() {
                self.stats.out_of_call_msgs += 1;
                self.log_err("Discarded message for new calls while quitting");
                return;
            }
            self.start_commanded_call(&call_id);
        }
        if is_abort_command(&cmd) {
            // SIPp `checkInternalCmd`: the other controller dropped its half.
            self.fail_call(&call_id, "aborted by the twin (internal-cmd: abort_call)");
            return;
        }
        self.process_twin_cmd(&call_id, &cmd);
    }

    /// SIPp `process_twinSippCom`: from the call's current step, skip
    /// optional steps and nops; the first `recvCmd` takes the command (in
    /// extended mode only if its `src=` is the command's `From:`), while a
    /// mandatory step of another kind means the command was unexpected and
    /// the call is rejected.
    fn process_twin_cmd(&mut self, call_id: &str, cmd: &str) {
        let index = self.calls.get(call_id).map_or(0, |c| c.index);
        let scenario = self.scenario_of(call_id);
        let mut found = None;
        let mut why = "no such message found";
        for (i, step) in scenario.steps.iter().enumerate().skip(index) {
            match step {
                Step::RecvCmd { src, .. } => {
                    found = Some((i, src.as_deref()));
                    break;
                }
                Step::Nop { .. } | Step::Label { .. } => {}
                Step::Recv(r) if r.optional => {}
                _ => {
                    why = "I was expecting a different type of message";
                    break;
                }
            }
        }
        let Some((si, src)) = found else {
            self.log_err(&format!(
                "Unexpected control message received ({why}):\n{cmd}"
            ));
            self.reject_call(call_id);
            return;
        };
        if matches!(self.twin, Some(TwinLink::Extended { .. }))
            && let Some(src) = src
            && command_from(cmd) != Some(src)
        {
            self.log_err(&format!(
                "Unexpected sender for the received peer message\n{cmd}"
            ));
            self.reject_call(call_id);
            return;
        }
        // Leaving the wait (and any recv window an optional recvCmd kept
        // open).
        if let Some(call) = self.calls.get_mut(call_id) {
            call.awaiting_cmd = false;
            call.waiting = false;
            if let Some((t, _)) = call.timer.take() {
                self.timers.cancel(t);
            }
            call.generation += 1;
        }
        let (actions, common) = match scenario.steps.get(si) {
            Some(Step::RecvCmd {
                actions, common, ..
            }) => (actions, common),
            _ => return,
        };
        // SIPp strips the trailing CRLFs the transport added before the
        // actions see the command.
        let text = cmd.trim_end_matches("\r\n");
        if !self.deliver_recv_cmd(call_id, si, actions, common, text) {
            self.advance(call_id);
        }
    }

    /// SIPp `rejectCall`: the call fails as unexpected, without the abort
    /// messages an `abortCall` would send.
    fn reject_call(&mut self, call_id: &str) {
        let secondary = self.on_secondary(call_id);
        self.stats_of(secondary).failed_unexpected += 1;
        self.remove_call(call_id);
    }

    /// SIPp's `3pcc_abort` command: when a call past its first step is
    /// aborted on an unexpected message while a classic twin is attached,
    /// the other controller is told to drop its half (`internal-cmd:
    /// abort_call`). Extended mode has no single twin socket, so SIPp sends
    /// nothing there.
    fn send_twin_abort(&mut self, call_id: &str) {
        let Some(TwinLink::Classic(ch)) = &self.twin else {
            return;
        };
        if self.calls.get(call_id).is_none_or(|c| c.index == 0) {
            return;
        }
        let cmd = format!("call-id: {call_id}\ninternal-cmd: abort_call\n\n");
        if let Err(e) = ch.send(&cmd) {
            self.log_err(&format!("sendCmdBuffer returned an error: {e}"));
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
        call.awaiting_cmd = false;
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

    /// A message went out: the `-trace_msg` frame, the `-trace_shortmsg`
    /// line and the call's `-trace_calldebug` entry (SIPp `send_raw` /
    /// `SIPpSocket::write_primitive`).
    fn trace_send(&mut self, buf: &[u8], _remote: SocketAddr) {
        let transport = self.transport_token;
        let rfc3339 = self.config.rfc3339;
        if let Some(f) = self.trace_msg.as_mut() {
            f.write(&sipr_stats::sipp_message_frame(transport, "sent", buf));
        }
        if let Some(f) = self.trace_shortmsg.as_mut() {
            f.write(&sipr_stats::short_message_line('S', buf, rfc3339));
        }
        if self.trace_calldebug.is_some()
            && let Some(call_id) = sipr_stats::message_call_id(buf)
        {
            let index = self.calls.get(&call_id).map_or(0, |c| c.index);
            self.call_debug(
                &call_id,
                format!(
                    "Sending {transport} message for call {call_id} (index {index}, hash {}):\n{}\n\n",
                    hash_bytes(buf),
                    String::from_utf8_lossy(buf)
                ),
            );
        }
    }

    /// A message came in: the `-trace_msg` frame, the `-trace_shortmsg`
    /// line and the call's `-trace_calldebug` entry (SIPp `process_message`
    /// / `call::process_incoming`).
    fn trace_recv(&mut self, packet: &sipr_net::InboundPacket) {
        let transport = self.transport_token;
        let rfc3339 = self.config.rfc3339;
        if let Some(f) = self.trace_msg.as_mut() {
            f.write(&sipr_stats::sipp_message_frame(
                transport,
                "received",
                &packet.raw,
            ));
        }
        if let Some(f) = self.trace_shortmsg.as_mut() {
            f.write(&sipr_stats::short_message_line('R', &packet.raw, rfc3339));
        }
        if self.trace_calldebug.is_some()
            && let Some(call_id) = self.trimmed_call_id(&packet.message)
        {
            self.call_debug(
                &call_id,
                format!(
                    "Processing {} byte incoming message for call-ID {call_id} (hash {}):\n{}\n\n",
                    packet.raw.len(),
                    hash_bytes(&packet.raw),
                    String::from_utf8_lossy(&packet.raw)
                ),
            );
        }
    }

    /// Append a `-trace_calldebug` entry to the call's buffer (SIPp
    /// `callDebug`: timestamped, dumped when the call aborts).
    fn call_debug(&mut self, call_id: &str, text: String) {
        if self.trace_calldebug.is_none() {
            return;
        }
        let rfc3339 = self.config.rfc3339;
        if let Some(call) = self.calls.get_mut(call_id) {
            call.debug
                .get_or_insert_with(String::new)
                .push_str(&sipr_stats::calldebug_line(&text, rfc3339));
        }
    }

    /// A `<log>` action's line, to the `-trace_logs` file (SIPp `LOG_MSG`).
    fn log_action(&mut self, line: &str) {
        if let Some(f) = self.trace_logs.as_mut() {
            f.write(&format!("{line}\n"));
        }
    }

    /// Remember a finished call for `-deadcall_wait` (SIPp `new deadcall`).
    fn remember_dead(&mut self, call_id: &str, reason: String) {
        if self.config.deadcall_wait.is_zero() {
            return;
        }
        self.dead_calls.insert(
            call_id.to_owned(),
            DeadCall {
                expires: Instant::now() + self.config.deadcall_wait,
                reason,
            },
        );
    }

    /// `dump variables` (SIPp `AllocVariableTable::dump` on the displayed
    /// scenario): the names per table level — global 0, user 1, call 2 —
    /// into the error trace.
    fn dump_variables(&mut self) {
        let displayed = match self.secondary.as_ref() {
            Some(o) if self.display_secondary => o.scenario,
            _ => self.scenario,
        };
        let call_names: Vec<String> = displayed
            .vars
            .in_scope(sipr_scenario::model::VarScope::Call)
            .map(|(_, name)| name.to_owned())
            .collect();
        let levels = [
            (0, self.var_space.global_names().to_vec()),
            (1, self.var_space.user_names().to_vec()),
            (2, call_names),
        ];
        for (level, names) in levels {
            self.log_err(&format!("{} level {level} variables:", names.len()));
            for name in names {
                self.log_err(&name);
            }
        }
    }

    /// A line for the `-trace_err` file, timestamped as SIPp's `WARNING`s.
    fn log_err(&mut self, line: &str) {
        let rfc3339 = self.config.rfc3339;
        if let Some(f) = self.trace_err.as_mut() {
            f.write(&sipr_stats::error_line(line, rfc3339));
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
            self.forget_secondary(&call);
            let stats = self.stats_of(call.secondary);
            stats.successful += 1;
            stats.record_call_length(call.started.elapsed());
            self.release_tdm(&call);
            self.return_user(&call);
            self.remember_dead(call_id, "successful".to_owned());
        }
    }

    /// Keep the secondary live count in step when a secondary call leaves
    /// the table.
    fn forget_secondary(&mut self, call: &CallState) {
        if call.secondary {
            self.secondary_live = self.secondary_live.saturating_sub(1);
        }
    }

    /// Remove a call and record its duration WITHOUT bumping a failure
    /// counter — the caller has already categorized the failure.
    fn remove_call(&mut self, call_id: &str) {
        if let Some(mut call) = self.calls.remove(call_id) {
            self.cancel_call_timers(&mut call);
            self.stop_media(call_id);
            self.forget_secondary(&call);
            self.stats_of(call.secondary)
                .record_call_length(call.started.elapsed());
            self.release_tdm(&call);
            self.return_user(&call);
            // SIPp `call::abort`: the call's debug buffer goes to
            // -trace_calldebug, then the Call-ID lives on as a dead call.
            if let Some(f) = self.trace_calldebug.as_mut() {
                let mut debug = call.debug.take().unwrap_or_default();
                debug.push_str(&sipr_stats::calldebug_line(
                    &format!("Aborting call {call_id} (index {}).\n", call.index),
                    self.config.rfc3339,
                ));
                f.write(&format!(
                    "-------------------------------------------------------------------------------\nCall debugging information for call {call_id}:\n{debug}"
                ));
            }
            self.remember_dead(call_id, format!("aborted at index {}", call.index));
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

    /// A finished call's user id goes back to the free pool, or — while more
    /// calls are live than `set users` now allows — to the retired list
    /// (SIPp `CallGenerationTask::free_user`: `CurrentCall >
    /// open_calls_allowed` after the call left the count). Whichever ids
    /// happen to be live keep running; nothing is dropped by number.
    fn return_user(&mut self, call: &CallState) {
        let Some(uid) = call.user_id else {
            return;
        };
        if self.live_main() > self.config.users.unwrap_or(0) {
            self.retired_users.push_front(uid);
        } else {
            self.free_users.push_front(uid);
        }
    }

    /// The user's variable table, created on its first call and kept for
    /// the run.
    fn user_table(&mut self, uid: usize) -> crate::vars::SharedTable {
        if let Some(table) = self.user_vars.get(&uid) {
            return table.clone();
        }
        let table = self.var_space.user_table();
        self.user_vars.insert(uid, table.clone());
        table
    }

    /// A new call's variable store: its scenario's layout over the shared
    /// globals and either its user's table or, with no user id (UAS, ooc,
    /// rx calls), a private one — SIPp's fresh `VariableTable(userVariables)`.
    fn new_store(&mut self, secondary: bool, user_id: Option<usize>) -> crate::actions::VarStore {
        let layout = match (&self.secondary_layout, secondary) {
            (Some(layout), true) => layout.clone(),
            _ => self.main_layout.clone(),
        };
        let user = match user_id {
            Some(uid) => self.user_table(uid),
            None => self.var_space.user_table(),
        };
        crate::actions::VarStore::new(layout, user, self.global_vars.clone())
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
            // SIPp `abortCall`: the `bye` behavior ends the dialog properly
            // (not after a send failure: the socket is the problem).
            if !reason.contains("cannot send") {
                self.send_abort_messages(call_id);
            }
            self.remove_call(call_id);
        }
    }

    /// SIPp's `abortCall` messages, when the `bye` behavior is on: for a
    /// client-side call past its first step — an unestablished INVITE
    /// answered with a 4xx or worse gets an ACK; one answered with a 200
    /// gets ACK then BYE; one answered provisionally gets a CANCEL; one
    /// never answered gets nothing; any other call that received something
    /// gets a BYE. Server-side and secondary calls send nothing.
    fn send_abort_messages(&mut self, call_id: &str) {
        if !self.config.behaviors.bye || self.scenario.role != Role::Uac {
            return;
        }
        let Some(call) = self.calls.get(call_id) else {
            return;
        };
        if call.secondary || call.index == 0 {
            return;
        }
        let last_was_invite = call
            .last_sent
            .as_deref()
            .is_some_and(|b| b.starts_with(b"INVITE"));
        let last_code = call.last_recv.as_ref().and_then(Inbound::status_code);
        let received_any = call.last_recv.is_some();
        let (established, ack_pending, index) = (call.established, call.ack_pending, call.index);
        let mut plan: Vec<MsgTemplate> = Vec::new();
        if !established && last_was_invite {
            if last_code.is_some_and(|c| c >= 400) {
                plan.push(self.default_msgs.ack.clone());
            } else if received_any {
                if ack_pending {
                    plan.push(self.default_msgs.ack.clone());
                    plan.push(self.default_msgs.bye.clone());
                } else {
                    plan.push(self.default_msgs.cancel.clone());
                }
            }
        } else if received_any {
            plan.push(self.default_msgs.bye.clone());
        }
        for template in plan {
            self.send_default_message(call_id, index, &template);
        }
    }

    /// Render one of SIPp's built-in messages for the call and send it.
    fn send_default_message(&mut self, call_id: &str, index: usize, template: &MsgTemplate) {
        let Some(text) = self.render_call_template(call_id, index, template) else {
            return;
        };
        let Some(remote) = self.calls.get(call_id).map(|c| c.remote) else {
            return;
        };
        let buf = text.into_bytes();
        if self.send_for_call(call_id, &buf, remote, None).is_ok() {
            self.call_stats(call_id).messages_sent += 1;
            self.trace_send(&buf, remote);
        }
    }

    /// SIPp `E_AM_UNEXP_BYE`/`E_AM_UNEXP_CANCEL`: with `abortunexp` the
    /// call is aborted — after a 200 when `bye` is on — else it continues.
    fn on_unexpected_bye_or_cancel(&mut self, call_id: &str, method: &str, secondary: bool) {
        if !self.config.behaviors.abortunexp {
            self.log_err(&format!(
                "Continuing call on an unexpected {method} for call: {call_id}"
            ));
            return;
        }
        self.log_err(&format!(
            "Aborting call on an unexpected {method} for call: {call_id}"
        ));
        if self.config.behaviors.bye {
            let index = self.calls.get(call_id).map_or(0, |c| c.index);
            let ok = self.default_msgs.ok.clone();
            self.send_default_message(call_id, index, &ok);
        }
        self.send_twin_abort(call_id);
        self.stats_of(secondary).failed_unexpected += 1;
        self.remove_call(call_id);
    }

    /// SIPp `E_AM_PING`: with `pingreply` a 200 answers the PING and the
    /// call ends, neither successful nor failed; else it is left alone.
    fn on_unexpected_ping(&mut self, call_id: &str) {
        if !self.config.behaviors.pingreply {
            self.log_err(&format!(
                "Do not answer on an unexpected PING for call: {call_id}"
            ));
            return;
        }
        self.log_err(&format!(
            "Automatic response mode for an unexpected PING for call: {call_id}"
        ));
        let index = self.calls.get(call_id).map_or(0, |c| c.index);
        let ok = self.default_msgs.ok.clone();
        self.send_default_message(call_id, index, &ok);
        self.stats.auto_answered += 1;
        if let Some(mut call) = self.calls.remove(call_id) {
            self.cancel_call_timers(&mut call);
            self.stop_media(call_id);
            self.forget_secondary(&call);
            self.release_tdm(&call);
            self.return_user(&call);
        }
    }

    /// A message's Call-ID as SIPp keys calls by it: the part after a
    /// `///` (its 3PCC twin marker) unless `-callid_slash_ign`.
    fn trimmed_call_id(&self, msg: &Inbound) -> Option<String> {
        let raw = msg.call_id()?;
        Some(trim_call_id(raw, self.config.callid_slash_ign).to_owned())
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
/// `test="var"` on a message (SIPp `call::next`): the branch is taken when
/// the variable `isSet` — a string once assigned, a double when non-zero,
/// a bool when true.
fn test_truthy(v: &crate::actions::Value) -> bool {
    v.is_set()
}

/// Short display label for a step (scenario screen rows).
/// RTD names in order of first appearance (`start_rtd=`, then `rtd=`, per
/// step): SIPp numbers its RTDs by first mention in the scenario.
fn rtd_names(scenario: &Scenario) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for step in &scenario.steps {
        if let Some(c) = step_common(step) {
            for n in [c.start_rtd.as_ref(), c.rtd.as_ref()].into_iter().flatten() {
                if !names.contains(n) {
                    names.push(n.clone());
                }
            }
        }
    }
    names
}

/// What a step is for the `-trace_counts` columns (SIPp `print_count_file`:
/// a send is named by its method or status code, a recv by what it expects).
fn step_kind(step: &Step) -> sipr_stats::StepKind {
    match step {
        Step::Send(s) => {
            let what = template_first_word(&s.template).unwrap_or_default();
            let name = if what == "SIP/2.0" {
                s.template
                    .spans
                    .first()
                    .map_or(String::new(), |sp| match sp {
                        Span::Lit(l) => l.split_whitespace().nth(1).unwrap_or("").to_owned(),
                        Span::Kw(_) => String::new(),
                    })
            } else {
                what
            };
            sipr_stats::StepKind::Send {
                name,
                retrans: s.retrans_ms.is_some(),
            }
        }
        Step::Recv(r) => sipr_stats::StepKind::Recv {
            name: match &r.expect {
                Expect::Response(c) => c.clone(),
                Expect::Request(m) => m.clone(),
            },
        },
        // SIPp gives every pause (a bare one carries its default
        // distribution) and a timewait the Pause columns.
        Step::Pause { .. } | Step::Timewait { .. } => sipr_stats::StepKind::Pause,
        Step::SendCmd { .. } => sipr_stats::StepKind::SendCmd,
        Step::RecvCmd { .. } => sipr_stats::StepKind::RecvCmd,
        Step::Nop { .. } | Step::Label { .. } => sipr_stats::StepKind::Other,
    }
}

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
        Step::Pause { spec, .. } => match spec {
            PauseSpec::Default => "pause".to_owned(),
            PauseSpec::Fixed(ms) => format!("pause {ms}ms"),
            PauseSpec::Variable(_) => "pause [$var]".to_owned(),
            PauseSpec::Distribution(d) => format!("pause {}", d.describe()),
        },
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

/// `-set VARIABLE VALUE` (SIPp `sipp.cpp` `SIPP_OPTION_VAR`): seed the
/// globals before the run. A name no scenario declared `<Global>` is fatal
/// with SIPp's wording, plus the declared names for help.
fn seed_globals(
    space: &crate::vars::VarSpace,
    globals: &crate::vars::SharedTable,
    sets: &[(String, String)],
) -> Result<(), EngineError> {
    for (name, value) in sets {
        let Some(slot) = space.global_slot(name) else {
            let declared = if space.global_names().is_empty() {
                "none".to_owned()
            } else {
                space.global_names().join(", ")
            };
            return Err(EngineError(format!(
                "Can not set the global variable {name}, because it does not exist \
                 (declared <Global> variables: {declared})"
            )));
        };
        globals.set(slot, crate::actions::Value::Str(value.clone()));
    }
    Ok(())
}

/// The run-wide render inputs for one call (a free function over the
/// engine's fields so a caller can hold `&mut self.rng` alongside it).
fn run_info<'a>(
    config: &'a EngineConfig,
    dynamic: &'a crate::render::DynamicId,
    files: &'a std::cell::RefCell<HashMap<String, String>>,
    run_start: Instant,
    call: &CallState,
) -> crate::render::RunInfo<'a> {
    crate::render::RunInfo {
        clock_tick: u64::try_from(run_start.elapsed().as_millis()).unwrap_or(u64::MAX),
        remote_host: &config.remote_host,
        generic: &config.generic_keywords,
        dynamic: Some(dynamic),
        rfc3339: config.rfc3339,
        tdm: config.tdm_map.as_ref().zip(call.tdm_number),
        files: Some(files),
    }
}

/// Whether any send in `scenario` renders `[tdmmap]`.
fn uses_tdmmap(scenario: &Scenario) -> bool {
    scenario.steps.iter().any(|s| match s {
        Step::Send(send) => send
            .template
            .keywords()
            .any(|k| matches!(k, Keyword::TdmMap)),
        _ => false,
    })
}

/// Fresh call state.
#[allow(clippy::too_many_arguments)]
fn new_call(
    number: u64,
    remote: SocketAddr,
    render_remote: SocketAddr,
    base_cseq: u32,
    store: crate::actions::VarStore,
    txns: Vec<TxnInstance>,
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
        store,
        txns,
        counters: std::collections::HashMap::new(),
        cnonce,
        challenge: None,
        peer_tag: None,
        routes: Vec::new(),
        last_recv: None,
        tdm_number: None,
        debug: None,
        established: false,
        ack_pending: false,
        last_recv_invite_cseq: None,
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
        secondary: false,
    }
}

/// A scenario's own stat set: repartitions and per-step counters/labels.
fn new_stat_set(scenario: &Scenario) -> sipr_stats::StatSet {
    let mut stats = sipr_stats::StatSet::new(
        &scenario.response_time_repartition,
        &scenario.call_length_repartition,
    );
    stats.init_steps(scenario.steps.iter().map(step_label).collect());
    stats.set_rtd_names(rtd_names(scenario));
    stats.set_step_kinds(scenario.steps.iter().map(step_kind).collect());
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
    secondary: Option<&'a mut SecondaryScenario<'_>>,
    on_secondary: bool,
) -> &'a mut sipr_stats::StatSet {
    match secondary {
        Some(o) if on_secondary => &mut o.stats,
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
        } else {
            // No `start_rtd=` for this name: SIPp starts every RTD's clock
            // when the call is created (`call::init`, `start_time_rtd[i] =
            // getmicroseconds()`), so `rtd=` alone measures from call
            // start — its own default UAC relies on that.
            stats.record_rtd(name, now.saturating_duration_since(call.started));
            if common.repeat_rtd {
                call.rtd_starts.push((name.clone(), now));
            }
        }
    }
}

enum Scan {
    /// Matched at this forward step index.
    Forward(usize),
    /// Matched an already-passed optional (contiguous block behind us).
    Old,
    /// A response for a named transaction behind the contiguous block —
    /// SIPp's "reply to an old transaction" (call.cpp ~l.5395).
    OldTxn(TxnId),
    NoMatch,
}

/// SIPp's recv window scan, as verified in call.cpp (SIPP_COMPAT §6).
fn scan_for_match(
    scenario: &Scenario,
    expected_cseq_method: &[Option<String>],
    txns: &[TxnInstance],
    window_start: usize,
    waiting: bool,
    msg: &Inbound,
) -> Scan {
    scan_for_match_guarded(
        scenario,
        expected_cseq_method,
        txns,
        window_start,
        waiting,
        msg,
        None,
    )
}

/// [`scan_for_match`] with the `cseq` behavior's guard: an ACK matches only
/// when its CSeq number is `ack_guard`'s (SIPp `call::matches_cseq`,
/// `DEFAULT_BEHAVIOR_BADCSEQ`).
#[allow(clippy::too_many_arguments)]
fn scan_for_match_guarded(
    scenario: &Scenario,
    expected_cseq_method: &[Option<String>],
    txns: &[TxnInstance],
    window_start: usize,
    waiting: bool,
    msg: &Inbound,
    ack_guard: Option<u32>,
) -> Scan {
    if ack_guard.is_some() && msg.method() == Some("ACK") && msg.cseq().map(|(n, _)| n) != ack_guard
    {
        return Scan::NoMatch;
    }
    // Forward: optionals may be skipped; stop at first mandatory recv
    // (inclusive) or any non-recv step.
    if waiting {
        let mut i = window_start;
        while let Some(step) = scenario.steps.get(i) {
            match step {
                Step::Label { .. } | Step::RecvCmd { optional: true, .. } => {
                    i += 1;
                }
                Step::Recv(r) => {
                    if recv_matches(r, expected_cseq_method.get(i), txns, i, msg) {
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
    // Further back, only a recv tied to a named transaction can still
    // claim a response — by branch — as an "old transaction" reply.
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
                if contig {
                    if recv_matches(r, expected_cseq_method.get(i), txns, i, msg) {
                        return Scan::Old;
                    }
                } else if let Some(txn) = r.response_txn
                    && recv_matches(r, expected_cseq_method.get(i), txns, i, msg)
                {
                    return Scan::OldTxn(txn);
                }
            }
            _ => contig = false,
        }
        if !contig && scenario.transactions.is_empty() {
            break;
        }
    }
    Scan::NoMatch
}

/// The `branch=` of the topmost Via in a message we rendered (SIPp
/// `extract_transaction`: the value up to `;`, `,` or whitespace).
fn sent_via_branch(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            return None;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if !(name.eq_ignore_ascii_case("Via") || name.eq_ignore_ascii_case("v")) {
            continue;
        }
        let (_, rest) = value.split_once(";branch=")?;
        let branch: String = rest
            .chars()
            .take_while(|c| !matches!(c, ';' | ',') && !c.is_whitespace())
            .collect();
        return Some(branch);
    }
    None
}

/// SIPp's `hash(msg)` stand-in: a hash of the datagram, to recognise a
/// repeated final response of a named transaction.
/// SIPp `get_trimmed_call_id`: the text after the first `///`, unless
/// `-callid_slash_ign` keeps the whole value.
fn trim_call_id(raw: &str, keep_slashes: bool) -> &str {
    if keep_slashes {
        return raw;
    }
    raw.split_once("///").map_or(raw, |(_, rest)| rest)
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    use std::hash::{DefaultHasher, Hasher};
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

fn recv_matches(
    step: &RecvStep,
    expected_method: Option<&Option<String>>,
    txns: &[TxnInstance],
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
            // A named transaction matches by Via branch alone (SIPp
            // `matches_scenario`: before, and instead of, the rules below).
            if let Some(t) = step.response_txn {
                return txns
                    .get(t)
                    .and_then(|x| x.branch.as_deref())
                    .is_some_and(|branch| msg.top_via_branch() == Some(branch));
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
        // A request that names a transaction is matched by branch, not by
        // CSeq method, so SIPp leaves it out of the method list.
        if let Step::Send(s) = step
            && s.start_txn.is_none()
            && s.ack_txn.is_none()
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

/// Calls the pacer earns for `elapsed` wall time at `rate` calls per
/// `rate_period` (SIPp's `elapsed × rate / rate_period`, applied
/// incrementally). Elapsed time, not tick count, so a late tick still
/// credits the interval it covers.
fn pacer_credit(rate: f64, elapsed: Duration, rate_period: Duration) -> f64 {
    let period = rate_period.as_secs_f64();
    if period <= 0.0 {
        return 0.0;
    }
    rate * elapsed.as_secs_f64() / period
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
/// The wire a `<setdest protocol=>` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetDestWire {
    Udp,
    Tcp,
    Tls,
    Sctp,
}

/// SIPp's `setdest` protocol checks: one of the four names in either case,
/// the run's own transport, never TLS, and TCP/SCTP only in the per-call
/// (`-t tn|sn`, "multisocket") modes.
fn setdest_protocol(protocol: &str, transport: TransportKind) -> Result<SetDestWire, String> {
    let wire = match protocol.to_ascii_lowercase().as_str() {
        "udp" => SetDestWire::Udp,
        "tcp" => SetDestWire::Tcp,
        "tls" => SetDestWire::Tls,
        "sctp" => SetDestWire::Sctp,
        _ => return Err(format!("Unknown transport for setdest: '{protocol}'")),
    };
    let running = match transport {
        TransportKind::UdpMono | TransportKind::UdpPerCall | TransportKind::UdpPerIp => {
            SetDestWire::Udp
        }
        TransportKind::TcpMono | TransportKind::TcpPerCall => SetDestWire::Tcp,
        TransportKind::TlsMono | TransportKind::TlsPerCall => SetDestWire::Tls,
        TransportKind::SctpMono | TransportKind::SctpPerCall => SetDestWire::Sctp,
    };
    if wire != running {
        return Err("Can not switch protocols during setdest.".to_owned());
    }
    if wire == SetDestWire::Tls {
        return Err("Changing destinations is not supported for TLS.".to_owned());
    }
    if matches!(wire, SetDestWire::Tcp | SetDestWire::Sctp) && !transport.per_call() {
        return Err("Changing destinations for TCP or SCTP requires multisocket mode.".to_owned());
    }
    Ok(wire)
}

/// SIPp parses the port with `strtod` and rejects trailing text.
fn setdest_port(port: &str) -> Result<u16, String> {
    let text = port.trim();
    let invalid = || format!("Invalid port for setdest: {port}");
    let number: f64 = text.parse().map_err(|_| invalid())?;
    if number.fract() != 0.0 || !(0.0..=f64::from(u16::MAX)).contains(&number) {
        return Err(invalid());
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(number as u16)
}

/// An IP literal costs nothing; a host name is a blocking lookup (SIPp's
/// `gai_getsockaddr`, documented to stall).
fn resolve_setdest_host(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.trim().parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    use std::net::ToSocketAddrs;
    (host.trim(), port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .ok_or_else(|| format!("Unknown host '{host}' for setdest"))
}

/// Reject a scenario whose `[fieldN file=…]` names an injection file that was
/// not loaded (SIPp errors at parse time). A bare name or a numeric index both
/// count; `None` (the default file) needs at least one `-inf` — the first
/// `default_files` entries of `files` — as `-rxinf` never sets SIPp's
/// `default_file` ("No injection file was specified!").
fn validate_field_files(
    scenario: &Scenario,
    files: &[std::cell::RefCell<InjectionFile>],
    default_files: usize,
) -> Result<(), EngineError> {
    let resolves = |spec: Option<&str>| -> bool {
        match spec {
            None => default_files > 0,
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
                    None => "No injection file was specified! (the scenario uses a bare \
                             [fieldN], which reads the first -inf file)"
                        .to_owned(),
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
            scan_for_match(&sc, &methods, &[], 1, true, &response(200, "INVITE", true)),
            Scan::Forward(4)
        ));
        // A 183 lands on its own optional step 3.
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 1, true, &response(183, "INVITE", false)),
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
            scan_for_match(&sc, &methods, &[], 8, true, &response(200, "INVITE", true)),
            Scan::Forward(8)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 8, true, &response(200, "BYE", true)),
            Scan::Forward(8)
        ));
        // … but a response to a method never sent cannot.
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 8, true, &response(200, "OPTIONS", true)),
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
            scan_for_match(&sc, &methods, &[], 4, true, &response(180, "INVITE", false)),
            Scan::Old
        ));
        // Once past the mandatory 200 (ACK sent, window start 5), contig is
        // broken by the mandatory step: a late 180 is unexpected — verified
        // against call.cpp's backward loop (contig dies at OPTIONAL_FALSE).
        assert!(matches!(
            scan_for_match(
                &sc,
                &methods,
                &[],
                5,
                false,
                &response(180, "INVITE", false)
            ),
            Scan::NoMatch
        ));
        // And a random 486 never matches backward.
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 4, true, &response(486, "INVITE", false)),
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
            scan_for_match(&sc, &methods, &[], 0, true, &request("INFO")),
            Scan::Forward(0)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 0, true, &request("OPTIONS")),
            Scan::Forward(0)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 0, true, &request("BYE")),
            Scan::NoMatch
        ));
        // Responses: the regex runs over the decimal code, unanchored.
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 3, true, &response(183, "INVITE", false)),
            Scan::Forward(3)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 3, true, &response(200, "INVITE", true)),
            Scan::Forward(4)
        ));
        assert!(matches!(
            scan_for_match(&sc, &methods, &[], 3, true, &response(486, "INVITE", true)),
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
            scan_for_match(&sc, &methods, &[], 1, true, &bye),
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

    /// INVITE `a`, its 200 and ACK by name, then a plain BYE/200.
    fn txn_scenario() -> Scenario {
        let xml = r#"<scenario name="txn">
  <send start_txn="a"><![CDATA[
    INVITE sip:s@[remote_ip] SIP/2.0
    Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
    Call-ID: [call_id]
    CSeq: 1 INVITE

  ]]></send>
  <recv response="200" response_txn="a"/>
  <send ack_txn="a"><![CDATA[
    ACK sip:s@[remote_ip] SIP/2.0
    Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
    Call-ID: [call_id]
    CSeq: 1 ACK

  ]]></send>
  <send><![CDATA[
    BYE sip:s@[remote_ip] SIP/2.0
    Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
    Call-ID: [call_id]
    CSeq: 2 BYE

  ]]></send>
  <recv response="200"/>
</scenario>"#;
        sipr_scenario::compile("txn", xml).scenario.unwrap()
    }

    fn slot(branch: &str) -> Vec<TxnInstance> {
        vec![TxnInstance {
            branch: Some(branch.to_owned()),
            final_hash: None,
            ack_index: None,
        }]
    }

    #[test]
    fn sent_via_branch_reads_the_top_via_up_to_a_separator() {
        let msg = b"INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK-1-2-3;rport\r\n\
                    Via: SIP/2.0/UDP g;branch=other\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(sent_via_branch(msg).as_deref(), Some("z9hG4bK-1-2-3"));
        let compact = b"ACK sip:x SIP/2.0\r\nv: SIP/2.0/UDP h;branch=z9hG4bK-9,x\r\n\r\n";
        assert_eq!(sent_via_branch(compact).as_deref(), Some("z9hG4bK-9"));
        assert_eq!(
            sent_via_branch(b"SIP/2.0 200 OK\r\nTo: <sip:b>\r\n\r\n"),
            None
        );
    }

    #[test]
    fn response_txn_matches_by_branch_alone() {
        let sc = txn_scenario();
        let methods = precompute_cseq_methods(&sc);
        // The helper's responses carry branch z9hG4bK-1.
        let ok = response(200, "INVITE", true);
        assert!(matches!(
            scan_for_match(&sc, &methods, &slot("z9hG4bK-1"), 1, true, &ok),
            Scan::Forward(1)
        ));
        // Same code, same CSeq method, another branch: not this transaction.
        assert!(matches!(
            scan_for_match(&sc, &methods, &slot("z9hG4bK-2"), 1, true, &ok),
            Scan::NoMatch
        ));
        // The branch decides even when the CSeq method looks wrong …
        assert!(matches!(
            scan_for_match(
                &sc,
                &methods,
                &slot("z9hG4bK-1"),
                1,
                true,
                &response(200, "BYE", true)
            ),
            Scan::Forward(1)
        ));
        // … and a transaction never sent (no branch yet) matches nothing.
        assert!(matches!(
            scan_for_match(&sc, &methods, &[TxnInstance::default()], 1, true, &ok),
            Scan::NoMatch
        ));
    }

    #[test]
    fn a_late_reply_to_a_named_transaction_is_flagged_behind_the_window() {
        let sc = txn_scenario();
        let methods = precompute_cseq_methods(&sc);
        // Waiting for the BYE's 200 (step 4): the INVITE's 200 comes again.
        // Its method is not in the guard list (named requests stay out of
        // it), so it cannot land on step 4; the branch finds transaction a.
        assert!(matches!(
            scan_for_match(
                &sc,
                &methods,
                &slot("z9hG4bK-1"),
                4,
                true,
                &response(200, "INVITE", true)
            ),
            Scan::OldTxn(0)
        ));
        assert!(matches!(
            scan_for_match(
                &sc,
                &methods,
                &slot("z9hG4bK-1"),
                4,
                true,
                &response(200, "BYE", true)
            ),
            Scan::Forward(4)
        ));
        assert_eq!(
            methods[4].as_deref(),
            Some("BYE"),
            "INVITE and ACK named a transaction"
        );
    }

    #[test]
    fn setdest_checks_follow_sipp() {
        use TransportKind as T;
        assert_eq!(setdest_protocol("udp", T::UdpMono), Ok(SetDestWire::Udp));
        assert_eq!(setdest_protocol("UDP", T::UdpPerCall), Ok(SetDestWire::Udp));
        assert_eq!(setdest_protocol("tcp", T::TcpPerCall), Ok(SetDestWire::Tcp));
        assert_eq!(
            setdest_protocol("bogus", T::UdpMono),
            Err("Unknown transport for setdest: 'bogus'".to_owned())
        );
        assert_eq!(
            setdest_protocol("tcp", T::UdpMono),
            Err("Can not switch protocols during setdest.".to_owned())
        );
        assert_eq!(
            setdest_protocol("tls", T::TlsPerCall),
            Err("Changing destinations is not supported for TLS.".to_owned())
        );
        assert_eq!(
            setdest_protocol("tcp", T::TcpMono),
            Err("Changing destinations for TCP or SCTP requires multisocket mode.".to_owned())
        );
        assert_eq!(setdest_port("5060"), Ok(5060));
        assert_eq!(setdest_port(" 5062 "), Ok(5062));
        for bad in ["5060x", "", "70000", "-1", "50.5"] {
            assert_eq!(
                setdest_port(bad),
                Err(format!("Invalid port for setdest: {bad}")),
                "{bad:?}"
            );
        }
        assert_eq!(
            resolve_setdest_host("127.0.0.1", 5080),
            Ok(SocketAddr::from(([127, 0, 0, 1], 5080)))
        );
        assert_eq!(
            resolve_setdest_host("::1", 5080).map(|a| a.port()),
            Ok(5080),
            "bare IPv6 literal"
        );
        assert_eq!(
            resolve_setdest_host("no-such-host.invalid", 5080),
            Err("Unknown host 'no-such-host.invalid' for setdest".to_owned())
        );
    }

    #[test]
    fn pacer_credit_follows_elapsed_time_not_tick_count() {
        let period = Duration::from_millis(1000);
        // A nominal 20 ms tick at 1 cps earns 0.02 of a call ...
        let nominal = pacer_credit(1.0, Duration::from_millis(20), period);
        assert!((nominal - 0.02).abs() < 1e-9);
        // ... and a tick that arrives 200 ms late earns the whole interval,
        // so a starved host does not silently run below the requested rate.
        let late = pacer_credit(1.0, Duration::from_millis(220), period);
        assert!((late - 0.22).abs() < 1e-9);
        // -rp scales it: 50 calls per 2 s period over 100 ms is 2.5 calls.
        let rp = pacer_credit(
            50.0,
            Duration::from_millis(100),
            Duration::from_millis(2000),
        );
        assert!((rp - 2.5).abs() < 1e-9);
        assert_eq!(
            pacer_credit(10.0, Duration::from_millis(10), Duration::ZERO),
            0.0
        );
    }

    #[test]
    fn default_behaviors_parse_like_sipp() {
        assert_eq!(Behaviors::parse("all").unwrap(), Behaviors::all());
        assert_eq!(Behaviors::parse("none").unwrap(), Behaviors::none());
        assert_eq!(
            Behaviors::parse("all,-bye").unwrap(),
            Behaviors {
                bye: false,
                ..Behaviors::all()
            }
        );
        assert_eq!(
            Behaviors::parse("bye,+cseq").unwrap(),
            Behaviors {
                bye: true,
                cseq: true,
                ..Behaviors::none()
            }
        );
        assert!(Behaviors::parse("all,none,pingreply").unwrap().pingreply);
        assert!(!Behaviors::parse("all,none,pingreply").unwrap().bye);
        assert_eq!(
            Behaviors::parse("all,-fooo").unwrap_err(),
            "Unknown default behavior: '-fooo'"
        );
        assert_eq!(Behaviors::default(), Behaviors::all());
    }

    #[test]
    fn call_id_slashes_trim_unless_ignored() {
        assert_eq!(trim_call_id("twin///real@h", false), "real@h");
        assert_eq!(trim_call_id("twin///real@h", true), "twin///real@h");
        assert_eq!(trim_call_id("plain@h", false), "plain@h");
        assert_eq!(trim_call_id("a///b///c", false), "b///c");
    }

    #[test]
    fn twin_commands_name_their_call_sender_and_abort() {
        // Call-ID in either spelling, case folded, `///` trimmed like SIPp.
        assert_eq!(
            command_call_id("Call-ID: abc@h\r\nFrom: m\r\n", false).as_deref(),
            Some("abc@h")
        );
        assert_eq!(
            command_call_id("call-id: twin///abc@h\ninternal-cmd: abort_call\n\n", false)
                .as_deref(),
            Some("abc@h")
        );
        assert_eq!(
            command_call_id("i: abc@h", true).as_deref(),
            Some("abc@h"),
            "compact form"
        );
        assert_eq!(command_call_id("From: m\nContent-Type: x", false), None);
        assert_eq!(command_call_id("Call-ID:   \n", false), None);
        // The sender is the first token of the From: line (check_peer_src).
        assert_eq!(command_from("Call-ID: c\nFrom: s1 extra\n"), Some("s1"));
        assert_eq!(command_from("Call-ID: c\nfrom:\tm\r\n"), Some("m"));
        assert_eq!(command_from("Call-ID: c\n"), None);
        // SIPp's 3pcc_abort default message.
        assert!(is_abort_command("call-id: c\ninternal-cmd: abort_call\n\n"));
        assert!(!is_abort_command("call-id: c\ninternal-cmd: hangup\n"));
        assert!(!is_abort_command(
            "call-id: c\nContent-Type: application/sdp\n"
        ));
    }

    #[test]
    fn default_messages_compile_with_sipps_keywords() {
        let d = DefaultMessages::compile();
        for t in [&d.ack, &d.bye, &d.cancel, &d.ok] {
            assert!(!t.spans.is_empty());
            assert!(
                !t.keywords().any(|k| matches!(k, Keyword::Unknown(_))),
                "{t:?}"
            );
        }
        assert!(
            d.ack
                .keywords()
                .any(|k| matches!(k, Keyword::LastRequestUri))
        );
        assert!(d.bye.keywords().any(|k| matches!(k, Keyword::NextUrl)));
    }
}
