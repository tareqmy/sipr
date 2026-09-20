//! Command-line interface. Flag names and syntax follow SIPp — see
//! `docs/SIPP_COMPAT.md` §3.
//!
//! This is a bespoke table-driven parser rather than clap: SIPp's flags are
//! multi-character with a single dash (`-sf`, `-sn`, `-trace_msg`), which clap
//! cannot express without rewriting argv, and a test tool wants byte-for-byte
//! control of its usage errors anyway. Zero dependencies as a bonus. Both `-sf`
//! and `--sf` are accepted; unknown flags fail with a did-you-mean suggestion.

use std::net::IpAddr;
use std::path::PathBuf;

/// Transport mode (`-t`).
// SIPp's own taxonomy: `u1`/`t1`/`l1` = one socket, `un`/`tn`/`ln` = one
// socket per call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// `u1`: UDP with one socket shared by all calls (SIPp's default).
    UdpMono,
    /// `un`: UDP with one socket per call.
    UdpPerCall,
    /// `ui`: UDP with one socket per IP address from the injection file.
    UdpPerIp,
    /// `t1`: TCP with one connection per peer (client dials, server accepts).
    TcpMono,
    /// `tn`: TCP with one connection per call.
    TcpPerCall,
    /// `l1`: TLS over TCP, same connection-per-peer model.
    TlsMono,
    /// `ln`: TLS with one connection per call.
    TlsPerCall,
    /// `s1`: SCTP with one association per peer (needs the `sctp` build feature).
    SctpMono,
    /// `sn`: SCTP with one association per call.
    SctpPerCall,
}

/// `-tls_version` argument. SIPp accepts 1.0–1.3; rustls has no pre-1.2
/// support, so 1.0/1.1 are rejected at parse time (documented divergence,
/// docs/SIPP_COMPAT.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsVersionArg {
    /// Autonegotiate (SIPp's default): TLS 1.2 or 1.3.
    #[default]
    Auto,
    /// Pin TLS 1.2.
    V1_2,
    /// Pin TLS 1.3.
    V1_3,
}

/// Parsed configuration. Field defaults follow SIPp where SIPp documents one.
#[derive(Debug, Clone, PartialEq)]
pub struct Cli {
    /// Remote target `host[:port]` to place calls to (required as UAC).
    pub target: Option<String>,
    /// `-sf`: load a scenario from an XML file.
    pub sf: Option<PathBuf>,
    /// `-sn`: use an embedded default scenario (`uac` | `uas` | ...).
    pub sn: Option<String>,
    /// `-sd`: print an embedded default scenario to stdout and exit.
    pub sd: Option<String>,
    /// `-oocsf`: load the out-of-call scenario from an XML file.
    pub oocsf: Option<PathBuf>,
    /// `-oocsn`: use an embedded out-of-call scenario (`ooc_default` |
    /// `ooc_dummy`).
    pub oocsn: Option<String>,
    /// `-rxsf`: load the mixed-mode receive scenario from an XML file.
    pub rxsf: Option<PathBuf>,
    /// `-rxsn`: use an embedded scenario (`uas`) as the receive scenario.
    pub rxsn: Option<String>,
    /// `-rxinf`: injection files loaded after the `-inf` ones, reachable by
    /// name from either scenario; repeatable, in order.
    pub rxinf: Vec<PathBuf>,
    /// `--check`: lint the scenario, print its compiled form, and exit (M1).
    pub check: bool,
    /// `-r`: new calls per rate period.
    pub rate: f64,
    /// `-rp`: rate period in milliseconds.
    pub rate_period_ms: u64,
    /// `-l`: maximum concurrent calls (excess calls are simply not started).
    pub limit: Option<u64>,
    /// `-m`: stop after this many calls have been started.
    pub max_calls: Option<u64>,
    /// `-d`: duration in ms of `<pause/>` steps with no explicit duration.
    pub pause_ms: u64,
    /// `-p`: local port (default: a free port chosen by the system).
    pub port: Option<u16>,
    /// `-i`: local IP address to bind.
    pub local_ip: Option<IpAddr>,
    /// `-mi`: media (RTP) address for `[media_ip]`; defaults to the local IP.
    pub media_ip: Option<IpAddr>,
    /// `-mp` / `-min_rtp_port`: base media port for `[media_port]`.
    pub media_port: Option<u16>,
    /// `-max_rtp_port`: top of the `[rtpstream_*_port]` allocation range.
    pub max_rtp_port: Option<u16>,
    /// `-rtp_payload`: default payload type for `rtp_stream` (SIPp: 8).
    pub rtp_payload: Option<u8>,
    /// `-random_base_ssrc`: randomize the SSRC base instead of `0xCA110000`.
    pub random_base_ssrc: bool,
    /// `-rate_increase`: add this to the rate every `-rate_interval`.
    pub rate_increase: Option<f64>,
    /// `-rate_max`: cap for the ramp; reaching it soft-quits unless `-no_rate_quit`.
    pub rate_max: Option<f64>,
    /// `-rate_interval`: ramp period (default: the `-fd` interval).
    pub rate_interval: Option<std::time::Duration>,
    /// `-no_rate_quit`: keep running at `-rate_max` instead of quitting.
    pub no_rate_quit: bool,
    /// `-rate_scale`: the step for the `+ - * /` keys (default 1).
    pub rate_scale: Option<f64>,
    /// `-rtp_echo`: echo RTP received on the media port (and +2) back.
    pub rtp_echo: bool,
    /// `-mb`: RTP echo buffer size (default 2048).
    pub media_bufsize: Option<usize>,
    /// `-audiotolerance`: RTP-check failure ratio that fails the run (audio).
    pub audio_tolerance: Option<f64>,
    /// `-videotolerance`: same for video streams.
    pub video_tolerance: Option<f64>,
    /// `-cp`: control socket port (`0` disables; default probes 8888..8947).
    pub control_port: Option<u16>,
    /// `-ci`: control socket bind address (default loopback).
    pub control_ip: Option<IpAddr>,
    /// `--sipr-http`: HTTP control API bind, `PORT` or `HOST:PORT`.
    pub http: Option<String>,
    /// `--sipr-http-token`: bearer token for the HTTP API.
    pub http_token: Option<String>,
    /// `-t`: transport mode.
    pub transport: Transport,
    /// `-max_socket`: sockets to open before per-call modes start sharing.
    pub max_socket: Option<usize>,
    /// `-rsa`: remote sending address `host[:port]`.
    pub remote_sending: Option<String>,
    /// `-ip_field`: injection-file field holding the local IP under `-t ui`.
    pub ip_field: usize,
    /// `-max_reconnect`: TCP/TLS reconnections allowed (-1 = unlimited).
    pub max_reconnect: i64,
    /// `-reconnect_close`: fail calls on a closed/reset connection.
    pub reconnect_close: bool,
    /// `-reconnect_sleep`: ms to wait before re-dialing.
    pub reconnect_sleep_ms: u64,
    /// `-s`: service / called user part, substituted for `[service]`.
    pub service: String,
    /// `-au`: username for `[authentication]`.
    pub auth_user: Option<String>,
    /// `-ap`: password for `[authentication]`.
    pub auth_password: Option<String>,
    /// `-auth_uri`: the digest `uri=` (SIPp prepends `sip:`; default
    /// `remote_ip:remote_port`).
    pub auth_uri: Option<String>,
    /// `-aa`: auto-answer in-dialog OPTIONS/INFO/UPDATE/NOTIFY with 200.
    pub auto_answer: bool,
    /// `-nd`: disable scenario default behaviors.
    pub no_defaults: bool,
    /// `-nr`: disable UDP retransmissions.
    pub no_retrans: bool,
    /// `-bg`: headless mode — no TUI, periodic stat lines instead.
    pub background: bool,
    /// `-trace_msg`: trace sent/received SIP messages to a log file.
    pub trace_msg: bool,
    /// `-trace_err`: trace errors to a log file.
    pub trace_err: bool,
    /// `-trace_stat`: dump statistics to a CSV file periodically.
    pub trace_stat: bool,
    /// `-stf`: statistics CSV file name (with `-trace_stat`).
    pub stat_file: Option<PathBuf>,
    /// `-fd`: statistics dump interval in seconds.
    pub stat_interval_s: Option<u64>,
    /// `-f`: screen / `-bg` line report frequency in seconds.
    pub report_interval_s: Option<u64>,
    /// `-trace_rtt`: every response time to a CSV file.
    pub trace_rtt: bool,
    /// `-rtt_freq`: buffered response times before a `-trace_rtt` flush.
    pub rtt_freq: Option<usize>,
    /// `-trace_counts`: per-message counters to a CSV file.
    pub trace_counts: bool,
    /// `-trace_error_codes`: unexpected response codes to a CSV file.
    pub trace_error_codes: bool,
    /// `-trace_screen`: the statistics screens to a file at exit.
    pub trace_screen: bool,
    /// `-screen_file`: that file's name.
    pub screen_file: Option<PathBuf>,
    /// `-stat_delimiter`: the statistics files' column separator.
    pub stat_delimiter: Option<String>,
    /// `-periodic_rtd`: zero the repartition tables each dump.
    pub periodic_rtd: bool,
    /// `-trace_logs`: `<log>` actions to a file.
    pub trace_logs: bool,
    /// `-log_file`: that file's name.
    pub log_file: Option<PathBuf>,
    /// `-trace_shortmsg`: one CSV line per message to a file.
    pub trace_shortmsg: bool,
    /// `-shortmessage_file`: that file's name.
    pub shortmessage_file: Option<PathBuf>,
    /// `-trace_calldebug`: aborted calls' debug history to a file.
    pub trace_calldebug: bool,
    /// `-calldebug_file`: that file's name.
    pub calldebug_file: Option<PathBuf>,
    /// `-trace_timeout`: accepted, no effect (SIPp never implemented it).
    pub trace_timeout: bool,
    /// `-error_file`: the error log's name.
    pub error_file: Option<PathBuf>,
    /// `-message_file`: the message log's name.
    pub message_file: Option<PathBuf>,
    /// `-message_overwrite`, `-error_overwrite`, `-log_overwrite`,
    /// `-shortmessage_overwrite`, `-calldebug_overwrite`, `-screen_overwrite`.
    pub message_overwrite: bool,
    pub error_overwrite: bool,
    pub log_overwrite: bool,
    pub shortmessage_overwrite: bool,
    pub calldebug_overwrite: bool,
    pub screen_overwrite: bool,
    /// `-ringbuffer_files`, `-ringbuffer_size`, `-max_log_size`.
    pub ringbuffer_files: Option<usize>,
    pub ringbuffer_size: Option<u64>,
    pub max_log_size: Option<u64>,
    /// `-deadcall_wait` in milliseconds.
    pub deadcall_wait_ms: Option<u64>,
    /// `-timeout`: global test timeout in seconds.
    pub timeout_s: Option<u64>,
    /// `-base_cseq`: initial CSeq value for outbound requests.
    pub base_cseq: Option<u32>,
    /// `-cid_str`: Call-ID format string (substituted for `[call_id]`).
    pub call_id_format: Option<String>,
    /// `-max_retrans`: maximum UDP retransmissions per message.
    pub max_retrans: Option<u32>,
    /// `-inf`: injection files (CSV) for `[fieldN]`; repeatable, in order.
    pub inf: Vec<std::path::PathBuf>,
    /// `-infindex FILE FIELD`: build a `<lookup>` index; repeatable.
    pub inf_index: Vec<(String, usize)>,
    /// `-set VARIABLE VALUE`: initial value of a `<Global>` variable; repeatable.
    pub set_vars: Vec<(String, String)>,
    /// `-key KEYWORD VALUE`: a generic keyword `[KEYWORD]` rendering VALUE; repeatable.
    pub generic_keywords: Vec<(String, String)>,
    /// `-tdmmap MAP`: the TDM circuit table `[tdmmap]` renders from.
    pub tdmmap: Option<sipr_engine::TdmMap>,
    /// `-dynamicStart`: first `[dynamic_id]` value (default 10000).
    pub dynamic_start: Option<u32>,
    /// `-dynamicMax`: `[dynamic_id]` wraps back to the start past this (default 18000).
    pub dynamic_max: Option<u32>,
    /// `-dynamicStep`: `[dynamic_id]` increment per render (default 4).
    pub dynamic_step: Option<u32>,
    /// `-rfc3339`: `[timestamp]` in RFC 3339 form.
    pub rfc3339: bool,
    /// `-3pcc HOST:PORT`: classic 3PCC twin control socket.
    pub three_pcc: Option<String>,
    /// `-users N`: closed-loop mode with N constant concurrent users.
    pub users: Option<usize>,
    /// `-tls_cert`: TLS certificate file (SIPp default: `cacert.pem`).
    pub tls_cert: PathBuf,
    /// `-tls_key`: TLS private key file (SIPp default: `cakey.pem`).
    pub tls_key: PathBuf,
    /// `-tls_ca`: CA file; presence switches peer verification ON.
    pub tls_ca: Option<PathBuf>,
    /// `-tls_crl`: CRL file; presence also switches verification ON.
    pub tls_crl: Option<PathBuf>,
    /// `-tls_version`: pin the TLS protocol version.
    pub tls_version: TlsVersionArg,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            target: None,
            sf: None,
            sn: None,
            sd: None,
            oocsf: None,
            oocsn: None,
            rxsf: None,
            rxsn: None,
            rxinf: Vec::new(),
            check: false,
            rate: 10.0,
            rate_period_ms: 1000,
            limit: None,
            max_calls: None,
            pause_ms: 3000,
            port: None,
            local_ip: None,
            media_ip: None,
            media_port: None,
            max_rtp_port: None,
            rtp_payload: None,
            random_base_ssrc: false,
            rate_increase: None,
            rate_max: None,
            rate_interval: None,
            no_rate_quit: false,
            rate_scale: None,
            rtp_echo: false,
            media_bufsize: None,
            audio_tolerance: None,
            video_tolerance: None,
            control_port: None,
            control_ip: None,
            http: None,
            http_token: None,
            transport: Transport::UdpMono,
            max_socket: None,
            remote_sending: None,
            ip_field: 0,
            max_reconnect: 0,
            reconnect_close: true,
            reconnect_sleep_ms: 1000,
            service: "service".to_owned(),
            auth_user: None,
            auth_password: None,
            auth_uri: None,
            auto_answer: false,
            no_defaults: false,
            no_retrans: false,
            background: false,
            trace_msg: false,
            trace_err: false,
            trace_stat: false,
            stat_file: None,
            stat_interval_s: None,
            report_interval_s: None,
            trace_rtt: false,
            rtt_freq: None,
            trace_counts: false,
            trace_error_codes: false,
            trace_screen: false,
            screen_file: None,
            stat_delimiter: None,
            periodic_rtd: false,
            trace_logs: false,
            log_file: None,
            trace_shortmsg: false,
            shortmessage_file: None,
            trace_calldebug: false,
            calldebug_file: None,
            trace_timeout: false,
            error_file: None,
            message_file: None,
            message_overwrite: true,
            error_overwrite: true,
            log_overwrite: true,
            shortmessage_overwrite: true,
            calldebug_overwrite: true,
            screen_overwrite: true,
            ringbuffer_files: None,
            ringbuffer_size: None,
            max_log_size: None,
            deadcall_wait_ms: None,
            timeout_s: None,
            base_cseq: None,
            call_id_format: None,
            max_retrans: None,
            inf: Vec::new(),
            inf_index: Vec::new(),
            set_vars: Vec::new(),
            generic_keywords: Vec::new(),
            tdmmap: None,
            dynamic_start: None,
            dynamic_max: None,
            dynamic_step: None,
            rfc3339: false,
            three_pcc: None,
            users: None,
            tls_cert: PathBuf::from("cacert.pem"),
            tls_key: PathBuf::from("cakey.pem"),
            tls_ca: None,
            tls_crl: None,
            tls_version: TlsVersionArg::Auto,
        }
    }
}

/// What an argv parse resolved to.
#[derive(Debug)]
pub enum Invocation {
    /// Run with this configuration.
    Run(Box<Cli>),
    /// `-h` / `--help`: print help and exit 0.
    Help,
    /// `-v` / `--version`: print version and exit 0.
    Version,
}

/// Flag table: (name, takes_value, value_name, help).
const FLAGS: &[(&str, bool, &str, &str)] = &[
    ("sf", true, "FILE", "Load a scenario from an XML file"),
    (
        "sn",
        true,
        "NAME",
        "Use an embedded default scenario: uac | uas | ooc_default | ooc_dummy",
    ),
    (
        "sd",
        true,
        "NAME",
        "Print an embedded default scenario and exit",
    ),
    (
        "oocsf",
        true,
        "FILE",
        "Load the out-of-call scenario (answers requests of no known call; client mode only) from an XML file",
    ),
    (
        "oocsn",
        true,
        "NAME",
        "Use an embedded out-of-call scenario: ooc_default | ooc_dummy",
    ),
    (
        "rxsf",
        true,
        "FILE",
        "Mixed mode: load a second, server-mode scenario from an XML file to terminate the calls the peer originates while the main (client-mode) scenario originates ours",
    ),
    (
        "rxsn",
        true,
        "NAME",
        "Mixed mode: use an embedded scenario (uas) as the receive scenario",
    ),
    (
        "check",
        false,
        "",
        "Lint the scenario, print its compiled form, exit",
    ),
    ("r", true, "RATE", "New calls per rate period [default: 10]"),
    (
        "rp",
        true,
        "MS",
        "Rate period in milliseconds [default: 1000]",
    ),
    ("l", true, "N", "Maximum concurrent calls"),
    ("m", true, "N", "Stop after N calls have been started"),
    (
        "d",
        true,
        "MS",
        "Default duration of <pause/> steps [default: 3000]",
    ),
    (
        "p",
        true,
        "PORT",
        "Local port [default: system-chosen free port]",
    ),
    ("i", true, "IP", "Local IP address to bind"),
    (
        "mi",
        true,
        "IP",
        "Media (RTP) IP for [media_ip] [default: the local IP]",
    ),
    (
        "mp",
        true,
        "PORT",
        "Base media port for [media_port] / [auto_media_port] [default: 6000]",
    ),
    ("min_rtp_port", true, "PORT", "Same as -mp (SIPp alias)"),
    (
        "max_rtp_port",
        true,
        "PORT",
        "Top of the [rtpstream_audio_port]/[rtpstream_video_port] range [default: 65535]",
    ),
    (
        "rtp_payload",
        true,
        "PT",
        "Default payload type for exec rtp_stream= [default: 8 (PCMA)]",
    ),
    (
        "random_base_ssrc",
        false,
        "",
        "Random SSRC base for rtp_stream instead of 0xCA110000",
    ),
    (
        "rate_increase",
        true,
        "N",
        "Increase the call rate by N every -rate_interval (SIPp ramp)",
    ),
    (
        "rate_max",
        true,
        "N",
        "With -rate_increase: cap the rate at N and quit (drain) when it would be exceeded",
    ),
    (
        "rate_interval",
        true,
        "TIME",
        "Ramp period: seconds, or with a unit (500ms, 10s, 1m) [default: the -fd interval]",
    ),
    (
        "no_rate_quit",
        false,
        "",
        "With -rate_max: keep running at the cap instead of quitting",
    ),
    (
        "rate_scale",
        true,
        "N",
        "Step for the + - * / rate keys [default: 1]",
    ),
    (
        "rtp_echo",
        false,
        "",
        "Echo RTP/UDP received on the media port (and media port + 2) back to the sender",
    ),
    ("mb", true, "BYTES", "RTP echo buffer size [default: 2048]"),
    (
        "audiotolerance",
        true,
        "RATIO",
        "Fail the run (exit 253, SIPp's -3) when this share of an audio rtp_stream's packets fail the echo check (0.0-1.0)",
    ),
    (
        "videotolerance",
        true,
        "RATIO",
        "Same as -audiotolerance for video streams",
    ),
    (
        "rtpcheck_debug",
        false,
        "",
        "Accepted for SIPp compatibility (sipr writes no RTP-check debug files)",
    ),
    (
        "srtpcheck_debug",
        false,
        "",
        "Accepted for SIPp compatibility (sipr writes no SRTP debug files)",
    ),
    (
        "cp",
        true,
        "PORT",
        "Control socket port (SIPp protocol) [default: first free of 8888..8947; 0 disables]",
    ),
    (
        "ci",
        true,
        "IP",
        "Control socket bind address [default: 127.0.0.1]",
    ),
    (
        "sipr-http",
        true,
        "[HOST:]PORT",
        "HTTP/JSON control API (sipr addition; docs/CONTROL_API.md) [default: off]",
    ),
    (
        "sipr-http-token",
        true,
        "TOKEN",
        "Bearer token for the HTTP API (required off loopback)",
    ),
    (
        "t",
        true,
        "MODE",
        "Transport: u1 (UDP, default), un (UDP, one socket per call), ui (UDP, one socket per injected IP; needs -inf and -ip_field), s1 (SCTP), sn (SCTP, one association per call; both need a build with the sctp feature and a Linux SCTP stack), t1 (TCP), tn (TCP, one connection per call), l1 (TLS), ln (TLS, one connection per call)",
    ),
    (
        "s",
        true,
        "NAME",
        "Service / called user part for [service]",
    ),
    ("au", true, "USER", "Username for [authentication]"),
    ("ap", true, "PASS", "Password for [authentication]"),
    (
        "auth_uri",
        true,
        "URI",
        "Digest uri= value; sip: is prepended as SIPp does [default: remote_ip:remote_port]",
    ),
    (
        "aa",
        false,
        "",
        "Auto-answer in-dialog OPTIONS/INFO/UPDATE/NOTIFY",
    ),
    ("nd", false, "", "Disable scenario default behaviors"),
    ("nr", false, "", "Disable UDP retransmissions"),
    (
        "key",
        true,
        "KEYWORD VALUE",
        "Set the generic parameter named KEYWORD to VALUE ([KEYWORD] in the scenario); repeatable",
    ),
    (
        "tdmmap",
        true,
        "MAP",
        "Generate and handle a table of TDM circuits for [tdmmap]; format {0-3}{99}{5-8}{1-31}",
    ),
    (
        "dynamicStart",
        true,
        "N",
        "Set the start offset of the [dynamic_id] variable (default 10000)",
    ),
    (
        "dynamicMax",
        true,
        "N",
        "Set the maximum of the [dynamic_id] variable (default 18000)",
    ),
    (
        "dynamicStep",
        true,
        "N",
        "Set the increment of the [dynamic_id] variable (default 4)",
    ),
    (
        "rfc3339",
        false,
        "",
        "Use timestamps in RFC 3339 format ([timestamp])",
    ),
    (
        "bg",
        false,
        "",
        "Headless mode: no TUI, periodic stat lines",
    ),
    (
        "trace_msg",
        false,
        "",
        "Trace sent/received SIP messages to a file",
    ),
    ("trace_err", false, "", "Trace errors to a file"),
    (
        "trace_logs",
        false,
        "",
        "Trace <log> actions to <scenario>_<pid>_logs.log",
    ),
    (
        "log_file",
        true,
        "FILE",
        "Set the name of the log actions log file",
    ),
    (
        "trace_shortmsg",
        false,
        "",
        "Trace sent and received messages as CSV lines to <scenario>_<pid>_shortmessages.log",
    ),
    (
        "shortmessage_file",
        true,
        "FILE",
        "Set the name of the short message log file",
    ),
    (
        "trace_calldebug",
        false,
        "",
        "Dump debugging information about aborted calls to <scenario>_<pid>_calldebug.log",
    ),
    (
        "calldebug_file",
        true,
        "FILE",
        "Set the name of the call debug log file",
    ),
    (
        "trace_timeout",
        false,
        "",
        "Accepted for SIPp compatibility; SIPp 3.7 never implemented it either",
    ),
    (
        "error_file",
        true,
        "FILE",
        "Set the name of the error log file",
    ),
    (
        "message_file",
        true,
        "FILE",
        "Set the name of the message log file",
    ),
    (
        "message_overwrite",
        true,
        "BOOL",
        "Overwrite (true, default) or append to the message log file",
    ),
    (
        "error_overwrite",
        true,
        "BOOL",
        "Overwrite (true, default) or append to the error log file",
    ),
    (
        "log_overwrite",
        true,
        "BOOL",
        "Overwrite (true, default) or append to the log actions log file",
    ),
    (
        "shortmessage_overwrite",
        true,
        "BOOL",
        "Overwrite (true, default) or append to the short message log file",
    ),
    (
        "calldebug_overwrite",
        true,
        "BOOL",
        "Overwrite (true, default) or append to the call debug log file",
    ),
    (
        "screen_overwrite",
        true,
        "BOOL",
        "Overwrite (true, default) or append to the screen file",
    ),
    (
        "ringbuffer_files",
        true,
        "N",
        "How many rotated error, message, shortmessage and calldebug files to keep",
    ),
    (
        "ringbuffer_size",
        true,
        "BYTES",
        "Rotate the error, message, shortmessage and calldebug files at this size",
    ),
    (
        "max_log_size",
        true,
        "BYTES",
        "Stop writing the error, message, shortmessage and calldebug files at this size",
    ),
    (
        "deadcall_wait",
        true,
        "MS",
        "How long a finished call's Call-ID stays known for late messages (default 33000)",
    ),
    (
        "trace_stat",
        false,
        "",
        "Dump statistics to a CSV file periodically",
    ),
    (
        "stf",
        true,
        "FILE",
        "Statistics CSV file name (with -trace_stat)",
    ),
    (
        "fd",
        true,
        "SECONDS",
        "Statistics dump log report frequency (default 60 s)",
    ),
    (
        "f",
        true,
        "SECONDS",
        "Statistics report frequency on screen and in -bg lines (default 1 s)",
    ),
    (
        "trace_rtt",
        false,
        "",
        "Trace every response time to <scenario>_<pid>_rtt.csv",
    ),
    (
        "rtt_freq",
        true,
        "N",
        "Dump response times every N calls to the -trace_rtt file (default 200)",
    ),
    (
        "trace_counts",
        false,
        "",
        "Dump the per-message counters to <scenario>_<pid>_counts.csv",
    ),
    (
        "trace_error_codes",
        false,
        "",
        "Dump the response codes of unexpected messages to <scenario>_<pid>_error_codes.csv",
    ),
    (
        "trace_screen",
        false,
        "",
        "Dump the statistics screens to <scenario>_<pid>_screens.log when quitting",
    ),
    (
        "screen_file",
        true,
        "FILE",
        "Set the name of the screen file (with -trace_screen)",
    ),
    (
        "stat_delimiter",
        true,
        "STRING",
        "Set the delimiter for the statistics files (default ;)",
    ),
    (
        "periodic_rtd",
        false,
        "",
        "Reset the response time repartition counters each logging interval",
    ),
    ("timeout", true, "SECONDS", "Global test timeout in seconds"),
    ("base_cseq", true, "N", "Initial CSeq for outbound requests"),
    (
        "cid_str",
        true,
        "FORMAT",
        "Call-ID format string for [call_id]",
    ),
    (
        "max_retrans",
        true,
        "N",
        "Maximum UDP retransmissions per message",
    ),
    (
        "multihome",
        true,
        "IP",
        "SIPp SCTP option: not supported by sipr (SCTP socket options are out of reach)",
    ),
    (
        "heartbeat",
        true,
        "MS",
        "SIPp SCTP option: not supported by sipr",
    ),
    (
        "assocmaxret",
        true,
        "N",
        "SIPp SCTP option: not supported by sipr",
    ),
    (
        "pathmaxret",
        true,
        "N",
        "SIPp SCTP option: not supported by sipr",
    ),
    ("pmtu", true, "N", "SIPp SCTP option: not supported by sipr"),
    (
        "gracefulclose",
        true,
        "true|false",
        "SIPp SCTP option: not supported by sipr",
    ),
    (
        "ip_field",
        true,
        "N",
        "Injection-file field holding the local IP each call sends from under -t ui (default 0)",
    ),
    (
        "rsa",
        true,
        "HOST[:PORT]",
        "Remote sending address: send every message there instead of to the target (UAC) or the request's source (UAS); default port 5060",
    ),
    (
        "max_reconnect",
        true,
        "N",
        "TCP/TLS reconnections allowed after a connection drops (default 0: none; -1: unlimited)",
    ),
    (
        "reconnect_close",
        true,
        "true|false",
        "Fail the calls on a connection that closed or reset (default true)",
    ),
    (
        "reconnect_sleep",
        true,
        "MS",
        "Milliseconds to wait before re-dialing a dropped connection (default 1000)",
    ),
    (
        "max_socket",
        true,
        "N",
        "Sockets to open before per-call modes (-t un|tn|ln) share them round-robin (default 50000)",
    ),
    (
        "inf",
        true,
        "FILE",
        "Injection file (CSV) for [fieldN]; repeatable",
    ),
    (
        "rxinf",
        true,
        "FILE",
        "Injection file (CSV) loaded after the -inf ones, for [fieldN file=NAME] in either scenario; repeatable",
    ),
    (
        "set",
        true,
        "VARIABLE VALUE",
        "Set the <Global variables=> variable VARIABLE to VALUE before the run; repeatable",
    ),
    (
        "infindex",
        true,
        "FILE FIELD",
        "Index an -inf file on FIELD for <lookup>; repeatable",
    ),
    (
        "3pcc",
        true,
        "HOST:PORT",
        "3PCC twin control socket (sendCmd/recvCmd)",
    ),
    (
        "users",
        true,
        "N",
        "Closed loop: keep N concurrent users constant",
    ),
    (
        "tls_cert",
        true,
        "FILE",
        "TLS certificate file [default: cacert.pem]",
    ),
    (
        "tls_key",
        true,
        "FILE",
        "TLS private key file [default: cakey.pem]",
    ),
    (
        "tls_ca",
        true,
        "FILE",
        "TLS CA file; enables peer verification",
    ),
    (
        "tls_crl",
        true,
        "FILE",
        "TLS certificate revocation list; enables verification",
    ),
    (
        "tls_version",
        true,
        "VER",
        "Pin the TLS version: 1.2 | 1.3 [default: autonegotiate]",
    ),
    ("h", false, "", "Print help"),
    ("help", false, "", "Print help"),
    ("v", false, "", "Print version"),
    ("version", false, "", "Print version"),
];

fn flag_spec(name: &str) -> Option<&'static (&'static str, bool, &'static str, &'static str)> {
    FLAGS.iter().find(|(n, ..)| *n == name)
}

/// Parse argv (including argv0) into an [`Invocation`].
///
/// # Errors
///
/// Returns a user-facing message for unknown flags (with a did-you-mean
/// suggestion), missing or malformed values, and conflicting options.
pub fn parse<I>(argv: I) -> Result<Invocation, String>
where
    I: IntoIterator<Item = String>,
{
    let mut cli = Cli::default();
    let mut args = argv.into_iter().skip(1);
    while let Some(arg) = args.next() {
        if !arg.starts_with('-') || arg == "-" {
            if let Some(prev) = &cli.target {
                return Err(format!(
                    "unexpected extra argument '{arg}' (remote target already set to '{prev}')"
                ));
            }
            cli.target = Some(arg);
            continue;
        }
        let body = arg.trim_start_matches('-');
        let (name, inline_value) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (body, None),
        };
        match name {
            "h" | "help" => return Ok(Invocation::Help),
            "v" | "version" => return Ok(Invocation::Version),
            _ => {}
        }
        // -set takes two arguments: VARIABLE then VALUE.
        if name == "set" {
            let variable = inline_value
                .or_else(|| args.next())
                .ok_or_else(|| "option '-set' requires VARIABLE and VALUE".to_owned())?;
            let value = args
                .next()
                .ok_or_else(|| "option '-set' requires a VALUE after VARIABLE".to_owned())?;
            cli.set_vars.push((variable, value));
            continue;
        }
        // -key takes two arguments too: KEYWORD then VALUE (a literal).
        if name == "key" {
            let keyword = inline_value
                .or_else(|| args.next())
                .ok_or_else(|| "option '-key' requires KEYWORD and VALUE".to_owned())?;
            let value = args
                .next()
                .ok_or_else(|| "option '-key' requires a VALUE after KEYWORD".to_owned())?;
            cli.generic_keywords.push((keyword, value));
            continue;
        }
        // -infindex is the other two-argument flag: FILE then FIELD.
        if name == "infindex" {
            let file = inline_value
                .or_else(|| args.next())
                .ok_or_else(|| "option '-infindex' requires FILE and FIELD".to_owned())?;
            let field_s = args
                .next()
                .ok_or_else(|| "option '-infindex' requires a FIELD after FILE".to_owned())?;
            let field = field_s.parse::<usize>().map_err(|_| {
                format!("option '-infindex' FIELD must be a number, got '{field_s}'")
            })?;
            cli.inf_index.push((file, field));
            continue;
        }
        let Some((flag, takes_value, ..)) = flag_spec(name) else {
            let mut msg = format!("unknown option '-{name}'");
            if let Some(best) = closest_flag(name) {
                msg.push_str(&format!(" — did you mean '-{best}'?"));
            }
            msg.push_str("\n\nFor usage, try '-h'.");
            return Err(msg);
        };
        let value = if *takes_value {
            let v = inline_value.or_else(|| args.next());
            match v {
                Some(v) => Some(v),
                None => return Err(format!("option '-{flag}' requires a value")),
            }
        } else {
            if inline_value.is_some() {
                return Err(format!("option '-{flag}' does not take a value"));
            }
            None
        };
        apply(&mut cli, flag, value)?;
    }
    if cli.sf.is_some() && cli.sn.is_some() {
        return Err("options '-sf' and '-sn' cannot be used together".to_owned());
    }
    if cli.oocsf.is_some() && cli.oocsn.is_some() {
        return Err("options '-oocsf' and '-oocsn' cannot be used together".to_owned());
    }
    if cli.rxsf.is_some() && cli.rxsn.is_some() {
        return Err("options '-rxsf' and '-rxsn' cannot be used together".to_owned());
    }
    // SIPp's out-of-call branch is unreachable in mixed mode (socket.cpp
    // `process_message` takes the MODE_MIXED arm first): refuse loudly rather
    // than load a scenario that never fires.
    if (cli.rxsf.is_some() || cli.rxsn.is_some()) && (cli.oocsf.is_some() || cli.oocsn.is_some()) {
        return Err(
            "options '-rxsf'/'-rxsn' and '-oocsf'/'-oocsn' cannot be used together \
             (SIPp never reaches the out-of-call scenario in mixed mode)"
                .to_owned(),
        );
    }
    if cli.users.is_some() && cli.limit.is_some() {
        return Err(
            "options '-users' and '-l' cannot be used together (users mode is closed-loop)"
                .to_owned(),
        );
    }
    if cli.transport == Transport::UdpPerIp && cli.inf.is_empty() {
        return Err("You must use the -inf option when using -t ui".into());
    }
    Ok(Invocation::Run(Box::new(cli)))
}

/// Apply one flag (with its raw value, if any) to the config.
fn apply(cli: &mut Cli, flag: &str, value: Option<String>) -> Result<(), String> {
    // Flags in the table marked takes_value=true always arrive with Some(..).
    let val = |v: Option<String>| v.unwrap_or_default();
    match flag {
        "sf" => cli.sf = Some(PathBuf::from(val(value))),
        "sn" => cli.sn = Some(val(value)),
        "sd" => cli.sd = Some(val(value)),
        "oocsf" => cli.oocsf = Some(PathBuf::from(val(value))),
        "oocsn" => cli.oocsn = Some(val(value)),
        "rxsf" => cli.rxsf = Some(PathBuf::from(val(value))),
        "rxsn" => cli.rxsn = Some(val(value)),
        "rxinf" => cli.rxinf.push(PathBuf::from(val(value))),
        "check" => cli.check = true,
        "r" => cli.rate = parse_num(flag, &val(value))?,
        "rp" => cli.rate_period_ms = parse_num(flag, &val(value))?,
        "l" => cli.limit = Some(parse_num(flag, &val(value))?),
        "m" => cli.max_calls = Some(parse_num(flag, &val(value))?),
        "d" => cli.pause_ms = parse_num(flag, &val(value))?,
        "p" => cli.port = Some(parse_num(flag, &val(value))?),
        "i" => cli.local_ip = Some(parse_num(flag, &val(value))?),
        "mi" => cli.media_ip = Some(parse_num(flag, &val(value))?),
        "mp" | "min_rtp_port" => cli.media_port = Some(parse_num(flag, &val(value))?),
        "max_rtp_port" => cli.max_rtp_port = Some(parse_num(flag, &val(value))?),
        "rtp_payload" => {
            let pt: u8 = parse_num(flag, &val(value))?;
            if pt > 127 {
                return Err(format!(
                    "invalid value '{pt}' for option '-rtp_payload' (0..=127)"
                ));
            }
            cli.rtp_payload = Some(pt);
        }
        "random_base_ssrc" => cli.random_base_ssrc = true,
        "rate_increase" => cli.rate_increase = Some(parse_num(flag, &val(value))?),
        "rate_max" => cli.rate_max = Some(parse_num(flag, &val(value))?),
        "rate_interval" => cli.rate_interval = Some(parse_time(flag, &val(value))?),
        "no_rate_quit" => cli.no_rate_quit = true,
        "rate_scale" => cli.rate_scale = Some(parse_num(flag, &val(value))?),
        "rtp_echo" => cli.rtp_echo = true,
        "mb" => cli.media_bufsize = Some(parse_num(flag, &val(value))?),
        "audiotolerance" | "videotolerance" => {
            let ratio: f64 = parse_num(flag, &val(value))?;
            if !(0.0..=1.0).contains(&ratio) {
                return Err(format!(
                    "invalid value '{ratio}' for option '-{flag}' (0.0..=1.0)"
                ));
            }
            if flag == "audiotolerance" {
                cli.audio_tolerance = Some(ratio);
            } else {
                cli.video_tolerance = Some(ratio);
            }
        }
        "srtpcheck_debug" | "rtpcheck_debug" => {}
        "cp" => cli.control_port = Some(parse_num(flag, &val(value))?),
        "ci" => cli.control_ip = Some(parse_num(flag, &val(value))?),
        "sipr-http" => cli.http = Some(val(value)),
        "sipr-http-token" => cli.http_token = Some(val(value)),
        "t" => cli.transport = parse_transport(&val(value))?,
        "s" => cli.service = val(value),
        "au" => cli.auth_user = Some(val(value)),
        "ap" => cli.auth_password = Some(val(value)),
        "auth_uri" => cli.auth_uri = Some(val(value)),
        "aa" => cli.auto_answer = true,
        "nd" => cli.no_defaults = true,
        "nr" => cli.no_retrans = true,
        "rfc3339" => cli.rfc3339 = true,
        "tdmmap" => cli.tdmmap = Some(sipr_engine::TdmMap::parse(&val(value))?),
        "dynamicStart" => cli.dynamic_start = Some(parse_num(flag, &val(value))?),
        "dynamicMax" => cli.dynamic_max = Some(parse_num(flag, &val(value))?),
        "dynamicStep" => cli.dynamic_step = Some(parse_num(flag, &val(value))?),
        "bg" => cli.background = true,
        "trace_msg" => cli.trace_msg = true,
        "trace_err" => cli.trace_err = true,
        "trace_stat" => cli.trace_stat = true,
        "stf" => cli.stat_file = Some(PathBuf::from(val(value))),
        "fd" => cli.stat_interval_s = Some(parse_num(flag, &val(value))?),
        "f" => cli.report_interval_s = Some(parse_num(flag, &val(value))?),
        "trace_rtt" => cli.trace_rtt = true,
        "rtt_freq" => cli.rtt_freq = Some(parse_num(flag, &val(value))?),
        "trace_counts" => cli.trace_counts = true,
        "trace_error_codes" => cli.trace_error_codes = true,
        "trace_screen" => cli.trace_screen = true,
        "screen_file" => cli.screen_file = Some(PathBuf::from(val(value))),
        "stat_delimiter" => cli.stat_delimiter = Some(val(value)),
        "periodic_rtd" => cli.periodic_rtd = true,
        "trace_logs" => cli.trace_logs = true,
        "log_file" => cli.log_file = Some(PathBuf::from(val(value))),
        "trace_shortmsg" => cli.trace_shortmsg = true,
        "shortmessage_file" => cli.shortmessage_file = Some(PathBuf::from(val(value))),
        "trace_calldebug" => cli.trace_calldebug = true,
        "calldebug_file" => cli.calldebug_file = Some(PathBuf::from(val(value))),
        "trace_timeout" => cli.trace_timeout = true,
        "error_file" => cli.error_file = Some(PathBuf::from(val(value))),
        "message_file" => cli.message_file = Some(PathBuf::from(val(value))),
        "message_overwrite" => cli.message_overwrite = parse_bool_value(flag, &val(value))?,
        "error_overwrite" => cli.error_overwrite = parse_bool_value(flag, &val(value))?,
        "log_overwrite" => cli.log_overwrite = parse_bool_value(flag, &val(value))?,
        "shortmessage_overwrite" => {
            cli.shortmessage_overwrite = parse_bool_value(flag, &val(value))?;
        }
        "calldebug_overwrite" => cli.calldebug_overwrite = parse_bool_value(flag, &val(value))?,
        "screen_overwrite" => cli.screen_overwrite = parse_bool_value(flag, &val(value))?,
        "ringbuffer_files" => cli.ringbuffer_files = Some(parse_num(flag, &val(value))?),
        "ringbuffer_size" => cli.ringbuffer_size = Some(parse_num(flag, &val(value))?),
        "max_log_size" => cli.max_log_size = Some(parse_num(flag, &val(value))?),
        "deadcall_wait" => cli.deadcall_wait_ms = Some(parse_num(flag, &val(value))?),
        "timeout" => cli.timeout_s = Some(parse_num(flag, &val(value))?),
        "base_cseq" => cli.base_cseq = Some(parse_num(flag, &val(value))?),
        "cid_str" => cli.call_id_format = Some(val(value)),
        "max_retrans" => cli.max_retrans = Some(parse_num(flag, &val(value))?),
        "inf" => cli.inf.push(std::path::PathBuf::from(val(value))),
        "3pcc" => cli.three_pcc = Some(val(value)),
        "users" => cli.users = Some(parse_num(flag, &val(value))?),
        "rsa" => cli.remote_sending = Some(val(value)),
        "ip_field" => cli.ip_field = parse_num(flag, &val(value))?,
        "multihome" | "heartbeat" | "assocmaxret" | "pathmaxret" | "pmtu" | "gracefulclose" => {
            return Err(format!(
                "-{flag} sets an SCTP socket option (libsctp) that sipr's SCTP transport \
                 cannot reach; it is not supported (docs/SIPP_COMPAT.md §6)"
            ));
        }
        "max_reconnect" => cli.max_reconnect = parse_num(flag, &val(value))?,
        "reconnect_close" => cli.reconnect_close = parse_bool_value(flag, &val(value))?,
        "reconnect_sleep" => cli.reconnect_sleep_ms = parse_num(flag, &val(value))?,
        "max_socket" => {
            let n: usize = parse_num(flag, &val(value))?;
            if n == 0 {
                return Err("-max_socket must be at least 1".into());
            }
            cli.max_socket = Some(n);
        }
        "tls_cert" => cli.tls_cert = PathBuf::from(val(value)),
        "tls_key" => cli.tls_key = PathBuf::from(val(value)),
        "tls_ca" => cli.tls_ca = Some(PathBuf::from(val(value))),
        "tls_crl" => cli.tls_crl = Some(PathBuf::from(val(value))),
        "tls_version" => cli.tls_version = parse_tls_version(&val(value))?,
        other => return Err(format!("internal error: unhandled flag '-{other}'")),
    }
    Ok(())
}

/// SIPp's time values (`SIPP_OPTION_TIME_SEC`): a number of seconds, or a
/// number with a unit — `ms`, `s`, `m`, `h`.
fn parse_time(flag: &str, raw: &str) -> Result<std::time::Duration, String> {
    let raw = raw.trim();
    let split = raw
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(raw.len());
    let (number, unit) = raw.split_at(split);
    let value: f64 = number
        .parse()
        .map_err(|_| format!("invalid time value '{raw}' for option '-{flag}'"))?;
    let secs = match unit.trim() {
        "" | "s" => value,
        "ms" => value / 1000.0,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        other => {
            return Err(format!(
                "invalid time unit '{other}' in '{raw}' for option '-{flag}' (ms, s, m, h)"
            ));
        }
    };
    if !(secs.is_finite() && secs >= 0.0) {
        return Err(format!("invalid time value '{raw}' for option '-{flag}'"));
    }
    Ok(std::time::Duration::from_secs_f64(secs))
}

fn parse_num<T: std::str::FromStr>(flag: &str, raw: &str) -> Result<T, String> {
    raw.parse()
        .map_err(|_| format!("invalid value '{raw}' for option '-{flag}'"))
}

/// SIPp's `get_bool`: `true`/`false` (also `1`/`0`).
fn parse_bool_value(flag: &str, raw: &str) -> Result<bool, String> {
    match raw {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(format!(
            "invalid value '{other}' for option '-{flag}' (expected true or false)"
        )),
    }
}

fn parse_transport(s: &str) -> Result<Transport, String> {
    match s {
        "u1" => Ok(Transport::UdpMono),
        "un" => Ok(Transport::UdpPerCall),
        "ui" => Ok(Transport::UdpPerIp),
        "t1" => Ok(Transport::TcpMono),
        "tn" => Ok(Transport::TcpPerCall),
        "l1" => Ok(Transport::TlsMono),
        "ln" => Ok(Transport::TlsPerCall),
        "s1" => Ok(Transport::SctpMono),
        "sn" => Ok(Transport::SctpPerCall),
        other => Err(format!(
            "unknown transport mode '{other}' (expected u1, un, ui, t1, tn, l1, ln, s1, or sn)"
        )),
    }
}

fn parse_tls_version(s: &str) -> Result<TlsVersionArg, String> {
    match s {
        "1.2" => Ok(TlsVersionArg::V1_2),
        "1.3" => Ok(TlsVersionArg::V1_3),
        "1.0" | "1.1" => Err(format!(
            "TLS {s} is not supported by sipr (rustls implements 1.2 and 1.3 \
             only; SIPp accepts 1.0–1.3)"
        )),
        other => Err(format!(
            "invalid value '{other}' for option '-tls_version' (expected 1.2 or 1.3)"
        )),
    }
}

/// Nearest known flag by edit distance, if it is plausibly a typo.
fn closest_flag(name: &str) -> Option<&'static str> {
    FLAGS
        .iter()
        .map(|(f, ..)| (edit_distance(name, f), *f))
        .min()
        .filter(|(d, _)| *d <= 2)
        .map(|(_, f)| f)
}

/// Plain Levenshtein distance; inputs are short flag names.
fn edit_distance(a: &str, b: &str) -> usize {
    // Optimal string alignment: a transposition of two adjacent characters
    // (`-trace_mgs` for `-trace_msg`) is one edit, so it beats a flag that
    // is a plain two-edit neighbour (`-trace_logs`).
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut before: Vec<usize> = vec![0; b.len() + 1];
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != cb);
            let mut d = sub.min(prev[j + 1] + 1).min(cur[j] + 1);
            if i > 0 && j > 0 && *ca == b[j - 1] && a[i - 1] == *cb {
                d = d.min(before[j - 1] + 1);
            }
            cur[j + 1] = d;
        }
        std::mem::swap(&mut before, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Render `-h` output. Flags use SIPp's single-dash names.
#[must_use]
pub fn help_text() -> String {
    let mut out = String::new();
    out.push_str(concat!(
        "sipr — a SIPp-like SIP testing tool and traffic generator\n\n",
        "USAGE:\n    sipr [OPTIONS] [REMOTE_HOST[:PORT]]\n\n",
        "OPTIONS (SIPp-style single-dash names; '--' forms also accepted):\n",
    ));
    for (name, takes_value, value_name, help) in FLAGS {
        if matches!(*name, "h" | "help" | "v" | "version") {
            continue;
        }
        let left = if *takes_value {
            format!("-{name} <{value_name}>")
        } else {
            format!("-{name}")
        };
        out.push_str(&format!("    {left:<24} {help}\n"));
    }
    out.push_str(concat!(
        "    -h, --help               Print help\n",
        "    -v, --version            Print version\n\n",
        "EXAMPLES:\n",
        "    sipr -sn uas -p 5060                 run the embedded UAS on port 5060\n",
        "    sipr -sn uac -r 50 -m 1000 10.0.0.2  place 1000 calls at 50 cps\n",
        "    sipr -sf scenario.xml -r 10 host     run a custom scenario\n",
        "    sipr -sd uac                         print an embedded scenario\n",
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Invocation, String> {
        let argv = std::iter::once("sipr".to_owned()).chain(args.iter().map(|s| (*s).to_owned()));
        parse(argv)
    }

    fn cli(args: &[&str]) -> Cli {
        match run(args).unwrap() {
            Invocation::Run(cli) => *cli,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn defaults_match_sipp() {
        let c = cli(&[]);
        assert!((c.rate - 10.0).abs() < f64::EPSILON);
        assert_eq!(c.rate_period_ms, 1000);
        assert_eq!(c.pause_ms, 3000);
        assert_eq!(c.service, "service");
        assert_eq!(c.transport, Transport::UdpMono);
        assert_eq!(c.port, None);
    }

    #[test]
    fn parses_typical_uac_invocation() {
        let c = cli(&[
            "-sn",
            "uac",
            "-r",
            "50",
            "-m",
            "1000",
            "-l",
            "200",
            "10.0.0.2:5060",
        ]);
        assert_eq!(c.sn.as_deref(), Some("uac"));
        assert!((c.rate - 50.0).abs() < f64::EPSILON);
        assert_eq!(c.max_calls, Some(1000));
        assert_eq!(c.limit, Some(200));
        assert_eq!(c.target.as_deref(), Some("10.0.0.2:5060"));
    }

    #[test]
    fn double_dash_forms_accepted() {
        let c = cli(&["--sn", "uas", "--trace_msg", "-p", "5060"]);
        assert_eq!(c.sn.as_deref(), Some("uas"));
        assert!(c.trace_msg);
        assert_eq!(c.port, Some(5060));
    }

    #[test]
    fn equals_form_accepted() {
        let c = cli(&["-r=25", "-s=alice", "127.0.0.1"]);
        assert!((c.rate - 25.0).abs() < f64::EPSILON);
        assert_eq!(c.service, "alice");
    }

    #[test]
    fn unknown_flag_suggests_nearest() {
        let err = run(&["-trace_mgs"]).unwrap_err();
        assert!(err.contains("unknown option '-trace_mgs'"), "{err}");
        assert!(err.contains("did you mean '-trace_msg'"), "{err}");
    }

    #[test]
    fn missing_value_is_an_error() {
        let err = run(&["-sf"]).unwrap_err();
        assert!(err.contains("'-sf' requires a value"), "{err}");
    }

    #[test]
    fn sf_conflicts_with_sn() {
        let err = run(&["-sf", "x.xml", "-sn", "uac"]).unwrap_err();
        assert!(err.contains("cannot be used together"), "{err}");
    }

    #[test]
    fn out_of_call_scenario_flags_parse_and_conflict() {
        let c = cli(&["-oocsn", "ooc_default", "host"]);
        assert_eq!(c.oocsn.as_deref(), Some("ooc_default"));
        assert!(c.oocsf.is_none());
        let c = cli(&["-oocsf", "ooc.xml", "host"]);
        assert_eq!(c.oocsf.as_deref(), Some(std::path::Path::new("ooc.xml")));
        let err = run(&["-oocsf", "ooc.xml", "-oocsn", "ooc_default"]).unwrap_err();
        assert!(
            err.contains("'-oocsf' and '-oocsn' cannot be used together"),
            "{err}"
        );
        let err = run(&["-oocsn"]).unwrap_err();
        assert!(err.contains("'-oocsn' requires a value"), "{err}");
    }

    #[test]
    fn mixed_mode_flags_parse_and_conflict() {
        let c = cli(&["-rxsn", "uas", "-rxinf", "a.csv", "-rxinf", "b.csv", "host"]);
        assert_eq!(c.rxsn.as_deref(), Some("uas"));
        assert!(c.rxsf.is_none());
        assert_eq!(
            c.rxinf,
            vec![PathBuf::from("a.csv"), PathBuf::from("b.csv")]
        );
        let c = cli(&["-rxsf", "rx.xml", "host"]);
        assert_eq!(c.rxsf.as_deref(), Some(std::path::Path::new("rx.xml")));
        let err = run(&["-rxsf", "rx.xml", "-rxsn", "uas"]).unwrap_err();
        assert!(
            err.contains("'-rxsf' and '-rxsn' cannot be used together"),
            "{err}"
        );
        let err = run(&["-rxsn", "uas", "-oocsn", "ooc_default"]).unwrap_err();
        assert!(
            err.contains("'-rxsf'/'-rxsn' and '-oocsf'/'-oocsn' cannot be used together"),
            "{err}"
        );
        let err = run(&["-rxsf"]).unwrap_err();
        assert!(err.contains("'-rxsf' requires a value"), "{err}");
    }

    #[test]
    fn transport_modes_parse_and_reject() {
        assert_eq!(cli(&["-t", "t1", "host"]).transport, Transport::TcpMono);
        assert_eq!(cli(&["-t", "l1", "host"]).transport, Transport::TlsMono);
        assert_eq!(cli(&["-t", "un", "host"]).transport, Transport::UdpPerCall);
        assert_eq!(cli(&["-t", "tn", "host"]).transport, Transport::TcpPerCall);
        assert_eq!(cli(&["-t", "ln", "host"]).transport, Transport::TlsPerCall);
        assert_eq!(cli(&["-max_socket", "3", "host"]).max_socket, Some(3));
        assert_eq!(
            cli(&["-rsa", "10.0.0.9:5080", "host"])
                .remote_sending
                .as_deref(),
            Some("10.0.0.9:5080")
        );
        let c = cli(&[
            "-max_reconnect",
            "-1",
            "-reconnect_close",
            "false",
            "-reconnect_sleep",
            "250",
            "host",
        ]);
        assert_eq!(c.max_reconnect, -1);
        assert!(!c.reconnect_close);
        assert_eq!(c.reconnect_sleep_ms, 250);
        let err = run(&["-reconnect_close", "maybe", "host"]).unwrap_err();
        assert!(err.contains("expected true or false"), "{err}");
        let err = run(&["-max_socket", "0", "host"]).unwrap_err();
        assert!(err.contains("at least 1"), "{err}");
        assert_eq!(
            cli(&["-t", "ui", "-inf", "ips.csv", "host"]).transport,
            Transport::UdpPerIp
        );
        assert_eq!(cli(&["-t", "s1", "host"]).transport, Transport::SctpMono);
        assert_eq!(cli(&["-t", "sn", "host"]).transport, Transport::SctpPerCall);
        let err = run(&["-t", "s1", "-heartbeat", "500", "host"]).unwrap_err();
        assert!(err.contains("not supported"), "{err}");
        assert_eq!(cli(&["-ip_field", "2", "host"]).ip_field, 2);
        let err = run(&["-t", "ui", "host"]).unwrap_err();
        assert!(err.contains("-inf"), "{err}");
        let err = run(&["-t", "x9"]).unwrap_err();
        assert!(err.contains("unknown transport mode"), "{err}");
    }

    #[test]
    fn media_flags_parse_with_sipp_alias() {
        let c = cli(&["-mi", "10.0.0.5", "-mp", "7000", "127.0.0.1"]);
        assert_eq!(c.media_ip, Some("10.0.0.5".parse().unwrap()));
        assert_eq!(c.media_port, Some(7000));
        let c = cli(&["-min_rtp_port", "8000", "127.0.0.1"]);
        assert_eq!(c.media_port, Some(8000));
        assert!(run(&["-mp", "x", "127.0.0.1"]).is_err());
        let c = cli(&["127.0.0.1"]);
        assert_eq!(c.media_ip, None);
        assert_eq!(c.media_port, None);
        let c = cli(&[
            "-max_rtp_port",
            "7000",
            "-rtp_payload",
            "0",
            "-random_base_ssrc",
            "x",
        ]);
        assert_eq!(c.max_rtp_port, Some(7000));
        assert_eq!(c.rtp_payload, Some(0));
        assert!(c.random_base_ssrc);
        assert!(run(&["-rtp_payload", "200", "x"]).is_err());
    }

    #[test]
    fn rate_ramp_flags_parse_with_time_units() {
        let c = cli(&[
            "-rate_increase",
            "10",
            "-rate_max",
            "100",
            "-rate_interval",
            "10s",
            "-no_rate_quit",
            "-rate_scale",
            "5",
            "x",
        ]);
        assert_eq!(c.rate_increase, Some(10.0));
        assert_eq!(c.rate_max, Some(100.0));
        assert_eq!(c.rate_interval, Some(std::time::Duration::from_secs(10)));
        assert!(c.no_rate_quit);
        assert_eq!(c.rate_scale, Some(5.0));
        assert_eq!(
            cli(&["-rate_interval", "500ms", "x"]).rate_interval,
            Some(std::time::Duration::from_millis(500))
        );
        assert_eq!(
            cli(&["-rate_interval", "2", "x"]).rate_interval,
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(
            cli(&["-rate_interval", "1m", "x"]).rate_interval,
            Some(std::time::Duration::from_secs(60))
        );
        assert!(run(&["-rate_interval", "5d", "x"]).is_err());
        assert!(run(&["-rate_interval", "abc", "x"]).is_err());
    }

    #[test]
    fn echo_and_rtpcheck_flags_parse() {
        let c = cli(&[
            "-rtp_echo",
            "-mb",
            "4096",
            "-audiotolerance",
            "0.5",
            "-videotolerance",
            "1",
            "x",
        ]);
        assert!(c.rtp_echo);
        assert_eq!(c.media_bufsize, Some(4096));
        assert_eq!(c.audio_tolerance, Some(0.5));
        assert_eq!(c.video_tolerance, Some(1.0));
        assert!(run(&["-audiotolerance", "1.5", "x"]).is_err());
    }

    #[test]
    fn control_flags_parse() {
        let c = cli(&[
            "-cp",
            "9000",
            "-ci",
            "0.0.0.0",
            "--sipr-http",
            "8080",
            "--sipr-http-token",
            "t",
            "x",
        ]);
        assert_eq!(c.control_port, Some(9000));
        assert_eq!(c.control_ip, Some("0.0.0.0".parse().unwrap()));
        assert_eq!(c.http.as_deref(), Some("8080"));
        assert_eq!(c.http_token.as_deref(), Some("t"));
        let c = cli(&["-cp", "0", "x"]);
        assert_eq!(c.control_port, Some(0));
        assert!(run(&["-cp", "x", "y"]).is_err());
    }

    #[test]
    fn tls_flags_parse_and_version_gates() {
        let c = cli(&[
            "-t",
            "l1",
            "-tls_cert",
            "my.pem",
            "-tls_key",
            "my.key",
            "-tls_ca",
            "ca.pem",
            "host",
        ]);
        assert_eq!(c.tls_cert, PathBuf::from("my.pem"));
        assert_eq!(c.tls_key, PathBuf::from("my.key"));
        assert_eq!(c.tls_ca, Some(PathBuf::from("ca.pem")));
        // SIPp defaults.
        let d = cli(&["host"]);
        assert_eq!(d.tls_cert, PathBuf::from("cacert.pem"));
        assert_eq!(d.tls_key, PathBuf::from("cakey.pem"));
        assert_eq!(d.tls_version, TlsVersionArg::Auto);
        // Version pins: 1.2/1.3 parse; 1.0/1.1 are a documented divergence.
        assert_eq!(
            cli(&["-tls_version", "1.3", "host"]).tls_version,
            TlsVersionArg::V1_3
        );
        let err = run(&["-tls_version", "1.0"]).unwrap_err();
        assert!(err.contains("not supported by sipr"), "{err}");
        let err = run(&["-tls_version", "2"]).unwrap_err();
        assert!(err.contains("-tls_version"), "{err}");
    }

    #[test]
    fn bad_numeric_value_reports_flag() {
        let err = run(&["-r", "fast"]).unwrap_err();
        assert!(
            err.contains("invalid value 'fast' for option '-r'"),
            "{err}"
        );
    }

    #[test]
    fn two_positionals_rejected() {
        let err = run(&["10.0.0.1", "10.0.0.2"]).unwrap_err();
        assert!(err.contains("unexpected extra argument"), "{err}");
    }

    #[test]
    fn help_and_version_flags() {
        assert!(matches!(run(&["-h"]).unwrap(), Invocation::Help));
        assert!(matches!(run(&["--help"]).unwrap(), Invocation::Help));
        assert!(matches!(run(&["-v"]).unwrap(), Invocation::Version));
        assert!(matches!(run(&["--version"]).unwrap(), Invocation::Version));
    }

    #[test]
    fn help_text_lists_every_flag() {
        let help = help_text();
        for (name, ..) in FLAGS {
            assert!(help.contains(&format!("-{name}")), "help missing -{name}");
        }
    }

    #[test]
    fn edit_distance_sanity() {
        assert_eq!(edit_distance("trace_mgs", "trace_msg"), 1);
        assert_eq!(edit_distance("trace_mgs", "trace_logs"), 2);
        assert_eq!(edit_distance("sn", "sn"), 0);
        assert!(closest_flag("zzzzzzzzzz").is_none());
    }

    #[test]
    fn set_takes_a_variable_and_a_value_and_repeats() {
        let c = cli(&[
            "-sn", "uac", "-set", "region", "eu", "-set", "tier", "gold", "host",
        ]);
        assert_eq!(
            c.set_vars,
            vec![
                ("region".to_owned(), "eu".to_owned()),
                ("tier".to_owned(), "gold".to_owned())
            ]
        );
        assert_eq!(c.target.as_deref(), Some("host"));
        let err = run(&["-set", "region"]).unwrap_err();
        assert!(err.contains("requires a VALUE after VARIABLE"), "{err}");
        let err = run(&["-set"]).unwrap_err();
        assert!(err.contains("requires VARIABLE and VALUE"), "{err}");
    }
}
