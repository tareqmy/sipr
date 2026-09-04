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
// The shared `Mono` postfix is SIPp's own taxonomy (`u1`/`t1`/`l1` = one
// socket) and will contrast with per-call multi-socket modes if those land.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// `u1`: UDP with one socket shared by all calls (SIPp's default).
    UdpMono,
    /// `t1`: TCP with one connection per peer (client dials, server accepts).
    TcpMono,
    /// `l1`: TLS over TCP, same connection-per-peer model.
    TlsMono,
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
    /// `-sn`: use an embedded default scenario (`uac` | `uas`).
    pub sn: Option<String>,
    /// `-sd`: print an embedded default scenario to stdout and exit.
    pub sd: Option<String>,
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
            timeout_s: None,
            base_cseq: None,
            call_id_format: None,
            max_retrans: None,
            inf: Vec::new(),
            inf_index: Vec::new(),
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
        "Use an embedded default scenario: uac | uas",
    ),
    (
        "sd",
        true,
        "NAME",
        "Print an embedded default scenario and exit",
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
        "Transport mode: u1 (UDP), t1 (TCP), l1 (TLS) [default: u1]",
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
    ("fd", true, "SECONDS", "Statistics dump interval in seconds"),
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
        "inf",
        true,
        "FILE",
        "Injection file (CSV) for [fieldN]; repeatable",
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
        // -infindex is the one two-argument flag: FILE then FIELD.
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
    if cli.users.is_some() && cli.limit.is_some() {
        return Err(
            "options '-users' and '-l' cannot be used together (users mode is closed-loop)"
                .to_owned(),
        );
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
        "bg" => cli.background = true,
        "trace_msg" => cli.trace_msg = true,
        "trace_err" => cli.trace_err = true,
        "trace_stat" => cli.trace_stat = true,
        "stf" => cli.stat_file = Some(PathBuf::from(val(value))),
        "fd" => cli.stat_interval_s = Some(parse_num(flag, &val(value))?),
        "timeout" => cli.timeout_s = Some(parse_num(flag, &val(value))?),
        "base_cseq" => cli.base_cseq = Some(parse_num(flag, &val(value))?),
        "cid_str" => cli.call_id_format = Some(val(value)),
        "max_retrans" => cli.max_retrans = Some(parse_num(flag, &val(value))?),
        "inf" => cli.inf.push(std::path::PathBuf::from(val(value))),
        "3pcc" => cli.three_pcc = Some(val(value)),
        "users" => cli.users = Some(parse_num(flag, &val(value))?),
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

fn parse_transport(s: &str) -> Result<Transport, String> {
    match s {
        "u1" => Ok(Transport::UdpMono),
        // SIPp's `tn`/`ln` (multi-socket) collapse onto our
        // one-connection-per-peer model; accept them as aliases.
        "t1" | "tn" => Ok(Transport::TcpMono),
        "l1" | "ln" => Ok(Transport::TlsMono),
        "un" | "ui" => Err(format!(
            "transport mode '{s}' is not implemented yet — 'u1' (UDP), 't1' \
             (TCP), and 'l1' (TLS) are supported"
        )),
        other => Err(format!(
            "unknown transport mode '{other}' (expected 'u1', 't1', or 'l1')"
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
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != cb);
            cur[j + 1] = sub.min(prev[j + 1] + 1).min(cur[j] + 1);
        }
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
    fn transport_modes_parse_and_reject() {
        assert_eq!(cli(&["-t", "t1", "host"]).transport, Transport::TcpMono);
        assert_eq!(cli(&["-t", "l1", "host"]).transport, Transport::TlsMono);
        // ln collapses onto connection-per-peer, like tn.
        assert_eq!(cli(&["-t", "ln", "host"]).transport, Transport::TlsMono);
        let err = run(&["-t", "un"]).unwrap_err();
        assert!(err.contains("not implemented yet"), "{err}");
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
        assert_eq!(edit_distance("trace_mgs", "trace_msg"), 2);
        assert_eq!(edit_distance("sn", "sn"), 0);
        assert!(closest_flag("zzzzzzzzzz").is_none());
    }
}
