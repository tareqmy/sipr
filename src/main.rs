//! sipr binary: CLI in, engine out. As of M1 the scenario front end is real —
//! scenarios are compiled to the step IR and linted (`--check`). The traffic
//! engine lands at M3; until then runs exit 99 ("aborted, no calls processed",
//! docs/SIPP_COMPAT.md §5) after validation.

mod cli;

use std::process::ExitCode;

use sipr_scenario::model::Role;

use crate::cli::{Cli, Invocation};

/// Usage-error exit code.
const EXIT_USAGE: u8 = 2;
/// Fatal error exit code (SIPp uses -1, i.e. 255).
const EXIT_FATAL: u8 = 255;

fn main() -> ExitCode {
    match cli::parse(std::env::args()) {
        Ok(Invocation::Help) => {
            print!("{}", cli::help_text());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("sipr {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(cli)) => run(&cli),
        Err(msg) => {
            eprintln!("sipr: error: {msg}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn run(cli: &Cli) -> ExitCode {
    // SIPp flags sipr accepts but cannot act on (cli::no_effect_reason).
    for warning in &cli.warnings {
        eprintln!("sipr: warning: {warning}");
    }

    // -sd: dump an embedded scenario and exit.
    if let Some(name) = cli.sd.as_deref() {
        return match sipr_scenario::embedded(name) {
            Some(xml) => {
                print!("{xml}");
                ExitCode::SUCCESS
            }
            None => fatal(&unknown_embedded(name)),
        };
    }

    // Scenario resolution: -sf beats -sn beats SIPp's default of uac.
    let (scenario_name, source) = if let Some(path) = &cli.sf {
        match std::fs::read(path) {
            Ok(bytes) => (path.display().to_string(), latin1_tolerant(bytes)),
            Err(e) => {
                return fatal(&format!(
                    "cannot read scenario file {}: {e}",
                    path.display()
                ));
            }
        }
    } else {
        let name = cli.sn.as_deref().unwrap_or("uac");
        match sipr_scenario::embedded(name) {
            Some(xml) => (name.to_owned(), xml.to_owned()),
            None => return fatal(&unknown_embedded(name)),
        }
    };

    // Compile to the step IR; every diagnostic is printed, loudly.
    // `-key` names render as literals instead of drawing the unknown-keyword
    // warning; the compiler needs them to tell the two apart. `--check` also
    // lints: scenarios that run but do not do what they say.
    let compile_options = sipr_scenario::CompileOptions {
        generic_keywords: cli
            .generic_keywords
            .iter()
            .map(|(k, _)| k.clone())
            .collect(),
        lint: cli.check,
    };
    let outcome = sipr_scenario::compile_with(&scenario_name, &source, &compile_options);
    for d in &outcome.diagnostics {
        eprintln!("sipr: {d}");
    }
    // The secondary scenario (-oocsf/-oocsn out-of-call, or -rxsf/-rxsn
    // receive) compiles independently, with the same loud diagnostics and
    // the same lint rules under --check.
    let secondary_outcome = match load_secondary_source(cli) {
        Ok(Some((kind, name, source))) => {
            let out = sipr_scenario::compile_with(&name, &source, &compile_options);
            for d in &out.diagnostics {
                eprintln!("sipr: {d}");
            }
            Some((kind, name, out))
        }
        Ok(None) => None,
        Err(msg) => return fatal(&msg),
    };

    if cli.check {
        // Lint mode: dump the IR; any diagnostic (even a warning) fails.
        if let Some(sc) = &outcome.scenario {
            print!("{}", sc.dump());
        }
        let mut clean = outcome.diagnostics.is_empty();
        if let Some((kind, _, out)) = &secondary_outcome {
            if let Some(sc) = &out.scenario {
                print!("{} {}", kind.noun(), sc.dump());
            }
            clean &= out.diagnostics.is_empty();
        }
        return if clean {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    let Some(scenario) = outcome.scenario else {
        return fatal(&format!("scenario '{scenario_name}' failed to compile"));
    };
    let secondary = match secondary_outcome {
        Some((kind, name, out)) => match out.scenario {
            Some(sc) => Some((kind, sc)),
            None => {
                return fatal(&format!(
                    "{} scenario '{name}' failed to compile",
                    kind.noun()
                ));
            }
        },
        None => None,
    };

    // A UAC needs somewhere to send calls; a UAS listens and needs none.
    let target = match (scenario.role, cli.target.as_deref()) {
        (Role::Uac, None) => {
            return fatal(&format!(
                "remote target required: scenario '{scenario_name}' is a UAC — \
                 pass REMOTE_HOST[:PORT]"
            ));
        }
        (_, Some(raw)) => match resolve_target(raw) {
            Ok(t) => Some(t),
            Err(e) => return fatal(&e),
        },
        (Role::Uas, None) => None,
    };

    // Trace file names follow SIPp: <scenario>_<pid>_<kind>.
    let base = std::path::Path::new(&scenario_name)
        .file_stem()
        .map_or_else(
            || scenario_name.clone(),
            |s| s.to_string_lossy().into_owned(),
        );
    let pid = std::process::id();
    if cli.trace_timeout {
        eprintln!("sipr: warning: -trace_timeout has no effect (SIPp 3.7 never implemented it)");
    }
    if cli.send_timeout.is_some() {
        eprintln!(
            "sipr: warning: -send_timeout has no effect (sipr has no send queue to time out)"
        );
    }
    if cli.timer_resol.is_some() {
        eprintln!("sipr: warning: -timer_resol has no effect (sipr's timers are exact)");
    }
    if let Some(d) = cli.sleep {
        std::thread::sleep(d);
    }
    let config = match engine_config(cli, target, &base, pid) {
        Ok(config) => config,
        Err(e) => return fatal(&e),
    };
    // Live TUI when attached to a terminal (and not headless/lint mode).
    let use_tui = {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal() && std::io::stdin().is_terminal() && !cli.background
    };
    let mut run = match sipr_engine::Run::start_with(scenario, secondary, config) {
        Ok(run) => run,
        Err(e) => return fatal(&e.to_string()),
    };
    let result = if use_tui {
        let snapshots = run.snapshots();
        let (key_tx, key_rx) = std::sync::mpsc::channel::<char>();
        let tui = std::thread::Builder::new()
            .name("sipr-tui".into())
            .spawn(move || sipr_tui::run(&snapshots, &key_tx))
            .ok();
        forward_keys(key_rx, run.control().clone());
        let outcome = run.wait();
        if let Some(t) = tui {
            let _ = t.join(); // restores the terminal before we print
        }
        outcome
    } else {
        // Headless: 'q' and 'Q' on stdin still quit unless -nostdin.
        if !cli.nostdin {
            forward_keys(stdin_keys(), run.control().clone());
        }
        run.wait()
    };
    match result {
        Ok(report) => {
            if let Some(msg) = &report.fatal {
                eprintln!("sipr: error: {msg}");
            }
            if cli.trace_screen {
                write_screens(cli, &base, pid, &report.snapshot);
            }
            eprintln!("sipr: run complete: {}", report.summary());
            ExitCode::from(report.exit_code())
        }
        Err(e) => fatal(&e.to_string()),
    }
}

/// The engine configuration for this invocation: SIPp's defaults from
/// [`sipr_engine::EngineConfig`] with what the command line set on top.
/// Only the command line's own values appear here — a default number
/// belongs in the engine, and the parity test below keeps the two in step.
/// `base` and `pid` name the trace files (`<scenario>_<pid>_<kind>`).
fn engine_config(
    cli: &Cli,
    target: Option<std::net::SocketAddr>,
    base: &str,
    pid: u32,
) -> Result<sipr_engine::EngineConfig, String> {
    use std::path::PathBuf;
    use std::time::Duration;

    let mut config = match target {
        Some(target) => sipr_engine::EngineConfig::uac(target),
        None => sipr_engine::EngineConfig::uas(),
    };
    // `[remote_host]` is the host as typed, brackets and port stripped.
    config.remote_host = cli.target.as_deref().map(host_part).unwrap_or_default();
    if let Some(ip) = cli.local_ip {
        config.local_ip = Some(ip);
    }
    config.bind_local = cli.bind_local;
    config.sockopts = sipr_engine::SocketOpts {
        buff_size: cli.buff_size,
        bind_device: cli.bind_to_device.clone(),
    };
    config.sendbuffer_warn = cli.sendbuffer_warn;
    config.port = cli.port;
    config.service.clone_from(&cli.service);
    config.rate = cli.rate;
    config.rate_period = Duration::from_millis(cli.rate_period_ms);
    config.limit = cli.limit;
    config.max_calls = cli.max_calls;
    config.pause_default = Duration::from_millis(cli.pause_ms);
    config.max_retrans = cli.max_retrans;
    config.no_retrans = cli.no_retrans;
    config.timeout = cli.timeout_s.map(Duration::from_secs);
    if let Some(cseq) = cli.base_cseq {
        config.base_cseq = cseq;
    }
    config.call_id_format.clone_from(&cli.call_id_format);
    config.periodic_stats = cli.background;
    config.auto_answer = cli.auto_answer;
    config.auth_user.clone_from(&cli.auth_user);
    config.auth_password.clone_from(&cli.auth_password);
    config.auth_uri.clone_from(&cli.auth_uri);
    let named = |explicit: &Option<PathBuf>, suffix: &str| {
        explicit
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("{base}_{pid}_{suffix}")))
    };
    config.trace_msg = cli
        .trace_msg
        .then(|| named(&cli.message_file, "messages.log"));
    config.trace_err = cli.trace_err.then(|| named(&cli.error_file, "errors.log"));
    config.trace_stat = cli.trace_stat.then(|| named(&cli.stat_file, ".csv"));
    // The final `-trace_stat` row is written whatever the interval.
    if let Some(secs) = cli.stat_interval_s {
        config.stat_interval = Duration::from_secs(secs);
    }
    config.inf = cli.inf.iter().cloned().map(Into::into).collect();
    config.rxinf = cli.rxinf.iter().cloned().map(Into::into).collect();
    config.inf_index.clone_from(&cli.inf_index);
    config.global_sets.clone_from(&cli.set_vars);
    config.generic_keywords.clone_from(&cli.generic_keywords);
    let (start, step, max) = config.dynamic_id;
    config.dynamic_id = (
        cli.dynamic_start.unwrap_or(start),
        cli.dynamic_step.unwrap_or(step),
        cli.dynamic_max.unwrap_or(max),
    );
    config.tdm_map.clone_from(&cli.tdmmap);
    config.rfc3339 = cli.rfc3339;
    if let Some(secs) = cli.report_interval_s {
        config.report_interval = Duration::from_secs(secs);
    }
    config.trace_rtt = cli.trace_rtt.then(|| named(&None, "rtt.csv"));
    config.trace_counts = cli.trace_counts.then(|| named(&None, "counts.csv"));
    config.trace_error_codes = cli
        .trace_error_codes
        .then(|| named(&None, "error_codes.csv"));
    if let Some(freq) = cli.rtt_freq {
        config.rtt_freq = freq;
    }
    if let Some(delimiter) = &cli.stat_delimiter {
        config.stat_delimiter.clone_from(delimiter);
    }
    config.periodic_rtd = cli.periodic_rtd;
    config.trace_logs = cli.trace_logs.then(|| named(&cli.log_file, "logs.log"));
    config.trace_shortmsg = cli
        .trace_shortmsg
        .then(|| named(&cli.shortmessage_file, "shortmessages.log"));
    config.trace_calldebug = cli
        .trace_calldebug
        .then(|| named(&cli.calldebug_file, "calldebug.log"));
    config.log_overwrite = sipr_engine::LogOverwrite {
        messages: cli.message_overwrite,
        errors: cli.error_overwrite,
        logs: cli.log_overwrite,
        shortmessages: cli.shortmessage_overwrite,
        calldebug: cli.calldebug_overwrite,
    };
    let rotation = config.log_rotation;
    config.log_rotation = sipr_stats::LogRotation {
        ringbuffer_files: cli.ringbuffer_files.unwrap_or(rotation.ringbuffer_files),
        ringbuffer_size: cli.ringbuffer_size.unwrap_or(rotation.ringbuffer_size),
        max_log_size: cli.max_log_size.unwrap_or(rotation.max_log_size),
    };
    if let Some(ms) = cli.deadcall_wait_ms {
        config.deadcall_wait = Duration::from_millis(ms);
    }
    if let Some(n) = cli.max_invite_retrans {
        config.max_invite_retrans = n;
    }
    if let Some(n) = cli.max_non_invite_retrans {
        config.max_non_invite_retrans = n;
    }
    config.recv_timeout = cli.recv_timeout;
    config.timeout_error = cli.timeout_error;
    config.lost = cli.lost;
    config.pause_msg_ign = cli.pause_msg_ign;
    config.behaviors = if cli.no_defaults {
        sipr_engine::Behaviors::none()
    } else {
        cli.default_behaviors.unwrap_or_default()
    };
    config.callid_slash_ign = cli.callid_slash_ign;
    config.transport = match cli.transport {
        crate::cli::Transport::UdpMono => sipr_engine::TransportKind::UdpMono,
        crate::cli::Transport::UdpPerCall => sipr_engine::TransportKind::UdpPerCall,
        crate::cli::Transport::UdpPerIp => sipr_engine::TransportKind::UdpPerIp,
        crate::cli::Transport::TcpMono => sipr_engine::TransportKind::TcpMono,
        crate::cli::Transport::TcpPerCall => sipr_engine::TransportKind::TcpPerCall,
        crate::cli::Transport::TlsMono => sipr_engine::TransportKind::TlsMono,
        crate::cli::Transport::TlsPerCall => sipr_engine::TransportKind::TlsPerCall,
        crate::cli::Transport::WsMono => sipr_engine::TransportKind::WsMono,
        crate::cli::Transport::WsPerCall => sipr_engine::TransportKind::WsPerCall,
        crate::cli::Transport::WssMono => sipr_engine::TransportKind::WssMono,
        crate::cli::Transport::WssPerCall => sipr_engine::TransportKind::WssPerCall,
        crate::cli::Transport::SctpMono => sipr_engine::TransportKind::SctpMono,
        crate::cli::Transport::SctpPerCall => sipr_engine::TransportKind::SctpPerCall,
    };
    if let Some(n) = cli.max_socket {
        config.max_socket = n;
    }
    config.ip_field = cli.ip_field;
    config.max_reconnect = cli.max_reconnect;
    config.reconnect_close = cli.reconnect_close;
    config.reconnect_sleep = Duration::from_millis(cli.reconnect_sleep_ms);
    config.remote_sending_addr = match &cli.remote_sending {
        Some(raw) => Some(resolve_target(raw).map_err(|e| format!("-rsa: {e}"))?),
        None => None,
    };
    config.twin_addr = match &cli.three_pcc {
        Some(raw) => Some(resolve_target(raw).map_err(|e| format!("-3pcc: {e}"))?),
        None => None,
    };
    config.extended_3pcc = extended_3pcc(cli)?;
    config.users = cli.users;
    config.media_ip = cli.media_ip;
    config.media_port = cli.media_port;
    config.max_rtp_port = cli.max_rtp_port;
    config.rtp_payload = cli.rtp_payload;
    config.random_base_ssrc = cli.random_base_ssrc;
    config.rate_increase = cli.rate_increase;
    config.rate_max = cli.rate_max;
    config.rate_interval = cli.rate_interval;
    config.rate_quit = !cli.no_rate_quit;
    config.rate_scale = cli.rate_scale;
    config.rtp_echo = cli.rtp_echo;
    config.media_bufsize = cli.media_bufsize;
    if let Some(t) = cli.audio_tolerance {
        config.audio_tolerance = t;
    }
    if let Some(t) = cli.video_tolerance {
        config.video_tolerance = t;
    }
    config.rtpcheck_debug = cli.rtpcheck_debug;
    config.ws_request = sipr_engine::WsRequest::new(
        cli.ws_path.as_deref().unwrap_or("/"),
        cli.ws_origin.as_deref(),
    )
    .map_err(|e| format!("--sipr-ws-path / --sipr-ws-origin: {e}"))?;
    config.control_port = cli.control_port;
    config.control_ip = cli.control_ip;
    config.http_addr = match cli.http.as_deref() {
        Some(raw) => Some(resolve_http_addr(raw).map_err(|e| format!("--sipr-http: {e}"))?),
        None => None,
    };
    config.http_token.clone_from(&cli.http_token);
    config.stats_json.clone_from(&cli.stats_json);
    config.trace_name_base = Some(format!("{base}_{pid}"));
    // pcap paths resolve next to the scenario file first (SIPp find_file).
    config.scenario_dir = cli
        .sf
        .as_deref()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf);
    // Built only when TLS is selected: cert/key defaults (cacert.pem /
    // cakey.pem, like SIPp) would otherwise error on absent files.
    config.tls = matches!(
        cli.transport,
        crate::cli::Transport::TlsMono
            | crate::cli::Transport::TlsPerCall
            | crate::cli::Transport::WssMono
            | crate::cli::Transport::WssPerCall
    )
    .then(|| sipr_engine::TlsConfig {
        cert: cli.tls_cert.clone(),
        key: cli.tls_key.clone(),
        ca: cli.tls_ca.clone(),
        crl: cli.tls_crl.clone(),
        version: match cli.tls_version {
            crate::cli::TlsVersionArg::Auto => sipr_engine::TlsVersion::Auto,
            crate::cli::TlsVersionArg::V1_2 => sipr_engine::TlsVersion::V1_2,
            crate::cli::TlsVersionArg::V1_3 => sipr_engine::TlsVersion::V1_3,
        },
    });
    Ok(config)
}

/// Hand every key a producer sends (the TUI, or stdin) to the engine.
fn forward_keys(keys: std::sync::mpsc::Receiver<char>, control: sipr_engine::EngineControl) {
    let _ = std::thread::Builder::new()
        .name("sipr-keys".into())
        .spawn(move || {
            for key in keys {
                control.key(key);
            }
        });
}

/// SIPp's keyboard control without a screen: the first character of each
/// stdin line is a key command for the engine (`q` soft quit, `Q` hard
/// quit, the rate keys). EOF ends the reader; `-nostdin` never starts it.
fn stdin_keys() -> std::sync::mpsc::Receiver<char> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("sipr-stdin".into())
        .spawn(move || {
            let mut line = String::new();
            loop {
                line.clear();
                match std::io::stdin().read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if let Some(c) = line.trim().chars().next() {
                            if tx.send(c).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });
    rx
}

/// Resolve `host[:port]` to a socket address (port defaults to 5060).
/// Accepts IPv4, hostnames, and IPv6 in bracketed (`[::1]`, `[2001:db8::1]:5060`)
/// or bare-literal (`::1`) form.
/// `--sipr-http PORT` binds loopback; `HOST:PORT` (or `[v6]:PORT`) binds there.
fn resolve_http_addr(raw: &str) -> Result<std::net::SocketAddr, String> {
    if let Ok(port) = raw.parse::<u16>() {
        return Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }
    let has_port = raw
        .rsplit(':')
        .next()
        .is_some_and(|p| p.parse::<u16>().is_ok())
        && (raw.starts_with('[') || raw.matches(':').count() == 1);
    if !has_port {
        return Err(format!("'{raw}' needs a port (PORT or HOST:PORT)"));
    }
    resolve_target(raw)
}

/// `[remote_host]`: the host part of the target as typed — `host`,
/// `host:port`, `[v6]` or `[v6]:port` — brackets and port stripped, never
/// resolved (SIPp's `remote_host`).
/// `-trace_screen`: the scenario, statistics and repartition screens as
/// text, in SIPp's `print_screens` order, to `-screen_file` or
/// `<scenario>_<pid>_screen.log` — SIPp's `screen` log file, whatever its
/// help text says (`_screens.log`).
fn write_screens(cli: &cli::Cli, base: &str, pid: u32, snap: &sipr_stats::Snapshot) {
    let path = cli
        .screen_file
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{base}_{pid}_screen.log")));
    let mut text = String::new();
    for screen in [
        sipr_tui::Screen::Scenario,
        sipr_tui::Screen::Main,
        sipr_tui::Screen::Repartition,
    ] {
        for line in sipr_tui::render_screen(snap, screen) {
            text.push_str(&line);
            text.push('\n');
        }
        text.push('\n');
    }
    let result = if cli.screen_overwrite {
        std::fs::write(&path, text)
    } else {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .and_then(|mut f| f.write_all(text.as_bytes()))
    };
    if let Err(e) = result {
        eprintln!("sipr: warning: cannot write {}: {e}", path.display());
    }
}

fn host_part(target: &str) -> String {
    if let Some(rest) = target.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_owned();
        }
    }
    match target.rsplit_once(':') {
        // One colon = host:port; more = a bare IPv6 literal.
        Some((host, _)) if host.matches(':').count() == 0 => host.to_owned(),
        _ => target.to_owned(),
    }
}

fn resolve_target(raw: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::{Ipv6Addr, ToSocketAddrs};
    let candidate = if raw.starts_with('[') {
        // Bracketed IPv6: "[addr]" needs a default port; "[addr]:port" is ready.
        if raw.contains("]:") {
            raw.to_owned()
        } else {
            format!("{raw}:5060")
        }
    } else if raw.parse::<Ipv6Addr>().is_ok() {
        // Bare IPv6 literal without a port — bracket it and add the default.
        format!("[{raw}]:5060")
    } else if raw
        .rsplit(':')
        .next()
        .is_some_and(|p| p.parse::<u16>().is_ok())
        && raw.matches(':').count() == 1
    {
        // host:port (IPv4 or hostname).
        raw.to_owned()
    } else {
        // host with no port.
        format!("{raw}:5060")
    };
    candidate
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve target '{raw}': {e}"))?
        .next()
        .ok_or_else(|| format!("target '{raw}' resolved to no addresses"))
}

/// The secondary scenario's kind, name and XML: `-oocsf`/`-rxsf` read a
/// file, `-oocsn`/`-rxsn` an embedded one. `None` when none is set —
/// requests of no known call are then discarded, as SIPp does by default.
/// (The CLI already refuses an out-of-call and a receive scenario together.)
fn load_secondary_source(
    cli: &Cli,
) -> Result<Option<(sipr_engine::SecondaryKind, String, String)>, String> {
    use sipr_engine::SecondaryKind;
    let (kind, file, embedded_name) = if cli.rxsf.is_some() || cli.rxsn.is_some() {
        (SecondaryKind::Receive, &cli.rxsf, &cli.rxsn)
    } else {
        (SecondaryKind::OutOfCall, &cli.oocsf, &cli.oocsn)
    };
    if let Some(path) = file {
        let bytes = std::fs::read(path).map_err(|e| {
            format!(
                "cannot read {} scenario file {}: {e}",
                kind.noun(),
                path.display()
            )
        })?;
        return Ok(Some((
            kind,
            path.display().to_string(),
            latin1_tolerant(bytes),
        )));
    }
    let Some(name) = embedded_name.as_deref() else {
        return Ok(None);
    };
    match sipr_scenario::embedded(name) {
        Some(xml) => Ok(Some((kind, name.to_owned(), xml.to_owned()))),
        None => Err(unknown_embedded(name)),
    }
}

fn unknown_embedded(name: &str) -> String {
    format!(
        "unknown embedded scenario '{name}' (available: {})",
        sipr_scenario::EMBEDDED_NAMES.join(", ")
    )
}

/// Decode file bytes as UTF-8, falling back to Latin-1 (SIPp scenarios are
/// traditionally ISO-8859-1).
fn latin1_tolerant(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => e.into_bytes().iter().map(|&b| b as char).collect(),
    }
}

/// `-master`/`-slave` + `-slave_cfg`: SIPp's option checks (`sipp.cpp`
/// `SIPP_OPTION_3PCC_EXTENDED`/`SIPP_OPTION_SLAVE_CFG`), then the peer table
/// read and resolved. `Ok(None)` when none of the three is given.
fn extended_3pcc(cli: &Cli) -> Result<Option<sipr_engine::Extended3pcc>, String> {
    if cli.master.is_some() && cli.slave.is_some() {
        return Err("-slave and -master options are not compatible".into());
    }
    if cli.three_pcc.is_some() {
        if cli.master.is_some() || cli.slave.is_some() {
            return Err("-master and -slave options are not compatible with -3PCC option".into());
        }
        if cli.slave_cfg.is_some() {
            return Err("-3pcc and -slave_cfg options are not compatible".into());
        }
    }
    let name = cli.master.as_ref().or(cli.slave.as_ref());
    let (Some(name), Some(path)) = (name, cli.slave_cfg.as_ref()) else {
        if name.is_some() || cli.slave_cfg.is_some() {
            return Err("-slave_cfg option must be used with -slave or -master option".into());
        }
        return Ok(None);
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Can not open slave_cfg file {}: {e}", path.display()))?;
    let table = sipr_engine::PeerTable::parse(&text);
    for line in table.skipped() {
        eprintln!(
            "sipr: warning: {}: line without a ';' skipped: {line}",
            path.display()
        );
    }
    let mut peers = Vec::new();
    for (peer, host) in table.entries() {
        let addr = resolve_target(host).map_err(|e| format!("-slave_cfg peer '{peer}': {e}"))?;
        peers.push((peer.to_owned(), addr));
    }
    if table.get(name).is_none() {
        return Err(format!(
            "get_peer_addr: Peer {name} not found in {}",
            path.display()
        ));
    }
    Ok(Some(sipr_engine::Extended3pcc {
        master: cli.master.is_some(),
        name: name.clone(),
        peers,
    }))
}

fn fatal(msg: &str) -> ExitCode {
    eprintln!("sipr: error: {msg}");
    ExitCode::from(EXIT_FATAL)
}

#[cfg(test)]
mod tests {
    use super::{engine_config, resolve_target};
    use crate::cli::{Invocation, parse};
    use sipr_engine::EngineConfig;

    /// The engine configuration a bare command line produces, with the
    /// trace-file stem the binary would name.
    fn config_for(argv: &[&str]) -> EngineConfig {
        let mut full = vec!["sipr"];
        full.extend_from_slice(argv);
        let Invocation::Run(cli) = parse(full.into_iter().map(str::to_owned)).unwrap() else {
            panic!("not a run");
        };
        let target = cli.target.as_deref().map(|t| resolve_target(t).unwrap());
        engine_config(&cli, target, "sn", 1).unwrap()
    }

    /// A command line that sets nothing must produce exactly the engine's
    /// own defaults: the numbers live in `EngineConfig::default()`, and this
    /// is what catches a default added or changed on only one side.
    #[test]
    fn bare_command_line_equals_the_engine_defaults() {
        let mut uac = EngineConfig::uac("127.0.0.1:5060".parse().unwrap());
        uac.trace_name_base = Some("sn_1".into());
        assert_eq!(config_for(&["-sn", "uac", "127.0.0.1"]), uac);

        let mut uas = EngineConfig::uas();
        uas.trace_name_base = Some("sn_1".into());
        assert_eq!(config_for(&["-sn", "uas"]), uas);
    }

    /// The v6 local-socket default and `[remote_host]` come from the
    /// constructor, not from the binary.
    #[test]
    fn ipv6_target_binds_a_v6_socket_by_default() {
        let config = config_for(&["-sn", "uac", "[::1]"]);
        assert_eq!(
            config.local_ip,
            Some(std::net::Ipv6Addr::UNSPECIFIED.into())
        );
        assert_eq!(config.remote_host, "::1");
        assert_eq!(config.target, Some("[::1]:5060".parse().unwrap()));
        // An explicit -i wins.
        let config = config_for(&["-sn", "uac", "-i", "::1", "[::1]"]);
        assert_eq!(config.local_ip, Some("::1".parse().unwrap()));
    }

    #[test]
    fn resolve_target_covers_v4_v6_and_hostnames() {
        // IPv4 with and without a port.
        assert_eq!(
            resolve_target("127.0.0.1").unwrap().to_string(),
            "127.0.0.1:5060"
        );
        assert_eq!(
            resolve_target("127.0.0.1:5080").unwrap().to_string(),
            "127.0.0.1:5080"
        );
        // Bare IPv6 literal -> bracketed with the default port.
        assert_eq!(resolve_target("::1").unwrap().to_string(), "[::1]:5060");
        assert_eq!(
            resolve_target("2001:db8::1").unwrap().to_string(),
            "[2001:db8::1]:5060"
        );
        // Bracketed IPv6, with and without a port.
        assert_eq!(resolve_target("[::1]").unwrap().to_string(), "[::1]:5060");
        assert_eq!(
            resolve_target("[2001:db8::1]:5080").unwrap().to_string(),
            "[2001:db8::1]:5080"
        );
        // localhost resolves (to v4 or v6); just ensure it succeeds with a port.
        assert!(resolve_target("localhost:5060").is_ok());
    }
}
