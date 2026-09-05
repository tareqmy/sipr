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
    let outcome = sipr_scenario::compile(&scenario_name, &source);
    for d in &outcome.diagnostics {
        eprintln!("sipr: {d}");
    }

    if cli.check {
        // Lint mode: dump the IR; any diagnostic (even a warning) fails.
        if let Some(sc) = &outcome.scenario {
            print!("{}", sc.dump());
        }
        return if outcome.diagnostics.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    let Some(scenario) = outcome.scenario else {
        return fatal(&format!("scenario '{scenario_name}' failed to compile"));
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
    // A v6 target needs a v6 local socket; default the bind family to `::` when
    // the target is IPv6 and no explicit -i was given.
    let local_ip = cli.local_ip.or_else(|| {
        target.and_then(|t| {
            t.is_ipv6()
                .then_some(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
        })
    });
    let config = sipr_engine::EngineConfig {
        target,
        local_ip,
        port: cli.port,
        service: cli.service.clone(),
        rate: cli.rate,
        rate_period: std::time::Duration::from_millis(cli.rate_period_ms),
        limit: cli.limit,
        max_calls: cli.max_calls,
        pause_default: std::time::Duration::from_millis(cli.pause_ms),
        max_retrans: cli.max_retrans,
        no_retrans: cli.no_retrans,
        timeout: cli.timeout_s.map(std::time::Duration::from_secs),
        base_cseq: cli.base_cseq.unwrap_or(1),
        call_id_format: cli.call_id_format.clone(),
        seed: 0,
        periodic_stats: cli.background,
        auto_answer: cli.auto_answer,
        auth_user: cli.auth_user.clone(),
        auth_password: cli.auth_password.clone(),
        auth_uri: cli.auth_uri.clone(),
        trace_msg: cli
            .trace_msg
            .then(|| std::path::PathBuf::from(format!("{base}_{pid}_messages.log"))),
        trace_err: cli
            .trace_err
            .then(|| std::path::PathBuf::from(format!("{base}_{pid}_errors.log"))),
        trace_stat: cli.trace_stat.then(|| {
            cli.stat_file
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from(format!("{base}_{pid}_.csv")))
        }),
        stat_interval: std::time::Duration::from_secs(cli.stat_interval_s.unwrap_or(1)),
        inf_files: cli.inf.clone(),
        inf_index: cli.inf_index.clone(),
        transport: match cli.transport {
            crate::cli::Transport::UdpMono => sipr_engine::TransportKind::UdpMono,
            crate::cli::Transport::UdpPerCall => sipr_engine::TransportKind::UdpPerCall,
            crate::cli::Transport::UdpPerIp => sipr_engine::TransportKind::UdpPerIp,
            crate::cli::Transport::TcpMono => sipr_engine::TransportKind::TcpMono,
            crate::cli::Transport::TcpPerCall => sipr_engine::TransportKind::TcpPerCall,
            crate::cli::Transport::TlsMono => sipr_engine::TransportKind::TlsMono,
            crate::cli::Transport::TlsPerCall => sipr_engine::TransportKind::TlsPerCall,
        },
        max_socket: cli.max_socket.unwrap_or(50_000),
        ip_field: cli.ip_field,
        max_reconnect: cli.max_reconnect,
        reconnect_close: cli.reconnect_close,
        reconnect_sleep: std::time::Duration::from_millis(cli.reconnect_sleep_ms),
        remote_sending_addr: match &cli.remote_sending {
            Some(raw) => match resolve_target(raw) {
                Ok(addr) => Some(addr),
                Err(e) => return fatal(&format!("-rsa: {e}")),
            },
            None => None,
        },
        twin_addr: match &cli.three_pcc {
            Some(raw) => match resolve_target(raw) {
                Ok(addr) => Some(addr),
                Err(e) => return fatal(&format!("-3pcc: {e}")),
            },
            None => None,
        },
        users: cli.users,
        media_ip: cli.media_ip,
        media_port: cli.media_port,
        max_rtp_port: cli.max_rtp_port,
        rtp_payload: cli.rtp_payload,
        random_base_ssrc: cli.random_base_ssrc,
        rate_increase: cli.rate_increase,
        rate_max: cli.rate_max,
        rate_interval: cli.rate_interval,
        rate_quit: !cli.no_rate_quit,
        rate_scale: cli.rate_scale,
        rtp_echo: cli.rtp_echo,
        media_bufsize: cli.media_bufsize,
        audio_tolerance: cli.audio_tolerance,
        video_tolerance: cli.video_tolerance,
        control_port: cli.control_port,
        control_ip: cli.control_ip,
        http_addr: match cli.http.as_deref() {
            None => None,
            Some(raw) => match resolve_http_addr(raw) {
                Ok(a) => Some(a),
                Err(e) => return fatal(&format!("--sipr-http: {e}")),
            },
        },
        http_token: cli.http_token.clone(),
        trace_name_base: Some(format!("{base}_{pid}")),
        // pcap paths resolve next to the scenario file first (SIPp find_file).
        scenario_dir: cli
            .sf
            .as_deref()
            .and_then(std::path::Path::parent)
            .map(std::path::Path::to_path_buf),
        // Built only when TLS is selected: cert/key defaults (cacert.pem /
        // cakey.pem, like SIPp) would otherwise error on absent files.
        tls: matches!(
            cli.transport,
            crate::cli::Transport::TlsMono | crate::cli::Transport::TlsPerCall
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
        }),
    };
    // Live TUI when attached to a terminal (and not headless/lint mode).
    let use_tui = {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal() && std::io::stdin().is_terminal() && !cli.background
    };
    let result = if use_tui {
        let (snap_tx, snap_rx) = std::sync::mpsc::channel::<sipr_stats::Snapshot>();
        let (key_tx, key_rx) = std::sync::mpsc::channel::<char>();
        let tui = std::thread::Builder::new()
            .name("sipr-tui".into())
            .spawn(move || sipr_tui::run(&snap_rx, &key_tx))
            .ok();
        let outcome = sipr_engine::run_with_ui(
            &scenario,
            &config,
            Some(sipr_engine::UiChannels {
                snapshots: snap_tx,
                keys: key_rx,
            }),
        );
        if let Some(t) = tui {
            let _ = t.join(); // restores the terminal before we print
        }
        outcome.map(|(report, _)| report)
    } else {
        sipr_engine::run(&scenario, &config)
    };
    match result {
        Ok(report) => {
            if let Some(msg) = &report.fatal {
                eprintln!("sipr: error: {msg}");
            }
            eprintln!("sipr: run complete: {}", report.summary());
            ExitCode::from(report.exit_code())
        }
        Err(e) => fatal(&e.to_string()),
    }
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

fn fatal(msg: &str) -> ExitCode {
    eprintln!("sipr: error: {msg}");
    ExitCode::from(EXIT_FATAL)
}

#[cfg(test)]
mod tests {
    use super::resolve_target;

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
