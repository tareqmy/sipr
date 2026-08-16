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
    let config = sipr_engine::EngineConfig {
        target,
        local_ip: cli.local_ip,
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
            eprintln!("sipr: run complete: {}", report.summary());
            ExitCode::from(report.exit_code())
        }
        Err(e) => fatal(&e.to_string()),
    }
}

/// Resolve `host[:port]` (port defaults to 5060). Bare IPv6 literals are a
/// post-v1 concern (docs/SIPP_COMPAT.md roadmap).
fn resolve_target(raw: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let candidate = if raw
        .rsplit(':')
        .next()
        .is_some_and(|p| p.parse::<u16>().is_ok())
        && raw.matches(':').count() == 1
    {
        raw.to_owned()
    } else {
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
