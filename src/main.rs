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
/// Exit code used until the engine exists: aborted, no calls processed.
const EXIT_NO_CALLS: u8 = 99;
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

    // UAS mode lands at M4; until then only UAC scenarios run.
    if scenario.role == Role::Uas {
        eprintln!(
            "sipr {}: scenario '{scenario_name}' accepted ({} steps, Uas) — UAS \
             mode is not implemented yet (M4; see docs/MILESTONES.md). Exiting.",
            env!("CARGO_PKG_VERSION"),
            scenario.steps.len(),
        );
        return ExitCode::from(EXIT_NO_CALLS);
    }

    // A UAC needs somewhere to send calls.
    let Some(target_raw) = cli.target.as_deref() else {
        return fatal(&format!(
            "remote target required: scenario '{scenario_name}' is a UAC — \
             pass REMOTE_HOST[:PORT]"
        ));
    };
    let target = match resolve_target(target_raw) {
        Ok(t) => t,
        Err(e) => return fatal(&e),
    };

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
    };
    match sipr_engine::run(&scenario, &config) {
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
