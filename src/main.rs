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

    // A UAC needs somewhere to send calls; a UAS does not.
    if scenario.role == Role::Uac && cli.target.is_none() {
        return fatal(&format!(
            "remote target required: scenario '{scenario_name}' is a UAC — \
             pass REMOTE_HOST[:PORT]"
        ));
    }

    eprintln!(
        "sipr {}: scenario '{scenario_name}' accepted ({} steps, {:?}) — the \
         traffic engine is not implemented yet (M1; see docs/MILESTONES.md). Exiting.",
        env!("CARGO_PKG_VERSION"),
        scenario.steps.len(),
        scenario.role,
    );
    ExitCode::from(EXIT_NO_CALLS)
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
