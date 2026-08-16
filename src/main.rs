//! sipr binary: CLI in, engine out. Until M3 lands there is no engine — the
//! binary validates the invocation, resolves the scenario, and exits 99
//! ("aborted, no calls processed" — see docs/SIPP_COMPAT.md §5).

mod cli;

use std::process::ExitCode;

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
            None => fatal(&format!(
                "unknown embedded scenario '{name}' (available: {})",
                sipr_scenario::EMBEDDED_NAMES.join(", ")
            )),
        };
    }

    // Scenario resolution: -sf beats -sn beats SIPp's default of uac.
    let (scenario_name, is_embedded_uas) = if let Some(path) = &cli.sf {
        if !path.is_file() {
            return fatal(&format!("scenario file not found: {}", path.display()));
        }
        (path.display().to_string(), false)
    } else {
        let name = cli.sn.as_deref().unwrap_or("uac");
        if sipr_scenario::embedded(name).is_none() {
            return fatal(&format!(
                "unknown embedded scenario '{name}' (available: {})",
                sipr_scenario::EMBEDDED_NAMES.join(", ")
            ));
        }
        (name.to_owned(), name == "uas")
    };

    // A UAC needs somewhere to send calls. (For -sf files the direction is
    // unknown until the M1 parser lands, so only embedded scenarios check.)
    if cli.target.is_none() && !is_embedded_uas && cli.sf.is_none() {
        return fatal("remote target required: sipr -sn uac needs a REMOTE_HOST[:PORT] argument");
    }

    eprintln!(
        "sipr {}: scenario '{scenario_name}' accepted — the traffic engine is not \
         implemented yet (M0 scaffold; see docs/MILESTONES.md). Exiting.",
        env!("CARGO_PKG_VERSION"),
    );
    ExitCode::from(EXIT_NO_CALLS)
}

fn fatal(msg: &str) -> ExitCode {
    eprintln!("sipr: error: {msg}");
    ExitCode::from(EXIT_FATAL)
}
