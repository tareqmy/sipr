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

/// Transport mode (`-t`). Only UDP mono-socket until the TCP/TLS milestones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// `u1`: UDP with one socket shared by all calls (SIPp's default).
    UdpMono,
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
    /// `-t`: transport mode.
    pub transport: Transport,
    /// `-s`: service / called user part, substituted for `[service]`.
    pub service: String,
    /// `-au`: username for `[authentication]`.
    pub auth_user: Option<String>,
    /// `-ap`: password for `[authentication]`.
    pub auth_password: Option<String>,
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
            transport: Transport::UdpMono,
            service: "service".to_owned(),
            auth_user: None,
            auth_password: None,
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
        "t",
        true,
        "MODE",
        "Transport mode; only 'u1' (UDP) in v1 [default: u1]",
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
        "t" => cli.transport = parse_transport(&val(value))?,
        "s" => cli.service = val(value),
        "au" => cli.auth_user = Some(val(value)),
        "ap" => cli.auth_password = Some(val(value)),
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
        other => return Err(format!("internal error: unhandled flag '-{other}'")),
    }
    Ok(())
}

fn parse_num<T: std::str::FromStr>(flag: &str, raw: &str) -> Result<T, String> {
    raw.parse()
        .map_err(|_| format!("invalid value '{raw}' for option '-{flag}'"))
}

fn parse_transport(s: &str) -> Result<Transport, String> {
    match s {
        "u1" => Ok(Transport::UdpMono),
        "un" | "ui" | "t1" | "tn" | "l1" | "ln" => Err(format!(
            "transport mode '{s}' is not implemented yet — only 'u1' (UDP \
             mono-socket) is supported in v1; TCP/TLS come post-v1"
        )),
        other => Err(format!("unknown transport mode '{other}' (expected 'u1')")),
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
    fn unimplemented_transport_rejected_helpfully() {
        let err = run(&["-t", "t1"]).unwrap_err();
        assert!(err.contains("not implemented yet"), "{err}");
        let err = run(&["-t", "x9"]).unwrap_err();
        assert!(err.contains("unknown transport mode"), "{err}");
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
