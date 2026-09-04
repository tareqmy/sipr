//! The control command set and SIPp's command-line grammar for it
//! (`socket.cpp` `process_command` / `process_set` / `process_trace` /
//! `process_dump` / `process_reset`). Error strings are SIPp's own
//! warnings, so scripts grepping SIPp's error log keep working.

/// Everything the engine can be told at runtime.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlCmd {
    /// A hot key (`+ - * / p q Q`, screen digits are ignored by the engine).
    Key(char),
    /// `set rate N` (rate mode only).
    SetRate(f64),
    /// `set rate-scale N`: the step multiplier for the rate keys.
    SetRateScale(f64),
    /// `set users N` (users mode only).
    SetUsers(u64),
    /// `set limit N` (rate mode only).
    SetLimit(u64),
    /// `set display main|ooc|rx` — a TUI matter; accepted for `main`.
    SetDisplay(String),
    /// `set hide true|false` — a TUI matter; accepted and remembered.
    SetHide(bool),
    /// `trace error|messages|logs|shortmessages on|off`.
    Trace {
        /// Which log.
        log: String,
        /// On or off.
        on: bool,
    },
    /// `dump tasks|variables`.
    Dump(String),
    /// `reset stats`.
    ResetStats,
    /// HTTP only: pause or resume traffic explicitly.
    SetPaused(bool),
    /// HTTP only: quit — drain (`false`) or abort (`true`).
    Quit {
        /// Abort instead of draining.
        force: bool,
    },
    /// HTTP only: report the current state, change nothing.
    Query,
}

/// One datagram on the control socket, as SIPp reads it: byte 0 decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    /// A hot key: the first byte; everything after it is discarded.
    Key(char),
    /// `c` + a command line (the rest of the datagram, trimmed).
    Command(String),
}

/// Classify a control-socket datagram. Empty datagrams yield `None`.
#[must_use]
pub fn parse_datagram(bytes: &[u8]) -> Option<Datagram> {
    let first = *bytes.first()?;
    if first == b'c' {
        let rest = String::from_utf8_lossy(&bytes[1..]).trim().to_owned();
        Some(Datagram::Command(rest))
    } else {
        Some(Datagram::Key(char::from(first)))
    }
}

/// Parse a command line (`set rate 10`, `trace messages on`, ...).
///
/// # Errors
///
/// SIPp's warning text for the malformed or unknown command.
pub fn parse_command(line: &str) -> Result<ControlCmd, String> {
    let line = line.trim();
    // SIPp splits on the first ASCII space only (tabs do not separate).
    let Some((verb, rest)) = line.split_once(' ') else {
        return Err(format!("The {line} command requires at least one argument"));
    };
    let rest = rest.trim();
    match verb {
        "set" => parse_set(rest),
        "trace" => parse_trace(rest),
        "dump" => match rest {
            "tasks" | "variables" => Ok(ControlCmd::Dump(rest.to_owned())),
            other => Err(format!("Unknown dump type: {other}")),
        },
        "reset" => match rest {
            "stats" => Ok(ControlCmd::ResetStats),
            other => Err(format!("Unknown reset type: {other}")),
        },
        other => Err(format!("Unrecognized command: \"{other}\"")),
    }
}

fn parse_set(rest: &str) -> Result<ControlCmd, String> {
    let Some((attr, value)) = rest.split_once(' ') else {
        return Err("The set command requires two arguments (attribute and value)".into());
    };
    let value = value.trim();
    match attr {
        "rate" => value
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .map(ControlCmd::SetRate)
            .ok_or_else(|| format!("Invalid rate value: {value}")),
        "rate-scale" => value
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .map(ControlCmd::SetRateScale)
            .ok_or_else(|| format!("Invalid rate-scale value: {value}")),
        "users" => parse_int(value)
            .map(ControlCmd::SetUsers)
            .ok_or_else(|| format!("Invalid users value: {value}")),
        "limit" => parse_int(value)
            .map(ControlCmd::SetLimit)
            .ok_or_else(|| format!("Invalid limit value: {value}")),
        "display" => match value {
            "main" | "ooc" | "rx" => Ok(ControlCmd::SetDisplay(value.to_owned())),
            other => Err(format!("Unknown display scenario: {other}")),
        },
        "hide" => match value {
            "true" => Ok(ControlCmd::SetHide(true)),
            "false" => Ok(ControlCmd::SetHide(false)),
            other => Err(format!("Invalid bool: {other}")),
        },
        other => Err(format!("Unknown set attribute: {other}")),
    }
}

fn parse_trace(rest: &str) -> Result<ControlCmd, String> {
    let Some((log, value)) = rest.split_once(' ') else {
        return Err("The trace command requires two arguments (log and [on|off])".into());
    };
    let on = match value.trim() {
        "on" | "true" => true,
        "off" | "false" => false,
        _ => return Err("The trace command's second argument must be on or off.".into()),
    };
    match log {
        "error" | "logs" | "messages" | "shortmessages" => Ok(ControlCmd::Trace {
            log: log.to_owned(),
            on,
        }),
        other => Err(format!("Unknown log file: {other}")),
    }
}

/// SIPp uses `strtol(..., 0)`: decimal, `0x` hex, or leading-zero octal.
fn parse_int(value: &str) -> Option<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    if value.len() > 1 && value.starts_with('0') {
        return u64::from_str_radix(&value[1..], 8).ok();
    }
    value.parse().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn datagrams_split_on_byte_zero() {
        assert_eq!(parse_datagram(b"p\n"), Some(Datagram::Key('p')));
        assert_eq!(parse_datagram(b"pq"), Some(Datagram::Key('p')));
        assert_eq!(
            parse_datagram(b"cset rate 10\n"),
            Some(Datagram::Command("set rate 10".into()))
        );
        assert_eq!(parse_datagram(b"c"), Some(Datagram::Command(String::new())));
        assert_eq!(parse_datagram(b""), None);
    }

    #[test]
    fn set_commands_follow_sipp() {
        assert_eq!(
            parse_command("set rate 12.5"),
            Ok(ControlCmd::SetRate(12.5))
        );
        assert_eq!(
            parse_command("set rate-scale 2"),
            Ok(ControlCmd::SetRateScale(2.0))
        );
        assert_eq!(
            parse_command("set users 0x10"),
            Ok(ControlCmd::SetUsers(16))
        );
        assert_eq!(parse_command("set users 010"), Ok(ControlCmd::SetUsers(8)));
        assert_eq!(parse_command("set limit 50"), Ok(ControlCmd::SetLimit(50)));
        assert_eq!(
            parse_command("set hide false"),
            Ok(ControlCmd::SetHide(false))
        );
        assert_eq!(
            parse_command("set display main"),
            Ok(ControlCmd::SetDisplay("main".into()))
        );
        assert_eq!(
            parse_command("set rate 10x"),
            Err("Invalid rate value: 10x".into())
        );
        assert_eq!(
            parse_command("set users -1"),
            Err("Invalid users value: -1".into())
        );
        assert_eq!(parse_command("set hide on"), Err("Invalid bool: on".into()));
        assert_eq!(
            parse_command("set bogus 1"),
            Err("Unknown set attribute: bogus".into())
        );
        assert_eq!(
            parse_command("set rate"),
            Err("The set command requires two arguments (attribute and value)".into())
        );
    }

    #[test]
    fn trace_dump_reset_and_errors() {
        assert_eq!(
            parse_command("trace messages on"),
            Ok(ControlCmd::Trace {
                log: "messages".into(),
                on: true
            })
        );
        assert_eq!(
            parse_command("trace error false"),
            Ok(ControlCmd::Trace {
                log: "error".into(),
                on: false
            })
        );
        assert_eq!(
            parse_command("trace messages maybe"),
            Err("The trace command's second argument must be on or off.".into())
        );
        assert_eq!(
            parse_command("trace x on"),
            Err("Unknown log file: x".into())
        );
        assert_eq!(
            parse_command("dump tasks"),
            Ok(ControlCmd::Dump("tasks".into()))
        );
        assert_eq!(
            parse_command("dump calls"),
            Err("Unknown dump type: calls".into())
        );
        assert_eq!(parse_command("reset stats"), Ok(ControlCmd::ResetStats));
        assert_eq!(
            parse_command("frobnicate now"),
            Err("Unrecognized command: \"frobnicate\"".into())
        );
        assert_eq!(
            parse_command("set"),
            Err("The set command requires at least one argument".into())
        );
        // Tabs are not separators, as in SIPp.
        assert!(parse_command("set\trate\t10").is_err());
    }
}
