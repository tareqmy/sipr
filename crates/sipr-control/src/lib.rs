//! `sipr-control`: runtime control of a running sipr (milestone M17).
//!
//! Two front ends feed one command set into the engine's event loop:
//!
//! - [`udp`] — SIPp's control socket (`-cp`/`-ci`, `socket.cpp`
//!   `handle_ctrl_socket`): one datagram is one command, byte 0 is a hot
//!   key unless it is `c`, in which case the rest is a `set` / `trace` /
//!   `dump` / `reset` command line. Fire-and-forget, exactly like SIPp.
//! - [`http`] — sipr's HTTP/JSON API (`--sipr-http`), which SIPp lacks:
//!   the same commands with answers, plus the live statistics snapshot.
//!
//! The engine owns everything; this crate only parses input into
//! [`ControlCmd`], ships it over a channel as a [`ControlRequest`], and
//! renders what comes back. The HTTP server reads stats from the same
//! once-a-second [`Snapshot`] the TUI gets — it never touches the engine.

pub mod api;
pub mod command;
pub mod http;
pub mod json;
pub mod prometheus;
pub mod udp;

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

pub use command::{ControlCmd, parse_command, parse_datagram};
use sipr_stats::Snapshot;

/// Where a run currently stands with respect to quitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quitting {
    /// Running normally.
    No,
    /// Not placing new calls; draining (`q`).
    Soft,
    /// Aborting (`Q`, or a second `q`).
    Hard,
}

impl Quitting {
    /// JSON token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Soft => "soft",
            Self::Hard => "hard",
        }
    }
}

/// The controllable state, as the engine reports it after a command.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlState {
    /// Calls per rate period (rate mode).
    pub rate: f64,
    /// Multiplier applied by the `+ - * /` keys.
    pub rate_scale: f64,
    /// Traffic paused (`p`).
    pub paused: bool,
    /// `-users` target, when in users mode.
    pub users: Option<u64>,
    /// `-l` concurrent-call cap, when set.
    pub limit: Option<u64>,
    /// Quit state.
    pub quitting: Quitting,
}

/// A command for the engine, with an optional reply channel (HTTP waits
/// for the answer; the UDP socket, like SIPp, never does).
pub struct ControlRequest {
    /// What to do.
    pub cmd: ControlCmd,
    /// Where to send the outcome: the new state, or SIPp's warning text.
    pub reply: Option<Sender<Result<ControlState, String>>>,
}

/// What the HTTP API needs from the engine: a request channel, the latest
/// snapshot, and static scenario facts.
#[derive(Clone)]
pub struct ControlLink {
    /// Requests into the engine loop.
    pub requests: Sender<ControlRequest>,
    /// The latest statistics snapshot (updated about once a second).
    pub snapshot: Arc<Mutex<Snapshot>>,
    /// Scenario name.
    pub scenario_name: String,
    /// `UAC` / `UAS`.
    pub role: &'static str,
    /// The compiled IR dump, one line per step.
    pub steps: Vec<String>,
    /// sipr version string.
    pub version: &'static str,
}
