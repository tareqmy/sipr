//! `sipr-engine`: the traffic engine — per-call state machines, the pacer,
//! transports and dialog bookkeeping, one event-loop thread per run — as a
//! library. The `sipr` binary is one embedder; a Rust test harness is
//! another: scenario in, statistics out, no CLI, no TUI.
//!
//! # Use
//!
//! 1. Compile a SIPp XML scenario with [`sipr_scenario::compile_strict`]
//!    (any diagnostic is an error) or [`sipr_scenario::compile_with`] (you
//!    read the diagnostics).
//! 2. Start from [`EngineConfig::uac`] or [`EngineConfig::uas`] — SIPp's
//!    defaults — and assign the fields you want otherwise. Every field
//!    names the SIPp flag it stands for.
//! 3. [`Run::start`] runs it on its own thread and returns once its
//!    sockets are bound; [`Run::control`] drives it, [`Run::snapshots`]
//!    reports it once a second, [`Run::wait`] ends with the [`RunReport`].
//!    [`run`] is the blocking shorthand.
//!
//! ```no_run
//! use sipr_engine::{EngineConfig, Run};
//! use sipr_scenario::{CompileOptions, compile_strict};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let xml = sipr_scenario::embedded("uas").ok_or("no uas")?;
//! let uas = compile_strict("uas", xml, &CompileOptions::default())
//!     .map_err(|diagnostics| format!("{diagnostics:?}"))?;
//! let mut cfg = EngineConfig::uas();
//! cfg.port = Some(0);
//! let server = Run::start(uas, cfg)?;
//! let listening_on = server.local_addr();
//! // ... exercise the system under test against `listening_on` ...
//! server.control().stop();
//! let report = server.wait()?;
//! assert_eq!(report.exit_code(), 0, "{}", report.summary());
//! # Ok(())
//! # }
//! ```
//!
//! `examples/embed.rs` is the complete version: a UAS and a UAC in one
//! process, notices read as values.
//!
//! # The supported surface
//!
//! What `docs/LIBRARY_API.md` promises — additive within a `0.x` minor
//! series, with `CHANGELOG.md` saying what a minor bump changed:
//!
//! - [`EngineConfig`] and the types its fields use: [`TransportKind`],
//!   [`Behaviors`], [`LogOverwrite`], [`Extended3pcc`] with [`PeerTable`],
//!   [`InjectionSource`], [`NoticeSink`] and [`Notice`], [`TdmMap`],
//!   [`SocketOpts`], [`TlsConfig`] and [`TlsVersion`], and
//!   `sipr_stats::LogRotation`.
//! - [`Run`], [`EngineControl`], [`RunReport`], [`SecondaryKind`], [`run`].
//! - [`EngineError`].
//! - `sipr_stats::Snapshot` and its rows, what [`Run::snapshots`] delivers.
//!
//! Everything else that is `pub` is there for the binary, the bench or an
//! earlier caller, is hidden from this documentation, and may change in any
//! release.
//!
//! # Threads and ports
//!
//! A run owns its threads — the engine loop, the transport's receive or
//! accept loop, the control listeners, the media and exec helpers — and they
//! end when the run does: [`Run::wait`] returns, or the `Run` is dropped.
//! The ports go with them, so the next run may bind the same port. Call
//! numbers (`[call_number]`, the default Call-ID) come from one counter per
//! process, so two runs in one process never reuse a Call-ID.

// The engine never prints: everything it has to say is a `Notice` and goes
// where `EngineConfig::notices` points (docs/LIBRARY_API.md).
#![deny(clippy::print_stderr, clippy::print_stdout)]

mod actions;
mod engine;
mod exec;
mod notice;
pub use notice::{Notice, NoticeSink};
mod render;
mod sample;
mod tdm;
pub use tdm::TdmMap;
mod vars;

pub use engine::{
    Behaviors, EngineConfig, EngineControl, EngineError, Extended3pcc, InjectionSource,
    LogOverwrite, Run, RunReport, SecondaryKind, TransportKind, run,
};
pub use sipr_net::{PeerTable, SocketOpts, TlsConfig, TlsVersion};

// The blocking entry points `Run` superseded, kept for one minor release.
#[doc(hidden)]
pub use engine::{UiChannels, run_scenarios, run_with_control, run_with_ui};
// The message renderer, `pub` for `benches/hot_path.rs` alone: not part of
// the supported surface, free to change.
#[doc(hidden)]
pub use render::{DynamicId, FieldSource, RenderCtx, RenderError, RunInfo, VarCtx, render};
