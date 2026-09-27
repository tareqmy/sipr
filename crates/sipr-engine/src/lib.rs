//! `sipr-engine`: the traffic engine — per-call state machines, the pacer,
//! and dialog bookkeeping, driven by one event-loop thread (M3: UAC mode).
//!
//! Entry point: [`Run::start`] with a compiled
//! [`sipr_scenario::model::Scenario`] and an [`EngineConfig`] — the run
//! gets its own thread, an [`EngineControl`] to drive it, a stream of
//! statistics snapshots, and [`Run::wait`] for the [`RunReport`]. [`run`]
//! is the blocking shorthand.

// The engine never prints: everything it has to say is a `Notice` and goes
// where `EngineConfig::notices` points (D3 of docs/LIBRARY_API.md).
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
    Behaviors, EngineConfig, EngineControl, EngineError, Extended3pcc, LogOverwrite, Run,
    RunReport, SecondaryKind, TransportKind, UiChannels, run, run_scenarios, run_with_control,
    run_with_ui,
};
// Re-exported so the binary can build a TLS config without depending on
// sipr-net directly.
// `RunInfo` and `DynamicId` are fields of the public `RenderCtx`, so they
// have to be nameable for anyone outside the crate to build one.
pub use render::{DynamicId, FieldSource, RenderCtx, RenderError, RunInfo, VarCtx, render};
pub use sipr_net::{PeerTable, SocketOpts, TlsConfig, TlsVersion};
