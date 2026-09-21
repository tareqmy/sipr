//! `sipr-engine`: the traffic engine — per-call state machines, the pacer,
//! and dialog bookkeeping, driven by one event-loop thread (M3: UAC mode).
//!
//! Entry point: [`run`] with a compiled [`sipr_scenario::model::Scenario`]
//! and an [`EngineConfig`]. The engine pre-validates that the scenario only
//! uses M3-supported features and refuses loudly otherwise (actions,
//! variables, and auth execute at M6; UAS mode lands at M4).

mod actions;
mod engine;
mod exec;
mod render;
mod sample;
mod tdm;
pub use tdm::TdmMap;
mod vars;

pub use engine::{
    Behaviors, EngineConfig, EngineControl, EngineError, Extended3pcc, LogOverwrite, RunReport,
    SecondaryKind, TransportKind, UiChannels, run, run_scenarios, run_with_control, run_with_ui,
};
// Re-exported so the binary can build a TLS config without depending on
// sipr-net directly.
pub use render::{FieldSource, RenderCtx, RenderError, VarCtx, render};
pub use sipr_net::{PeerTable, TlsConfig, TlsVersion};
