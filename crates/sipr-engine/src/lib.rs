//! `sipr-engine`: the traffic engine — per-call state machines, the pacer,
//! and dialog bookkeeping, driven by one event-loop thread (M3: UAC mode).
//!
//! Entry point: [`run`] with a compiled [`sipr_scenario::model::Scenario`]
//! and an [`EngineConfig`]. The engine pre-validates that the scenario only
//! uses M3-supported features and refuses loudly otherwise (actions,
//! variables, and auth execute at M6; UAS mode lands at M4).

mod engine;
mod render;

pub use engine::{EngineConfig, EngineControl, EngineError, RunReport, run, run_with_control};
pub use render::{RenderCtx, RenderError, render};
