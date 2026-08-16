//! `sipr-tui`: the live terminal dashboard (milestone M5).
//!
//! Hand-rolled on ANSI escapes + `stty` because ratatui/crossterm are
//! unreachable from the build environment (recorded in docs/MILESTONES.md
//! M5) — and SIPp's screens are simple tables, well within plain-ANSI
//! territory. Split cleanly: [`render`] is pure (`Snapshot` → lines,
//! unit-tested), [`terminal`] is the thin interactive shell (raw mode,
//! alternate screen, `/dev/tty` keys) with restore-on-drop plus a panic
//! hook so no exit path wrecks the shell.

pub mod render;
pub mod terminal;

pub use render::{Screen, render as render_screen};
pub use terminal::run;
