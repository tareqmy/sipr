//! `sipr-net`: UDP transport, inbound message parsing, timers, and the
//! retransmission schedule (milestone M2).
//!
//! Std-only by decision (docs/MILESTONES.md M2 note): the runtime model is
//! dedicated threads — a UDP recv loop and a timer thread — all funneling
//! events into the engine's single `mpsc` channel. That is SIPp's own
//! one-event-loop architecture with threads instead of `poll()`; if the
//! workspace later gains tokio, only the thin drivers here change, not the
//! pure logic ([`timer::TimerQueue`], [`retrans::RetransSchedule`],
//! [`message::Inbound`]).
//!
//! This crate knows how to move bytes, fire timers, and extract routing
//! fields. It does NOT know what an INVITE means — scenario semantics live
//! in `sipr-engine` (docs/ARCHITECTURE.md §6).

pub mod message;
pub mod retrans;
pub mod rng;
pub mod table;
pub mod tcp;
pub mod timer;
pub mod transport;

pub use message::{Inbound, MsgKind, ParseError};
pub use retrans::RetransSchedule;
pub use table::CallTable;
pub use tcp::{TcpFramer, TcpTransport};
pub use timer::{TimerQueue, TimerService};
pub use transport::{InboundPacket, NetEvent, TransportConfig, UdpTransport};
