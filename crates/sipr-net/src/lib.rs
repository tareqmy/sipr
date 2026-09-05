//! `sipr-net`: UDP transport, inbound message parsing, timers, and the
//! retransmission schedule (milestone M2).
//!
//! Std-first by decision (docs/MILESTONES.md M2 note): the runtime model is
//! dedicated threads — recv loops and a timer thread — all funneling
//! events into the engine's single `mpsc` channel. That is SIPp's own
//! one-event-loop architecture with threads instead of `poll()`; if the
//! workspace later gains tokio, only the thin drivers here change, not the
//! pure logic ([`timer::TimerQueue`], [`retrans::RetransSchedule`],
//! [`message::Inbound`]). The lone external dependency is `rustls` for the
//! TLS transport (M13) — SIP itself is still served by std sockets.
//!
//! This crate knows how to move bytes, fire timers, and extract routing
//! fields. It does NOT know what an INVITE means — scenario semantics live
//! in `sipr-engine` (docs/ARCHITECTURE.md §6).

pub mod message;
pub mod retrans;
pub mod rng;
#[cfg(feature = "sctp")]
pub mod sctp;
pub mod table;
pub mod tcp;
pub mod timer;
pub mod tls;
pub mod transport;
pub mod twin;

pub use message::{Inbound, MsgKind, ParseError};
pub use retrans::RetransSchedule;
#[cfg(feature = "sctp")]
pub use sctp::{SctpCallConn, SctpTransport};
pub use table::CallTable;
pub use tcp::{TcpCallConn, TcpFramer, TcpTransport};
pub use timer::{TimerQueue, TimerService};
pub use tls::{TlsCallConn, TlsConfig, TlsTransport, TlsVersion};
pub use transport::{InboundPacket, NetEvent, TransportConfig, UdpCallSocket, UdpTransport};
pub use twin::{EscFramer, TwinChannel};
