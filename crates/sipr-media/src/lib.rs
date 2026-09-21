//! `sipr-media`: pcap replay and RTP media (milestone M14).
//!
//! Three pieces, all std-only:
//!
//! - [`pcap`] — a pure-Rust reader for capture files, classic pcap and
//!   (via [`pcapng`]) the pcapng format `tcpdump` writes by default, that
//!   extracts the UDP payloads and their relative timing. No libpcap: sipr
//!   only ever *reads* capture files, never captures live traffic.
//! - [`sdp`] — the minimal SDP scan that learns where the peer wants media
//!   (`c=` + `m=<kind> <port>`), the same crude scan SIPp does.
//! - [`replay`] — the media thread: one scheduler for every active stream,
//!   sending each stream's frames on the capture's absolute timeline.
//! - [`rtp`] — generated RTP streams from raw codec files or test patterns
//!   (`exec rtp_stream=`), and [`dtmf`] — RFC 4733 event bursts
//!   (`exec play_dtmf=`), both scheduled by the same thread.
//!
//! Behavioral oracle: SIPp's `prepare_pcap.c` / `send_packets.c`
//! (`exec play_pcap_*`). Deliberate divergences are recorded in
//! `docs/SIPP_COMPAT.md` §6 — chiefly that sipr sends through ordinary UDP
//! sockets bound to the media port (no raw socket, so no root needed).

pub mod dtmf;
pub mod echo;
pub mod pcap;
pub mod pcapng;
pub mod replay;
pub mod rtp;
pub mod sdp;
pub mod srtp;
pub mod srtp_echo;

pub use echo::EchoServer;
pub use pcap::{Frame, PcapError, PcapStream};
pub use replay::{MediaEvent, MediaPlayer, Source, StreamSpec};
pub use rtp::{RtpParams, RtpSource};
pub use srtp::{MasterKey, SrtpContext, Suite};
pub use srtp_echo::EchoStream;
