//! SCTP transport (`-t s1` / `-t sn`), behind the `sctp` cargo feature.
//!
//! SIPp (`socket.cpp`, `USE_SCTP`) uses one-to-one `SOCK_STREAM` SCTP
//! sockets and receives with `sctp_recvmsg`: every SCTP message is one whole
//! SIP message, so there is no Content-Length framing as over TCP, and sends
//! wait until the association is up. sipr gets the same from `socket2`
//! (`Socket::new(_, STREAM, IPPROTO_SCTP)`) plus the blocking `connect`,
//! which returns only once the association is established: each `read` on
//! the resulting stream yields one SCTP message, each `write` sends one.
//!
//! What `socket2` cannot reach — `SCTP_EVENTS` notifications, `SCTP_NODELAY`,
//! per-path parameters (`-heartbeat`, `-pathmaxret`, `-pmtu`,
//! `-assocmaxret`), `sctp_bindx` multi-homing (`-multihome`) and the
//! SHUTDOWN/ABORT choice (`-gracefulclose`) — is out of scope; those flags
//! are accepted with a "no effect" warning (docs/SIPP_COMPAT.md §6 M44).
//!
//! The module compiles on every OS; whether the kernel has an SCTP stack is
//! discovered at run time ([`available`]) — macOS and Windows have none.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};

use crate::message::Inbound;
use crate::rng::Rng;
use crate::transport::{InboundPacket, NetEvent, TransportConfig};

/// `IPPROTO_SCTP` (the same number on Linux, the BSDs, and macOS).
const IPPROTO_SCTP: i32 = 132;

/// The largest SCTP message we accept in one read (SIP messages are far
/// smaller; SIPp reads into a 64 KiB buffer too).
const MAX_MESSAGE: usize = 64 * 1024;

/// Whether this host can open an SCTP socket at all.
#[must_use]
pub fn available() -> bool {
    sctp_socket(Domain::IPV4).is_ok()
}

fn sctp_socket(domain: Domain) -> std::io::Result<Socket> {
    Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))
}

fn domain_of(addr: SocketAddr) -> Domain {
    if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    }
}

/// Dial `remote`; blocks until the association is up (SIPp's SCTP_COMM_UP
/// gating). `local` binds a specific source address/port when given.
fn dial(remote: SocketAddr, local: Option<SocketAddr>) -> std::io::Result<TcpStream> {
    let sock = sctp_socket(domain_of(remote))?;
    if let Some(l) = local {
        sock.bind(&l.into())?;
    }
    sock.connect(&remote.into())?;
    Ok(sock.into())
}

/// Live associations keyed by peer address.
type Conns = Arc<Mutex<HashMap<SocketAddr, TcpStream>>>;

/// The `s1` SCTP transport: one association per peer (client dials, server
/// accepts); in `sn` client mode only the pool per-call associations are
/// opened from.
pub struct SctpTransport {
    local_addr: SocketAddr,
    conns: Conns,
    send_rng: Mutex<Rng>,
    send_loss_pct: f64,
    sink: Sender<NetEvent>,
    _accept: Option<std::thread::JoinHandle<()>>,
}

/// A per-call SCTP association (`-t sn`); dropping it shuts it down.
pub struct SctpCallConn {
    stream: TcpStream,
    local_addr: SocketAddr,
}

impl SctpCallConn {
    /// The association's local address (`[local_port]` for this call).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for SctpCallConn {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl SctpTransport {
    /// Client (`UAC`, `s1`): one association to `remote`, opened now. `-p`
    /// binds the local port when given.
    ///
    /// # Errors
    ///
    /// No SCTP stack, or connection failures.
    pub fn connect(
        config: &TransportConfig,
        sink: Sender<NetEvent>,
        remote: SocketAddr,
    ) -> std::io::Result<Self> {
        let local = config.port.map(|p| {
            SocketAddr::new(
                config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                p,
            )
        });
        let stream = dial(remote, local)?;
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let conns: Conns = Arc::new(Mutex::new(HashMap::new()));
        register(&conns, peer, stream, &sink)?;
        Ok(Self {
            local_addr,
            conns,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0031)),
            send_loss_pct: config.send_loss_pct,
            sink,
            _accept: None,
        })
    }

    /// Server (`UAS`): listen and accept associations, reading each.
    ///
    /// # Errors
    ///
    /// No SCTP stack, or bind failures.
    pub fn listen(config: &TransportConfig, sink: Sender<NetEvent>) -> std::io::Result<Self> {
        let ip = config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let bind_at = SocketAddr::new(ip, config.port.unwrap_or(0));
        let listener = sctp_socket(domain_of(bind_at))?;
        listener.bind(&bind_at.into())?;
        listener.listen(128)?;
        let local_addr = listener
            .local_addr()?
            .as_socket()
            .ok_or_else(|| std::io::Error::other("SCTP listener has no inet address"))?;
        let conns: Conns = Arc::new(Mutex::new(HashMap::new()));
        let accept_conns = conns.clone();
        let accept_sink = sink.clone();
        let accept = std::thread::Builder::new()
            .name("sipr-sctp-accept".into())
            .spawn(move || {
                loop {
                    let Ok((sock, _)) = listener.accept() else {
                        continue;
                    };
                    let stream: TcpStream = sock.into();
                    let Ok(peer) = stream.peer_addr() else {
                        continue;
                    };
                    let _ = register(&accept_conns, peer, stream, &accept_sink);
                }
            })
            .ok();
        Ok(Self {
            local_addr,
            conns,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0032)),
            send_loss_pct: config.send_loss_pct,
            sink,
            _accept: accept,
        })
    }

    /// Client in `sn` mode: no association yet — each call dials its own.
    #[must_use]
    pub fn client_pool(config: &TransportConfig, sink: Sender<NetEvent>) -> Self {
        let ip = config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Self {
            local_addr: SocketAddr::new(ip, 0),
            conns: Arc::new(Mutex::new(HashMap::new())),
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0033)),
            send_loss_pct: config.send_loss_pct,
            sink,
            _accept: None,
        }
    }

    /// The bound local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Dial a per-call association (`-t sn`).
    ///
    /// # Errors
    ///
    /// Connection failures (the call fails, not the run).
    pub fn connect_call(&self, remote: SocketAddr) -> std::io::Result<SctpCallConn> {
        let stream = dial(remote, None)?;
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let read_half = stream.try_clone()?;
        let sink = self.sink.clone();
        std::thread::Builder::new()
            .name("sipr-sctp-call".into())
            .spawn(move || read_loop(read_half, peer, &sink))?;
        Ok(SctpCallConn { stream, local_addr })
    }

    /// Re-dial the mono association after it dropped (`-max_reconnect`).
    ///
    /// # Errors
    ///
    /// Connection failures.
    pub fn reconnect(&self, remote: SocketAddr) -> std::io::Result<()> {
        let stream = dial(remote, None)?;
        let peer = stream.peer_addr()?;
        register(&self.conns, peer, stream, &self.sink)
    }

    /// Drop the association to `peer` from the table once the engine has
    /// processed its `Disconnected` event.
    pub fn forget(&self, peer: SocketAddr) {
        if let Ok(mut map) = self.conns.lock() {
            map.remove(&peer);
        }
    }

    /// Send one SIP message as one SCTP message to the association for `to`.
    ///
    /// # Errors
    ///
    /// No association to `to`, or the write failed.
    pub fn send_to(
        &self,
        data: &[u8],
        to: SocketAddr,
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false);
        }
        let mut map = match self.conns.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(stream) = map.get_mut(&to) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("no SCTP association with {to}"),
            ));
        };
        stream.write_all(data)?;
        Ok(true)
    }

    /// Send on a per-call association.
    ///
    /// # Errors
    ///
    /// Write failures.
    pub fn send_via(
        &self,
        conn: &SctpCallConn,
        data: &[u8],
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false);
        }
        let mut out = &conn.stream;
        out.write_all(data)?;
        Ok(true)
    }

    fn simulate_loss(&self, lost_pct: Option<f64>) -> bool {
        let pct = lost_pct.unwrap_or(self.send_loss_pct);
        if pct <= 0.0 {
            return false;
        }
        let mut rng = match self.send_rng.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        rng.chance_pct(pct)
    }
}

fn register(
    conns: &Conns,
    peer: SocketAddr,
    stream: TcpStream,
    sink: &Sender<NetEvent>,
) -> std::io::Result<()> {
    let read_half = stream.try_clone()?;
    if let Ok(mut map) = conns.lock() {
        map.insert(peer, stream);
    }
    let sink = sink.clone();
    std::thread::Builder::new()
        .name("sipr-sctp-recv".into())
        .spawn(move || read_loop(read_half, peer, &sink))
        .ok();
    Ok(())
}

/// One SCTP message per read, each a whole SIP message (SIPp's
/// `sctp_recvmsg` model); the end of the association is reported as with
/// TCP and the engine `forget`s it.
fn read_loop(mut stream: TcpStream, peer: SocketAddr, sink: &Sender<NetEvent>) {
    let local = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let mut buf = vec![0u8; MAX_MESSAGE];
    let clean = loop {
        match stream.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => {
                let raw = buf[..n].to_vec();
                let event = match Inbound::parse(&raw) {
                    Ok(message) => NetEvent::Packet(InboundPacket {
                        message,
                        raw,
                        from: peer,
                        local,
                        received_at: Instant::now(),
                    }),
                    Err(reason) => NetEvent::Garbage { from: peer, reason },
                };
                if sink.send(event).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break false,
        }
    };
    let _ = sink.send(NetEvent::Disconnected { peer, local, clean });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    const MSG: &[u8] =
        b"OPTIONS sip:x SIP/2.0\r\nCall-ID: s-1\r\nCSeq: 9 OPTIONS\r\nContent-Length: 0\r\n\r\n";

    /// Two SIP messages sent back to back arrive as two packets — SCTP keeps
    /// message boundaries where TCP would need Content-Length framing. Skips
    /// where the OS has no SCTP stack.
    #[test]
    fn messages_keep_their_boundaries_and_round_trip() {
        if !available() {
            eprintln!(
                "SKIPPED sctp::messages_keep_their_boundaries_and_round_trip — no SCTP stack"
            );
            return;
        }
        let cfg = TransportConfig {
            local_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..TransportConfig::default()
        };
        let (stx, srx) = mpsc::channel();
        let server = SctpTransport::listen(&cfg, stx).expect("listen");
        let (ctx, crx) = mpsc::channel();
        let client = SctpTransport::connect(&cfg, ctx, server.local_addr()).expect("connect");
        assert!(
            client
                .send_to(MSG, server.local_addr(), None)
                .expect("send 1")
        );
        assert!(
            client
                .send_to(MSG, server.local_addr(), None)
                .expect("send 2")
        );
        let mut from = None;
        for _ in 0..2 {
            match srx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
                NetEvent::Packet(p) => {
                    assert_eq!(p.raw, MSG, "one SCTP message = one SIP message");
                    from = Some(p.from);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let from = from.expect("peer");
        assert!(server.send_to(MSG, from, None).expect("reply"));
        assert!(matches!(
            crx.recv_timeout(Duration::from_secs(2)).expect("delivered"),
            NetEvent::Packet(_)
        ));
        // Per-call associations are distinct peers and close on drop.
        let pool = SctpTransport::client_pool(&cfg, mpsc::channel().0);
        let a = pool.connect_call(server.local_addr()).expect("dial a");
        assert!(pool.send_via(&a, MSG, None).expect("send via a"));
        match srx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
            NetEvent::Packet(p) => assert_eq!(p.from, a.local_addr()),
            other => panic!("unexpected {other:?}"),
        }
        let a_addr = a.local_addr();
        drop(a);
        loop {
            match srx
                .recv_timeout(Duration::from_secs(2))
                .expect("disconnect reported")
            {
                NetEvent::Disconnected { peer, .. } if peer == a_addr => break,
                _ => {}
            }
        }
    }

    /// Without an SCTP stack, opening a socket fails cleanly (the engine turns
    /// this into "SCTP is not supported on this host").
    #[test]
    fn unavailable_stack_is_a_clean_error() {
        if available() {
            return;
        }
        let cfg = TransportConfig::default();
        assert!(SctpTransport::listen(&cfg, mpsc::channel().0).is_err());
    }
}
