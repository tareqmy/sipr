//! UDP transport: the socket, its recv loop, and simulated packet loss.
//!
//! `u1` mode (SIPp's default): one socket shared by every call. A dedicated
//! recv thread parses each datagram just enough to route — Call-ID extraction
//! via [`crate::message::Inbound`] — and forwards it into the engine's single
//! event channel. Simulated loss (`lost` attributes, deterministic seeded
//! RNG) applies on both paths *before* any real I/O or delivery, exactly as
//! if the network dropped the packet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::message::{Inbound, ParseError};
use crate::rng::Rng;

/// Maximum UDP datagram we accept (RFC 3261 suggests messages fit well
/// under the 65k UDP ceiling; jumbo inbound is truncated at this size).
pub const MAX_DATAGRAM: usize = 65_535;

/// An inbound datagram, parsed and routed by the recv loop.
#[derive(Debug)]
pub struct InboundPacket {
    /// The parsed message (start line + lazy header access).
    pub message: Inbound,
    /// The datagram exactly as received (for `-trace_msg`).
    pub raw: Vec<u8>,
    /// Sender address.
    pub from: SocketAddr,
    /// The local address it arrived on (`[server_ip]`, `-t ui` routing).
    pub local: SocketAddr,
    /// Arrival timestamp.
    pub received_at: Instant,
}

/// Events the transport delivers into the engine's channel.
#[derive(Debug)]
pub enum NetEvent {
    /// A parsed SIP message arrived.
    Packet(InboundPacket),
    /// A datagram arrived but was not a SIP message (counted, not fatal).
    Garbage {
        /// Sender address.
        from: SocketAddr,
        /// Why parsing rejected it.
        reason: ParseError,
    },
    /// The socket died; the recv loop has exited.
    SocketError(std::io::ErrorKind),
    /// A TCP/TLS connection ended: `clean` when the peer closed it in an
    /// orderly way (FIN / close_notify), false on a reset or read error.
    /// `local` identifies a per-call connection.
    Disconnected {
        /// The remote end.
        peer: SocketAddr,
        /// Our end.
        local: SocketAddr,
        /// Orderly close, as opposed to an error.
        clean: bool,
    },
}

/// Configuration for binding the transport.
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    /// Local IP (`-i`); defaults to 0.0.0.0.
    pub local_ip: Option<IpAddr>,
    /// Local port (`-p`); defaults to a system-chosen free port.
    pub port: Option<u16>,
    /// Simulated outbound loss percentage (per-send `lost` overrides at M3).
    pub send_loss_pct: f64,
    /// Simulated inbound loss percentage.
    pub recv_loss_pct: f64,
    /// RNG seed for reproducible loss patterns (0 → fixed default seed).
    pub loss_seed: u64,
}

/// The `u1` UDP transport (also the main socket of `un`).
pub struct UdpTransport {
    socket: UdpSocket,
    local_addr: SocketAddr,
    send_rng: Mutex<Rng>,
    send_loss_pct: f64,
    recv_loss_pct: f64,
    loss_seed: u64,
    sink: Sender<NetEvent>,
    recv_thread: Option<std::thread::JoinHandle<()>>,
}

/// A per-call UDP socket (`-t un`, SIPp's `new_sipp_call_socket`): bound to
/// the local IP on a system-chosen port, with its own recv loop delivering
/// into the transport's sink. Dropping it closes the socket.
pub struct UdpCallSocket {
    socket: UdpSocket,
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl UdpCallSocket {
    /// The bound local address (`[local_port]` for this call).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for UdpCallSocket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(thread) = self.thread.take() else {
            return;
        };
        // Wake the blocking recv with an empty datagram, then reap it.
        let any: IpAddr = match self.local_addr.ip() {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        if let Ok(waker) = UdpSocket::bind(SocketAddr::new(any, 0)) {
            let _ = waker.send_to(&[], self.local_addr);
        }
        let _ = thread.join();
    }
}

/// One socket's receive loop: parse, route, deliver until the sink is gone,
/// the socket dies, or `stop` is raised (per-call sockets).
fn recv_loop(
    socket: &UdpSocket,
    sink: &Sender<NetEvent>,
    recv_loss_pct: f64,
    mut recv_rng: Rng,
    stop: Option<&AtomicBool>,
) {
    let local = socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
                    return;
                }
                if n == 0 {
                    continue; // a wake-up, or noise
                }
                if recv_loss_pct > 0.0 && recv_rng.chance_pct(recv_loss_pct) {
                    continue; // simulated inbound loss
                }
                let event = match Inbound::parse(&buf[..n]) {
                    Ok(message) => NetEvent::Packet(InboundPacket {
                        message,
                        raw: buf[..n].to_vec(),
                        from,
                        local,
                        received_at: Instant::now(),
                    }),
                    Err(reason) => NetEvent::Garbage { from, reason },
                };
                if sink.send(event).is_err() {
                    return; // engine gone
                }
            }
            Err(e) if is_transient_recv_error(&e) => continue,
            Err(e) => {
                if stop.is_none() {
                    let _ = sink.send(NetEvent::SocketError(e.kind()));
                }
                return;
            }
        }
    }
}

/// Errors a UDP receive loop must ride out rather than die on. Windows
/// reports an ICMP port-unreachable for an earlier `send_to` as a
/// `ConnectionReset` on the *unconnected* socket (the `WSAECONNRESET`
/// quirk); Linux never surfaces it, and a peer being down is exactly what a
/// test tool is expected to keep running through. `Interrupted` is a
/// signal, not a dead socket.
fn is_transient_recv_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::Interrupted
    )
}

impl UdpTransport {
    /// Bind the socket and start the recv loop, delivering into `sink`.
    ///
    /// # Errors
    ///
    /// I/O errors from binding or inspecting the socket.
    pub fn bind(config: &TransportConfig, sink: Sender<NetEvent>) -> std::io::Result<Self> {
        let ip = config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let socket = UdpSocket::bind(SocketAddr::new(ip, config.port.unwrap_or(0)))?;
        let local_addr = socket.local_addr()?;
        let recv_socket = socket.try_clone()?;
        let recv_loss_pct = config.recv_loss_pct;
        let recv_rng = Rng::new(config.loss_seed ^ 0x5EED_0002);
        let recv_sink = sink.clone();
        let recv_thread = std::thread::Builder::new()
            .name("sipr-udp-recv".into())
            .spawn(move || recv_loop(&recv_socket, &recv_sink, recv_loss_pct, recv_rng, None))
            .ok();
        Ok(Self {
            socket,
            local_addr,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0001)),
            send_loss_pct: config.send_loss_pct,
            recv_loss_pct: config.recv_loss_pct,
            loss_seed: config.loss_seed,
            sink,
            recv_thread,
        })
    }

    /// Open a per-call socket (`-t un`) on the same local IP, system-chosen
    /// port, delivering into this transport's sink.
    ///
    /// # Errors
    ///
    /// Bind or thread-spawn failures.
    pub fn open_call_socket(&self) -> std::io::Result<UdpCallSocket> {
        self.open_call_socket_at(SocketAddr::new(self.local_addr.ip(), 0))
    }

    /// Open a call socket bound to exactly `at` (`-t ui`: one socket per
    /// injected IP, all on the main socket's port).
    ///
    /// # Errors
    ///
    /// Bind or thread-spawn failures (an IP that is not local, a port in
    /// use).
    pub fn open_call_socket_at(&self, at: SocketAddr) -> std::io::Result<UdpCallSocket> {
        let socket = UdpSocket::bind(at)?;
        let local_addr = socket.local_addr()?;
        let recv_socket = socket.try_clone()?;
        let sink = self.sink.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let recv_loss_pct = self.recv_loss_pct;
        let recv_rng = Rng::new(self.loss_seed ^ u64::from(local_addr.port()) ^ 0x5EED_0003);
        let thread = std::thread::Builder::new()
            .name("sipr-udp-call".into())
            .spawn(move || {
                recv_loop(
                    &recv_socket,
                    &sink,
                    recv_loss_pct,
                    recv_rng,
                    Some(&stop_flag),
                );
            })?;
        Ok(UdpCallSocket {
            socket,
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    /// Send `data` to `to` from a per-call socket, honoring simulated loss
    /// like [`Self::send_to`].
    ///
    /// # Errors
    ///
    /// Real socket errors.
    pub fn send_via(
        &self,
        socket: &UdpCallSocket,
        data: &[u8],
        to: SocketAddr,
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false);
        }
        socket.socket.send_to(data, to)?;
        Ok(true)
    }

    /// Roll the simulated-loss dice for one send.
    fn simulate_loss(&self, lost_pct: Option<f64>) -> bool {
        let pct = lost_pct.unwrap_or(self.send_loss_pct);
        if pct <= 0.0 {
            return false;
        }
        let mut rng = match self.send_rng.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        rng.chance_pct(pct)
    }

    /// The bound local address (real port when `-p` was omitted).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send `data` to `to`, honoring simulated loss.
    ///
    /// Returns `true` if the datagram actually left (false = simulated drop).
    /// A per-send `lost` percentage overrides the transport-wide default.
    ///
    /// # Errors
    ///
    /// Real socket errors. Simulated drops are `Ok(false)`, not errors.
    pub fn send_to(
        &self,
        data: &[u8],
        to: SocketAddr,
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false);
        }
        self.socket.send_to(data, to)?;
        Ok(true)
    }
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        // Unblock the recv thread by shutting the socket down via a
        // self-addressed empty-ish datagram is unreliable; instead we rely on
        // process teardown in the binary. In tests, dropping the receiver
        // makes the loop exit on the next datagram. Detach the handle.
        if let Some(t) = self.recv_thread.take() {
            drop(t); // detach; recv loop exits when sink or socket dies
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn bind(config: &TransportConfig) -> (UdpTransport, mpsc::Receiver<NetEvent>) {
        let (tx, rx) = mpsc::channel();
        let mut cfg = config.clone();
        cfg.local_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let t = UdpTransport::bind(&cfg, tx).expect("bind");
        (t, rx)
    }

    const OPTIONS: &[u8] = b"OPTIONS sip:x SIP/2.0\r\nCall-ID: t-1\r\nCSeq: 9 OPTIONS\r\n\r\n";

    /// `-t ui`: a call socket bound at an explicit address, and every packet
    /// names the local address it arrived on.
    #[test]
    fn call_socket_at_binds_the_given_address_and_packets_carry_local() {
        let (a, _arx) = bind(&TransportConfig::default());
        let (b, brx) = bind(&TransportConfig::default());
        let want = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let call = a.open_call_socket_at(want).expect("bind at");
        assert_eq!(call.local_addr().ip(), want.ip());
        assert!(
            a.send_via(&call, OPTIONS, b.local_addr(), None)
                .expect("send")
        );
        match brx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
            NetEvent::Packet(p) => {
                assert_eq!(p.from, call.local_addr());
                assert_eq!(p.local, b.local_addr(), "arrived on b's socket");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// `-t un`: a per-call socket has its own port, delivers into the same
    /// sink, and closes (port released, thread reaped) on drop.
    #[test]
    fn per_call_socket_round_trips_and_closes() {
        let (a, arx) = bind(&TransportConfig::default());
        let (b, brx) = bind(&TransportConfig::default());
        let call = a.open_call_socket().expect("call socket");
        let call_port = call.local_addr().port();
        assert_ne!(call_port, a.local_addr().port());
        assert!(
            a.send_via(&call, OPTIONS, b.local_addr(), None)
                .expect("send")
        );
        let from = match brx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
            NetEvent::Packet(p) => p.from,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(from.port(), call_port, "sent from the call socket");
        // A reply to the call socket lands in a's sink.
        assert!(b.send_to(OPTIONS, from, None).expect("reply"));
        assert!(matches!(
            arx.recv_timeout(Duration::from_secs(2)).expect("delivered"),
            NetEvent::Packet(_)
        ));
        let started = std::time::Instant::now();
        drop(call);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "drop hung on the recv thread"
        );
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), call_port))
            .expect("call socket port released");
    }

    #[test]
    fn loopback_roundtrip_parses_and_routes() {
        let (a, _arx) = bind(&TransportConfig::default());
        let (b, brx) = bind(&TransportConfig::default());
        assert!(a.send_to(OPTIONS, b.local_addr(), None).expect("send"));
        match brx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
            NetEvent::Packet(p) => {
                assert_eq!(p.message.call_id(), Some("t-1"));
                assert_eq!(p.message.method(), Some("OPTIONS"));
                assert_eq!(p.from.ip(), a.local_addr().ip());
            }
            other => panic!("expected Packet, got {other:?}"),
        }
    }

    #[test]
    fn garbage_is_reported_not_dropped_silently() {
        let (a, _arx) = bind(&TransportConfig::default());
        let (b, brx) = bind(&TransportConfig::default());
        assert!(
            a.send_to(b"not sip at all", b.local_addr(), None)
                .expect("send")
        );
        match brx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
            NetEvent::Garbage { reason, .. } => assert_eq!(reason, ParseError::NotSip),
            other => panic!("expected Garbage, got {other:?}"),
        }
    }

    #[test]
    fn full_send_loss_drops_everything() {
        let cfg = TransportConfig {
            send_loss_pct: 100.0,
            ..Default::default()
        };
        let (a, _arx) = bind(&cfg);
        let (b, brx) = bind(&TransportConfig::default());
        for _ in 0..5 {
            assert!(
                !a.send_to(OPTIONS, b.local_addr(), None)
                    .expect("no io error"),
                "100% loss must simulate a drop"
            );
        }
        assert!(brx.recv_timeout(Duration::from_millis(150)).is_err());
        // Per-send override beats the transport default.
        assert!(a.send_to(OPTIONS, b.local_addr(), Some(0.0)).expect("send"));
        assert!(matches!(
            brx.recv_timeout(Duration::from_secs(2)).expect("delivered"),
            NetEvent::Packet(_)
        ));
    }

    #[test]
    fn ephemeral_port_is_reported() {
        let (a, _rx) = bind(&TransportConfig::default());
        assert_ne!(a.local_addr().port(), 0);
    }
}
