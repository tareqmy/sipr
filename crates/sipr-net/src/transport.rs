//! UDP transport: the socket, its recv loop, and simulated packet loss.
//!
//! `u1` mode (SIPp's default): one socket shared by every call. A dedicated
//! recv thread parses each datagram just enough to route — Call-ID extraction
//! via [`crate::message::Inbound`] — and forwards it into the engine's single
//! event channel. Simulated loss (`lost` attributes, deterministic seeded
//! RNG) applies on both paths *before* any real I/O or delivery, exactly as
//! if the network dropped the packet.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::sync::mpsc::Sender;
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

/// The `u1` UDP transport.
pub struct UdpTransport {
    socket: UdpSocket,
    local_addr: SocketAddr,
    send_rng: Mutex<Rng>,
    send_loss_pct: f64,
    recv_thread: Option<std::thread::JoinHandle<()>>,
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
        let mut recv_rng = Rng::new(config.loss_seed ^ 0x5EED_0002);
        let recv_thread = std::thread::Builder::new()
            .name("sipr-udp-recv".into())
            .spawn(move || {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                loop {
                    match recv_socket.recv_from(&mut buf) {
                        Ok((n, from)) => {
                            if recv_loss_pct > 0.0 && recv_rng.chance_pct(recv_loss_pct) {
                                continue; // simulated inbound loss
                            }
                            let event = match Inbound::parse(&buf[..n]) {
                                Ok(message) => NetEvent::Packet(InboundPacket {
                                    message,
                                    raw: buf[..n].to_vec(),
                                    from,
                                    received_at: Instant::now(),
                                }),
                                Err(reason) => NetEvent::Garbage { from, reason },
                            };
                            if sink.send(event).is_err() {
                                return; // engine gone
                            }
                        }
                        Err(e) => {
                            let _ = sink.send(NetEvent::SocketError(e.kind()));
                            return;
                        }
                    }
                }
            })
            .ok();
        Ok(Self {
            socket,
            local_addr,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0001)),
            send_loss_pct: config.send_loss_pct,
            recv_thread,
        })
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
        let pct = lost_pct.unwrap_or(self.send_loss_pct);
        if pct > 0.0 {
            let dropped = {
                let mut rng = match self.send_rng.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                rng.chance_pct(pct)
            };
            if dropped {
                return Ok(false);
            }
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
