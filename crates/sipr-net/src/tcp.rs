//! TCP transport (`t1`): stream de-framing plus a connection-per-peer socket
//! table shared by the client (one dialed connection) and server (accepted
//! connections).
//!
//! SIP over TCP is a byte stream, so message boundaries come from the
//! Content-Length header, not datagram edges (RFC 3261 §7.5). [`TcpFramer`]
//! turns a stream of reads into whole messages; [`TcpTransport`] runs a reader
//! thread per connection that frames inbound bytes into [`NetEvent`]s and keeps
//! a write handle keyed by peer address so responses go back the way they came.
//!
//! Reliability is TCP's job: the engine sends each message once and schedules
//! no SIP retransmissions on this transport (RFC 3261 §18.2).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::message::Inbound;
use crate::rng::Rng;
use crate::transport::{InboundPacket, NetEvent, TransportConfig};

/// One read from the socket; big enough to hold most whole messages, but the
/// framer copes with any split.
const READ_CHUNK: usize = 64 * 1024;

/// Accumulates stream bytes and yields complete SIP messages.
///
/// A message is its headers up to the first `\r\n\r\n`, then exactly
/// `Content-Length` body bytes. Leading `\r\n` runs (SIP/TCP keep-alive pings,
/// RFC 5626) are discarded between messages.
#[derive(Debug, Default)]
pub struct TcpFramer {
    buf: Vec<u8>,
}

impl TcpFramer {
    /// A framer with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append freshly read bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete message, or `None` if more bytes are needed.
    ///
    /// Call in a loop after each [`Self::push`] — one read can carry several
    /// messages, or a fraction of one.
    pub fn next_message(&mut self) -> Option<Vec<u8>> {
        // Drop leading CRLF keep-alives / inter-message padding.
        while self.buf.starts_with(b"\r\n") {
            self.buf.drain(..2);
        }
        if self.buf.is_empty() {
            return None;
        }
        let sep = find_subslice(&self.buf, b"\r\n\r\n")?;
        let body_start = sep + 4;
        let content_len = content_length(&self.buf[..sep]);
        let total = body_start + content_len;
        if self.buf.len() < total {
            return None; // headers complete, body still arriving
        }
        Some(self.buf.drain(..total).collect())
    }
}

/// First index of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse `Content-Length` (or the compact `l`) from header bytes; `0` when
/// absent or unparseable (SIP defaults a missing Content-Length to 0 on
/// stream transports would be unsafe, but SIPp always emits one).
fn content_length(head: &[u8]) -> usize {
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, rest) = line.split_at(colon);
        let name = trim_ascii(name);
        if name.eq_ignore_ascii_case(b"content-length") || name.eq_ignore_ascii_case(b"l") {
            let value = trim_ascii(&rest[1..]);
            if let Ok(s) = std::str::from_utf8(value) {
                if let Ok(n) = s.trim().parse::<usize>() {
                    return n;
                }
            }
        }
    }
    0
}

/// Trim ASCII whitespace from both ends of a byte slice.
fn trim_ascii(mut b: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = b {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = b {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// Shared table of live connections, keyed by peer address.
type Conns = Arc<Mutex<HashMap<SocketAddr, TcpStream>>>;

/// The `t1` TCP transport: one connection per peer, framed reader threads,
/// writes routed back by peer address. In `tn` client mode it is only the
/// pool that per-call connections are opened from.
pub struct TcpTransport {
    local_addr: SocketAddr,
    conns: Conns,
    send_rng: Mutex<Rng>,
    send_loss_pct: f64,
    sink: Sender<NetEvent>,
    /// Kept so the accept loop lives as long as the transport (server only).
    _accept: Option<std::thread::JoinHandle<()>>,
}

/// A per-call TCP connection (`-t tn`): dialed for one call, read by its own
/// framing thread into the transport's sink; dropping it closes the
/// connection (the peer sees FIN).
pub struct TcpCallConn {
    stream: TcpStream,
    local_addr: SocketAddr,
}

impl TcpCallConn {
    /// The connection's local address (`[local_port]` for this call).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for TcpCallConn {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl TcpTransport {
    /// Client (`UAC`): dial the single mono-socket connection to `remote` and
    /// start framing responses. The local address is the socket's own.
    ///
    /// # Errors
    ///
    /// Connection failures (e.g. the peer is not listening yet).
    pub fn connect(
        config: &TransportConfig,
        sink: Sender<NetEvent>,
        remote: SocketAddr,
    ) -> std::io::Result<Self> {
        let stream = TcpStream::connect(remote)?;
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let conns: Conns = Arc::new(Mutex::new(HashMap::new()));
        register(&conns, peer, stream, &sink)?;
        Ok(Self {
            local_addr,
            conns,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0011)),
            send_loss_pct: config.send_loss_pct,
            sink,
            _accept: None,
        })
    }

    /// Client in `tn` mode: no connection yet — each call dials its own
    /// with [`Self::connect_call`]. `local_addr` is the local IP, port 0.
    #[must_use]
    pub fn client_pool(config: &TransportConfig, sink: Sender<NetEvent>) -> Self {
        let ip = config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Self {
            local_addr: SocketAddr::new(ip, 0),
            conns: Arc::new(Mutex::new(HashMap::new())),
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0013)),
            send_loss_pct: config.send_loss_pct,
            sink,
            _accept: None,
        }
    }

    /// Drop the connection to `peer` from the table once the engine has
    /// processed its `Disconnected` event.
    pub fn forget(&self, peer: SocketAddr) {
        if let Ok(mut map) = self.conns.lock() {
            map.remove(&peer);
        }
    }

    /// Re-dial the mono connection to `remote` after it dropped
    /// (`-max_reconnect`): the new stream replaces the old one under the
    /// same peer key.
    ///
    /// # Errors
    ///
    /// Connection failures.
    pub fn reconnect(&self, remote: SocketAddr) -> std::io::Result<()> {
        let stream = TcpStream::connect(remote)?;
        let peer = stream.peer_addr()?;
        register(&self.conns, peer, stream, &self.sink)
    }

    /// Dial a per-call connection to `remote` (`-t tn`, SIPp's
    /// `connect_socket_if_needed`) and start framing what comes back.
    ///
    /// # Errors
    ///
    /// Connection failures (the call fails, not the run).
    pub fn connect_call(&self, remote: SocketAddr) -> std::io::Result<TcpCallConn> {
        let stream = TcpStream::connect(remote)?;
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let read_half = stream.try_clone()?;
        let sink = self.sink.clone();
        std::thread::Builder::new()
            .name("sipr-tcp-call".into())
            .spawn(move || read_loop(read_half, peer, &sink))?;
        Ok(TcpCallConn { stream, local_addr })
    }

    /// Send `data` on a per-call connection, honoring simulated loss.
    ///
    /// # Errors
    ///
    /// Write failures.
    pub fn send_via(
        &self,
        conn: &TcpCallConn,
        data: &[u8],
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false);
        }
        let mut out = &conn.stream;
        out.write_all(data)?;
        out.flush()?;
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

    /// Server (`UAS`): bind a listener and accept connections, framing each.
    ///
    /// # Errors
    ///
    /// Bind failures.
    pub fn listen(config: &TransportConfig, sink: Sender<NetEvent>) -> std::io::Result<Self> {
        let ip = config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let listener = TcpListener::bind(SocketAddr::new(ip, config.port.unwrap_or(0)))?;
        let local_addr = listener.local_addr()?;
        let conns: Conns = Arc::new(Mutex::new(HashMap::new()));
        let accept_conns = conns.clone();
        let accept_sink = sink.clone();
        let accept = std::thread::Builder::new()
            .name("sipr-tcp-accept".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let Ok(peer) = stream.peer_addr() else {
                        continue;
                    };
                    // A dead connection here is a per-peer problem, not fatal.
                    let _ = register(&accept_conns, peer, stream, &accept_sink);
                }
            })
            .ok();
        Ok(Self {
            local_addr,
            conns,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0012)),
            send_loss_pct: config.send_loss_pct,
            sink,
            _accept: accept,
        })
    }

    /// The bound local address (a real ephemeral port when `-p` was omitted).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send `data` to the connection for `to`, honoring simulated loss.
    ///
    /// Returns `true` when the bytes were written (`false` = simulated drop).
    ///
    /// # Errors
    ///
    /// No connection exists for `to`, or the write failed.
    pub fn send_to(
        &self,
        data: &[u8],
        to: SocketAddr,
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false); // simulated app-layer loss
        }
        let mut map = match self.conns.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(stream) = map.get_mut(&to) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("no TCP connection to {to}"),
            ));
        };
        stream.write_all(data)?;
        stream.flush()?;
        Ok(true)
    }
}

/// Register `stream` under `peer`: keep it as the write handle and spawn a
/// framed reader (on a clone) that delivers into `sink` and deregisters on
/// close. The original stream is stored, not dropped — closing it would tear
/// the connection down even though clones remain.
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
    let conns = conns.clone();
    // The reader only reports the end of the connection; the engine calls
    // `forget` when it processes that event, so a send it has already
    // queued (an ACK for the 200 that came just before the FIN) still goes
    // out on the half-closed socket, as SIPp's does.
    let _ = conns;
    std::thread::Builder::new()
        .name("sipr-tcp-recv".into())
        .spawn(move || read_loop(read_half, peer, &sink))
        .ok();
    Ok(())
}

/// Frame everything arriving on one connection until it closes or errors,
/// then tell the engine how it ended (`Disconnected`): the engine decides
/// whether calls die and whether to reconnect (`-reconnect_*`); a server
/// never stops because one client hung up.
fn read_loop(mut stream: TcpStream, peer: SocketAddr, sink: &Sender<NetEvent>) {
    let local = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let mut framer = TcpFramer::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let clean = loop {
        match stream.read(&mut buf) {
            Ok(0) => break true, // peer closed
            Ok(n) => {
                framer.push(&buf[..n]);
                while let Some(raw) = framer.next_message() {
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
                        return; // engine gone
                    }
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
        b"OPTIONS sip:x SIP/2.0\r\nCall-ID: t-1\r\nCSeq: 9 OPTIONS\r\nContent-Length: 0\r\n\r\n";

    /// A peer closing the mono connection is reported as a clean
    /// `Disconnected`; after `forget`, sends fail until `reconnect` re-dials.
    #[test]
    fn disconnect_is_reported_and_reconnect_restores_sending() {
        let (stx, srx) = mpsc::channel();
        let cfg = TransportConfig {
            local_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..TransportConfig::default()
        };
        let server = TcpTransport::listen(&cfg, stx).expect("listen");
        let (ctx, crx) = mpsc::channel();
        let client = TcpTransport::connect(&cfg, ctx, server.local_addr()).expect("connect");
        assert!(
            client
                .send_to(MSG, server.local_addr(), None)
                .expect("send")
        );
        let from = match srx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
            NetEvent::Packet(p) => p.from,
            other => panic!("unexpected {other:?}"),
        };
        // The server drops the client's connection.
        if let Ok(mut map) = server.conns.lock() {
            let stream = map.remove(&from).expect("registered");
            let _ = stream.shutdown(Shutdown::Both);
        }
        match crx
            .recv_timeout(Duration::from_secs(2))
            .expect("disconnect reported")
        {
            NetEvent::Disconnected { peer, clean, .. } => {
                assert_eq!(peer, server.local_addr());
                assert!(clean, "orderly close");
                client.forget(peer);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(client.send_to(MSG, server.local_addr(), None).is_err());
        client.reconnect(server.local_addr()).expect("reconnect");
        assert!(
            client
                .send_to(MSG, server.local_addr(), None)
                .expect("send again")
        );
        // The server's sink also hears the old connection end; skip that.
        loop {
            match srx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
                NetEvent::Packet(_) => break,
                NetEvent::Disconnected { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    /// `-t tn`: two per-call connections from one client pool reach the
    /// server as two peers; replies route back on each; drop closes it.
    #[test]
    fn per_call_connections_are_distinct_and_close_on_drop() {
        let (stx, srx) = mpsc::channel();
        let cfg = TransportConfig {
            local_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..TransportConfig::default()
        };
        let server = TcpTransport::listen(&cfg, stx).expect("listen");
        let (ctx, crx) = mpsc::channel();
        let client = TcpTransport::client_pool(&cfg, ctx);
        let a = client.connect_call(server.local_addr()).expect("dial a");
        let b = client.connect_call(server.local_addr()).expect("dial b");
        assert_ne!(a.local_addr().port(), b.local_addr().port());
        assert!(client.send_via(&a, MSG, None).expect("send a"));
        assert!(client.send_via(&b, MSG, None).expect("send b"));
        let mut peers = Vec::new();
        for _ in 0..2 {
            match srx.recv_timeout(Duration::from_secs(2)).expect("delivered") {
                NetEvent::Packet(p) => peers.push(p.from),
                other => panic!("unexpected {other:?}"),
            }
        }
        peers.sort();
        let mut expected = vec![a.local_addr(), b.local_addr()];
        expected.sort();
        assert_eq!(peers, expected);
        // Reply to a on its own connection: it arrives in the client's sink.
        assert!(server.send_to(MSG, a.local_addr(), None).expect("reply"));
        assert!(matches!(
            crx.recv_timeout(Duration::from_secs(2)).expect("delivered"),
            NetEvent::Packet(_)
        ));
        let a_addr = a.local_addr();
        drop(a);
        // The server hears the FIN as a Disconnected for that peer and, once
        // it forgets the connection, can no longer send to it.
        loop {
            match srx
                .recv_timeout(Duration::from_secs(2))
                .expect("disconnect reported")
            {
                NetEvent::Disconnected { peer, clean, .. } if peer == a_addr => {
                    assert!(clean);
                    server.forget(peer);
                    break;
                }
                _ => {}
            }
        }
        assert!(
            server.send_to(MSG, a_addr, None).is_err(),
            "forgotten connection"
        );
        assert!(
            server
                .send_to(MSG, b.local_addr(), None)
                .expect("b still up")
        );
    }

    #[test]
    fn frames_one_message() {
        let mut f = TcpFramer::new();
        f.push(MSG);
        assert_eq!(f.next_message().as_deref(), Some(MSG));
        assert_eq!(f.next_message(), None);
    }

    #[test]
    fn frames_across_partial_reads() {
        let mut f = TcpFramer::new();
        f.push(&MSG[..10]);
        assert_eq!(f.next_message(), None, "headers incomplete");
        f.push(&MSG[10..]);
        assert_eq!(f.next_message().as_deref(), Some(MSG));
    }

    #[test]
    fn frames_two_messages_in_one_read() {
        let mut both = MSG.to_vec();
        both.extend_from_slice(MSG);
        let mut f = TcpFramer::new();
        f.push(&both);
        assert_eq!(f.next_message().as_deref(), Some(MSG));
        assert_eq!(f.next_message().as_deref(), Some(MSG));
        assert_eq!(f.next_message(), None);
    }

    #[test]
    fn respects_content_length_body() {
        let msg = b"INVITE sip:x SIP/2.0\r\nContent-Length: 5\r\n\r\nv=0\r\n";
        let mut f = TcpFramer::new();
        f.push(&msg[..msg.len() - 2]); // body one field short
        assert_eq!(f.next_message(), None, "body incomplete");
        f.push(b"\r\n");
        assert_eq!(f.next_message().as_deref(), Some(&msg[..]));
    }

    #[test]
    fn compact_content_length_and_keepalive() {
        // Leading keep-alive CRLFs are skipped; compact `l:` is honored.
        let msg = b"MESSAGE sip:x SIP/2.0\r\nl: 3\r\n\r\nabc";
        let mut f = TcpFramer::new();
        f.push(b"\r\n\r\n"); // a keep-alive ping
        f.push(msg);
        assert_eq!(f.next_message().as_deref(), Some(&msg[..]));
    }

    #[test]
    fn missing_content_length_defaults_to_zero() {
        let msg = b"ACK sip:x SIP/2.0\r\nCall-ID: c\r\n\r\n";
        let mut f = TcpFramer::new();
        f.push(msg);
        assert_eq!(f.next_message().as_deref(), Some(&msg[..]));
    }

    fn config() -> TransportConfig {
        TransportConfig {
            local_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..Default::default()
        }
    }

    #[test]
    fn client_server_roundtrip_and_reply() {
        // Server accepts and frames; client dials and sends; server replies on
        // the same connection and the client frames the reply.
        let (srv_tx, srv_rx) = mpsc::channel();
        let server = TcpTransport::listen(&config(), srv_tx).expect("listen");
        let srv_addr = server.local_addr();

        let (cli_tx, cli_rx) = mpsc::channel();
        let client = TcpTransport::connect(&config(), cli_tx, srv_addr).expect("connect");

        assert!(client.send_to(MSG, srv_addr, None).expect("send"));
        let from = match srv_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server rx")
        {
            NetEvent::Packet(p) => {
                assert_eq!(p.message.call_id(), Some("t-1"));
                p.from
            }
            other => panic!("expected Packet, got {other:?}"),
        };
        // Reply to the client on the accepted connection.
        let reply =
            b"SIP/2.0 200 OK\r\nCall-ID: t-1\r\nCSeq: 9 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        assert!(server.send_to(reply, from, None).expect("reply"));
        match cli_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("client rx")
        {
            NetEvent::Packet(p) => assert_eq!(p.message.status_code(), Some(200)),
            other => panic!("expected Packet, got {other:?}"),
        }
    }

    #[test]
    fn send_without_connection_errors() {
        let (tx, _rx) = mpsc::channel();
        let server = TcpTransport::listen(&config(), tx).expect("listen");
        let nowhere = "127.0.0.1:9".parse().expect("addr");
        assert!(server.send_to(MSG, nowhere, None).is_err());
    }

    #[test]
    fn full_loss_simulates_drop() {
        let (srv_tx, srv_rx) = mpsc::channel();
        let server = TcpTransport::listen(&config(), srv_tx).expect("listen");
        let srv_addr = server.local_addr();
        let (cli_tx, _cli_rx) = mpsc::channel();
        let mut cfg = config();
        cfg.send_loss_pct = 100.0;
        let client = TcpTransport::connect(&cfg, cli_tx, srv_addr).expect("connect");
        assert!(
            !client.send_to(MSG, srv_addr, None).expect("no io error"),
            "100% loss drops the write"
        );
        assert!(srv_rx.recv_timeout(Duration::from_millis(150)).is_err());
    }
}
