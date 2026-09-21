//! 3PCC twin control channels: ESC-delimited TCP links between sipr
//! instances — SIPp's classic `-3pcc` pair and its extended master/slave
//! mesh (`-slave_cfg` + `-master`/`-slave`).
//!
//! Peers exchange command messages over TCP; each command is the rendered
//! text followed by a single ESC byte (0x1B), exactly as SIPp frames twin
//! traffic (`call.cpp` appends `delimitor[0]=27`). In the classic pair the
//! role is decided by which twin command the scenario reaches first: a
//! `sendCmd` first dials the peer, a `recvCmd` first listens for it. In the
//! extended mode every instance listens on its own address from the
//! `-slave_cfg` table and dials each peer it `sendCmd`s to, so a pair of
//! instances is joined by two one-way connections, one per direction.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

/// What a twin link reports to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwinEvent {
    /// A complete command arrived (ESC stripped).
    Command(String),
    /// A peer connected to our listening socket.
    Connected,
    /// A control connection closed (peer ended); SIPp exits on this.
    Closed,
}

/// The ESC (0x1B) byte that terminates each twin command on the wire.
const ESC: u8 = 0x1b;

/// One read chunk from the twin socket.
const READ_CHUNK: usize = 16 * 1024;

/// Accumulates stream bytes and yields whole ESC-delimited commands.
#[derive(Debug, Default)]
pub struct EscFramer {
    buf: Vec<u8>,
}

impl EscFramer {
    /// A framer with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append freshly read bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete command (ESC stripped), or `None` if none yet.
    pub fn next_command(&mut self) -> Option<String> {
        let pos = self.buf.iter().position(|&b| b == ESC)?;
        let frame: Vec<u8> = self.buf.drain(..=pos).collect();
        // Drop the trailing ESC; commands are otherwise verbatim text.
        Some(String::from_utf8_lossy(&frame[..frame.len() - 1]).into_owned())
    }
}

/// A twin control channel over one TCP connection. The write half becomes
/// available immediately on `connect`, or once the peer arrives on `listen`.
pub struct TwinChannel {
    write: Arc<Mutex<Option<TcpStream>>>,
    local_addr: SocketAddr,
    /// Kept so the accept thread outlives the constructor (listen only).
    _accept: Option<std::thread::JoinHandle<()>>,
}

impl TwinChannel {
    /// Controller-A role: dial the peer's twin socket and start reading
    /// commands. `sink` receives each decoded command.
    ///
    /// # Errors
    ///
    /// Connection failure (e.g. the peer is not listening yet).
    pub fn connect(remote: SocketAddr, sink: Sender<TwinEvent>) -> std::io::Result<Self> {
        let stream = TcpStream::connect(remote)?;
        let local_addr = stream.local_addr()?;
        let read = stream.try_clone()?;
        let write = Arc::new(Mutex::new(Some(stream)));
        spawn_reader(read, sink);
        Ok(Self {
            write,
            local_addr,
            _accept: None,
        })
    }

    /// Controller-B role: bind the local twin socket and accept the peer's one
    /// connection, then read commands into `sink`.
    ///
    /// # Errors
    ///
    /// Bind failure.
    pub fn listen(local: SocketAddr, sink: Sender<TwinEvent>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(local)?;
        let local_addr = listener.local_addr()?;
        let write = Arc::new(Mutex::new(None));
        let write_slot = write.clone();
        let accept = std::thread::Builder::new()
            .name("sipr-twin-accept".into())
            .spawn(move || {
                if let Ok((stream, _peer)) = listener.accept() {
                    if let Ok(read) = stream.try_clone() {
                        if let Ok(mut slot) = write_slot.lock() {
                            *slot = Some(stream);
                        }
                        let _ = sink.send(TwinEvent::Connected);
                        spawn_reader(read, sink);
                    }
                }
            })
            .ok();
        Ok(Self {
            write,
            local_addr,
            _accept: accept,
        })
    }

    /// The bound/local address of the twin socket.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send a command: the text plus the ESC delimiter.
    ///
    /// # Errors
    ///
    /// The peer has not connected yet, or the write failed.
    pub fn send(&self, text: &str) -> std::io::Result<()> {
        let mut guard = match self.write.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(stream) = guard.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "twin peer has not connected yet",
            ));
        };
        stream.write_all(text.as_bytes())?;
        stream.write_all(&[ESC])?;
        stream.flush()?;
        Ok(())
    }
}

impl Drop for TwinChannel {
    /// Shut the connection down (not just this handle): the reader thread's
    /// duplicate would otherwise keep it open and the peer would never see
    /// us end.
    fn drop(&mut self) {
        if let Ok(guard) = self.write.lock()
            && let Some(stream) = guard.as_ref()
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Frame ESC-delimited commands off `stream` into `sink` until it closes,
/// then report the close.
fn spawn_reader(mut stream: TcpStream, sink: Sender<TwinEvent>) {
    std::thread::Builder::new()
        .name("sipr-twin-recv".into())
        .spawn(move || {
            let mut framer = EscFramer::new();
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        framer.push(&buf[..n]);
                        while let Some(cmd) = framer.next_command() {
                            if sink.send(TwinEvent::Command(cmd)).is_err() {
                                return; // engine gone
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = sink.send(TwinEvent::Closed);
        })
        .ok();
}

/// The `-slave_cfg` table: one `name;host:port` line per instance (SIPp
/// `parse_slave_cfg`: the first two `;`-separated fields, anything after
/// them ignored, lines without a `;` skipped).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerTable {
    entries: Vec<(String, String)>,
    /// Non-empty lines that had no `;` and were skipped, for a warning.
    skipped: Vec<String>,
}

impl PeerTable {
    /// Parse the file text. Never fails: SIPp skips what it cannot split.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut table = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split(';');
            let name = fields.next().unwrap_or_default().trim();
            match fields.next().map(str::trim) {
                Some(host) if !name.is_empty() && !host.is_empty() => {
                    table.entries.retain(|(n, _)| n != name);
                    table.entries.push((name.to_owned(), host.to_owned()));
                }
                _ => table.skipped.push(line.to_owned()),
            }
        }
        table
    }

    /// The `host:port` text for `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, h)| h.as_str())
    }

    /// Every `(name, host:port)` pair, in file order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, h)| (n.as_str(), h.as_str()))
    }

    /// Lines skipped for having no `;`.
    #[must_use]
    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }
}

/// Extended 3PCC links: our listening socket, on which every peer that
/// talks to us connects, and one dialed connection per peer we talk to.
/// Commands go out on the dialed connection of the named peer and come in
/// on the accepted ones, as in SIPp (`socket.cpp` `connect_to_all_peers`,
/// `local_sockets`).
pub struct PeerLinks {
    local_addr: SocketAddr,
    links: Arc<Mutex<HashMap<String, TcpStream>>>,
    /// The connections peers made to us, shut down when we end.
    accepted: Arc<Mutex<Vec<TcpStream>>>,
    sink: Sender<TwinEvent>,
    connected: bool,
    /// Kept so the accept loop outlives the constructor.
    _accept: Option<std::thread::JoinHandle<()>>,
}

impl PeerLinks {
    /// Bind our own twin address and accept peers for the rest of the run;
    /// each accepted connection reports `Connected` and then its commands.
    ///
    /// # Errors
    ///
    /// Bind failure.
    pub fn listen(local: SocketAddr, sink: Sender<TwinEvent>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(local)?;
        let local_addr = listener.local_addr()?;
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let accepted_reg = accepted.clone();
        let accept_sink = sink.clone();
        let accept = std::thread::Builder::new()
            .name("sipr-twin-accept".into())
            .spawn(move || {
                while let Ok((stream, _peer)) = listener.accept() {
                    if accept_sink.send(TwinEvent::Connected).is_err() {
                        return; // engine gone
                    }
                    if let Ok(dup) = stream.try_clone()
                        && let Ok(mut reg) = accepted_reg.lock()
                    {
                        reg.push(dup);
                    }
                    spawn_reader(stream, accept_sink.clone());
                }
            })
            .ok();
        Ok(Self {
            local_addr,
            links: Arc::new(Mutex::new(HashMap::new())),
            accepted,
            sink,
            connected: false,
            _accept: accept,
        })
    }

    /// Dial every named peer (SIPp `connect_to_all_peers`). A peer already
    /// linked is left alone. The dialed side is read too, only so that the
    /// peer ending shows up as `Closed`.
    ///
    /// # Errors
    ///
    /// The first peer that cannot be reached, named in the message.
    pub fn connect_all(&mut self, peers: &[(String, SocketAddr)]) -> std::io::Result<()> {
        for (name, addr) in peers {
            if self.has_link(name) {
                continue;
            }
            let stream = TcpStream::connect(addr).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Unable to connect a twin sipp TCP socket to peer '{name}' at {addr}: {e}"
                    ),
                )
            })?;
            if let Ok(read) = stream.try_clone() {
                spawn_reader(read, self.sink.clone());
            }
            if let Ok(mut links) = self.links.lock() {
                links.insert(name.clone(), stream);
            }
        }
        self.connected = true;
        Ok(())
    }

    /// Whether `connect_all` has run.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    fn has_link(&self, name: &str) -> bool {
        self.links.lock().is_ok_and(|l| l.contains_key(name))
    }

    /// The bound address of our listening socket.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send a command to the named peer: the text plus the ESC delimiter.
    ///
    /// # Errors
    ///
    /// No link to that peer, or the write failed.
    pub fn send_to(&self, peer: &str, text: &str) -> std::io::Result<()> {
        let mut links = match self.links.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(stream) = links.get_mut(peer) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("no twin connection to peer '{peer}'"),
            ));
        };
        stream.write_all(text.as_bytes())?;
        stream.write_all(&[ESC])?;
        stream.flush()?;
        Ok(())
    }
}

impl Drop for PeerLinks {
    /// Shut every connection down so each peer sees us end (SIPp's
    /// `close_peer_sockets` + `close_local_sockets`).
    fn drop(&mut self) {
        if let Ok(links) = self.links.lock() {
            for stream in links.values() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        }
        if let Ok(accepted) = self.accepted.lock() {
            for stream in accepted.iter() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn framer_splits_on_esc() {
        let mut f = EscFramer::new();
        f.push(b"hello\x1bwor");
        assert_eq!(f.next_command().as_deref(), Some("hello"));
        assert_eq!(f.next_command(), None, "partial command held");
        f.push(b"ld\x1b");
        assert_eq!(f.next_command().as_deref(), Some("world"));
        assert_eq!(f.next_command(), None);
    }

    #[test]
    fn framer_multiple_in_one_push() {
        let mut f = EscFramer::new();
        f.push(b"a\x1bb\x1bc\x1b");
        assert_eq!(f.next_command().as_deref(), Some("a"));
        assert_eq!(f.next_command().as_deref(), Some("b"));
        assert_eq!(f.next_command().as_deref(), Some("c"));
        assert_eq!(f.next_command(), None);
    }

    #[test]
    fn connect_and_listen_exchange_commands() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // B listens; grab its bound port, then A dials it.
        let (b_tx, b_rx) = mpsc::channel();
        let b = TwinChannel::listen(local, b_tx).expect("listen");
        let b_addr = b.local_addr();
        let (a_tx, a_rx) = mpsc::channel();
        let a = TwinChannel::connect(b_addr, a_tx).expect("connect");

        // B sees the peer arrive, then A's command.
        assert_eq!(
            b_rx.recv_timeout(Duration::from_secs(2))
                .expect("b connected"),
            TwinEvent::Connected
        );
        a.send("Call-ID: x\r\noffer").expect("a send");
        assert_eq!(
            b_rx.recv_timeout(Duration::from_secs(2)).expect("b rx"),
            TwinEvent::Command("Call-ID: x\r\noffer".into())
        );
        // B -> A (write half is ready once B accepted, which the recv proves).
        b.send("answer").expect("b send");
        assert_eq!(
            a_rx.recv_timeout(Duration::from_secs(2)).expect("a rx"),
            TwinEvent::Command("answer".into())
        );
        // A going away is reported to B.
        drop(a);
        assert_eq!(
            b_rx.recv_timeout(Duration::from_secs(2)).expect("b closed"),
            TwinEvent::Closed
        );
    }

    #[test]
    fn peer_table_parses_sipps_format() {
        let t = PeerTable::parse(
            "s1;127.0.0.1:8080\ns2;127.0.0.1:7080;extra\n\nm;127.0.0.1:6080\n# no semicolon\n",
        );
        assert_eq!(t.get("s1"), Some("127.0.0.1:8080"));
        assert_eq!(t.get("s2"), Some("127.0.0.1:7080"), "third field ignored");
        assert_eq!(t.get("m"), Some("127.0.0.1:6080"));
        assert_eq!(t.get("s3"), None);
        assert_eq!(t.skipped(), ["# no semicolon".to_owned()]);
        assert_eq!(t.entries().count(), 3);
        // A repeated name: the last line wins, as SIPp's map overwrite does.
        let t = PeerTable::parse("m;1.1.1.1:1\nm;2.2.2.2:2\n");
        assert_eq!(t.get("m"), Some("2.2.2.2:2"));
        assert_eq!(t.entries().count(), 1);
    }

    #[test]
    fn peer_links_route_commands_by_name_and_report_closes() {
        let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // Two slaves listen; the master dials both and each slave dials back.
        let (s1_tx, s1_rx) = mpsc::channel();
        let mut s1 = PeerLinks::listen(any, s1_tx).expect("s1 listen");
        let (s2_tx, s2_rx) = mpsc::channel();
        let s2 = PeerLinks::listen(any, s2_tx).expect("s2 listen");
        let (m_tx, m_rx) = mpsc::channel();
        let mut m = PeerLinks::listen(any, m_tx).expect("m listen");
        assert!(!m.is_connected());
        m.connect_all(&[
            ("s1".to_owned(), s1.local_addr()),
            ("s2".to_owned(), s2.local_addr()),
        ])
        .expect("master dials");
        assert!(m.is_connected());
        assert_eq!(
            s1_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("s1 accept"),
            TwinEvent::Connected
        );
        assert_eq!(
            s2_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("s2 accept"),
            TwinEvent::Connected
        );
        m.send_to("s1", "From: m\nfor s1").expect("m -> s1");
        m.send_to("s2", "From: m\nfor s2").expect("m -> s2");
        assert_eq!(
            s1_rx.recv_timeout(Duration::from_secs(2)).expect("s1 rx"),
            TwinEvent::Command("From: m\nfor s1".into())
        );
        assert_eq!(
            s2_rx.recv_timeout(Duration::from_secs(2)).expect("s2 rx"),
            TwinEvent::Command("From: m\nfor s2".into())
        );
        // The slave dials back on its own connection and answers.
        s1.connect_all(&[("m".to_owned(), m.local_addr())])
            .expect("s1 dials");
        assert_eq!(
            m_rx.recv_timeout(Duration::from_secs(2)).expect("m accept"),
            TwinEvent::Connected
        );
        s1.send_to("m", "From: s1\nanswer").expect("s1 -> m");
        assert_eq!(
            m_rx.recv_timeout(Duration::from_secs(2)).expect("m rx"),
            TwinEvent::Command("From: s1\nanswer".into())
        );
        // An unknown peer is an error, not a silent drop.
        assert!(m.send_to("s3", "x").is_err());
        // A peer ending is reported on the surviving side.
        drop(s2);
        assert_eq!(
            m_rx.recv_timeout(Duration::from_secs(2)).expect("m closed"),
            TwinEvent::Closed
        );
    }

    #[test]
    fn send_before_peer_connects_errors() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (tx, _rx) = mpsc::channel();
        let b = TwinChannel::listen(local, tx).expect("listen");
        assert!(b.send("nobody home").is_err(), "no peer yet");
    }
}
