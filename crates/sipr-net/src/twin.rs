//! 3PCC twin control channel: an ESC-delimited TCP link between two sipr
//! instances (SIPp's classic `-3pcc`).
//!
//! The two peers exchange command messages over one TCP connection; each
//! command is the rendered text followed by a single ESC byte (0x1B), exactly
//! as SIPp frames twin traffic (`call.cpp` appends `delimitor[0]=27`). The role
//! is decided by which twin command the scenario reaches first: a `sendCmd`
//! first dials the peer, a `recvCmd` first listens for it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

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
    pub fn connect(remote: SocketAddr, sink: Sender<String>) -> std::io::Result<Self> {
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
    pub fn listen(local: SocketAddr, sink: Sender<String>) -> std::io::Result<Self> {
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

/// Frame ESC-delimited commands off `stream` into `sink` until it closes.
fn spawn_reader(mut stream: TcpStream, sink: Sender<String>) {
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
                            if sink.send(cmd).is_err() {
                                return; // engine gone
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        })
        .ok();
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

        // A -> B.
        a.send("Call-ID: x\r\noffer").expect("a send");
        assert_eq!(
            b_rx.recv_timeout(Duration::from_secs(2)).expect("b rx"),
            "Call-ID: x\r\noffer"
        );
        // B -> A (write half is ready once B accepted, which the recv proves).
        b.send("answer").expect("b send");
        assert_eq!(
            a_rx.recv_timeout(Duration::from_secs(2)).expect("a rx"),
            "answer"
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
