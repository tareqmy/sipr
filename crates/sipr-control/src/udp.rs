//! SIPp's control socket (`socket.cpp` `setup_ctrl_socket` /
//! `handle_ctrl_socket`): a UDP port where each datagram is one hot key or
//! one `c`-prefixed command line. Fire-and-forget — SIPp `recv()`s without
//! a peer address and never answers; neither does this.
//!
//! Binding follows SIPp: an explicit `-cp` port is tried once and failure
//! is fatal; otherwise ports 8888..8947 are probed and running without a
//! control socket is only a warning. One deliberate divergence: the
//! default bind address is loopback, not every interface — the socket can
//! kill the run with no authentication, so it should not face the network
//! unless `-ci` says so.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::Sender;

use crate::command::{Datagram, parse_command, parse_datagram};
use crate::{ControlCmd, ControlRequest};

/// SIPp's `DEFAULT_CTRL_SOCKET_PORT`.
pub const DEFAULT_PORT: u16 = 8888;
/// SIPp probes this many consecutive ports when `-cp` is not given.
const PROBE_PORTS: u16 = 60;

/// Bind the control socket. `port` = `Some(p)` for an explicit `-cp`
/// (tried once), `None` for SIPp's probing default.
///
/// # Errors
///
/// The bind error (for an explicit port, or when the whole probe range
/// is taken).
pub fn bind(ip: Option<IpAddr>, port: Option<u16>) -> std::io::Result<UdpSocket> {
    let ip = ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    match port {
        Some(p) => UdpSocket::bind(SocketAddr::new(ip, p)),
        None => {
            let mut last = None;
            for p in DEFAULT_PORT..DEFAULT_PORT + PROBE_PORTS {
                match UdpSocket::bind(SocketAddr::new(ip, p)) {
                    Ok(s) => return Ok(s),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| std::io::Error::other("no ports to probe")))
        }
    }
}

/// Serve `socket` on a background thread: every datagram becomes a
/// [`ControlRequest`] without a reply channel. Parse errors (SIPp's
/// warning text) go to `warn`.
pub fn serve(
    socket: UdpSocket,
    requests: Sender<ControlRequest>,
    warn: impl Fn(&str) + Send + 'static,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("sipr-ctrl-udp".into())
        .spawn(move || {
            let mut buf = [0u8; 65_536];
            while let Ok((n, _)) = socket.recv_from(&mut buf) {
                let cmd = match parse_datagram(&buf[..n]) {
                    None => continue,
                    Some(Datagram::Key(c)) => ControlCmd::Key(c),
                    Some(Datagram::Command(line)) => match parse_command(&line) {
                        Ok(cmd) => cmd,
                        Err(e) => {
                            warn(&e);
                            continue;
                        }
                    },
                };
                if requests.send(ControlRequest { cmd, reply: None }).is_err() {
                    return;
                }
            }
        })?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    #[test]
    fn datagrams_become_requests_and_bad_ones_warn() {
        let sock = bind(None, Some(0)).unwrap();
        let addr = sock.local_addr().unwrap();
        let (tx, rx) = channel();
        let (warn_tx, warn_rx) = channel::<String>();
        serve(sock, tx, move |w| {
            let _ = warn_tx.send(w.to_owned());
        })
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(b"p\n", addr).unwrap();
        client.send_to(b"cset rate 5\n", addr).unwrap();
        client.send_to(b"cset bogus 1", addr).unwrap();
        let first = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(first.cmd, ControlCmd::Key('p'));
        assert!(first.reply.is_none());
        let second = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(second.cmd, ControlCmd::SetRate(5.0));
        assert_eq!(
            warn_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "Unknown set attribute: bogus"
        );
    }

    #[test]
    fn probing_finds_a_free_port() {
        // Whatever else is running, 60 consecutive loopback ports won't all
        // be taken; the socket lands in the SIPp range.
        let s = bind(None, None).unwrap();
        let p = s.local_addr().unwrap().port();
        assert!((DEFAULT_PORT..DEFAULT_PORT + PROBE_PORTS).contains(&p));
    }
}
