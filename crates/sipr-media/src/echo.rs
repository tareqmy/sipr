//! `-rtp_echo`: SIPp's global RTP echo (`sipp.cpp` `rtp_echo_thread`,
//! `setup_media_sockets`). Two UDP sockets — the audio one on the media
//! port, the video one two above it — send every datagram straight back to
//! its sender while echoing is enabled. The scenario's `<rtp_echo value=>`
//! action flips that switch for the whole process, as in SIPp.
//!
//! Binding follows SIPp: with `-rtp_echo` the media port is probed upward
//! in steps of two (RTP ports stay even) until both sockets bind, and the
//! port that won is what `[media_port]` renders.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// SIPp's `-mb` default.
pub const DEFAULT_BUFSIZE: usize = 2048;
/// SIPp tries this many even ports before giving up.
const MAX_TRIES: u16 = 100;

/// Counters for one echo socket.
#[derive(Debug, Default)]
pub struct EchoCounters {
    /// Datagrams echoed.
    pub packets: AtomicU64,
    /// Bytes echoed.
    pub bytes: AtomicU64,
}

/// The two echo sockets and their threads.
pub struct EchoServer {
    /// The media port the audio socket bound (video is `+2`).
    pub media_port: u16,
    /// Echo on/off (`<rtp_echo value=>`); SIPp's `rtp_echo_state`, default on.
    pub enabled: Arc<AtomicBool>,
    /// Audio socket counters (SIPp's `rtp_pckts`/`rtp_bytes`).
    pub audio: Arc<EchoCounters>,
    /// Video socket counters (`rtp2_pckts`/`rtp2_bytes`).
    pub video: Arc<EchoCounters>,
    stop: Arc<AtomicBool>,
}

impl EchoServer {
    /// Bind and start echoing on `ip`, from `base_port` upward.
    ///
    /// # Errors
    ///
    /// The last bind error when no port pair in the probe range is free.
    pub fn start(ip: IpAddr, base_port: u16, bufsize: usize) -> std::io::Result<Self> {
        let (audio_sock, video_sock, media_port) = bind_pair(ip, base_port)?;
        let enabled = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let audio = Arc::new(EchoCounters::default());
        let video = Arc::new(EchoCounters::default());
        for (name, sock, counters) in [
            ("sipr-rtp-echo-audio", audio_sock, Arc::clone(&audio)),
            ("sipr-rtp-echo-video", video_sock, Arc::clone(&video)),
        ] {
            let enabled = Arc::clone(&enabled);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name(name.into())
                .spawn(move || echo_loop(&sock, bufsize, &enabled, &stop, &counters))?;
        }
        Ok(Self {
            media_port,
            enabled,
            audio,
            video,
            stop,
        })
    }

    /// Flip echoing on or off (`<rtp_echo value="0|1"/>`).
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// SIPp `bind_rtp_sockets` + the probe loop in `setup_media_sockets`.
fn bind_pair(ip: IpAddr, base_port: u16) -> std::io::Result<(UdpSocket, UdpSocket, u16)> {
    let mut port = base_port;
    let mut last = None;
    for _ in 0..MAX_TRIES {
        let audio = UdpSocket::bind(SocketAddr::new(ip, port));
        let video = UdpSocket::bind(SocketAddr::new(ip, port.wrapping_add(2)));
        match (audio, video) {
            (Ok(a), Ok(v)) => return Ok((a, v, port)),
            (Err(e), _) | (_, Err(e)) => last = Some(e),
        }
        port = port.wrapping_add(2);
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no ports to probe")))
}

fn echo_loop(
    sock: &UdpSocket,
    bufsize: usize,
    enabled: &AtomicBool,
    stop: &AtomicBool,
    counters: &EchoCounters,
) {
    // SIPp: a 100 ms receive timeout so the thread can notice a stop.
    let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = vec![0u8; bufsize.max(1)];
    while !stop.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if !enabled.load(Ordering::Relaxed) {
                    continue;
                }
                if sock.send_to(&buf[..n], from).is_ok() {
                    counters.packets.fetch_add(1, Ordering::Relaxed);
                    counters.bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// An even port the echo server can start probing from. It may be in
    /// use (rounding an ephemeral port down to even lands on whatever the
    /// previous socket got, on Windows); the server probes past that.
    fn even_free_base() -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let p = s.local_addr().unwrap().port();
        (p & !1).max(1024)
    }

    /// An even port bound and held by the returned socket.
    fn held_even_port() -> (u16, UdpSocket) {
        for _ in 0..100 {
            let base = even_free_base();
            if let Ok(sock) = UdpSocket::bind(("127.0.0.1", base)) {
                return (base, sock);
            }
        }
        panic!("no even port could be bound");
    }

    #[test]
    fn echoes_both_streams_and_counts() {
        let base = even_free_base();
        let echo = EchoServer::start("127.0.0.1".parse().unwrap(), base, DEFAULT_BUFSIZE).unwrap();
        let port = echo.media_port;
        assert_eq!(port % 2, 0);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 64];
        client.send_to(b"audio", ("127.0.0.1", port)).unwrap();
        let (n, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"audio");
        assert_eq!(from.port(), port);
        client.send_to(b"video!", ("127.0.0.1", port + 2)).unwrap();
        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"video!");
        // The echo thread counts after its send returns, so the reply can
        // arrive here first (it does on Linux): wait for the counters.
        // Each stream has its own thread, so wait for both counters.
        let settled = std::time::Instant::now() + Duration::from_secs(2);
        while (echo.audio.packets.load(Ordering::Relaxed) < 1
            || echo.video.packets.load(Ordering::Relaxed) < 1)
            && std::time::Instant::now() < settled
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(echo.audio.packets.load(Ordering::Relaxed), 1);
        assert_eq!(echo.audio.bytes.load(Ordering::Relaxed), 5);
        assert_eq!(echo.video.packets.load(Ordering::Relaxed), 1);
        // Disabled: swallowed, not echoed.
        echo.set_enabled(false);
        client.send_to(b"silent", ("127.0.0.1", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        assert!(client.recv_from(&mut buf).is_err());
        echo.set_enabled(true);
        client.send_to(b"back", ("127.0.0.1", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert!(client.recv_from(&mut buf).is_ok());
    }

    #[test]
    fn probes_past_a_taken_port() {
        let (base, _taken) = held_even_port();
        let echo = EchoServer::start("127.0.0.1".parse().unwrap(), base, 512).unwrap();
        assert!(echo.media_port > base);
        assert_eq!(echo.media_port % 2, 0);
    }
}
