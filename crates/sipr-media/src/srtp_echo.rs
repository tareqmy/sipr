//! Per-call RTP/SRTP echo: SIPp's `exec rtp_echo="startaudio|…"`
//! (`rtpstream.cpp` `rtpstream_audioecho_thread`). One thread per stream,
//! bound to the port the call advertised (`[rtpstream_audio_port]`),
//! sends every datagram straight back to its sender — unprotecting it
//! under the peer's key and re-protecting it under our own when SDES was
//! negotiated, keeping the caller's SSRC and sequence numbers exactly as
//! SIPp's echo does. A packet that fails authentication is dropped (SIPp
//! logs and forwards garbage; dropping is the kinder divergence).
//!
//! Unlike `-rtp_echo` (the process-wide sockets), this echo belongs to a
//! call and dies with it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::echo::EchoCounters;
use crate::srtp::SrtpContext;

/// A running per-call echo. Dropping it stops the thread and releases the
/// port — synchronously, so an `update` can rebind it at once.
pub struct EchoStream {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The bound address.
    pub local: SocketAddr,
}

impl EchoStream {
    /// Bind `local` and start echoing. `srtp` is `(receive, send)`: the
    /// peer's context to unprotect with and ours to re-protect with.
    ///
    /// # Errors
    ///
    /// The bind error.
    pub fn start(
        local: SocketAddr,
        srtp: Option<(SrtpContext, SrtpContext)>,
        counters: Arc<EchoCounters>,
    ) -> std::io::Result<Self> {
        let sock = UdpSocket::bind(local)?;
        let local = sock.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("sipr-srtp-echo".into())
            .spawn(move || echo_loop(&sock, srtp, &stop_flag, &counters))?;
        Ok(Self {
            stop,
            thread: Some(thread),
            local,
        })
    }

    /// Stop echoing and wait for the socket to close (also happens on drop).
    /// The thread is woken with an empty datagram so this returns at once
    /// rather than after its receive timeout.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(thread) = self.thread.take() else {
            return;
        };
        let any: IpAddr = match self.local.ip() {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        if let Ok(waker) = UdpSocket::bind(SocketAddr::new(any, 0)) {
            let _ = waker.send_to(&[], self.local);
        }
        let _ = thread.join();
    }
}

impl Drop for EchoStream {
    fn drop(&mut self) {
        self.stop();
    }
}

fn echo_loop(
    sock: &UdpSocket,
    mut srtp: Option<(SrtpContext, SrtpContext)>,
    stop: &AtomicBool,
    counters: &EchoCounters,
) {
    // SIPp: a 100 ms receive timeout so the thread can notice a stop.
    let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = [0u8; 2048];
    while !stop.load(Ordering::Relaxed) {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => return,
        };
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if n == 0 {
            continue; // the wake-up datagram, or noise
        }
        let wire: Vec<u8> = match srtp.as_mut() {
            None => buf[..n].to_vec(),
            Some((rx, tx)) => match rx.unprotect(&buf[..n]) {
                Ok(clear) => tx.protect(&clear),
                Err(_) => continue, // failed authentication: not echoed
            },
        };
        if sock.send_to(&wire, from).is_ok() {
            counters.packets.fetch_add(1, Ordering::Relaxed);
            counters
                .bytes
                .fetch_add(wire.len() as u64, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::srtp::{MasterKey, Suite};

    fn key(seed: u8) -> MasterKey {
        let mut raw = [0u8; 30];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(seed);
        }
        MasterKey::from_bytes(&raw)
    }

    /// The echo thread counts after its send returns, so an echoed packet can
    /// arrive before the counter moves (it does on Linux).
    fn wait_for_packets(counters: &EchoCounters, n: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while counters.packets.load(Ordering::Relaxed) < n && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn rtp(seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 0x00];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]);
        p.extend_from_slice(&0xabcd_0001u32.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn plain_echo_returns_bytes_to_the_sender() {
        let counters = Arc::new(EchoCounters::default());
        let echo =
            EchoStream::start("127.0.0.1:0".parse().unwrap(), None, Arc::clone(&counters)).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.send_to(b"hello", echo.local).unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, echo.local);
        wait_for_packets(&counters, 1);
        assert_eq!(counters.packets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stopping_releases_the_port_immediately() {
        let counters = Arc::new(EchoCounters::default());
        let first =
            EchoStream::start("127.0.0.1:0".parse().unwrap(), None, Arc::clone(&counters)).unwrap();
        let port = first.local;
        let started = std::time::Instant::now();
        drop(first);
        let again = EchoStream::start(port, None, counters).expect("rebind after drop");
        assert!(
            started.elapsed() < Duration::from_millis(90),
            "stop waited for the timeout"
        );
        assert_eq!(again.local, port);
    }

    #[test]
    fn srtp_echo_rekeys_under_our_key_keeping_seq_and_ssrc() {
        let caller_key = key(1);
        let our_key = key(2);
        let suite = Suite::AesCm128HmacSha180;
        let counters = Arc::new(EchoCounters::default());
        let echo = EchoStream::start(
            "127.0.0.1:0".parse().unwrap(),
            Some((
                SrtpContext::new(suite, &caller_key, false),
                SrtpContext::new(suite, &our_key, false),
            )),
            Arc::clone(&counters),
        )
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut caller_tx = SrtpContext::new(suite, &caller_key, false);
        let mut caller_rx = SrtpContext::new(suite, &our_key, false);
        let mut buf = [0u8; 256];
        for seq in [10u16, 11, 12] {
            let plain = rtp(seq, b"pattern payload!");
            client
                .send_to(&caller_tx.protect(&plain), echo.local)
                .unwrap();
            let (n, _) = client.recv_from(&mut buf).unwrap();
            let clear = caller_rx.unprotect(&buf[..n]).expect("echo under our key");
            assert_eq!(clear, plain, "seq {seq} round-trips with header intact");
        }
        // Garbage / wrong key: dropped, not echoed.
        client
            .send_to(&rtp(13, b"not srtp at all!"), echo.local)
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        assert!(
            client.recv_from(&mut buf).is_err(),
            "unauthenticated packet was echoed"
        );
        wait_for_packets(&counters, 3);
        assert_eq!(counters.packets.load(Ordering::Relaxed), 3);
    }
}
